#!/bin/zsh
set -euo pipefail
umask 077

# Builds, signs and verifies QR-Scanner.
#
# This app is deliberately independent of Keep Vault: its own bundle
# identifier, its own signature, its own folder, no shared code and no shared
# build step. Nothing here reads or writes anything under KeepVaultMac.
#
# Usage:
#   ./QrCodeScanner/tools/Build-QrScanner-macOS.sh
#   ./QrCodeScanner/tools/Build-QrScanner-macOS.sh --install
#   ./QrCodeScanner/tools/Build-QrScanner-macOS.sh --notary-profile "QR-Scanner"

script_dir=${0:A:h}
project_root=${script_dir:h}
packaging_dir=${project_root}/Packaging
sources_dir=${project_root}/Sources
bundle_identifier='de.michael-feinermann.qr-scanner'
app_name='QR-Scanner'
marketing_version='1.0.0'
build_version='1'
architecture='universal'
deployment_target='14.0'
install_app=0
run_tests=1
preflight_only=0
atomic_publish_self_test=0
identity=${QRSCANNER_CODESIGN_IDENTITY:-}
# Name of an "xcrun notarytool store-credentials" keychain profile. Empty means
# the build stops short of notarization; no secret ever lives in this file.
notary_profile=${QRSCANNER_NOTARY_PROFILE:-}

while (( $# > 0 )); do
  case $1 in
    --install)
      install_app=1
      ;;
    --identity)
      (( $# >= 2 )) || { print -u2 'Missing value for --identity.'; exit 64; }
      identity=$2
      shift
      ;;
    --notary-profile)
      (( $# >= 2 )) || { print -u2 'Missing value for --notary-profile.'; exit 64; }
      notary_profile=$2
      shift
      ;;
    --arch)
      (( $# >= 2 )) || { print -u2 'Missing value for --arch.'; exit 64; }
      architecture=$2
      shift
      ;;
    --version)
      (( $# >= 2 )) || { print -u2 'Missing value for --version.'; exit 64; }
      marketing_version=$2
      shift
      ;;
    --build-number)
      (( $# >= 2 )) || { print -u2 'Missing value for --build-number.'; exit 64; }
      build_version=$2
      shift
      ;;
    --preflight)
      preflight_only=1
      ;;
    --self-test-atomic-publish)
      atomic_publish_self_test=1
      ;;
    --skip-tests)
      run_tests=0
      ;;
    -h|--help)
      print 'Usage: Build-QrScanner-macOS.sh [--install] [--identity NAME] [--notary-profile NAME]'
      print '       [--arch universal|arm64|x86_64] [--version X.Y.Z] [--build-number N]'
      print '       [--skip-tests] [--preflight] [--self-test-atomic-publish]'
      exit 0
      ;;
    *)
      print -u2 "Unknown argument: $1"
      exit 64
      ;;
  esac
  shift
done

if [[ ! ${marketing_version} =~ '^[0-9]+([.][0-9]+){1,2}$' || ! ${build_version} =~ '^[1-9][0-9]*$' ]]; then
  print -u2 'Version values must be numeric (for example 4.0.2 and build 6).'
  exit 64
fi

render_info_plist() {
  local destination=$1
  sed -e "s/@@MARKETING_VERSION@@/${marketing_version}/g" \
      -e "s/@@BUILD_VERSION@@/${build_version}/g" \
    ${packaging_dir}/Info.plist.template > ${destination}
  plutil -lint ${destination} > /dev/null
  [[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' ${destination}) == ${bundle_identifier} ]] || {
    print -u2 'The rendered QR-Scanner bundle identifier is incorrect.'
    exit 1
  }
  [[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' ${destination}) == ${marketing_version} ]] || {
    print -u2 'The rendered QR-Scanner marketing version is incorrect.'
    exit 1
  }
  [[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' ${destination}) == ${build_version} ]] || {
    print -u2 'The rendered QR-Scanner build number is incorrect.'
    exit 1
  }
  [[ $(/usr/libexec/PlistBuddy -c 'Print :LSMultipleInstancesProhibited' ${destination}) == true ]] || {
    print -u2 'The rendered QR-Scanner does not prohibit multiple camera/payload instances.'
    exit 1
  }
}

for required_command in xcrun codesign security plutil ditto iconutil; do
  if ! command -v ${required_command} > /dev/null 2>&1; then
    print -u2 "Required command not found: ${required_command}"
    exit 1
  fi
done

if (( preflight_only )); then
  preflight_root=$(mktemp -d "${TMPDIR:-/tmp}/qr-scanner-preflight.XXXXXXXX")
  cleanup_preflight() {
    if [[ -n ${preflight_root:-} && -d ${preflight_root} && ${preflight_root} == */qr-scanner-preflight.* ]]; then
      rm -rf -- ${preflight_root}
    fi
  }
  trap cleanup_preflight EXIT INT TERM
  render_info_plist ${preflight_root}/Info.plist
  print "preflight_version=${marketing_version}"
  print "preflight_build=${build_version}"
  print 'preflight_single_instance=true'
  exit 0
fi

# Pick a signing identity if none was named.
#
# Developer ID is what a downloaded copy needs, so it wins when it is present.
# An Apple Development certificate signs an app that runs on this machine but
# that the notary service rejects, and ad-hoc signing runs here only. All three
# are useful at different points, so the build reports which one it used rather
# than pretending they are equivalent.
if [[ -z ${identity} ]]; then
  identity=$(security find-identity -v -p codesigning \
    | grep -o 'Developer ID Application: [^"]*' | head -n 1 || true)
fi
if [[ -z ${identity} ]]; then
  identity=$(security find-identity -v -p codesigning \
    | grep -o 'Apple Development: [^"]*' | head -n 1 || true)
fi
if [[ -z ${identity} ]]; then
  identity='-'
  print 'signing=ad-hoc (no codesigning certificate found; the app runs on this Mac only)'
elif [[ ${identity} == 'Developer ID Application: '* ]]; then
  print "signing=developer-id (${identity})"
else
  print "signing=development (${identity}) — usable on this Mac; the notary service rejects this certificate"
fi

# Build the complete distribution in a private sibling tree. The previous
# signed scanner remains untouched if compilation, signing, notarization or a
# final trust gate fails. Only a fully verified tree is exchanged into `dist`
# with one same-volume kernel rename at the end.
final_build_root=${project_root}/dist
if [[ -L ${project_root} || -L ${final_build_root} ]]; then
  print -u2 'Refusing to build or publish QR-Scanner through a symbolic-link path.'
  exit 1
fi
staging_root=$(mktemp -d "${project_root}/.qr-build.XXXXXXXX")
publish_helper_root=$(mktemp -d "${project_root}/.qr-publish-helper.XXXXXXXX")
backup_dir=''
cleanup_build() {
  if [[ -n ${backup_dir:-} && -d ${backup_dir} \
      && ${backup_dir} == ${TMPDIR:-/tmp}/qr-scanner-backup.* ]]; then
    rm -rf -- ${backup_dir}
  fi
  if [[ -n ${staging_root:-} && -d ${staging_root} \
      && ${staging_root} == ${project_root}/.qr-build.* ]]; then
    rm -rf -- ${staging_root}
  fi
  if [[ -n ${publish_helper_root:-} && -d ${publish_helper_root} \
      && ${publish_helper_root} == ${project_root}/.qr-publish-helper.* ]]; then
    rm -rf -- ${publish_helper_root}
  fi
}
trap cleanup_build EXIT INT TERM

atomic_publish_helper=${publish_helper_root}/atomic-publish
xcrun --sdk macosx clang -O2 -Wall -Wextra -Werror \
  -mmacosx-version-min=${deployment_target} -x c - -o ${atomic_publish_helper} <<'EOF'
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 4) return 64;
  unsigned int flags;
  if (strcmp(argv[1], "swap") == 0) {
    flags = RENAME_SWAP;
  } else if (strcmp(argv[1], "exclusive") == 0) {
    flags = RENAME_EXCL;
  } else {
    return 64;
  }
  if (renameatx_np(AT_FDCWD, argv[2], AT_FDCWD, argv[3], flags) != 0) {
    perror("renameatx_np");
    return 1;
  }
  return 0;
}
EOF

publish_distribution() {
  local staged_distribution=$1
  local final_distribution=$2
  local inject_pre_publish_failure=${3:-0}

  if [[ ${inject_pre_publish_failure} == 1 ]]; then
    return 86
  fi
  if [[ -e ${final_distribution} || -L ${final_distribution} ]]; then
    if [[ ! -d ${final_distribution} || -L ${final_distribution} ]]; then
      print -u2 "Refusing to replace a non-directory QR distribution: ${final_distribution}"
      return 1
    fi
    ${atomic_publish_helper} swap ${staged_distribution} ${final_distribution}
  else
    ${atomic_publish_helper} exclusive ${staged_distribution} ${final_distribution}
  fi
}

run_atomic_publish_self_test() {
  local self_test_root=${publish_helper_root}/self-test
  local current_distribution=${self_test_root}/dist
  local staged_distribution=${self_test_root}/stage
  local outside_hard_link=${self_test_root}/old-hard-link
  mkdir -p -- ${current_distribution} ${staged_distribution}
  print -rn -- 'old-release' > ${current_distribution}/sentinel
  print -rn -- 'new-release' > ${staged_distribution}/sentinel
  print -rn -- 'complete' > ${staged_distribution}/new-only
  ln ${current_distribution}/sentinel ${outside_hard_link}
  local old_inode=$(stat -f %i ${current_distribution}/sentinel)

  if publish_distribution ${staged_distribution} ${current_distribution} 1; then
    print -u2 'QR publish self-test did not inject the requested pre-publish failure.'
    return 1
  fi
  [[ $(<${current_distribution}/sentinel) == old-release \
      && ! -e ${current_distribution}/new-only \
      && $(<${staged_distribution}/sentinel) == new-release \
      && $(stat -f %i ${current_distribution}/sentinel) == ${old_inode} \
      && $(stat -f %i ${outside_hard_link}) == ${old_inode} ]] || {
    print -u2 'A QR pre-publish failure changed the old distribution or exposed a partial new tree.'
    return 1
  }

  publish_distribution ${staged_distribution} ${current_distribution} 0
  [[ $(<${current_distribution}/sentinel) == new-release \
      && $(<${current_distribution}/new-only) == complete \
      && $(<${staged_distribution}/sentinel) == old-release \
      && $(stat -f %i ${staged_distribution}/sentinel) == ${old_inode} \
      && $(stat -f %i ${outside_hard_link}) == ${old_inode} \
      && $(<${outside_hard_link}) == old-release ]] || {
    print -u2 'The QR distribution exchange was partial or followed an old hard link.'
    return 1
  }

  local first_distribution=${self_test_root}/first-stage
  local first_destination=${self_test_root}/first-dist
  mkdir -p -- ${first_distribution}
  print -rn -- 'first-release' > ${first_distribution}/sentinel
  publish_distribution ${first_distribution} ${first_destination} 0
  [[ ! -e ${first_distribution} && $(<${first_destination}/sentinel) == first-release ]] || {
    print -u2 'The first QR distribution was not published as one complete exclusive tree.'
    return 1
  }

  print 'qr_atomic_publish_pre_publish_failure_preserved_old_tree=true'
  print 'qr_atomic_publish_hard_link_not_followed=true'
  print 'qr_atomic_publish_exchange_complete=true'
  print 'qr_atomic_publish_first_release_exclusive=true'
}

if (( atomic_publish_self_test )); then
  run_atomic_publish_self_test
  exit 0
fi

build_root=${staging_root}

app_bundle=${build_root}/${app_name}.app
contents=${app_bundle}/Contents
macos_dir=${contents}/MacOS
resources_dir=${contents}/Resources
mkdir -p ${macos_dir} ${resources_dir}

# The unit tests cover the arbitration rule — which of two QR codes is taken —
# and that rule is the reason this app exists, so it is checked before anything
# is signed rather than after.
if (( run_tests )); then
  host_arch=$(uname -m)
  test_binary=${build_root}/ArbiterTests
  xcrun swiftc \
    -target ${host_arch}-apple-macos${deployment_target} \
    -O -parse-as-library \
    ${sources_dir}/CodeArbiter.swift \
    ${sources_dir}/PayloadInspector.swift \
    ${sources_dir}/Localization.swift \
    ${sources_dir}/VolatileClipboard.swift \
    ${sources_dir}/ScanSessionLifecycle.swift \
    ${sources_dir}/SingleInstancePolicy.swift \
    ${project_root}/Tests/ArbiterTests.swift \
    -framework AppKit \
    -o ${test_binary}
  ${test_binary}
  rm -f ${test_binary}
fi

architectures=(arm64)
case ${architecture} in
  universal) architectures=(arm64 x86_64) ;;
  arm64) architectures=(arm64) ;;
  x86_64) architectures=(x86_64) ;;
  *) print -u2 "Unknown architecture: ${architecture}"; exit 64 ;;
esac

# The Info.plist is linked into the executable as well as written into the
# bundle. LaunchServices reads the bundle's copy; the embedded section is what
# the camera prompt reads when the process is examined directly.
plist_path=${publish_helper_root}/Info.plist
render_info_plist ${plist_path}

thin_binaries=()
for slice in ${architectures[@]}; do
  thin=${build_root}/qr-scanner-${slice}
  xcrun swiftc \
    -target ${slice}-apple-macos${deployment_target} \
    -O -whole-module-optimization -parse-as-library \
    ${sources_dir}/CodeArbiter.swift \
    ${sources_dir}/PayloadInspector.swift \
    ${sources_dir}/Localization.swift \
    ${sources_dir}/VolatileClipboard.swift \
    ${sources_dir}/ScanSessionLifecycle.swift \
    ${sources_dir}/ScanSession.swift \
    ${sources_dir}/MainWindowController.swift \
    ${sources_dir}/SingleInstancePolicy.swift \
    ${sources_dir}/App.swift \
    -framework AppKit -framework AVFoundation \
    -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker ${plist_path} \
    -o ${thin}
  thin_binaries+=(${thin})
done

executable=${macos_dir}/${app_name}
if (( ${#thin_binaries} > 1 )); then
  xcrun lipo -create ${thin_binaries[@]} -output ${executable}
  xcrun lipo ${executable} -verify_arch ${architectures[@]}
else
  ditto ${thin_binaries[1]} ${executable}
fi
chmod 0755 ${executable}
rm -f ${thin_binaries[@]}

ditto ${plist_path} ${contents}/Info.plist
print -n 'APPL????' > ${contents}/PkgInfo

# The icon is generated from tools/make-icon.swift, so what it depicts is
# readable source rather than a committed binary.
iconset=${build_root}/AppIcon.iconset
xcrun swift ${script_dir}/make-icon.swift ${iconset} > /dev/null
iconutil -c icns ${iconset} -o ${resources_dir}/AppIcon.icns
rm -rf ${iconset}

# Refuse the entitlements that would undo the point of the sandbox.
#
# Each of these lets another process put code into this one, and this process
# is the one holding the scanned value in memory. A signature over a bundle
# carrying any of them would be signing away the guarantee the app is making,
# so the build stops rather than producing it.
forbidden=(
  'com.apple.security.cs.disable-library-validation'
  'com.apple.security.cs.allow-unsigned-executable-memory'
  'com.apple.security.cs.allow-dyld-environment-variables'
  'com.apple.security.cs.disable-executable-page-protection'
  'com.apple.security.get-task-allow'
)
# Matched as a plist <key> element rather than as loose text, so the comment in
# the entitlements file naming these keys does not trip the check on itself.
entitlements_source=$(< ${packaging_dir}/QrScanner.entitlements)
for forbidden_key in ${forbidden[@]}; do
  if [[ ${entitlements_source} == *"<key>${forbidden_key}</key>"* ]]; then
    print -u2 "The entitlements request ${forbidden_key}, which reopens code injection."
    exit 1
  fi
done

timestamp_arguments=(--timestamp)
[[ ${identity} == '-' ]] && timestamp_arguments=()

codesign --force --sign ${identity} --options runtime ${timestamp_arguments[@]} \
  --entitlements ${packaging_dir}/QrScanner.entitlements \
  --identifier ${bundle_identifier} \
  ${app_bundle}

codesign --verify --strict --deep --verbose=2 ${app_bundle}

# Confirm the bundle actually carries what was requested. A signature that
# silently dropped the sandbox would still verify happily.
#
# The output is captured whole and matched in the shell rather than piped into
# "grep -q": grep exits at its first match, the tool upstream dies of SIGPIPE,
# and under "set -o pipefail" that turns a successful check into a failed one.
granted=$(codesign -d --entitlements :- ${app_bundle} 2>/dev/null || true)
for required_key in 'com.apple.security.app-sandbox' 'com.apple.security.device.camera'; do
  if [[ ${granted} != *${required_key}* ]]; then
    print -u2 "The signed bundle is missing ${required_key}."
    exit 1
  fi
done
for forbidden_key in ${forbidden[@]}; do
  if [[ ${granted} == *${forbidden_key}* ]]; then
    print -u2 "The signed bundle carries ${forbidden_key}."
    exit 1
  fi
done
print 'entitlements=sandbox+camera (no injection-enabling entitlements present)'

signature_details=$(codesign -dvvv ${app_bundle} 2>&1 || true)
if [[ ${signature_details} != *'flags='*'runtime'* ]]; then
  print -u2 'The signed bundle does not carry the hardened runtime.'
  exit 1
fi
print 'hardened-runtime=enabled'

# Notarization. Requires a Developer ID Application certificate and a stored
# notarytool profile:
#
#   xcrun notarytool store-credentials "QR-Scanner" \
#     --apple-id you@example.com --team-id TEAMID --password APP-SPECIFIC-PASSWORD
#
# then pass --notary-profile "QR-Scanner". The submission ZIP is scratch: the
# released ZIP is assembled only after the stapled app and all five hybrid
# sidecars exist, otherwise users would receive an archive that the repository
# verifier necessarily rejects.
release_zip=${build_root}/${app_name}-macOS.zip
if [[ -z ${notary_profile} ]]; then
  print 'notarization=not_performed (pass --notary-profile NAME once a Developer ID certificate and a notarytool profile exist)'
elif [[ ${signature_details} != *'Authority=Developer ID Application:'* ]]; then
  print -u2 'Notarization requires a Developer ID Application identity; the notary service rejects an Apple Development certificate.'
  exit 1
else
  notary_submission_zip=${publish_helper_root}/QR-Scanner-notary-submission.zip
  ditto -c -k --keepParent ${app_bundle} ${notary_submission_zip}
  xcrun notarytool submit ${notary_submission_zip} --keychain-profile ${notary_profile} --wait
  xcrun stapler staple ${app_bundle}
  xcrun stapler validate ${app_bundle}
  spctl --assess --type execute --verbose=4 ${app_bundle}
  print "notarization=stapled (${notary_profile})"
fi

# --- Hybrid Signatures --------------------------------------------------------
repo_root=${project_root:h}
dotnet_command=${KEEPVAULT_DOTNET:-/Users/michael/.dotnet-keepvault/dotnet}
pfx_path=${KEEPVAULT_SIGNING_PFX:-}
if [[ -z ${pfx_path} ]]; then
  for candidate in /Volumes/*/Keep\ Vault\ ReleaseKeys*/*.pfx(N); do
    [[ -f ${candidate} && ! -L ${candidate} ]] || continue
    pfx_path=${candidate}
    break
  done
fi
# Where the keys actually live when no removable volume is mounted. Without
# this the search ended empty on the machine that holds them, the signing block
# below was skipped, and the build failed a minute later in the verifier with
# a missing sidecar rather than with the reason.
if [[ -z ${pfx_path} ]]; then
  pfx_path="${HOME}/Library/Application Support/Keep Vault/ReleaseKeys/hybrid-rsa4096.pfx"
fi

mldsa_private_key=${KEEPVAULT_MLDSA_PRIVATE_KEY:-}
if [[ -z ${mldsa_private_key} ]]; then
  for candidate in /Volumes/*/Keep\ Vault\ ReleaseKeys*/mldsa87-private.key(N); do
    [[ -f ${candidate} && ! -L ${candidate} ]] || continue
    mldsa_private_key=${candidate}
    break
  done
fi
if [[ -z ${mldsa_private_key} ]]; then
  mldsa_private_key="${HOME}/Library/Application Support/Keep Vault/ReleaseKeys/mldsa87-private.key"
fi
mldsa_private_key_encrypted=${KEEPVAULT_MLDSA_PRIVATE_KEY_ENCRYPTED:-${mldsa_private_key}.enc}
mldsa_keychain_service=${KEEPVAULT_MLDSA_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.hybrid-wrapping-key}
mldsa_keychain_account=${KEEPVAULT_MLDSA_KEYCHAIN_ACCOUNT:-${USER:-}}

mldsa_key_arguments=(--mldsa-private-key ${mldsa_private_key})
if [[ -f ${mldsa_private_key_encrypted} && ! -L ${mldsa_private_key_encrypted} ]]; then
  mldsa_key_arguments=(
    --mldsa-private-key-encrypted ${mldsa_private_key_encrypted}
    --mldsa-key-keychain-service ${mldsa_keychain_service}
    --mldsa-key-keychain-account ${mldsa_keychain_account}
  )
fi

wrapping_key_file=${KEEPVAULT_WRAPPING_KEY_FILE:-}
if [[ -z ${wrapping_key_file} ]]; then
  for candidate in /Volumes/*/Keep\ Vault\ ReleaseKeys*/wrapping-key.b64(N); do
    [[ -f ${candidate} && ! -L ${candidate} ]] || continue
    wrapping_key_file=${candidate}
    break
  done
fi
if [[ -n ${wrapping_key_file} && -f ${wrapping_key_file} && ! -L ${wrapping_key_file} ]]; then
  mldsa_key_arguments+=(--wrapping-key-file ${wrapping_key_file})
fi

mldsa_public_key=${KEEPVAULT_MLDSA_PUBLIC_KEY:-${repo_root}/KeepVaultMac/Packaging/Keys/mldsa87-public.key}
pfx_password_encrypted=${KEEPVAULT_PFX_PASSWORD_ENCRYPTED:-${pfx_path}.password.enc}
pfx_password_arguments=()
if [[ -f ${pfx_password_encrypted} && ! -L ${pfx_password_encrypted} ]]; then
  pfx_password_arguments=(--pfx-password-encrypted ${pfx_password_encrypted})
fi
pfx_password_service=${KEEPVAULT_PFX_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.hybrid-pfx}
pfx_password_account=${KEEPVAULT_PFX_KEYCHAIN_ACCOUNT:-${USER:-}}
pfx_password_environment=${KEEPVAULT_PFX_PASSWORD_ENV:-KEEPVAULT_HYBRID_PFX_PASSWORD}

# The wrapped key is the normal case: once both halves are wrapped, the
# plaintext ML-DSA key is deleted and only the .enc file remains. Testing for
# the plaintext path alone made this block skip itself on exactly the tree that
# had been migrated, which is the tree every release is built from.
mldsa_key_present=0
if [[ -f ${mldsa_private_key} && ! -L ${mldsa_private_key} ]]; then
  mldsa_key_present=1
fi
if [[ -f ${mldsa_private_key_encrypted} && ! -L ${mldsa_private_key_encrypted} ]]; then
  mldsa_key_present=1
fi

if [[ -n ${pfx_path} && -f ${pfx_path} && ${mldsa_key_present} -eq 1 && -x ${dotnet_command} ]]; then
  signer_dll=${repo_root}/KeepVaultMac/Packaging/HybridSigner/bin/Release/net10.0/KeepVaultMac.HybridSigner.dll
  (
    cd ${repo_root}/KeepVaultMac
    ${dotnet_command} restore Packaging/HybridSigner/KeepVaultMac.HybridSigner.csproj --locked-mode --nologo
    ${dotnet_command} build Packaging/HybridSigner/KeepVaultMac.HybridSigner.csproj -c Release --no-restore --nologo
  )
  
  hybrid_arguments=(
    ${signer_dll}
    sign
    --pfx ${pfx_path}
    ${pfx_password_arguments[@]}
    ${mldsa_key_arguments[@]}
    --mldsa-public-key ${mldsa_public_key}
    --reference-library ${repo_root}/KeepVaultMac/Native/osx-arm64/libmldsa87_ref.dylib
    --policy ${repo_root}/KeepVaultMac/Directory.Build.props
    --launcher-pins ${publish_helper_root}/ScannerPins.swift
    --target ${app_bundle}/Contents/MacOS/QR-Scanner
  )
  if [[ ${#pfx_password_arguments[@]} -eq 0 ]]; then
    if [[ -n ${pfx_password_service} ]]; then
      hybrid_arguments+=(--pfx-password-keychain-service ${pfx_password_service})
      [[ -n ${pfx_password_account} ]] && hybrid_arguments+=(--pfx-keychain-account ${pfx_password_account})
    else
      hybrid_arguments+=(--pfx-password-env ${pfx_password_environment})
    fi
  fi

  hybrid_keychain_tmp=${publish_helper_root}/hybrid-keychain-app
  mkdir -p -m 0700 ${hybrid_keychain_tmp}
  (
    cd ${repo_root}/KeepVaultMac
    TMPDIR=${hybrid_keychain_tmp} \
      KEEPVAULT_KEYCHAIN_TEMP_ROOT=${hybrid_keychain_tmp} \
      DOTNET_EnableDiagnostics=0 \
      ${dotnet_command} ${hybrid_arguments[@]}
  )

  scanner_bin=${app_bundle}/Contents/MacOS/QR-Scanner
  for sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    if [[ ! -f ${scanner_bin}${sidecar_suffix} || -L ${scanner_bin}${sidecar_suffix} ]]; then
      print -u2 "QR-Scanner hybrid signing omitted ${sidecar_suffix}."
      exit 1
    fi
    mv -- ${scanner_bin}${sidecar_suffix} ${app_bundle}${sidecar_suffix}
  done
  codesign --verify --strict --verbose=2 ${app_bundle}
  print "scanner_dual_signature=${app_bundle}.khsig"
else
  # Everything that consumes this bundle pins its hybrid sidecars, so a copy
  # without them is not a lesser build, it is an unusable one. Say which input
  # was missing here rather than letting the verifier report the consequence.
  print -u2 'QR-Scanner hybrid signing was skipped, so the bundle has no sidecars and nothing will accept it.'
  print -u2 "  RSA PFX:            ${pfx_path} ($([[ -f ${pfx_path} ]] && print present || print MISSING))"
  print -u2 "  ML-DSA key:         ${mldsa_private_key} ($([[ -f ${mldsa_private_key} ]] && print present || print absent))"
  print -u2 "  ML-DSA key wrapped: ${mldsa_private_key_encrypted} ($([[ -f ${mldsa_private_key_encrypted} ]] && print present || print MISSING))"
  print -u2 "  dotnet:             ${dotnet_command} ($([[ -x ${dotnet_command} ]] && print executable || print MISSING))"
  exit 1
fi

# Validate the staged companion with the same independent gate that Keep Vault
# and the installer use. A successful codesign check alone says nothing about
# the detached RSA-PSS/ML-DSA pair or its SHA3/Skein manifests.
${repo_root}/tools/Verify-QR-Scanner-macOS.sh \
  --app ${app_bundle} \
  --allow-development \
  --mldsa-public-key ${mldsa_public_key}

# The former build archived the app before the detached sidecars existed, so
# its advertised ZIP could never pass Verify-QR-Scanner after extraction.
# Assemble the real release payload only now and verify the extracted copy.
archive_payload=${publish_helper_root}/archive-payload
archive_check=${publish_helper_root}/archive-check
mkdir -p -- ${archive_payload} ${archive_check}
ditto ${app_bundle} ${archive_payload}/${app_name}.app
for sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
  ditto ${app_bundle}${sidecar_suffix} ${archive_payload}/${app_name}.app${sidecar_suffix}
done
ditto -c -k --sequesterRsrc ${archive_payload} ${release_zip}
ditto -x -k ${release_zip} ${archive_check}
${repo_root}/tools/Verify-QR-Scanner-macOS.sh \
  --app ${archive_check}/${app_name}.app \
  --allow-development \
  --mldsa-public-key ${mldsa_public_key}

# The archive is a release artifact in its own right. Bind it and both hash
# manifests to the same RSA-PSS plus ML-DSA-87 policy as the scanner binary.
archive_hybrid_arguments=(
  ${signer_dll}
  sign
  --pfx ${pfx_path}
  ${pfx_password_arguments[@]}
  ${mldsa_key_arguments[@]}
  --mldsa-public-key ${mldsa_public_key}
  --reference-library ${repo_root}/KeepVaultMac/Native/osx-arm64/libmldsa87_ref.dylib
  --policy ${repo_root}/KeepVaultMac/Directory.Build.props
  --launcher-pins ${publish_helper_root}/ScannerArchivePins.swift
  --target ${release_zip}
)
if [[ ${#pfx_password_arguments[@]} -eq 0 ]]; then
  if [[ -n ${pfx_password_service} ]]; then
    archive_hybrid_arguments+=(--pfx-password-keychain-service ${pfx_password_service})
    [[ -n ${pfx_password_account} ]] && archive_hybrid_arguments+=(--pfx-keychain-account ${pfx_password_account})
  else
    archive_hybrid_arguments+=(--pfx-password-env ${pfx_password_environment})
  fi
fi
archive_keychain_tmp=${publish_helper_root}/hybrid-keychain-archive
mkdir -p -m 0700 ${archive_keychain_tmp}
(
  cd ${repo_root}/KeepVaultMac
  TMPDIR=${archive_keychain_tmp} \
    KEEPVAULT_KEYCHAIN_TEMP_ROOT=${archive_keychain_tmp} \
    DOTNET_EnableDiagnostics=0 \
    ${dotnet_command} ${archive_hybrid_arguments[@]}
)
(
  cd ${repo_root}/KeepVaultMac
  DOTNET_EnableDiagnostics=0 \
    ${dotnet_command} ${signer_dll} verify \
      --mldsa-public-key ${mldsa_public_key} \
      --policy ${repo_root}/KeepVaultMac/Directory.Build.props \
      --target ${release_zip}
)

expected_outputs=(
  ${app_bundle}
  ${app_bundle}.sha3
  ${app_bundle}.skein
  ${app_bundle}.khsig
  ${app_bundle}.sha3.khsig
  ${app_bundle}.skein.khsig
  ${release_zip}
  ${release_zip}.sha3
  ${release_zip}.skein
  ${release_zip}.khsig
  ${release_zip}.sha3.khsig
  ${release_zip}.skein.khsig
)
actual_outputs=(${build_root}/*(N))
if (( ${#actual_outputs[@]} != ${#expected_outputs[@]} )); then
  print -u2 "The staged QR distribution contains ${#actual_outputs[@]} top-level objects instead of the exact signed set."
  exit 1
fi
for expected_output in ${expected_outputs[@]}; do
  if [[ -L ${expected_output} || ( ! -f ${expected_output} && ! -d ${expected_output} ) ]]; then
    print -u2 "The staged QR distribution is missing a regular expected object: ${expected_output}"
    exit 1
  fi
done
if find ${build_root} -type l -print -quit | grep -q . \
    || find ${build_root} -type f -links +1 -print -quit | grep -q .; then
  print -u2 'The staged QR distribution contains a symbolic link or hard-linked file.'
  exit 1
fi

publish_distribution ${staging_root} ${final_build_root} 0
app_bundle=${final_build_root}/${app_name}.app
release_zip=${final_build_root}/${app_name}-macOS.zip
print "distribution_publish=atomic (${final_build_root})"

if (( install_app )); then
  destination=/Applications/${app_name}.app
  backup_dir=$(mktemp -d "${TMPDIR:-/tmp}/qr-scanner-backup.XXXXXXXX")
  install_stage=${publish_helper_root}/install-stage
  install_app_bundle=${install_stage}/${app_name}.app
  mkdir -p -- ${install_stage}
  ditto ${app_bundle} ${install_app_bundle}
  for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    ditto ${app_bundle}${suffix} ${install_app_bundle}${suffix}
  done
  has_existing=0
  if [[ -e ${destination} || -L ${destination} ]]; then
    if [[ ! -d ${destination} || -L ${destination} ]]; then
      print -u2 "Refusing to replace a non-directory object: ${destination}"
      exit 1
    fi
    existing_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' ${destination}/Contents/Info.plist 2>/dev/null || true)
    if [[ ${existing_id} != ${bundle_identifier} ]]; then
      print -u2 "Refusing to replace foreign app at ${destination} (bundle id: ${existing_id})"
      exit 1
    fi
    has_existing=1
    ditto ${destination} ${backup_dir}/QR-Scanner.app
    for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
      if [[ -f ${destination}${suffix} ]]; then
        ditto ${destination}${suffix} ${backup_dir}/QR-Scanner.app${suffix}
      fi
    done
  fi

  # Atomic replace
  if (( has_existing )); then
    backup_name=.QR-Scanner.previous.$RANDOM.$$.app
    DESTINATION_PATH=${destination} NEW_ITEM_PATH=${install_app_bundle} BACKUP_ITEM_NAME=${backup_name} \
      osascript -l JavaScript <<'JAVASCRIPT'
ObjC.import('Foundation')
const env = $.NSProcessInfo.processInfo.environment
const dest = $.NSURL.fileURLWithPath(ObjC.unwrap(env.objectForKey('DESTINATION_PATH')))
const newItem = $.NSURL.fileURLWithPath(ObjC.unwrap(env.objectForKey('NEW_ITEM_PATH')))
const bName = ObjC.unwrap(env.objectForKey('BACKUP_ITEM_NAME'))
const err = Ref()
const replaced = $.NSFileManager.defaultManager.replaceItemAtURLWithItemAtURLBackupItemNameOptionsResultingItemURLError(
  dest, newItem, bName, $.NSFileManagerItemReplacementWithoutDeletingBackupItem, Ref(), err)
if (!replaced) throw new Error(err[0] ? ObjC.unwrap(err[0].localizedDescription) : 'replace failed')
JAVASCRIPT
  else
    ditto ${install_app_bundle} ${destination}
  fi

  # Copy sidecars
  for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    if [[ -f ${install_app_bundle}${suffix} ]]; then
      ditto ${install_app_bundle}${suffix} ${destination}${suffix}
    fi
  done

  # Verify installed scanner
  if ! ${repo_root}/tools/Verify-QR-Scanner-macOS.sh --app ${destination} --allow-development; then
    print -u2 "Installed QR-Scanner verification failed; restoring previous version..."
    if (( has_existing )) && [[ -d ${backup_dir}/QR-Scanner.app ]]; then
      ditto ${backup_dir}/QR-Scanner.app ${destination}
      for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
        if [[ -f ${backup_dir}/QR-Scanner.app${suffix} ]]; then
          ditto ${backup_dir}/QR-Scanner.app${suffix} ${destination}${suffix}
        fi
      done
    fi
    exit 1
  fi

  chmod -R go+rX ${destination}
  /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
    -f ${destination} > /dev/null 2>&1 || true
  print "installed=${destination}"
fi

print "bundle=${app_bundle}"
print "zip=${release_zip}"
