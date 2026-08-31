#!/bin/zsh
# Builds the portable Keep Vault release for macOS, the counterpart of
# tools/Build-Portable.ps1 on Windows.
#
# "Portable" means the result runs from wherever it is unpacked — a USB stick,
# an external disk, a home directory — without an installer, without a .NET
# runtime, and without touching /Applications. The folder carries the signed
# app bundle, a standalone release verifier, and a README naming the pins that
# were compiled in. The ZIP and both hash manifests are signed with the same
# hybrid RSA-PSS + ML-DSA-87 pair as everything else, so the download can be
# checked before anything is launched.
set -euo pipefail
umask 077

script_dir=${0:A:h}
repo_root=${script_dir:h}
mac_project=${repo_root}/KeepVaultMac
packaging_dir=${mac_project}/Packaging
verifier_project=${repo_root}/KeepVaultMac.ReleaseVerifier/KeepVaultMac.ReleaseVerifier.csproj
team_identifier='2T6K9PGS55'
bundle_identifier='de.michael-feinermann.keep-vault'
output_name='Keep Vault-portable-macOS'
architecture='universal'
identity=${KEEPVAULT_CODESIGN_IDENTITY:-}
notary_profile=${KEEPVAULT_NOTARY_PROFILE:-}
self_test_rollback=0
pfx_path=${KEEPVAULT_HYBRID_PFX:-${HOME}/Library/Application Support/Keep Vault/ReleaseKeys/hybrid-rsa4096.pfx}
mldsa_private_key=${KEEPVAULT_MLDSA_PRIVATE_KEY:-${HOME}/Library/Application Support/Keep Vault/ReleaseKeys/mldsa87-private.key}
mldsa_private_key_encrypted=${KEEPVAULT_MLDSA_PRIVATE_KEY_ENCRYPTED:-${mldsa_private_key}.enc}
mldsa_keychain_service=${KEEPVAULT_MLDSA_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.hybrid-wrapping-key}
pfx_password_encrypted=${KEEPVAULT_PFX_PASSWORD_ENCRYPTED:-${pfx_path}.password.enc}
mldsa_keychain_account=${KEEPVAULT_MLDSA_KEYCHAIN_ACCOUNT:-${USER:-}}

# Both halves of the hybrid certificate are released by one Keychain
# confirmation once they have been wrapped: a signature counts only when
# RSA-PSS and ML-DSA-87 both verify, so gating them separately would mean two
# prompts for one indivisible decision. The unwrapped paths stay as a fallback
# so a tree that has not been migrated still builds.
mldsa_key_arguments=(--mldsa-private-key ${mldsa_private_key})
if [[ -f ${mldsa_private_key_encrypted} && ! -L ${mldsa_private_key_encrypted} ]]; then
  mldsa_key_arguments=(
    --mldsa-private-key-encrypted ${mldsa_private_key_encrypted}
    --mldsa-key-keychain-service ${mldsa_keychain_service}
    --mldsa-key-keychain-account ${mldsa_keychain_account}
  )
fi
pfx_password_arguments=()
if [[ -f ${pfx_password_encrypted} && ! -L ${pfx_password_encrypted} ]]; then
  pfx_password_arguments=(--pfx-password-encrypted ${pfx_password_encrypted})
fi

# A wrapping key on removable media lets a build run unattended while that
# volume is mounted; unplug it and signing falls back to the Keychain prompt.
# Physical presence is a weaker gate than the prompt -- anything running as this
# user can read a mounted volume -- but it is bounded by something the key
# holder can see and pull out, and it keeps routine development from being four
# confirmations long.
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
  print "wrapping_key=removable media (${wrapping_key_file:h:t})"
else
  print "wrapping_key=Keychain (confirmation required per signing pass)"
fi

mldsa_public_key=${KEEPVAULT_MLDSA_PUBLIC_KEY:-${packaging_dir}/Keys/mldsa87-public.key}
pfx_password_service=${KEEPVAULT_PFX_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.hybrid-pfx}
pfx_password_account=${KEEPVAULT_PFX_KEYCHAIN_ACCOUNT:-${USER:-}}
dotnet_command=${KEEPVAULT_DOTNET:-/Users/michael/.dotnet-keepvault/dotnet}
source_app=${repo_root}/dist/Keep\ Vault-macOS/Keep\ Vault.app
scanner_app=${repo_root}/QrCodeScanner/dist/QR-Scanner.app

usage() {
  print -u2 'Usage: Build-Portable-macOS.sh [--app "Keep Vault.app"] [--scanner "QR-Scanner.app"]'
  print -u2 '       [--identity HASH] [--notary-profile NOTARYTOOL_KEYCHAIN_PROFILE]'
  print -u2 '       [--output-name NAME] [--self-test-rollback]'
  print -u2 '       [--architecture universal|arm64] [--dotnet /path/to/dotnet]'
  exit 64
}

while (( $# != 0 )); do
  case $1 in
    --app) (( $# >= 2 )) || usage; source_app=$2; shift 2 ;;
    --scanner) (( $# >= 2 )) || usage; scanner_app=$2; shift 2 ;;
    --identity) (( $# >= 2 )) || usage; identity=$2; shift 2 ;;
    --notary-profile) (( $# >= 2 )) || usage; notary_profile=$2; shift 2 ;;
    --output-name) (( $# >= 2 )) || usage; output_name=$2; shift 2 ;;
    --architecture) (( $# >= 2 )) || usage; architecture=$2; shift 2 ;;
    --dotnet) (( $# >= 2 )) || usage; dotnet_command=$2; shift 2 ;;
    --self-test-rollback) self_test_rollback=1; shift ;;
    *) usage ;;
  esac
done

if [[ ${architecture} != universal && ${architecture} != arm64 ]]; then
  print -u2 'Only universal or arm64 portable releases are supported.'
  exit 64
fi
if [[ ! ${output_name} =~ '^[A-Za-z0-9][A-Za-z0-9._ -]{0,126}[A-Za-z0-9]$' ]]; then
  print -u2 'The output name must be a plain 2-128 character file name without trailing punctuation.'
  exit 64
fi
if (( self_test_rollback )); then
  exec ${script_dir}/Test-PortablePublishRollback-macOS.sh
fi
if [[ ! -d ${source_app} || -L ${source_app} ]]; then
  print -u2 "Signed app bundle not found or is a symbolic link: ${source_app}"
  print -u2 'Run tools/Build-KeepVault-macOS.sh first.'
  exit 1
fi
if [[ ! -d ${scanner_app} || -L ${scanner_app} ]]; then
  print -u2 "Signed QR-Scanner bundle not found or is a symbolic link: ${scanner_app}"
  print -u2 'Build it with the same --version and --build-number as Keep Vault first.'
  exit 1
fi
${script_dir}/Verify-ReleasePairMetadata-macOS.sh --app ${source_app} --scanner ${scanner_app}
if [[ ! -x ${dotnet_command} || -L ${dotnet_command} ]]; then
  print -u2 "The official .NET SDK host is unavailable or a symbolic link: ${dotnet_command}"
  exit 1
fi
for required_command in xcrun codesign security ditto shasum lipo openssl spctl; do
  command -v ${required_command} >/dev/null 2>&1 || {
    print -u2 "Required release tool is unavailable: ${required_command}"
    exit 1
  }
done

if [[ -z ${identity} ]]; then
  identity=$(security find-identity -v -p codesigning | awk '/Developer ID Application/{print $2; exit}')
fi
if [[ -z ${identity} ]]; then
  identity=$(security find-identity -v -p codesigning | awk '/Apple Development/{print $2; exit}')
fi
[[ -n ${identity} ]] || {
  print -u2 'No Developer ID Application or Apple Development code-signing identity was found.'
  exit 1
}
identity_details=$(security find-identity -v -p codesigning | grep -F -- "${identity}" | head -1 || true)
identity_label=${identity_details#*\"}
identity_label=${identity_label%%\"*}
certificate_subject=$(security find-certificate -c ${identity_label} -p \
  | openssl x509 -noout -subject -nameopt RFC2253 2>/dev/null || true)
if [[ ${certificate_subject} != *"OU=${team_identifier}"* ]]; then
  print -u2 "The selected portable signing certificate does not belong to team ${team_identifier}."
  exit 2
fi
codesign_timestamp_arguments=()
if [[ ${identity_details} == *'Developer ID Application'* ]]; then
  if [[ -z ${notary_profile} ]]; then
    print -u2 'RELEASE GATE: a Developer ID portable release requires --notary-profile.'
    exit 2
  fi
  portable_signing_description='Developer ID Application identity. The apps are stapled and the final portable archive is accepted by Apple notarization.'
  codesign_timestamp_arguments=(--timestamp)
  development_build=0
elif [[ ${identity_details} == *'Apple Development'* ]]; then
  if [[ -n ${notary_profile} ]]; then
    print -u2 'Apple Development output cannot use a notary profile or claim a public Gatekeeper release.'
    exit 2
  fi
  portable_signing_description='local Apple Development identity. It is not a public Gatekeeper release and has not been notarized.'
  development_build=1
else
  print -u2 'The selected identity is neither Developer ID Application nor Apple Development.'
  exit 2
fi

input_verify_flags=(--app ${source_app} --require-launcher-signature --mldsa-public-key ${mldsa_public_key})
scanner_verify_flags=(--app ${scanner_app})
source_signature=$(codesign -dvvv ${source_app} 2>&1 || true)
scanner_signature=$(codesign -dvvv ${scanner_app} 2>&1 || true)
if (( development_build )); then
  if [[ ${source_signature} != *'Authority=Apple Development:'* \
      || ${scanner_signature} != *'Authority=Apple Development:'* ]]; then
    print -u2 'A development portable package requires both input apps to use Apple Development.'
    exit 2
  fi
  input_verify_flags+=(--allow-development)
  scanner_verify_flags+=(--allow-development)
else
  if [[ ${source_signature} != *'Authority=Developer ID Application:'* \
      || ${scanner_signature} != *'Authority=Developer ID Application:'* ]]; then
    print -u2 'A public portable package requires both input apps to use Developer ID Application.'
    exit 2
  fi
  input_verify_flags+=(--require-notarization)
  scanner_verify_flags+=(--require-notarization)
fi
${script_dir}/Verify-KeepVault-macOS.sh ${input_verify_flags[@]}
${script_dir}/Verify-QR-Scanner-macOS.sh ${scanner_verify_flags[@]}

required_architectures=(arm64)
[[ ${architecture} == universal ]] && required_architectures+=(x86_64)
for input_macho in \
    ${source_app}/Contents/MacOS/Keep\ Vault\ Launcher \
    ${scanner_app}/Contents/MacOS/QR-Scanner; do
  for required_architecture in ${required_architectures[@]}; do
    xcrun lipo ${input_macho} -verify_arch ${required_architecture}
  done
done

if (( development_build )); then
  portable_output_root=${repo_root}/build/dev
  print 'portable_publish_mode=development (build/dev only; no public Gatekeeper claim)'
else
  portable_output_root=${repo_root}/dist
  print 'portable_publish_mode=release (Developer ID plus Apple notarization required)'
fi
mkdir -p -- ${portable_output_root}
if [[ -L ${portable_output_root} || ! -d ${portable_output_root} ]]; then
  print -u2 "Portable output root is not a physical directory: ${portable_output_root}"
  exit 1
fi
portable_output_identity=$(stat -f '%d:%i' ${portable_output_root} 2>/dev/null || true)
if [[ ! ${portable_output_identity} =~ '^[0-9]+:[0-9]+$' ]]; then
  print -u2 'Portable output root has no stable device/inode identity.'
  exit 1
fi

build_root=$(mktemp -d "${TMPDIR:-/tmp}/keep-vault-portable.XXXXXXXX")
chmod 0700 ${build_root}
build_root_identity=$(stat -f '%d:%i' ${build_root})
release_stage=''
release_stage_identity=''
published_paths=()
published_identities=()
publish_committed=0

publish_rename_source=${script_dir}/ReleasePublishRename.c
publish_delete_source=${script_dir}/InstallerBoundDelete.c
publish_rename_helper=${build_root}/release-publish-rename
publish_delete_helper=${build_root}/release-publish-delete
if [[ ! -f ${publish_rename_source} || -L ${publish_rename_source} \
    || ! -f ${publish_delete_source} || -L ${publish_delete_source} ]]; then
  print -u2 'Portable publish helper source is missing or symbolic.'
  exit 1
fi
xcrun clang -std=c17 -Wall -Wextra -Werror -O2 \
  ${publish_rename_source} -o ${publish_rename_helper}
xcrun clang -std=c17 -Wall -Wextra -Werror -O2 \
  ${publish_delete_source} -o ${publish_delete_helper}

rollback_quarantine=$(mktemp -d "${portable_output_root}/.keep-vault-portable-rollback.XXXXXXXX")
chmod 0700 ${rollback_quarantine}
rollback_quarantine_identity=$(stat -f '%d:%i' ${rollback_quarantine})

delete_published_expected() {
  local published_path=$1
  local expected_identity=$2
  [[ ${published_path:h} == ${portable_output_root} ]] || return 64
  ${publish_delete_helper} \
    ${portable_output_root} ${published_path:t} \
    ${portable_output_identity%%:*} ${portable_output_identity#*:} \
    ${rollback_quarantine} \
    ${rollback_quarantine_identity%%:*} ${rollback_quarantine_identity#*:} \
    ${expected_identity}
}

cleanup() {
  set +e
  if (( ! ${publish_committed:-0} )); then
    local published_index=${#published_paths[@]}
    local current_identity=''
    while (( published_index >= 1 )); do
      current_identity=$(stat -f '%d:%i' ${published_paths[${published_index}]} 2>/dev/null || true)
      if [[ ! -e ${published_paths[${published_index}]} \
          && ! -L ${published_paths[${published_index}]} ]]; then
        :
      elif [[ ${current_identity} != ${published_identities[${published_index}]} ]]; then
        print -u2 "Portable rollback left a concurrently created destination untouched: ${published_paths[${published_index}]}"
      elif ! delete_published_expected \
          ${published_paths[${published_index}]} \
          ${published_identities[${published_index}]}; then
        print -u2 "Portable rollback preserved a substituted or undeletable object in: ${rollback_quarantine}"
      fi
      (( --published_index ))
    done
  fi
  if [[ -n ${release_stage:-} && -n ${release_stage_identity:-} \
      && ${release_stage:h} == ${portable_output_root} \
      && ( -e ${release_stage} || -L ${release_stage} ) ]]; then
    if [[ $(stat -f '%d:%i' ${release_stage} 2>/dev/null || true) != ${release_stage_identity} ]]; then
      print -u2 "Portable staging cleanup left a replacement pathname untouched: ${release_stage}"
    elif ! delete_published_expected ${release_stage} ${release_stage_identity}; then
      print -u2 "Portable staging cleanup preserved an identity mismatch in: ${rollback_quarantine}"
    fi
  fi
  if [[ -d ${rollback_quarantine:-} && ! -L ${rollback_quarantine:-} \
      && $(stat -f '%d:%i' ${rollback_quarantine} 2>/dev/null || true) == ${rollback_quarantine_identity:-invalid} \
      && -z $(find ${rollback_quarantine} -mindepth 1 -print -quit 2>/dev/null) ]]; then
    rmdir -- ${rollback_quarantine}
  else
    print -u2 "Portable rollback quarantine was replaced or is nonempty and was preserved: ${rollback_quarantine:-missing}"
  fi
  if [[ -d ${build_root:-} && ! -L ${build_root:-} \
      && ${build_root} == ${TMPDIR:-/tmp}/keep-vault-portable.* \
      && $(stat -f '%d:%i' ${build_root} 2>/dev/null || true) == ${build_root_identity:-invalid} ]]; then
    rm -rf -- ${build_root}
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Publish each already-verified top-level artifact with a descriptor-relative,
# identity-checked RENAME_EXCL. The rollback trap removes a partial set only
# through the same no-follow, expected-inode deletion helper as the installer.
publish_exclusively() {
  local staged_path=$1
  local final_path=$2
  [[ ! -L ${staged_path} && ( -f ${staged_path} || -d ${staged_path} ) \
      && ${staged_path:h} == ${release_stage} \
      && ${final_path:h} == ${portable_output_root} ]] || {
    print -u2 "Refusing to publish an unbound or special portable artifact: ${staged_path}"
    return 1
  }
  local staged_identity=''
  staged_identity=$(stat -f '%d:%i' ${staged_path} 2>/dev/null) || {
    print -u2 "Portable stage has no readable identity: ${staged_path}"
    return 1
  }
  if [[ ! ${staged_identity} =~ '^[0-9]+:[0-9]+$' ]]; then
    print -u2 "Portable stage returned an invalid identity: ${staged_path}"
    return 1
  fi
  published_paths+=(${final_path})
  published_identities+=(${staged_identity})
  local rename_status=0
  if ${publish_rename_helper} exclusive \
      ${release_stage} ${staged_path:t} \
      ${portable_output_root} ${final_path:t} \
      ${release_stage_identity} ${portable_output_identity} \
      ${staged_identity} -; then
    rename_status=0
  else
    rename_status=$?
    # Exit 70 means the atomic rename completed but its compensating identity
    # rollback could not prove a clean namespace. Remove whichever object is
    # currently public into the private quarantine. A mismatching inode is
    # preserved there by InstallerBoundDelete instead of being destroyed.
    if (( rename_status == 70 )) \
        && [[ -e ${final_path} || -L ${final_path} ]]; then
      local uncertain_cleanup_status=0
      delete_published_expected ${final_path} ${staged_identity} \
        || uncertain_cleanup_status=$?
      if (( uncertain_cleanup_status != 0 && uncertain_cleanup_status != 68 )); then
        print -u2 "Portable publication left an uncertain public pathname that could not be quarantined: ${final_path}"
      fi
    fi
    return ${rename_status}
  fi
  [[ ! -L ${final_path} && $(stat -f '%d:%i' ${final_path}) == ${staged_identity} ]] || {
    print -u2 "Published portable artifact changed identity: ${final_path}"
    return 1
  }
}

# --- Standalone release verifier -------------------------------------------
verifier_slices=()
verifier_runtimes=(osx-arm64)
[[ ${architecture} == universal ]] && verifier_runtimes+=(osx-x64)
# The verifier lock file intentionally covers the complete macOS RID graph.
# Restoring once without narrowing --runtime keeps that locked graph identical;
# a per-slice restore rewrites the evaluated RID set and correctly fails NU1004.
(
  cd ${repo_root}/KeepVaultMac.ReleaseVerifier
  ${dotnet_command} restore ${verifier_project} \
    --locked-mode \
    --nologo
)
for runtime in ${verifier_runtimes[@]}; do
  publish_dir=${build_root}/verifier-${runtime}
  (
    cd ${repo_root}/KeepVaultMac.ReleaseVerifier
    # NativeAOT runtime packs are part of the locked graph restored above.
    # Publish is now incapable of reaching NuGet or changing that graph.
    ${dotnet_command} publish ${verifier_project} \
      -c Release \
      -r ${runtime} \
      --no-restore \
      --self-contained true \
      --nologo \
      -p:PublishAot=true \
      -p:PublishTrimmed=true \
      -p:StripSymbols=true \
      -o ${publish_dir}
  )
  slice=${publish_dir}/Keep\ Vault\ Release\ Verifier
  [[ -f ${slice} && ! -L ${slice} ]] || {
    print -u2 "The NativeAOT verifier was not produced for ${runtime}."
    exit 1
  }
  verifier_slices+=(${slice})
done

verifier_path=${build_root}/Keep\ Vault\ Release\ Verifier
if (( ${#verifier_slices} > 1 )); then
  xcrun lipo -create ${verifier_slices[@]} -output ${verifier_path}
  xcrun lipo ${verifier_path} -verify_arch arm64 x86_64
else
  ditto ${verifier_slices[1]} ${verifier_path}
fi
chmod 0755 ${verifier_path}
codesign \
  --force \
  --sign ${identity} \
  --options runtime \
  ${codesign_timestamp_arguments[@]} \
  --identifier ${bundle_identifier}.releaseverifier \
  ${verifier_path}
codesign --verify --strict ${verifier_path}

# --- Portable folder --------------------------------------------------------
final_portable_dir=${portable_output_root}/${output_name}
final_portable_zip=${portable_output_root}/${output_name}.zip
for existing in ${final_portable_dir} ${final_portable_zip} ${final_portable_zip}.sha3 ${final_portable_zip}.skein \
    ${final_portable_zip}.khsig ${final_portable_zip}.sha3.khsig ${final_portable_zip}.skein.khsig; do
  if [[ -e ${existing} || -L ${existing} ]]; then
    print -u2 "Refusing to overwrite an existing portable artifact: ${existing}"
    exit 1
  fi
done

release_stage=$(mktemp -d "${portable_output_root}/.keep-vault-portable-publish.XXXXXXXX")
chmod 0700 ${release_stage}
release_stage_identity=$(stat -f '%d:%i' ${release_stage})
portable_dir=${release_stage}/${output_name}
portable_zip=${release_stage}/${output_name}.zip
mkdir -p ${portable_dir}
ditto ${source_app} ${portable_dir}/Keep\ Vault.app

# The launcher's dual signature covers the bundle's main executable, whose bytes
# codesign rewrites when it seals the bundle — so it cannot live inside. It sits
# beside the app and is checked at every launch; without it the app refuses to
# start, which makes it part of the portable payload.
for launcher_sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
  launcher_sidecar=${source_app}.launcher${launcher_sidecar_suffix}
  if [[ ! -f ${launcher_sidecar} || -L ${launcher_sidecar} ]]; then
    print -u2 "The launcher self-signature is missing from the source: ${launcher_sidecar:t}"
    exit 1
  fi
  ditto ${launcher_sidecar} ${portable_dir}/Keep\ Vault.app.launcher${launcher_sidecar_suffix}
done
ditto ${verifier_path} ${portable_dir}/Keep\ Vault\ Release\ Verifier

# The QR scanner always rides along. It is a separate program
# with its own identifier, signature and sandbox, and shares no code with Keep
# Vault — it travels in the same package only because the two are used together
# and are released under one matching version/build pair.
ditto ${scanner_app} ${portable_dir}/QR-Scanner.app
codesign --verify --strict --verbose=2 ${portable_dir}/QR-Scanner.app
print "bundled_scanner=${portable_dir}/QR-Scanner.app"

props=${mac_project}/Directory.Build.props
read_pin() {
  /usr/bin/sed -n "s|.*<$1>\(.*\)</$1>.*|\1|p" ${props} | head -1
}

cat > ${portable_dir}/PORTABLE_README.txt <<README
Keep Vault Portable (macOS)
===========================

Start:
  Keep Vault.app
  Keep Vault.app.launcher.khsig (plus .sha3/.skein sidecars)

Reading the printed QR codes:
  QR-Scanner.app — a separate, sandboxed program. Keep Vault itself never
  touches the camera and declares no hardware capability at all.

This folder is self-contained for macOS ${architecture} and requires no
installer and no .NET runtime. Keep the app bundle, the verifier, and the
.sha3, .skein and .khsig files together.

Check the download before launching anything:
  From the directory that contains both the portable folder and its ZIP:
  "./${output_name}/Keep Vault Release Verifier" "./${output_name}.zip"
  "./${output_name}/Keep Vault Release Verifier" "./${output_name}/Keep Vault.app"

Every executable carries an Apple code signature bound to the pinned Team ID
below, plus a detached RSA-PSS/SHA-512 and ML-DSA-87 signature. The hash
manifests are signed the same way. Verification requires BOTH signatures: the
classical RSA one and the post-quantum ML-DSA-87 one.

Because macOS reserves Contents/MacOS for executables, the detached manifests
and signatures live in Contents/Resources/HybridSignatures, mirroring the
layout below Contents/MacOS.

Pinned Apple Team ID: ${team_identifier}
Pinned RSA SHA-256(SPKI): $(read_pin KalynaExpectedSignerSha256)
Pinned RSA SHA3-512(SPKI): $(read_pin KalynaExpectedSignerSha3_512)
Pinned RSA Skein-1024(SPKI): $(read_pin KalynaExpectedSignerSkein1024)
Pinned ML-DSA-87 SHA-256: $(read_pin KalynaExpectedMldsa87Sha256)
Pinned ML-DSA-87 SHA3-512: $(read_pin KalynaExpectedMldsa87Sha3_512)
Pinned ML-DSA-87 Skein-1024: $(read_pin KalynaExpectedMldsa87Skein1024)

Signing status:
  ${portable_signing_description}
The app accepts only its exact compiled pins regardless.

macOS cannot enforce an application-level exclusion from screenshots or screen
recording the way Windows can. Keep Vault conceals secret views when it is
deactivated, but capture prevention cannot be guaranteed on this platform.
README

# The hybrid signer and its scratch keychain are resolved once here: the scanner
# is signed before the archive is built, and the archive is signed after, so both
# steps need them.
signer_dll=${packaging_dir}/HybridSigner/bin/Release/net10.0/KeepVaultMac.HybridSigner.dll
(
  cd ${mac_project}
  ${dotnet_command} restore Packaging/HybridSigner/KeepVaultMac.HybridSigner.csproj \
    --locked-mode \
    --nologo
  ${dotnet_command} build Packaging/HybridSigner/KeepVaultMac.HybridSigner.csproj \
    -c Release \
    --no-restore \
    --nologo
)
[[ -f ${signer_dll} && ! -L ${signer_dll} ]] || {
  print -u2 'The locked HybridSigner build did not produce its release assembly.'
  exit 1
}
keychain_temp=${build_root}/keychain-temp
mkdir -p ${keychain_temp}

# Everything in the package that is executable code gets the same post-quantum
# pair, so no component rests on Apple's signature alone. That includes the
# verifier itself: a tool that vouches for the rest while carrying no signature
# of its own is the obvious thing to replace.
#
# The scanner's sidecars go beside its bundle rather than inside it. Apple's
# seal covers Contents/Resources, so a file added there afterwards would
# invalidate the very signature it sits under -- the same reason the launcher's
# own signature lives outside the bundle.
package_signature_arguments=(
  ${signer_dll}
  sign
  --pfx ${pfx_path}
  ${mldsa_key_arguments[@]}
  ${pfx_password_arguments[@]}
  --mldsa-public-key ${mldsa_public_key}
  --reference-library ${mac_project}/Native/osx-arm64/libmldsa87_ref.dylib
  --policy ${props}
  --launcher-pins ${build_root}/PackageHybridPins.swift
  --target ${portable_dir}/Keep\ Vault\ Release\ Verifier
)
package_signature_arguments+=(--target ${portable_dir}/QR-Scanner.app/Contents/MacOS/QR-Scanner)
if [[ -n ${pfx_password_service} ]]; then
  package_signature_arguments+=(--pfx-password-keychain-service ${pfx_password_service})
  [[ -n ${pfx_password_account} ]] && package_signature_arguments+=(--pfx-keychain-account ${pfx_password_account})
fi
(
  cd ${mac_project}
  TMPDIR=${keychain_temp} \
    KEEPVAULT_KEYCHAIN_TEMP_ROOT=${keychain_temp} \
    DOTNET_EnableDiagnostics=0 \
    ${dotnet_command} ${package_signature_arguments[@]}
)
print "verifier_dual_signature=${portable_dir}/Keep Vault Release Verifier.khsig"

scanner_sidecar_source=${portable_dir}/QR-Scanner.app/Contents/MacOS/QR-Scanner
for sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
  if [[ ! -f ${scanner_sidecar_source}${sidecar_suffix} ]]; then
    print -u2 "The scanner's dual signature is incomplete: ${sidecar_suffix}"
    exit 1
  fi
  mv -- ${scanner_sidecar_source}${sidecar_suffix} ${portable_dir}/QR-Scanner.app${sidecar_suffix}
done

# Moving the sidecars out again leaves the bundle byte-identical to what Apple
# sealed, which this re-check proves rather than assumes.
codesign --verify --strict --verbose=2 ${portable_dir}/QR-Scanner.app
print "scanner_dual_signature=${portable_dir}/QR-Scanner.app.khsig"

# --- Archive, manifests, hybrid signatures ----------------------------------
# Signing the archive also emits its SHA3-512 and Skein-1024 manifests and signs
# those in turn, so all five sidecars appear next to the ZIP.
ditto -c -k --sequesterRsrc --keepParent ${portable_dir} ${portable_zip}

signer_arguments=(
  ${signer_dll}
  sign
  --pfx ${pfx_path}
  ${mldsa_key_arguments[@]}
  ${pfx_password_arguments[@]}
  --mldsa-public-key ${mldsa_public_key}
  --reference-library ${mac_project}/Native/osx-arm64/libmldsa87_ref.dylib
  --policy ${props}
  --launcher-pins ${build_root}/HybridPins.swift
  --target ${portable_zip}
)
if [[ -n ${pfx_password_service} ]]; then
  signer_arguments+=(--pfx-password-keychain-service ${pfx_password_service})
  [[ -n ${pfx_password_account} ]] && signer_arguments+=(--pfx-keychain-account ${pfx_password_account})
fi

(
  cd ${mac_project}
  TMPDIR=${keychain_temp} \
    KEEPVAULT_KEYCHAIN_TEMP_ROOT=${keychain_temp} \
    DOTNET_EnableDiagnostics=0 \
    ${dotnet_command} ${signer_arguments[@]}
)

# --- Final gate -------------------------------------------------------------
# Check the shipped artifacts with the verifier that ships alongside them, so a
# release cannot be published unless its own tool accepts it.
${portable_dir}/Keep\ Vault\ Release\ Verifier ${portable_zip}
${portable_dir}/Keep\ Vault\ Release\ Verifier ${portable_dir}/Keep\ Vault.app
# The whole folder, which is what a user actually points the tool at: it covers
# the scanner and the verifier as well and refuses any executable that has no
# signature.
${portable_dir}/Keep\ Vault\ Release\ Verifier ${portable_dir}

if (( development_build )); then
  portable_notarization_status='notarization=not_performed (Apple Development output is confined to build/dev)'
else
  # The two application bundles arrive already stapled from their respective
  # release builds. The final ZIP is then submitted exactly as it will be
  # published, which also registers the loose Developer-ID verifier with
  # Gatekeeper. A ZIP cannot itself carry a staple ticket, so stapling is
  # validated on both contained apps and spctl is required for all executables.
  xcrun stapler validate ${portable_dir}/Keep\ Vault.app
  xcrun stapler validate ${portable_dir}/QR-Scanner.app
  xcrun notarytool submit ${portable_zip} \
    --keychain-profile ${notary_profile} \
    --wait
  spctl --assess --type execute --verbose=4 ${portable_dir}/Keep\ Vault.app
  spctl --assess --type execute --verbose=4 ${portable_dir}/QR-Scanner.app
  spctl --assess --type execute --verbose=4 ${portable_dir}/Keep\ Vault\ Release\ Verifier
  portable_notarization_status="notarization=accepted-and-apps-stapled (${notary_profile})"
fi

# Nothing becomes visible at a release name before all gates above pass.
# Publish the directory last. If any no-replace rename fails or the process is
# interrupted, the EXIT trap removes only already-published objects whose
# device/inode still matches this private stage, leaving no partial release.
for portable_suffix in '' .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
  publish_exclusively ${portable_zip}${portable_suffix} ${final_portable_zip}${portable_suffix}
done
publish_exclusively ${portable_dir} ${final_portable_dir}
publish_committed=1

print "portable_folder=${final_portable_dir}"
print "portable_archive=${final_portable_zip}"
print "verifier=${final_portable_dir}/Keep Vault Release Verifier"
print ${portable_notarization_status}
