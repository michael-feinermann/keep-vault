#!/bin/zsh -f
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
PATH='/usr/bin:/bin:/usr/sbin:/sbin'
export PATH
unset ZDOTDIR ENV BASH_ENV CDPATH PERL5OPT PERL5LIB PYTHONHOME PYTHONPATH \
  RUBYOPT RUBYLIB NODE_OPTIONS OPENSSL_CONF OPENSSL_MODULES SSL_CERT_FILE \
  SSL_CERT_DIR CURL_HOME XDG_CONFIG_HOME
unset DEVELOPER_DIR SDKROOT TOOLCHAINS
unset CCC_OVERRIDE_OPTIONS COMPILER_PATH CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH \
  OBJC_INCLUDE_PATH LIBRARY_PATH GCC_EXEC_PREFIX ADDITIONAL_SWIFT_DRIVER_FLAGS \
  SWIFT_EXEC SWIFT_DRIVER_SWIFT_FRONTEND_EXEC SWIFT_DRIVER_SWIFTSCAN_LIB \
  SWIFT_DRIVER_TOOLCHAIN_CASPLUGIN_LIB DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
  DYLD_FRAMEWORK_PATH DYLD_FALLBACK_LIBRARY_PATH DYLD_FALLBACK_FRAMEWORK_PATH
unset DOTNET_STARTUP_HOOKS DOTNET_ADDITIONAL_DEPS DOTNET_SHARED_STORE DOTNET_ROOT \
  DOTNET_ROOT_X64 DOTNET_ROOT_ARM64 DOTNET_HOST_PATH DOTNET_DiagnosticPorts \
  DOTNET_DefaultDiagnosticPortSuspend DOTNET_ROLL_FORWARD \
  DOTNET_ROLL_FORWARD_ON_NO_CANDIDATE_FX DOTNET_ROLL_FORWARD_TO_PRERELEASE \
  DOTNET_MULTILEVEL_LOOKUP CORECLR_ENABLE_PROFILING CORECLR_PROFILER \
  CORECLR_PROFILER_PATH CORECLR_PROFILER_PATH_32 CORECLR_PROFILER_PATH_64 \
  CORECLR_PROFILER_PATH_ARM64 COR_ENABLE_PROFILING COR_PROFILER \
  COR_PROFILER_PATH COR_PROFILER_PATH_32 COR_PROFILER_PATH_64 \
  COMPlus_AltJit COMPlus_AltJitName DOTNET_AltJit DOTNET_AltJitName \
  MSBuildSDKsPath MSBUILD_EXE_PATH MSBuildExtensionsPath \
  MSBuildExtensionsPath32 MSBuildExtensionsPath64 MSBuildUserExtensionsPath \
  MSBuildToolsPath MSBuildBinPath MSBUILDLEGACYEXTENSIONSPATH \
  MSBUILDADDITIONALSDKRESOLVERSFOLDER CustomBeforeMicrosoftCommonTargets \
  CustomAfterMicrosoftCommonTargets CustomBeforeMicrosoftCSharpTargets \
  CustomAfterMicrosoftCSharpTargets DirectoryBuildPropsPath \
  DirectoryBuildTargetsPath ImportDirectoryBuildProps ImportDirectoryBuildTargets \
  DOTNET_MSBUILD_SDK_RESOLVER_CLI_DIR DOTNET_MSBUILD_SDK_RESOLVER_SDKS_DIR \
  DOTNET_MSBUILD_SDK_RESOLVER_SDKS_VER NUGET_PLUGIN_PATHS \
  NUGET_CREDENTIALPROVIDERS_PATH NUGET_EXTENSIONS_PATH NUGET_PACKAGES \
  NUGET_HTTP_CACHE_PATH NUGET_SCRATCH RestoreSources \
  RestoreAdditionalProjectSources RestoreFallbackFolders RestorePackagesPath \
  RestoreConfigFile
export DOTNET_EnableDiagnostics=0 COMPlus_EnableDiagnostics=0

env_path=/usr/bin/env
private_temp_parent=/private/tmp

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
mldsa_private_key_encrypted=${KEEPVAULT_MLDSA_PRIVATE_KEY_ENCRYPTED:-${HOME}/Library/Application Support/Keep Vault/ReleaseKeys/mldsa87-private.key.v12.enc}
pfx_password_encrypted=${KEEPVAULT_PFX_PASSWORD_ENCRYPTED:-${pfx_path}.password.v12.enc}
mldsa_wrapping_service=${KEEPVAULT_MLDSA_WRAPPING_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.v12.mldsa-wrapping-key}
mldsa_wrapping_account=${KEEPVAULT_MLDSA_WRAPPING_KEYCHAIN_ACCOUNT:-keep-vault-mldsa-v12:${USER:-}}
pfx_wrapping_service=${KEEPVAULT_PFX_WRAPPING_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.v12.pfx-wrapping-key}
pfx_wrapping_account=${KEEPVAULT_PFX_WRAPPING_KEYCHAIN_ACCOUNT:-keep-vault-pfx-v12:${USER:-}}

mldsa_public_key=${KEEPVAULT_MLDSA_PUBLIC_KEY:-${packaging_dir}/Keys/mldsa87-public.key}
dotnet_command=''
source_app=${repo_root}/dist/Keep\ Vault-macOS/Keep\ Vault.app
scanner_app=${repo_root}/QrCodeScanner/dist/QR-Scanner.app

usage() {
  print -u2 'Usage: Build-Portable-macOS.sh [--app "Keep Vault.app"] [--scanner "QR-Scanner.app"]'
  print -u2 '       [--identity HASH] [--notary-profile NOTARYTOOL_KEYCHAIN_PROFILE]'
  print -u2 '       [--output-name NAME] [--self-test-rollback]'
  print -u2 '       [--architecture universal|arm64]'
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
if [[ ! -x ${env_path} || -L ${env_path} \
    || $(/usr/bin/stat -f '%u' ${env_path} 2>/dev/null || print invalid) != 0 \
    || $(( 8#$(/usr/bin/stat -f '%Lp' ${env_path}) & 8#022 )) != 0 ]]; then
  print -u2 'Portable release requires the physical root-owned /usr/bin/env.'
  exit 2
fi
private_temp_uid=$(/usr/bin/stat -f '%u' ${private_temp_parent} 2>/dev/null || print invalid)
private_temp_mode=$(( 8#$(/usr/bin/stat -f '%p' ${private_temp_parent} 2>/dev/null || print 0) & 8#7777 ))
if [[ ! -d ${private_temp_parent} || -L ${private_temp_parent} \
    || ${private_temp_uid} != 0 ]] || (( private_temp_mode != 8#1777 )); then
  print -u2 'Portable release requires physical root-owned mode-1777 /private/tmp.'
  exit 2
fi
for required_command in xcrun codesign security ditto shasum lipo openssl spctl; do
  command -v ${required_command} >/dev/null 2>&1 || {
    print -u2 "Required release tool is unavailable: ${required_command}"
    exit 1
  }
done
shasum() { ${env_path} -i PATH=${PATH} /usr/bin/shasum "$@"; }

if ! zmodload zsh/system || ! zmodload -F zsh/stat b:zstat; then
  print -u2 'Portable release requires zsh descriptor/stat modules.'
  exit 2
fi

expected_third_party_notices_sha256='bd4bd21c7ffa79d36a4f20abb6b7af3116fc005d3971ca0be09b49e083d6f159'

portable_notice_fd_identity() {
  local descriptor=$1
  local -A descriptor_stat
  local -A modification_time
  local -A change_time
  zstat -f ${descriptor} -H descriptor_stat 2>/dev/null || return 2
  zstat -f ${descriptor} -H modification_time -F '%s.%N' +mtime 2>/dev/null || return 2
  zstat -f ${descriptor} -H change_time -F '%s.%N' +ctime 2>/dev/null || return 2
  print -r -- \
    ${descriptor_stat[device]}:${descriptor_stat[inode]}:${descriptor_stat[uid]}:${descriptor_stat[mode]}:${descriptor_stat[nlink]}:${descriptor_stat[size]}:${modification_time[mtime]}:${change_time[ctime]}
}

hash_portable_notice_fd() {
  local descriptor=$1
  local digest_line=''
  sysseek -u ${descriptor} -w start 0 || return 2
  if ! digest_line=$(shasum -a 256 <&${descriptor}); then
    sysseek -u ${descriptor} -w start 0 2>/dev/null || true
    return 2
  fi
  sysseek -u ${descriptor} -w start 0 || return 2
  REPLY=${digest_line%%[[:space:]]*}
  (( ${#REPLY} == 64 )) && [[ ${REPLY} != *[^0-9a-f]* ]]
}

copy_portable_root_notice() (
  emulate -L zsh
  set -euo pipefail
  local source=$1
  local destination=$2
  local expected_sha256=$3
  local source_fd=-1
  local destination_fd=-1

  sysopen -r -o nofollow -u source_fd ${source} || {
    print -u2 'Portable release could not open its in-app notice without following a symbolic link.'
    return 2
  }
  local source_before=$(portable_notice_fd_identity ${source_fd}) || return 2
  local -a source_fields=("${(@s.:.)source_before}")
  local source_mode=${source_fields[4]}
  if (( (source_mode & 8#170000) != 8#100000 \
      || (source_mode & 8#022) != 0 || source_fields[5] != 1 \
      || source_fields[6] < 300000 || source_fields[6] > 2000000 )) \
      || [[ ${source_fields[3]} != 0 && ${source_fields[3]} != ${EUID} ]]; then
    print -u2 'Portable release in-app notice has unsafe descriptor metadata.'
    return 2
  fi
  hash_portable_notice_fd ${source_fd} || return 2
  [[ ${REPLY} == ${expected_sha256} ]] || {
    print -u2 'Portable release in-app notice does not match the reviewed whole-file digest.'
    return 2
  }

  if [[ -e ${destination} || -L ${destination} ]] \
      || ! sysopen -rw -m 0600 -o create,excl,nofollow,sync \
        -u destination_fd ${destination}; then
    print -u2 'Portable release root notice could not be created exclusively.'
    return 2
  fi
  chmod 0600 /dev/fd/${destination_fd}
  local destination_before=$(portable_notice_fd_identity ${destination_fd}) || return 2
  local -a destination_fields=("${(@s.:.)destination_before}")
  local destination_object=${destination_fields[1]}:${destination_fields[2]}:${destination_fields[3]}:${destination_fields[5]}
  local destination_mode=${destination_fields[4]}
  if [[ ${destination_fields[3]} != ${EUID} || ${destination_fields[5]} != 1 ]] \
      || (( (destination_mode & 8#170000) != 8#100000 \
          || (destination_mode & 8#0777) != 8#0600 )); then
    print -u2 'Portable release root notice output has unsafe descriptor metadata.'
    return 2
  fi

  local transfer_status=0
  while true; do
    if sysread -i ${source_fd} -o ${destination_fd} -s 65536; then
      continue
    else
      transfer_status=$?
    fi
    (( transfer_status == 5 )) && break
    print -u2 'Portable release root notice failed during descriptor-bound copy.'
    return 2
  done

  local source_after=$(portable_notice_fd_identity ${source_fd}) || return 2
  hash_portable_notice_fd ${source_fd} || return 2
  if [[ ${source_after} != ${source_before} || ${REPLY} != ${expected_sha256} ]]; then
    print -u2 'Portable release in-app notice changed during descriptor-bound copy.'
    return 2
  fi

  chmod 0644 /dev/fd/${destination_fd}
  local output_before_hash=$(portable_notice_fd_identity ${destination_fd}) || return 2
  local -a output_fields=("${(@s.:.)output_before_hash}")
  local output_mode=${output_fields[4]}
  if [[ ${output_fields[1]}:${output_fields[2]}:${output_fields[3]}:${output_fields[5]} != ${destination_object} ]] \
      || (( (output_mode & 8#170000) != 8#100000 \
          || (output_mode & 8#0777) != 8#0644 \
          || output_fields[6] < 300000 || output_fields[6] > 2000000 )); then
    print -u2 'Portable release root notice output changed identity.'
    return 2
  fi
  hash_portable_notice_fd ${destination_fd} || return 2
  [[ ${REPLY} == ${expected_sha256} ]] || {
    print -u2 'Portable release root notice does not match the reviewed whole-file digest.'
    return 2
  }
  local output_after_hash=$(portable_notice_fd_identity ${destination_fd}) || return 2
  local -A output_path_stat
  zstat -L -H output_path_stat ${destination} 2>/dev/null || return 2
  if [[ ${output_after_hash} != ${output_before_hash} \
      || ${output_path_stat[device]}:${output_path_stat[inode]}:${output_path_stat[uid]}:${output_path_stat[nlink]} != ${destination_object} ]] \
      || (( (output_path_stat[mode] & 8#170000) != 8#100000 )); then
    print -u2 'Portable release root notice changed during its final bound hash.'
    return 2
  fi
)

if [[ -z ${USER:-} || -z ${mldsa_wrapping_service} || -z ${mldsa_wrapping_account} \
    || -z ${pfx_wrapping_service} || -z ${pfx_wrapping_account} \
    || ${mldsa_wrapping_service} == ${pfx_wrapping_service} \
    || ${mldsa_wrapping_account} == ${pfx_wrapping_account} ]]; then
  print -u2 'RSA and ML-DSA need distinct, nonempty Keychain services and accounts.'
  exit 2
fi
pfx_path=${pfx_path:A}
mldsa_private_key_encrypted=${mldsa_private_key_encrypted:A}
pfx_password_encrypted=${pfx_password_encrypted:A}
for private_path in ${pfx_path} ${mldsa_private_key_encrypted} ${pfx_password_encrypted}; do
  if [[ ${private_path} == ${repo_root}/* \
      || ! -f ${private_path} || -L ${private_path} ]]; then
    print -u2 "Private signing material is missing, symbolic, or inside the repository: ${private_path}"
    exit 2
  fi
  private_mode=$(( 8#$(stat -f %Lp ${private_path}) ))
  if (( (private_mode & 8#077) != 0 )); then
    print -u2 "Private signing material must be mode 0600 or stricter: ${private_path}"
    exit 2
  fi
done

KEEPVAULT_MLDSA_PRIVATE_KEY_ENCRYPTED=${mldsa_private_key_encrypted} \
KEEPVAULT_PFX_PASSWORD_ENCRYPTED=${pfx_password_encrypted} \
KEEPVAULT_MLDSA_WRAPPING_KEYCHAIN_SERVICE=${mldsa_wrapping_service} \
KEEPVAULT_MLDSA_WRAPPING_KEYCHAIN_ACCOUNT=${mldsa_wrapping_account} \
KEEPVAULT_PFX_WRAPPING_KEYCHAIN_SERVICE=${pfx_wrapping_service} \
KEEPVAULT_PFX_WRAPPING_KEYCHAIN_ACCOUNT=${pfx_wrapping_account} \
  ${script_dir}/Protect-HybridKeys-macOS.sh --verify-only

mldsa_key_arguments=(
  --mldsa-private-key-encrypted ${mldsa_private_key_encrypted}
  --mldsa-wrapping-key-keychain-service ${mldsa_wrapping_service}
  --mldsa-wrapping-key-keychain-account ${mldsa_wrapping_account}
)
pfx_password_arguments=(
  --pfx-password-encrypted ${pfx_password_encrypted}
  --pfx-wrapping-key-keychain-service ${pfx_wrapping_service}
  --pfx-wrapping-key-keychain-account ${pfx_wrapping_account}
)

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

build_root=$(mktemp -d "${private_temp_parent}/keep-vault-portable.XXXXXXXX")
chmod 0700 ${build_root}
build_root_identity=$(stat -f '%d:%i' ${build_root})
private_nuget_root=''
private_nuget_root_identity=''
private_nuget_packages=''
private_nuget_packages_identity=''
private_nuget_http_cache=''
private_nuget_http_cache_identity=''
private_nuget_scratch=''
private_nuget_scratch_identity=''
private_dotnet_cli_home=''
private_dotnet_cli_home_identity=''
private_dotnet_tmp=''
private_dotnet_tmp_identity=''
private_artifacts_root=''
private_artifacts_root_identity=''
private_verifier_artifacts=''
private_verifier_artifacts_identity=''
private_signer_artifacts=''
private_signer_artifacts_identity=''
verified_dotnet_root=''
verified_dotnet_root_identity=''
dotnet_command_identity=''
signer_dll=''
signer_dll_identity=''
release_stage=''
release_stage_identity=''
published_paths=()
published_identities=()
publish_committed=0

# Install an identity-bound cleanup before SDK/cache provisioning. The fuller
# rollback handler below replaces this function once public staging state
# exists, while the trap continues to resolve the current definition.
cleanup() {
  set +e
  if [[ -d ${build_root:-} && ! -L ${build_root:-} \
      && ${build_root} == ${private_temp_parent}/keep-vault-portable.* \
      && $(stat -f '%d:%i' ${build_root} 2>/dev/null || print invalid) == ${build_root_identity:-invalid} ]]; then
    rm -rf -- ${build_root}
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

require_private_directory_identity() {
  local directory=$1
  local expected_identity=$2
  [[ -n ${directory} && -d ${directory} && ! -L ${directory} \
      && $(stat -f '%d:%i' ${directory} 2>/dev/null || print invalid) == ${expected_identity} \
      && $(stat -f '%u:%Lp' ${directory} 2>/dev/null || print invalid) == ${EUID}:700 ]]
}

require_private_nuget_cache_identity() {
  require_private_directory_identity ${build_root} ${build_root_identity} \
    && require_private_directory_identity ${private_nuget_root} ${private_nuget_root_identity} \
    && require_private_directory_identity ${private_nuget_packages} ${private_nuget_packages_identity} \
    && require_private_directory_identity ${private_nuget_http_cache} ${private_nuget_http_cache_identity} \
    && require_private_directory_identity ${private_nuget_scratch} ${private_nuget_scratch_identity} \
    && require_private_directory_identity ${private_dotnet_cli_home} ${private_dotnet_cli_home_identity} \
    && require_private_directory_identity ${private_dotnet_tmp} ${private_dotnet_tmp_identity} \
    && require_private_directory_identity ${private_artifacts_root} ${private_artifacts_root_identity} \
    && require_private_directory_identity ${private_verifier_artifacts} ${private_verifier_artifacts_identity} \
    && require_private_directory_identity ${private_signer_artifacts} ${private_signer_artifacts_identity} \
    && { [[ -z ${verified_dotnet_root} ]] \
      || { require_private_directory_identity ${verified_dotnet_root} ${verified_dotnet_root_identity} \
        && [[ -f ${dotnet_command} && ! -L ${dotnet_command} && -x ${dotnet_command} \
          && $(stat -f '%d:%i' ${dotnet_command} 2>/dev/null || print invalid) == ${dotnet_command_identity} ]]; }; }
}

create_private_nuget_cache() {
  private_nuget_root=${build_root}/nuget
  private_nuget_packages=${private_nuget_root}/packages
  private_nuget_http_cache=${private_nuget_root}/http-cache
  private_nuget_scratch=${private_nuget_root}/scratch
  private_dotnet_cli_home=${private_nuget_root}/cli-home
  private_dotnet_tmp=${private_nuget_root}/tmp
  private_artifacts_root=${build_root}/artifacts
  private_verifier_artifacts=${private_artifacts_root}/verifier
  private_signer_artifacts=${private_artifacts_root}/signer
  mkdir -m 0700 ${private_nuget_root} ${private_nuget_packages} \
    ${private_nuget_http_cache} ${private_nuget_scratch} \
    ${private_dotnet_cli_home} ${private_dotnet_tmp} ${private_artifacts_root} \
    ${private_verifier_artifacts} ${private_signer_artifacts}
  private_nuget_root_identity=$(stat -f '%d:%i' ${private_nuget_root})
  private_nuget_packages_identity=$(stat -f '%d:%i' ${private_nuget_packages})
  private_nuget_http_cache_identity=$(stat -f '%d:%i' ${private_nuget_http_cache})
  private_nuget_scratch_identity=$(stat -f '%d:%i' ${private_nuget_scratch})
  private_dotnet_cli_home_identity=$(stat -f '%d:%i' ${private_dotnet_cli_home})
  private_dotnet_tmp_identity=$(stat -f '%d:%i' ${private_dotnet_tmp})
  private_artifacts_root_identity=$(stat -f '%d:%i' ${private_artifacts_root})
  private_verifier_artifacts_identity=$(stat -f '%d:%i' ${private_verifier_artifacts})
  private_signer_artifacts_identity=$(stat -f '%d:%i' ${private_signer_artifacts})
  require_private_nuget_cache_identity || {
    print -u2 'Portable release failed to create its identity-bound private NuGet cache.'
    exit 2
  }
}

cleanup_private_nuget_cache() {
  require_private_nuget_cache_identity || {
    print -u2 'Portable private NuGet cache identity changed; preserving it for inspection.'
    return 1
  }
}

run_dotnet_clean() {
  require_private_nuget_cache_identity || {
    print -u2 'Portable private NuGet cache identity changed before a .NET invocation.'
    return 2
  }
  local dotnet_status=0
  ${env_path} -i \
    HOME=${private_dotnet_cli_home} \
    PATH=${PATH} \
    TMPDIR=${private_dotnet_tmp} \
    DOTNET_CLI_HOME=${private_dotnet_cli_home} \
    NUGET_PACKAGES=${private_nuget_packages} \
    NUGET_HTTP_CACHE_PATH=${private_nuget_http_cache} \
    NUGET_SCRATCH=${private_nuget_scratch} \
    DOTNET_EnableDiagnostics=0 \
    COMPlus_EnableDiagnostics=0 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
    DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=1 \
    DOTNET_GENERATE_ASPNET_CERTIFICATE=false \
    DOTNET_ADD_GLOBAL_TOOLS_TO_PATH=false \
    MSBUILDDISABLENODEREUSE=1 \
    ${dotnet_command} "$@" || dotnet_status=$?
  require_private_nuget_cache_identity || {
    print -u2 'Portable private NuGet cache identity changed during a .NET invocation.'
    return 2
  }
  return ${dotnet_status}
}

run_dotnet_signer_clean() {
  require_private_nuget_cache_identity \
    && require_private_directory_identity ${keychain_temp} ${keychain_temp_identity} \
    && [[ -n ${signer_dll} && ${signer_dll} == ${private_signer_artifacts}/* \
      && -f ${signer_dll} && ! -L ${signer_dll} \
      && $(stat -f '%d:%i:%u:%Lp:%z:%m:%c:%l' ${signer_dll} 2>/dev/null || print invalid) == ${signer_dll_identity} \
      && $(stat -f '%u:%l' ${signer_dll} 2>/dev/null || print invalid) == ${EUID}:1 ]] || {
      print -u2 'Portable signer scratch identity changed before execution.'
      return 2
    }
  local signer_status=0
  ${env_path} -i \
    PATH=${PATH} TMPDIR=${keychain_temp} \
    DOTNET_CLI_HOME=${private_dotnet_cli_home} \
    NUGET_PACKAGES=${private_nuget_packages} \
    NUGET_HTTP_CACHE_PATH=${private_nuget_http_cache} \
    NUGET_SCRATCH=${private_nuget_scratch} \
    KEEPVAULT_KEYCHAIN_TEMP_ROOT=${keychain_temp} \
    DOTNET_EnableDiagnostics=0 COMPlus_EnableDiagnostics=0 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
    DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=1 \
    DOTNET_GENERATE_ASPNET_CERTIFICATE=false \
    DOTNET_ADD_GLOBAL_TOOLS_TO_PATH=false MSBUILDDISABLENODEREUSE=1 \
    ${dotnet_command} "$@" || signer_status=$?
  require_private_nuget_cache_identity \
    && require_private_directory_identity ${keychain_temp} ${keychain_temp_identity} \
    && [[ -f ${signer_dll} && ! -L ${signer_dll} \
      && $(stat -f '%d:%i:%u:%Lp:%z:%m:%c:%l' ${signer_dll} 2>/dev/null || print invalid) == ${signer_dll_identity} \
      && $(stat -f '%u:%l' ${signer_dll} 2>/dev/null || print invalid) == ${EUID}:1 ]] || {
      print -u2 'Portable signer, scratch, or NuGet cache identity changed during execution.'
      return 2
    }
  return ${signer_status}
}

create_private_nuget_cache
dotnet_provisioner=${script_dir}/Provision-VerifiedDotnet-macOS.sh
if [[ ! -f ${dotnet_provisioner} || -L ${dotnet_provisioner} || ! -x ${dotnet_provisioner} ]]; then
  print -u2 'Portable release requires the physical verified .NET SDK provisioner.'
  exit 2
fi
verified_dotnet_target=${build_root}/dotnet-sdk
dotnet_command=$(${dotnet_provisioner} --target ${verified_dotnet_target})
verified_dotnet_root=${verified_dotnet_target}
verified_dotnet_root_identity=$(stat -f '%d:%i' ${verified_dotnet_root})
dotnet_command_identity=$(stat -f '%d:%i' ${dotnet_command})
require_private_nuget_cache_identity || {
  print -u2 'Portable release lost the freshly provisioned Microsoft SDK identity.'
  exit 2
}
selected_sdk=$(run_dotnet_clean --version)
if [[ ${selected_sdk} != '10.0.400' ]]; then
  print -u2 'Portable release builds require the reviewed official .NET SDK 10.0.400.'
  exit 2
fi

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
  if cleanup_private_nuget_cache \
      && [[ -d ${build_root:-} && ! -L ${build_root:-} \
      && ${build_root} == ${private_temp_parent}/keep-vault-portable.* \
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
  run_dotnet_clean restore ${verifier_project} \
    --artifacts-path ${private_verifier_artifacts} \
    --locked-mode \
    --force \
    --force-evaluate \
    --no-http-cache \
    --disable-build-servers \
    --nologo
  run_dotnet_clean restore ${packaging_dir}/HybridSigner/KeepVaultMac.HybridSigner.csproj \
    --artifacts-path ${private_signer_artifacts} \
    --locked-mode \
    --force \
    --force-evaluate \
    --no-http-cache \
    --disable-build-servers \
    --nologo
)
for runtime in ${verifier_runtimes[@]}; do
  publish_dir=${build_root}/verifier-${runtime}
  (
    cd ${repo_root}/KeepVaultMac.ReleaseVerifier
    # NativeAOT runtime packs are part of the locked graph restored above.
    # Publish is now incapable of reaching NuGet or changing that graph.
    run_dotnet_clean publish ${verifier_project} \
      -c Release \
      -r ${runtime} \
      --artifacts-path ${private_verifier_artifacts} \
      --no-restore \
      --self-contained true \
      --nologo \
      -p:PublishAot=true \
      -p:PublishTrimmed=true \
      -p:StripSymbols=true \
      -p:UseSharedCompilation=false \
      --disable-build-servers \
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
copy_portable_root_notice \
  ${portable_dir}/Keep\ Vault.app/Contents/Resources/THIRD-PARTY-NOTICES.txt \
  ${portable_dir}/THIRD-PARTY-NOTICES.txt \
  ${expected_third_party_notices_sha256}

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

Third-party licences:
  THIRD-PARTY-NOTICES.txt (the exact reviewed copy also sealed inside Keep Vault.app)

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
signer_dll=${private_signer_artifacts}/bin/KeepVaultMac.HybridSigner/release/KeepVaultMac.HybridSigner.dll
(
  cd ${mac_project}
  run_dotnet_clean build Packaging/HybridSigner/KeepVaultMac.HybridSigner.csproj \
    -c Release \
    --no-restore \
    --no-incremental \
    --artifacts-path ${private_signer_artifacts} \
    --disable-build-servers \
    -p:UseSharedCompilation=false \
    --nologo
)
[[ -f ${signer_dll} && ! -L ${signer_dll} ]] || {
  print -u2 'The locked HybridSigner build did not produce its release assembly.'
  exit 1
}
signer_dll_identity=$(stat -f '%d:%i:%u:%Lp:%z:%m:%c:%l' ${signer_dll})
if [[ $(stat -f '%u:%l' ${signer_dll} 2>/dev/null || print invalid) != ${EUID}:1 ]]; then
  print -u2 'The private HybridSigner assembly is not a single-link caller-owned file.'
  exit 2
fi
keychain_temp=${build_root}/keychain-temp
mkdir -m 0700 ${keychain_temp}
keychain_temp_identity=$(stat -f '%d:%i' ${keychain_temp})

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
(
  cd ${mac_project}
  run_dotnet_signer_clean ${package_signature_arguments[@]}
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
(
  cd ${mac_project}
  run_dotnet_signer_clean ${signer_arguments[@]}
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
