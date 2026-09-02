#!/bin/zsh -f
# Provisions and verifies the two independent v12 hybrid-signing envelopes.
#
# RSA-PSS and ML-DSA-87 are accepted only together, but their private material
# must not share a failure domain. This script therefore creates two unrelated
# 32-byte keys with Security.framework, two separately labelled prompt-only
# ACLs, two distinct service/account identities and two incompatible AES-GCM
# envelope formats. No wrapping key enters argv, stdout, an environment
# variable or a plaintext file.
#
# Nothing is deleted or modified outside the two no-replace v12 outputs.
set -euo pipefail
umask 077
PATH='/usr/bin:/bin:/usr/sbin:/sbin'
export PATH
unset ZDOTDIR ENV BASH_ENV CDPATH PERL5OPT PERL5LIB PYTHONHOME PYTHONPATH \
  RUBYOPT RUBYLIB NODE_OPTIONS OPENSSL_CONF OPENSSL_MODULES SSL_CERT_FILE \
  SSL_CERT_DIR CURL_HOME XDG_CONFIG_HOME
unset DEVELOPER_DIR SDKROOT TOOLCHAINS \
  CCC_OVERRIDE_OPTIONS COMPILER_PATH CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH \
  OBJC_INCLUDE_PATH LIBRARY_PATH GCC_EXEC_PREFIX \
  ADDITIONAL_SWIFT_DRIVER_FLAGS SWIFT_EXEC SWIFT_DRIVER_SWIFT_FRONTEND_EXEC \
  SWIFT_DRIVER_SWIFTSCAN_LIB SWIFT_DRIVER_TOOLCHAIN_CASPLUGIN_LIB \
  DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH \
  DYLD_FALLBACK_LIBRARY_PATH DYLD_FALLBACK_FRAMEWORK_PATH
unset DOTNET_STARTUP_HOOKS DOTNET_ADDITIONAL_DEPS DOTNET_SHARED_STORE \
  DOTNET_ROOT DOTNET_ROOT_X64 DOTNET_ROOT_ARM64 DOTNET_HOST_PATH \
  DOTNET_DiagnosticPorts DOTNET_DefaultDiagnosticPortSuspend DOTNET_ROLL_FORWARD \
  DOTNET_ROLL_FORWARD_ON_NO_CANDIDATE_FX DOTNET_ROLL_FORWARD_TO_PRERELEASE \
  DOTNET_MULTILEVEL_LOOKUP CORECLR_ENABLE_PROFILING CORECLR_PROFILER \
  CORECLR_PROFILER_PATH CORECLR_PROFILER_PATH_32 CORECLR_PROFILER_PATH_64 \
  CORECLR_PROFILER_PATH_ARM64 COR_ENABLE_PROFILING COR_PROFILER \
  COR_PROFILER_PATH COR_PROFILER_PATH_32 COR_PROFILER_PATH_64 \
  COMPlus_AltJit COMPlus_AltJitName DOTNET_AltJit DOTNET_AltJitName \
  MSBuildSDKsPath MSBUILD_EXE_PATH MSBuildExtensionsPath MSBuildExtensionsPath32 \
  MSBuildExtensionsPath64 MSBuildUserExtensionsPath MSBuildToolsPath \
  MSBuildBinPath MSBUILDLEGACYEXTENSIONSPATH MSBUILDADDITIONALSDKRESOLVERSFOLDER \
  CustomBeforeMicrosoftCommonTargets CustomAfterMicrosoftCommonTargets \
  CustomBeforeMicrosoftCSharpTargets CustomAfterMicrosoftCSharpTargets \
  DirectoryBuildPropsPath DirectoryBuildTargetsPath ImportDirectoryBuildProps \
  ImportDirectoryBuildTargets DOTNET_MSBUILD_SDK_RESOLVER_CLI_DIR \
  DOTNET_MSBUILD_SDK_RESOLVER_SDKS_DIR DOTNET_MSBUILD_SDK_RESOLVER_SDKS_VER \
  NUGET_PLUGIN_PATHS NUGET_CREDENTIALPROVIDERS_PATH NUGET_EXTENSIONS_PATH \
  NUGET_PACKAGES NUGET_HTTP_CACHE_PATH NUGET_SCRATCH RestoreSources \
  RestoreAdditionalProjectSources RestoreFallbackFolders RestorePackagesPath \
  RestoreConfigFile
export DOTNET_EnableDiagnostics=0 COMPlus_EnableDiagnostics=0
require_sanitized_injection_environment() {
  local variable=''
  for variable in \
      ZDOTDIR ENV BASH_ENV CDPATH PERL5OPT PERL5LIB PYTHONHOME PYTHONPATH \
      RUBYOPT RUBYLIB NODE_OPTIONS OPENSSL_CONF OPENSSL_MODULES CURL_HOME \
      DEVELOPER_DIR SDKROOT TOOLCHAINS CCC_OVERRIDE_OPTIONS CPATH \
      ADDITIONAL_SWIFT_DRIVER_FLAGS SWIFT_DRIVER_SWIFTSCAN_LIB \
      DYLD_INSERT_LIBRARIES DOTNET_STARTUP_HOOKS CORECLR_ENABLE_PROFILING \
      CORECLR_PROFILER CORECLR_PROFILER_PATH MSBuildSDKsPath \
      CustomBeforeMicrosoftCommonTargets CustomBeforeMicrosoftCSharpTargets \
      NUGET_PLUGIN_PATHS NUGET_PACKAGES NUGET_HTTP_CACHE_PATH NUGET_SCRATCH; do
    if (( ${+parameters[$variable]} )); then
      print -u2 "RELEASE GATE: inherited build-injection variable survived sanitization: ${variable}"
      return 2
    fi
  done
  if [[ ${DOTNET_EnableDiagnostics} != 0 || ${COMPlus_EnableDiagnostics} != 0 ]]; then
    print -u2 'RELEASE GATE: managed diagnostics must remain disabled.'
    return 2
  fi
}
require_sanitized_injection_environment

xcrun_path=/usr/bin/xcrun
env_path=/usr/bin/env
security_path=/usr/bin/security
stat_path=/usr/bin/stat
mktemp_path=/usr/bin/mktemp
chmod_path=/bin/chmod
rm_path=/bin/rm
mkdir_path=/bin/mkdir
mv_path=/bin/mv
rmdir_path=/bin/rmdir

require_root_system_tool() {
  local tool=$1
  if [[ ${tool} != /* || ! -f ${tool} || -L ${tool} || ! -x ${tool} \
      || $(${stat_path} -f %u -- ${tool}) != 0 ]]; then
    print -u2 "KEY PROTECTION GATE: required tool is not an absolute root-owned regular file: ${tool}"
    exit 2
  fi
  local tool_mode=$(( 8#$(${stat_path} -f %Lp -- ${tool}) ))
  if (( (tool_mode & 8#022) != 0 )); then
    print -u2 "KEY PROTECTION GATE: required tool is group/other writable: ${tool}"
    exit 2
  fi
}

for fixed_tool in \
    ${xcrun_path} ${env_path} ${security_path} ${stat_path} ${mktemp_path} \
    ${chmod_path} ${rm_path} ${mkdir_path} ${mv_path} ${rmdir_path}; do
  require_root_system_tool ${fixed_tool}
done

clang_path=$(${xcrun_path} --sdk macosx --find clang)
clang_path=${clang_path:A}
require_root_system_tool ${clang_path}
sdk_root=$(${xcrun_path} --sdk macosx --show-sdk-path)
sdk_root=${sdk_root:A}
if [[ ! -d ${sdk_root} || -L ${sdk_root} \
    || $(${stat_path} -f %u -- ${sdk_root}) != 0 ]]; then
  print -u2 'KEY PROTECTION GATE: the selected macOS SDK is not a root-owned physical directory.'
  exit 2
fi
sdk_mode=$(( 8#$(${stat_path} -f %Lp -- ${sdk_root}) ))
if (( (sdk_mode & 8#022) != 0 )); then
  print -u2 'KEY PROTECTION GATE: the selected macOS SDK is group/other writable.'
  exit 2
fi

security() { ${security_path} "$@"; }
mktemp() { ${mktemp_path} "$@"; }
chmod() { ${chmod_path} "$@"; }
rm() { ${rm_path} "$@"; }
mkdir() { ${mkdir_path} "$@"; }
mv() { ${mv_path} "$@"; }
rmdir() { ${rmdir_path} "$@"; }
clang() { ${clang_path} "$@"; }

script_dir=${0:A:h}
repo_root=${script_dir:h}
mac_project=${repo_root}/KeepVaultMac
packaging_dir=${mac_project}/Packaging
dotnet_command=''
verified_dotnet_provisioner=${repo_root}/tools/Provision-VerifiedDotnet-macOS.sh
verified_dotnet_provisioner_identity=''
dotnet_command_identity=''

private_tmp_parent=/private/tmp
private_dotnet_root=''
private_dotnet_tmp=''
private_dotnet_cli_home=''
private_dotnet_packages=''
private_dotnet_http_cache=''
private_dotnet_scratch=''
private_dotnet_keychain_temp=''
private_dotnet_sdk_target=''
private_dotnet_artifacts=''
private_signer_intermediate=''
private_helper_build_root=''
signer_dll=''
signer_dll_identity=''
private_dotnet_directories=()
private_dotnet_identities=()

require_private_tmp_parent() {
  local private_tmp_mode=$(( 8#$(stat -f %p -- ${private_tmp_parent}) ))
  if [[ ! -d ${private_tmp_parent} || -L ${private_tmp_parent} \
      || ${private_tmp_parent:A} != ${private_tmp_parent} \
      || $(stat -f %u -- ${private_tmp_parent}) != 0 ]] \
      || (( (private_tmp_mode & 8#7777) != 8#1777 )); then
    print -u2 'KEY PROTECTION GATE: /private/tmp must be a physical root-owned mode-1777 directory.'
    return 2
  fi
}

create_private_nuget_cache() {
  [[ -z ${private_dotnet_root} ]] || return 0
  require_private_tmp_parent

  private_dotnet_root=$(mktemp -d "${private_tmp_parent}/keep-vault-protect-dotnet.XXXXXXXX")
  private_dotnet_root=${private_dotnet_root:A}
  private_dotnet_tmp=${private_dotnet_root}/tmp
  private_dotnet_cli_home=${private_dotnet_root}/cli-home
  private_dotnet_packages=${private_dotnet_root}/packages
  private_dotnet_http_cache=${private_dotnet_root}/http-cache
  private_dotnet_scratch=${private_dotnet_root}/scratch
  private_dotnet_keychain_temp=${private_dotnet_root}/keychain-temp
  private_dotnet_sdk_target=${private_dotnet_root}/verified-sdk
  private_dotnet_artifacts=${private_dotnet_root}/artifacts
  private_signer_intermediate=${private_dotnet_root}/signer-obj
  private_helper_build_root=${private_dotnet_root}/keychain-helper
  chmod 0700 ${private_dotnet_root}
  private_dotnet_directories=(${private_dotnet_root})
  private_dotnet_identities=("$(stat -f '%d:%i:%u:%Lp' -- ${private_dotnet_root})")
  local directory=''
  for directory in \
      ${private_dotnet_tmp} \
      ${private_dotnet_cli_home} \
      ${private_dotnet_packages} \
      ${private_dotnet_http_cache} \
      ${private_dotnet_scratch} \
      ${private_dotnet_keychain_temp} \
      ${private_dotnet_artifacts} \
      ${private_signer_intermediate} \
      ${private_helper_build_root}; do
    mkdir -m 0700 -- ${directory}
    private_dotnet_directories+=(${directory})
    private_dotnet_identities+=("$(stat -f '%d:%i:%u:%Lp' -- ${directory})")
  done
  require_private_nuget_cache_identity
}

require_private_nuget_cache_identity() {
  if [[ -z ${private_dotnet_root} \
      || ${#private_dotnet_directories[@]} != ${#private_dotnet_identities[@]} ]]; then
    print -u2 'KEY PROTECTION GATE: the private .NET cache has no complete identity record.'
    return 2
  fi
  local index=0
  local directory=''
  local actual=''
  for (( index = 1; index <= ${#private_dotnet_directories[@]}; index++ )); do
    directory=${private_dotnet_directories[index]}
    if [[ ! -d ${directory} || -L ${directory} ]]; then
      print -u2 'KEY PROTECTION GATE: a private .NET cache directory was replaced.'
      return 2
    fi
    actual=$(stat -f '%d:%i:%u:%Lp' -- ${directory})
    if [[ ${actual} != ${private_dotnet_identities[index]} \
        || $(stat -f %u -- ${directory}) != ${EUID} \
        || $(stat -f %Lp -- ${directory}) != 700 ]]; then
      print -u2 'KEY PROTECTION GATE: a private .NET cache identity, owner or mode changed.'
      return 2
    fi
  done
}

cleanup_private_nuget_cache() {
  [[ -n ${private_dotnet_root} ]] || return 0
  if ! require_private_nuget_cache_identity; then
    print -u2 'KEY PROTECTION GATE: refusing to remove a substituted private .NET cache path.'
    return 2
  fi
  if ! rm -rf -- ${private_dotnet_root}; then
    print -u2 'KEY PROTECTION GATE: unable to remove the private .NET cache.'
    return 2
  fi
  private_dotnet_root=''
  private_dotnet_directories=()
  private_dotnet_identities=()
}

self_test_private_nuget_cache_identity() {
  require_private_nuget_cache_identity
  local held_path=${private_dotnet_root}.held
  if [[ -e ${held_path} || -L ${held_path} ]]; then
    print -u2 'KEY PROTECTION GATE: private-cache identity self-test path already exists.'
    return 2
  fi
  mv -- ${private_dotnet_root} ${held_path}
  if [[ $(stat -f '%d:%i:%u:%Lp' -- ${held_path}) != ${private_dotnet_identities[1]} ]]; then
    print -u2 'KEY PROTECTION GATE: private-cache identity changed during the self-test hold.'
    return 2
  fi
  mkdir -m 0700 -- ${private_dotnet_root}
  local replacement_identity=$(stat -f '%d:%i:%u:%Lp' -- ${private_dotnet_root})
  local substitution_was_rejected=0
  require_private_nuget_cache_identity >/dev/null 2>&1 \
    || substitution_was_rejected=1
  if [[ $(stat -f '%d:%i:%u:%Lp' -- ${private_dotnet_root}) != ${replacement_identity} ]]; then
    print -u2 'KEY PROTECTION GATE: refusing to remove a changed cache-test replacement.'
    return 2
  fi
  rmdir -- ${private_dotnet_root}
  mv -- ${held_path} ${private_dotnet_root}
  require_private_nuget_cache_identity
  if (( ! substitution_was_rejected )); then
    print -u2 'KEY PROTECTION GATE: private-cache pathname substitution was not rejected.'
    return 2
  fi
}

require_verified_dotnet_identity() {
  if [[ -z ${dotnet_command} || ${dotnet_command} != ${private_dotnet_sdk_target}/dotnet \
      || ! -f ${dotnet_command} || -L ${dotnet_command} || ! -x ${dotnet_command} \
      || $(stat -f '%d:%i:%u:%Lp' -- ${dotnet_command}) != ${dotnet_command_identity} \
      || $(stat -f %u -- ${dotnet_command}) != ${EUID} ]]; then
    print -u2 'KEY PROTECTION GATE: the freshly verified .NET SDK host identity changed.'
    return 2
  fi
  local dotnet_mode=$(( 8#$(stat -f %Lp -- ${dotnet_command}) ))
  if (( (dotnet_mode & 8#022) != 0 )); then
    print -u2 'KEY PROTECTION GATE: the freshly verified .NET SDK host became writable by another user.'
    return 2
  fi
}

ensure_verified_dotnet() {
  if [[ -n ${dotnet_command} ]]; then
    require_verified_dotnet_identity
    return
  fi
  if [[ ! -f ${verified_dotnet_provisioner} || -L ${verified_dotnet_provisioner} \
      || ! -x ${verified_dotnet_provisioner} \
      || $(stat -f %u -- ${verified_dotnet_provisioner}) != ${EUID} ]]; then
    print -u2 'KEY PROTECTION GATE: the reviewed .NET SDK provisioner is unavailable or substituted.'
    return 2
  fi
  local provisioner_mode=$(( 8#$(stat -f %Lp -- ${verified_dotnet_provisioner}) ))
  if (( (provisioner_mode & 8#022) != 0 )); then
    print -u2 'KEY PROTECTION GATE: the reviewed .NET SDK provisioner is group/other writable.'
    return 2
  fi
  verified_dotnet_provisioner_identity=$(stat -f '%d:%i:%u:%Lp' -- ${verified_dotnet_provisioner})

  local provisioned_dotnet=''
  local provision_status=0
  provisioned_dotnet=$(${env_path} -i \
    "PATH=${PATH}" \
    "TMPDIR=${private_dotnet_tmp}/" \
    ${verified_dotnet_provisioner} --target ${private_dotnet_sdk_target}) \
    || provision_status=$?
  if [[ $(stat -f '%d:%i:%u:%Lp' -- ${verified_dotnet_provisioner}) \
      != ${verified_dotnet_provisioner_identity} ]]; then
    print -u2 'KEY PROTECTION GATE: the .NET SDK provisioner identity changed while executing.'
    return 2
  fi
  if (( provision_status != 0 )); then
    print -u2 'KEY PROTECTION GATE: the pinned Microsoft .NET SDK could not be provisioned.'
    return ${provision_status}
  fi
  if [[ ${provisioned_dotnet} != ${private_dotnet_sdk_target}/dotnet \
      || ! -d ${private_dotnet_sdk_target} || -L ${private_dotnet_sdk_target} ]]; then
    print -u2 'KEY PROTECTION GATE: the SDK provisioner returned an unexpected host path.'
    return 2
  fi
  private_dotnet_directories+=(${private_dotnet_sdk_target})
  private_dotnet_identities+=("$(stat -f '%d:%i:%u:%Lp' -- ${private_dotnet_sdk_target})")
  dotnet_command=${provisioned_dotnet}
  dotnet_command_identity=$(stat -f '%d:%i:%u:%Lp' -- ${dotnet_command})
  require_private_nuget_cache_identity
  require_verified_dotnet_identity
}

run_dotnet_clean() {
  require_private_nuget_cache_identity || return
  ensure_verified_dotnet || return
  require_verified_dotnet_identity || return
  local runtime_tmp=${private_dotnet_tmp}
  local -a home_environment=("HOME=${private_dotnet_cli_home}")
  local -a keychain_environment=()
  if [[ ${1:-} == --with-keychain-temp ]]; then
    shift
    runtime_tmp=${private_dotnet_keychain_temp}
    home_environment=()
    keychain_environment=(
      "KEEPVAULT_KEYCHAIN_TEMP_ROOT=${private_dotnet_keychain_temp}"
    )
  fi
  local dotnet_status=0
  ${env_path} -i \
    "${home_environment[@]}" \
    "PATH=${PATH}" \
    "TMPDIR=${runtime_tmp}/" \
    "${keychain_environment[@]}" \
    "DOTNET_CLI_HOME=${private_dotnet_cli_home}" \
    "NUGET_PACKAGES=${private_dotnet_packages}" \
    "NUGET_HTTP_CACHE_PATH=${private_dotnet_http_cache}" \
    "NUGET_SCRATCH=${private_dotnet_scratch}" \
    DOTNET_EnableDiagnostics=0 \
    COMPlus_EnableDiagnostics=0 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
    DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=1 \
    DOTNET_NOLOGO=1 \
    ${dotnet_command} "$@" || dotnet_status=$?
  require_private_nuget_cache_identity || return
  require_verified_dotnet_identity || return
  return ${dotnet_status}
}

require_private_signer_identity() {
  if [[ -z ${signer_dll_identity} \
      || ${signer_dll} != ${private_dotnet_artifacts}/bin/KeepVaultMac.HybridSigner/release/KeepVaultMac.HybridSigner.dll \
      || ! -f ${signer_dll} || -L ${signer_dll} \
      || $(stat -f '%d:%i:%u:%Lp:%z:%m:%c:%l' -- ${signer_dll}) != ${signer_dll_identity} \
      || $(stat -f %u -- ${signer_dll}) != ${EUID} \
      || $(stat -f %l -- ${signer_dll}) != 1 ]]; then
    print -u2 'KEY PROTECTION GATE: the private HybridSigner assembly identity changed.'
    return 2
  fi
  local signer_mode=$(( 8#$(stat -f %Lp -- ${signer_dll}) ))
  if (( (signer_mode & 8#022) != 0 )); then
    print -u2 'KEY PROTECTION GATE: the private HybridSigner assembly became writable by another user.'
    return 2
  fi
}

capture_private_signer_identity() {
  signer_dll=${private_dotnet_artifacts}/bin/KeepVaultMac.HybridSigner/release/KeepVaultMac.HybridSigner.dll
  if [[ ! -f ${signer_dll} || -L ${signer_dll} ]]; then
    print -u2 'KEY PROTECTION GATE: the isolated build did not produce its private HybridSigner assembly.'
    return 2
  fi
  signer_dll_identity=$(stat -f '%d:%i:%u:%Lp:%z:%m:%c:%l' -- ${signer_dll})
  require_private_signer_identity
}

run_dotnet_signer_clean() {
  require_private_signer_identity || return
  local signer_status=0
  if [[ ${1:-} == --with-keychain-temp ]]; then
    shift
    run_dotnet_clean --with-keychain-temp ${signer_dll} "$@" || signer_status=$?
  else
    run_dotnet_clean ${signer_dll} "$@" || signer_status=$?
  fi
  require_private_signer_identity || return
  return ${signer_status}
}

keychain_helper_source=${packaging_dir}/AddHybridWrappingKey.c
verify_only=0
tool_path_self_test=0

if (( $# > 1 )); then
  print -u2 'Usage: Protect-HybridKeys-macOS.sh [--verify-only|--tool-path-self-test]'
  exit 64
fi
if (( $# == 1 )); then
  case $1 in
    --verify-only) verify_only=1 ;;
    --tool-path-self-test) tool_path_self_test=1 ;;
    *)
      print -u2 'Usage: Protect-HybridKeys-macOS.sh [--verify-only|--tool-path-self-test]'
      exit 64
      ;;
  esac
fi

cleanup_protection() {
  local original_status=$?
  local cleanup_status=0
  trap - EXIT INT TERM
  cleanup_private_nuget_cache || cleanup_status=$?
  if (( original_status == 0 && cleanup_status != 0 )); then
    original_status=${cleanup_status}
  fi
  exit ${original_status}
}
trap cleanup_protection EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
create_private_nuget_cache

if (( tool_path_self_test )); then
  require_sanitized_injection_environment
  self_test_private_nuget_cache_identity
  clang --version >/dev/null
  run_dotnet_clean --version >/dev/null
  print 'hybrid_protection_tool_paths=verified'
  exit 0
fi

release_user=${USER:-}
if [[ -z ${release_user} ]]; then
  print -u2 'USER is unavailable; explicit, role-specific Keychain accounts are required.'
  exit 1
fi

key_root=${KEEPVAULT_RELEASE_KEYS:-${HOME}/Library/Application Support/Keep Vault/ReleaseKeys}
plain_key=${KEEPVAULT_MLDSA_PRIVATE_KEY:-${key_root}/mldsa87-private.key}
mldsa_envelope=${KEEPVAULT_MLDSA_PRIVATE_KEY_ENCRYPTED:-${key_root}/mldsa87-private.key.v12.enc}
pfx_envelope=${KEEPVAULT_PFX_PASSWORD_ENCRYPTED:-${key_root}/hybrid-rsa4096.pfx.password.v12.enc}

mldsa_service=${KEEPVAULT_MLDSA_WRAPPING_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.v12.mldsa-wrapping-key}
mldsa_account=${KEEPVAULT_MLDSA_WRAPPING_KEYCHAIN_ACCOUNT:-keep-vault-mldsa-v12:${release_user}}
pfx_wrapping_service=${KEEPVAULT_PFX_WRAPPING_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.v12.pfx-wrapping-key}
pfx_wrapping_account=${KEEPVAULT_PFX_WRAPPING_KEYCHAIN_ACCOUNT:-keep-vault-pfx-v12:${release_user}}

# The provisioning PFX-password item is never reused as a wrapping-key item.
pfx_password_service=${KEEPVAULT_PFX_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.hybrid-pfx}
pfx_password_account=${KEEPVAULT_PFX_KEYCHAIN_ACCOUNT:-${release_user}}

if [[ -z ${mldsa_service} || -z ${mldsa_account} \
    || -z ${pfx_wrapping_service} || -z ${pfx_wrapping_account} ]]; then
  print -u2 'Both role-specific Keychain services and accounts must be nonempty.'
  exit 1
fi
if [[ ${mldsa_service} == ${pfx_wrapping_service} \
    || ${mldsa_account} == ${pfx_wrapping_account} ]]; then
  print -u2 'RSA and ML-DSA wrapping keys require different services and different accounts.'
  exit 1
fi
if [[ ${pfx_password_service} == ${pfx_wrapping_service} \
    && ${pfx_password_account} == ${pfx_wrapping_account} ]]; then
  print -u2 'The PFX-password provisioning item cannot also be the v12 PFX wrapping-key item.'
  exit 1
fi

wrap_mldsa=1
if [[ -e ${mldsa_envelope} || -L ${mldsa_envelope} ]]; then
  if [[ ! -f ${mldsa_envelope} || -L ${mldsa_envelope} ]]; then
    print -u2 "The ML-DSA v12 envelope is not a regular physical file: ${mldsa_envelope}"
    exit 1
  fi
  wrap_mldsa=0
fi
wrap_pfx=1
if [[ -e ${pfx_envelope} || -L ${pfx_envelope} ]]; then
  if [[ ! -f ${pfx_envelope} || -L ${pfx_envelope} ]]; then
    print -u2 "The PFX-password v12 envelope is not a regular physical file: ${pfx_envelope}"
    exit 1
  fi
  wrap_pfx=0
fi

if (( verify_only )); then
  if (( wrap_mldsa || wrap_pfx )); then
    print -u2 'Both role-specific v12 envelopes are required by the release signer.'
    exit 1
  fi
fi

if (( wrap_mldsa )); then
  if [[ ! -f ${plain_key} || -L ${plain_key} ]]; then
    print -u2 'No physical ML-DSA provisioning key exists for the missing v12 envelope.'
    exit 1
  fi
fi

if (( wrap_pfx && ! verify_only )); then
  if ! security find-generic-password \
      -s ${pfx_password_service} -a ${pfx_password_account} >/dev/null 2>&1; then
    print -u2 'The PFX-password provisioning Keychain item is unavailable.'
    exit 1
  fi
fi

if [[ ! -f ${keychain_helper_source} || -L ${keychain_helper_source} ]]; then
  print -u2 "The Security.framework Keychain helper source is missing or symbolic: ${keychain_helper_source}"
  exit 1
fi
helper_build_root=${private_helper_build_root}
helper_path=${helper_build_root}/AddHybridWrappingKey

clang -isysroot ${sdk_root} -std=c17 -Wall -Wextra -Werror -O2 \
  -framework Security -framework CoreFoundation \
  ${keychain_helper_source} -o ${helper_path}
chmod 0700 ${helper_path}

ensure_role_item() {
  local role=$1
  local service=$2
  local account=$3
  local may_create=$4
  if security find-generic-password \
      -s ${service} -a ${account} >/dev/null 2>&1; then
    ${helper_path} verify ${role} ${service} ${account}
  elif (( may_create )); then
    ${helper_path} create ${role} ${service} ${account}
  else
    print -u2 "The ${role} v12 envelope exists but its bound Keychain item is missing."
    return 1
  fi
  # Re-run the read-free ACL inspection after creation as a release invariant.
  ${helper_path} verify ${role} ${service} ${account}
  print "${role}_keychain_acl=verified"
}

ensure_role_item mldsa ${mldsa_service} ${mldsa_account} $(( ! verify_only && wrap_mldsa ))
ensure_role_item pfx ${pfx_wrapping_service} ${pfx_wrapping_account} $(( ! verify_only && wrap_pfx ))

if (( verify_only )); then
  print 'hybrid_wrapping_separation=verified'
  exit 0
fi

if (( wrap_mldsa || wrap_pfx )); then
  (
    cd ${mac_project}
    run_dotnet_clean restore Packaging/HybridSigner/KeepVaultMac.HybridSigner.csproj \
      --artifacts-path ${private_dotnet_artifacts} \
      -p:BaseIntermediateOutputPath=${private_signer_intermediate}/ \
      -p:MSBuildProjectExtensionsPath=${private_signer_intermediate}/ \
      --locked-mode --disable-build-servers --nologo
    run_dotnet_clean build Packaging/HybridSigner/KeepVaultMac.HybridSigner.csproj \
      --artifacts-path ${private_dotnet_artifacts} \
      -p:BaseIntermediateOutputPath=${private_signer_intermediate}/ \
      -p:MSBuildProjectExtensionsPath=${private_signer_intermediate}/ \
      -c Release --no-restore --no-incremental --disable-build-servers \
      -p:UseSharedCompilation=false --nologo
  )
  capture_private_signer_identity
fi

if (( wrap_mldsa )); then
  (
    cd ${mac_project}
    run_dotnet_signer_clean --with-keychain-temp wrap-mldsa-key \
      --mldsa-private-key ${plain_key} \
      --mldsa-private-key-encrypted ${mldsa_envelope} \
      --mldsa-wrapping-key-keychain-service ${mldsa_service} \
      --mldsa-wrapping-key-keychain-account ${mldsa_account}
  )
else
  print 'mldsa_envelope=already present'
fi

if (( wrap_pfx )); then
  (
    cd ${mac_project}
    run_dotnet_signer_clean --with-keychain-temp wrap-pfx-password \
      --pfx-password-keychain-service ${pfx_password_service} \
      --pfx-password-keychain-account ${pfx_password_account} \
      --pfx-password-encrypted ${pfx_envelope} \
      --pfx-wrapping-key-keychain-service ${pfx_wrapping_service} \
      --pfx-wrapping-key-keychain-account ${pfx_wrapping_account}
  )
else
  print 'pfx_envelope=already present'
fi

print ''
print 'hybrid_wrapping_separation=verified'
print 'Provisioning sources were not modified. Both v12 Keychain items are required'
print 'for every published hybrid signature.'
