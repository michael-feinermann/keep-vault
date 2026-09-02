#!/bin/zsh -f
set -euo pipefail
umask 077
PATH='/usr/bin:/bin:/usr/sbin:/sbin'
export PATH
unset DEVELOPER_DIR SDKROOT TOOLCHAINS KEEPVAULT_DOTNET \
  ZDOTDIR ENV BASH_ENV CDPATH FPATH SHELLOPTS BASHOPTS \
  PERL5OPT PERL5LIB PYTHONHOME PYTHONPATH PYTHONSTARTUP \
  PERLLIB PERL_LOCAL_LIB_ROOT PERL_MB_OPT PERL_MM_OPT \
  RUBYOPT RUBYLIB NODE_OPTIONS NODE_PATH GEM_HOME GEM_PATH \
  OPENSSL_CONF OPENSSL_MODULES SSL_CERT_FILE SSL_CERT_DIR \
  XDG_CONFIG_HOME CURL_HOME TAR_OPTIONS
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

xcrun_path=/usr/bin/xcrun
codesign_path=/usr/bin/codesign
find_path=/usr/bin/find
grep_path=/usr/bin/grep
mktemp_path=/usr/bin/mktemp
stat_path=/usr/bin/stat
plistbuddy_path=/usr/libexec/PlistBuddy
shasum_path=/usr/bin/shasum
awk_path=/usr/bin/awk
ditto_path=/usr/bin/ditto
spctl_path=/usr/sbin/spctl
rm_path=/bin/rm
env_path=/usr/bin/env
id_path=/usr/bin/id
mkdir_path=/bin/mkdir
chmod_path=/bin/chmod
mv_path=/bin/mv
rmdir_path=/bin/rmdir

require_root_system_tool() {
  local tool=$1
  if [[ ${tool} != /* || ! -f ${tool} || -L ${tool} || ! -x ${tool} \
      || $(${stat_path} -f %u -- ${tool}) != 0 ]]; then
    print -u2 "QR VERIFY GATE: required tool is not an absolute root-owned regular file: ${tool}"
    exit 2
  fi
  local tool_mode=$(( 8#$(${stat_path} -f %Lp -- ${tool}) ))
  if (( (tool_mode & 8#022) != 0 )); then
    print -u2 "QR VERIFY GATE: required tool is group/other writable: ${tool}"
    exit 2
  fi
}

for fixed_tool in \
    ${xcrun_path} ${codesign_path} ${find_path} ${grep_path} ${mktemp_path} \
    ${stat_path} ${plistbuddy_path} ${shasum_path} ${awk_path} \
    ${ditto_path} ${spctl_path} ${rm_path} ${env_path} ${id_path} \
    ${mkdir_path} ${chmod_path} ${mv_path} ${rmdir_path}; do
  require_root_system_tool ${fixed_tool}
done

stapler_path=$(${xcrun_path} --find stapler)
stapler_path=${stapler_path:A}
require_root_system_tool ${stapler_path}

sdk_root=$(${xcrun_path} --sdk macosx --show-sdk-path)
sdk_root=${sdk_root:A}
if [[ ! -d ${sdk_root} || -L ${sdk_root} \
    || $(${stat_path} -f %u -- ${sdk_root}) != 0 ]]; then
  print -u2 'QR VERIFY GATE: the selected macOS SDK is not a root-owned physical directory.'
  exit 2
fi
sdk_mode=$(( 8#$(${stat_path} -f %Lp -- ${sdk_root}) ))
if (( (sdk_mode & 8#022) != 0 )); then
  print -u2 'QR VERIFY GATE: the selected macOS SDK is group/other writable.'
  exit 2
fi

codesign() { ${codesign_path} "$@"; }
find() { ${find_path} "$@"; }
grep() { ${grep_path} "$@"; }
mktemp() { ${mktemp_path} "$@"; }
plistbuddy() { ${plistbuddy_path} "$@"; }
shasum() { ${env_path} -i PATH='/usr/bin:/bin:/usr/sbin:/sbin' ${shasum_path} "$@"; }
awk() { ${awk_path} "$@"; }
ditto() { ${ditto_path} "$@"; }
spctl() { ${spctl_path} "$@"; }
rm() { ${rm_path} "$@"; }
stapler() { ${stapler_path} "$@"; }
mkdir() { ${mkdir_path} "$@"; }
chmod() { ${chmod_path} "$@"; }
mv() { ${mv_path} "$@"; }
rmdir() { ${rmdir_path} "$@"; }

require_managed_injection_environment_cleared() {
  local variable
  local injection_variables=(
    KEEPVAULT_DOTNET
    ZDOTDIR ENV BASH_ENV CDPATH FPATH SHELLOPTS BASHOPTS
    PERL5OPT PERL5LIB PYTHONHOME PYTHONPATH PYTHONSTARTUP
    PERLLIB PERL_LOCAL_LIB_ROOT PERL_MB_OPT PERL_MM_OPT
    RUBYOPT RUBYLIB NODE_OPTIONS NODE_PATH GEM_HOME GEM_PATH
    OPENSSL_CONF OPENSSL_MODULES SSL_CERT_FILE SSL_CERT_DIR
    XDG_CONFIG_HOME CURL_HOME TAR_OPTIONS
    DOTNET_STARTUP_HOOKS DOTNET_ADDITIONAL_DEPS DOTNET_SHARED_STORE DOTNET_ROOT
    DOTNET_ROOT_X64 DOTNET_ROOT_ARM64 DOTNET_HOST_PATH DOTNET_DiagnosticPorts
    DOTNET_DefaultDiagnosticPortSuspend DOTNET_ROLL_FORWARD
    DOTNET_ROLL_FORWARD_ON_NO_CANDIDATE_FX DOTNET_ROLL_FORWARD_TO_PRERELEASE
    DOTNET_MULTILEVEL_LOOKUP CORECLR_ENABLE_PROFILING CORECLR_PROFILER
    CORECLR_PROFILER_PATH CORECLR_PROFILER_PATH_32 CORECLR_PROFILER_PATH_64
    CORECLR_PROFILER_PATH_ARM64 COR_ENABLE_PROFILING COR_PROFILER
    COR_PROFILER_PATH COR_PROFILER_PATH_32 COR_PROFILER_PATH_64
    COMPlus_AltJit COMPlus_AltJitName DOTNET_AltJit DOTNET_AltJitName
    MSBuildSDKsPath MSBUILD_EXE_PATH MSBuildExtensionsPath
    MSBuildExtensionsPath32 MSBuildExtensionsPath64 MSBuildUserExtensionsPath
    MSBuildToolsPath MSBuildBinPath MSBUILDLEGACYEXTENSIONSPATH
    MSBUILDADDITIONALSDKRESOLVERSFOLDER CustomBeforeMicrosoftCommonTargets
    CustomAfterMicrosoftCommonTargets CustomBeforeMicrosoftCSharpTargets
    CustomAfterMicrosoftCSharpTargets DirectoryBuildPropsPath
    DirectoryBuildTargetsPath ImportDirectoryBuildProps ImportDirectoryBuildTargets
    DOTNET_MSBUILD_SDK_RESOLVER_CLI_DIR DOTNET_MSBUILD_SDK_RESOLVER_SDKS_DIR
    DOTNET_MSBUILD_SDK_RESOLVER_SDKS_VER NUGET_PLUGIN_PATHS
    NUGET_CREDENTIALPROVIDERS_PATH NUGET_EXTENSIONS_PATH NUGET_PACKAGES
    NUGET_HTTP_CACHE_PATH NUGET_SCRATCH RestoreSources
    RestoreAdditionalProjectSources RestoreFallbackFolders RestorePackagesPath
    RestoreConfigFile
  )
  for variable in ${injection_variables[@]}; do
    if (( ${+parameters[$variable]} )); then
      print -u2 "QR VERIFY GATE: managed injection variable survived sanitization: ${variable}"
      exit 2
    fi
  done
  if [[ ${DOTNET_EnableDiagnostics} != 0 || ${COMPlus_EnableDiagnostics} != 0 ]]; then
    print -u2 'QR VERIFY GATE: managed diagnostics were not disabled.'
    exit 2
  fi
}

private_temp_parent=/private/tmp
private_temp_parent_identity=''
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
private_dotnet_artifacts=''
private_dotnet_artifacts_identity=''
private_dotnet_sdk=''
private_dotnet_sdk_identity=''
private_dotnet_sdk_ready=0
private_nuget_cache_ready=0
verified_user=$(${id_path} -un)
dotnet_host_identity=''
dotnet_command=''
signer_dll=''
signer_dll_identity=''

directory_identity() {
  ${stat_path} -f '%d:%i:%u:%p' -- $1 2>/dev/null
}

require_private_temp_parent_identity() {
  [[ -d ${private_temp_parent} && ! -L ${private_temp_parent} \
      && $(directory_identity ${private_temp_parent} || print invalid) == ${private_temp_parent_identity} \
      && $(${stat_path} -f '%u:%p' -- ${private_temp_parent} 2>/dev/null || print invalid) == '0:41777' ]]
}

require_private_directory_identity() {
  local directory=$1
  local expected_identity=$2
  [[ -n ${directory} && -n ${expected_identity} && -d ${directory} && ! -L ${directory} \
      && $(directory_identity ${directory} || print invalid) == ${expected_identity} \
      && $(${stat_path} -f '%u:%p' -- ${directory} 2>/dev/null || print invalid) == "${EUID}:40700" ]]
}

require_private_nuget_cache_identity() {
  if (( ! private_nuget_cache_ready )) \
      || ! require_private_temp_parent_identity \
      || ! require_private_directory_identity ${private_nuget_root} ${private_nuget_root_identity} \
      || ! require_private_directory_identity ${private_nuget_packages} ${private_nuget_packages_identity} \
      || ! require_private_directory_identity ${private_nuget_http_cache} ${private_nuget_http_cache_identity} \
      || ! require_private_directory_identity ${private_nuget_scratch} ${private_nuget_scratch_identity} \
      || ! require_private_directory_identity ${private_dotnet_cli_home} ${private_dotnet_cli_home_identity} \
      || ! require_private_directory_identity ${private_dotnet_tmp} ${private_dotnet_tmp_identity} \
      || ! require_private_directory_identity ${private_dotnet_artifacts} ${private_dotnet_artifacts_identity}; then
    return 1
  fi
  if (( private_dotnet_sdk_ready )) \
      && ! require_private_directory_identity ${private_dotnet_sdk} ${private_dotnet_sdk_identity}; then
    return 1
  fi
  return 0
}

create_private_nuget_cache() {
  require_private_temp_parent_identity || {
    print -u2 'QR VERIFY GATE: /private/tmp identity changed before cache creation.'
    return 2
  }
  private_nuget_root=$(mktemp -d "${private_temp_parent}/qr-verifier.XXXXXXXX")
  chmod 0700 ${private_nuget_root}
  private_nuget_root_identity=$(directory_identity ${private_nuget_root})
  private_nuget_packages=${private_nuget_root}/packages
  private_nuget_http_cache=${private_nuget_root}/http-cache
  private_nuget_scratch=${private_nuget_root}/scratch
  private_dotnet_cli_home=${private_nuget_root}/cli-home
  private_dotnet_tmp=${private_nuget_root}/tmp
  private_dotnet_artifacts=${private_nuget_root}/artifacts
  private_dotnet_sdk=${private_nuget_root}/sdk
  mkdir -m 0700 ${private_nuget_packages} ${private_nuget_http_cache} \
    ${private_nuget_scratch} ${private_dotnet_cli_home} ${private_dotnet_tmp} \
    ${private_dotnet_artifacts}
  private_nuget_packages_identity=$(directory_identity ${private_nuget_packages})
  private_nuget_http_cache_identity=$(directory_identity ${private_nuget_http_cache})
  private_nuget_scratch_identity=$(directory_identity ${private_nuget_scratch})
  private_dotnet_cli_home_identity=$(directory_identity ${private_dotnet_cli_home})
  private_dotnet_tmp_identity=$(directory_identity ${private_dotnet_tmp})
  private_dotnet_artifacts_identity=$(directory_identity ${private_dotnet_artifacts})
  private_nuget_cache_ready=1
  require_private_nuget_cache_identity || {
    print -u2 'QR VERIFY GATE: failed to create the identity-bound private NuGet cache.'
    return 2
  }
  local -a initial_package_entries=(${private_nuget_packages}/*(DN))
  if (( ${#initial_package_entries[@]} != 0 )); then
    print -u2 'QR VERIFY GATE: the new private NuGet package cache is not empty.'
    return 2
  fi
}

cleanup_private_nuget_cache() {
  [[ -n ${private_nuget_root:-} ]] || return 0
  if (( private_nuget_cache_ready )); then
    require_private_nuget_cache_identity || {
      print -u2 'QR VERIFY GATE: private NuGet cache identity changed; preserving it for inspection.'
      return 2
    }
  elif [[ ${private_nuget_root} != ${private_temp_parent}/qr-verifier.* \
      || ! -d ${private_nuget_root} || -L ${private_nuget_root} \
      || $(directory_identity ${private_nuget_root} || print invalid) != ${private_nuget_root_identity} ]]; then
    print -u2 'QR VERIFY GATE: incomplete private NuGet cache cannot be removed safely.'
    return 2
  fi
  rm -rf -- ${private_nuget_root}
  if [[ -e ${private_nuget_root} || -L ${private_nuget_root} ]]; then
    print -u2 'QR VERIFY GATE: private NuGet cache cleanup failed.'
    return 2
  fi
  private_nuget_root=''
  private_nuget_cache_ready=0
}

self_test_private_nuget_cache_identity() {
  require_private_nuget_cache_identity
  local held_path=${private_nuget_root}.held
  if [[ -e ${held_path} || -L ${held_path} ]]; then
    print -u2 'QR VERIFY GATE: private-cache identity self-test path already exists.'
    return 2
  fi
  mv -- ${private_nuget_root} ${held_path}
  if [[ $(directory_identity ${held_path}) != ${private_nuget_root_identity} ]]; then
    print -u2 'QR VERIFY GATE: private-cache identity changed during the self-test hold.'
    return 2
  fi
  mkdir -m 0700 ${private_nuget_root}
  local replacement_identity=$(directory_identity ${private_nuget_root})
  local substitution_was_rejected=0
  require_private_nuget_cache_identity >/dev/null 2>&1 || substitution_was_rejected=1
  if [[ $(directory_identity ${private_nuget_root}) != ${replacement_identity} ]]; then
    print -u2 'QR VERIFY GATE: refusing to remove a changed cache-test replacement.'
    return 2
  fi
  rmdir -- ${private_nuget_root}
  mv -- ${held_path} ${private_nuget_root}
  require_private_nuget_cache_identity
  if (( ! substitution_was_rejected )); then
    print -u2 'QR VERIFY GATE: private-cache pathname substitution was not rejected.'
    return 2
  fi
}

require_dotnet_host_identity() {
  [[ -n ${dotnet_host_identity} && ${dotnet_command} == /* \
      && -f ${dotnet_command} && ! -L ${dotnet_command} && -x ${dotnet_command} \
      && $(${stat_path} -f '%d:%i:%u:%p:%z:%m:%c:%l' -- ${dotnet_command} 2>/dev/null || print invalid) == ${dotnet_host_identity} ]]
}

require_private_signer_identity() {
  [[ -n ${signer_dll_identity} && ${signer_dll} == ${private_dotnet_artifacts}/* \
      && -f ${signer_dll} && ! -L ${signer_dll} \
      && $(${stat_path} -f '%d:%i:%u:%p:%z:%m:%c:%l' -- ${signer_dll} 2>/dev/null || print invalid) == ${signer_dll_identity} \
      && $(${stat_path} -f %u -- ${signer_dll}) == ${EUID} \
      && $(${stat_path} -f %l -- ${signer_dll}) == 1 ]] || return 1
  local signer_mode=$(( 8#$(${stat_path} -f %Lp -- ${signer_dll}) ))
  (( (signer_mode & 8#022) == 0 ))
}

require_repository_executable() {
  local executable=$1
  [[ ${executable} == /* && -f ${executable} && ! -L ${executable} && -x ${executable} \
      && $(${stat_path} -f %u -- ${executable} 2>/dev/null || print invalid) == ${EUID} \
      && $(${stat_path} -f %l -- ${executable} 2>/dev/null || print invalid) == 1 ]] || return 1
  local executable_mode=$(( 8#$(${stat_path} -f %Lp -- ${executable}) ))
  (( (executable_mode & 8#022) == 0 ))
}

provision_verified_dotnet() {
  if ! require_private_nuget_cache_identity \
      || ! require_repository_executable ${dotnet_provisioner} \
      || [[ $(${stat_path} -f '%d:%i:%u:%p:%z:%m:%c:%l' -- ${dotnet_provisioner}) \
          != ${dotnet_provisioner_identity} ]]; then
    print -u2 'QR VERIFY GATE: private runtime or SDK provisioner identity changed before provisioning.'
    return 2
  fi
  if [[ -e ${private_dotnet_sdk} || -L ${private_dotnet_sdk} ]]; then
    print -u2 'QR VERIFY GATE: verified SDK target already exists.'
    return 2
  fi
  local provision_status=0
  dotnet_command=$(${env_path} -i \
    HOME=${private_dotnet_cli_home} \
    USER=${verified_user} \
    PATH='/usr/bin:/bin:/usr/sbin:/sbin' \
    TMPDIR=${private_dotnet_tmp} \
    ${dotnet_provisioner} --target ${private_dotnet_sdk}) || provision_status=$?
  if ! require_repository_executable ${dotnet_provisioner} \
      || [[ $(${stat_path} -f '%d:%i:%u:%p:%z:%m:%c:%l' -- ${dotnet_provisioner}) \
          != ${dotnet_provisioner_identity} ]]; then
    print -u2 'QR VERIFY GATE: SDK provisioner identity changed while executing.'
    return 2
  fi
  (( provision_status == 0 )) || return ${provision_status}
  if [[ ${dotnet_command} != ${private_dotnet_sdk}/dotnet \
      || ! -d ${private_dotnet_sdk} || -L ${private_dotnet_sdk} ]]; then
    print -u2 'QR VERIFY GATE: verified SDK provisioner returned an unexpected host path.'
    return 2
  fi
  private_dotnet_sdk_identity=$(directory_identity ${private_dotnet_sdk})
  private_dotnet_sdk_ready=1
  dotnet_host_identity=$(${stat_path} -f '%d:%i:%u:%p:%z:%m:%c:%l' -- ${dotnet_command})
  if ! require_private_nuget_cache_identity || ! require_dotnet_host_identity; then
    print -u2 'QR VERIFY GATE: provisioned SDK identity validation failed.'
    return 2
  fi
}

run_dotnet_clean() {
  if ! require_private_nuget_cache_identity || ! require_dotnet_host_identity; then
    print -u2 'QR VERIFY GATE: private cache or .NET host identity changed before a .NET invocation.'
    return 2
  fi
  local direct_signer=0
  if [[ ${1:-} == --direct-signer ]]; then
    direct_signer=1
    shift
    if [[ ${1:-} != ${signer_dll} ]] || ! require_private_signer_identity; then
      print -u2 'QR VERIFY GATE: private signer identity changed before execution.'
      return 2
    fi
  fi
  local -a clean_environment=(
    PATH='/usr/bin:/bin:/usr/sbin:/sbin'
    TMPDIR=${private_dotnet_tmp}
    DOTNET_CLI_HOME=${private_dotnet_cli_home}
    NUGET_PACKAGES=${private_nuget_packages}
    NUGET_HTTP_CACHE_PATH=${private_nuget_http_cache}
    NUGET_SCRATCH=${private_nuget_scratch}
    DOTNET_EnableDiagnostics=0
    COMPlus_EnableDiagnostics=0
    DOTNET_CLI_TELEMETRY_OPTOUT=1
    DOTNET_NOLOGO=1
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
    DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=1
    DOTNET_GENERATE_ASPNET_CERTIFICATE=false
    DOTNET_ADD_GLOBAL_TOOLS_TO_PATH=false
    MSBUILDDISABLENODEREUSE=1
  )
  if (( ! direct_signer )); then
    clean_environment+=(HOME=${private_dotnet_cli_home} USER=${verified_user})
  fi
  local dotnet_status=0
  ${env_path} -i ${clean_environment[@]} ${dotnet_command} "$@" || dotnet_status=$?
  if ! require_private_nuget_cache_identity || ! require_dotnet_host_identity; then
    print -u2 'QR VERIFY GATE: private cache or .NET host identity changed during a .NET invocation.'
    (( dotnet_status != 0 )) && return ${dotnet_status}
    return 2
  fi
  if (( direct_signer )) && ! require_private_signer_identity; then
    print -u2 'QR VERIFY GATE: private signer identity changed during execution.'
    (( dotnet_status != 0 )) && return ${dotnet_status}
    return 2
  fi
  return ${dotnet_status}
}

if [[ ! -d ${private_temp_parent} || -L ${private_temp_parent} \
    || $(${stat_path} -f '%u:%p' -- ${private_temp_parent} 2>/dev/null || print invalid) != '0:41777' ]]; then
  print -u2 'QR VERIFY GATE: /private/tmp must be a physical root-owned mode-1777 directory.'
  exit 2
fi
private_temp_parent_identity=$(directory_identity ${private_temp_parent})
require_private_temp_parent_identity || {
  print -u2 'QR VERIFY GATE: could not bind the physical /private/tmp directory identity.'
  exit 2
}

script_dir=${0:A:h}
repo_root=${script_dir:h}
dotnet_provisioner=${script_dir}/Provision-VerifiedDotnet-macOS.sh
require_repository_executable ${dotnet_provisioner} || {
  print -u2 'QR VERIFY GATE: verified SDK provisioner is missing or unsafe.'
  exit 2
}
dotnet_provisioner_identity=$(${stat_path} -f '%d:%i:%u:%p:%z:%m:%c:%l' -- ${dotnet_provisioner})
expected_team='2T6K9PGS55'
expected_bundle='de.michael-feinermann.qr-scanner'
app_path=''
allow_development=0
require_notarization=0
tool_path_self_test=0
mldsa_public_key=${KEEPVAULT_MLDSA_PUBLIC_KEY:-${repo_root}/KeepVaultMac/Packaging/Keys/mldsa87-public.key}
expected_signer_lock_sha256='B07635B8B5CF158644267CBB99E6483D6F947F37D3B9918B4FF39407EB6BA5EB'

usage() {
  print -u2 'Usage: Verify-QR-Scanner-macOS.sh --app "QR-Scanner.app" [--allow-development]'
  print -u2 '       [--require-notarization] [--mldsa-public-key FILE] [--tool-path-self-test]'
  exit 64
}

while (( $# != 0 )); do
  case $1 in
    --app)
      (( $# >= 2 )) || usage
      app_path=$2
      shift 2
      ;;
    --allow-development)
      allow_development=1
      shift
      ;;
    --require-notarization)
      require_notarization=1
      shift
      ;;
    --mldsa-public-key)
      (( $# >= 2 )) || usage
      mldsa_public_key=$2
      shift 2
      ;;
    --tool-path-self-test)
      tool_path_self_test=1
      shift
      ;;
    *) usage ;;
  esac
done

if (( tool_path_self_test )); then
  require_managed_injection_environment_cleared
  create_private_nuget_cache
  self_test_status=0
  self_test_private_nuget_cache_identity || self_test_status=$?
  cleanup_private_nuget_cache || self_test_status=$?
  (( self_test_status == 0 )) || exit ${self_test_status}
  print 'qr_verifier_tool_paths=verified'
  exit 0
fi

[[ -n ${app_path} ]] || usage
app_path=${app_path:A}
if [[ ! -d ${app_path} || -L ${app_path} || ${app_path:e} != app ]]; then
  print -u2 "QR-Scanner app bundle is missing, not a directory, or a symbolic link: ${app_path}"
  exit 1
fi

if find ${app_path} -type l -print -quit | grep -q .; then
  print -u2 'The QR-Scanner bundle contains a symbolic link and is rejected.'
  exit 1
fi

if find ${app_path} -type f -links +1 -print -quit | grep -q .; then
  print -u2 'The QR-Scanner bundle contains hard-linked files and is rejected.'
  exit 1
fi

info_plist=${app_path}/Contents/Info.plist
if [[ ! -f ${info_plist} || -L ${info_plist} ]]; then
  print -u2 "Info.plist is missing from the QR-Scanner bundle: ${app_path}"
  exit 1
fi

bundle_id=$(plistbuddy -c 'Print :CFBundleIdentifier' ${info_plist} 2>/dev/null || true)
if [[ ${bundle_id} != ${expected_bundle} ]]; then
  print -u2 "The QR-Scanner bundle identifier '${bundle_id}' does not match '${expected_bundle}'."
  exit 1
fi
single_instance=$(plistbuddy -c 'Print :LSMultipleInstancesProhibited' ${info_plist} 2>/dev/null || true)
if [[ ${single_instance} != true ]]; then
  print -u2 'QR-Scanner must prohibit multiple simultaneous camera/payload instances.'
  exit 1
fi

scanner_binary=${app_path}/Contents/MacOS/QR-Scanner
if [[ ! -f ${scanner_binary} || -L ${scanner_binary} || ! -x ${scanner_binary} ]]; then
  print -u2 "QR-Scanner executable is missing or not executable: ${scanner_binary}"
  exit 1
fi

# Apple Code Signature & Team verification
if ! codesign -v --strict ${app_path}; then
  print -u2 'Apple code-signature validity check failed on QR-Scanner.'
  exit 1
fi

app_signature=$(codesign -dvvv ${app_path} 2>&1)
if [[ ${app_signature} == *'Authority=Developer ID Application:'* ]]; then
  if [[ ${app_signature} == *"TeamIdentifier=${expected_team}"* ]]; then
    print "team_id=${expected_team}"
  else
    print -u2 "The QR-Scanner is signed with Developer ID, but not with pinned Team ID ${expected_team}."
    exit 1
  fi
elif [[ ${app_signature} == *'Authority=Apple Development:'* ]]; then
  if (( ! allow_development )); then
    print -u2 'The QR-Scanner is signed with Apple Development, but --allow-development was not specified.'
    exit 1
  fi
  if [[ ${app_signature} == *"TeamIdentifier=${expected_team}"* ]]; then
    print 'team_id=development (accepted by --allow-development)'
  else
    print -u2 "The QR-Scanner is signed with Apple Development, but not with pinned Team ID ${expected_team}."
    exit 1
  fi
else
  print -u2 'The QR-Scanner does not have a recognized Developer ID Application or Apple Development signature.'
  exit 1
fi

# Verify Hardened Runtime and Entitlements
if [[ ${app_signature} != *'flags='*'runtime'* ]]; then
  print -u2 'The QR-Scanner is missing the hardened runtime flag.'
  exit 1
fi

if ! codesign -d --entitlements - ${app_path} >/dev/null 2>&1; then
  print -u2 'Could not read entitlements from QR-Scanner.'
  exit 1
fi

entitlements_xml=$(mktemp "${private_temp_parent}/qr-scanner-entitlements.XXXXXX")
cleanup() {
  local original_status=$?
  local cleanup_status=0
  trap - EXIT INT TERM
  set +e
  cleanup_private_nuget_cache || cleanup_status=$?
  rm -f -- ${entitlements_xml} || cleanup_status=$?
  if (( original_status != 0 )); then
    exit ${original_status}
  fi
  exit ${cleanup_status}
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

codesign -d --entitlements :${entitlements_xml} ${app_path} >/dev/null 2>&1

sandbox_val=$(plistbuddy -c 'Print :com.apple.security.app-sandbox' ${entitlements_xml} 2>/dev/null || true)
camera_val=$(plistbuddy -c 'Print :com.apple.security.device.camera' ${entitlements_xml} 2>/dev/null || true)

if [[ ${sandbox_val} != 'true' ]]; then
  print -u2 'The QR-Scanner is missing mandatory entitlement: com.apple.security.app-sandbox'
  exit 1
fi

if [[ ${camera_val} != 'true' ]]; then
  print -u2 'The QR-Scanner is missing mandatory entitlement: com.apple.security.device.camera'
  exit 1
fi

disallowed_entitlements=(
  com.apple.security.get-task-allow
  com.apple.security.cs.allow-jit
  com.apple.security.cs.allow-unsigned-executable-memory
  com.apple.security.cs.disable-library-validation
  com.apple.security.cs.disable-executable-page-protection
  com.apple.security.cs.allow-dyld-environment-variables
  com.apple.security.cs.allow-relative-library-loads
  com.apple.security.cs.debugger
  com.apple.security.network.client
  com.apple.security.network.server
  com.apple.security.device.audio-input
  com.apple.security.device.usb
  com.apple.security.device.bluetooth
  com.apple.security.automation.apple-events
)

for disallowed in ${disallowed_entitlements[@]}; do
  if plistbuddy -c "Print :${disallowed}" ${entitlements_xml} >/dev/null 2>&1; then
    print -u2 "Disallowed entitlement is present in QR-Scanner: ${disallowed}"
    exit 1
  fi
done

# Verify five hybrid integrity sidecars beside the app
for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
  sidecar=${app_path}${suffix}
  if [[ ! -f ${sidecar} || -L ${sidecar} ]]; then
    print -u2 "Required hybrid signature sidecar is missing from QR-Scanner: ${sidecar}"
    exit 1
  fi
done

if [[ -f ${mldsa_public_key} ]]; then
  signer_lock=${repo_root}/KeepVaultMac/Packaging/HybridSigner/packages.lock.json
  if [[ ! -f ${signer_lock} || -L ${signer_lock} \
      || $(shasum -a 256 ${signer_lock} | awk '{print toupper($1)}') != ${expected_signer_lock_sha256} ]]; then
    print -u2 'The reviewed hybrid-verifier NuGet lockfile is missing or changed.'
    exit 1
  fi
  create_private_nuget_cache
  provision_verified_dotnet
  selected_sdk=$(run_dotnet_clean --version)
  [[ ${selected_sdk} == '10.0.400' ]] || {
    print -u2 'The managed hybrid verifier requires the reviewed official .NET SDK 10.0.400.'
    exit 1
  }
  signer_dll=${private_dotnet_artifacts}/bin/KeepVaultMac.HybridSigner/release/KeepVaultMac.HybridSigner.dll
  signer_project=${repo_root}/KeepVaultMac/Packaging/HybridSigner/KeepVaultMac.HybridSigner.csproj
  signer_intermediate=${private_dotnet_artifacts}/obj/KeepVaultMac.HybridSigner
  run_dotnet_clean restore ${signer_project} --locked-mode --nologo \
    --artifacts-path ${private_dotnet_artifacts} --disable-build-servers \
    -p:BaseIntermediateOutputPath=${signer_intermediate}/ \
    -p:MSBuildProjectExtensionsPath=${signer_intermediate}/
  run_dotnet_clean build ${signer_project} -c Release --no-restore --no-incremental --nologo \
    --artifacts-path ${private_dotnet_artifacts} --disable-build-servers \
    -p:BaseIntermediateOutputPath=${signer_intermediate}/ \
    -p:MSBuildProjectExtensionsPath=${signer_intermediate}/ \
    -p:UseSharedCompilation=false
  [[ -f ${signer_dll} && ! -L ${signer_dll} ]] || {
    print -u2 'The locked hybrid verifier build did not produce its managed entry assembly.'
    exit 1
  }
  signer_dll_identity=$(${stat_path} -f '%d:%i:%u:%p:%z:%m:%c:%l' -- ${signer_dll})
  require_private_signer_identity || {
    print -u2 'The private managed hybrid verifier has unsafe or unstable identity metadata.'
    exit 1
  }

  scanner_stage=$(mktemp -d "${private_dotnet_tmp}/qr-scanner-verify.XXXXXXXX")
  ditto ${scanner_binary} ${scanner_stage}/QR-Scanner
  for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    ditto ${app_path}${suffix} ${scanner_stage}/QR-Scanner${suffix}
  done
  scanner_status=0
  run_dotnet_clean --direct-signer ${signer_dll} verify \
    --mldsa-public-key ${mldsa_public_key} \
    --policy ${repo_root}/KeepVaultMac/Directory.Build.props \
    --target ${scanner_stage}/QR-Scanner || scanner_status=$?
  rm -rf -- ${scanner_stage}
  (( scanner_status == 0 )) || exit ${scanner_status}
  print 'scanner_hybrid_signature=verified'
else
  print -u2 'The independent managed hybrid verifier or pinned ML-DSA public key is unavailable for QR-Scanner.'
  exit 1
fi

if spctl --assess --type execute --verbose=4 ${app_path}; then
  print 'scanner_gatekeeper=accepted'
else
  if (( allow_development )) && [[ ${app_signature} == *'Authority=Apple Development:'* ]]; then
    print 'scanner_gatekeeper=not_accepted (expected for local Apple Development signing)'
  else
    print -u2 'Gatekeeper did not accept the QR-Scanner bundle.'
    exit 1
  fi
fi

if (( require_notarization )); then
  stapler validate ${app_path}
  print 'scanner_notarization=stapled-and-valid'
fi

print "scanner_verified=${app_path}"
