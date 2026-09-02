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
plutil_path=/usr/bin/plutil
file_path=/usr/bin/file
find_path=/usr/bin/find
grep_path=/usr/bin/grep
tr_path=/usr/bin/tr
sort_path=/usr/bin/sort
xargs_path=/usr/bin/xargs
awk_path=/usr/bin/awk
mktemp_path=/usr/bin/mktemp
shasum_path=/usr/bin/shasum
ditto_path=/usr/bin/ditto
stat_path=/usr/bin/stat
plistbuddy_path=/usr/libexec/PlistBuddy
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
    print -u2 "KEEP VAULT VERIFY GATE: required tool is not an absolute root-owned regular file: ${tool}"
    exit 2
  fi
  local tool_mode=$(( 8#$(${stat_path} -f %Lp -- ${tool}) ))
  if (( (tool_mode & 8#022) != 0 )); then
    print -u2 "KEEP VAULT VERIFY GATE: required tool is group/other writable: ${tool}"
    exit 2
  fi
}

for fixed_tool in \
    ${xcrun_path} ${codesign_path} ${plutil_path} ${file_path} ${find_path} \
    ${grep_path} ${tr_path} ${sort_path} ${xargs_path} ${awk_path} \
    ${mktemp_path} ${shasum_path} ${ditto_path} ${stat_path} \
    ${plistbuddy_path} ${spctl_path} ${rm_path} ${env_path} ${id_path} \
    ${mkdir_path} ${chmod_path} ${mv_path} ${rmdir_path}; do
  require_root_system_tool ${fixed_tool}
done

lipo_path=$(${xcrun_path} --sdk macosx --find lipo)
lipo_path=${lipo_path:A}
otool_path=$(${xcrun_path} --sdk macosx --find otool)
otool_path=${otool_path:A}
stapler_path=$(${xcrun_path} --find stapler)
stapler_path=${stapler_path:A}
for developer_tool in ${lipo_path} ${otool_path} ${stapler_path}; do
  require_root_system_tool ${developer_tool}
done

sdk_root=$(${xcrun_path} --sdk macosx --show-sdk-path)
sdk_root=${sdk_root:A}
if [[ ! -d ${sdk_root} || -L ${sdk_root} \
    || $(${stat_path} -f %u -- ${sdk_root}) != 0 ]]; then
  print -u2 'KEEP VAULT VERIFY GATE: the selected macOS SDK is not a root-owned physical directory.'
  exit 2
fi
sdk_mode=$(( 8#$(${stat_path} -f %Lp -- ${sdk_root}) ))
if (( (sdk_mode & 8#022) != 0 )); then
  print -u2 'KEEP VAULT VERIFY GATE: the selected macOS SDK is group/other writable.'
  exit 2
fi

codesign() { ${codesign_path} "$@"; }
plutil() { ${plutil_path} "$@"; }
file() { ${file_path} "$@"; }
find() { ${find_path} "$@"; }
grep() { ${grep_path} "$@"; }
tr() { ${tr_path} "$@"; }
sort() { ${sort_path} "$@"; }
xargs() { ${xargs_path} "$@"; }
awk() { ${awk_path} "$@"; }
mktemp() { ${mktemp_path} "$@"; }
shasum() { ${env_path} -i PATH='/usr/bin:/bin:/usr/sbin:/sbin' ${shasum_path} "$@"; }
ditto() { ${ditto_path} "$@"; }
plistbuddy() { ${plistbuddy_path} "$@"; }
spctl() { ${spctl_path} "$@"; }
rm() { ${rm_path} "$@"; }
lipo() { ${lipo_path} "$@"; }
otool() { ${otool_path} "$@"; }
stapler() { ${stapler_path} "$@"; }
mkdir() { ${mkdir_path} "$@"; }
chmod() { ${chmod_path} "$@"; }
mv() { ${mv_path} "$@"; }
rmdir() { ${rmdir_path} "$@"; }

if ! zmodload zsh/system || ! zmodload -F zsh/stat b:zstat; then
  print -u2 'KEEP VAULT VERIFY GATE: zsh descriptor/stat modules are unavailable.'
  exit 2
fi

bound_verifier_notice_identity() {
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

hash_verifier_notice_fd() {
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
      print -u2 "KEEP VAULT VERIFY GATE: managed injection variable survived sanitization: ${variable}"
      exit 2
    fi
  done
  if [[ ${DOTNET_EnableDiagnostics} != 0 || ${COMPlus_EnableDiagnostics} != 0 ]]; then
    print -u2 'KEEP VAULT VERIFY GATE: managed diagnostics were not disabled.'
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
    print -u2 'KEEP VAULT VERIFY GATE: /private/tmp identity changed before cache creation.'
    return 2
  }
  private_nuget_root=$(mktemp -d "${private_temp_parent}/keep-vault-verifier.XXXXXXXX")
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
    print -u2 'KEEP VAULT VERIFY GATE: failed to create the identity-bound private NuGet cache.'
    return 2
  }
  local -a initial_package_entries=(${private_nuget_packages}/*(DN))
  if (( ${#initial_package_entries[@]} != 0 )); then
    print -u2 'KEEP VAULT VERIFY GATE: the new private NuGet package cache is not empty.'
    return 2
  fi
}

cleanup_private_nuget_cache() {
  [[ -n ${private_nuget_root:-} ]] || return 0
  if (( private_nuget_cache_ready )); then
    require_private_nuget_cache_identity || {
      print -u2 'KEEP VAULT VERIFY GATE: private NuGet cache identity changed; preserving it for inspection.'
      return 2
    }
  elif [[ ${private_nuget_root} != ${private_temp_parent}/keep-vault-verifier.* \
      || ! -d ${private_nuget_root} || -L ${private_nuget_root} \
      || $(directory_identity ${private_nuget_root} || print invalid) != ${private_nuget_root_identity} ]]; then
    print -u2 'KEEP VAULT VERIFY GATE: incomplete private NuGet cache cannot be removed safely.'
    return 2
  fi
  rm -rf -- ${private_nuget_root}
  if [[ -e ${private_nuget_root} || -L ${private_nuget_root} ]]; then
    print -u2 'KEEP VAULT VERIFY GATE: private NuGet cache cleanup failed.'
    return 2
  fi
  private_nuget_root=''
  private_nuget_cache_ready=0
}

self_test_private_nuget_cache_identity() {
  require_private_nuget_cache_identity
  local held_path=${private_nuget_root}.held
  if [[ -e ${held_path} || -L ${held_path} ]]; then
    print -u2 'KEEP VAULT VERIFY GATE: private-cache identity self-test path already exists.'
    return 2
  fi
  mv -- ${private_nuget_root} ${held_path}
  if [[ $(directory_identity ${held_path}) != ${private_nuget_root_identity} ]]; then
    print -u2 'KEEP VAULT VERIFY GATE: private-cache identity changed during the self-test hold.'
    return 2
  fi
  mkdir -m 0700 ${private_nuget_root}
  local replacement_identity=$(directory_identity ${private_nuget_root})
  local substitution_was_rejected=0
  require_private_nuget_cache_identity >/dev/null 2>&1 || substitution_was_rejected=1
  if [[ $(directory_identity ${private_nuget_root}) != ${replacement_identity} ]]; then
    print -u2 'KEEP VAULT VERIFY GATE: refusing to remove a changed cache-test replacement.'
    return 2
  fi
  rmdir -- ${private_nuget_root}
  mv -- ${held_path} ${private_nuget_root}
  require_private_nuget_cache_identity
  if (( ! substitution_was_rejected )); then
    print -u2 'KEEP VAULT VERIFY GATE: private-cache pathname substitution was not rejected.'
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
    print -u2 'KEEP VAULT VERIFY GATE: private runtime or SDK provisioner identity changed before provisioning.'
    return 2
  fi
  if [[ -e ${private_dotnet_sdk} || -L ${private_dotnet_sdk} ]]; then
    print -u2 'KEEP VAULT VERIFY GATE: verified SDK target already exists.'
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
    print -u2 'KEEP VAULT VERIFY GATE: SDK provisioner identity changed while executing.'
    return 2
  fi
  (( provision_status == 0 )) || return ${provision_status}
  if [[ ${dotnet_command} != ${private_dotnet_sdk}/dotnet \
      || ! -d ${private_dotnet_sdk} || -L ${private_dotnet_sdk} ]]; then
    print -u2 'KEEP VAULT VERIFY GATE: verified SDK provisioner returned an unexpected host path.'
    return 2
  fi
  private_dotnet_sdk_identity=$(directory_identity ${private_dotnet_sdk})
  private_dotnet_sdk_ready=1
  dotnet_host_identity=$(${stat_path} -f '%d:%i:%u:%p:%z:%m:%c:%l' -- ${dotnet_command})
  if ! require_private_nuget_cache_identity || ! require_dotnet_host_identity; then
    print -u2 'KEEP VAULT VERIFY GATE: provisioned SDK identity validation failed.'
    return 2
  fi
}

run_dotnet_clean() {
  if ! require_private_nuget_cache_identity || ! require_dotnet_host_identity; then
    print -u2 'KEEP VAULT VERIFY GATE: private cache or .NET host identity changed before a .NET invocation.'
    return 2
  fi
  local direct_signer=0
  if [[ ${1:-} == --direct-signer ]]; then
    direct_signer=1
    shift
    if [[ ${1:-} != ${signer_dll} ]] || ! require_private_signer_identity; then
      print -u2 'KEEP VAULT VERIFY GATE: private signer identity changed before execution.'
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
    print -u2 'KEEP VAULT VERIFY GATE: private cache or .NET host identity changed during a .NET invocation.'
    (( dotnet_status != 0 )) && return ${dotnet_status}
    return 2
  fi
  if (( direct_signer )) && ! require_private_signer_identity; then
    print -u2 'KEEP VAULT VERIFY GATE: private signer identity changed during execution.'
    (( dotnet_status != 0 )) && return ${dotnet_status}
    return 2
  fi
  return ${dotnet_status}
}

if [[ ! -d ${private_temp_parent} || -L ${private_temp_parent} \
    || $(${stat_path} -f '%u:%p' -- ${private_temp_parent} 2>/dev/null || print invalid) != '0:41777' ]]; then
  print -u2 'KEEP VAULT VERIFY GATE: /private/tmp must be a physical root-owned mode-1777 directory.'
  exit 2
fi
private_temp_parent_identity=$(directory_identity ${private_temp_parent})
require_private_temp_parent_identity || {
  print -u2 'KEEP VAULT VERIFY GATE: could not bind the physical /private/tmp directory identity.'
  exit 2
}

script_dir=${0:A:h}
repo_root=${script_dir:h}
dotnet_provisioner=${script_dir}/Provision-VerifiedDotnet-macOS.sh
require_repository_executable ${dotnet_provisioner} || {
  print -u2 'KEEP VAULT VERIFY GATE: verified SDK provisioner is missing or unsafe.'
  exit 2
}
dotnet_provisioner_identity=$(${stat_path} -f '%d:%i:%u:%p:%z:%m:%c:%l' -- ${dotnet_provisioner})
expected_team='2T6K9PGS55'
expected_bundle='de.michael-feinermann.keep-vault'
app_path=''
allow_development=0
require_notarization=0
mldsa_public_key=${KEEPVAULT_MLDSA_PUBLIC_KEY:-${repo_root}/KeepVaultMac/Packaging/Keys/mldsa87-public.key}
require_launcher_signature=0
tool_path_self_test=0
expected_signer_lock_sha256='B07635B8B5CF158644267CBB99E6483D6F947F37D3B9918B4FF39407EB6BA5EB'

usage() {
  print -u2 'Usage: Verify-KeepVault-macOS.sh --app "Keep Vault.app" [--allow-development]'
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
    --require-launcher-signature)
      require_launcher_signature=1
      shift
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
  print 'keepvault_verifier_tool_paths=verified'
  exit 0
fi

[[ -n ${app_path} ]] || usage
app_path=${app_path:A}
if [[ ! -d ${app_path} || -L ${app_path} || ${app_path:e} != app ]]; then
  print -u2 "App bundle is missing, not a directory, or a symbolic link: ${app_path}"
  exit 1
fi
if find ${app_path} -type l -print -quit | grep -q .; then
  print -u2 'The Keep Vault bundle contains a symbolic link and is rejected.'
  exit 1
fi
if find ${app_path} -type f -links +1 -print -quit | grep -q .; then
  print -u2 'The Keep Vault bundle contains hard-linked files and is rejected.'
  exit 1
fi
if find ${app_path} -perm -022 -print -quit | grep -q .; then
  print -u2 'The Keep Vault bundle contains group- or world-writable objects and is rejected.'
  exit 1
fi

info_plist=${app_path}/Contents/Info.plist
plutil -lint ${info_plist} >/dev/null
plist_value() {
  plistbuddy -c "Print :$1" ${info_plist}
}

[[ $(plist_value CFBundleIdentifier) == ${expected_bundle} ]] || {
  print -u2 'Unexpected CFBundleIdentifier.'
  exit 1
}
[[ $(plist_value CFBundleDisplayName) == 'Keep Vault' ]] || {
  print -u2 'Unexpected CFBundleDisplayName.'
  exit 1
}
[[ $(plist_value CFBundleExecutable) == 'Keep Vault Launcher' ]] || {
  print -u2 'The bundle does not name the integrity launcher as its entry point.'
  exit 1
}
[[ $(plist_value LSMinimumSystemVersion) == '14.0' ]] || {
  print -u2 'Unexpected minimum macOS version.'
  exit 1
}
[[ $(plist_value CFBundleDocumentTypes:0:CFBundleTypeExtensions:0) == kzpaq ]] || {
  print -u2 'The .kzpaq file association is missing.'
  exit 1
}
[[ $(plist_value CFBundleDocumentTypes:1:CFBundleTypeExtensions:0) == zpaq ]] || {
  print -u2 'The .zpaq file association is missing.'
  exit 1
}

launcher=${app_path}/Contents/MacOS/Keep\ Vault\ Launcher
core=${app_path}/Contents/MacOS/Keep\ Vault
supervisor=${app_path}/Contents/MacOS/Keep\ Vault\ Supervisor
native_dir=${app_path}/Contents/MacOS/Native
third_party_notices=${app_path}/Contents/Resources/THIRD-PARTY-NOTICES.txt
expected_third_party_notices_sha256='bd4bd21c7ffa79d36a4f20abb6b7af3116fc005d3971ca0be09b49e083d6f159'
third_party_notice_fd=-1
if ! sysopen -r -o nofollow -u third_party_notice_fd ${third_party_notices}; then
  print -u2 'THIRD-PARTY-NOTICES.txt is missing or cannot be opened without following a symbolic link.'
  exit 1
fi
third_party_notice_before=$(bound_verifier_notice_identity ${third_party_notice_fd}) || {
  print -u2 'THIRD-PARTY-NOTICES.txt has no stable descriptor identity.'
  exit 1
}
third_party_notice_fields=("${(@s.:.)third_party_notice_before}")
third_party_notice_mode=${third_party_notice_fields[4]}
third_party_notice_size=${third_party_notice_fields[6]}
if (( (third_party_notice_mode & 8#170000) != 8#100000 \
    || (third_party_notice_mode & 8#022) != 0 \
    || third_party_notice_fields[5] != 1 \
    || third_party_notice_size < 300000 || third_party_notice_size > 2000000 )) \
    || [[ ${third_party_notice_fields[3]} != 0 \
        && ${third_party_notice_fields[3]} != ${EUID} ]]; then
  print -u2 'THIRD-PARTY-NOTICES.txt is not a protected single-link regular file with a plausible length.'
  exit 1
fi
hash_verifier_notice_fd ${third_party_notice_fd} || {
  print -u2 'THIRD-PARTY-NOTICES.txt could not be hashed through its bound descriptor.'
  exit 1
}
if [[ ${REPLY} != ${expected_third_party_notices_sha256} ]]; then
  print -u2 'THIRD-PARTY-NOTICES.txt does not match the reviewed whole-file digest.'
  exit 1
fi
for notice_marker in \
    'Crypto++ 8.9.0' \
    'ZPAQ and libdivsufsort-lite' \
    'BouncyCastle.Cryptography 2.6.2' \
    'QRCoder 1.8.0' \
    'HarfBuzzSharp native assets 8.3.1.3 third-party notices' \
    'SkiaSharp native assets 3.119.4 third-party notices' \
    '.NET 10.0.11 NativeAOT runtime third-party notices' \
    'SIL OPEN FONT LICENSE Version 1.1' \
    'Brian Gladman'; do
  sysseek -u ${third_party_notice_fd} -w start 0 || exit 1
  if ! grep -Fq -- ${notice_marker} <&${third_party_notice_fd}; then
    print -u2 "THIRD-PARTY-NOTICES.txt is incomplete; missing section: ${notice_marker}"
    exit 1
  fi
done
third_party_notice_after=$(bound_verifier_notice_identity ${third_party_notice_fd}) || exit 1
local_notice_path_identity=invalid
local_notice_path_mode=0
typeset -A local_notice_path_stat
if zstat -L -H local_notice_path_stat ${third_party_notices} 2>/dev/null; then
  local_notice_path_identity=${local_notice_path_stat[device]}:${local_notice_path_stat[inode]}
  local_notice_path_mode=${local_notice_path_stat[mode]}
fi
if [[ ${third_party_notice_after} != ${third_party_notice_before} \
    || ${local_notice_path_identity} != ${third_party_notice_fields[1]}:${third_party_notice_fields[2]} ]] \
    || (( (local_notice_path_mode & 8#170000) != 8#100000 )); then
  print -u2 'THIRD-PARTY-NOTICES.txt changed identity while it was verified.'
  exit 1
fi
exec {third_party_notice_fd}<&-
required_native=(
  zpaq
  libkalyna_v12.dylib
  libthreefish_ref.dylib
  libmars_ref.dylib
  libshacal2_ref.dylib
  libaes_ref.dylib
  libchachapoly_ref.dylib
  libargon2_ref.dylib
  argon2
)
for required_path in ${launcher} ${core} ${supervisor} ${required_native[@]/#/${native_dir}/}; do
  if [[ ! -f ${required_path} || -L ${required_path} ]]; then
    print -u2 "Required executable component is missing or a symbolic link: ${required_path}"
    exit 1
  fi
  [[ -x ${required_path} ]] || {
    print -u2 "Required executable component is not executable: ${required_path}"
    exit 1
  }
  file -b ${required_path} | grep -q 'Mach-O' || {
    print -u2 "Required executable component is not Mach-O: ${required_path}"
    exit 1
  }
done

# The list above is the macOS spelling of
# NativeToolIntegrity.RequiredLogicalToolNames. Presence alone is not enough:
# an unreviewed extra helper in Native/ is executable payload too and must not
# slip past the release inventory merely because the nine expected files are
# present as well.
native_entries=(${native_dir}/*(N))
if (( ${#native_entries[@]} != ${#required_native[@]} )); then
  print -u2 "The shipped Native directory is not the exact required nine-component set."
  exit 1
fi
typeset -A required_native_set
for required_name in ${required_native[@]}; do
  required_native_set[${required_name}]=1
done
for native_entry in ${native_entries[@]}; do
  if [[ ! -f ${native_entry} || -z ${required_native_set[${native_entry:t}]:-} ]]; then
    print -u2 "Unexpected object in the shipped Native directory: ${native_entry}"
    exit 1
  fi
done

codesign --verify --deep --strict --verbose=4 ${app_path}
outer_requirement="identifier \"${expected_bundle}\" and anchor apple generic and certificate leaf[subject.OU] = \"${expected_team}\""
core_requirement="identifier \"${expected_bundle}.core\" and anchor apple generic and certificate leaf[subject.OU] = \"${expected_team}\""
supervisor_requirement="identifier \"${expected_bundle}.supervisor\" and anchor apple generic and certificate leaf[subject.OU] = \"${expected_team}\""
codesign --verify --strict -R=${outer_requirement} ${app_path}
codesign --verify --strict -R=${core_requirement} ${core}
codesign --verify --strict -R=${supervisor_requirement} ${supervisor}

macho_files=()
while IFS= read -r -d '' candidate; do
  if file -b ${candidate} | grep -q 'Mach-O'; then
    macho_files+=(${candidate})
  fi
done < <(find ${app_path}/Contents -type f -print0)
minimum_macho_count=$(( 3 + ${#required_native[@]} ))
(( ${#macho_files[@]} >= minimum_macho_count )) || {
  print -u2 'The signed bundle has fewer Mach-O components than expected.'
  exit 1
}

expected_architectures=$(lipo ${launcher} -archs | tr ' ' '\n' | sort | xargs)
for macho in ${macho_files[@]}; do
  codesign --verify --strict --verbose=2 ${macho}
  signature_details=$(codesign -dvvv ${macho} 2>&1)
  [[ ${signature_details} == *"TeamIdentifier=${expected_team}"* ]] || {
    print -u2 "Unexpected or absent Apple TeamIdentifier: ${macho}"
    exit 1
  }
  [[ ${signature_details} == *'flags='*'runtime'* ]] || {
    print -u2 "Hardened Runtime is absent: ${macho}"
    exit 1
  }
  architectures=$(lipo ${macho} -archs)
  [[ " ${architectures} " == *' arm64 '* ]] || {
    print -u2 "arm64 slice is absent: ${macho}"
    exit 1
  }
  normalized_architectures=$(print -r -- ${architectures} | tr ' ' '\n' | sort | xargs)
  [[ ${normalized_architectures} == ${expected_architectures} ]] || {
    print -u2 "Mach-O architecture set differs from the launcher: ${macho}"
    exit 1
  }
  # Enumerate real load-time dependencies straight from the Mach-O load
  # commands instead of parsing "otool -L". That listing repeats an unindented
  # header for every universal slice, and for a library its first entry is the
  # file's own LC_ID_DYLIB install name rather than a dependency — Avalonia's
  # native library, for instance, is named /usr/local/lib/... without ever
  # loading from there. Selecting the LC_LOAD_* commands covers every slice and
  # every load kind while excluding the install name by construction.
  while IFS= read -r dependency; do
    [[ -z ${dependency} ]] && continue
    case ${dependency} in
      /System/Library/*|/usr/lib/*|@rpath/*|@loader_path/*|@executable_path/*) ;;
      *)
        print -u2 "Non-system absolute Mach-O dependency is blocked: ${macho} -> ${dependency}"
        exit 1
        ;;
    esac
  done < <(otool -l ${macho} | awk '
    /^ *cmd LC_(LOAD_DYLIB|LOAD_WEAK_DYLIB|REEXPORT_DYLIB|LAZY_LOAD_DYLIB|LOAD_UPWARD_DYLIB)$/ { want = 1; next }
    /^ *cmd / { want = 0 }
    want && /^ *name / { print $2; want = 0 }')
done

core_details=$(codesign -dvvv ${core} 2>&1)
supervisor_details=$(codesign -dvvv ${supervisor} 2>&1)
outer_details=$(codesign -dvvv ${app_path} 2>&1)
[[ ${outer_details} == *"Identifier=${expected_bundle}"* ]] || {
  print -u2 'The outer app signature identifier is incorrect.'
  exit 1
}
[[ ${core_details} == *'Identifier=de.michael-feinermann.keep-vault.core'* ]] || {
  print -u2 'The nested NativeAOT Core identifier is incorrect.'
  exit 1
}
[[ ${supervisor_details} == *'Identifier=de.michael-feinermann.keep-vault.supervisor'* ]] || {
  print -u2 'The suspended-execution Supervisor identifier is incorrect.'
  exit 1
}

entitlement_root=$(mktemp -d "${private_temp_parent}/keep-vault-entitlements.XXXXXXXX")
cleanup() {
  local original_status=$?
  local cleanup_status=0
  trap - EXIT INT TERM
  set +e
  cleanup_private_nuget_cache || cleanup_status=$?
  if [[ -n ${entitlement_root:-} && -d ${entitlement_root} && ${entitlement_root} == */keep-vault-entitlements.* ]]; then
    rm -rf -- ${entitlement_root} || cleanup_status=$?
  fi
  if (( original_status != 0 )); then
    exit ${original_status}
  fi
  exit ${cleanup_status}
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

extract_entitlements() {
  local executable=$1
  local output=$2
  codesign -d --entitlements :- --xml ${executable} > ${output} 2>/dev/null
  # A correctly signed dylib normally carries no entitlement blob at all.
  # codesign reports that state successfully but writes zero bytes, whereas
  # plutil quite properly rejects a zero-length file. Normalize only that
  # successful no-entitlements result to an empty plist so every Mach-O can
  # still flow through the same deny-list below.
  if [[ ! -s ${output} ]]; then
    plutil -create xml1 ${output}
  fi
  plutil -lint ${output} >/dev/null
}

entitlement_files=()
for macho in ${macho_files[@]}; do
  entitlement_name=$(print -n -- ${macho#${app_path}/} | shasum -a 256 | awk '{print $1 ".plist"}')
  entitlement_file=${entitlement_root}/${entitlement_name}
  extract_entitlements ${macho} ${entitlement_file}
  entitlement_files+=(${entitlement_file})
done

# Keep Vault does not use the App Sandbox: it is mutually exclusive with the
# integrity chain on macOS, because a sandboxed process is not served a file
# panel and making the core able to own a sandbox would place it inside the
# bundle seal, whose re-sealing invalidates the hybrid signature the launcher
# verifies before running it. See KeepVault.entitlements for the full reasoning.
#
# That trade-off is only defensible if it stays deliberate, so assert the
# sandbox is absent everywhere rather than letting it reappear unnoticed and
# silently break panels again.
for image_entitlements in ${entitlement_files[@]}; do
  for sandbox_key in com.apple.security.app-sandbox com.apple.security.inherit; do
    if plistbuddy -c "Print :${sandbox_key}" ${image_entitlements} >/dev/null 2>&1; then
      print -u2 "The App Sandbox must not be declared: ${sandbox_key} in ${image_entitlements:t}"
      exit 1
    fi
  done
done

# Nothing in this bundle reaches hardware any more. Reading a printed key sheet
# by camera moved to a separate application, so no image here declares a device
# capability at all — the core included.
for bare_entitlements in ${entitlement_files[@]}; do
  if plistbuddy -c 'Print :com.apple.security.device.camera' ${bare_entitlements} >/dev/null 2>&1; then
    print -u2 "No component may declare camera access: ${bare_entitlements:t}"
    exit 1
  fi
done

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
for entitlement_file in ${entitlement_files[@]}; do
  for disallowed in ${disallowed_entitlements[@]}; do
    if plistbuddy -c "Print :${disallowed}" ${entitlement_file} >/dev/null 2>&1; then
      print -u2 "Disallowed entitlement is present: ${disallowed}"
      exit 1
    fi
  done
done

# Contents/MacOS is reserved for Mach-O executables, so the detached hash and
# hybrid-signature sidecars live under Contents/Resources/HybridSignatures,
# mirroring the layout below Contents/MacOS.
macos_root=${app_path}/Contents/MacOS
signature_root=${app_path}/Contents/Resources/HybridSignatures
hybrid_targets=()
for macho in ${macho_files[@]}; do
  [[ ${macho} == ${launcher} ]] && continue
  if [[ ${macho} != ${macos_root}/* ]]; then
    print -u2 "Mach-O payload exists outside Contents/MacOS and has no defined hybrid-sidecar layout: ${macho}"
    exit 1
  fi
  hybrid_targets+=(${macho})
done
for target in ${hybrid_targets[@]}; do
  sidecar_base=${signature_root}/${target#${macos_root}/}
  for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    sidecar=${sidecar_base}${suffix}
    if [[ ! -f ${sidecar} || -L ${sidecar} ]]; then
      print -u2 "Required hybrid integrity sidecar is missing or a symbolic link: ${sidecar}"
      exit 1
    fi
  done
done

# Nothing but Mach-O payload may remain in Contents/MacOS, otherwise codesign
# cannot seal the bundle and the relocation step silently regressed.
if find ${macos_root} -type f \( -name '*.sha3' -o -name '*.skein' -o -name '*.khsig' \) -print -quit | grep -q .; then
  print -u2 'Hybrid-signature sidecars are present in Contents/MacOS; the bundle layout is invalid.'
  exit 1
fi

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
  verify_arguments=(
    ${signer_dll}
    verify
    --mldsa-public-key ${mldsa_public_key}
    --policy ${repo_root}/KeepVaultMac/Directory.Build.props
    --payload-root ${macos_root}
    --signature-root ${signature_root}
  )
  for target in ${hybrid_targets[@]}; do
    verify_arguments+=(--target ${target})
  done
  run_dotnet_clean --direct-signer ${verify_arguments[@]}
  # The launcher carries the bundle seal in its own bytes, so its dual
  # signature lives beside the app rather than inside it. Verifying it needs the
  # default sidecar naming, so binary and sidecars are staged together under the
  # name the verifier expects; copying preserves the bytes the signature binds
  # to.
  launcher_binary=${macos_root}/Keep\ Vault\ Launcher
  launcher_sidecar_base=${app_path}.launcher
  if [[ -f ${launcher_sidecar_base}.khsig && ! -L ${launcher_sidecar_base}.khsig ]]; then
    launcher_stage=$(mktemp -d "${private_dotnet_tmp}/keep-vault-launcher-verify.XXXXXXXX")
    ditto ${launcher_binary} ${launcher_stage}/Keep\ Vault\ Launcher
    for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
      if [[ ! -f ${launcher_sidecar_base}${suffix} || -L ${launcher_sidecar_base}${suffix} ]]; then
        rm -rf -- ${launcher_stage}
        print -u2 "The launcher self-signature is incomplete: ${launcher_sidecar_base:t}${suffix}"
        exit 1
      fi
      ditto ${launcher_sidecar_base}${suffix} ${launcher_stage}/Keep\ Vault\ Launcher${suffix}
    done
    launcher_status=0
    run_dotnet_clean --direct-signer ${signer_dll} verify \
      --mldsa-public-key ${mldsa_public_key} \
      --policy ${repo_root}/KeepVaultMac/Directory.Build.props \
      --target ${launcher_stage}/Keep\ Vault\ Launcher || launcher_status=$?
    rm -rf -- ${launcher_stage}
    (( launcher_status == 0 )) || exit ${launcher_status}
    print 'launcher_self_signature=verified'
  elif (( require_launcher_signature )); then
    print -u2 "The launcher self-signature is required but missing: ${launcher_sidecar_base:t}.khsig"
    exit 1
  else
    print 'launcher_self_signature=absent (bundle not yet released)'
  fi
else
  print -u2 'The independent managed hybrid verifier or pinned ML-DSA public key is unavailable.'
  exit 1
fi

if spctl --assess --type execute --verbose=4 ${app_path}; then
  print 'gatekeeper=accepted'
else
  app_signature=$(codesign -dvvv ${app_path} 2>&1)
  if (( allow_development )) && [[ ${app_signature} == *'Authority=Apple Development:'* ]]; then
    print 'gatekeeper=not_accepted (expected for local Apple Development signing)'
  else
    print -u2 'Gatekeeper did not accept the app bundle.'
    exit 1
  fi
fi

if (( require_notarization )); then
  stapler validate ${app_path}
  print 'notarization=stapled-and-valid'
else
  print 'notarization=not-required-by-this-local-verification'
fi

print "bundle_verified=${app_path}"
