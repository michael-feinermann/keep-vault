#!/bin/zsh -f
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
codesign_path=/usr/bin/codesign
security_path=/usr/bin/security
plutil_path=/usr/bin/plutil
ditto_path=/usr/bin/ditto
iconutil_path=/usr/bin/iconutil
sed_path=/usr/bin/sed
grep_path=/usr/bin/grep
head_path=/usr/bin/head
stat_path=/usr/bin/stat
mktemp_path=/usr/bin/mktemp
uname_path=/usr/bin/uname
find_path=/usr/bin/find
plistbuddy_path=/usr/libexec/PlistBuddy
spctl_path=/usr/sbin/spctl
rm_path=/bin/rm
mkdir_path=/bin/mkdir
ln_path=/bin/ln
chmod_path=/bin/chmod
mv_path=/bin/mv
rmdir_path=/bin/rmdir

require_root_system_tool() {
  local tool=$1
  if [[ ${tool} != /* || ! -f ${tool} || -L ${tool} || ! -x ${tool} \
      || $(${stat_path} -f %u -- ${tool}) != 0 ]]; then
    print -u2 "QR RELEASE GATE: required tool is not an absolute root-owned regular file: ${tool}"
    exit 2
  fi
  local tool_mode=$(( 8#$(${stat_path} -f %Lp -- ${tool}) ))
  if (( (tool_mode & 8#022) != 0 )); then
    print -u2 "QR RELEASE GATE: required tool is group/other writable: ${tool}"
    exit 2
  fi
}

for fixed_tool in \
    ${xcrun_path} ${env_path} ${codesign_path} ${security_path} ${plutil_path} \
    ${ditto_path} ${iconutil_path} ${sed_path} ${grep_path} ${head_path} \
    ${stat_path} ${mktemp_path} ${uname_path} ${find_path} \
    ${plistbuddy_path} ${spctl_path} ${rm_path} ${mkdir_path} ${ln_path} \
    ${chmod_path} ${mv_path} ${rmdir_path}; do
  require_root_system_tool ${fixed_tool}
done

# Resolve every Xcode tool once through the already validated system xcrun,
# then execute only its physical, root-owned binary. The Swift compiler is a
# multicall driver, so ARGV0 selects its `swiftc` or `swift` mode without
# following Xcode's public symlink aliases.
clang_path=$(${xcrun_path} --sdk macosx --find clang)
clang_path=${clang_path:A}
swiftc_alias=$(${xcrun_path} --sdk macosx --find swiftc)
swift_driver_path=${swiftc_alias:h}/swift-driver
swift_driver_path=${swift_driver_path:A}
swift_frontend_path=${swiftc_alias:A}
lipo_path=$(${xcrun_path} --sdk macosx --find lipo)
lipo_path=${lipo_path:A}
notarytool_path=$(${xcrun_path} --find notarytool)
notarytool_path=${notarytool_path:A}
stapler_path=$(${xcrun_path} --find stapler)
stapler_path=${stapler_path:A}
for developer_tool in \
    ${clang_path} ${swift_driver_path} ${swift_frontend_path} ${lipo_path} \
    ${notarytool_path} ${stapler_path}; do
  require_root_system_tool ${developer_tool}
done

sdk_root=$(${xcrun_path} --sdk macosx --show-sdk-path)
sdk_root=${sdk_root:A}
if [[ ! -d ${sdk_root} || -L ${sdk_root} \
    || $(${stat_path} -f %u -- ${sdk_root}) != 0 ]]; then
  print -u2 'QR RELEASE GATE: the selected macOS SDK is not a root-owned physical directory.'
  exit 2
fi
sdk_mode=$(( 8#$(${stat_path} -f %Lp -- ${sdk_root}) ))
if (( (sdk_mode & 8#022) != 0 )); then
  print -u2 'QR RELEASE GATE: the selected macOS SDK is group/other writable.'
  exit 2
fi

codesign() { ${codesign_path} "$@"; }
security() { ${security_path} "$@"; }
plutil() { ${plutil_path} "$@"; }
ditto() { ${ditto_path} "$@"; }
iconutil() { ${iconutil_path} "$@"; }
sed() { ${sed_path} "$@"; }
grep() { ${grep_path} "$@"; }
head() { ${head_path} "$@"; }
stat() { ${stat_path} "$@"; }
mktemp() { ${mktemp_path} "$@"; }
uname() { ${uname_path} "$@"; }
find() { ${find_path} "$@"; }
plistbuddy() { ${plistbuddy_path} "$@"; }
spctl() { ${spctl_path} "$@"; }
rm() { ${rm_path} "$@"; }
mkdir() { ${mkdir_path} "$@"; }
ln() { ${ln_path} "$@"; }
chmod() { ${chmod_path} "$@"; }
mv() { ${mv_path} "$@"; }
rmdir() { ${rmdir_path} "$@"; }
clang() { ${clang_path} "$@"; }
swiftc() { ARGV0=swiftc ${swift_driver_path} "$@"; }
swift() { ARGV0=swift ${swift_driver_path} "$@"; }
lipo() { ${lipo_path} "$@"; }
notarytool() { ${notarytool_path} "$@"; }
stapler() { ${stapler_path} "$@"; }

# A locked restore authenticates downloaded package archives, but NuGet trusts
# files that are already extracted in a shared cache. Give every invocation a
# new cache below the physical system temporary directory, and bind each path
# to the device/inode that was created here. The clean environment also closes
# open-ended MSBuild, profiler, startup-hook and NuGet-plugin injection paths.
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
    print -u2 'QR RELEASE GATE: /private/tmp must be a physical root-owned mode-1777 directory.'
    return 2
  fi
}

create_private_nuget_cache() {
  [[ -z ${private_dotnet_root} ]] || return 0
  require_private_tmp_parent

  private_dotnet_root=$(mktemp -d "${private_tmp_parent}/keep-vault-qr-dotnet.XXXXXXXX")
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
      ${private_signer_intermediate}; do
    mkdir -m 0700 -- ${directory}
    private_dotnet_directories+=(${directory})
    private_dotnet_identities+=("$(stat -f '%d:%i:%u:%Lp' -- ${directory})")
  done
  require_private_nuget_cache_identity
}

require_private_nuget_cache_identity() {
  if [[ -z ${private_dotnet_root} \
      || ${#private_dotnet_directories[@]} != ${#private_dotnet_identities[@]} ]]; then
    print -u2 'QR RELEASE GATE: the private .NET cache has no complete identity record.'
    return 2
  fi
  local index=0
  local directory=''
  local actual=''
  for (( index = 1; index <= ${#private_dotnet_directories[@]}; index++ )); do
    directory=${private_dotnet_directories[index]}
    if [[ ! -d ${directory} || -L ${directory} ]]; then
      print -u2 'QR RELEASE GATE: a private .NET cache directory was replaced.'
      return 2
    fi
    actual=$(stat -f '%d:%i:%u:%Lp' -- ${directory})
    if [[ ${actual} != ${private_dotnet_identities[index]} \
        || $(stat -f %u -- ${directory}) != ${EUID} \
        || $(stat -f %Lp -- ${directory}) != 700 ]]; then
      print -u2 'QR RELEASE GATE: a private .NET cache identity, owner or mode changed.'
      return 2
    fi
  done
}

cleanup_private_nuget_cache() {
  [[ -n ${private_dotnet_root} ]] || return 0
  if ! require_private_nuget_cache_identity; then
    print -u2 'QR RELEASE GATE: refusing to remove a substituted private .NET cache path.'
    return 2
  fi
  if ! rm -rf -- ${private_dotnet_root}; then
    print -u2 'QR RELEASE GATE: unable to remove the private .NET cache.'
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
    print -u2 'QR RELEASE GATE: private-cache identity self-test path already exists.'
    return 2
  fi
  mv -- ${private_dotnet_root} ${held_path}
  if [[ $(stat -f '%d:%i:%u:%Lp' -- ${held_path}) != ${private_dotnet_identities[1]} ]]; then
    print -u2 'QR RELEASE GATE: private-cache identity changed during the self-test hold.'
    return 2
  fi
  mkdir -m 0700 -- ${private_dotnet_root}
  local replacement_identity=$(stat -f '%d:%i:%u:%Lp' -- ${private_dotnet_root})
  local substitution_was_rejected=0
  require_private_nuget_cache_identity >/dev/null 2>&1 \
    || substitution_was_rejected=1
  if [[ $(stat -f '%d:%i:%u:%Lp' -- ${private_dotnet_root}) != ${replacement_identity} ]]; then
    print -u2 'QR RELEASE GATE: refusing to remove a changed cache-test replacement.'
    return 2
  fi
  rmdir -- ${private_dotnet_root}
  mv -- ${held_path} ${private_dotnet_root}
  require_private_nuget_cache_identity
  if (( ! substitution_was_rejected )); then
    print -u2 'QR RELEASE GATE: private-cache pathname substitution was not rejected.'
    return 2
  fi
}

require_verified_dotnet_identity() {
  if [[ -z ${dotnet_command} || ${dotnet_command} != ${private_dotnet_sdk_target}/dotnet \
      || ! -f ${dotnet_command} || -L ${dotnet_command} || ! -x ${dotnet_command} \
      || $(stat -f '%d:%i:%u:%Lp' -- ${dotnet_command}) != ${dotnet_command_identity} \
      || $(stat -f %u -- ${dotnet_command}) != ${EUID} ]]; then
    print -u2 'QR RELEASE GATE: the freshly verified .NET SDK host identity changed.'
    return 2
  fi
  local dotnet_mode=$(( 8#$(stat -f %Lp -- ${dotnet_command}) ))
  if (( (dotnet_mode & 8#022) != 0 )); then
    print -u2 'QR RELEASE GATE: the freshly verified .NET SDK host became writable by another user.'
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
    print -u2 'QR RELEASE GATE: the reviewed .NET SDK provisioner is unavailable or substituted.'
    return 2
  fi
  local provisioner_mode=$(( 8#$(stat -f %Lp -- ${verified_dotnet_provisioner}) ))
  if (( (provisioner_mode & 8#022) != 0 )); then
    print -u2 'QR RELEASE GATE: the reviewed .NET SDK provisioner is group/other writable.'
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
    print -u2 'QR RELEASE GATE: the .NET SDK provisioner identity changed while executing.'
    return 2
  fi
  if (( provision_status != 0 )); then
    print -u2 'QR RELEASE GATE: the pinned Microsoft .NET SDK could not be provisioned.'
    return ${provision_status}
  fi
  if [[ ${provisioned_dotnet} != ${private_dotnet_sdk_target}/dotnet \
      || ! -d ${private_dotnet_sdk_target} || -L ${private_dotnet_sdk_target} ]]; then
    print -u2 'QR RELEASE GATE: the SDK provisioner returned an unexpected host path.'
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
    print -u2 'QR RELEASE GATE: the private HybridSigner assembly identity changed.'
    return 2
  fi
  local signer_mode=$(( 8#$(stat -f %Lp -- ${signer_dll}) ))
  if (( (signer_mode & 8#022) != 0 )); then
    print -u2 'QR RELEASE GATE: the private HybridSigner assembly became writable by another user.'
    return 2
  fi
}

capture_private_signer_identity() {
  signer_dll=${private_dotnet_artifacts}/bin/KeepVaultMac.HybridSigner/release/KeepVaultMac.HybridSigner.dll
  if [[ ! -f ${signer_dll} || -L ${signer_dll} ]]; then
    print -u2 'QR RELEASE GATE: the isolated build did not produce its private HybridSigner assembly.'
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

# Builds, signs and verifies QR-Scanner.
#
# This app is deliberately independent of Keep Vault: its own bundle
# identifier, its own signature, its own folder, no shared code and no shared
# build step. Nothing here reads or writes anything under KeepVaultMac.
#
# Usage:
#   ./QrCodeScanner/tools/Build-QrScanner-macOS.sh
#   ./QrCodeScanner/tools/Build-QrScanner-macOS.sh --notary-profile "QR-Scanner"

script_dir=${0:A:h}
project_root=${script_dir:h}
repository_root=${project_root:h}
packaging_dir=${project_root}/Packaging
sources_dir=${project_root}/Sources
bundle_identifier='de.michael-feinermann.qr-scanner'
app_name='QR-Scanner'
marketing_version='1.0.0'
build_version='1'
architecture='universal'
deployment_target='14.0'
run_tests=1
preflight_only=0
atomic_publish_self_test=0
tool_path_self_test=0
identity=${QRSCANNER_CODESIGN_IDENTITY:-}
# Name of an "xcrun notarytool store-credentials" keychain profile. Empty means
# the build stops short of notarization; no secret ever lives in this file.
notary_profile=${QRSCANNER_NOTARY_PROFILE:-}
dotnet_command=''
verified_dotnet_provisioner=${repository_root}/tools/Provision-VerifiedDotnet-macOS.sh
verified_dotnet_provisioner_identity=''
dotnet_command_identity=''

while (( $# > 0 )); do
  case $1 in
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
    --tool-path-self-test)
      tool_path_self_test=1
      ;;
    --skip-tests)
      run_tests=0
      ;;
    -h|--help)
      print 'Usage: Build-QrScanner-macOS.sh [--identity NAME] [--notary-profile NAME]'
      print '       [--arch universal|arm64|x86_64] [--version X.Y.Z] [--build-number N]'
      print '       [--skip-tests] [--preflight] [--self-test-atomic-publish] [--tool-path-self-test]'
      exit 0
      ;;
    *)
      print -u2 "Unknown argument: $1"
      exit 64
      ;;
  esac
  shift
done

cleanup_early() {
  local original_status=$?
  local cleanup_status=0
  trap - EXIT INT TERM
  cleanup_private_nuget_cache || cleanup_status=$?
  if (( original_status == 0 && cleanup_status != 0 )); then
    original_status=${cleanup_status}
  fi
  exit ${original_status}
}
trap cleanup_early EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
create_private_nuget_cache

if (( tool_path_self_test )); then
  require_sanitized_injection_environment
  self_test_private_nuget_cache_identity
  clang --version >/dev/null
  swiftc --version >/dev/null
  swift --version >/dev/null
  run_dotnet_clean --version >/dev/null
  print 'qr_release_tool_paths=verified'
  exit 0
fi

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
  [[ $(plistbuddy -c 'Print :CFBundleIdentifier' ${destination}) == ${bundle_identifier} ]] || {
    print -u2 'The rendered QR-Scanner bundle identifier is incorrect.'
    exit 1
  }
  [[ $(plistbuddy -c 'Print :CFBundleShortVersionString' ${destination}) == ${marketing_version} ]] || {
    print -u2 'The rendered QR-Scanner marketing version is incorrect.'
    exit 1
  }
  [[ $(plistbuddy -c 'Print :CFBundleVersion' ${destination}) == ${build_version} ]] || {
    print -u2 'The rendered QR-Scanner build number is incorrect.'
    exit 1
  }
  [[ $(plistbuddy -c 'Print :LSMultipleInstancesProhibited' ${destination}) == true ]] || {
    print -u2 'The rendered QR-Scanner does not prohibit multiple camera/payload instances.'
    exit 1
  }
}

if (( preflight_only )); then
  preflight_root=$(mktemp -d "${TMPDIR:-/tmp}/qr-scanner-preflight.XXXXXXXX")
  cleanup_preflight() {
    local original_status=$?
    local cleanup_status=0
    trap - EXIT INT TERM
    if [[ -n ${preflight_root:-} && -d ${preflight_root} && ${preflight_root} == */qr-scanner-preflight.* ]]; then
      rm -rf -- ${preflight_root}
    fi
    cleanup_private_nuget_cache || cleanup_status=$?
    if (( original_status == 0 && cleanup_status != 0 )); then
      original_status=${cleanup_status}
    fi
    exit ${original_status}
  }
  trap cleanup_preflight EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
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
  local original_status=$?
  local cleanup_status=0
  trap - EXIT INT TERM
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
  cleanup_private_nuget_cache || cleanup_status=$?
  if (( original_status == 0 && cleanup_status != 0 )); then
    original_status=${cleanup_status}
  fi
  exit ${original_status}
}
trap cleanup_build EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

atomic_publish_helper=${publish_helper_root}/atomic-publish
clang -isysroot ${sdk_root} -O2 -Wall -Wextra -Werror \
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
  swiftc -sdk ${sdk_root} \
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
  swiftc -sdk ${sdk_root} \
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
  lipo -create ${thin_binaries[@]} -output ${executable}
  lipo ${executable} -verify_arch ${architectures[@]}
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
swift -sdk ${sdk_root} ${script_dir}/make-icon.swift ${iconset} > /dev/null
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
#   /usr/bin/xcrun notarytool store-credentials "Keep Vault v12" \
#     --apple-id you@example.com --team-id TEAMID
#
# Enter the app-specific password only at notarytool's protected prompt, then
# pass --notary-profile "Keep Vault v12". The submission ZIP is scratch: the
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
  notarytool submit ${notary_submission_zip} --keychain-profile ${notary_profile} --wait
  stapler staple ${app_bundle}
  stapler validate ${app_bundle}
  spctl --assess --type execute --verbose=4 ${app_bundle}
  print "notarization=stapled (${notary_profile})"
fi

# --- Hybrid Signatures --------------------------------------------------------
repo_root=${project_root:h}
release_key_root="${HOME}/Library/Application Support/Keep Vault/ReleaseKeys"
pfx_path=${KEEPVAULT_HYBRID_PFX:-${release_key_root}/hybrid-rsa4096.pfx}
mldsa_private_key_encrypted=${KEEPVAULT_MLDSA_PRIVATE_KEY_ENCRYPTED:-${release_key_root}/mldsa87-private.key.v12.enc}
pfx_password_encrypted=${KEEPVAULT_PFX_PASSWORD_ENCRYPTED:-${release_key_root}/hybrid-rsa4096.pfx.password.v12.enc}
mldsa_wrapping_service=${KEEPVAULT_MLDSA_WRAPPING_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.v12.mldsa-wrapping-key}
mldsa_wrapping_account=${KEEPVAULT_MLDSA_WRAPPING_KEYCHAIN_ACCOUNT:-keep-vault-mldsa-v12:${USER:-}}
pfx_wrapping_service=${KEEPVAULT_PFX_WRAPPING_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.v12.pfx-wrapping-key}
pfx_wrapping_account=${KEEPVAULT_PFX_WRAPPING_KEYCHAIN_ACCOUNT:-keep-vault-pfx-v12:${USER:-}}
mldsa_public_key=${KEEPVAULT_MLDSA_PUBLIC_KEY:-${repo_root}/KeepVaultMac/Packaging/Keys/mldsa87-public.key}

if [[ -z ${mldsa_wrapping_service} || -z ${mldsa_wrapping_account} \
    || -z ${pfx_wrapping_service} || -z ${pfx_wrapping_account} \
    || ${mldsa_wrapping_service} == ${pfx_wrapping_service} \
    || ${mldsa_wrapping_account} == ${pfx_wrapping_account} ]]; then
  print -u2 'QR-Scanner signing requires distinct, nonempty ML-DSA and PFX wrapping-key services and accounts.'
  exit 1
fi

hybrid_secret_arguments=(
  --pfx ${pfx_path}
  --pfx-password-encrypted ${pfx_password_encrypted}
  --pfx-wrapping-key-keychain-service ${pfx_wrapping_service}
  --pfx-wrapping-key-keychain-account ${pfx_wrapping_account}
  --mldsa-private-key-encrypted ${mldsa_private_key_encrypted}
  --mldsa-wrapping-key-keychain-service ${mldsa_wrapping_service}
  --mldsa-wrapping-key-keychain-account ${mldsa_wrapping_account}
)

if [[ -f ${pfx_path} && ! -L ${pfx_path} \
    && -f ${mldsa_private_key_encrypted} && ! -L ${mldsa_private_key_encrypted} \
    && -f ${pfx_password_encrypted} && ! -L ${pfx_password_encrypted} ]]; then
  ensure_verified_dotnet
  (
    cd ${repo_root}/KeepVaultMac
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
  
  hybrid_arguments=(
    sign
    ${hybrid_secret_arguments[@]}
    --mldsa-public-key ${mldsa_public_key}
    --reference-library ${repo_root}/KeepVaultMac/Native/osx-arm64/libmldsa87_ref.dylib
    --policy ${repo_root}/KeepVaultMac/Directory.Build.props
    --launcher-pins ${publish_helper_root}/ScannerPins.swift
    --target ${app_bundle}/Contents/MacOS/QR-Scanner
  )

  (
    cd ${repo_root}/KeepVaultMac
    run_dotnet_signer_clean --with-keychain-temp ${hybrid_arguments[@]}
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
  print -u2 "  RSA PFX:              ${pfx_path} ($([[ -f ${pfx_path} && ! -L ${pfx_path} ]] && print present || print MISSING))"
  print -u2 "  ML-DSA v12 envelope:  ${mldsa_private_key_encrypted} ($([[ -f ${mldsa_private_key_encrypted} && ! -L ${mldsa_private_key_encrypted} ]] && print present || print MISSING))"
  print -u2 "  PFX v12 envelope:     ${pfx_password_encrypted} ($([[ -f ${pfx_password_encrypted} && ! -L ${pfx_password_encrypted} ]] && print present || print MISSING))"
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
  sign
  ${hybrid_secret_arguments[@]}
  --mldsa-public-key ${mldsa_public_key}
  --reference-library ${repo_root}/KeepVaultMac/Native/osx-arm64/libmldsa87_ref.dylib
  --policy ${repo_root}/KeepVaultMac/Directory.Build.props
  --launcher-pins ${publish_helper_root}/ScannerArchivePins.swift
  --target ${release_zip}
)
(
  cd ${repo_root}/KeepVaultMac
  run_dotnet_signer_clean --with-keychain-temp ${archive_hybrid_arguments[@]}
)
(
  cd ${repo_root}/KeepVaultMac
  run_dotnet_signer_clean verify \
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

print "bundle=${app_bundle}"
print "zip=${release_zip}"
