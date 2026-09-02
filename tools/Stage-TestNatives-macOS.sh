#!/bin/zsh -f
# Produces byte-identical copies of the released native components for the
# comprehensive test suite. The shipped zpaq and argon2 helpers deliberately
# have no app-sandbox or inherit entitlement (Helper.entitlements is empty), so
# they can and must execute unchanged under the test runner. Re-signing them
# here would test different bytes and would invalidate the release evidence.
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

codesign_path=/usr/bin/codesign
awk_path=/usr/bin/awk
stat_path=/usr/bin/stat
mktemp_path=/usr/bin/mktemp
ditto_path=/usr/bin/ditto
cmp_path=/usr/bin/cmp
plistbuddy_path=/usr/libexec/PlistBuddy
rm_path=/bin/rm
mkdir_path=/bin/mkdir

require_root_system_tool() {
  local tool=$1
  if [[ ${tool} != /* || ! -f ${tool} || -L ${tool} || ! -x ${tool} \
      || $(${stat_path} -f %u -- ${tool}) != 0 ]]; then
    print -u2 "NATIVE STAGING GATE: required tool is not an absolute root-owned regular file: ${tool}"
    exit 2
  fi
  local tool_mode=$(( 8#$(${stat_path} -f %Lp -- ${tool}) ))
  if (( (tool_mode & 8#022) != 0 )); then
    print -u2 "NATIVE STAGING GATE: required tool is group/other writable: ${tool}"
    exit 2
  fi
}

for fixed_tool in \
    ${codesign_path} ${awk_path} ${stat_path} ${mktemp_path} ${ditto_path} \
    ${cmp_path} ${plistbuddy_path} ${rm_path} ${mkdir_path}; do
  require_root_system_tool ${fixed_tool}
done

codesign() { ${codesign_path} "$@"; }
awk() { ${awk_path} "$@"; }
mktemp() { ${mktemp_path} "$@"; }
ditto() { ${ditto_path} "$@"; }
cmp() { ${cmp_path} "$@"; }
plistbuddy() { ${plistbuddy_path} "$@"; }
rm() { ${rm_path} "$@"; }
mkdir() { ${mkdir_path} "$@"; }

script_dir=${0:A:h}
repo_root=${script_dir:h}
mac_project=${repo_root}/KeepVaultMac
packaging_dir=${mac_project}/Packaging
source_app=${repo_root}/dist/Keep\ Vault-macOS/Keep\ Vault.app
destination=''
identity_argument=''
tool_path_self_test=0

usage() {
  print -u2 'Usage: Stage-TestNatives-macOS.sh --destination DIR [--app "Keep Vault.app"] [--identity HASH]'
  print -u2 '       Stage-TestNatives-macOS.sh --tool-path-self-test'
  exit 64
}

while (( $# != 0 )); do
  case $1 in
    --app) (( $# >= 2 )) || usage; source_app=$2; shift 2 ;;
    --destination) (( $# >= 2 )) || usage; destination=$2; shift 2 ;;
    # Kept for compatibility with Build-KeepVault-macOS.sh. The release bytes
    # are never re-signed here, so this value is intentionally unused.
    --identity) (( $# >= 2 )) || usage; identity_argument=$2; shift 2 ;;
    --tool-path-self-test) tool_path_self_test=1; shift ;;
    *) usage ;;
  esac
done

if (( tool_path_self_test )); then
  require_sanitized_injection_environment
  print 'stage_test_natives_tool_paths=verified'
  exit 0
fi

[[ -n ${destination} ]] || usage

if [[ ! -d ${source_app} || -L ${source_app} ]]; then
  print -u2 "Signed app bundle not found or is a symbolic link: ${source_app}"
  exit 1
fi
source_natives=${source_app}/Contents/MacOS/Native
signature_root=${source_app}/Contents/Resources/HybridSignatures/Native
components=(zpaq argon2 libaes_ref.dylib libargon2_ref.dylib libchachapoly_ref.dylib libkalyna_v12.dylib libmars_ref.dylib libshacal2_ref.dylib libthreefish_ref.dylib)
helpers=(zpaq argon2)

app_team=$(codesign -dv --verbose=4 ${source_app} 2>&1 \
  | awk -F= '/^TeamIdentifier=/{print $2; exit}')
if [[ -z ${app_team} || ${app_team} == not\ set ]]; then
  print -u2 'The release app has no TeamIdentifier.'
  exit 1
fi

require_release_helper_entitlements() {
  local helper=$1
  local entitlement_dump=$2
  if ! codesign -d --entitlements :- --xml ${helper} > ${entitlement_dump} 2>/dev/null; then
    print -u2 "Unable to inspect helper entitlements: ${helper}"
    return 1
  fi
  local forbidden=''
  for forbidden in com.apple.security.app-sandbox com.apple.security.inherit; do
    if plistbuddy -c "Print :${forbidden}" ${entitlement_dump} >/dev/null 2>&1; then
      print -u2 "Release helper carries forbidden entitlement ${forbidden}: ${helper}"
      return 1
    fi
  done
}

entitlement_root=$(mktemp -d "${TMPDIR:-/tmp}/keep-vault-test-entitlements.XXXXXXXX")
cleanup() {
  [[ -n ${entitlement_root:-} && -d ${entitlement_root} ]] && rm -rf -- ${entitlement_root}
}
trap cleanup EXIT INT TERM

mkdir -p ${destination}
for component in ${components[@]}; do
  if [[ ! -f ${source_natives}/${component} || -L ${source_natives}/${component} ]]; then
    print -u2 "Signed native component is missing: ${component}"
    exit 1
  fi
  ditto ${source_natives}/${component} ${destination}/${component}
  if ! cmp -s -- ${source_natives}/${component} ${destination}/${component}; then
    print -u2 "Staged native component differs from the released bytes: ${component}"
    exit 1
  fi
  for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    if [[ ! -f ${signature_root}/${component}${suffix} ]]; then
      print -u2 "Release sidecar is missing: ${component}${suffix}"
      exit 1
    fi
    ditto ${signature_root}/${component}${suffix} ${destination}/${component}${suffix}
    if ! cmp -s -- ${signature_root}/${component}${suffix} ${destination}/${component}${suffix}; then
      print -u2 "Staged native sidecar differs from the release sidecar: ${component}${suffix}"
      exit 1
    fi
  done
done

for helper in ${helpers[@]}; do
  source_helper=${source_natives}/${helper}
  staged_helper=${destination}/${helper}
  codesign --verify --strict --verbose=2 ${source_helper}
  codesign --verify --strict --verbose=2 ${staged_helper}
  helper_team=$(codesign -dv --verbose=4 ${staged_helper} 2>&1 \
    | awk -F= '/^TeamIdentifier=/{print $2; exit}')
  if [[ ${helper_team} != ${app_team} ]]; then
    print -u2 "Staged helper TeamIdentifier differs from the release app: ${helper}"
    exit 1
  fi
  require_release_helper_entitlements \
    ${source_helper} ${entitlement_root}/${helper}.source.plist
  require_release_helper_entitlements \
    ${staged_helper} ${entitlement_root}/${helper}.staged.plist
done

# The ML-DSA and SHA3 reference adapters are test oracles only: they are
# deliberately not shipped inside the app, so they come from the project tree
# rather than from the signed bundle and carry no hybrid sidecars.
#
# Both have to be staged. The differential group resolves them from the test
# output directory unless KEEPVAULT_MLDSA_REFERENCE / KEEPVAULT_SHA3_REFERENCE
# override it, and the release gate in Build-KeepVault-macOS.sh sets neither.
# Leaving the SHA3 oracle out therefore failed every release build, not just an
# ad-hoc test run.
for reference_oracle in libmldsa87_ref.dylib libsha3_ref.dylib; do
  reference_path=${mac_project}/Native/osx-arm64/${reference_oracle}
  if [[ ! -f ${reference_path} || -L ${reference_path} ]]; then
    print -u2 "Reference oracle is missing: ${reference_path}"
    exit 1
  fi
  ditto ${reference_path} ${destination}/${reference_oracle}
done

# A component killed for a code-signature or sandbox violation dies on SIGTRAP
# (exit 133). Any ordinary usage/exit status means it started, which is all this
# check needs to establish.
for component in ${helpers[@]}; do
  target=${destination}/${component}
  launch_status=0
  ${target} >/dev/null 2>&1 || launch_status=$?
  if (( launch_status == 133 )); then
    print -u2 "Released helper cannot start unchanged under the test runner: ${component}"
    exit 1
  fi
done

print "release_native_bytes=unchanged"
print "release_helper_entitlements=verified-empty-of-sandbox-and-inherit"
print "test_natives=${destination}"
