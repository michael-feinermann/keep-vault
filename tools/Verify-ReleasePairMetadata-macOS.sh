#!/bin/zsh -f
set -euo pipefail
umask 077
PATH='/usr/bin:/bin:/usr/sbin:/sbin'
export PATH
unset DEVELOPER_DIR SDKROOT TOOLCHAINS
unset CCC_OVERRIDE_OPTIONS COMPILER_PATH CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH \
  OBJC_INCLUDE_PATH LIBRARY_PATH GCC_EXEC_PREFIX ADDITIONAL_SWIFT_DRIVER_FLAGS \
  SWIFT_EXEC SWIFT_DRIVER_SWIFT_FRONTEND_EXEC SWIFT_DRIVER_SWIFTSCAN_LIB \
  SWIFT_DRIVER_TOOLCHAIN_CASPLUGIN_LIB DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
  DYLD_FRAMEWORK_PATH DYLD_FALLBACK_LIBRARY_PATH DYLD_FALLBACK_FRAMEWORK_PATH

xcrun_path=/usr/bin/xcrun
stat_path=/usr/bin/stat
plistbuddy_path=/usr/libexec/PlistBuddy

require_root_system_tool() {
  local tool=$1
  if [[ ${tool} != /* || ! -f ${tool} || -L ${tool} || ! -x ${tool} \
      || $(${stat_path} -f %u -- ${tool}) != 0 ]]; then
    print -u2 "RELEASE PAIR VERIFY GATE: required tool is not an absolute root-owned regular file: ${tool}"
    exit 2
  fi
  local tool_mode=$(( 8#$(${stat_path} -f %Lp -- ${tool}) ))
  if (( (tool_mode & 8#022) != 0 )); then
    print -u2 "RELEASE PAIR VERIFY GATE: required tool is group/other writable: ${tool}"
    exit 2
  fi
}

for fixed_tool in ${xcrun_path} ${stat_path} ${plistbuddy_path}; do
  require_root_system_tool ${fixed_tool}
done

plutil_path=$(${xcrun_path} --find plutil)
plutil_path=${plutil_path:A}
require_root_system_tool ${plutil_path}

sdk_root=$(${xcrun_path} --sdk macosx --show-sdk-path)
sdk_root=${sdk_root:A}
if [[ ! -d ${sdk_root} || -L ${sdk_root} \
    || $(${stat_path} -f %u -- ${sdk_root}) != 0 ]]; then
  print -u2 'RELEASE PAIR VERIFY GATE: the selected macOS SDK is not a root-owned physical directory.'
  exit 2
fi
sdk_mode=$(( 8#$(${stat_path} -f %Lp -- ${sdk_root}) ))
if (( (sdk_mode & 8#022) != 0 )); then
  print -u2 'RELEASE PAIR VERIFY GATE: the selected macOS SDK is group/other writable.'
  exit 2
fi

plutil() { ${plutil_path} "$@"; }
plistbuddy() { ${plistbuddy_path} "$@"; }

expected_keep_vault_identifier='de.michael-feinermann.keep-vault'
expected_scanner_identifier='de.michael-feinermann.qr-scanner'
keep_vault_app=''
scanner_app=''
tool_path_self_test=0

usage() {
  print -u2 'Usage: Verify-ReleasePairMetadata-macOS.sh --app "Keep Vault.app" --scanner "QR-Scanner.app"'
  print -u2 '       [--tool-path-self-test]'
  exit 64
}

while (( $# != 0 )); do
  case $1 in
    --app) (( $# >= 2 )) || usage; keep_vault_app=$2; shift 2 ;;
    --scanner) (( $# >= 2 )) || usage; scanner_app=$2; shift 2 ;;
    --tool-path-self-test) tool_path_self_test=1; shift ;;
    *) usage ;;
  esac
done

if (( tool_path_self_test )); then
  print 'release_pair_verifier_tool_paths=verified'
  exit 0
fi

for bundle in ${keep_vault_app} ${scanner_app}; do
  if [[ -z ${bundle} || ! -d ${bundle} || -L ${bundle} ]]; then
    print -u2 "Release companion bundle is missing, not a directory, or a symbolic link: ${bundle:-<unset>}"
    exit 1
  fi
  if [[ ! -f ${bundle}/Contents/Info.plist || -L ${bundle}/Contents/Info.plist ]]; then
    print -u2 "Release companion Info.plist is missing or a symbolic link: ${bundle}"
    exit 1
  fi
  plutil -lint ${bundle}/Contents/Info.plist >/dev/null
done

plist_value() {
  local bundle=$1
  local key=$2
  plistbuddy -c "Print :${key}" ${bundle}/Contents/Info.plist
}

[[ $(plist_value ${keep_vault_app} CFBundleIdentifier) == ${expected_keep_vault_identifier} ]] || {
  print -u2 'The Keep Vault release bundle identifier is incorrect.'
  exit 1
}
[[ $(plist_value ${scanner_app} CFBundleIdentifier) == ${expected_scanner_identifier} ]] || {
  print -u2 'The QR-Scanner release bundle identifier is incorrect.'
  exit 1
}

keep_vault_version=$(plist_value ${keep_vault_app} CFBundleShortVersionString)
keep_vault_build=$(plist_value ${keep_vault_app} CFBundleVersion)
scanner_version=$(plist_value ${scanner_app} CFBundleShortVersionString)
scanner_build=$(plist_value ${scanner_app} CFBundleVersion)
for numeric_value in ${keep_vault_version} ${scanner_version}; do
  [[ ${numeric_value} =~ '^[0-9]+([.][0-9]+){1,2}$' ]] || {
    print -u2 'A release companion has an invalid marketing version.'
    exit 1
  }
done
for numeric_value in ${keep_vault_build} ${scanner_build}; do
  [[ ${numeric_value} =~ '^[1-9][0-9]*$' ]] || {
    print -u2 'A release companion has an invalid build number.'
    exit 1
  }
done

if [[ ${keep_vault_version} != ${scanner_version} || ${keep_vault_build} != ${scanner_build} ]]; then
  print -u2 "Release companion version mismatch: Keep Vault ${keep_vault_version} (${keep_vault_build}), QR-Scanner ${scanner_version} (${scanner_build})."
  exit 1
fi

print "release_pair_version=${keep_vault_version}"
print "release_pair_build=${keep_vault_build}"
