#!/bin/zsh -f
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

xcrun_path=/usr/bin/xcrun
codesign_path=/usr/bin/codesign
security_path=/usr/bin/security
plutil_path=/usr/bin/plutil
ditto_path=/usr/bin/ditto
file_path=/usr/bin/file
shasum_path=/usr/bin/shasum
openssl_path=/usr/bin/openssl
awk_path=/usr/bin/awk
stat_path=/usr/bin/stat
grep_path=/usr/bin/grep
sed_path=/usr/bin/sed
find_path=/usr/bin/find
sort_path=/usr/bin/sort
comm_path=/usr/bin/comm
cmp_path=/usr/bin/cmp
mktemp_path=/usr/bin/mktemp
env_path=/usr/bin/env
chmod_path=/bin/chmod
mkdir_path=/bin/mkdir
rm_path=/bin/rm
mv_path=/bin/mv
sips_path=/usr/bin/sips
iconutil_path=/usr/bin/iconutil
cat_path=/bin/cat

require_root_system_tool() {
  local tool=$1
  if [[ ${tool} != /* || ! -f ${tool} || -L ${tool} || ! -x ${tool} \
      || $(${stat_path} -f %u -- ${tool}) != 0 ]]; then
    print -u2 "RELEASE GATE: required system tool is not an absolute root-owned regular file: ${tool}"
    exit 2
  fi
  local tool_mode=$(( 8#$(${stat_path} -f %Lp -- ${tool}) ))
  if (( (tool_mode & 8#022) != 0 )); then
    print -u2 "RELEASE GATE: required system tool is group/other writable: ${tool}"
    exit 2
  fi
}
for fixed_tool in \
    ${xcrun_path} ${codesign_path} ${security_path} ${plutil_path} \
    ${ditto_path} ${file_path} ${shasum_path} ${openssl_path} ${awk_path} \
    ${stat_path} ${grep_path} ${sed_path} ${find_path} ${sort_path} \
    ${comm_path} ${cmp_path} ${mktemp_path} ${env_path} ${chmod_path} ${mkdir_path} \
    ${rm_path} ${mv_path} ${sips_path} ${iconutil_path} ${cat_path}; do
  require_root_system_tool ${fixed_tool}
done

xcrun() { ${xcrun_path} "$@"; }
codesign() { ${codesign_path} "$@"; }
security() { ${security_path} "$@"; }
plutil() { ${plutil_path} "$@"; }
ditto() { ${ditto_path} "$@"; }
file() { ${file_path} "$@"; }
shasum() { ${env_path} -i PATH=${PATH} ${shasum_path} "$@"; }
openssl() { ${openssl_path} "$@"; }
awk() { ${awk_path} "$@"; }
stat() { ${stat_path} "$@"; }
grep() { ${grep_path} "$@"; }
sed() { ${sed_path} "$@"; }
find() { ${find_path} "$@"; }
sort() { ${sort_path} "$@"; }
comm() { ${comm_path} "$@"; }
cmp() { ${cmp_path} "$@"; }
mktemp() { ${mktemp_path} "$@"; }
env() { ${env_path} "$@"; }
chmod() { ${chmod_path} "$@"; }
mkdir() { ${mkdir_path} "$@"; }
rm() { ${rm_path} "$@"; }
mv() { ${mv_path} "$@"; }
sips() { ${sips_path} "$@"; }
iconutil() { ${iconutil_path} "$@"; }
cat() { ${cat_path} "$@"; }

if ! zmodload zsh/system; then
  print -u2 'RELEASE GATE: zsh/system is required for descriptor-bound notice assembly.'
  exit 2
fi
if ! zmodload -F zsh/stat b:zstat; then
  print -u2 'RELEASE GATE: zsh/stat is required for descriptor-bound notice identities.'
  exit 2
fi

# A notice source is opened exactly once with O_NOFOLLOW. All metadata, hashes
# and bytes are then obtained through that one descriptor. This prevents a
# same-UID process from changing the pathname between the digest checks and the
# copy. The destination likewise remains one O_EXCL descriptor until its final
# digest and namespace identity have been checked.
third_party_notice_fd=-1
third_party_notice_output_object=''
third_party_notice_sha256=''
notice_binding_test_hook=''

bound_notice_fd_identity() {
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

require_bound_notice_source_identity() {
  local identity=$1
  local label=$2
  local -a fields=("${(@s.:.)identity}")
  if (( ${#fields} != 8 )); then
    print -u2 "RELEASE GATE: third-party notice identity is incomplete: ${label}"
    return 2
  fi
  local mode_value=${fields[4]}
  if [[ ${fields[3]} != ${EUID} || ${fields[5]} != 1 ]] \
      || (( (mode_value & 8#170000) != 8#100000 \
          || (mode_value & 8#022) != 0 \
          || fields[6] <= 0 || fields[6] > 2000000 )); then
    print -u2 "RELEASE GATE: third-party notice is not a protected current-user-owned single-link regular file: ${label}"
    return 2
  fi
}

hash_bound_notice_fd() {
  local descriptor=$1
  local digest_line=''
  sysseek -u ${descriptor} -w start 0 || return 2
  if ! digest_line=$(shasum -a 256 <&${descriptor}); then
    sysseek -u ${descriptor} -w start 0 2>/dev/null || true
    return 2
  fi
  sysseek -u ${descriptor} -w start 0 || return 2
  REPLY=${digest_line%%[[:space:]]*}
  if (( ${#REPLY} != 64 )) || [[ ${REPLY} == *[^0-9a-f]* ]]; then
    print -u2 'RELEASE GATE: a descriptor-bound notice hash was malformed.'
    return 2
  fi
}

require_bound_notice_output_object() {
  local identity
  identity=$(bound_notice_fd_identity ${third_party_notice_fd}) || return 2
  local -a fields=("${(@s.:.)identity}")
  local mode_value=${fields[4]}
  local object_identity=${fields[1]}:${fields[2]}:${fields[3]}:${fields[5]}
  if [[ ${fields[3]} != ${EUID} || ${fields[5]} != 1 \
      || ${object_identity} != ${third_party_notice_output_object} ]] \
      || (( (mode_value & 8#170000) != 8#100000 \
          || (mode_value & 8#0777) != 8#0600 )); then
    print -u2 'RELEASE GATE: the third-party-notice output descriptor changed identity.'
    return 2
  fi
}

create_bound_notice_output() {
  local output_path=$1
  if [[ -e ${output_path} || -L ${output_path} ]]; then
    print -u2 'RELEASE GATE: refusing to replace an existing third-party-notice output.'
    return 2
  fi
  if ! sysopen -rw -m 0600 -o create,excl,nofollow,sync \
      -u third_party_notice_fd ${output_path}; then
    print -u2 'RELEASE GATE: the third-party-notice output could not be created exclusively.'
    return 2
  fi

  local identity
  identity=$(bound_notice_fd_identity ${third_party_notice_fd}) || return 2
  local -a fields=("${(@s.:.)identity}")
  third_party_notice_output_object=${fields[1]}:${fields[2]}:${fields[3]}:${fields[5]}
  require_bound_notice_output_object
}

copy_pinned_notice_source() (
  emulate -L zsh
  set -euo pipefail
  local label=$1
  local notice_source=$2
  local expected_sha256=$3
  local include_heading=$4
  local source_fd=-1
  local before_identity=''
  local after_identity=''
  local before_sha256=''
  local after_sha256=''

  require_bound_notice_output_object || return 2
  if ! sysopen -r -o nofollow -u source_fd ${notice_source}; then
    print -u2 "RELEASE GATE: required third-party notice cannot be opened without following a symbolic link: ${label}"
    return 2
  fi
  before_identity=$(bound_notice_fd_identity ${source_fd}) || {
    print -u2 "RELEASE GATE: required third-party notice cannot be identified: ${label}"
    return 2
  }
  require_bound_notice_source_identity ${before_identity} ${label} || return 2
  hash_bound_notice_fd ${source_fd} || {
    print -u2 "RELEASE GATE: required third-party notice cannot be hashed through its descriptor: ${label}"
    return 2
  }
  before_sha256=${REPLY}
  if [[ ${before_sha256} != ${expected_sha256} ]]; then
    print -u2 "RELEASE GATE: third-party notice digest changed: ${label}"
    return 2
  fi

  if (( notice_binding_self_test )) && [[ -n ${notice_binding_test_hook} ]]; then
    if ! ${notice_binding_test_hook} ${notice_source} ${label}; then
      print -u2 'RELEASE GATE: the notice-binding test hook itself failed.'
      return 70
    fi
  fi

  if (( include_heading )); then
    print -r -u ${third_party_notice_fd} -- ''
    print -r -u ${third_party_notice_fd} -- '=============================================================================='
    print -r -u ${third_party_notice_fd} -- ${label}
    print -r -u ${third_party_notice_fd} -- '=============================================================================='
  fi
  sysseek -u ${source_fd} -w start 0 || return 2
  local transfer_status=0
  while true; do
    if sysread -i ${source_fd} -o ${third_party_notice_fd} -s 65536; then
      continue
    else
      transfer_status=$?
    fi
    if (( transfer_status == 5 )); then
      break
    fi
    print -u2 "RELEASE GATE: third-party notice copy failed through its bound descriptor: ${label}"
    return 2
  done

  after_identity=$(bound_notice_fd_identity ${source_fd}) || return 2
  hash_bound_notice_fd ${source_fd} || return 2
  after_sha256=${REPLY}
  if [[ ${after_identity} != ${before_identity} \
      || ${after_sha256} != ${before_sha256} \
      || ${after_sha256} != ${expected_sha256} ]]; then
    print -u2 "RELEASE GATE: third-party notice changed while its bound descriptor was copied: ${label}"
    return 2
  fi
  require_bound_notice_output_object
)

append_pinned_notice() {
  copy_pinned_notice_source $1 $2 $3 1
}

finalize_bound_notice_output() {
  local output_path=$1
  local minimum_size=$2
  local maximum_size=$3
  local expected_sha256=$4
  require_bound_notice_output_object || return 2
  chmod 0644 /dev/fd/${third_party_notice_fd}

  local before_identity
  local after_identity
  before_identity=$(bound_notice_fd_identity ${third_party_notice_fd}) || return 2
  local -a fields=("${(@s.:.)before_identity}")
  local mode_value=${fields[4]}
  if [[ ${fields[3]} != ${EUID} || ${fields[5]} != 1 ]] \
      || (( (mode_value & 8#170000) != 8#100000 \
          || (mode_value & 8#0777) != 8#0644 \
          || fields[6] < minimum_size || fields[6] > maximum_size )); then
    print -u2 'RELEASE GATE: the completed third-party notice has invalid descriptor metadata.'
    return 2
  fi
  hash_bound_notice_fd ${third_party_notice_fd} || return 2
  third_party_notice_sha256=${REPLY}
  if [[ ${third_party_notice_sha256} != ${expected_sha256} ]]; then
    print -u2 'RELEASE GATE: the assembled third-party notice does not match its reviewed whole-file digest.'
    return 2
  fi
  after_identity=$(bound_notice_fd_identity ${third_party_notice_fd}) || return 2
  local descriptor_path_identity=${fields[1]}:${fields[2]}:${fields[3]}:${fields[5]}
  local -A output_path_stat
  local output_path_identity=invalid
  local output_path_mode=0
  if zstat -L -H output_path_stat ${output_path} 2>/dev/null; then
    output_path_identity=${output_path_stat[device]}:${output_path_stat[inode]}:${output_path_stat[uid]}:${output_path_stat[nlink]}
    output_path_mode=${output_path_stat[mode]}
  fi
  if [[ ${after_identity} != ${before_identity} || -L ${output_path} \
      || ${output_path_identity} != ${descriptor_path_identity} ]] \
      || (( (output_path_mode & 8#170000) != 8#100000 )); then
    print -u2 'RELEASE GATE: the completed third-party notice changed during its final descriptor hash.'
    return 2
  fi
  exec {third_party_notice_fd}>&-
  third_party_notice_fd=-1
}

create_notice_self_test_file() {
  local path=$1
  local contents=$2
  local descriptor=-1
  sysopen -rw -m 0600 -o create,excl,nofollow,sync -u descriptor ${path} || return 2
  chmod 0600 /dev/fd/${descriptor} || return 2
  syswrite -o ${descriptor} ${contents} || return 2
  exec {descriptor}>&-
}

notice_self_test_path_aba() {
  local source=$1
  mv ${source} ${source}.held
  create_notice_self_test_file ${source} $'attacker replacement\n'
  mv ${source} ${source}.replacement
  mv ${source}.held ${source}
}

notice_self_test_inplace_aba() {
  local source=$1
  local descriptor=-1
  sysopen -w -o trunc,nofollow,sync -u descriptor ${source} || return 2
  syswrite -o ${descriptor} $'changed notice!!\n' || return 2
  exec {descriptor}>&-
  chmod 0400 ${source}
  chmod 0600 ${source}
  sysopen -w -o trunc,nofollow,sync -u descriptor ${source} || return 2
  syswrite -o ${descriptor} $'reviewed notice\n' || return 2
  exec {descriptor}>&-
}

run_notice_binding_self_test() {
  local test_root
  test_root=$(mktemp -d '/private/tmp/keep-vault-notice-binding.XXXXXXXX')
  chmod 0700 ${test_root}
  local test_root_identity=$(stat -f '%d:%i:%u:%Lp' ${test_root})
  local test_status=0
  (
    local source=${test_root}/source.txt
    local output=${test_root}/notices.txt
    create_notice_self_test_file ${source} $'reviewed notice\n' || return 2
    local expected_sha256
    expected_sha256=$(shasum -a 256 ${source} | awk '{print $1}') || return 2

    create_bound_notice_output ${output} || return 2
    copy_pinned_notice_source 'self-test baseline' ${source} ${expected_sha256} 0 || return 2
    finalize_bound_notice_output ${output} 1 4096 ${expected_sha256} || return 2
    [[ ${third_party_notice_sha256} == ${expected_sha256} ]] || {
      print -u2 'RELEASE GATE: descriptor-bound notice baseline digest changed.'
      return 2
    }

    source=${test_root}/source-swap.txt
    output=${test_root}/notices-swap.txt
    create_notice_self_test_file ${source} $'reviewed notice\n' || return 2
    create_bound_notice_output ${output} || return 2
    notice_binding_test_hook=notice_self_test_path_aba
    local swap_status=0
    copy_pinned_notice_source 'self-test path swap/ABA' \
      ${source} ${expected_sha256} 0 2>/dev/null || swap_status=$?
    notice_binding_test_hook=''
    if (( swap_status != 2 )) \
        || [[ $(shasum -a 256 ${source} | awk '{print $1}') != ${expected_sha256} ]]; then
      print -u2 'RELEASE GATE: a notice pathname swap/ABA was not rejected after the exact source was restored.'
      return 2
    fi
    exec {third_party_notice_fd}>&-
    third_party_notice_fd=-1

    source=${test_root}/source-output.txt
    output=${test_root}/notices-output.txt
    create_notice_self_test_file ${source} $'reviewed notice\n' || return 2
    create_bound_notice_output ${output} || return 2
    copy_pinned_notice_source 'self-test output mutation' \
      ${source} ${expected_sha256} 0 || return 2
    local attacker_fd=-1
    sysopen -w -o trunc,nofollow,sync -u attacker_fd ${output} || return 2
    syswrite -o ${attacker_fd} $'attacker notice\n' || return 2
    exec {attacker_fd}>&-
    local output_mutation_status=0
    finalize_bound_notice_output ${output} 1 4096 ${expected_sha256} \
      2>/dev/null || output_mutation_status=$?
    if (( output_mutation_status != 2 )); then
      print -u2 'RELEASE GATE: an in-place mutation of the bound notice output was accepted.'
      return 2
    fi
    exec {third_party_notice_fd}>&-
    third_party_notice_fd=-1

    source=${test_root}/source-inplace.txt
    output=${test_root}/notices-inplace.txt
    create_notice_self_test_file ${source} $'reviewed notice\n' || return 2
    create_bound_notice_output ${output} || return 2
    notice_binding_test_hook=notice_self_test_inplace_aba
    local inplace_status=0
    copy_pinned_notice_source 'self-test in-place ABA' \
      ${source} ${expected_sha256} 0 2>/dev/null || inplace_status=$?
    notice_binding_test_hook=''
    if (( inplace_status != 2 )) \
        || [[ $(shasum -a 256 ${source} | awk '{print $1}') != ${expected_sha256} ]]; then
      print -u2 'RELEASE GATE: an in-place notice ABA mutation with restored bytes was not rejected.'
      return 2
    fi
    exec {third_party_notice_fd}>&-
    third_party_notice_fd=-1
  ) || test_status=$?

  if [[ $(stat -f '%d:%i:%u:%Lp' ${test_root} 2>/dev/null || print invalid) == ${test_root_identity} ]]; then
    rm -rf -- ${test_root}
  else
    print -u2 'RELEASE GATE: notice self-test root identity changed; it was preserved.'
    (( test_status == 0 )) && test_status=2
  fi
  (( test_status == 0 )) || return ${test_status}
  print 'notice_binding=verified'
}

script_dir=${0:A:h}
repo_root=${script_dir:h}
mac_project=${repo_root}/KeepVaultMac
packaging_dir=${mac_project}/Packaging
team_identifier='2T6K9PGS55'
bundle_identifier='de.michael-feinermann.keep-vault'
core_identifier='de.michael-feinermann.keep-vault.core'
configuration='Release'
architecture='universal'
marketing_version='5.0.0'
build_version='12'
preflight_only=0
tool_path_self_test=0
notice_binding_self_test=0
release_mode=0
identity=${KEEPVAULT_CODESIGN_IDENTITY:-}
# Name of an "xcrun notarytool store-credentials" keychain profile. Empty means
# the build stops short of notarization; the secrets never live here.
notary_profile=${KEEPVAULT_NOTARY_PROFILE:-}
requested_performance_baseline=${KEEPVAULT_PERF_BASELINE:-}
unset KEEPVAULT_TEST_RELEASE_ROOT KEEPVAULT_PERF_BASELINE
pfx_path=${KEEPVAULT_HYBRID_PFX:-${HOME}/Library/Application Support/Keep Vault/ReleaseKeys/hybrid-rsa4096.pfx}
mldsa_private_key_encrypted=${KEEPVAULT_MLDSA_PRIVATE_KEY_ENCRYPTED:-${HOME}/Library/Application Support/Keep Vault/ReleaseKeys/mldsa87-private.key.v12.enc}
pfx_password_encrypted=${KEEPVAULT_PFX_PASSWORD_ENCRYPTED:-${pfx_path}.password.v12.enc}
mldsa_wrapping_service=${KEEPVAULT_MLDSA_WRAPPING_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.v12.mldsa-wrapping-key}
mldsa_wrapping_account=${KEEPVAULT_MLDSA_WRAPPING_KEYCHAIN_ACCOUNT:-keep-vault-mldsa-v12:${USER:-}}
pfx_wrapping_service=${KEEPVAULT_PFX_WRAPPING_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.v12.pfx-wrapping-key}
pfx_wrapping_account=${KEEPVAULT_PFX_WRAPPING_KEYCHAIN_ACCOUNT:-keep-vault-pfx-v12:${USER:-}}

mldsa_public_key=${KEEPVAULT_MLDSA_PUBLIC_KEY:-${packaging_dir}/Keys/mldsa87-public.key}
dotnet_command=''
expected_main_lock_sha256='B111FBCD11FBF46DF0E61164109CBD8BFB2C22B80EC79E4B4D1EA0ED7FE07DE7'
expected_signer_lock_sha256='B07635B8B5CF158644267CBB99E6483D6F947F37D3B9918B4FF39407EB6BA5EB'
expected_tests_lock_sha256='EE7FEDF92179705DE025536CDCF1CB6B5991AA69D457B26103B3E420B9957A24'

usage() {
  print -u2 'Usage: Build-KeepVault-macOS.sh [--architecture universal|arm64] [--identity HASH_OR_NAME]'
  print -u2 '       [--pfx FILE] [--mldsa-private-key-encrypted FILE] [--pfx-password-encrypted FILE]'
  print -u2 '       [--mldsa-public-key FILE]'
  print -u2 '       [--version X.Y.Z] [--build-number N]'
  print -u2 '       [--notary-profile NOTARYTOOL_KEYCHAIN_PROFILE] [--release] [--preflight]'
  print -u2 '       [--tool-path-self-test] [--notice-binding-self-test]'
  exit 64
}

while (( $# != 0 )); do
  case $1 in
    --architecture)
      (( $# >= 2 )) || usage
      architecture=$2
      shift 2
      ;;
    --identity)
      (( $# >= 2 )) || usage
      identity=$2
      shift 2
      ;;
    --pfx)
      (( $# >= 2 )) || usage
      pfx_path=$2
      shift 2
      ;;
    --mldsa-private-key-encrypted)
      (( $# >= 2 )) || usage
      mldsa_private_key_encrypted=$2
      shift 2
      ;;
    --pfx-password-encrypted)
      (( $# >= 2 )) || usage
      pfx_password_encrypted=$2
      shift 2
      ;;
    --mldsa-public-key)
      (( $# >= 2 )) || usage
      mldsa_public_key=$2
      shift 2
      ;;
    --version)
      (( $# >= 2 )) || usage
      marketing_version=$2
      shift 2
      ;;
    --build-number)
      (( $# >= 2 )) || usage
      build_version=$2
      shift 2
      ;;
    --release)
      release_mode=1
      shift
      ;;
    --notary-profile)
      (( $# >= 2 )) || usage
      notary_profile=$2
      shift 2
      ;;
    --preflight)
      preflight_only=1
      shift
      ;;
    --tool-path-self-test)
      tool_path_self_test=1
      shift
      ;;
    --notice-binding-self-test)
      notice_binding_self_test=1
      shift
      ;;
    *) usage ;;
  esac
done

if (( tool_path_self_test )); then
  print 'release_tool_paths=verified'
  exit 0
fi

if [[ ${architecture} != universal && ${architecture} != arm64 ]]; then
  print -u2 'Only universal or arm64 release architectures are supported.'
  exit 64
fi
if [[ ! ${marketing_version} =~ '^[0-9]+([.][0-9]+){1,2}$' || ! ${build_version} =~ '^[1-9][0-9]*$' ]]; then
  print -u2 'Version values must be numeric (for example 1.0.0 and build 1).'
  exit 64
fi
if [[ -L ${repo_root} || -L ${mac_project} || -L ${packaging_dir} ]]; then
  print -u2 'Refusing to build through a symbolic-link workspace or packaging path.'
  exit 1
fi

private_temp_parent=/private/tmp
private_temp_uid=$(stat -f '%u' ${private_temp_parent} 2>/dev/null || print invalid)
private_temp_mode=$(( 8#$(stat -f '%p' ${private_temp_parent} 2>/dev/null || print 0) & 8#7777 ))
if [[ ! -d ${private_temp_parent} || -L ${private_temp_parent} \
    || ${private_temp_uid} != 0 ]] || (( private_temp_mode != 8#1777 )); then
  print -u2 'RELEASE GATE: /private/tmp must be a physical root-owned mode-1777 directory.'
  exit 2
fi

if (( notice_binding_self_test )); then
  run_notice_binding_self_test
  exit 0
fi

build_root=''
build_root_identity=''
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
private_app_artifacts=''
private_app_artifacts_identity=''
private_signer_artifacts=''
private_signer_artifacts_identity=''
private_tests_artifacts=''
private_tests_artifacts_identity=''
verified_dotnet_root=''
verified_dotnet_root_identity=''
dotnet_command_identity=''
hybrid_keychain_tmp=''
hybrid_keychain_tmp_identity=''
signer_dll=''
signer_dll_identity=''

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
    && require_private_directory_identity ${private_app_artifacts} ${private_app_artifacts_identity} \
    && require_private_directory_identity ${private_signer_artifacts} ${private_signer_artifacts_identity} \
    && require_private_directory_identity ${private_tests_artifacts} ${private_tests_artifacts_identity} \
    && { [[ -z ${verified_dotnet_root} ]] \
      || { require_private_directory_identity ${verified_dotnet_root} ${verified_dotnet_root_identity} \
        && [[ -f ${dotnet_command} && ! -L ${dotnet_command} && -x ${dotnet_command} \
          && $(stat -f '%d:%i' ${dotnet_command} 2>/dev/null || print invalid) == ${dotnet_command_identity} ]]; }; }
}

create_private_nuget_cache() {
  build_root=$(mktemp -d "${private_temp_parent}/keep-vault-release.XXXXXXXX")
  chmod 0700 ${build_root}
  build_root_identity=$(stat -f '%d:%i' ${build_root})
  private_nuget_root=${build_root}/nuget
  private_nuget_packages=${private_nuget_root}/packages
  private_nuget_http_cache=${private_nuget_root}/http-cache
  private_nuget_scratch=${private_nuget_root}/scratch
  private_dotnet_cli_home=${private_nuget_root}/cli-home
  private_dotnet_tmp=${private_nuget_root}/tmp
  private_artifacts_root=${build_root}/artifacts
  private_app_artifacts=${private_artifacts_root}/app
  private_signer_artifacts=${private_artifacts_root}/signer
  private_tests_artifacts=${private_artifacts_root}/tests
  mkdir -m 0700 ${private_nuget_root} ${private_nuget_packages} \
    ${private_nuget_http_cache} ${private_nuget_scratch} \
    ${private_dotnet_cli_home} ${private_dotnet_tmp} ${private_artifacts_root} \
    ${private_app_artifacts} ${private_signer_artifacts} ${private_tests_artifacts}
  private_nuget_root_identity=$(stat -f '%d:%i' ${private_nuget_root})
  private_nuget_packages_identity=$(stat -f '%d:%i' ${private_nuget_packages})
  private_nuget_http_cache_identity=$(stat -f '%d:%i' ${private_nuget_http_cache})
  private_nuget_scratch_identity=$(stat -f '%d:%i' ${private_nuget_scratch})
  private_dotnet_cli_home_identity=$(stat -f '%d:%i' ${private_dotnet_cli_home})
  private_dotnet_tmp_identity=$(stat -f '%d:%i' ${private_dotnet_tmp})
  private_artifacts_root_identity=$(stat -f '%d:%i' ${private_artifacts_root})
  private_app_artifacts_identity=$(stat -f '%d:%i' ${private_app_artifacts})
  private_signer_artifacts_identity=$(stat -f '%d:%i' ${private_signer_artifacts})
  private_tests_artifacts_identity=$(stat -f '%d:%i' ${private_tests_artifacts})
  require_private_nuget_cache_identity || {
    print -u2 'RELEASE GATE: failed to create the identity-bound private NuGet cache.'
    exit 2
  }
}

cleanup_private_nuget_cache() {
  if [[ -z ${build_root:-} ]]; then
    return 0
  fi
  require_private_nuget_cache_identity || {
    print -u2 'RELEASE GATE: private NuGet cache identity changed; preserving it for inspection.'
    return 1
  }
  return 0
}

cleanup() {
  set +e
  if cleanup_private_nuget_cache \
      && [[ ${build_root} == ${private_temp_parent}/keep-vault-release.* ]]; then
    rm -rf -- ${build_root}
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

create_private_nuget_cache

run_dotnet_clean() {
  require_private_nuget_cache_identity || {
    print -u2 'RELEASE GATE: private NuGet cache identity changed before a .NET invocation.'
    return 2
  }
  local -a clean_environment=(
    HOME=${private_dotnet_cli_home}
    PATH=${PATH}
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
  [[ -z ${KEEPVAULT_TEST_RELEASE_ROOT:-} ]] \
    || clean_environment+=(KEEPVAULT_TEST_RELEASE_ROOT=${KEEPVAULT_TEST_RELEASE_ROOT})
  clean_environment+=(KEEPVAULT_TEST_REPOSITORY_ROOT=${repo_root})
  [[ -z ${KEEPVAULT_PERF_BASELINE:-} ]] \
    || clean_environment+=(KEEPVAULT_PERF_BASELINE=${KEEPVAULT_PERF_BASELINE})
  local dotnet_status=0
  ${env_path} -i "${clean_environment[@]}" ${dotnet_command} "$@" || dotnet_status=$?
  require_private_nuget_cache_identity || {
    print -u2 'RELEASE GATE: private NuGet cache identity changed during a .NET invocation.'
    return 2
  }
  return ${dotnet_status}
}

dotnet_provisioner=${script_dir}/Provision-VerifiedDotnet-macOS.sh
if [[ ! -f ${dotnet_provisioner} || -L ${dotnet_provisioner} || ! -x ${dotnet_provisioner} ]]; then
  print -u2 'RELEASE GATE: verified .NET SDK provisioner is missing, symbolic, or not executable.'
  exit 2
fi
verified_dotnet_target=${build_root}/dotnet-sdk
dotnet_command=$(${dotnet_provisioner} --target ${verified_dotnet_target})
verified_dotnet_root=${verified_dotnet_target}
verified_dotnet_root_identity=$(stat -f '%d:%i' ${verified_dotnet_root})
dotnet_command_identity=$(stat -f '%d:%i' ${dotnet_command})
require_private_nuget_cache_identity || {
  print -u2 'RELEASE GATE: freshly provisioned Microsoft SDK lost its identity binding.'
  exit 2
}

dotnet_command=${dotnet_command:A}
if [[ ! -x ${dotnet_command} || -L ${dotnet_command} ]]; then
  print -u2 "The explicitly selected official .NET SDK host is unavailable or a symbolic link: ${dotnet_command}"
  exit 1
fi
selected_sdk=$(cd ${repo_root} && run_dotnet_clean --version)
if [[ ${selected_sdk} != '10.0.400' ]]; then
  print -u2 'Keep Vault release builds require the reviewed official .NET SDK 10.0.400.'
  exit 1
fi

if [[ -z ${identity} ]]; then
  identity=$(security find-identity -v -p codesigning \
    | awk '($0 ~ /Developer ID Application:/) { print $2; exit }')
  if [[ -z ${identity} ]]; then
    identity=$(security find-identity -v -p codesigning \
      | awk '($0 ~ /Apple Development:/) { print $2; exit }')
  fi
fi
if [[ -z ${identity} ]]; then
  print -u2 "RELEASE GATE: no Apple code-signing identity for team ${team_identifier} is available."
  exit 2
fi

identity_details=$(security find-identity -v -p codesigning | grep -F -- "${identity}" || true)
if [[ -z ${identity_details} ]]; then
  print -u2 'The selected Apple signing identity is absent.'
  exit 2
fi
identity_label=${identity_details#*\"}
identity_label=${identity_label%%\"*}
certificate_subject=$(security find-certificate -c ${identity_label} -p \
  | openssl x509 -noout -subject -nameopt RFC2253 2>/dev/null || true)
if [[ ${certificate_subject} != *"OU=${team_identifier}"* ]]; then
  print -u2 "The selected Apple signing certificate does not belong to team ${team_identifier}."
  exit 2
fi
timestamp_arguments=(--timestamp=none)
if [[ ${identity_label} == 'Developer ID Application:'* ]]; then
  timestamp_arguments=(--timestamp)
  if [[ -z ${notary_profile} ]]; then
    print -u2 'RELEASE GATE: Developer ID release requires --notary-profile.'
    exit 2
  fi
elif [[ ${identity_label} == 'Apple Development:'* ]]; then
  timestamp_arguments=(--timestamp=none)
  if (( release_mode )); then
    print -u2 'RELEASE GATE: published release requires Developer ID.'
    exit 2
  fi
else
  print -u2 'The selected identity is neither Apple Development nor Developer ID Application.'
  exit 2
fi

if [[ -z ${pfx_path} || -z ${mldsa_private_key_encrypted} \
    || -z ${pfx_password_encrypted} ]]; then
  print -u2 'RELEASE GATE: macOS hybrid-signing private keys are not available.'
  print -u2 'Provide the external RSA PFX and both role-specific v12 secret envelopes.'
  print -u2 'Private keys are intentionally never generated in or copied into the repository.'
  exit 2
fi
if [[ -z ${USER:-} || -z ${mldsa_wrapping_service} || -z ${mldsa_wrapping_account} \
    || -z ${pfx_wrapping_service} || -z ${pfx_wrapping_account} \
    || ${mldsa_wrapping_service} == ${pfx_wrapping_service} \
    || ${mldsa_wrapping_account} == ${pfx_wrapping_account} ]]; then
  print -u2 'RELEASE GATE: RSA and ML-DSA need distinct, nonempty Keychain services and accounts.'
  exit 2
fi

pfx_path=${pfx_path:A}
mldsa_private_key_encrypted=${mldsa_private_key_encrypted:A}
pfx_password_encrypted=${pfx_password_encrypted:A}
mldsa_public_key=${mldsa_public_key:A}
for private_path in ${pfx_path} ${mldsa_private_key_encrypted} ${pfx_password_encrypted}; do
  if [[ ${private_path} == ${repo_root}/* ]]; then
    print -u2 "RELEASE GATE: private signing material must remain outside the repository: ${private_path}"
    exit 2
  fi
  if [[ ! -f ${private_path} || -L ${private_path} ]]; then
    print -u2 "Private signing material is missing or a symbolic link: ${private_path}"
    exit 2
  fi
  if [[ $(stat -f %u ${private_path}) != ${EUID} ]]; then
    print -u2 "Private signing material is not owned by the current user: ${private_path}"
    exit 2
  fi
  private_mode=$(( 8#$(stat -f %Lp ${private_path}) ))
  if (( (private_mode & 8#077) != 0 )); then
    print -u2 "Private signing material must be mode 0600 or stricter: ${private_path}"
    exit 2
  fi
  private_parent=${private_path:h}
  if [[ ! -d ${private_parent} || -L ${private_parent} || $(stat -f %u ${private_parent}) != ${EUID} ]]; then
    print -u2 "Private signing directory is unsafe: ${private_parent}"
    exit 2
  fi
  private_parent_mode=$(( 8#$(stat -f %Lp ${private_parent}) ))
  if (( (private_parent_mode & 8#077) != 0 )); then
    print -u2 "Private signing directory must be mode 0700 or stricter: ${private_parent}"
    exit 2
  fi
done
if [[ ! -f ${mldsa_public_key} || -L ${mldsa_public_key} ]]; then
  print -u2 "Pinned ML-DSA-87 public key is missing or a symbolic link: ${mldsa_public_key}"
  exit 2
fi

# The read-free verifier rejects a missing item, a shared identity, a trusted
# application added with "Always Allow", or a role-swapped ACL before any
# signing secret is requested.
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

main_lock=${mac_project}/packages.lock.json
signer_lock=${packaging_dir}/HybridSigner/packages.lock.json
tests_lock=${repo_root}/KeepVaultMac.Tests/packages.lock.json
lock_files=("${main_lock}" "${signer_lock}" "${tests_lock}")
expected_lock_hashes=(
  ${expected_main_lock_sha256}
  ${expected_signer_lock_sha256}
  ${expected_tests_lock_sha256}
)
for (( lock_index = 1; lock_index <= ${#lock_files}; lock_index++ )); do
  lock_file=${lock_files[lock_index]}
  expected_lock_hash=${expected_lock_hashes[lock_index]}
  if [[ ! -f ${lock_file} || -L ${lock_file} ]]; then
    print -u2 "RELEASE GATE: reviewed NuGet lockfile is missing or a symbolic link: ${lock_file}"
    exit 2
  fi
  actual_lock_hash=$(shasum -a 256 ${lock_file} | awk '{print toupper($1)}')
  if [[ ${actual_lock_hash} != ${expected_lock_hash} ]]; then
    print -u2 "RELEASE GATE: reviewed NuGet lockfile digest changed: ${lock_file}"
    exit 2
  fi
done

if (( preflight_only )); then
  print "preflight=passed"
  print "identity=${identity}"
  print "architecture=${architecture}"
  exit 0
fi

(
  cd ${mac_project}
  run_dotnet_clean restore KeepVaultMac.csproj --artifacts-path ${private_app_artifacts} --locked-mode --force --force-evaluate --no-http-cache --disable-build-servers --nologo
  run_dotnet_clean restore Packaging/HybridSigner/KeepVaultMac.HybridSigner.csproj --artifacts-path ${private_signer_artifacts} --locked-mode --force --force-evaluate --no-http-cache --disable-build-servers --nologo
)
(
  cd ${repo_root}
  run_dotnet_clean restore KeepVaultMac.Tests/KeepVaultMac.Tests.csproj --artifacts-path ${private_tests_artifacts} --locked-mode --force --force-evaluate --no-http-cache --disable-build-servers --nologo
)

hybrid_keychain_tmp=${build_root}/hybrid-keychain-tmp
mkdir -m 0700 ${hybrid_keychain_tmp}
hybrid_keychain_tmp_identity=$(stat -f '%d:%i' ${hybrid_keychain_tmp})
keychain_inventory_counter=0
run_hybrid_signer() {
  local before_inventory=${build_root}/keychains-before-${keychain_inventory_counter}.txt
  local after_inventory=${build_root}/keychains-after-${keychain_inventory_counter}.txt
  local new_keychain_paths=${build_root}/keychains-new-${keychain_inventory_counter}.txt
  (( keychain_inventory_counter += 1 ))
  if ! require_private_nuget_cache_identity \
      || ! require_private_directory_identity ${hybrid_keychain_tmp} ${hybrid_keychain_tmp_identity} \
      || [[ -z ${signer_dll_identity} || -z ${signer_dll} \
        || ${signer_dll} != ${private_signer_artifacts}/* \
        || ! -f ${signer_dll} || -L ${signer_dll} \
        || $(stat -f '%d:%i:%u:%Lp:%z:%m:%c:%l' ${signer_dll} 2>/dev/null || print invalid) != ${signer_dll_identity} ]]; then
    print -u2 'RELEASE GATE: private signer or signer scratch identity changed before execution.'
    return 2
  fi
  if find ${hybrid_keychain_tmp} -mindepth 1 -print -quit | grep -q .; then
    print -u2 'RELEASE GATE: the isolated temporary-keychain directory was not empty before PFX loading.'
    return 2
  fi
  if [[ -d ${HOME}/Library/Keychains && ! -L ${HOME}/Library/Keychains ]]; then
    find -x ${HOME}/Library/Keychains -print | LC_ALL=C sort > ${before_inventory}
  else
    : > ${before_inventory}
  fi

  local signer_status=0
  require_private_nuget_cache_identity || return 2
  ${env_path} -i \
    PATH=${PATH} \
    TMPDIR=${hybrid_keychain_tmp} \
    DOTNET_CLI_HOME=${private_dotnet_cli_home} \
    NUGET_PACKAGES=${private_nuget_packages} \
    NUGET_HTTP_CACHE_PATH=${private_nuget_http_cache} \
    NUGET_SCRATCH=${private_nuget_scratch} \
    KEEPVAULT_KEYCHAIN_TEMP_ROOT=${hybrid_keychain_tmp} \
    DOTNET_EnableDiagnostics=0 \
    COMPlus_EnableDiagnostics=0 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
    DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=1 \
    DOTNET_GENERATE_ASPNET_CERTIFICATE=false \
    DOTNET_ADD_GLOBAL_TOOLS_TO_PATH=false \
    MSBUILDDISABLENODEREUSE=1 \
    ${dotnet_command} "$@" || signer_status=$?
  if ! require_private_nuget_cache_identity \
      || ! require_private_directory_identity ${hybrid_keychain_tmp} ${hybrid_keychain_tmp_identity} \
      || [[ ! -f ${signer_dll} || -L ${signer_dll} \
        || $(stat -f '%d:%i:%u:%Lp:%z:%m:%c:%l' ${signer_dll} 2>/dev/null || print invalid) != ${signer_dll_identity} ]]; then
    print -u2 'RELEASE GATE: private signer or signer scratch identity changed during execution.'
    return 2
  fi

  if [[ -d ${HOME}/Library/Keychains && ! -L ${HOME}/Library/Keychains ]]; then
    find -x ${HOME}/Library/Keychains -print | LC_ALL=C sort > ${after_inventory}
  else
    : > ${after_inventory}
  fi
  comm -13 ${before_inventory} ${after_inventory} > ${new_keychain_paths}
  if find ${hybrid_keychain_tmp} -mindepth 1 -print -quit | grep -q . \
      || [[ -s ${new_keychain_paths} ]]; then
    print -u2 'RELEASE GATE: macOS PFX loading left a temporary keychain object behind.'
    [[ ! -s ${new_keychain_paths} ]] || sed 's/^/  /' ${new_keychain_paths} >&2
    return 2
  fi
  return ${signer_status}
}

${script_dir}/Build-Native-macOS.sh

publish_runtime() {
  local runtime=$1
  local output=$2
  (
    cd ${mac_project}
    run_dotnet_clean publish KeepVaultMac.csproj \
      -c ${configuration} \
      -r ${runtime} \
      --artifacts-path ${private_app_artifacts} \
      --no-restore \
      --self-contained true \
      --nologo \
      -p:PublishAot=true \
      -p:PublishTrimmed=true \
      -p:StripSymbols=true \
      -p:UseSharedCompilation=false \
      --disable-build-servers \
      -o ${output}
  )
}

arm_publish=${build_root}/publish-arm64
publish_runtime osx-arm64 ${arm_publish}
merged_publish=${build_root}/publish-merged
ditto ${arm_publish} ${merged_publish}

if [[ ${architecture} == universal ]]; then
  x64_publish=${build_root}/publish-x64
  publish_runtime osx-x64 ${x64_publish}
  while IFS= read -r -d '' arm_file; do
    relative=${arm_file#${arm_publish}/}
    [[ ${relative} == Native/* ]] && continue
    # Debug-symbol bundles are architecture-specific by construction (the
    # relocation directory is named after the slice, aarch64 versus x86_64),
    # so they have no cross-architecture counterpart. They are stripped from
    # the staged bundle below and never ship, so skip them here.
    [[ ${relative} == *.dSYM/* ]] && continue
    x64_file=${x64_publish}/${relative}
    merged_file=${merged_publish}/${relative}
    if [[ ! -f ${x64_file} || -L ${x64_file} ]]; then
      print -u2 "Universal publish counterpart is missing: ${relative}"
      exit 1
    fi
    if file -b ${arm_file} | grep -q 'Mach-O'; then
      if ! file -b ${x64_file} | grep -q 'Mach-O'; then
        print -u2 "Universal publish architecture mismatch: ${relative}"
        exit 1
      fi
      arm_architectures=$(xcrun lipo ${arm_file} -archs)
      x64_architectures=$(xcrun lipo ${x64_file} -archs)
      [[ " ${arm_architectures} " == *' arm64 '* ]] || {
        print -u2 "The arm64 publish lacks an arm64 Mach-O slice: ${relative}"
        exit 1
      }
      [[ " ${x64_architectures} " == *' x86_64 '* ]] || {
        print -u2 "The x86_64 publish lacks an x86_64 Mach-O slice: ${relative}"
        exit 1
      }
      arm_slice=${build_root}/universal-arm64-slice
      x64_slice=${build_root}/universal-x86_64-slice
      if [[ ${arm_architectures} == arm64 ]]; then
        ditto ${arm_file} ${arm_slice}
      else
        xcrun lipo ${arm_file} -thin arm64 -output ${arm_slice}
      fi
      if [[ ${x64_architectures} == x86_64 ]]; then
        ditto ${x64_file} ${x64_slice}
      else
        xcrun lipo ${x64_file} -thin x86_64 -output ${x64_slice}
      fi
      xcrun lipo -create ${arm_slice} ${x64_slice} -output ${merged_file}
      chmod $(stat -f %Lp ${arm_file}) ${merged_file}
      xcrun lipo ${merged_file} -verify_arch arm64 x86_64
      rm -- ${arm_slice} ${x64_slice}
    elif ! cmp -s ${arm_file} ${x64_file}; then
      print -u2 "Non-Mach-O publish outputs differ between architectures: ${relative}"
      exit 1
    fi
  done < <(find ${arm_publish} -type f -print0)
  while IFS= read -r -d '' x64_file; do
    relative=${x64_file#${x64_publish}/}
    [[ ${relative} == Native/* ]] && continue
    [[ ${relative} == *.dSYM/* ]] && continue
    [[ -f ${arm_publish}/${relative} ]] || {
      print -u2 "Unexpected x86_64-only publish output: ${relative}"
      exit 1
    }
  done < <(find ${x64_publish} -type f -print0)
else
  while IFS= read -r -d '' merged_file; do
    [[ ${merged_file#${merged_publish}/} == Native/* ]] && continue
    [[ ${merged_file#${merged_publish}/} == *.dSYM/* ]] && continue
    file -b ${merged_file} | grep -q 'Mach-O' || continue
    published_architectures=$(xcrun lipo ${merged_file} -archs)
    [[ " ${published_architectures} " == *' arm64 '* ]] || {
      print -u2 "The arm64 publish contains a Mach-O without an arm64 slice: ${merged_file#${merged_publish}/}"
      exit 1
    }
    if [[ ${published_architectures} != arm64 ]]; then
      thinned_file=${build_root}/arm64-publish-slice
      xcrun lipo ${merged_file} -thin arm64 -output ${thinned_file}
      chmod $(stat -f %Lp ${merged_file}) ${thinned_file}
      mv ${thinned_file} ${merged_file}
      xcrun lipo ${merged_file} -verify_arch arm64
    fi
  done < <(find ${merged_publish} -type f -print0)
fi

# Debug symbols must not ship inside the signed bundle: they would add
# unsigned Mach-O payload under Contents/MacOS and hand a reverse engineer a
# full symbol map of the security core. Move them next to the release instead.
symbols_dir=${build_root}/symbols
mkdir -p ${symbols_dir}
while IFS= read -r -d '' dsym_path; do
  [[ ${dsym_path} == ${merged_publish}/* ]] || continue
  ditto ${dsym_path} ${symbols_dir}/${dsym_path:t}
  rm -rf -- ${dsym_path}
done < <(find ${merged_publish} -type d -name '*.dSYM' -print0)
if find ${merged_publish} -name '*.dSYM' -print -quit | grep -q .; then
  print -u2 'Debug-symbol bundles survived removal from the staged payload.'
  exit 1
fi

native_dir=${merged_publish}/Native
if [[ -d ${native_dir} && ${native_dir} == ${build_root}/* ]]; then
  rm -rf -- ${native_dir}
fi
mkdir -p ${native_dir}
native_source=${repo_root}/KeepVaultMac/Native/$([[ ${architecture} == universal ]] && print osx-universal || print osx-arm64)
for native_name in zpaq argon2 libaes_ref.dylib libargon2_ref.dylib libchachapoly_ref.dylib libkalyna_v12.dylib libmars_ref.dylib libshacal2_ref.dylib libthreefish_ref.dylib; do
  ditto ${native_source}/${native_name} ${native_dir}/${native_name}
done

core_path=${merged_publish}/Keep\ Vault
if [[ ! -f ${core_path} || -L ${core_path} ]]; then
  print -u2 "NativeAOT core was not produced: ${core_path}"
  exit 1
fi

app_stage=${build_root}/Keep\ Vault.app
contents=${app_stage}/Contents
macos_dir=${contents}/MacOS
resources_dir=${contents}/Resources
mkdir -p ${macos_dir} ${resources_dir}
ditto ${merged_publish} ${macos_dir}

# License compliance is part of the signed payload, not an external web page.
# The exact locked-package notices are copied only after the private restore and
# publish have completed. Every source is opened once without following a
# symbolic link, hash-pinned and copied through that same identity-bound FD. The
# single O_EXCL output stays descriptor-bound through its final hash and is then
# covered by Apple's CodeResources seal and Keep Vault's detached manifests.
third_party_header=${packaging_dir}/ThirdPartyNoticesHeader.txt
third_party_notices=${resources_dir}/THIRD-PARTY-NOTICES.txt
expected_third_party_header_sha256='908f80164af2529cc884b1712649f306ca4653c18ea79b910e7835df368ce4ae'
expected_third_party_notices_sha256='bd4bd21c7ffa79d36a4f20abb6b7af3116fc005d3971ca0be09b49e083d6f159'
create_bound_notice_output ${third_party_notices}
copy_pinned_notice_source 'reviewed third-party-notice header' \
  ${third_party_header} ${expected_third_party_header_sha256} 0

nativeaot_notice_root=${private_nuget_packages}/microsoft.netcore.app.runtime.nativeaot.osx-arm64/10.0.11
if [[ ! -d ${nativeaot_notice_root} ]]; then
  nativeaot_notice_root=${private_nuget_packages}/microsoft.netcore.app.runtime.nativeaot.osx-x64/10.0.11
fi
append_pinned_notice 'Crypto++ 8.9.0' \
  ${repo_root}/external/cryptopp/License.txt \
  78e4010b682cb94187fe0b57e50116d0ba271ef81104d1ddb35c80c3d81e3169
append_pinned_notice 'ZPAQ and libdivsufsort-lite' \
  ${repo_root}/external/zpaq/COPYING \
  927b5feda84f7a7f2063998b124829182967f54b954db2c3569e8bd07958bf07
append_pinned_notice 'Argon2 reference implementation' \
  ${repo_root}/external/phc-winner-argon2/LICENSE \
  e01fc30f00792a2bb95136ebe7dd7d01baab62e719ed26ae1b08a3b6b114fdad
append_pinned_notice 'ML-DSA reference implementation used by release tooling' \
  ${repo_root}/external/ML-DSA-reference/LICENSE \
  83504f283bf6b5d1ee3ede4d73eba3e2d620f507183a3915e3fbca7d574cb04a
append_pinned_notice 'BouncyCastle.Cryptography 2.6.2' \
  ${private_nuget_packages}/bouncycastle.cryptography/2.6.2/LICENSE.md \
  afc1653b666b64a2386b7b9b914406904f45c20b9571765d8c1121b513313179
append_pinned_notice 'QRCoder 1.8.0' \
  ${private_nuget_packages}/qrcoder/1.8.0/LICENSE.txt \
  fde71b40fff47192a02738042cb39fa780635daa00827771bec65366ccd1e46d
append_pinned_notice 'HarfBuzzSharp native assets 8.3.1.3 licence' \
  ${private_nuget_packages}/harfbuzzsharp.nativeassets.macos/8.3.1.3/LICENSE.txt \
  89101e35a8c66fd4d6dffc1763259161d35cb564c169714ec227a768c89f2938
append_pinned_notice 'HarfBuzzSharp native assets 8.3.1.3 third-party notices' \
  ${private_nuget_packages}/harfbuzzsharp.nativeassets.macos/8.3.1.3/THIRD-PARTY-NOTICES.txt \
  21504c46c4c58aa64c1055bd2dcbc5f9a136b4b8c412ed3cc6740e22c5b127f5
append_pinned_notice 'SkiaSharp native assets 3.119.4 licence' \
  ${private_nuget_packages}/skiasharp.nativeassets.macos/3.119.4/LICENSE.txt \
  89101e35a8c66fd4d6dffc1763259161d35cb564c169714ec227a768c89f2938
append_pinned_notice 'SkiaSharp native assets 3.119.4 third-party notices' \
  ${private_nuget_packages}/skiasharp.nativeassets.macos/3.119.4/THIRD-PARTY-NOTICES.txt \
  21504c46c4c58aa64c1055bd2dcbc5f9a136b4b8c412ed3cc6740e22c5b127f5
append_pinned_notice '.NET 10.0.11 NativeAOT runtime licence' \
  ${nativeaot_notice_root}/LICENSE.TXT \
  cfc21f5e8bd655ae997eec916138b707b1d290b83272c02a95c9f821b8c87310
append_pinned_notice '.NET 10.0.11 NativeAOT runtime third-party notices' \
  ${nativeaot_notice_root}/THIRD-PARTY-NOTICES.TXT \
  66f1d4e44973185519bb4aa8a9718eb22fc7af2cc532e3ae9cfc4c127ee7fc54

finalize_bound_notice_output \
  ${third_party_notices} 300000 2000000 ${expected_third_party_notices_sha256}
print "third_party_notices_sha256=${third_party_notice_sha256}"

sed \
  -e "s/@@MARKETING_VERSION@@/${marketing_version}/g" \
  -e "s/@@BUILD_VERSION@@/${build_version}/g" \
  ${packaging_dir}/Info.plist.template > ${contents}/Info.plist
plutil -lint ${contents}/Info.plist

icon_work=${build_root}/icon
iconset=${icon_work}/KeepVault.iconset
mkdir -p ${iconset}
xcrun swift ${packaging_dir}/GenerateIcon.swift ${icon_work}/KeepVault-1024.png
for icon_size in 16 32 128 256 512; do
  sips -z ${icon_size} ${icon_size} ${icon_work}/KeepVault-1024.png --out ${iconset}/icon_${icon_size}x${icon_size}.png >/dev/null
  double_size=$(( icon_size * 2 ))
  sips -z ${double_size} ${double_size} ${icon_work}/KeepVault-1024.png --out ${iconset}/icon_${icon_size}x${icon_size}@2x.png >/dev/null
done
iconutil -c icns ${iconset} -o ${resources_dir}/KeepVault.icns

sign_macho() {
  local macho_path=$1
  local identifier_value=$2
  local entitlements=${3:-}
  local arguments=(--force --sign ${identity} --options runtime ${timestamp_arguments[@]} --identifier ${identifier_value})
  if [[ -n ${entitlements} ]]; then
    arguments+=(--entitlements ${entitlements})
  fi
  codesign ${arguments[@]} ${macho_path}
}

while IFS= read -r -d '' candidate; do
  [[ ${candidate} == ${macos_dir}/Keep\ Vault ]] && continue
  if file -b ${candidate} | grep -q 'Mach-O'; then
    relative=${candidate#${macos_dir}/}
    helper_id=${bundle_identifier}.component.$(print -n ${relative} | shasum -a 256 | awk '{print substr($1,1,16)}')
    if [[ ${candidate:t} == zpaq || ${candidate:t} == argon2 ]]; then
      sign_macho ${candidate} ${helper_id} ${packaging_dir}/Helper.entitlements
    else
      sign_macho ${candidate} ${helper_id}
    fi
  fi
done < <(find ${macos_dir} -type f -print0)
sign_macho ${macos_dir}/Keep\ Vault ${core_identifier} ${packaging_dir}/KeepVault.entitlements

launcher_architectures=(arm64)
[[ ${architecture} == universal ]] && launcher_architectures+=(x86_64)

signer_project=${packaging_dir}/HybridSigner/KeepVaultMac.HybridSigner.csproj
(
  cd ${mac_project}
  run_dotnet_clean build Packaging/HybridSigner/KeepVaultMac.HybridSigner.csproj -c Release --no-restore --no-incremental --artifacts-path ${private_signer_artifacts} --disable-build-servers -p:UseSharedCompilation=false --nologo
)
signer_dll=${private_signer_artifacts}/bin/KeepVaultMac.HybridSigner/release/KeepVaultMac.HybridSigner.dll
if [[ ! -f ${signer_dll} || -L ${signer_dll} ]]; then
  print -u2 'The reviewed hybrid signer did not produce its managed entry assembly.'
  exit 1
fi
signer_dll_identity=$(stat -f '%d:%i:%u:%Lp:%z:%m:%c:%l' ${signer_dll})
if [[ ${signer_dll_identity} != *:${EUID}:*:*:*:*:1 ]]; then
  print -u2 'The private hybrid signer assembly is not a single-link caller-owned file.'
  exit 2
fi

signer_arguments=(
  ${signer_dll}
  sign
  --pfx ${pfx_path}
  ${mldsa_key_arguments[@]}
  ${pfx_password_arguments[@]}
  --mldsa-public-key ${mldsa_public_key}
  --reference-library ${repo_root}/KeepVaultMac/Native/$([[ ${architecture} == universal ]] && print osx-universal || print osx-arm64)/libmldsa87_ref.dylib
  --policy ${mac_project}/Directory.Build.props
  --launcher-pins ${build_root}/HybridPins.swift
)

# Every Mach-O below Contents/MacOS gets a hybrid signature, enumerated from the
# bundle rather than listed by hand. A hand-written list only covers what
# somebody remembered to add: the three Avalonia and Skia libraries were signed
# by Apple in the loop above and then left out here, so they ran inside the
# process that holds the archive keys protected by Apple's signature alone --
# exactly the layer the post-quantum pair exists to stop relying on.
#
# The supervisor and the launcher are skipped here because each gets its own
# later pass: the supervisor after its cdhash pin is generated, and the launcher
# because it carries the bundle seal and its signature has to live outside the
# bundle. Neither is compiled into the bundle yet at this point; the guard is
# there so reordering the build cannot silently sign them twice.
hybrid_target_count=0
while IFS= read -r -d '' hybrid_candidate; do
  [[ ${hybrid_candidate:t} == 'Keep Vault Supervisor' || ${hybrid_candidate:t} == 'Keep Vault Launcher' ]] && continue
  file -b ${hybrid_candidate} | grep -q 'Mach-O' || continue
  signer_arguments+=(--target ${hybrid_candidate})
  (( hybrid_target_count += 1 ))
done < <(find ${macos_dir} -type f -print0 | sort -z)
if (( hybrid_target_count < 10 )); then
  print -u2 "Too few Mach-O hybrid-signing targets were found: ${hybrid_target_count}"
  exit 1
fi
(
  cd ${mac_project}
  run_hybrid_signer ${signer_arguments[@]}
)

generate_cdhash_pins() {
  local signed_binary=$1
  local output_source=$2
  local enum_name=$3
  shift 3
  local temporary_source=${output_source}.tmp
  : > ${temporary_source}
  print -r -- '// Generated by Build-KeepVault-macOS.sh. Do not edit.' >> ${temporary_source}
  print -r -- "enum ${enum_name} {" >> ${temporary_source}
  print -r -- '    static let cdHashes = [' >> ${temporary_source}
  local requested_architecture signature_output cdhash
  for requested_architecture in "$@"; do
    signature_output=$(codesign -dvvv --arch ${requested_architecture} ${signed_binary} 2>&1)
    cdhash=$(print -r -- ${signature_output} | awk -F= '/^CDHash=/{print $2; exit}')
    if [[ ! ${cdhash} =~ '^[0-9A-Fa-f]{40}$' ]]; then
      print -u2 "Unable to derive the signed ${requested_architecture} CDHash: ${signed_binary}"
      return 1
    fi
    print -r -- "        \"${cdhash:u}\"," >> ${temporary_source}
  done
  print -r -- '    ]' >> ${temporary_source}
  print -r -- '}' >> ${temporary_source}
  mv ${temporary_source} ${output_source}
}

core_apple_pins=${build_root}/CoreApplePins.swift
generate_cdhash_pins \
  ${macos_dir}/Keep\ Vault \
  ${core_apple_pins} \
  KeepVaultCoreApplePins \
  ${launcher_architectures[@]}

supervisor_thin=()
for supervisor_arch in ${launcher_architectures[@]}; do
  thin_supervisor=${build_root}/Keep\ Vault\ Supervisor-${supervisor_arch}
  xcrun swiftc \
    -target ${supervisor_arch}-apple-macos14.0 \
    -O -whole-module-optimization -parse-as-library \
    ${packaging_dir}/Supervisor.swift ${core_apple_pins} \
    -framework Foundation -framework Security \
    -o ${thin_supervisor}
  supervisor_thin+=(${thin_supervisor})
done

supervisor_path=${macos_dir}/Keep\ Vault\ Supervisor
if [[ ${architecture} == universal ]]; then
  xcrun lipo -create ${supervisor_thin[@]} -output ${supervisor_path}
  xcrun lipo ${supervisor_path} -verify_arch arm64 x86_64
else
  ditto ${supervisor_thin[1]} ${supervisor_path}
fi
chmod 0755 ${supervisor_path}
sign_macho ${supervisor_path} ${bundle_identifier}.supervisor ${packaging_dir}/Helper.entitlements

# The supervisor embeds the signed core's pins, so it cannot exist before the
# first hybrid pass and gets its own. It is checked against the same
# post-quantum pair as the core: its Apple signature and its cdhash pin are both
# anchored in RSA and ECDSA, and resting one process on that alone would
# undercut the assumption the whole chain is built on.
supervisor_signature_arguments=(
  ${signer_dll}
  sign
  --pfx ${pfx_path}
  ${mldsa_key_arguments[@]}
  ${pfx_password_arguments[@]}
  --mldsa-public-key ${mldsa_public_key}
  --reference-library ${repo_root}/KeepVaultMac/Native/$([[ ${architecture} == universal ]] && print osx-universal || print osx-arm64)/libmldsa87_ref.dylib
  --policy ${mac_project}/Directory.Build.props
  --launcher-pins ${build_root}/SupervisorHybridPins.swift
  --target ${supervisor_path}
)
(
  cd ${mac_project}
  run_hybrid_signer ${supervisor_signature_arguments[@]}
)

supervisor_apple_pins=${build_root}/SupervisorApplePins.swift
generate_cdhash_pins \
  ${supervisor_path} \
  ${supervisor_apple_pins} \
  KeepVaultSupervisorApplePins \
  ${launcher_architectures[@]}

launcher_sources=(
  ${repo_root}/native/mldsa87_ref_export.c
  ${repo_root}/external/ML-DSA-reference/ref/sign.c
  ${repo_root}/external/ML-DSA-reference/ref/packing.c
  ${repo_root}/external/ML-DSA-reference/ref/polyvec.c
  ${repo_root}/external/ML-DSA-reference/ref/poly.c
  ${repo_root}/external/ML-DSA-reference/ref/ntt.c
  ${repo_root}/external/ML-DSA-reference/ref/reduce.c
  ${repo_root}/external/ML-DSA-reference/ref/rounding.c
  ${repo_root}/external/ML-DSA-reference/ref/symmetric-shake.c
  ${repo_root}/external/ML-DSA-reference/ref/fips202.c
)
launcher_thin=()
for launcher_arch in ${launcher_architectures[@]}; do
  object_dir=${build_root}/launcher-objects-${launcher_arch}
  mkdir -p ${object_dir}
  object_files=()
  object_index=0
  for launcher_source in ${launcher_sources[@]}; do
    object_path=${object_dir}/${object_index}.o
    xcrun clang \
      -arch ${launcher_arch} \
      -mmacosx-version-min=14.0 \
      -O2 -DNDEBUG -DDILITHIUM_MODE=5 \
      -fstack-protector-strong -fvisibility=hidden -fno-common \
      -I${repo_root}/external/ML-DSA-reference/ref \
      -c ${launcher_source} -o ${object_path}
    object_files+=(${object_path})
    (( object_index += 1 ))
  done
  # The rollback floor the launcher enforces against the machine-wide anchor.
  launcher_version_source=${build_root}/KeepVaultBuildVersion.swift
  print "enum KeepVaultBuild { static let version: UInt64 = ${build_version} }" > ${launcher_version_source}
  thin_launcher=${build_root}/Keep\ Vault\ Launcher-${launcher_arch}
  xcrun swiftc \
    -target ${launcher_arch}-apple-macos14.0 \
    -O -whole-module-optimization -parse-as-library \
    ${packaging_dir}/Launcher.swift ${build_root}/HybridPins.swift ${supervisor_apple_pins} \
    ${launcher_version_source} \
    ${object_files[@]} \
    -framework AppKit -framework Security \
    -o ${thin_launcher}
  launcher_thin+=(${thin_launcher})
done

launcher_path=${macos_dir}/Keep\ Vault\ Launcher
if [[ ${architecture} == universal ]]; then
  xcrun lipo -create ${launcher_thin[@]} -output ${launcher_path}
  xcrun lipo ${launcher_path} -verify_arch arm64 x86_64
else
  ditto ${launcher_thin[1]} ${launcher_path}
fi
chmod 0755 ${launcher_path}

# Apple's bundle format reserves Contents/MacOS for Mach-O executables. The
# detached hash and hybrid-signature sidecars written next to each binary above
# are not code, and codesign refuses to seal a bundle that carries them there.
# Relocate them under Contents/Resources, mirroring the layout below
# Contents/MacOS, which also brings them under the bundle's CodeResources seal.
# This must precede signing the launcher: codesign resolves the path of a
# bundle's main executable to the enclosing bundle, so that step already seals
# the whole app.
signature_dir=${resources_dir}/HybridSignatures
mkdir -p ${signature_dir}
relocated_sidecars=0
while IFS= read -r -d '' sidecar_path; do
  relative=${sidecar_path#${macos_dir}/}
  destination=${signature_dir}/${relative}
  mkdir -p ${destination:h}
  mv -- ${sidecar_path} ${destination}
  relocated_sidecars=$(( relocated_sidecars + 1 ))
done < <(find ${macos_dir} -type f \( -name '*.sha3' -o -name '*.skein' -o -name '*.khsig' \) -print0)
if (( relocated_sidecars == 0 )); then
  print -u2 'No hybrid-signature sidecars were found to relocate; the signing chain is incomplete.'
  exit 1
fi
if find ${macos_dir} -type f \( -name '*.sha3' -o -name '*.skein' -o -name '*.khsig' \) -print -quit | grep -q .; then
  print -u2 'Hybrid-signature sidecars survived relocation out of Contents/MacOS.'
  exit 1
fi
print "relocated_sidecars=${relocated_sidecars}"

sign_macho ${launcher_path} ${bundle_identifier}.launcher ${packaging_dir}/Launcher.entitlements

codesign \
  --force \
  --sign ${identity} \
  --options runtime \
  ${timestamp_arguments[@]} \
  --entitlements ${packaging_dir}/Launcher.entitlements \
  --identifier ${bundle_identifier} \
  ${app_stage}

${script_dir}/Verify-KeepVault-macOS.sh \
  --app ${app_stage} \
  --allow-development \
  --mldsa-public-key ${mldsa_public_key}

dist_dir=${repo_root}/dist/Keep\ Vault-macOS
mkdir -p ${dist_dir}

# Keep build output out of Spotlight. Without this the release copy, the
# portable copy and the installed app all answer to a search for "Keep Vault",
# and the user is left guessing which of them they are about to open.
dist_stage=${build_root}/dist-stage
mkdir -p ${dist_stage}

final_app=${dist_stage}/Keep\ Vault.app
final_zip=${dist_stage}/Keep\ Vault-macOS-${architecture}.zip

ditto ${app_stage} ${final_app}

# The launcher is the bundle's main executable, so codesign writes the bundle
# seal into that very file. A hybrid signature over its own bytes therefore
# cannot live inside the bundle: adding it would change the seal and invalidate
# itself. It is signed now, once the bytes are final, and placed beside the app
# — which is also what gets published, so the one component that was covered by
# Apple's signature alone now carries the dual signature too.
launcher_signature_common=(
  ${signer_dll}
  sign
  --pfx ${pfx_path}
  ${mldsa_key_arguments[@]}
  ${pfx_password_arguments[@]}
  --mldsa-public-key ${mldsa_public_key}
  --reference-library ${repo_root}/KeepVaultMac/Native/$([[ ${architecture} == universal ]] && print osx-universal || print osx-arm64)/libmldsa87_ref.dylib
  --policy ${mac_project}/Directory.Build.props
  --launcher-pins ${build_root}/SelfHybridPins.swift
  --target ${final_app}/Contents/MacOS/Keep\ Vault\ Launcher
)
(
  cd ${mac_project}
  run_hybrid_signer ${launcher_signature_common[@]}
)

# Move the launcher's sidecars out of the bundle and beside it, under the app's
# own name, which is where the launcher looks for them at startup.
launcher_sidecar_source=${final_app}/Contents/MacOS/Keep\ Vault\ Launcher
for sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
  if [[ ! -f ${launcher_sidecar_source}${sidecar_suffix} ]]; then
    print -u2 "The launcher self-signature is incomplete: ${sidecar_suffix}"
    exit 1
  fi
  mv -- ${launcher_sidecar_source}${sidecar_suffix} ${final_app}.launcher${sidecar_suffix}
done
print "launcher_self_signature=${final_app}.launcher.khsig"
final_symbols=${dist_stage}/Keep\ Vault-macOS-${architecture}.dSYMs
rm -rf -- ${final_symbols}
ditto ${symbols_dir} ${final_symbols}

# --- Companion QR Scanner -----------------------------------------------------
scanner_build_script=${repo_root}/QrCodeScanner/tools/Build-QrScanner-macOS.sh
scanner_dist=${repo_root}/QrCodeScanner/dist/QR-Scanner.app
if [[ -f ${scanner_build_script} ]]; then
  scanner_args=(
    --identity "${identity_label}"
    --arch ${architecture}
    --version "${marketing_version}"
    --build-number "${build_version}"
  )
  if [[ -n ${notary_profile:-} && ${identity_label} == 'Developer ID Application:'* ]]; then
    scanner_args+=(--notary-profile "${notary_profile}")
  fi
  ${scanner_build_script} ${scanner_args[@]}

  # Verify release pair metadata and hybrid integrity
  ${script_dir}/Verify-ReleasePairMetadata-macOS.sh --app ${final_app} --scanner ${scanner_dist}
  scanner_verify_args=(--app ${scanner_dist})
  if [[ ${identity_label} == 'Apple Development:'* ]]; then
    scanner_verify_args+=(--allow-development)
  fi
  if [[ -n ${notary_profile:-} && ${identity_label} == 'Developer ID Application:'* ]]; then
    scanner_verify_args+=(--require-notarization)
  fi
  ${script_dir}/Verify-QR-Scanner-macOS.sh ${scanner_verify_args[@]}

  ditto ${scanner_dist} ${dist_stage}/QR-Scanner.app
  for sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    if [[ ! -f ${scanner_dist}${sidecar_suffix} || -L ${scanner_dist}${sidecar_suffix} ]]; then
      print -u2 "QR-Scanner hybrid sidecar is missing: ${sidecar_suffix}"
      exit 1
    fi
    ditto ${scanner_dist}${sidecar_suffix} ${dist_stage}/QR-Scanner.app${sidecar_suffix}
  done
fi

# The launcher will not start without its own dual signature, so the sidecars
# have to be inside the distribution archive as well. Archiving the contents of
# a staging directory (rather than --keepParent on the bundle) keeps the app at
# the archive root and puts the sidecars beside it, exactly as installed.
zip_stage=${build_root}/zip-stage
rm -rf -- ${zip_stage}
mkdir -p ${zip_stage}
ditto ${final_app} ${zip_stage}/Keep\ Vault.app
for sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
  ditto ${final_app}.launcher${sidecar_suffix} ${zip_stage}/Keep\ Vault.app.launcher${sidecar_suffix}
done

if [[ -d ${dist_stage}/QR-Scanner.app ]]; then
  ditto ${dist_stage}/QR-Scanner.app ${zip_stage}/QR-Scanner.app
  for sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    ditto ${dist_stage}/QR-Scanner.app${sidecar_suffix} ${zip_stage}/QR-Scanner.app${sidecar_suffix}
  done
fi

ditto -c -k --sequesterRsrc ${zip_stage} ${final_zip}

archive_common=(
  ${signer_dll}
  sign
  --pfx ${pfx_path}
  ${mldsa_key_arguments[@]}
  ${pfx_password_arguments[@]}
  --mldsa-public-key ${mldsa_public_key}
  --reference-library ${repo_root}/KeepVaultMac/Native/$([[ ${architecture} == universal ]] && print osx-universal || print osx-arm64)/libmldsa87_ref.dylib
  --policy ${mac_project}/Directory.Build.props
  --launcher-pins ${build_root}/ArchiveHybridPins.swift
  --target ${final_zip}
)
(
  cd ${mac_project}
  run_hybrid_signer ${archive_common[@]}
)

archive_check=${build_root}/archive-check
rm -rf -- ${archive_check}
mkdir -p ${archive_check}
ditto -x -k ${final_zip} ${archive_check}
if [[ ! -d ${archive_check}/Keep\ Vault.app || -L ${archive_check}/Keep\ Vault.app ]]; then
  print -u2 'The distribution archive did not reproduce the Keep Vault app bundle.'
  exit 1
fi
${script_dir}/Verify-KeepVault-macOS.sh \
  --app ${archive_check}/Keep\ Vault.app \
  --allow-development \
  --require-launcher-signature \
  --mldsa-public-key ${mldsa_public_key}

if [[ -d ${archive_check}/QR-Scanner.app ]]; then
  ${script_dir}/Verify-QR-Scanner-macOS.sh \
    --app ${archive_check}/QR-Scanner.app \
    --allow-development
fi

${script_dir}/Verify-KeepVault-macOS.sh \
  --app ${final_app} \
  --allow-development \
  --require-launcher-signature \
  --mldsa-public-key ${mldsa_public_key}

print 'RELEASE GATE: running native slice KATs across architectures...'
native_kats_source=${packaging_dir}/NativeKats.c
native_kats_arm64=${build_root}/native-kats-arm64
xcrun clang -arch arm64 -O2 ${native_kats_source} -o ${native_kats_arm64}
${native_kats_arm64} ${repo_root}/KeepVaultMac/Native/osx-arm64

if [[ ${architecture} == universal ]]; then
  native_kats_x64=${build_root}/native-kats-x64
  xcrun clang -arch x86_64 -O2 ${native_kats_source} -o ${native_kats_x64}
  arch -x86_64 ${native_kats_x64} ${repo_root}/KeepVaultMac/Native/osx-x64
fi

print 'RELEASE GATE: building the test project before staging any signed test-native bytes...'
(
  cd ${repo_root}
  run_dotnet_clean build KeepVaultMac.Tests/KeepVaultMac.Tests.csproj \
    -c Release \
    --no-restore \
    --no-incremental \
    --artifacts-path ${private_tests_artifacts} \
    --disable-build-servers \
    -p:UseSharedCompilation=false \
    --nologo
)

print 'RELEASE GATE: staging test natives after the final project build...'
${script_dir}/Stage-TestNatives-macOS.sh \
  --app ${final_app} \
  --destination ${private_tests_artifacts}/bin/KeepVaultMac.Tests/release_osx-arm64/Native \
  --identity ${identity}
(
  cd ${repo_root}
  test_sheet_dir=$(mktemp -d "${build_root}/test-sheets.XXXXXX")
  trap 'rm -rf -- "${test_sheet_dir}"' EXIT INT TERM
  test_project=KeepVaultMac.Tests/KeepVaultMac.Tests.csproj
  test_inventory=$(run_dotnet_clean run \
    --project ${test_project} \
    --artifacts-path ${private_tests_artifacts} \
    -c Release \
    --no-build \
    --no-restore \
    --disable-build-servers \
    -- \
    --list)
  required_test_ids=(
    crypto.v12-parallel-mac-kat
    crypto.chacha20-poly1305-rfc8439
    containers.v12-production-worker-equivalence
    containers.v12-kpar2-roundtrip
    recovery.parallel-worker-equivalence
    recovery.physical-eio-repair
    packaging.keychain-secret-not-in-argv
    packaging.hybrid-key-separation
    zpaq.full-matrix
    zpaq.process-resource-limits
    zpaq.fail-fast-error-preservation
    zpaq.sync-consumer-fail-fast
    performance.cipher-suites
    performance.paranoia-256mib-e2e
    performance.paranoia-complex-tree-e2e
    containers.suite.kalyna512-512
    containers.suite.threefish1024
    containers.suite.threefish-over-kalyna
    containers.suite.paranoia-cascade
    containers.suite.chacha-over-aes
    containers.suite.aes256
    containers.suite.mars448
    containers.suite.shacal2-512
    containers.suite.chacha20-poly1305
    containers.suite.mixed-cascade
  )
  for required_test_id in ${required_test_ids[@]}; do
    if ! print -r -- ${test_inventory} | grep -Fq -- ${required_test_id}; then
      print -u2 "RELEASE GATE: required v12 test is absent: ${required_test_id}"
      exit 2
    fi
  done

  logical_processors=$(/usr/sbin/sysctl -n hw.logicalcpu 2>/dev/null || print 1)
  if [[ ! ${logical_processors} =~ '^[1-9][0-9]*$' ]]; then
    print -u2 'RELEASE GATE: the logical processor count is unavailable.'
    exit 2
  fi
  parallel_test_workers=$(( logical_processors > 8 ? 8 : logical_processors ))
  if (( parallel_test_workers < 2 )); then
    print -u2 'RELEASE GATE: production worker equivalence requires at least two logical processors.'
    exit 2
  fi

  print 'RELEASE GATE: running the complete suite with one test worker...'
  KEEPVAULT_TEST_RELEASE_ROOT=${dist_stage} \
    run_dotnet_clean run \
      --project ${test_project} \
      --artifacts-path ${private_tests_artifacts} \
      -c Release \
      --no-build \
      --no-restore \
      --disable-build-servers \
      -- \
      --full \
      --parallel 1 \
      --dump-key-sheets "${test_sheet_dir}"

  if (( release_mode )); then
    print "RELEASE GATE: running the complete suite with ${parallel_test_workers} test workers..."
    KEEPVAULT_TEST_RELEASE_ROOT=${dist_stage} \
      run_dotnet_clean run \
        --project ${test_project} \
        --artifacts-path ${private_tests_artifacts} \
        -c Release \
        --no-build \
        --no-restore \
        --disable-build-servers \
        -- \
        --full \
        --parallel ${parallel_test_workers}

    print 'RELEASE GATE: explicitly running the production worker-1-vs-N container KAT...'
    KEEPVAULT_TEST_RELEASE_ROOT=${dist_stage} \
      run_dotnet_clean run \
        --project ${test_project} \
        --artifacts-path ${private_tests_artifacts} \
        -c Release \
        --no-build \
        --no-restore \
        --disable-build-servers \
        -- \
        --full \
        --no-smoke \
        --only containers.v12-production-worker-equivalence \
        --parallel 1

    print 'RELEASE GATE: explicitly running the independently pinned v12 parallel-MAC KAT...'
    KEEPVAULT_TEST_RELEASE_ROOT=${dist_stage} \
      run_dotnet_clean run \
        --project ${test_project} \
        --artifacts-path ${private_tests_artifacts} \
        -c Release \
        --no-build \
        --no-restore \
        --disable-build-servers \
        -- \
        --full \
        --no-smoke \
        --only crypto.v12-parallel-mac-kat \
        --parallel 1

    print 'RELEASE GATE: explicitly running the integrated v12 container, ZPAQ and KPAR2 end-to-end gates...'
    KEEPVAULT_TEST_RELEASE_ROOT=${dist_stage} \
      run_dotnet_clean run \
        --project ${test_project} \
        --artifacts-path ${private_tests_artifacts} \
        -c Release \
        --no-build \
        --no-restore \
        --disable-build-servers \
        -- \
        --full \
        --no-smoke \
        --only containers.v12-kpar2-roundtrip \
        --parallel 1
    KEEPVAULT_TEST_RELEASE_ROOT=${dist_stage} \
      run_dotnet_clean run \
        --project ${test_project} \
        --artifacts-path ${private_tests_artifacts} \
        -c Release \
        --no-build \
        --no-restore \
        --disable-build-servers \
        -- \
        --full \
        --no-smoke \
        --only recovery.parallel-worker-equivalence \
        --parallel 1
    KEEPVAULT_TEST_RELEASE_ROOT=${dist_stage} \
      run_dotnet_clean run \
        --project ${test_project} \
        --artifacts-path ${private_tests_artifacts} \
        -c Release \
        --no-build \
        --no-restore \
        --disable-build-servers \
        -- \
        --full \
        --no-smoke \
        --only recovery.physical-eio-repair \
        --parallel 1
    KEEPVAULT_TEST_RELEASE_ROOT=${dist_stage} \
      run_dotnet_clean run \
        --project ${test_project} \
        --artifacts-path ${private_tests_artifacts} \
        -c Release \
        --no-build \
        --no-restore \
        --disable-build-servers \
        -- \
        --full \
        --no-smoke \
        --only zpaq.full-matrix \
        --parallel 1

    performance_baseline=${requested_performance_baseline}
    if [[ -z ${performance_baseline} || ! -f ${performance_baseline} || -L ${performance_baseline} ]]; then
      print -u2 'RELEASE GATE: --release requires KEEPVAULT_PERF_BASELINE to name a regular same-machine schema-2 baseline.'
      exit 2
    fi
    performance_baseline=${performance_baseline:A}
    print 'RELEASE GATE: running the ten-suite manual performance matrix on one test worker...'
    KEEPVAULT_TEST_RELEASE_ROOT=${dist_stage} \
      KEEPVAULT_PERF_BASELINE=${performance_baseline} \
      run_dotnet_clean run \
        --project ${test_project} \
        --artifacts-path ${private_tests_artifacts} \
        -c Release \
        --no-build \
        --no-restore \
        --disable-build-servers \
        -- \
        --performance \
        --only performance.cipher-suites \
        --parallel 1
  fi
)

# Notarization. Apple must see the build before Gatekeeper will accept it on
# another Mac. Credentials are never passed on the command line or stored in
# this repository: create a keychain profile once with
#
#     xcrun notarytool store-credentials "Keep Vault v12" \
#       --apple-id <your-apple-id> --team-id <your-team-id>
#
# Enter the app-specific password only at notarytool's protected prompt, then
# pass --notary-profile "Keep Vault v12". The profile name is all this script
# ever sees; the secrets stay in the login keychain.
if [[ -z ${notary_profile} ]]; then
  print 'notarization=not_performed (pass --notary-profile NAME once a Developer ID certificate and a notarytool profile exist)'
else
  if [[ ${identity_details} != *'Developer ID Application'* ]]; then
    print -u2 'Notarization requires a Developer ID Application identity; an Apple Development certificate is rejected by the notary service.'
    exit 1
  fi

  xcrun notarytool submit ${final_zip} --keychain-profile ${notary_profile} --wait
  xcrun stapler staple ${final_app}
  xcrun stapler validate ${final_app}

  # The stapled ticket changes the bundle, so the distribution archive and its
  # signed manifests have to be rebuilt from the stapled app including all 5 launcher sidecars.
  rm -f -- ${final_zip} ${final_zip}.sha3 ${final_zip}.skein \
    ${final_zip}.khsig ${final_zip}.sha3.khsig ${final_zip}.skein.khsig
  rm -rf -- ${zip_stage}
  mkdir -p ${zip_stage}
  ditto ${final_app} ${zip_stage}/Keep\ Vault.app
  for sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    ditto ${final_app}.launcher${sidecar_suffix} ${zip_stage}/Keep\ Vault.app.launcher${sidecar_suffix}
  done
  if [[ -d ${dist_stage}/QR-Scanner.app ]]; then
    ditto ${dist_stage}/QR-Scanner.app ${zip_stage}/QR-Scanner.app
    for sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
      ditto ${dist_stage}/QR-Scanner.app${sidecar_suffix} ${zip_stage}/QR-Scanner.app${sidecar_suffix}
    done
  fi
  ditto -c -k --sequesterRsrc ${zip_stage} ${final_zip}
  (
    cd ${mac_project}
    run_hybrid_signer ${archive_common[@]}
  )

  # Re-verify the unzipped post-notarization bundle
  rm -rf -- ${archive_check}
  mkdir -p ${archive_check}
  ditto -x -k ${final_zip} ${archive_check}
  ${script_dir}/Verify-KeepVault-macOS.sh \
    --app ${archive_check}/Keep\ Vault.app \
    --require-launcher-signature \
    --require-notarization \
    --mldsa-public-key ${mldsa_public_key}

  spctl --assess --type execute -vv ${final_app}
  print "notarization=stapled (${notary_profile})"
fi

# ATOMIC PUBLISH: Only official, Developer-ID-signed and notarized release artifacts
# land in dist/. Development and local builds land in build/dev/ to avoid accidental distribution.
publish_target_dir=''
if (( release_mode )) && [[ -n ${notary_profile:-} && ${identity_details} == *'Developer ID Application'* ]]; then
  publish_target_dir=${repo_root}/dist/Keep\ Vault-macOS
else
  publish_target_dir=${repo_root}/build/dev/Keep\ Vault-macOS
  print "publish_mode=development (outputs placed in build/dev/; dist/ is reserved for Developer ID + notarized production releases)"
fi

publish_parent=${publish_target_dir:h}
mkdir -p ${publish_parent}

if [[ -L ${publish_parent} || ! -d ${publish_parent} ]]; then
  print -u2 "Release publish parent is not a physical directory: ${publish_parent}"
  exit 1
fi
publish_parent_identity=$(stat -f '%d:%i' ${publish_parent} 2>/dev/null || true)
if [[ ! ${publish_parent_identity} =~ '^[0-9]+:[0-9]+$' ]]; then
  print -u2 "Release publish parent has no stable device/inode identity: ${publish_parent}"
  exit 1
fi

# Both first publication and replacement are one descriptor-relative Darwin
# rename. There is deliberately no path-only two-move fallback: if the kernel
# primitive or its reviewed helper is unavailable, the previous public tree is
# left intact and the build fails closed.
publish_stage=$(mktemp -d "${publish_parent}/.publish_stage.XXXXXXXX")
chmod 0700 ${publish_stage}
ditto ${dist_stage} ${publish_stage}
publish_stage_identity=$(stat -f '%d:%i' ${publish_stage} 2>/dev/null || true)

publish_quarantine=$(mktemp -d "${publish_parent}/.publish_cleanup.XXXXXXXX")
chmod 0700 ${publish_quarantine}
publish_quarantine_identity=$(stat -f '%d:%i' ${publish_quarantine} 2>/dev/null || true)

publish_rename_source=${script_dir}/ReleasePublishRename.c
publish_delete_source=${script_dir}/InstallerBoundDelete.c
publish_rename_helper=${build_root}/release-publish-rename
publish_delete_helper=${build_root}/release-publish-delete
if [[ ! -f ${publish_rename_source} || -L ${publish_rename_source} \
    || ! -f ${publish_delete_source} || -L ${publish_delete_source} \
    || ! ${publish_stage_identity} =~ '^[0-9]+:[0-9]+$' \
    || ! ${publish_quarantine_identity} =~ '^[0-9]+:[0-9]+$' ]]; then
  print -u2 'Release publish helpers or private staging identities are invalid; staged objects were preserved.'
  exit 1
fi
xcrun clang -std=c17 -Wall -Wextra -Werror -O2 \
  ${publish_rename_source} -o ${publish_rename_helper}
xcrun clang -std=c17 -Wall -Wextra -Werror -O2 \
  ${publish_delete_source} -o ${publish_delete_helper}

delete_old_publish_tree() {
  local object_name=$1
  local expected_identity=$2
  ${publish_delete_helper} \
    ${publish_parent} ${object_name} \
    ${publish_parent_identity%%:*} ${publish_parent_identity#*:} \
    ${publish_quarantine} \
    ${publish_quarantine_identity%%:*} ${publish_quarantine_identity#*:} \
    ${expected_identity}
}

quarantine_uncertain_publish_target() {
  local expected_identity=$1
  local cleanup_status=0
  if [[ ! -e ${publish_target_dir} && ! -L ${publish_target_dir} ]]; then
    return 0
  fi
  delete_old_publish_tree ${publish_target_dir:t} ${expected_identity} \
    || cleanup_status=$?
  # Exit 68 means a foreign inode was removed from the public name and retained
  # in the private quarantine for inspection. That is a safe failed publish.
  (( cleanup_status == 0 || cleanup_status == 68 ))
}

if [[ -e ${publish_target_dir} || -L ${publish_target_dir} ]]; then
  if [[ -L ${publish_target_dir} || ! -d ${publish_target_dir} ]]; then
    print -u2 "Refusing to replace a non-directory or symbolic-link release target: ${publish_target_dir}"
    exit 1
  fi
  previous_publish_identity=$(stat -f '%d:%i' ${publish_target_dir} 2>/dev/null || true)
  if [[ ! ${previous_publish_identity} =~ '^[0-9]+:[0-9]+$' ]]; then
    print -u2 'The previous release target has no stable device/inode identity.'
    exit 1
  fi
  publish_swap_status=0
  if ${publish_rename_helper} swap \
      ${publish_parent} ${publish_stage:t} ${publish_parent} ${publish_target_dir:t} \
      ${publish_parent_identity} ${publish_parent_identity} \
      ${publish_stage_identity} ${previous_publish_identity}; then
    publish_swap_status=0
  else
    publish_swap_status=$?
  fi
  if (( publish_swap_status == 70 )); then
    current_publish_identity=$(stat -f '%d:%i' ${publish_target_dir} 2>/dev/null || true)
    current_stage_identity=$(stat -f '%d:%i' ${publish_stage} 2>/dev/null || true)
    if [[ ${current_publish_identity} == ${publish_stage_identity} \
        && ${current_stage_identity} == ${previous_publish_identity} ]]; then
      # The exchange itself and both identities are complete. A descriptor-close
      # error cannot invalidate that persistent state, so finish normal cleanup.
      publish_swap_status=0
    elif [[ ${current_publish_identity} == ${previous_publish_identity} ]]; then
      print -u2 'RELEASE GATE: the previous public tree was restored after an uncertain exchange.'
    elif [[ ${current_stage_identity} == ${previous_publish_identity} ]]; then
      if quarantine_uncertain_publish_target ${publish_stage_identity} \
          && ${publish_rename_helper} exclusive \
            ${publish_parent} ${publish_stage:t} ${publish_parent} ${publish_target_dir:t} \
            ${publish_parent_identity} ${publish_parent_identity} \
            ${previous_publish_identity} -; then
        print -u2 'RELEASE GATE: the previous public tree was restored after quarantining an uncertain replacement.'
      else
        print -u2 'RELEASE GATE: an uncertain exchange could not restore the previous public tree.'
      fi
    else
      quarantine_uncertain_publish_target ${publish_stage_identity} || true
      print -u2 'RELEASE GATE: an uncertain exchange was quarantined, but the previous tree identity was unavailable.'
    fi
  fi
  if (( publish_swap_status != 0 )); then
    print -u2 'RELEASE GATE: crash-atomic verified directory exchange failed; no path-only fallback was attempted.'
    print -u2 "Staged objects were preserved for inspection at: ${publish_stage}"
    exit 1
  fi
  if ! delete_old_publish_tree ${publish_stage:t} ${previous_publish_identity}; then
    print -u2 'RELEASE GATE: the exact previous publish tree could not be deleted through the inode-bound helper.'
    print -u2 "Any quarantined object was preserved at: ${publish_quarantine}"
    exit 1
  fi
else
  first_publish_status=0
  if ${publish_rename_helper} exclusive \
      ${publish_parent} ${publish_stage:t} ${publish_parent} ${publish_target_dir:t} \
      ${publish_parent_identity} ${publish_parent_identity} \
      ${publish_stage_identity} -; then
    first_publish_status=0
  else
    first_publish_status=$?
  fi
  if (( first_publish_status == 70 )); then
    quarantine_uncertain_publish_target ${publish_stage_identity} || true
  fi
  if (( first_publish_status != 0 )); then
    print -u2 'RELEASE GATE: exclusive first publication failed; no existing destination was overwritten.'
    print -u2 "Staged objects were preserved for inspection at: ${publish_stage}"
    exit 1
  fi
fi

if [[ $(stat -f '%d:%i' ${publish_quarantine} 2>/dev/null || true) != ${publish_quarantine_identity} \
    || -n $(find ${publish_quarantine} -mindepth 1 -print -quit 2>/dev/null) ]]; then
  print -u2 "Release cleanup quarantine changed or is not empty and was preserved: ${publish_quarantine}"
  exit 1
fi
rmdir -- ${publish_quarantine}

touch ${publish_parent}/.metadata_never_index

print "published_app=${publish_target_dir}/Keep Vault.app"
print "published_archive=${publish_target_dir}/Keep Vault-macOS-${architecture}.zip"
