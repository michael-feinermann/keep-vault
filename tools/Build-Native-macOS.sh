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
shasum_path=/usr/bin/shasum
awk_path=/usr/bin/awk
file_path=/usr/bin/file
stat_path=/usr/bin/stat
mktemp_path=/usr/bin/mktemp
chmod_path=/bin/chmod
mkdir_path=/bin/mkdir
rm_path=/bin/rm
mv_path=/bin/mv
readlink_path=/usr/bin/readlink
env_path=/usr/bin/env

require_root_system_tool() {
  local tool=$1
  if [[ ${tool} != /* || ! -f ${tool} || -L ${tool} || ! -x ${tool} \
      || $(${stat_path} -f %u -- ${tool}) != 0 ]]; then
    print -u2 "Native build tool is not an absolute root-owned regular file: ${tool}"
    exit 1
  fi
  local tool_mode=$(( 8#$(${stat_path} -f %Lp -- ${tool}) ))
  if (( (tool_mode & 8#022) != 0 )); then
    print -u2 "Native build tool is group/other writable: ${tool}"
    exit 1
  fi
}
for fixed_tool in ${xcrun_path} ${shasum_path} ${awk_path} ${file_path} \
    ${stat_path} ${mktemp_path} ${chmod_path} ${mkdir_path} ${rm_path} ${mv_path} \
    ${readlink_path} ${env_path}; do
  require_root_system_tool ${fixed_tool}
done

xcrun() { ${xcrun_path} "$@"; }
shasum() { ${env_path} -i PATH=${PATH} ${shasum_path} "$@"; }
awk() { ${awk_path} "$@"; }
file() { ${file_path} "$@"; }
stat() { ${stat_path} "$@"; }
mktemp() { ${mktemp_path} "$@"; }
chmod() { ${chmod_path} "$@"; }
mkdir() { ${mkdir_path} "$@"; }
rm() { ${rm_path} "$@"; }
mv() { ${mv_path} "$@"; }
readlink() { ${readlink_path} "$@"; }

tool_path_self_test=0
if (( $# == 1 )) && [[ $1 == --tool-path-self-test ]]; then
  tool_path_self_test=1
fi

script_dir=${0:A:h}
repo_root=${script_dir:h}
final_output_root=${repo_root}/KeepVaultMac/Native
reference_dir=${repo_root}/external/ML-DSA-reference
native_source_manifest=${repo_root}/external/NATIVE_SOURCE_SHA256SUMS
native_vendor_paths=()
cc=$(xcrun --find clang)
# Xcode's clang++ pathname is a symlink. Use the reviewed physical clang
# binary directly; every C++ invocation below names .cpp inputs or -std=c++17,
# so the driver selects C++ without following that alias.
cxx=${cc}
cxx_driver_flags=(--driver-mode=g++)
sdk_root=$(${readlink_path} -f "$(xcrun --sdk macosx --show-sdk-path)")
require_root_system_tool ${cc}
if [[ ! -d ${sdk_root} || -L ${sdk_root} \
    || $(${stat_path} -f %u -- ${sdk_root}) != 0 ]]; then
  print -u2 'The selected macOS SDK is not a root-owned physical directory.'
  exit 1
fi
if (( tool_path_self_test )); then
  print 'native_tool_paths=verified'
  exit 0
fi

verify_native_vendor_sources() {
  if [[ ! -f ${native_source_manifest} || -L ${native_source_manifest} ]]; then
    print -u2 'The reviewed native-source SHA-256 manifest is missing or is a symbolic link.'
    exit 1
  fi

  local expected=''
  local relative_path=''
  local source_file=''
  local actual=''
  local entry_count=0
  while read -r expected relative_path; do
    [[ -z ${expected:-} ]] && continue
    if [[ ! ${expected} =~ '^[0-9A-F]{64}$' \
        || ${relative_path} != external/* \
        || ${relative_path} == *'..'* \
        || ${relative_path} == /* ]]; then
      print -u2 "Invalid native-source manifest entry: ${expected} ${relative_path}"
      exit 1
    fi

    source_file=${repo_root}/${relative_path}
    if [[ ! -f ${source_file} || -L ${source_file} ]]; then
      print -u2 "Pinned native vendor source is missing or is a symbolic link: ${relative_path}"
      exit 1
    fi

    actual=$(shasum -a 256 -- ${source_file} | awk '{print toupper($1)}')
    if [[ ${actual} != ${expected} ]]; then
      print -u2 "Pinned native vendor SHA-256 mismatch: ${relative_path}"
      exit 1
    fi

    native_vendor_paths+=(${relative_path})
    (( entry_count += 1 ))
  done < ${native_source_manifest}

  if (( entry_count == 0 )); then
    print -u2 'The reviewed native-source SHA-256 manifest is empty.'
    exit 1
  fi
}

compile_rename_swap_helper() {
  local helper_path=$1
  # Build for the host that must execute the helper. The output tree itself is
  # still arm64+x86_64 below; forcing this tiny tool to arm64 would make the
  # universal build impossible to run on a supported Intel Mac.
  ${cc} -isysroot ${sdk_root} -mmacosx-version-min=14.0 \
    -O2 -x c - -o ${helper_path} <<'EOF'
#include <fcntl.h>
#include <sys/stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc != 3) return 64;
  return renameatx_np(AT_FDCWD, argv[1], AT_FDCWD, argv[2], RENAME_SWAP);
}
EOF
}

publish_native_tree() {
  local current_tree=$1
  local staged_tree=$2
  local helper_directory=$3
  local inject_pre_publish_failure=${4:-0}

  # This hook is an argument to the helper rather than an ambient environment
  # variable, so production builds cannot accidentally inherit it. The
  # executable self-test below uses it to prove that all staging work remains
  # invisible if the last pre-publish step fails.
  if [[ ${inject_pre_publish_failure} == 1 ]]; then
    return 86
  fi

  if [[ -e ${current_tree} ]]; then
    local swap_helper=${helper_directory}/rename-swap
    if [[ ! -x ${swap_helper} ]]; then
      compile_rename_swap_helper ${swap_helper}
    fi
    ${swap_helper} ${current_tree} ${staged_tree}
  else
    mv -- ${staged_tree} ${current_tree}
  fi
}

run_atomic_publish_self_test() {
  local self_test_root=$1
  local current_tree=${self_test_root}/Native
  local staged_tree=${self_test_root}/stage/Native
  local outside_hard_link=${self_test_root}/old-hard-link
  mkdir -p -- ${current_tree} ${staged_tree}

  print -rn -- 'old-a' > ${current_tree}/a
  print -rn -- 'old-only' > ${current_tree}/only-old
  ln ${current_tree}/a ${outside_hard_link}
  local original_inode=$(stat -f %i ${current_tree}/a)
  [[ $(stat -f %l ${current_tree}/a) == 2 ]]

  print -rn -- 'new-a' > ${staged_tree}/a
  print -rn -- 'new-only' > ${staged_tree}/only-new
  for staged_artifact in ${staged_tree}/*(N); do
    [[ -f ${staged_artifact} && ! -L ${staged_artifact} \
        && $(stat -f %l ${staged_artifact}) == 1 ]]
  done

  if publish_native_tree ${current_tree} ${staged_tree} ${self_test_root} 1; then
    print -u2 'Atomic native publish self-test did not inject the requested pre-publish failure.'
    return 1
  fi
  [[ $(<${current_tree}/a) == 'old-a' \
      && $(<${current_tree}/only-old) == 'old-only' \
      && ! -e ${current_tree}/only-new \
      && $(stat -f %i ${current_tree}/a) == ${original_inode} \
      && $(stat -f %i ${outside_hard_link}) == ${original_inode} \
      && $(<${outside_hard_link}) == 'old-a' \
      && $(<${staged_tree}/a) == 'new-a' \
      && $(<${staged_tree}/only-new) == 'new-only' ]] || {
    print -u2 'A pre-publish failure changed the old native target or exposed a partial staged tree.'
    return 1
  }

  publish_native_tree ${current_tree} ${staged_tree} ${self_test_root} 0
  [[ $(<${current_tree}/a) == 'new-a' \
      && $(<${current_tree}/only-new) == 'new-only' \
      && ! -e ${current_tree}/only-old \
      && $(<${staged_tree}/a) == 'old-a' \
      && $(<${staged_tree}/only-old) == 'old-only' \
      && ! -e ${staged_tree}/only-new \
      && $(stat -f %i ${staged_tree}/a) == ${original_inode} \
      && $(stat -f %i ${outside_hard_link}) == ${original_inode} \
      && $(<${outside_hard_link}) == 'old-a' ]] || {
    print -u2 'Atomic native publish self-test observed a partial exchange or a followed old hard link.'
    return 1
  }

  print 'atomic_publish_pre_publish_failure_preserved_old_tree=true'
  print 'atomic_publish_hard_link_not_followed=true'
  print 'atomic_publish_exchange_complete=true'
}

if (( $# > 0 )); then
  if [[ $# != 1 || ( $1 != --self-test-atomic-publish && $1 != --verify-sources ) ]]; then
    print -u2 'Usage: Build-Native-macOS.sh [--self-test-atomic-publish|--verify-sources]'
    exit 64
  fi
  if [[ $1 == --verify-sources ]]; then
    verify_native_vendor_sources
    print "native_source_manifest=verified (${#native_vendor_paths} files)"
    exit 0
  fi
  atomic_self_test_root=$(mktemp -d "${TMPDIR:-/tmp}/keep-vault-native-publish-selftest.XXXXXXXX")
  cleanup_atomic_self_test() {
    if [[ -n ${atomic_self_test_root:-} && -d ${atomic_self_test_root} \
        && ${atomic_self_test_root} == ${TMPDIR:-/tmp}/keep-vault-native-publish-selftest.* ]]; then
      rm -rf -- ${atomic_self_test_root}
    fi
  }
  trap cleanup_atomic_self_test EXIT INT TERM
  run_atomic_publish_self_test ${atomic_self_test_root}
  exit 0
fi

if [[ -L ${repo_root} || -L ${final_output_root:h} || -L ${final_output_root} ]]; then
  print -u2 "Refusing to build through a symbolic-link workspace path."
  exit 1
fi

verify_native_vendor_sources

# Compile into a private sibling tree. Writing directly into tracked Native/
# follows any prepared hard link and leaves a mixture of old and new slices if
# one later compiler invocation fails. The complete, validated tree is swapped
# into place only after both thin builds and every universal artifact exist.
native_build_root=$(mktemp -d "${repo_root}/KeepVaultMac/.native-build.XXXXXXXX")
output_root=${native_build_root}/Native
mkdir -p -- ${output_root}
cleanup_native_build() {
  if [[ -n ${native_build_root:-} && -d ${native_build_root} \
      && ${native_build_root} == ${repo_root}/KeepVaultMac/.native-build.* ]]; then
    rm -rf -- ${native_build_root}
  fi
}
trap cleanup_native_build EXIT INT TERM

expected_commit='d35ba3fe5449bee3e6d43e1f296c3ca818bd36be'
actual_commit=$(<${reference_dir}/PINNED_COMMIT.txt)
actual_commit=${actual_commit//$'\r'/}
actual_commit=${actual_commit//$'\n'/}
if [[ ${actual_commit} != ${expected_commit} ]]; then
  print -u2 "The ML-DSA reference commit pin is not the reviewed source revision."
  exit 1
fi

while read -r expected relative_path; do
  [[ -z ${expected:-} ]] && continue
  source_file=${reference_dir}/${relative_path}
  if [[ ! -f ${source_file} || -L ${source_file} ]]; then
    print -u2 "Pinned ML-DSA source is missing or is a symbolic link: ${relative_path}"
    exit 1
  fi
  actual=$(shasum -a 256 -- "${source_file}" | awk '{print toupper($1)}')
  if [[ ${actual} != ${expected} ]]; then
    print -u2 "Pinned ML-DSA SHA-256 mismatch: ${relative_path}"
    exit 1
  fi
done < ${reference_dir}/SOURCE_SHA256SUMS

link_flags=(
  -Wl,-dead_strip
  -Wl,-fatal_warnings
)

mldsa_sources=(
  sign.c
  packing.c
  polyvec.c
  poly.c
  ntt.c
  reduce.c
  rounding.c
  symmetric-shake.c
  fips202.c
)
mldsa_paths=()
for source_name in ${mldsa_sources[@]}; do
  mldsa_paths+=(${reference_dir}/ref/${source_name})
done

argon_root=${repo_root}/external/phc-winner-argon2
argon_sources=(
  ${argon_root}/src/argon2.c
  ${argon_root}/src/core.c
  ${argon_root}/src/encoding.c
  ${argon_root}/src/ref.c
  ${argon_root}/src/thread.c
  ${argon_root}/src/blake2/blake2b.c
)
argon_includes=(
  -I${argon_root}/include
  -I${argon_root}/src
  -I${argon_root}/src/blake2
)

build_architecture() {
  local architecture=$1
  local runtime=$2
  local output_dir=${output_root}/${runtime}
  local common_flags=(
    -arch
    ${architecture}
    -O2
    -DNDEBUG
    -fstack-protector-strong
    -fvisibility=hidden
    -fno-common
    -isysroot
    ${sdk_root}
    -mmacosx-version-min=14.0
    -Wall
    -Wextra
    -Wpedantic
  )

  mkdir -p -- ${output_dir}

  # Crypto++ is compiled once per architecture into a static archive rather
  # than listed file by file next to each adapter.
  #
  # Its algorithm sources cannot be cherry-picked: rijndael.cpp and its
  # siblings reach cryptlib, misc, secblock, algparam and from there the whole
  # integer machinery, so a hand-picked subset does not link and would have to
  # be re-picked at every update. The whole library takes about ten seconds per
  # architecture, which is less than the time spent discovering that a shorter
  # list is incomplete.
  local cryptopp_dir=${repo_root}/external/cryptopp
  # Must be identical for the archive and for every adapter compiled against
  # it: the headers branch on these, so a mismatch would give the two sides
  # different class layouts.
  #
  # CRYPTOPP_DISABLE_ASM used to be set here, which cost AES-256 the crypto
  # instructions every Mac this ships to has had since the first Apple silicon
  # and every x86 Mac since Westmere. The Windows build never disabled them.
  local cryptopp_flags=(-std=c++17)
  local cryptopp_objects=${output_dir}/cryptopp-objects
  local cryptopp_archive=${output_dir}/libcryptopp.a
  rm -rf -- ${cryptopp_objects}
  mkdir -p -- ${cryptopp_objects}

  local cryptopp_sources=()
  local simd_sources=()
  local manifest_cryptopp_sources=()
  local disk_cryptopp_sources=(${cryptopp_dir}/*.cpp(N:t))
  local relative_path
  local candidate
  for relative_path in ${native_vendor_paths[@]}; do
    if [[ ${relative_path:h} == external/cryptopp && ${relative_path:e} == cpp ]]; then
      manifest_cryptopp_sources+=(${relative_path:t})
    fi
  done

  if [[ ${(F)${(on)manifest_cryptopp_sources}} != ${(F)${(on)disk_cryptopp_sources}} ]]; then
    print -u2 'Crypto++ source inventory differs from the reviewed native-source manifest.'
    exit 1
  fi

  # Compile only the reviewed manifest inventory. A newly dropped .cpp file
  # cannot silently enter the native artifacts through a filesystem wildcard.
  for candidate in ${manifest_cryptopp_sources[@]}; do
    # The validation, benchmark and self-test drivers ship in the same
    # directory as the library and pull in a main().
    case ${candidate} in
      test.cpp|bench1.cpp|bench2.cpp|bench3.cpp|datatest.cpp|dlltest.cpp|fipsalgt.cpp|adhoc.cpp)
        continue
        ;;
      regtest*.cpp|validat*.cpp)
        continue
        ;;
      # Compiled below, each with the one instruction-set flag its own
      # intrinsics need. Upstream gives every one of these its own makefile
      # rule; the suffixes are its naming, not a guess.
      *_simd.cpp|*_avx.cpp|*_sse.cpp|darn.cpp)
        simd_sources+=(${candidate})
        continue
        ;;
    esac
    cryptopp_sources+=(${candidate})
  done

  if (( ${#cryptopp_sources} == 0 )); then
    print -u2 'No Crypto++ sources were found; external/cryptopp is missing or empty.'
    exit 1
  fi

  print -r -- ${(F)cryptopp_sources} \
    | xargs -P 10 -I{} ${cxx} ${cxx_driver_flags[@]} ${common_flags[@]} ${cryptopp_flags[@]} -c \
        -I${cryptopp_dir} -o ${cryptopp_objects}/{}.o ${cryptopp_dir}/{}

  # One flag set per file, copied from the rules in Crypto++'s own GNUmakefile.
  #
  # The flag goes only on the translation unit whose intrinsics need it, which
  # is the whole reason upstream separates these files: give -maes to a unit
  # whose run-time guard only tested for SSE2 and the compiler may put an AES
  # instruction on a path that machine never proved it could run. Whether a
  # path is taken is decided at run time by cpu.cpp from CPUID or the ARM
  # feature registers, so a slice built this way still runs where the extension
  # is absent - it just takes the portable code there.
  #
  # A file whose flag is empty compiles to nothing on this architecture: its
  # contents sit behind an #if for the other one.
  local -A simd_flags
  if [[ ${architecture} == arm64 ]]; then
    simd_flags=(
      rijndael_simd.cpp '-march=armv8-a+crypto'
      sha_simd.cpp      '-march=armv8-a+crypto'
      shacal2_simd.cpp  '-march=armv8-a+crypto'
      gcm_simd.cpp      '-march=armv8-a+crypto'
      gf2n_simd.cpp     '-march=armv8-a+crypto'
      crc_simd.cpp      '-march=armv8-a+crc'
      sm4_simd.cpp      '-march=armv8-a'
      neon_simd.cpp     '-march=armv8-a'
      chacha_simd.cpp   '-march=armv8-a'
      blake2b_simd.cpp  '-march=armv8-a'
      blake2s_simd.cpp  '-march=armv8-a'
      cham_simd.cpp     '-march=armv8-a'
      lea_simd.cpp      '-march=armv8-a'
      keccak_simd.cpp   '-march=armv8-a'
      simon128_simd.cpp '-march=armv8-a'
      speck128_simd.cpp '-march=armv8-a'
      sse_simd.cpp      ''
      ppc_simd.cpp      ''
      donna_sse.cpp     ''
      chacha_avx.cpp    ''
      lsh256_sse.cpp    ''
      lsh256_avx.cpp    ''
      lsh512_sse.cpp    ''
      lsh512_avx.cpp    ''
      darn.cpp          ''
    )
  else
    simd_flags=(
      rijndael_simd.cpp '-msse4.1 -maes'
      sha_simd.cpp      '-msse4.2 -msha'
      shacal2_simd.cpp  '-msse4.2 -msha'
      gcm_simd.cpp      '-mssse3 -mpclmul'
      gf2n_simd.cpp     '-mpclmul'
      crc_simd.cpp      '-msse4.2'
      sm4_simd.cpp      '-mssse3 -maes'
      chacha_simd.cpp   '-msse2'
      blake2b_simd.cpp  '-msse4.1'
      blake2s_simd.cpp  '-msse4.1'
      cham_simd.cpp     '-mssse3'
      lea_simd.cpp      '-mssse3'
      keccak_simd.cpp   '-mssse3'
      simon128_simd.cpp '-mssse3'
      speck128_simd.cpp '-mssse3'
      sse_simd.cpp      '-msse2'
      donna_sse.cpp     '-msse2'
      chacha_avx.cpp    '-mavx2'
      lsh256_sse.cpp    '-mssse3'
      lsh256_avx.cpp    '-mavx2'
      lsh512_sse.cpp    '-mssse3'
      lsh512_avx.cpp    '-mavx2'
      neon_simd.cpp     ''
      ppc_simd.cpp      ''
      darn.cpp          ''
    )
  fi

  local simd_source
  for simd_source in ${simd_sources[@]}; do
    if [[ -z ${simd_flags[${simd_source}]+set} ]]; then
      print -u2 "Crypto++ has an instruction-set source this build has no flag for: ${simd_source}"
      exit 1
    fi

    ${cxx} ${cxx_driver_flags[@]} ${common_flags[@]} ${cryptopp_flags[@]} ${=simd_flags[${simd_source}]} -c \
      -I${cryptopp_dir} -o ${cryptopp_objects}/${simd_source}.o ${cryptopp_dir}/${simd_source}
  done

  xcrun ar rcs ${cryptopp_archive} ${cryptopp_objects}/*.o
  rm -rf -- ${cryptopp_objects}

  ${cxx} ${cxx_driver_flags[@]} ${common_flags[@]} ${cryptopp_flags[@]} -dynamiclib -pthread \
    -install_name @rpath/libmars_ref.dylib \
    -o ${output_dir}/libmars_ref.dylib \
    -I${cryptopp_dir} \
    ${repo_root}/native/mars_ref_export.cpp \
    ${cryptopp_archive} \
    ${link_flags[@]}

  ${cxx} ${cxx_driver_flags[@]} ${common_flags[@]} ${cryptopp_flags[@]} -dynamiclib -pthread \
    -install_name @rpath/libaes_ref.dylib \
    -o ${output_dir}/libaes_ref.dylib \
    -I${cryptopp_dir} \
    ${repo_root}/native/aes_ref_export.cpp \
    ${cryptopp_archive} \
    ${link_flags[@]}

  ${cxx} ${cxx_driver_flags[@]} ${common_flags[@]} ${cryptopp_flags[@]} -dynamiclib -pthread \
    -install_name @rpath/libchachapoly_ref.dylib \
    -o ${output_dir}/libchachapoly_ref.dylib \
    -I${cryptopp_dir} \
    ${repo_root}/native/chachapoly_ref_export.cpp \
    ${cryptopp_archive} \
    ${link_flags[@]}

  ${cxx} ${cxx_driver_flags[@]} ${common_flags[@]} ${cryptopp_flags[@]} -dynamiclib -pthread \
    -install_name @rpath/libshacal2_ref.dylib \
    -o ${output_dir}/libshacal2_ref.dylib \
    -I${cryptopp_dir} \
    ${repo_root}/native/shacal2_ref_export.cpp \
    ${cryptopp_archive} \
    ${link_flags[@]}

  ${cxx} ${cxx_driver_flags[@]} ${common_flags[@]} -DNOJIT -DBSD -fPIE -pthread \
    -o ${output_dir}/zpaq \
    ${repo_root}/external/zpaq/zpaq.cpp \
    ${repo_root}/external/zpaq/libzpaq.cpp \
    -framework CoreFoundation \
    -Wl,-pie ${link_flags[@]}

  # v12 uses only Crypto++'s Boost-licensed Kalyna implementation. The old
  # unlicensed reference source and its derived table path are intentionally
  # absent from both this build and the repository.
  ${cxx} ${cxx_driver_flags[@]} ${common_flags[@]} ${cryptopp_flags[@]} -dynamiclib -pthread \
    -install_name @rpath/libkalyna_v12.dylib \
    -Wl,-exported_symbol,_keepvault_v12_kalyna_512_512_ctr_xcrypt \
    -Wl,-exported_symbol,_keepvault_v12_kalyna_512_512_ctr_xcrypt_scalar \
    -Wl,-exported_symbol,_keepvault_v12_kalyna_join_failure_kat \
    -o ${output_dir}/libkalyna_v12.dylib \
    -I${cryptopp_dir} \
    ${repo_root}/native/kalyna_v12_export.cpp \
    ${cryptopp_archive} \
    ${link_flags[@]}

  ${cc} ${common_flags[@]} -dynamiclib -pthread \
    -install_name @rpath/libthreefish_ref.dylib \
    -o ${output_dir}/libthreefish_ref.dylib \
    ${repo_root}/native/threefish_ref_export.c \
    ${repo_root}/external/Skein-reference/NIST/CD/Reference_Implementation/skein.c \
    ${repo_root}/external/Skein-reference/NIST/CD/Reference_Implementation/skein_block.c \
    ${link_flags[@]}

  # SHA3-512 reference, for differential testing against the Bouncy Castle
  # implementation the app uses in production. Verification aid only; it is
  # never placed in the shipped bundle.
  ${cc} ${common_flags[@]} -dynamiclib \
    -I${reference_dir}/ref \
    -install_name @rpath/libsha3_ref.dylib \
    -o ${output_dir}/libsha3_ref.dylib \
    ${repo_root}/native/sha3_ref_export.c \
    ${reference_dir}/ref/fips202.c \
    ${link_flags[@]}

  ${cc} ${common_flags[@]} -dynamiclib -DDILITHIUM_MODE=5 \
    -I${reference_dir}/ref \
    -install_name @rpath/libmldsa87_ref.dylib \
    -o ${output_dir}/libmldsa87_ref.dylib \
    ${repo_root}/native/mldsa87_ref_export.c \
    ${mldsa_paths[@]} \
    -framework Security \
    ${link_flags[@]}

  ${cc} ${common_flags[@]} -dynamiclib -pthread \
    ${argon_includes[@]} \
    -install_name @rpath/libargon2_ref.dylib \
    -o ${output_dir}/libargon2_ref.dylib \
    ${repo_root}/native/argon2_ref_export.c \
    ${argon_sources[@]} \
    ${link_flags[@]}

  ${cc} ${common_flags[@]} -fPIE -pthread \
    ${argon_includes[@]} \
    -o ${output_dir}/argon2 \
    ${argon_root}/src/run.c \
    ${argon_sources[@]} \
    -Wl,-pie ${link_flags[@]}

  chmod 0755 ${output_dir}/zpaq ${output_dir}/argon2 ${output_dir}/*.dylib
  for artifact in ${output_dir}/zpaq ${output_dir}/argon2 ${output_dir}/*.dylib; do
    if [[ ! -f ${artifact} || -L ${artifact} || $(stat -f %l ${artifact}) != 1 ]]; then
      print -u2 "Native build did not produce a regular single-link file: ${artifact}"
      exit 1
    fi
    xcrun lipo ${artifact} -verify_arch ${architecture}
    file -- ${artifact}
  done
}

build_architecture arm64 osx-arm64
build_architecture x86_64 osx-x64

universal_dir=${output_root}/osx-universal
mkdir -p -- ${universal_dir}
artifacts=(zpaq argon2 libaes_ref.dylib libargon2_ref.dylib libchachapoly_ref.dylib libkalyna_v12.dylib libmars_ref.dylib libmldsa87_ref.dylib libshacal2_ref.dylib libsha3_ref.dylib libthreefish_ref.dylib)
for artifact_name in ${artifacts[@]}; do
  xcrun lipo -create \
    ${output_root}/osx-arm64/${artifact_name} \
    ${output_root}/osx-x64/${artifact_name} \
    -output ${universal_dir}/${artifact_name}
  chmod 0755 ${universal_dir}/${artifact_name}
  xcrun lipo ${universal_dir}/${artifact_name} -verify_arch arm64 x86_64
  file -- ${universal_dir}/${artifact_name}
done

for runtime in osx-arm64 osx-x64 osx-universal; do
  runtime_dir=${output_root}/${runtime}
  if [[ ! -d ${runtime_dir} || -L ${runtime_dir} ]]; then
    print -u2 "Native staging directory is missing or is a symbolic link: ${runtime_dir}"
    exit 1
  fi
  for artifact in ${runtime_dir}/*(N); do
    if [[ ! -f ${artifact} || -L ${artifact} || $(stat -f %l ${artifact}) != 1 ]]; then
      print -u2 "Native staging artifact is not a regular single-link file: ${artifact}"
      exit 1
    fi
  done
done

# renameatx_np(RENAME_SWAP) is an atomic exchange on the same macOS volume. A
# failed or interrupted compile never touched Native/, and a process crash just
# after this exchange leaves the previous complete tree in .native-build.* for
# manual recovery rather than leaving half a build installed.
if [[ -e ${final_output_root} ]]; then
  publish_native_tree ${final_output_root} ${output_root} ${native_build_root} 0 || {
    print -u2 'Atomic native-output directory exchange failed; the previous Native tree remains untouched.'
    exit 1
  }
else
  publish_native_tree ${final_output_root} ${output_root} ${native_build_root} 0
fi

for runtime in osx-arm64 osx-x64 osx-universal; do
  if [[ ! -d ${final_output_root}/${runtime} || -L ${final_output_root}/${runtime} ]]; then
    print -u2 "Published native directory is invalid: ${final_output_root}/${runtime}"
    exit 1
  fi
  for artifact in ${final_output_root}/${runtime}/*(N); do
    if [[ ! -f ${artifact} || -L ${artifact} || $(stat -f %l ${artifact}) != 1 ]]; then
      print -u2 "Published native artifact is not a regular single-link file: ${artifact}"
      exit 1
    fi
  done
done

print "macOS native builds complete: osx-arm64, osx-x64, and osx-universal"
