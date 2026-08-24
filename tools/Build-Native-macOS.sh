#!/bin/zsh
set -euo pipefail

script_dir=${0:A:h}
repo_root=${script_dir:h}
output_root=${repo_root}/KeepVaultMac/Native
reference_dir=${repo_root}/external/ML-DSA-reference

if [[ -L ${repo_root} || -L ${output_root:h} ]]; then
  print -u2 "Refusing to build through a symbolic-link workspace path."
  exit 1
fi

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

cc=$(xcrun --find clang)
cxx=$(xcrun --find clang++)
sdk_root=$(xcrun --sdk macosx --show-sdk-path)
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
  local candidate
  for candidate in ${cryptopp_dir}/*.cpp(N:t); do
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
    | xargs -P 10 -I{} ${cxx} ${common_flags[@]} ${cryptopp_flags[@]} -c \
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

    ${cxx} ${common_flags[@]} ${cryptopp_flags[@]} ${=simd_flags[${simd_source}]} -c \
      -I${cryptopp_dir} -o ${cryptopp_objects}/${simd_source}.o ${cryptopp_dir}/${simd_source}
  done

  xcrun ar rcs ${cryptopp_archive} ${cryptopp_objects}/*.o
  rm -rf -- ${cryptopp_objects}

  ${cxx} ${common_flags[@]} ${cryptopp_flags[@]} -dynamiclib -pthread \
    -install_name @rpath/libmars_ref.dylib \
    -o ${output_dir}/libmars_ref.dylib \
    -I${cryptopp_dir} \
    ${repo_root}/native/mars_ref_export.cpp \
    ${cryptopp_archive} \
    ${link_flags[@]}

  ${cxx} ${common_flags[@]} ${cryptopp_flags[@]} -dynamiclib -pthread \
    -install_name @rpath/libaes_ref.dylib \
    -o ${output_dir}/libaes_ref.dylib \
    -I${cryptopp_dir} \
    ${repo_root}/native/aes_ref_export.cpp \
    ${cryptopp_archive} \
    ${link_flags[@]}

  ${cxx} ${common_flags[@]} ${cryptopp_flags[@]} -dynamiclib -pthread \
    -install_name @rpath/libchachapoly_ref.dylib \
    -o ${output_dir}/libchachapoly_ref.dylib \
    -I${cryptopp_dir} \
    ${repo_root}/native/chachapoly_ref_export.cpp \
    ${cryptopp_archive} \
    ${link_flags[@]}

  ${cxx} ${common_flags[@]} ${cryptopp_flags[@]} -dynamiclib -pthread \
    -install_name @rpath/libshacal2_ref.dylib \
    -o ${output_dir}/libshacal2_ref.dylib \
    -I${cryptopp_dir} \
    ${repo_root}/native/shacal2_ref_export.cpp \
    ${cryptopp_archive} \
    ${link_flags[@]}

  ${cxx} ${common_flags[@]} -DNOJIT -DBSD -fPIE -pthread \
    -o ${output_dir}/zpaq \
    ${repo_root}/external/zpaq/zpaq.cpp \
    ${repo_root}/external/zpaq/libzpaq.cpp \
    -Wl,-pie ${link_flags[@]}

  # kalyna_fast.c carries the table-driven encryption; the reference stays
  # linked in and verifies it at start-up before it may be used.
  ${cc} ${common_flags[@]} -dynamiclib -pthread \
    -install_name @rpath/libkalyna_ref.dylib \
    -o ${output_dir}/libkalyna_ref.dylib \
    ${repo_root}/native/kalyna_ref_export.c \
    ${repo_root}/native/kalyna_fast.c \
    ${repo_root}/external/Kalyna-reference/kalyna.c \
    ${repo_root}/external/Kalyna-reference/tables.c \
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
    if [[ -L ${artifact} ]]; then
      print -u2 "Native build unexpectedly produced a symbolic link: ${artifact}"
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
artifacts=(zpaq argon2 libaes_ref.dylib libargon2_ref.dylib libchachapoly_ref.dylib libkalyna_ref.dylib libmars_ref.dylib libmldsa87_ref.dylib libshacal2_ref.dylib libsha3_ref.dylib libthreefish_ref.dylib)
for artifact_name in ${artifacts[@]}; do
  xcrun lipo -create \
    ${output_root}/osx-arm64/${artifact_name} \
    ${output_root}/osx-x64/${artifact_name} \
    -output ${universal_dir}/${artifact_name}
  chmod 0755 ${universal_dir}/${artifact_name}
  xcrun lipo ${universal_dir}/${artifact_name} -verify_arch arm64 x86_64
  file -- ${universal_dir}/${artifact_name}
done

print "macOS native builds complete: osx-arm64, osx-x64, and osx-universal"
