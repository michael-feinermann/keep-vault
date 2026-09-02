#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MLDSA87_PUBLIC_KEY_BYTES 2592U
#define MLDSA87_PRIVATE_KEY_BYTES 4896U
#define MLDSA87_SIGNATURE_BYTES 4627U

typedef int (*kalyna_ctr_fn)(
    const uint8_t[64],
    const uint8_t[64],
    const uint8_t*,
    uint8_t*,
    size_t);
typedef int (*no_argument_kat_fn)(void);
typedef int (*threefish_block_fn)(
    const uint8_t[128],
    const uint8_t[16],
    const uint8_t[128],
    uint8_t[128]);
typedef int (*skein_hash_fn)(const uint8_t*, size_t, uint8_t[128]);
typedef int (*block_cipher_fn)(const uint8_t*, size_t, const uint8_t*, uint8_t*);
typedef int (*ctr_cipher_fn)(const uint8_t*, const uint8_t*, const uint8_t*, uint8_t*, size_t);
typedef int (*aes_provider_fn)(void);
typedef int (*chacha20_fn)(
    const uint8_t[32],
    const uint8_t[12],
    uint32_t,
    const uint8_t*,
    uint8_t*,
    size_t);
typedef int (*chachapoly_encrypt_fn)(
    const uint8_t[32],
    const uint8_t[12],
    const uint8_t*,
    size_t,
    const uint8_t*,
    uint8_t*,
    size_t,
    uint8_t[16]);
typedef int (*mldsa_keypair_fn)(uint8_t*, size_t, uint8_t*, size_t);
typedef int (*mldsa_sign_fn)(
    uint8_t*,
    size_t,
    size_t*,
    const uint8_t*,
    size_t,
    const uint8_t*,
    size_t,
    const uint8_t*,
    size_t);
typedef int (*mldsa_verify_fn)(
    const uint8_t*,
    size_t,
    const uint8_t*,
    size_t,
    const uint8_t*,
    size_t,
    const uint8_t*,
    size_t);
typedef const char* (*mldsa_commit_fn)(void);
typedef int (*argon2_hash_fn)(
    uint32_t,
    uint32_t,
    uint32_t,
    uint8_t*,
    uint32_t,
    uint8_t*,
    uint32_t,
    uint8_t*,
    uint32_t);

_Noreturn static void fail(const char* message)
{
    fprintf(stderr, "Native KAT failed: %s\n", message);
    exit(1);
}

static void secure_zero(void* pointer, size_t length)
{
    (void)memset_s(pointer, length, 0, length);
}

static void require_equal(
    const uint8_t* expected,
    const uint8_t* actual,
    size_t length,
    const char* message)
{
    uint8_t difference = 0;
    for (size_t index = 0; index < length; ++index) {
        difference |= (uint8_t)(expected[index] ^ actual[index]);
    }
    if (difference != 0) {
        fail(message);
    }
}

static uint8_t hex_nibble(char value)
{
    if (value >= '0' && value <= '9') {
        return (uint8_t)(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return (uint8_t)(value - 'a' + 10);
    }
    if (value >= 'A' && value <= 'F') {
        return (uint8_t)(value - 'A' + 10);
    }
    fail("an embedded hexadecimal vector is malformed");
}

static void decode_hex(const char* encoded, uint8_t* output, size_t output_length)
{
    if (strlen(encoded) != output_length * 2U) {
        fail("an embedded hexadecimal vector has the wrong length");
    }
    for (size_t index = 0; index < output_length; ++index) {
        output[index] = (uint8_t)((hex_nibble(encoded[index * 2U]) << 4U)
            | hex_nibble(encoded[index * 2U + 1U]));
    }
}

static void* open_library(const char* directory, const char* name)
{
    size_t required = strlen(directory) + strlen(name) + 2U;
    char* path = calloc(required, 1U);
    if (path == NULL) {
        fail("memory allocation failed while resolving a KAT library");
    }
    int written = snprintf(path, required, "%s/%s", directory, name);
    if (written < 0 || (size_t)written >= required) {
        free(path);
        fail("a KAT library path is too long");
    }
    void* handle = dlopen(path, RTLD_LOCAL | RTLD_NOW);
    if (handle == NULL) {
        fprintf(stderr, "Native KAT could not load %s: %s\n", path, dlerror());
        free(path);
        exit(1);
    }
    free(path);
    return handle;
}

static void load_symbol(void* handle, const char* name, void* destination, size_t destination_size)
{
    void* symbol = dlsym(handle, name);
    if (symbol == NULL || destination_size != sizeof(symbol)) {
        fprintf(stderr, "Native KAT could not resolve %s: %s\n", name, dlerror());
        exit(1);
    }
    memcpy(destination, &symbol, sizeof(symbol));
}

static void run_kalyna_kat(const char* directory)
{
    static const uint64_t expected_words[8] = {
        UINT64_C(0x6a351c811be3264a), UINT64_C(0x1a239605cad61da6),
        UINT64_C(0xa1f347aa5483ba67), UINT64_C(0xb856eb20c3ee1d3e),
        UINT64_C(0x66ab5b1717f4d095), UINT64_C(0x6cc815bb34f1d62f),
        UINT64_C(0xb7fe6e85266a90cb), UINT64_C(0xd9d90d947264bcc5),
    };
    uint8_t key[64];
    uint8_t nonce[64];
    uint8_t input[64] = {0};
    uint8_t output[64] = {0};
    for (size_t index = 0; index < sizeof(key); ++index) {
        key[index] = (uint8_t)index;
        nonce[index] = (uint8_t)(index + 0x40U);
    }

    void* handle = open_library(directory, "libkalyna_v12.dylib");
    kalyna_ctr_fn xcrypt = NULL;
    no_argument_kat_fn join_failure_kat = NULL;
    load_symbol(handle, "keepvault_v12_kalyna_512_512_ctr_xcrypt", &xcrypt, sizeof(xcrypt));
    load_symbol(
        handle,
        "keepvault_v12_kalyna_join_failure_kat",
        &join_failure_kat,
        sizeof(join_failure_kat));
    if (xcrypt(key, nonce, input, output, sizeof(output)) != 0) {
        fail("Kalyna-512/512 CTR adapter returned an error");
    }
    require_equal(
        (const uint8_t*)expected_words,
        output,
        sizeof(output),
        "Kalyna-512/512 official CTR vector mismatch");
    if (join_failure_kat() != 0) {
        fail("Kalyna worker join-failure handling KAT failed");
    }
    secure_zero(key, sizeof(key));
    secure_zero(nonce, sizeof(nonce));
    secure_zero(output, sizeof(output));
    if (dlclose(handle) != 0) {
        fail("Kalyna KAT library could not be closed");
    }
}

static void run_threefish_and_skein_kats(const char* directory)
{
    static const uint64_t expected_threefish_words[16] = {
        UINT64_C(0x04B3053D0A3D5CF0), UINT64_C(0x0136E0D1C7DD85F7),
        UINT64_C(0x067B212F6EA78A5C), UINT64_C(0x0DA9C10B4C54E1C6),
        UINT64_C(0x0F4EC27394CBACF0), UINT64_C(0x32437F0568EA4FD5),
        UINT64_C(0xCFF56D1D7654B49C), UINT64_C(0xA2D5FB14369B2E7B),
        UINT64_C(0x540306B460472E0B), UINT64_C(0x71C18254BCEA820D),
        UINT64_C(0xC36B4068BEAF32C8), UINT64_C(0xFA4329597A360095),
        UINT64_C(0xC4A36C28434A5B9A), UINT64_C(0xD54331444B1046CF),
        UINT64_C(0xDF11834830B2A460), UINT64_C(0x1E39E8DFE1F7EE4F),
    };
    static const char expected_skein_hex[] =
        "E62C05802EA0152407CDD8787FDA9E35703DE862A4FBC119CFF8590AFE79250B"
        "CCC8B3FAF1BD2422AB5C0D263FB2F8AFB3F796F048000381531B6F00D85161BC"
        "0FFF4BEF2486B1EBCD3773FABF50AD4AD5639AF9040E3F29C6C931301BF79832"
        "E9DA09857E831E82EF8B4691C235656515D437D2BDA33BCEC001C67FFDE15BA8";
    uint8_t zero_key[128] = {0};
    uint8_t zero_tweak[16] = {0};
    uint8_t zero_input[128] = {0};
    uint8_t block_output[128] = {0};
    uint8_t skein_output[128] = {0};
    uint8_t expected_skein[128] = {0};
    const uint8_t skein_message[1] = {0xFF};
    decode_hex(expected_skein_hex, expected_skein, sizeof(expected_skein));

    void* handle = open_library(directory, "libthreefish_ref.dylib");
    threefish_block_fn encrypt_block = NULL;
    skein_hash_fn hash = NULL;
    no_argument_kat_fn join_failure_kat = NULL;
    load_symbol(handle, "threefish_1024_encrypt_block", &encrypt_block, sizeof(encrypt_block));
    load_symbol(handle, "skein_1024_hash", &hash, sizeof(hash));
    load_symbol(
        handle,
        "keepvault_v12_threefish_join_failure_kat",
        &join_failure_kat,
        sizeof(join_failure_kat));
    if (encrypt_block(zero_key, zero_tweak, zero_input, block_output) != 0) {
        fail("Threefish-1024 adapter returned an error");
    }
    require_equal(
        (const uint8_t*)expected_threefish_words,
        block_output,
        sizeof(block_output),
        "Threefish-1024 official zero vector mismatch");
    if (hash(skein_message, sizeof(skein_message), skein_output) != 0) {
        fail("Skein-1024 adapter returned an error");
    }
    require_equal(expected_skein, skein_output, sizeof(skein_output), "Skein-1024 official 8-bit KAT mismatch");
    if (join_failure_kat() != 0) {
        fail("Threefish worker create/join-failure handling KAT failed");
    }
    secure_zero(block_output, sizeof(block_output));
    secure_zero(skein_output, sizeof(skein_output));
    secure_zero(expected_skein, sizeof(expected_skein));
    if (dlclose(handle) != 0) {
        fail("Threefish/Skein KAT library could not be closed");
    }
}

static void run_ctr_exhaustion_kat(
    ctr_cipher_fn xcrypt,
    const uint8_t* key,
    size_t key_length,
    size_t block_length,
    const char* final_block_message,
    const char* wrap_message,
    const char* sentinel_message)
{
    uint8_t* maximum_counter = malloc(block_length);
    uint8_t* input = malloc(block_length * 2U);
    uint8_t* output = malloc(block_length * 2U);
    if (maximum_counter == NULL || input == NULL || output == NULL) {
        fail("CTR exhaustion KAT allocation failed");
    }
    (void)key_length;
    memset(maximum_counter, 0xFF, block_length);
    memset(input, 0x3C, block_length * 2U);
    memset(output, 0, block_length * 2U);
    if (xcrypt(key, maximum_counter, input, output, block_length) != 0) {
        fail(final_block_message);
    }

    memset(output, 0xA5, block_length * 2U);
    if (xcrypt(key, maximum_counter, input, output, block_length * 2U) == 0) {
        fail(wrap_message);
    }
    for (size_t index = 0; index < block_length * 2U; ++index) {
        if (output[index] != 0xA5U) {
            fail(sentinel_message);
        }
    }

    secure_zero(maximum_counter, block_length);
    secure_zero(input, block_length * 2U);
    secure_zero(output, block_length * 2U);
    free(maximum_counter);
    free(input);
    free(output);
}

static void run_cryptopp_cipher_kats(const char* directory)
{
    static const char aes_key_hex[] =
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    static const char aes_plain_hex[] = "00112233445566778899AABBCCDDEEFF";
    static const char aes_expected_hex[] = "8EA2B7CA516745BFEAFC49904B496089";
    static const char mars_key_hex[] =
        "B55CAC37410991F8B1EC8376E8634B3B275173B72CA8B5A44F71F70286E1722A"
        "B6A1D2AFCCBB50C2639D5A52FE6B75B17E022E4CC4A9785A";
    static const char mars_plain_hex[] = "7C4614E4A3846DE5F48BFAA5B87B196F";
    static const char mars_expected_hex[] = "27574F61D5384B8F283A102CCEAC7197";
    static const char shacal_key_hex[] =
        "8000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000";
    static const char shacal_expected_hex[] =
        "361AB6322FA9E7A7BB23818D839E01BDDAFDF47305426EDD297AEDB9F6202BAE";

    uint8_t aes_key[32];
    uint8_t aes_plain[16];
    uint8_t aes_expected[16];
    uint8_t aes_actual[16] = {0};
    uint8_t mars_key[56];
    uint8_t mars_plain[16];
    uint8_t mars_expected[16];
    uint8_t mars_actual[16] = {0};
    uint8_t shacal_key[64];
    uint8_t shacal_plain[32] = {0};
    uint8_t shacal_expected[32];
    uint8_t shacal_actual[32] = {0};
    decode_hex(aes_key_hex, aes_key, sizeof(aes_key));
    decode_hex(aes_plain_hex, aes_plain, sizeof(aes_plain));
    decode_hex(aes_expected_hex, aes_expected, sizeof(aes_expected));
    decode_hex(mars_key_hex, mars_key, sizeof(mars_key));
    decode_hex(mars_plain_hex, mars_plain, sizeof(mars_plain));
    decode_hex(mars_expected_hex, mars_expected, sizeof(mars_expected));
    decode_hex(shacal_key_hex, shacal_key, sizeof(shacal_key));
    decode_hex(shacal_expected_hex, shacal_expected, sizeof(shacal_expected));

    void* aes_handle = open_library(directory, "libaes_ref.dylib");
    block_cipher_fn aes_block = NULL;
    ctr_cipher_fn aes_ctr = NULL;
    aes_provider_fn aes_provider = NULL;
    load_symbol(aes_handle, "aes_encrypt_block", &aes_block, sizeof(aes_block));
    load_symbol(aes_handle, "aes_256_ctr_xcrypt", &aes_ctr, sizeof(aes_ctr));
    load_symbol(aes_handle, "aes_get_runtime_provider", &aes_provider, sizeof(aes_provider));
    if (aes_block(aes_key, sizeof(aes_key), aes_plain, aes_actual) != 0) {
        fail("AES-256 FIPS-197 block KAT returned an error");
    }
    require_equal(aes_expected, aes_actual, sizeof(aes_actual), "AES-256 FIPS-197 block KAT mismatch");
#if defined(__aarch64__) || defined(__arm64__)
    if (aes_provider() != 2) {
        fail("Apple-silicon AES did not select Crypto++'s ARMv8 provider");
    }
#else
    if (aes_provider() <= 0) {
        fail("AES runtime-provider export returned an invalid value");
    }
#endif
    run_ctr_exhaustion_kat(
        aes_ctr, aes_key, sizeof(aes_key), sizeof(aes_plain),
        "AES refused the final full-width CTR block",
        "AES accepted a full-width CTR wrap",
        "AES wrote output before refusing a full-width CTR wrap");
    if (dlclose(aes_handle) != 0) {
        fail("AES KAT library could not be closed");
    }

    void* mars_handle = open_library(directory, "libmars_ref.dylib");
    block_cipher_fn mars_block = NULL;
    ctr_cipher_fn mars_ctr = NULL;
    load_symbol(mars_handle, "mars_encrypt_block", &mars_block, sizeof(mars_block));
    load_symbol(mars_handle, "mars_448_ctr_xcrypt", &mars_ctr, sizeof(mars_ctr));
    if (mars_block(mars_key, sizeof(mars_key), mars_plain, mars_actual) != 0) {
        fail("MARS-448 independent block KAT returned an error");
    }
    require_equal(mars_expected, mars_actual, sizeof(mars_actual), "MARS-448 Botan-derived block KAT mismatch");
    run_ctr_exhaustion_kat(
        mars_ctr, mars_key, sizeof(mars_key), sizeof(mars_plain),
        "MARS-448 refused the final full-width CTR block",
        "MARS-448 accepted a full-width CTR wrap",
        "MARS-448 wrote output before refusing a full-width CTR wrap");
    if (dlclose(mars_handle) != 0) {
        fail("MARS KAT library could not be closed");
    }

    void* shacal_handle = open_library(directory, "libshacal2_ref.dylib");
    block_cipher_fn shacal_block = NULL;
    ctr_cipher_fn shacal_ctr = NULL;
    load_symbol(shacal_handle, "shacal2_encrypt_block", &shacal_block, sizeof(shacal_block));
    load_symbol(shacal_handle, "shacal2_512_ctr_xcrypt", &shacal_ctr, sizeof(shacal_ctr));
    if (shacal_block(shacal_key, sizeof(shacal_key), shacal_plain, shacal_actual) != 0) {
        fail("SHACAL-2-512 NESSIE block KAT returned an error");
    }
    require_equal(
        shacal_expected, shacal_actual, sizeof(shacal_actual), "SHACAL-2-512 NESSIE block KAT mismatch");
    run_ctr_exhaustion_kat(
        shacal_ctr, shacal_key, sizeof(shacal_key), sizeof(shacal_plain),
        "SHACAL-2-512 refused the final full-width CTR block",
        "SHACAL-2-512 accepted a full-width CTR wrap",
        "SHACAL-2-512 wrote output before refusing a full-width CTR wrap");
    if (dlclose(shacal_handle) != 0) {
        fail("SHACAL-2 KAT library could not be closed");
    }

    secure_zero(aes_key, sizeof(aes_key));
    secure_zero(aes_plain, sizeof(aes_plain));
    secure_zero(aes_expected, sizeof(aes_expected));
    secure_zero(aes_actual, sizeof(aes_actual));
    secure_zero(mars_key, sizeof(mars_key));
    secure_zero(mars_plain, sizeof(mars_plain));
    secure_zero(mars_expected, sizeof(mars_expected));
    secure_zero(mars_actual, sizeof(mars_actual));
    secure_zero(shacal_key, sizeof(shacal_key));
    secure_zero(shacal_expected, sizeof(shacal_expected));
    secure_zero(shacal_actual, sizeof(shacal_actual));
}

static void run_chacha_kats(const char* directory)
{
    static const char key_hex[] =
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    static const char nonce_hex[] = "000000090000004A00000000";
    static const char expected_stream_hex[] =
        "10F1E7E4D13B5915500FDD1FA32071C4C7D1F4C733C068030422AA9AC3D46C4E"
        "D2826446079FAA0914C2D705D98B02A2B5129CD1DE164EB9CBD083E8A2503C4E";
    static const char aead_key_hex[] =
        "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F";
    static const char aead_nonce_hex[] = "070000004041424344454647";
    static const char aad_hex[] = "50515253C0C1C2C3C4C5C6C7";
    static const char expected_ciphertext_hex[] =
        "D31A8D34648E60DB7B86AFBC53EF7EC2A4ADED51296E08FEA9E2B5A736EE62D6"
        "3DBEA45E8CA9671282FAFB69DA92728B1A71DE0A9E060B2905D6A5B67ECD3B36"
        "92DDBD7F2D778B8C9803AEE328091B58FAB324E4FAD675945585808B4831D7BC"
        "3FF4DEF08E4B7A9DE576D26586CEC64B6116";
    static const char expected_tag_hex[] = "1AE10B594F09E26A7E902ECBD0600691";
    static const char plaintext[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t zeros[64] = {0};
    uint8_t expected_stream[64];
    uint8_t parallel_stream[64] = {0};
    uint8_t serial_stream[64] = {0};
    uint8_t aead_key[32];
    uint8_t aead_nonce[12];
    uint8_t aad[12];
    uint8_t expected_ciphertext[sizeof(plaintext) - 1U];
    uint8_t expected_tag[16];
    uint8_t ciphertext[sizeof(plaintext) - 1U];
    uint8_t tag[16] = {0};
    decode_hex(key_hex, key, sizeof(key));
    decode_hex(nonce_hex, nonce, sizeof(nonce));
    decode_hex(expected_stream_hex, expected_stream, sizeof(expected_stream));
    decode_hex(aead_key_hex, aead_key, sizeof(aead_key));
    decode_hex(aead_nonce_hex, aead_nonce, sizeof(aead_nonce));
    decode_hex(aad_hex, aad, sizeof(aad));
    decode_hex(expected_ciphertext_hex, expected_ciphertext, sizeof(expected_ciphertext));
    decode_hex(expected_tag_hex, expected_tag, sizeof(expected_tag));

    void* handle = open_library(directory, "libchachapoly_ref.dylib");
    chacha20_fn parallel = NULL;
    chacha20_fn serial = NULL;
    chachapoly_encrypt_fn encrypt = NULL;
    load_symbol(handle, "chacha20_xcrypt", &parallel, sizeof(parallel));
    load_symbol(handle, "chacha20_xcrypt_serial", &serial, sizeof(serial));
    load_symbol(handle, "chacha20poly1305_encrypt", &encrypt, sizeof(encrypt));
    if (parallel(key, nonce, 1U, zeros, parallel_stream, sizeof(parallel_stream)) != 0
        || serial(key, nonce, 1U, zeros, serial_stream, sizeof(serial_stream)) != 0) {
        fail("ChaCha20 RFC 8439 raw-keystream KAT returned an error");
    }
    require_equal(expected_stream, parallel_stream, sizeof(parallel_stream), "ChaCha20 RFC 8439 stream mismatch");
    require_equal(expected_stream, serial_stream, sizeof(serial_stream), "ChaCha20 serial stream mismatch");

    uint8_t wrap_input[192];
    uint8_t wrap_output[192];
    memset(wrap_input, 0x3C, sizeof(wrap_input));
    memset(wrap_output, 0, sizeof(wrap_output));
    if (parallel(key, nonce, UINT32_MAX, wrap_input, wrap_output, 64U) != 0) {
        fail("ChaCha20 split refused the final counter block");
    }
    memset(wrap_output, 0, sizeof(wrap_output));
    if (serial(key, nonce, UINT32_MAX, wrap_input, wrap_output, 64U) != 0) {
        fail("ChaCha20 serial refused the final counter block");
    }

    memset(wrap_output, 0xA5, sizeof(wrap_output));
    if (parallel(key, nonce, UINT32_MAX - 1U, wrap_input, wrap_output, sizeof(wrap_input)) != 4) {
        fail("ChaCha20 split did not reject counter exhaustion");
    }
    for (size_t index = 0; index < sizeof(wrap_output); ++index) {
        if (wrap_output[index] != 0xA5U) {
            fail("ChaCha20 split wrote output before rejecting counter exhaustion");
        }
    }
    memset(wrap_output, 0x5A, sizeof(wrap_output));
    if (serial(key, nonce, UINT32_MAX - 1U, wrap_input, wrap_output, sizeof(wrap_input)) != 4) {
        fail("ChaCha20 serial did not reject counter exhaustion");
    }
    for (size_t index = 0; index < sizeof(wrap_output); ++index) {
        if (wrap_output[index] != 0x5AU) {
            fail("ChaCha20 serial wrote output before rejecting counter exhaustion");
        }
    }

    if (encrypt(
            aead_key,
            aead_nonce,
            aad,
            sizeof(aad),
            (const uint8_t*)plaintext,
            ciphertext,
            sizeof(ciphertext),
            tag) != 0) {
        fail("ChaCha20-Poly1305 RFC 8439 AEAD KAT returned an error");
    }
    require_equal(
        expected_ciphertext,
        ciphertext,
        sizeof(ciphertext),
        "ChaCha20-Poly1305 RFC 8439 ciphertext mismatch");
    require_equal(expected_tag, tag, sizeof(tag), "ChaCha20-Poly1305 RFC 8439 tag mismatch");

    secure_zero(key, sizeof(key));
    secure_zero(nonce, sizeof(nonce));
    secure_zero(expected_stream, sizeof(expected_stream));
    secure_zero(parallel_stream, sizeof(parallel_stream));
    secure_zero(serial_stream, sizeof(serial_stream));
    secure_zero(aead_key, sizeof(aead_key));
    secure_zero(aead_nonce, sizeof(aead_nonce));
    secure_zero(aad, sizeof(aad));
    secure_zero(expected_ciphertext, sizeof(expected_ciphertext));
    secure_zero(expected_tag, sizeof(expected_tag));
    secure_zero(ciphertext, sizeof(ciphertext));
    secure_zero(tag, sizeof(tag));
    secure_zero(wrap_input, sizeof(wrap_input));
    secure_zero(wrap_output, sizeof(wrap_output));
    if (dlclose(handle) != 0) {
        fail("ChaCha20-Poly1305 KAT library could not be closed");
    }
}

static void run_mldsa_self_test(const char* directory)
{
    static const char expected_commit[] =
        "pq-crystals/dilithium@d35ba3fe5449bee3e6d43e1f296c3ca818bd36be";
    static const uint8_t message[] = "Keep Vault ML-DSA-87 per-slice self-test";
    static const uint8_t context[] = "KeepVault/KAT/v1";
    uint8_t* public_key = calloc(MLDSA87_PUBLIC_KEY_BYTES, 1U);
    uint8_t* private_key = calloc(MLDSA87_PRIVATE_KEY_BYTES, 1U);
    uint8_t* signature = calloc(MLDSA87_SIGNATURE_BYTES, 1U);
    uint8_t* second_signature = calloc(MLDSA87_SIGNATURE_BYTES, 1U);
    if (public_key == NULL || private_key == NULL || signature == NULL || second_signature == NULL) {
        fail("ML-DSA-87 self-test allocation failed");
    }

    void* handle = open_library(directory, "libmldsa87_ref.dylib");
    mldsa_keypair_fn keypair = NULL;
    mldsa_sign_fn sign = NULL;
    mldsa_verify_fn verify = NULL;
    mldsa_commit_fn commit = NULL;
    load_symbol(handle, "mldsa87_keypair", &keypair, sizeof(keypair));
    load_symbol(handle, "mldsa87_sign", &sign, sizeof(sign));
    load_symbol(handle, "mldsa87_verify", &verify, sizeof(verify));
    load_symbol(handle, "mldsa87_reference_commit", &commit, sizeof(commit));
    if (commit() == NULL || strcmp(commit(), expected_commit) != 0) {
        fail("ML-DSA-87 reference revision mismatch");
    }
    if (keypair(public_key, MLDSA87_PUBLIC_KEY_BYTES, private_key, MLDSA87_PRIVATE_KEY_BYTES) != 0) {
        fail("ML-DSA-87 key generation failed");
    }
    size_t signature_length = 0;
    if (sign(
            signature,
            MLDSA87_SIGNATURE_BYTES,
            &signature_length,
            message,
            sizeof(message) - 1U,
            context,
            sizeof(context) - 1U,
            private_key,
            MLDSA87_PRIVATE_KEY_BYTES) != 0
        || signature_length != MLDSA87_SIGNATURE_BYTES) {
        fail("ML-DSA-87 signing failed");
    }
    if (verify(
            signature,
            signature_length,
            message,
            sizeof(message) - 1U,
            context,
            sizeof(context) - 1U,
            public_key,
            MLDSA87_PUBLIC_KEY_BYTES) != 0) {
        fail("ML-DSA-87 verification failed");
    }
    uint8_t changed_message[sizeof(message) - 1U];
    memcpy(changed_message, message, sizeof(changed_message));
    changed_message[0] ^= 0x80U;
    if (verify(
            signature,
            signature_length,
            changed_message,
            sizeof(changed_message),
            context,
            sizeof(context) - 1U,
            public_key,
            MLDSA87_PUBLIC_KEY_BYTES) == 0) {
        fail("ML-DSA-87 accepted a changed message");
    }
    signature[MLDSA87_SIGNATURE_BYTES / 2U] ^= 1U;
    if (verify(
            signature,
            signature_length,
            message,
            sizeof(message) - 1U,
            context,
            sizeof(context) - 1U,
            public_key,
            MLDSA87_PUBLIC_KEY_BYTES) == 0) {
        fail("ML-DSA-87 accepted a changed signature");
    }
    signature[MLDSA87_SIGNATURE_BYTES / 2U] ^= 1U;
    size_t second_length = 0;
    if (sign(
            second_signature,
            MLDSA87_SIGNATURE_BYTES,
            &second_length,
            message,
            sizeof(message) - 1U,
            context,
            sizeof(context) - 1U,
            private_key,
            MLDSA87_PRIVATE_KEY_BYTES) != 0
        || second_length != MLDSA87_SIGNATURE_BYTES
        || memcmp(signature, second_signature, MLDSA87_SIGNATURE_BYTES) == 0) {
        fail("ML-DSA-87 randomized signing self-test failed");
    }

    secure_zero(public_key, MLDSA87_PUBLIC_KEY_BYTES);
    secure_zero(private_key, MLDSA87_PRIVATE_KEY_BYTES);
    secure_zero(signature, MLDSA87_SIGNATURE_BYTES);
    secure_zero(second_signature, MLDSA87_SIGNATURE_BYTES);
    free(public_key);
    free(private_key);
    free(signature);
    free(second_signature);
    if (dlclose(handle) != 0) {
        fail("ML-DSA-87 self-test library could not be closed");
    }
}

static void run_argon2_policy_kat(const char* directory)
{
    static const char expected_hex[] =
        "EA1770676778A3197837EC64A7BBD78163F7C8986909089B86941A9AF473187A"
        "EDE081B1ADD1A54D041B3C2D950168B1069B7450B5DBC1F2AB215D1841FE8FFE";
    uint8_t password[] = "KeepVault-Native-KAT-Argon2id-1GiB-2026";
    uint8_t salt[] = "0123456789abcdef0123456789abcdef";
    uint8_t output[64] = {0};
    uint8_t expected[64] = {0};
    decode_hex(expected_hex, expected, sizeof(expected));

    void* handle = open_library(directory, "libargon2_ref.dylib");
    argon2_hash_fn hash = NULL;
    load_symbol(handle, "phc_argon2id_hash_raw", &hash, sizeof(hash));
    if (hash(
            4U,
            1048576U,
            4U,
            password,
            (uint32_t)(sizeof(password) - 1U),
            salt,
            (uint32_t)(sizeof(salt) - 1U),
            output,
            (uint32_t)sizeof(output)) != 0) {
        fail("the enforced Argon2id 1-GiB/4/4 adapter profile failed");
    }
    require_equal(expected, output, sizeof(output), "Argon2id 1-GiB/4/4 policy KAT mismatch");

    memset(output, 0xA5, sizeof(output));
    if (hash(
            4U,
            65536U,
            4U,
            password,
            (uint32_t)(sizeof(password) - 1U),
            salt,
            (uint32_t)(sizeof(salt) - 1U),
            output,
            (uint32_t)sizeof(output)) == 0) {
        fail("Argon2id adapter accepted a weakened memory profile");
    }
    for (size_t index = 0; index < sizeof(output); ++index) {
        if (output[index] != 0xA5U) {
            fail("Argon2id adapter modified output after rejecting a weakened profile");
        }
    }
    secure_zero(password, sizeof(password));
    secure_zero(salt, sizeof(salt));
    secure_zero(output, sizeof(output));
    secure_zero(expected, sizeof(expected));
    if (dlclose(handle) != 0) {
        fail("Argon2id KAT library could not be closed");
    }
}

int main(int argument_count, char** arguments)
{
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Keep Vault native KAT vectors require a reviewed little-endian target."
#endif
    if (argument_count != 2 || arguments[1][0] == '\0') {
        fprintf(stderr, "Usage: %s /absolute/native/slice/directory\n", arguments[0]);
        return 64;
    }
    run_kalyna_kat(arguments[1]);
    run_threefish_and_skein_kats(arguments[1]);
    run_cryptopp_cipher_kats(arguments[1]);
    run_chacha_kats(arguments[1]);
    run_mldsa_self_test(arguments[1]);
    run_argon2_policy_kat(arguments[1]);
    puts("Native per-slice cryptographic KATs passed.");
    return 0;
}
