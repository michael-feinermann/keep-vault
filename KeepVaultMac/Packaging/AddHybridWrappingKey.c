#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    RoleInvalid = 0,
    RoleMldsa,
    RolePfx
} WrappingRole;

static void secure_zero(void *pointer, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *)pointer;
    while (length-- > 0) {
        *bytes++ = 0;
    }
}

static void print_security_error(const char *operation, OSStatus status)
{
    CFStringRef message = SecCopyErrorMessageString(status, NULL);
    char text[512] = {0};
    if (message != NULL
        && CFStringGetCString(message, text, sizeof(text), kCFStringEncodingUTF8)) {
        fprintf(stderr, "AddHybridWrappingKey: %s: %s.\n", operation, text);
    } else {
        fprintf(stderr, "AddHybridWrappingKey: %s (Security.framework status %d).\n",
                operation, (int)status);
    }
    if (message != NULL) {
        CFRelease(message);
    }
}

static void encode_base64_32(const uint8_t input[32], char output[45])
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t source = 0;
    size_t target = 0;
    while (source + 3 <= 32) {
        uint32_t value = ((uint32_t)input[source] << 16)
            | ((uint32_t)input[source + 1] << 8)
            | input[source + 2];
        output[target++] = alphabet[(value >> 18) & 0x3f];
        output[target++] = alphabet[(value >> 12) & 0x3f];
        output[target++] = alphabet[(value >> 6) & 0x3f];
        output[target++] = alphabet[value & 0x3f];
        source += 3;
    }

    uint32_t tail = (uint32_t)input[source] << 16
        | (uint32_t)input[source + 1] << 8;
    output[target++] = alphabet[(tail >> 18) & 0x3f];
    output[target++] = alphabet[(tail >> 12) & 0x3f];
    output[target++] = alphabet[(tail >> 6) & 0x3f];
    output[target++] = '=';
    output[target] = '\0';
}

static WrappingRole parse_role(const char *value)
{
    if (strcmp(value, "mldsa") == 0) return RoleMldsa;
    if (strcmp(value, "pfx") == 0) return RolePfx;
    return RoleInvalid;
}

static CFStringRef role_label(WrappingRole role)
{
    return role == RoleMldsa
        ? CFSTR("Keep Vault v12 ML-DSA-87 wrapping key")
        : CFSTR("Keep Vault v12 RSA PFX-password wrapping key");
}

static CFStringRef role_comment(WrappingRole role)
{
    return role == RoleMldsa
        ? CFSTR("Releases only the ML-DSA-87 private key. Every prompt should be one you started.")
        : CFSTR("Releases only the RSA PFX password. Every prompt should be one you started.");
}

static int verify_acl(const char *service_text, const char *account_text,
                      WrappingRole role)
{
    int result = EXIT_FAILURE;
    SecKeychainItemRef item = NULL;
    SecAccessRef access = NULL;
    CFArrayRef acl_list = NULL;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    OSStatus status = SecKeychainFindGenericPassword(
        NULL,
        (UInt32)strlen(service_text), service_text,
        (UInt32)strlen(account_text), account_text,
        NULL, NULL,
        &item);
#pragma clang diagnostic pop
    if (status != errSecSuccess || item == NULL) {
        print_security_error("could not find the role-specific wrapping key", status);
        goto cleanup;
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    status = SecKeychainItemCopyAccess(item, &access);
#pragma clang diagnostic pop
    if (status != errSecSuccess || access == NULL) {
        print_security_error("could not inspect the wrapping-key ACL", status);
        goto cleanup;
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    acl_list = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt);
#pragma clang diagnostic pop
    if (acl_list == NULL || CFArrayGetCount(acl_list) == 0) {
        fputs("AddHybridWrappingKey: the wrapping key has no decrypt ACL.\n", stderr);
        goto cleanup;
    }

    CFIndex acl_count = CFArrayGetCount(acl_list);
    for (CFIndex index = 0; index < acl_count; ++index) {
        SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acl_list, index);
        CFArrayRef trusted_applications = NULL;
        CFStringRef description = NULL;
        SecKeychainPromptSelector prompt_selector = 0;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        status = SecACLCopyContents(
            acl,
            &trusted_applications,
            &description,
            &prompt_selector);
#pragma clang diagnostic pop
        if (status != errSecSuccess
            || trusted_applications == NULL
            || CFArrayGetCount(trusted_applications) != 0
            || description == NULL
            || CFStringCompare(description, role_label(role), 0) != kCFCompareEqualTo) {
            if (description != NULL) CFRelease(description);
            if (trusted_applications != NULL) CFRelease(trusted_applications);
            fputs("AddHybridWrappingKey: the wrapping key ACL is not role-specific and prompt-only.\n", stderr);
            goto cleanup;
        }
        CFRelease(description);
        CFRelease(trusted_applications);
    }

    result = EXIT_SUCCESS;

cleanup:
    if (acl_list != NULL) CFRelease(acl_list);
    if (access != NULL) CFRelease(access);
    if (item != NULL) CFRelease(item);
    return result;
}

static int create_key(const char *service_text, const char *account_text,
                      WrappingRole role)
{
    int result = EXIT_FAILURE;
    uint8_t random_key[32] = {0};
    char encoded_key[45] = {0};
    CFStringRef service = NULL;
    CFStringRef account = NULL;
    CFArrayRef trusted_applications = NULL;
    SecAccessRef access = NULL;
    CFDataRef secret_data = NULL;
    CFDictionaryRef attributes = NULL;

    OSStatus status = SecRandomCopyBytes(kSecRandomDefault, sizeof(random_key), random_key);
    if (status != errSecSuccess) {
        print_security_error("could not generate the role-specific wrapping key", status);
        goto cleanup;
    }
    encode_base64_32(random_key, encoded_key);

    service = CFStringCreateWithCString(
        kCFAllocatorDefault, service_text, kCFStringEncodingUTF8);
    account = CFStringCreateWithCString(
        kCFAllocatorDefault, account_text, kCFStringEncodingUTF8);
    trusted_applications = CFArrayCreate(
        kCFAllocatorDefault, NULL, 0, &kCFTypeArrayCallBacks);
    if (service == NULL || account == NULL || trusted_applications == NULL) {
        fputs("AddHybridWrappingKey: could not allocate non-secret Keychain metadata.\n", stderr);
        goto cleanup;
    }

    /* Each invocation creates a fresh SecAccess object. Its empty trusted-app
       list means no binary may read this role's key silently. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    status = SecAccessCreate(role_label(role), trusted_applications, &access);
#pragma clang diagnostic pop
    if (status != errSecSuccess || access == NULL) {
        print_security_error("could not create the role-specific prompt-only ACL", status);
        goto cleanup;
    }

    secret_data = CFDataCreateWithBytesNoCopy(
        kCFAllocatorDefault,
        (const UInt8 *)encoded_key,
        44,
        kCFAllocatorNull);
    if (secret_data == NULL) {
        fputs("AddHybridWrappingKey: could not prepare the wrapping key for Keychain insertion.\n", stderr);
        goto cleanup;
    }

    const void *keys[] = {
        kSecClass,
        kSecAttrService,
        kSecAttrAccount,
        kSecAttrLabel,
        kSecAttrDescription,
        kSecAttrComment,
        kSecAttrAccess,
        kSecValueData,
    };
    const void *values[] = {
        kSecClassGenericPassword,
        service,
        account,
        role_label(role),
        role_label(role),
        role_comment(role),
        access,
        secret_data,
    };
    attributes = CFDictionaryCreate(
        kCFAllocatorDefault,
        keys,
        values,
        (CFIndex)(sizeof(keys) / sizeof(keys[0])),
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if (attributes == NULL) {
        fputs("AddHybridWrappingKey: could not create the Keychain insertion request.\n", stderr);
        goto cleanup;
    }

    status = SecItemAdd(attributes, NULL);
    if (status != errSecSuccess) {
        print_security_error("could not add the role-specific wrapping key", status);
        goto cleanup;
    }
    result = EXIT_SUCCESS;

cleanup:
    if (attributes != NULL) CFRelease(attributes);
    if (secret_data != NULL) CFRelease(secret_data);
    if (access != NULL) CFRelease(access);
    if (trusted_applications != NULL) CFRelease(trusted_applications);
    if (account != NULL) CFRelease(account);
    if (service != NULL) CFRelease(service);
    secure_zero(encoded_key, sizeof(encoded_key));
    secure_zero(random_key, sizeof(random_key));
    return result;
}

int main(int argc, char **argv)
{
    if (argc != 5
        || argv[1][0] == '\0'
        || argv[2][0] == '\0'
        || argv[3][0] == '\0'
        || argv[4][0] == '\0') {
        fputs("AddHybridWrappingKey: usage: AddHybridWrappingKey create|verify mldsa|pfx SERVICE ACCOUNT\n", stderr);
        return EXIT_FAILURE;
    }

    WrappingRole role = parse_role(argv[2]);
    if (role == RoleInvalid) {
        fputs("AddHybridWrappingKey: role must be mldsa or pfx.\n", stderr);
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "create") == 0) {
        if (create_key(argv[3], argv[4], role) != EXIT_SUCCESS) {
            return EXIT_FAILURE;
        }
        return verify_acl(argv[3], argv[4], role);
    }
    if (strcmp(argv[1], "verify") == 0) {
        return verify_acl(argv[3], argv[4], role);
    }

    fputs("AddHybridWrappingKey: command must be create or verify.\n", stderr);
    return EXIT_FAILURE;
}
