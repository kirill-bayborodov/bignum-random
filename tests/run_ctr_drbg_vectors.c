/**
 * @file run_ctr_drbg_vectors.c
 * @brief Runs AES-256 CTR_DRBG use-df CAVP-style records without Python.
 * @details Parses the project RSP subset, loads the shared library through
 * POSIX dynamic linking, injects vector inputs, and compares ReturnedBits.
 * This is a test-only C11 runner and is not part of the production module.
 */
#include "bignum_ctr_drbg.h"

#include <ctype.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HEX_CAP 4096U
#define MAX_ADDITIONAL 2U
#define MAX_PR_ENTROPY 2U
#define MAX_CASES 4096U

typedef struct vector_case {
    char section[64];
    char entropy[HEX_CAP];
    char nonce[HEX_CAP];
    char personalization[HEX_CAP];
    char additional[MAX_ADDITIONAL][HEX_CAP];
    size_t additional_count;
    char reseed_entropy[HEX_CAP];
    char reseed_additional[HEX_CAP];
    char pr_entropy[MAX_PR_ENTROPY][HEX_CAP];
    size_t pr_entropy_count;
    char returned_bits[HEX_CAP];
    unsigned long count;
} vector_case_t;

typedef bignum_ctr_drbg_status_t (*instantiate_fn)(
    bignum_ctr_drbg_ctx *, const uint8_t *, size_t,
    const uint8_t *, size_t, const uint8_t *, size_t);
typedef bignum_ctr_drbg_status_t (*reseed_fn)(
    bignum_ctr_drbg_ctx *, const uint8_t *, size_t,
    const uint8_t *, size_t);
typedef bignum_ctr_drbg_status_t (*generate_fn)(
    bignum_ctr_drbg_ctx *, uint8_t *, size_t,
    const uint8_t *, size_t);

typedef struct api {
    instantiate_fn instantiate;
    reseed_fn reseed;
    generate_fn generate;
} api_t;

static void trim(char *text)
{
    size_t length = strlen(text);
    size_t start = 0U;
    while (start < length && isspace((unsigned char)text[start]) != 0) ++start;
    while (length > start && isspace((unsigned char)text[length - 1U]) != 0) --length;
    if (start != 0U) memmove(text, text + start, length - start);
    text[length - start] = '\0';
}

static int copy_field(char *destination, size_t capacity, const char *value)
{
    size_t length = strlen(value);
    if (length >= capacity) return 0;
    memcpy(destination, value, length + 1U);
    return 1;
}

static int parse_hex(const char *text, uint8_t *output, size_t capacity, size_t *length)
{
    size_t chars = strlen(text);
    size_t i;
    if ((chars & 1U) != 0U || chars / 2U > capacity) return 0;
    for (i = 0U; i < chars / 2U; ++i) {
        unsigned int high, low;
        if (sscanf(text + 2U * i, "%1x%1x", &high, &low) != 2) return 0;
        output[i] = (uint8_t)((high << 4U) | low);
    }
    *length = chars / 2U;
    return 1;
}

static void reset_case(vector_case_t *record, const char *section)
{
    memset(record, 0, sizeof(*record));
    (void)copy_field(record->section, sizeof(record->section), section);
}

static int store_pair(vector_case_t *record, const char *key, const char *value)
{
    if (strcmp(key, "EntropyInput") == 0) return copy_field(record->entropy, sizeof(record->entropy), value);
    if (strcmp(key, "Nonce") == 0) return copy_field(record->nonce, sizeof(record->nonce), value);
    if (strcmp(key, "PersonalizationString") == 0) return copy_field(record->personalization, sizeof(record->personalization), value);
    if (strcmp(key, "AdditionalInput") == 0) {
        if (record->additional_count >= MAX_ADDITIONAL) return 0;
        if (!copy_field(record->additional[record->additional_count], sizeof(record->additional[0]), value)) return 0;
        ++record->additional_count;
        return 1;
    }
    if (strcmp(key, "EntropyInputReseed") == 0) return copy_field(record->reseed_entropy, sizeof(record->reseed_entropy), value);
    if (strcmp(key, "AdditionalInputReseed") == 0) return copy_field(record->reseed_additional, sizeof(record->reseed_additional), value);
    if (strcmp(key, "EntropyInputPR") == 0) {
        if (record->pr_entropy_count >= MAX_PR_ENTROPY) return 0;
        if (!copy_field(record->pr_entropy[record->pr_entropy_count], sizeof(record->pr_entropy[0]), value)) return 0;
        ++record->pr_entropy_count;
        return 1;
    }
    if (strcmp(key, "ReturnedBits") == 0) return copy_field(record->returned_bits, sizeof(record->returned_bits), value);
    if (strcmp(key, "COUNT") == 0) return sscanf(value, "%lu", &record->count) == 1;
    return 1;
}

static int run_case(const api_t *api, const vector_case_t *record, size_t ordinal)
{
    uint8_t entropy[1024], nonce[1024], personalization[1024], extra[1024], expected[1024], output[1024];
    size_t entropy_len, nonce_len, personalization_len, extra_len, expected_len, i;
    bignum_ctr_drbg_ctx context;
    bignum_ctr_drbg_status_t status;
    if (!parse_hex(record->entropy, entropy, sizeof(entropy), &entropy_len) ||
        !parse_hex(record->nonce, nonce, sizeof(nonce), &nonce_len) ||
        !parse_hex(record->personalization, personalization, sizeof(personalization), &personalization_len) ||
        !parse_hex(record->returned_bits, expected, sizeof(expected), &expected_len)) return 0;
    if (entropy_len != 32U || nonce_len != 16U || expected_len != 64U) return 0;
    status = api->instantiate(&context, entropy, entropy_len, nonce, nonce_len, personalization, personalization_len);
    if (status != BIGNUM_CTR_DRBG_SUCCESS) return 0;
    if (record->pr_entropy_count != 0U) {
        if (record->pr_entropy_count != 2U || record->additional_count > 2U) return 0;
        for (i = 0U; i < 2U; ++i) {
            if (!parse_hex(record->pr_entropy[i], entropy, sizeof(entropy), &entropy_len)) return 0;
            extra_len = 0U;
            if (i < record->additional_count && !parse_hex(record->additional[i], extra, sizeof(extra), &extra_len)) return 0;
            status = api->reseed(&context, entropy, entropy_len, extra, extra_len);
            if (status != BIGNUM_CTR_DRBG_SUCCESS || api->generate(&context, output, expected_len, NULL, 0U) != BIGNUM_CTR_DRBG_SUCCESS) return 0;
        }
    } else {
        if (record->reseed_entropy[0] != '\0') {
            if (!parse_hex(record->reseed_entropy, entropy, sizeof(entropy), &entropy_len) ||
                !parse_hex(record->reseed_additional, extra, sizeof(extra), &extra_len)) return 0;
            status = api->reseed(&context, entropy, entropy_len, extra, extra_len);
            if (status != BIGNUM_CTR_DRBG_SUCCESS) return 0;
        }
        for (i = 0U; i < 2U; ++i) {
            extra_len = 0U;
            if (i < record->additional_count && !parse_hex(record->additional[i], extra, sizeof(extra), &extra_len)) return 0;
            if (api->generate(&context, output, expected_len, extra, extra_len) != BIGNUM_CTR_DRBG_SUCCESS) return 0;
        }
    }
    if (memcmp(output, expected, expected_len) != 0) {
        fprintf(stderr, "COUNT %lu (case %zu) mismatch\n", record->count, ordinal);
        return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    FILE *file;
    void *library;
    api_t api;
    vector_case_t record;
    char line[HEX_CAP + 128U], section[64] = "";
    size_t cases = 0U, passed = 0U;
    int have_record = 0;
    if (argc != 3) {
        fprintf(stderr, "usage: %s LIBRARY VECTOR_RSP\n", argv[0]);
        return 2;
    }
    library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (library == NULL) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    *(void **)(&api.instantiate) = dlsym(library, "bignum_ctr_drbg_instantiate");
    *(void **)(&api.reseed) = dlsym(library, "bignum_ctr_drbg_reseed");
    *(void **)(&api.generate) = dlsym(library, "bignum_ctr_drbg_generate");
    if (api.instantiate == NULL || api.reseed == NULL || api.generate == NULL) { fprintf(stderr, "missing DRBG API\n"); dlclose(library); return 2; }
    file = fopen(argv[2], "r");
    if (file == NULL) { perror(argv[2]); dlclose(library); return 2; }
    reset_case(&record, "");
    while (fgets(line, sizeof(line), file) != NULL) {
        char *equals, *key, *value;
        trim(line);
        if (line[0] == '[') {
            if (strstr(line, "use df]") != NULL || strstr(line, "no df]") != NULL) {
                if (have_record && strcmp(record.section, "[AES-256 use df]") == 0) {
                    if (!run_case(&api, &record, cases)) { fclose(file); dlclose(library); return 1; }
                    ++cases; ++passed;
                }
                if (!copy_field(section, sizeof(section), line)) { fclose(file); dlclose(library); return 1; }
                reset_case(&record, section);
                have_record = 0;
            }
            continue;
        }
        if (line[0] == '\0') {
            if (have_record && record.entropy[0] != '\0' && record.returned_bits[0] != '\0') {
                if (strcmp(record.section, "[AES-256 use df]") == 0) {
                    if (cases >= MAX_CASES || !run_case(&api, &record, cases)) { fclose(file); dlclose(library); return 1; }
                    ++cases; ++passed;
                }
                reset_case(&record, section);
                have_record = 0;
            }
            continue;
        }
        equals = strstr(line, " = ");
        if (equals != NULL) {
            *equals = '\0'; key = line; value = equals + 3; trim(key); trim(value);
            if (!store_pair(&record, key, value)) { fclose(file); dlclose(library); return 1; }
            have_record = 1;
        }
    }
    if (have_record && strcmp(record.section, "[AES-256 use df]") == 0) {
        if (cases >= MAX_CASES || !run_case(&api, &record, cases)) { fclose(file); dlclose(library); return 1; }
        ++cases; ++passed;
    }
    fclose(file);
    dlclose(library);
    if (cases == 0U) { fprintf(stderr, "no AES-256 use-df cases found\n"); return 1; }
    printf("AES-256 use-df vectors: PASS (%zu cases)\n", passed);
    return 0;
}
