/**
 * @file test_bignum_random.c
 * @brief Deterministic public-contract tests for bignum_random.
 * @details The cryptographic source deliberately prevents an exact value oracle.
 * These tests instead use fixed bounds and verify the complete observable
 * contract on every call: named status, strict range membership, normalized
 * output, input preservation, and transactional failure behavior. Repeated
 * sampling uses only invariant checks and does not assume a particular stream.
 */
#include "bignum_random.h"
#ifdef BIGNUM_RANDOM_CTR_DRBG_VECTOR_TEST
#include "../src/internal/bignum_ctr_drbg.h"
#endif

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/**
 * @brief Initializes a normalized bignum from a little-endian word sequence.
 * @param[out] value Writable record to initialize.
 * @param[in] words Little-endian words; NULL is permitted only with zero count.
 * @param[in] length Exact normalized active-word count.
 * @return No status; test fixtures provide valid arguments.
 */
static void set_value(bignum_t *value, const uint64_t *words, size_t length)
{
    memset(value, 0, sizeof(*value));
    if (length > 0U) memcpy(value->words, words, length * sizeof(words[0]));
    value->len = length;
}

/**
 * @brief Compares two normalized fixed-capacity unsigned bignums.
 * @param[in] left First borrowed normalized value.
 * @param[in] right Second borrowed normalized value.
 * @return Negative, zero, or positive according to unsigned numeric ordering.
 */
static int compare_values(const bignum_t *left, const bignum_t *right)
{
    size_t index = left->len > right->len ? left->len : right->len;

    while (index > 0U) {
        uint64_t left_word;
        uint64_t right_word;

        --index;
        left_word = index < left->len ? left->words[index] : UINT64_C(0);
        right_word = index < right->len ? right->words[index] : UINT64_C(0);
        if (left_word < right_word) return -1;
        if (left_word > right_word) return 1;
    }
    return 0;
}

/**
 * @brief Verifies normalized representation and strict half-open range output.
 * @param[in] value Borrowed output record returned by bignum_random.
 * @param[in] bound Borrowed normalized positive exclusive upper bound.
 * @return One when every representation and range invariant holds, otherwise zero.
 */
static int is_valid_sample(const bignum_t *value, const bignum_t *bound)
{
    if (value->len > BIGNUM_CAPACITY) return 0;
    if (value->len > 0U && value->words[value->len - 1U] == UINT64_C(0)) return 0;
    for (size_t index = value->len; index < BIGNUM_CAPACITY; ++index) {
        if (value->words[index] != UINT64_C(0)) return 0;
    }
    return compare_values(value, bound) < 0;
}

/**
 * @brief Exercises null, alias, empty-range, length, and normalization errors.
 * @details Each failure scenario starts with a distinct canary output snapshot.
 * The oracle requires the named status and byte-for-byte output preservation,
 * proving that validation occurs before entropy acquisition or output mutation.
 * @return One on success and zero on the first contract violation.
 */
static int test_invalid_arguments_preserve_output(void)
{
    const uint64_t seven[] = { UINT64_C(7) };
    bignum_t output;
    bignum_t before;
    bignum_t bound;

    set_value(&output, seven, 1U);
    before = output;
    if (bignum_random(&output, NULL) != BIGNUM_RANDOM_ERROR_NULL_ARG ||
        memcmp(&output, &before, sizeof(output)) != 0) return 0;

    set_value(&bound, seven, 1U);
    if (bignum_random(&bound, &bound) != BIGNUM_RANDOM_ERROR_ALIAS) return 0;

    memset(&bound, 0, sizeof(bound));
    if (bignum_random(&output, &bound) != BIGNUM_RANDOM_ERROR_RANGE ||
        memcmp(&output, &before, sizeof(output)) != 0) return 0;

    bound.len = BIGNUM_CAPACITY + 1U;
    if (bignum_random(&output, &bound) != BIGNUM_RANDOM_ERROR_LENGTH ||
        memcmp(&output, &before, sizeof(output)) != 0) return 0;

    memset(&bound, 0, sizeof(bound));
    bound.len = 1U;
    if (bignum_random(&output, &bound) != BIGNUM_RANDOM_ERROR_NORMALIZATION ||
        memcmp(&output, &before, sizeof(output)) != 0) return 0;
    return 1;
}

/**
 * @brief Verifies the unique output for the singleton interval `[0, 1)`.
 * @details The fixed bound one gives an exact oracle despite nondeterministic
 * entropy: every accepted candidate must be zero and must have normalized
 * length zero. The loop also checks that repeated entropy calls remain valid.
 * @return One when all 64 samples equal zero, otherwise zero.
 */
static int test_singleton_range(void)
{
    const uint64_t one[] = { UINT64_C(1) };
    bignum_t bound;

    set_value(&bound, one, 1U);
    for (size_t iteration = 0U; iteration < 64U; ++iteration) {
        bignum_t output;

        memset(&output, 0xA5, sizeof(output));
        if (bignum_random(&output, &bound) != BIGNUM_RANDOM_SUCCESS ||
            output.len != 0U || output.words[0] != UINT64_C(0) ||
            !is_valid_sample(&output, &bound)) return 0;
    }
    return 1;
}

/**
 * @brief Checks strict range and input preservation for fixed representative bounds.
 * @details Bounds 2, 3, and `2^64 + 1` exercise a power of two, a rejection-
 * sampling case, and a two-word bit-length boundary. The reference oracle is
 * numeric comparison rather than a predicted random byte sequence.
 * @return One when 768 successful samples obey every invariant, otherwise zero.
 */
static int test_representative_ranges(void)
{
    const uint64_t bounds[][2] = {
        { UINT64_C(2), UINT64_C(0) },
        { UINT64_C(3), UINT64_C(0) },
        { UINT64_C(1), UINT64_C(1) }
    };
    const size_t lengths[] = { 1U, 1U, 2U };

    for (size_t case_index = 0U; case_index < 3U; ++case_index) {
        bignum_t bound;
        bignum_t snapshot;

        set_value(&bound, bounds[case_index], lengths[case_index]);
        snapshot = bound;
        for (size_t iteration = 0U; iteration < 256U; ++iteration) {
            bignum_t output;

            memset(&output, 0x5A, sizeof(output));
            if (bignum_random(&output, &bound) != BIGNUM_RANDOM_SUCCESS ||
                !is_valid_sample(&output, &bound) ||
                memcmp(&bound, &snapshot, sizeof(bound)) != 0) return 0;
        }
    }
    return 1;
}

/**
 * @brief Verifies successful child sampling after a parent has filled the ASM cache.
 * @details The parent first samples below three to create reusable entropy state.
 * A child created with `fork()` then performs an independent public call. The
 * child exits successfully only for `BIGNUM_RANDOM_SUCCESS` and a valid strict
 * range result; the parent waits through EINTR and validates the child status.
 * This is a public behavioral test, while syscall tracing separately confirms
 * that the child cache invalidation path obtains fresh kernel entropy.
 * @return One when parent prefill and child post-fork sampling both satisfy the
 * public contract, otherwise zero.
 */
static int test_fork_child_sampling(void)
{
    const uint64_t three[] = { UINT64_C(3) };
    bignum_t bound;
    bignum_t parent_output;
    pid_t child;
    pid_t waited;
    int wait_status;

    set_value(&bound, three, 1U);
    if (bignum_random(&parent_output, &bound) != BIGNUM_RANDOM_SUCCESS ||
        !is_valid_sample(&parent_output, &bound)) return 0;

    child = fork();
    if (child < 0) return 0;
    if (child == 0) {
        bignum_t child_output;
        const int valid = bignum_random(&child_output, &bound) == BIGNUM_RANDOM_SUCCESS &&
                          is_valid_sample(&child_output, &bound);

        _exit(valid ? 0 : 1);
    }

    do {
        waited = waitpid(child, &wait_status, 0);
    } while (waited < 0 && errno == EINTR);

    return waited == child && WIFEXITED(wait_status) && WEXITSTATUS(wait_status) == 0;
}

/**
 * @brief Runs all deterministic public-contract scenarios.
 * @details Each line identifies the exact scenario so a CI failure exposes the
 * violated API invariant without relying on a non-reproducible sampled value.
 * @return ISO C process success only when all listed scenarios pass.
 */
#ifdef BIGNUM_RANDOM_CTR_DRBG_VECTOR_TEST
static int test_ctr_drbg_vectors(const char *library_path, const char *vector_path);
#endif

int main(int argc, char **argv)
{
    int failed = 0;

    printf("--- Starting deterministic bignum_random tests ---\n");
    if (test_invalid_arguments_preserve_output()) printf("test_invalid_arguments_preserve_output: PASSED\n");
    else { printf("test_invalid_arguments_preserve_output: FAILED\n"); ++failed; }
    if (test_singleton_range()) printf("test_singleton_range: PASSED\n");
    else { printf("test_singleton_range: FAILED\n"); ++failed; }
    if (test_representative_ranges()) printf("test_representative_ranges: PASSED\n");
    else { printf("test_representative_ranges: FAILED\n"); ++failed; }
    if (test_fork_child_sampling()) printf("test_fork_child_sampling: PASSED\n");
    else { printf("test_fork_child_sampling: FAILED\n"); ++failed; }
#ifdef BIGNUM_RANDOM_CTR_DRBG_VECTOR_TEST
    if (argc != 3 || !test_ctr_drbg_vectors(argv[1], argv[2])) {
        printf("test_ctr_drbg_vectors: FAILED\n");
        ++failed;
    } else {
        printf("test_ctr_drbg_vectors: PASSED\n");
    }
#else
    (void)argc;
    (void)argv;
#endif
    printf("--- Deterministic bignum_random tests: %s ---\n", failed == 0 ? "PASSED" : "FAILED");
    return failed == 0 ? 0 : 1;
}

#ifdef BIGNUM_RANDOM_CTR_DRBG_VECTOR_TEST
#define VECTOR_TEXT_CAP 4096U

typedef struct vector_record {
    char section[64];
    char entropy[VECTOR_TEXT_CAP];
    char nonce[VECTOR_TEXT_CAP];
    char personalization[VECTOR_TEXT_CAP];
    char additional[2][VECTOR_TEXT_CAP];
    size_t additional_count;
    char reseed_entropy[VECTOR_TEXT_CAP];
    char reseed_additional[VECTOR_TEXT_CAP];
    char pr_entropy[2][VECTOR_TEXT_CAP];
    size_t pr_entropy_count;
    char returned_bits[VECTOR_TEXT_CAP];
    unsigned long count;
} vector_record_t;

static void vector_trim(char *text)
{
    size_t length = strlen(text);
    size_t start = 0U;
    while (start < length && (text[start] == ' ' || text[start] == '\t' || text[start] == '\r' || text[start] == '\n')) ++start;
    while (length > start && (text[length - 1U] == ' ' || text[length - 1U] == '\t' || text[length - 1U] == '\r' || text[length - 1U] == '\n')) --length;
    if (start != 0U) memmove(text, text + start, length - start);
    text[length - start] = '\0';
}

static int vector_copy(char *destination, size_t capacity, const char *source)
{
    const size_t length = strlen(source);
    if (length >= capacity) return 0;
    memcpy(destination, source, length + 1U);
    return 1;
}

static int vector_hex(const char *text, uint8_t *output, size_t capacity, size_t *length)
{
    size_t chars = strlen(text);
    size_t index;
    if ((chars & 1U) != 0U || chars / 2U > capacity) return 0;
    for (index = 0U; index < chars / 2U; ++index) {
        unsigned int high, low;
        if (sscanf(text + index * 2U, "%1x%1x", &high, &low) != 2) return 0;
        output[index] = (uint8_t)((high << 4U) | low);
    }
    *length = chars / 2U;
    return 1;
}

static void vector_reset(vector_record_t *record, const char *section)
{
    memset(record, 0, sizeof(*record));
    (void)vector_copy(record->section, sizeof(record->section), section);
}

static int vector_field(vector_record_t *record, const char *key, const char *value)
{
    if (strcmp(key, "COUNT") == 0) return sscanf(value, "%lu", &record->count) == 1;
    if (strcmp(key, "EntropyInput") == 0) return vector_copy(record->entropy, sizeof(record->entropy), value);
    if (strcmp(key, "Nonce") == 0) return vector_copy(record->nonce, sizeof(record->nonce), value);
    if (strcmp(key, "PersonalizationString") == 0) return vector_copy(record->personalization, sizeof(record->personalization), value);
    if (strcmp(key, "EntropyInputReseed") == 0) return vector_copy(record->reseed_entropy, sizeof(record->reseed_entropy), value);
    if (strcmp(key, "AdditionalInputReseed") == 0) return vector_copy(record->reseed_additional, sizeof(record->reseed_additional), value);
    if (strcmp(key, "ReturnedBits") == 0) return vector_copy(record->returned_bits, sizeof(record->returned_bits), value);
    if (strcmp(key, "AdditionalInput") == 0) {
        if (record->additional_count >= 2U) return 0;
        if (!vector_copy(record->additional[record->additional_count], sizeof(record->additional[0]), value)) return 0;
        ++record->additional_count;
        return 1;
    }
    if (strcmp(key, "EntropyInputPR") == 0) {
        if (record->pr_entropy_count >= 2U) return 0;
        if (!vector_copy(record->pr_entropy[record->pr_entropy_count], sizeof(record->pr_entropy[0]), value)) return 0;
        ++record->pr_entropy_count;
    }
    return 1;
}

static int vector_run_record(const vector_record_t *record)
{
    uint8_t entropy[1024], nonce[1024], personalization[1024], extra[1024], expected[1024], output[1024];
    size_t entropy_len = 0U, nonce_len = 0U, personalization_len = 0U, extra_len = 0U, expected_len = 0U, index;
    bignum_ctr_drbg_ctx context;
    if (!vector_hex(record->entropy, entropy, sizeof(entropy), &entropy_len) ||
        !vector_hex(record->nonce, nonce, sizeof(nonce), &nonce_len) ||
        !vector_hex(record->personalization, personalization, sizeof(personalization), &personalization_len) ||
        !vector_hex(record->returned_bits, expected, sizeof(expected), &expected_len) ||
        entropy_len != 32U || nonce_len != 16U || expected_len != 64U) { return 0; }
    if (bignum_ctr_drbg_instantiate(&context, entropy, entropy_len, nonce, nonce_len, personalization, personalization_len) != BIGNUM_CTR_DRBG_SUCCESS) { return 0; }
    if (record->pr_entropy_count == 2U) {
        for (index = 0U; index < 2U; ++index) {
            if (!vector_hex(record->pr_entropy[index], entropy, sizeof(entropy), &entropy_len)) return 0;
            extra_len = 0U;
            if (index < record->additional_count && !vector_hex(record->additional[index], extra, sizeof(extra), &extra_len)) return 0;
            if (bignum_ctr_drbg_reseed(&context, entropy, entropy_len, extra, extra_len) != BIGNUM_CTR_DRBG_SUCCESS ||
                bignum_ctr_drbg_generate(&context, output, expected_len, NULL, 0U) != BIGNUM_CTR_DRBG_SUCCESS) { return 0; }
        }
    } else {
        if (record->reseed_entropy[0] != '\0' &&
            (!vector_hex(record->reseed_entropy, entropy, sizeof(entropy), &entropy_len) ||
             !vector_hex(record->reseed_additional, extra, sizeof(extra), &extra_len) ||
             bignum_ctr_drbg_reseed(&context, entropy, entropy_len, extra, extra_len) != BIGNUM_CTR_DRBG_SUCCESS)) return 0;
        for (index = 0U; index < 2U; ++index) {
            extra_len = 0U;
            if (index < record->additional_count && !vector_hex(record->additional[index], extra, sizeof(extra), &extra_len)) return 0;
            if (bignum_ctr_drbg_generate(&context, output, expected_len, extra, extra_len) != BIGNUM_CTR_DRBG_SUCCESS) { return 0; }
        }
    }
    if (memcmp(output, expected, expected_len) != 0) {
        fprintf(stderr, "vector COUNT %lu mismatch\n", record->count);
        return 0;
    }
    return 1;
}

static int test_ctr_drbg_vectors(const char *library_path, const char *vector_path)
{
    FILE *file = fopen(vector_path, "r");
    vector_record_t record;
    char line[VECTOR_TEXT_CAP + 128U], section[64] = "";
    size_t cases = 0U;
    int active = 0;
    (void)library_path;
    if (file == NULL) return 0;
    vector_reset(&record, "");
    while (fgets(line, sizeof(line), file) != NULL) {
        char *equals;
        vector_trim(line);
        if (line[0] == '[') {
            if (strstr(line, "use df]") != NULL || strstr(line, "no df]") != NULL) {
                if (active && strcmp(record.section, "[AES-256 use df]") == 0) {
                    if (!vector_run_record(&record)) { fclose(file); return 0; }
                    ++cases;
                }
                if (!vector_copy(section, sizeof(section), line)) { fclose(file); return 0; }
                vector_reset(&record, section);
                active = 0;
            }
            continue;
        }
        if (line[0] == '\0') {
            if (record.entropy[0] != '\0' && record.returned_bits[0] != '\0') active = 1;
            if (active && strcmp(record.section, "[AES-256 use df]") == 0) {
                if (!vector_run_record(&record)) { fclose(file); return 0; }
                ++cases;
                vector_reset(&record, section);
                active = 0;
            }
            continue;
        }
        equals = strstr(line, " = ");
        if (equals != NULL) {
            *equals = '\0';
            vector_trim(line);
            vector_trim(equals + 3);
            if (strcmp(line, "COUNT") == 0 && record.entropy[0] != '\0' && record.returned_bits[0] != '\0') {
                if (strcmp(record.section, "[AES-256 use df]") == 0) {
                    if (!vector_run_record(&record)) { fclose(file); return 0; }
                    ++cases;
                }
                vector_reset(&record, section);
            }
            if (!vector_field(&record, line, equals + 3)) { fclose(file); return 0; }
        }
    }
    if (active && strcmp(record.section, "[AES-256 use df]") == 0) {
        if (!vector_run_record(&record)) { fclose(file); return 0; }
        ++cases;
    }
    fclose(file);
    printf("C11 DRBG vectors: PASS (%zu cases)\n", cases);
    return cases == 240U;
}
#endif
