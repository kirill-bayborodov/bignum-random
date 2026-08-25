/**
 * @file test_bignum_random_mt.c
 * @brief Independent-object concurrency test for bignum_random.
 * @details Eight pthread workers repeatedly sample from private normalized
 * bounds. The test does not compare cryptographic bytes between threads; its
 * oracle checks named success, strict range membership, normalized output, and
 * unchanged input snapshots. It therefore detects shared mutable state or an
 * unsafe entropy integration without assuming a deterministic random stream.
 */
#include "bignum_random.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/** @brief Number of independent reentrancy workers. */
#define RANDOM_MT_THREADS 8U
/** @brief Successful samples required from each worker. */
#define RANDOM_MT_ITERATIONS 1000U

/**
 * @brief Holds one thread-private bound and its aggregate test result.
 * @details Each worker owns the complete structure from creation through join.
 * `failed` is written by its worker before `pthread_join` and read only after
 * that join, so the test performs no unsynchronized shared-data access.
 */
typedef struct random_mt_case {
    bignum_t bound; /**< [in] Private normalized positive exclusive endpoint. */
    int failed; /**< [out] Zero on complete success; one after the first invariant failure. */
} random_mt_case_t;

/**
 * @brief Compares two unsigned bignum records numerically.
 * @param[in] left First borrowed normalized or zero record.
 * @param[in] right Second borrowed normalized or zero record.
 * @return Negative, zero, or positive based on unsigned numeric ordering.
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
 * @brief Checks the sample postcondition needed by each worker.
 * @param[in] output Borrowed successful bignum_random output.
 * @param[in] bound Borrowed thread-private normalized upper bound.
 * @return One when output is normalized and strictly in range, otherwise zero.
 */
static int valid_sample(const bignum_t *output, const bignum_t *bound)
{
    if (output->len > BIGNUM_CAPACITY) return 0;
    if (output->len > 0U && output->words[output->len - 1U] == UINT64_C(0)) return 0;
    for (size_t index = output->len; index < BIGNUM_CAPACITY; ++index) {
        if (output->words[index] != UINT64_C(0)) return 0;
    }
    return compare_values(output, bound) < 0;
}

/**
 * @brief Samples repeatedly from one private bound in a worker thread.
 * @details Every iteration snapshots the bound before calling the API. The
 * output is intentionally prefilled with a canary so success must fully
 * normalize it rather than preserve stale tail data.
 * @param[in,out] opaque Pointer to one caller-owned `random_mt_case_t`.
 * @return Always NULL; failure is recorded in `random_mt_case_t::failed`.
 */
static void *worker(void *opaque)
{
    random_mt_case_t *test_case = opaque;

    for (size_t iteration = 0U; iteration < RANDOM_MT_ITERATIONS; ++iteration) {
        bignum_t output;
        const bignum_t snapshot = test_case->bound;

        memset(&output, 0x4D, sizeof(output));
        if (bignum_random(&output, &test_case->bound) != BIGNUM_RANDOM_SUCCESS ||
            !valid_sample(&output, &test_case->bound) ||
            memcmp(&test_case->bound, &snapshot, sizeof(snapshot)) != 0) {
            test_case->failed = 1;
            return NULL;
        }
    }
    return NULL;
}

/**
 * @brief Starts and joins independent random-sampling workers.
 * @details Bounds differ by high word and all have two active words, covering
 * concurrent system entropy reads with distinct caller-owned inputs. The exact
 * oracle is zero worker failures after joins complete.
 * @return One when every thread was created, joined, and passed, otherwise zero.
 */
static int test_independent_thread_safety(void)
{
    pthread_t threads[RANDOM_MT_THREADS];
    random_mt_case_t cases[RANDOM_MT_THREADS];

    for (size_t index = 0U; index < RANDOM_MT_THREADS; ++index) {
        memset(&cases[index], 0, sizeof(cases[index]));
        cases[index].bound.words[0] = UINT64_C(0xFEDCBA9876543211) + (uint64_t)index;
        cases[index].bound.words[1] = UINT64_C(1) + (uint64_t)index;
        cases[index].bound.len = 2U;
        if (pthread_create(&threads[index], NULL, worker, &cases[index]) != 0) return 0;
    }
    for (size_t index = 0U; index < RANDOM_MT_THREADS; ++index) {
        if (pthread_join(threads[index], NULL) != 0 || cases[index].failed != 0) return 0;
    }
    return 1;
}

/**
 * @brief Executes the module's independent-object concurrency regression test.
 * @return ISO C process success only when all workers satisfy the range oracle.
 */
int main(void)
{
    printf("--- Starting MT bignum_random tests ---\n");
    if (!test_independent_thread_safety()) {
        printf("--- MT bignum_random: FAILED ---\n");
        return 1;
    }
    printf("--- MT bignum_random: PASSED ---\n");
    return 0;
}
