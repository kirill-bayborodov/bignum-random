/**
 * @file benchmark_framework.h
 * @brief Project include bridge for the benchmark-framework distribution.
 * @details The CI workflow downloads the vendor distribution into
 * `libs/benchmark-framework/dist`. Keeping this bridge in the project include
 * directory makes the active adapter independent of whether the compiler also
 * receives the vendor include directory from a local build environment.
 */
#ifndef BIGNUM_RANDOM_BENCHMARK_FRAMEWORK_H
#define BIGNUM_RANDOM_BENCHMARK_FRAMEWORK_H

#include "../libs/benchmark-framework/dist/benchmark_framework.h"

#endif /* BIGNUM_RANDOM_BENCHMARK_FRAMEWORK_H */
