/* Copyright (c) 2005 Sean Chittenden <sean@chittenden.org>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <err.h>
#include <sysexits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "memcache.h"

double tt(const struct timeval *t1, const struct timeval *t2);

double
tt(const struct timeval *t1, const struct timeval *t2) {
  double ret;

  ret = t2->tv_sec - t1->tv_sec;
  ret += 0.000001 * (t2->tv_usec - t1->tv_usec);

  return ret;
}


int
main(int argc, char *argv[]) {
  struct memcache *mc = NULL;
  u_int32_t num_tests = 0, maxsize = 0;
  u_int32_t i, j;
  char *val, *ret;
  char *key;
  u_int32_t keylen;
  u_int32_t hash_pre, hash_post;

  if (argc > 1)
    num_tests = strtol(argv[1], NULL, 10);

  if (num_tests == 0)
    num_tests = 1;

  if (argc > 2)
    maxsize = strtol(argv[2], NULL, 10);

  if (maxsize == 0)
    maxsize = (u_int32_t)(INIT_GET_BUF_SIZE * 2.1);

  mc = mc_new();
  mc_err_filter_del(MCM_ERR_LVL_INFO);
  mc_err_filter_del(MCM_ERR_LVL_NOTICE);

  if (mc == NULL)
    err(EX_OSERR, "Unable to allocate a new memcache object");

  mc_server_add4(mc, "localhost:11211");

  printf("Num tests:\t\t%d\n", num_tests);
  printf("Max val size per test:\t%d\n", maxsize);

  for (i = 1; i <= num_tests; i++) {
    printf("Starting test run %u\n", i);

    for (j = 1; j < maxsize; j++) {
      printf(".");
      fflush(stdout);

      val = (char *)malloc(j + 1);
      memset(val, 69, j);
      val[j] = '\0';

      hash_pre = mc_hash_key(val, j);

      if (!asprintf(&key, "key-%d-%d", i, j)) {
	printf("asprintf(3) failed (%d %d)\n", i, j);
	exit(1);
      }
      keylen = strlen(key);

      mc_set(mc, key, keylen, val, j, 0, 0);
      ret = mc_aget(mc, key, keylen);

      if (ret != NULL)
	hash_post = mc_hash_key(ret, strlen(ret));
      else {
	printf("\nFailed to get key \"%s\"\n", key);
	hash_post = 0;
      }

      if (hash_pre != hash_post) {
	printf("Hash values different (%u %u) for test %u, size %u\n", hash_pre, hash_post, i, j);
	exit(1);
      }

      free(key);
      free(val);
      free(ret);
    }

    printf("Completed test run %u\n", i);
  }

  mc_free(mc);

  return EX_OK;
}
