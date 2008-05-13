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
  u_int32_t num_tests = 0, valsize = 0;
  u_int32_t i;
  struct timeval t1, t2;
  const char *key;
  char *tests = NULL;
  char *val;
  u_int32_t keylen;
  double addtime, deltime;
  const char fmt[] = "%s\t%f\t%f\t%f\n";
  struct memcache_req *req;
  struct memcache_res *res;

  if (argc > 1)
    num_tests = strtol(argv[1], NULL, 10);

  if (num_tests == 0)
    num_tests = 10;

  if (argc > 2)
    valsize = strtol(argv[2], NULL, 10);

  if (argc > 3)
    tests = strdup(argv[3]);

  if (tests == NULL)
    tests = strdup("adgs");

  if (valsize == 0)
    valsize = 50;

  val = (char *)malloc(valsize + 1);
  memset(val, 69, valsize);
  val[valsize] = '\0';

  /* XXX I should add a min/max time value for each request */
  printf("Value size:\t%d\n", valsize);
  printf("Num tests:\t%d\n", num_tests);
  printf("Test\tOps per second\tTotal Time\tTime per Request\n");

  key = "bench_key";
  keylen = strlen(key);

  mc = mc_new();
  if (mc == NULL)
    err(EX_OSERR, "Unable to allocate a new memcache object");

  mc_err_filter_del(MCM_ERR_LVL_INFO);
  mc_err_filter_del(MCM_ERR_LVL_NOTICE);

  mc_server_add4(mc, "localhost:11211");

  /* Establish a connection */
  mc_set(mc, key, keylen, val, valsize, 0, 0);

  /* BEGIN set test, if specified */
  if (strchr(tests, (int)'s') != NULL) {
    if (gettimeofday(&t1, NULL) != 0)
      err(EX_OSERR, "gettimeofday(2)");

    for (i = 0; i < num_tests; i++) {
      mc_set(mc, key, keylen, val, valsize, 0, 0);
    }

    if (gettimeofday(&t2, NULL) != 0)
      err(EX_OSERR, "gettimeofday(2)");
    /* END set test */
    printf(fmt, "set", num_tests / tt(&t1, &t2), tt(&t1, &t2), tt(&t1, &t2) / num_tests);
  }


  if (strchr(tests, (int)'g') != NULL) {
    /* BEGIN get request */
    req = mc_req_new();
    res = mc_req_add(req, key, keylen);
    res->size = valsize;
    res->val = malloc(res->size);
    mc_res_free_on_delete(res, 1);

    if (gettimeofday(&t1, NULL) != 0)
      err(EX_OSERR, "gettimeofday(2)");

    for (i = 0; i < num_tests; i++) {
      mc_get(mc, req);
    }

    if (gettimeofday(&t2, NULL) != 0)
      err(EX_OSERR, "gettimeofday(2)");

    mc_req_free(req);
    /* END get test */
    printf(fmt, "get", num_tests / tt(&t1, &t2), tt(&t1, &t2), tt(&t1, &t2) / num_tests);
  }



  if (strchr(tests, 'a') != NULL || strchr(tests, 'd') != NULL) {
    /* Run the add/delete test */
    mc_delete(mc, key, keylen, 0);
    addtime = deltime = 0.0;
    for (i = 0; i < num_tests; i++) {
      /* BEGIN add test */
      if (strchr(tests, 'a') != NULL) {
	if (gettimeofday(&t1, NULL) != 0)
	  err(EX_OSERR, "gettimeofday(2)");

	mc_add(mc, key, keylen, val, valsize, 0, 0);

	if (gettimeofday(&t2, NULL) != 0)
	  err(EX_OSERR, "gettimeofday(2)");

	addtime += tt(&t1, &t2);
	/* END add test */
      }

      /* BEGIN delete test */
      if (strchr(tests, 'd') != NULL) {
	if (gettimeofday(&t1, NULL) != 0)
	  err(EX_OSERR, "gettimeofday(2)");

	mc_delete(mc, key, keylen, 0);

	if (gettimeofday(&t2, NULL) != 0)
	  err(EX_OSERR, "gettimeofday(2)");

	deltime += tt(&t1, &t2);
	/* END delete test */
      }
    }

    if (strchr(tests, 'a') != NULL)
      printf(fmt, "add",    num_tests / addtime, addtime, addtime / num_tests);

    if (strchr(tests, 'd') != NULL)
      printf(fmt, "delete", num_tests / deltime, deltime, deltime / num_tests);
  }


  free(tests);
  free(val);
  mc_free(mc);

  return EX_OK;
}
