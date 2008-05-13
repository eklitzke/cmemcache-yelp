/* Copyright (c) 2004-2005 Sean Chittenden <sean@chittenden.org>
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
 *
 * This is a test program for the memcache C API.  Note to developers
 * who would otherwise use this code as base place to start for future
 * projects/work: MCM_CSTRLEN() uses sizeof().  Only use MCM_CSTRLEN()
 * on const strings.  For variable length strings, use strlen()
 * instead.
 */

#include <err.h>
#include <sysexits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <memcache.h>

void test_add(struct memcache *mc, const u_int32_t);
void test_aget(struct memcache *mc, const char *key, const u_int32_t);
void test_decr(struct memcache *mc, const u_int32_t);
void test_delete(struct memcache *mc, const u_int32_t);
void test_incr(struct memcache *mc, const u_int32_t);
void test_loop(struct memcache *mc, const u_int32_t);
void test_multi_get(struct memcache *mc, const u_int32_t);
void test_multi_get_loop(struct memcache *mc, const u_int32_t);
void test_long_poisoned_get(struct memcache *mc, const u_int32_t, const u_int32_t);
void validate_long_poisoned_response(struct memcache_res *res, const u_int32_t);
void test_set(struct memcache *mc, const u_int32_t);
void test_stats(struct memcache *mc, int out);
void test_replace(struct memcache *mc, const u_int32_t);
void test_callback(struct memcache *mc, const u_int32_t);

static u_int32_t num_times_my_callback_called = 0;
static u_int32_t num_attempted = 0;
static u_int32_t num_found = 0;

int
main(int argc, char *argv[]) {
  struct memcache *mc = NULL;
  u_int32_t num_tests = 0;
  u_int32_t i;
  u_int32_t long_string_size = 9000;
  char *long_string;

  if (argc > 1)
    num_tests = strtol(argv[1], NULL, 10);

  if (num_tests == 0)
    num_tests = 10;

  mc = mc_new();
  mc_err_filter_del(MCM_ERR_LVL_INFO);
  mc_err_filter_del(MCM_ERR_LVL_NOTICE);

  if (mc == NULL)
    err(EX_OSERR, "Unable to allocate a new memcache object");

  mc_server_add(mc, "127.0.0.1", "11211");
  mc_server_add4(mc, "127.0.0.1:11212");
  mc_server_add4(mc, "127.0.0.1:11213");
  mc_server_add4(mc, "localhost:11214");

  mc_set(mc, "foo", MCM_CSTRLEN("foo"), "test", MCM_CSTRLEN("test"), 0, 0);

  /* Long string of all \r\n, this is to test that we will not fail
   * regardless of what is in the data stored */
  long_string = malloc(long_string_size);

  for (i = 0; i < long_string_size; ++i)
    long_string[i] = i % 2 == 0 ? '\r' : '\n';

  if (mc_set(mc, "long_poisoned_string", MCM_CSTRLEN("long_poisoned_string"), long_string, long_string_size, 0, 0) != 0)
    warnx("set for long poisoned string failed");

  warnx("starting long_poisoned_get test");
  test_long_poisoned_get(mc, num_tests, long_string_size);

  warnx("starting multi_get test");
  test_multi_get(mc, num_tests);

  warnx("starting incr test");
  test_incr(mc, num_tests);

  warnx("starting decr test");
  test_decr(mc, num_tests);

  warnx("starting add test");
  test_add(mc, num_tests);

  warnx("starting replace test");
  test_replace(mc, num_tests);

  warnx("starting delete test");
  test_delete(mc, num_tests);

  warnx("starting set test");
  test_set(mc, num_tests);

  warnx("starting multi_get loop test");
  test_multi_get_loop(mc, num_tests);

  warnx("starting aget loop test");
  test_loop(mc, num_tests);

  warnx("starting aget miss test");
  test_aget(mc, "frob", num_tests);

  warnx("starting stats run");
  test_stats(mc, 1);

  warnx("starting callback test");
  test_callback(mc, num_tests);

  warnx("Disconnecting from all servers");
  mc_server_disconnect_all(mc);

  for (i = 0; i < num_tests; i++) {
    test_multi_get_loop(mc, i);
    test_set(mc, i);
    test_loop(mc, i);
    test_replace(mc, i);
    test_aget(mc, "frob", i);
    test_stats(mc, 0);
    test_callback(mc, i);
  }

  test_stats(mc, 1);

  free(long_string);
  mc_free(mc);

  warnx("Callback stats:");
  warnx("\tnum times callback called:\t%u", num_times_my_callback_called);
  warnx("\tnum attempted:\t%u", num_attempted);
  warnx("\tnum found:\t%u", num_found);

  return EX_OK;
}


void
test_stats(struct memcache *mc, int out) {
  struct memcache_server_stats *s;

  s = mc_stats(mc);
  if (s == NULL)
    warnx("Unable to get stats");
  else {
    if (out) {
      printf("pid:\t\t\t%u\n", s->pid);
      printf("uptime:\t\t\t%llu\n", (u_int64_t)s->uptime);
      printf("time:\t\t\t%llu\n", (u_int64_t)s->time);
      printf("version:\t\t%s\n", s->version);
      printf("rusage_user:\t\t%llu.%llus\n", (u_int64_t)s->rusage_user.tv_sec, (u_int64_t)s->rusage_user.tv_usec);
      printf("rusage_system:\t\t%llu.%llus\n", (u_int64_t)s->rusage_system.tv_sec, (u_int64_t)s->rusage_system.tv_usec);
      printf("curr_items:\t\t%u\n", s->curr_items);
      printf("total_items:\t\t%llu\n", s->total_items);
      printf("bytes:\t\t\t%llu\n", s->bytes);
      printf("curr_connections:\t%u\n", s->curr_connections);
      printf("total_connections:\t%llu\n", s->total_connections);
      printf("connection_structures:\t%u\n", s->connection_structures);
      printf("cmd_get:\t\t%llu\n", s->cmd_get);
      printf("cmd_set:\t\t%llu\n", s->cmd_set);
      printf("get_hits:\t\t%llu\n", s->get_hits);
      printf("get_misses:\t\t%llu\n", s->get_misses);
      printf("bytes_read:\t\t%llu\n", s->bytes_read);
      printf("bytes_written:\t\t%llu\n", s->bytes_written);
      printf("limit_maxbytes:\t\t%llu\n", s->limit_maxbytes);
    }
  }

  mc_server_stats_free(s);
}


void
test_add(struct memcache *mc, const u_int32_t count) {
  size_t left, len;
  char buf[50];
  char *cp;
  int ret;
  u_int32_t i;

  bzero(&buf, (size_t)50);
  memcpy(&buf, "testing_key", MCM_CSTRLEN("testing_key"));
  cp = &buf[MCM_CSTRLEN("testing_key")];
  left = 50 - MCM_CSTRLEN("testing_key");
  for (i = 0; i < count; i++) {
    len = snprintf(cp, left, "%d", i);
    if (len > 0) {
      ret = mc_add(mc, buf, len + MCM_CSTRLEN("testing_key"), "test", (size_t)4, 0, 0);
      if (ret == 0) {
	/* Worked */
      } else {
	/* Skunk fucked */
	warnx("Unable to add a key %d", ret);
      }
    }
  }
}


void
test_aget(struct memcache *mc, const char *key, const u_int32_t count) {
  void *val;
  u_int32_t i;

  for (i = 0; i < count; i++) {
    val = mc_aget(mc, key, strlen(key));
    if (val != NULL) {
      free(val);
    }
  }
}


void
test_loop(struct memcache *mc, const u_int32_t count) {
  const char *key = "foo";
  void *val;
  u_int32_t i;
  size_t len;

  len = strlen(key);
  for (i = 0; i < count; i++) {
    val = mc_aget(mc, key, len);
    if (val != NULL)
      free(val);
  }
}


void
test_long_poisoned_get(struct memcache *mc, const u_int32_t count, const u_int32_t longstrlen) {
  struct memcache_req *req;
  struct memcache_res *res1, *res2, *res3;
  u_int32_t i;

  req = mc_req_new();
  res1 = mc_req_add(req, "long_poisoned_string", MCM_CSTRLEN("long_poisoned_string"));

  /* First just test a single get of the long string, see if thats good */
  mc_get(mc, req);
  validate_long_poisoned_response(res1, longstrlen);
  mc_req_free(req);

  req = mc_req_new();

  res1 = mc_req_add(req, "long_poisoned_string", MCM_CSTRLEN("long_poisoned_string"));
  res2 = mc_req_add(req, "foo", MCM_CSTRLEN("foo"));
  res3 = mc_req_add(req, "long_poisoned_string", MCM_CSTRLEN("long_poisoned_string"));

  for (i = 0; i < count; i++) {
    mc_get(mc, req);
  }

  validate_long_poisoned_response(res1, longstrlen);
  validate_long_poisoned_response(res3, longstrlen);
  mc_req_free(req);
}


void
validate_long_poisoned_response(struct memcache_res *res, const u_int32_t longstrlen) {
  char *cp;
  u_int32_t i;

  /* Check that the last value we got out matched the expected string. */
  if (res->size != longstrlen) {
    warnx("Bad size for long poisoned response: %d %d %d %p", res->bytes, res->size, longstrlen, &res->val);
  } else {
    cp = (char *)res->val;
    for (i = 0; i < res->size; ++i) {
      if (i % 2 == 0) {
	if (cp[i] != '\r') {
	  warnx("%d\tExpected \\r in response, found '%d'", i, cp[i]);
	}
      } else {
	if (cp[i] != '\n') {
	  warnx("%d\tExpected \\n in response, found '%d'", i, cp[i]);
	}
      }
    }
  }
}


void
test_multi_get(struct memcache *mc, const u_int32_t count) {
  struct memcache_req *req;
  struct memcache_res *res;
  u_int32_t i;

  req = mc_req_new();
  mc_req_add(req, "foo", MCM_CSTRLEN("foo"));
  mc_req_add(req, "frob", MCM_CSTRLEN("frob"));
  res = mc_req_add(req, "foo", MCM_CSTRLEN("foo"));
  res->size = 1024;
  res->val = malloc(res->size);
  mc_res_free_on_delete(res, 1);

  for (i = 0; i < count; i++)
    mc_get(mc, req);

  mc_req_free(req);
}


void
test_multi_get_loop(struct memcache *mc, const u_int32_t count) {
  struct memcache_req *req;
  struct memcache_res *res;
  u_int32_t i;

  req = mc_req_new();
  res = mc_req_add(req, "foo", MCM_CSTRLEN("foo"));
  res->size = 1024;
  res->val = malloc(res->size);
  mc_res_free_on_delete(res, 1);

  for (i = 0; i < count; i++)
    mc_get(mc, req);

  mc_req_free(req);
}


void
test_replace(struct memcache *mc, const u_int32_t count) {
  size_t left, len ;
  char buf[50];
  char *cp;
  u_int32_t i;

  bzero(&buf, (size_t)50);
  memcpy(&buf, "testing_key", MCM_CSTRLEN("testing_key"));
  cp = &buf[MCM_CSTRLEN("testing_key")];
  left = 50 - MCM_CSTRLEN("testing_key");
  for (i = 0; i < count; i++) {
    len = snprintf(cp, left, "%d", i);
    if (len > 0) {
      if (mc_replace(mc, buf, len + MCM_CSTRLEN("testing_key"), "test", (size_t)MCM_CSTRLEN("test2"), 0, 0) == 0) {
	/* Worked */
      } else {
	/* Skunk fucked */
	warnx("Unable to replace a key");
      }
    }
  }
}


void
test_set(struct memcache *mc, const u_int32_t count) {
  size_t left, len ;
  char buf[50];
  char *cp;
  u_int32_t i;

  bzero(&buf, (size_t)50);
  memcpy(&buf, "testing_key", MCM_CSTRLEN("testing_key"));
  cp = &buf[MCM_CSTRLEN("testing_key")];
  left = 50 - MCM_CSTRLEN("testing_key");
  for (i = 0; i < count; i++) {
    len = snprintf(cp, left, "%d", i);
    if (len > 0) {
      if (mc_set(mc, buf, len + MCM_CSTRLEN("testing_key"), "foobar", (size_t)MCM_CSTRLEN("foobar"), 0, 0) == 0) {
	/* Worked */
      } else {
	/* Skunk fucked */
	warnx("Unable to set a key");
      }
    }
  }
}


void
test_delete(struct memcache *mc, const u_int32_t count) {
  size_t left, len ;
  char buf[50];
  char *cp;
  u_int32_t i;

  bzero(&buf, (size_t)50);
  memcpy(&buf, "testing_key", MCM_CSTRLEN("testing_key"));
  cp = &buf[MCM_CSTRLEN("testing_key")];
  left = 50 - MCM_CSTRLEN("testing_key");
  for (i = 0; i < count; i++) {
    len = snprintf(cp, left, "%d", i);
    if (len > 0) {
      if (mc_delete(mc, buf, len + MCM_CSTRLEN("testing_key"), 0) == 0) {
	/* Worked */
      } else {
	/* Skunk fucked */
	warnx("Unable to remove a key");
      }
    }
  }
}


void
test_incr(struct memcache *mc, const u_int32_t count) {
  u_int32_t i, val;

  mc_set(mc, "atop_key", MCM_CSTRLEN("atop_key"), "0", (size_t)MCM_CSTRLEN("0"), 0, 0);
  for (i = 1; i < count; i++) {
    val = mc_incr(mc, "atop_key", MCM_CSTRLEN("atop_key"), 1);
    if (val == i) {
      /* Worked */
    } else {
      /* Skunk fucked */
      warnx("Unable to incr a key");
    }
  }
}


void
test_decr(struct memcache *mc, const u_int32_t count) {
  u_int32_t i, val;
  char buf[10];

  snprintf(buf, (size_t)10, "%u", count);
  mc_set(mc, "atop_key", MCM_CSTRLEN("atop_key"), buf, (size_t)strlen(buf), 0, 0);
  for (i = count; i > 0; i--) {
    val = mc_decr(mc, "atop_key", MCM_CSTRLEN("atop_key"), 1);
    if (val == i - 1) {
      /* Worked */
    } else {
      /* Skunk fucked */
      warnx("Unable to decr a key");
    }
  }

  if (mc_decr(mc, "atop_key", MCM_CSTRLEN("atop_key"), 1) != 0)
    warnx("underflow");
}


static void my_callback(MCM_CALLBACK_SIG);
static void
my_callback(MCM_CALLBACK_FUNC) {
  struct memcache_res *res = MCM_CALLBACK_RES;

  num_times_my_callback_called++;

  if (mc_res_attempted(res) == 1)
    num_attempted++;

  if (mc_res_found(res) == 1)
    num_found++;
}


void
test_callback(struct memcache *mc, const u_int32_t count) {
  struct memcache_res *res1, *res2;
  struct memcache_req *req;
  u_int32_t i;

  mc_set(mc, "callback", MCM_CSTRLEN("callback"), "foobar", (size_t)MCM_CSTRLEN("foobar"), 0, 0);

  req = mc_req_new();
  res1 = mc_req_add(req, "callback", MCM_CSTRLEN("callback"));
  res1->size = MCM_CSTRLEN("foobar");
  res1->val = malloc(res1->size);
  mc_res_free_on_delete(res1, 1);
  mc_res_register_fetch_cb(req, res1, my_callback, NULL);

  res2 = mc_req_add(req, "does_not_exist", MCM_CSTRLEN("does_not_exist"));
  mc_res_register_fetch_cb(req, res2, my_callback, NULL);

  for (i = count; i > 0; i--) {
    mc_get(mc, req);
  }

  mc_req_free(req);
}
