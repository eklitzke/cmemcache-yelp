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

static int32_t			 err_func(MCM_ERR_FUNC_SIG);
static void                     *server_find(const void *ctxt, void *mc, const u_int32_t hash);
static u_int32_t		 hash_key(const void *ctxt, const char *key, const size_t len);


static int32_t
err_func(MCM_ERR_FUNC_ARGS) {
  const struct memcache_ctxt *ctxt;
  struct memcache_err_ctxt *ectxt;
  const char *errno_str, *severity;
  struct timeval tv;

  MCM_ERR_INIT_CTXT(ctxt, ectxt);

  if (ectxt->errnum != 0)
    errno_str = strerror(ectxt->errnum);
  else
    errno_str = NULL;

  switch (ectxt->severity) {
  case MCM_ERR_LVL_INFO:
    severity = "INFO";
    break;
  case MCM_ERR_LVL_NOTICE:
    severity = "NOTICE";
    break;
  case MCM_ERR_LVL_WARN:
    severity = "WARN";
    break;
  case MCM_ERR_LVL_ERR:
    severity = "ERROR";
    break;
  case MCM_ERR_LVL_FATAL:
    severity = "FATAL";
    break;
  default:
    severity = "UNKNOWN";
  }

  /*
   * Quick explaination of the various bits of text:
   *
   * ectxt->errmsg - per error message passed along via one of the MCM_*_MSG() macros (optional)
   * ectxt->errstr - memcache(3) error string (optional, though almost always set)
   * errno_str - errno error string (optional)
   */
  if (gettimeofday(&tv, NULL) != 0) {
    tv.tv_sec = 0;
    tv.tv_usec = 0;
  }

  switch (ectxt->errcode) {
  case MCM_ERR_MC_SERV_LIST:
    warnx("Server list lookup failed, calling bailout/rebuild server code");
    exit(1);
    break;
    /* Other handling for various error codes. */
  }

  if (ectxt->errmsg != NULL && errno_str != NULL && ectxt->errmsg != NULL)
    fprintf(stderr, "[%s@%d.%06d] %s():%u: %s: %s: %.*s\n", severity, (int)tv.tv_sec, (int)tv.tv_usec, ectxt->funcname, ectxt->lineno, ectxt->errstr, errno_str, (int)ectxt->errlen, ectxt->errmsg);
  else if (ectxt->errmsg == NULL && errno_str != NULL && ectxt->errmsg != NULL)
    fprintf(stderr, "[%s@%d.%06d] %s():%u: %s: %.*s\n", severity, (int)tv.tv_sec, (int)tv.tv_usec, ectxt->funcname, ectxt->lineno, errno_str, (int)ectxt->errlen, ectxt->errmsg);
  else if (ectxt->errmsg != NULL && errno_str == NULL && ectxt->errmsg != NULL)
    fprintf(stderr, "[%s@%d.%06d] %s():%u: %s: %.*s\n", severity, (int)tv.tv_sec, (int)tv.tv_usec, ectxt->funcname, ectxt->lineno, ectxt->errstr, (int)ectxt->errlen, ectxt->errmsg);
  else if (ectxt->errmsg != NULL && errno_str != NULL && ectxt->errmsg == NULL)
    fprintf(stderr, "[%s@%d.%06d] %s():%u: %s: %s\n", severity, (int)tv.tv_sec, (int)tv.tv_usec, ectxt->funcname, ectxt->lineno, errno_str, ectxt->errstr);
  else if (ectxt->errmsg == NULL && errno_str == NULL && ectxt->errmsg != NULL)
    fprintf(stderr, "[%s@%d.%06d] %s():%u: %.*s\n", severity, (int)tv.tv_sec, (int)tv.tv_usec, ectxt->funcname, ectxt->lineno, (int)ectxt->errlen, ectxt->errmsg);
  else if (ectxt->errmsg == NULL && errno_str != NULL && ectxt->errmsg == NULL)
    fprintf(stderr, "[%s@%d.%06d] %s():%u: %s\n", severity, (int)tv.tv_sec, (int)tv.tv_usec, ectxt->funcname, ectxt->lineno, errno_str);
  else if (ectxt->errmsg != NULL && errno_str == NULL && ectxt->errmsg == NULL)
    fprintf(stderr, "[%s@%d.%06d] %s():%u: %s\n", severity, (int)tv.tv_sec, (int)tv.tv_usec, ectxt->funcname, ectxt->lineno, ectxt->errmsg);
  else
    fprintf(stderr, "[%s@%d.%06d] %s():%u\n", severity, (int)tv.tv_sec, (int)tv.tv_usec, ectxt->funcname, ectxt->lineno);

  return 0;
}


static u_int32_t
hash_key(const void *ctxt, const char *key, const size_t len) {
  static int ret = 0;

  fprintf(stderr, "Hash value: %d\n", ret);
  return ret++;
}


static void *
server_find(const void *ctxt_void, void *mc_void, const u_int32_t hash) {
  struct memcache_server *ret;
  struct memcache *mc;

  mc = (struct memcache *)mc_void;

  ret = mc->servers[hash % mc->num_servers];
  if (ret->active == 'd') {
    ret = NULL;
  }

  if (ret != NULL) {
    ret->_last_hash = hash;
    fprintf(stderr, "Testing server %p (%s:%s)\n", (void *)ret, ret->hostname, ret->port);
  }
  return ret;
}


int
main(int argc, char *argv[]) {
  struct memcache *mc = NULL;
  struct memcache_ctxt *ctxt;

  mc = mc_new();
  if (mc == NULL)
    err(EX_OSERR, "Unable to allocate a new memcache object");
  ctxt = mc_global_ctxt();

  mcm_err_filter_del(ctxt, MCM_ERR_LVL_INFO);
  mcm_err_filter_del(ctxt, MCM_ERR_LVL_NOTICE);

  ctxt->mcErr = err_func;
  ctxt->mcHashKey = hash_key;
  ctxt->mcServerFind = server_find;

  mc_server_add4(mc, "localhost:11212");
  mc_server_add4(mc, "localhost:11211");
  mc_server_add4(mc, "localhost:11213");

  mc_set(mc, "key1", MCM_CSTRLEN("key1"), "val1", MCM_CSTRLEN("val1"), 0, 0);
  mc_set(mc, "key2", MCM_CSTRLEN("key2"), "val2", MCM_CSTRLEN("val2"), 0, 0);
  mc_set(mc, "key3", MCM_CSTRLEN("key3"), "val3", MCM_CSTRLEN("val3"), 0, 0);

  mc_free(mc);

  return EX_OK;
}
