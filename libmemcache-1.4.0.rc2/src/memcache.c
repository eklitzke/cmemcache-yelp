/*
 * Copyright (c) 2004-2005 Sean Chittenden <sean@chittenden.org>
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

/* The crc32 functions and data was originally written by Spencer
 * Garrett <srg@quick.com> and was cleaned from the PostgreSQL source
 * tree via the files contrib/ltree/crc32.[ch].  No license was
 * included, therefore it is assumed that this code is public
 * domain.  Attribution still noted. */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <errno.h>
#include <sys/types.h>
#ifdef __linux
# ifndef __USE_POSIX
#  define __USE_POSIX
#warning "Working around busted-ass Linux header include problems: use FreeBSD instead"
#warning "http://www.FreeBSD.org/ - you won't regret it"
# endif
#endif
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

#define __MEMCACHE__
# include "memcache.h"
# include "memcache/buffer.h"
#undef __MEMCACHE__

#ifdef MAX
# undef MAX
#endif
#define MAX(a,b) (((a)>(b))?(a):(b))

#ifdef MIN
# undef MIN
#endif
#define MIN(a,b) (((a)<(b))?(a):(b))


/* Prototypes for static functions that are mcm_*() safe, but don't
 * require a memory context. */
static void			 mcm_server_init(const struct memcache_ctxt *ctxt, struct memcache_server *ms);

/* Prototypes for static functions that require a memory context */
static u_int32_t		 mcm_atomic_cmd(struct memcache_ctxt *ctxt, struct memcache *mc,
						const char *cmd, const size_t cmd_len,
						char *key, const size_t key_len, const u_int32_t val);
static int32_t			 mcm_err_func(MCM_ERR_FUNC_SIG);
static void			 mcm_fetch_cmd(struct memcache_ctxt *ctxt, struct memcache *mc,
					       struct memcache_req *req, const char *cmd, const size_t cmd_len);
static char			*mcm_get_line(struct memcache_ctxt *ctxt, struct memcache *mc,
					      struct memcache_server *ms);
static u_int32_t		 mcm_hash_key_func(MCM_HASH_SIG);
static size_t			 mcm_read_fd(struct memcache_ctxt *ctxt, struct memcache *mc, struct memcache_server *ms, char *buf, size_t bytes);
static void			 mcm_res_cb_free(struct memcache_req *req, struct memcache_res_cb *cb);
static struct memcache_res	*mcm_res_new(const struct memcache_ctxt *ctxt);
static int			 mcm_server_connect(struct memcache_ctxt *ctxt, struct memcache *mc, struct memcache_server *ms);
static struct memcache_server	*mcm_server_connect_next_avail(struct memcache_ctxt *ctxt, struct memcache *mc, const u_int32_t hash);
static void			*mcm_server_find_func(const void *ctxt, void *mc, const u_int32_t hash);
static int			 mcm_server_readable(struct memcache_ctxt *ctxt, struct memcache_server *ms, struct timeval *tv);
static int			 mcm_server_resolve(struct memcache_ctxt *ctxt, struct memcache_server *ms);
static size_t			 mcm_server_send_cmd(struct memcache_ctxt *ctxt, struct memcache *mc, struct memcache_server *ms);
inline static ssize_t		 mcm_server_send_last_cmd(struct memcache_ctxt *ctxt, struct memcache *mc, struct memcache_server *ms);
static struct memcache_server_stats	*mcm_server_stats_new(const struct memcache_ctxt *ctxt);
static int			 mcm_server_writable(struct memcache_ctxt *ctxt, struct memcache_server *ms, struct timeval *tv);
static int			 mcm_storage_cmd(struct memcache_ctxt *ctxt, struct memcache *mc,
						 const char *cmd, const size_t cmd_len,
						 char *key, const size_t key_len,
						 const void *val, const size_t bytes,
						 const time_t expire, const u_int16_t flags);
inline static int32_t		 mcm_validate_key(const struct memcache_ctxt *ctxt, char *key, size_t len);
static int32_t			 mcm_validate_key_func(MCM_KEY_VALID_FUNC_SIG);

/* Simple macro to test the input of keys. */
#define MCM_VALIDATE_KEY(_key, _len)	do { int32_t _validate_ret; \
	_validate_ret = mcm_validate_key(ctxt, _key, _len); \
	if (_validate_ret != 0) return _validate_ret; \
} while(0);

#define MCM_VALIDATE_KEY_RET(_key, _len, _ret)	do { int32_t _validate_ret; \
	_validate_ret = mcm_validate_key(ctxt, _key, _len); \
	if (_validate_ret != 0) return _ret; \
} while(0);

#define MCM_CLEAN_BUFS(ctxt, ms) do { \
	if (ms->rbuf->off == ms->rbuf->len) \
		mcm_buf_reset(ctxt, ms->rbuf); \
	if (ms->wbuf->off == ms->wbuf->len) \
		mcm_buf_reset(ctxt, ms->wbuf); \
} while(0)


/* This is kinda ugly, but, it saves on some warnings and a tad of
 * stack space across the library. Note, remember strlen(3) does not
 * include the trailing null character, but sizeoof() does, so when
 * computing the sizeof() commands, subtract one from its return. */
static const char	str_add_cmd[] = "add ";
static const size_t	str_add_len = MCM_CSTRLEN(str_add_cmd);
static const char	str_decr_cmd[] = "decr ";
static const size_t	str_decr_len = MCM_CSTRLEN(str_decr_cmd);
static const char	str_delete_cmd[] = "delete ";
static const size_t	str_delete_len = MCM_CSTRLEN(str_delete_cmd);
static const char	str_endl[] = "\r\n";
static const size_t	str_endl_len = MCM_CSTRLEN(str_endl);
static const char	str_get_cmd[] = "get ";
static const size_t	str_get_len = MCM_CSTRLEN(str_get_cmd);
static const char	str_incr_cmd[] = "incr ";
static const size_t	str_incr_len = MCM_CSTRLEN(str_incr_cmd);
#ifdef SEAN_HACKS
static const char	str_listen_cmd[] = "listen ";
static const size_t	str_listen_len = MCM_CSTRLEN(str_listen_cmd);
static const char	str_refresh_cmd[] = "refresh ";
static const size_t	str_refresh_len = MCM_CSTRLEN(str_refresh_cmd);
#endif
static const char	str_replace_cmd[] = "replace ";
static const size_t	str_replace_len = MCM_CSTRLEN(str_replace_cmd);
static const char	str_set_cmd[] = "set ";
static const size_t	str_set_len = MCM_CSTRLEN(str_set_cmd);
static const char	str_space[] = " ";
static const size_t	str_space_len = MCM_CSTRLEN(str_space);


/* Set the default error handling context. */
static struct memcache_err_ctxt mcGlobalECtxt;

/* Set the default memory handling routines to be system defaults. */
static struct memcache_ctxt mcGlobalCtxt = {
  (mcFreeFunc)free,
  (mcMallocFunc)malloc,
  (mcMallocFunc)malloc,
  (mcReallocFunc)realloc,
  (mcErrFunc)mcm_err_func,
  (mcKeyValidFunc)mcm_validate_key_func,
  (mcHashKeyFunc)mcm_hash_key_func,
  (mcServerFindFunc)mcm_server_find_func,
  (u_int32_t)0,
  (struct memcache_buf *)NULL,
  (struct memcache_buf *)NULL,
  (u_int32_t)0,
  (struct memcache_err_ctxt *)&mcGlobalECtxt,
  (u_int32_t)0
};


int
mc_add(struct memcache *mc,
       char *key, const size_t key_len,
       const void *val, const size_t bytes,
       const time_t expire, const u_int16_t flags) {
  return mcm_storage_cmd(&mcGlobalCtxt, mc, str_add_cmd, str_add_len, key, key_len, val, bytes, expire, flags);
}


void *
mc_aget(struct memcache *mc, char *key, const size_t len) {
  return mcm_aget(&mcGlobalCtxt, mc, key, len);
}


void *
mc_aget2(struct memcache *mc, char *key, const size_t len, size_t *retlen) {
  return mcm_aget2(&mcGlobalCtxt, mc, key, len, retlen);
}


#ifdef SEAN_HACKS
void *
mc_alisten(struct memcache *mc, char *key, const size_t len) {
  return mcm_alisten(&mcGlobalCtxt, mc, key, len);
}


void *
mc_arefresh(struct memcache *mc, char *key, const size_t len) {
  return mcm_arefresh(&mcGlobalCtxt, mc, key, len);
}
#endif


u_int32_t
mc_decr(struct memcache *mc, char *key, const size_t key_len, const u_int32_t val) {
  return mcm_atomic_cmd(&mcGlobalCtxt, mc, str_decr_cmd, str_decr_len, key, key_len, val);
}


int
mc_delete(struct memcache *mc, char *key, const size_t key_len, const time_t hold) {
  return mcm_delete(&mcGlobalCtxt, mc, key, key_len, hold);
}


int
mc_err_filter_add(const u_int32_t err_mask) {
  return mcm_err_filter_add(&mcGlobalCtxt, err_mask);
}


int
mc_err_filter_del(const u_int32_t err_mask) {
  return mcm_err_filter_del(&mcGlobalCtxt, err_mask);
}


u_int32_t
mc_err_filter_get(void) {
  return mcm_err_filter_get(&mcGlobalCtxt);
}


int
mc_err_filter_test(const u_int32_t err_lvl) {
  return mcm_err_filter_test(&mcGlobalCtxt, err_lvl);
}


void
mc_err_test(void) {
  mcm_err_test(&mcGlobalCtxt);
}


int
mc_flush(struct memcache *mc, struct memcache_server *ms) {
  return mcm_flush(&mcGlobalCtxt, mc, ms);
}


int
mc_flush_all(struct memcache *mc) {
  return mcm_flush_all(&mcGlobalCtxt, mc);
}


void
mc_free(struct memcache *mc) {
  mcm_free(&mcGlobalCtxt, mc);
}


void
mc_get(struct memcache *mc, struct memcache_req *req) {
  mcm_get(&mcGlobalCtxt, mc, req);
}


inline struct memcache_ctxt *
mc_global_ctxt(void) {
  return &mcGlobalCtxt;
}


u_int32_t
mc_hash(const struct memcache *mc, const char *key, const size_t len) {
  return mcGlobalCtxt.mcHashKey(&mcGlobalCtxt, mc, key, len);
}


u_int32_t
mc_hash_key(const char *key, const size_t len) {
  return mcGlobalCtxt.mcHashKey(&mcGlobalCtxt, NULL, key, len);
}


u_int32_t
mc_incr(struct memcache *mc, char *key, const size_t key_len, const u_int32_t val) {
  return mcm_atomic_cmd(&mcGlobalCtxt, mc, str_incr_cmd, str_incr_len, key, key_len, val);
}


struct memcache *
mc_new(void) {
  return mcm_new(&mcGlobalCtxt);
}


#ifdef SEAN_HACKS
void
mc_listen(struct memcache *mc, struct memcache_req *req) {
  mcm_fetch_cmd(&mcGlobalCtxt, mc, req, str_listen_cmd, str_listen_len);
}


void
mc_refresh(struct memcache *mc, struct memcache_req *req) {
  mcm_fetch_cmd(&mcGlobalCtxt, mc, req, str_refresh_cmd, str_refresh_len);
}
#endif


u_int32_t
mc_reldate(void) {
  return MEMCACHE_RELDATE;
}


int
mc_replace(struct memcache *mc,
	   char *key, const size_t key_len,
	   const void *val, const size_t bytes,
	   const time_t expire, const u_int16_t flags) {
  return mcm_storage_cmd(&mcGlobalCtxt, mc, str_replace_cmd, str_replace_len, key, key_len, val, bytes, expire, flags);
}


struct memcache_res *
mc_req_add(struct memcache_req *req, char *key, const size_t len) {
  return mcm_req_add(&mcGlobalCtxt, req, key, len);
}


struct memcache_res *
mc_req_add_ref(struct memcache_req *req, char *key, const size_t len) {
  return mcm_req_add_ref(&mcGlobalCtxt, req, key, len);
}


void
mc_req_free(struct memcache_req *req) {
  mcm_req_free(&mcGlobalCtxt, req);
}


struct memcache_req *
mc_req_new(void) {
  return mcm_req_new(&mcGlobalCtxt);
}


int
mc_res_attempted(const struct memcache_res *res) {
  return mcm_res_attempted(&mcGlobalCtxt, res);
}


int
mc_res_found(const struct memcache_res *res) {
  return mcm_res_found(&mcGlobalCtxt, res);
}


void
mc_res_free(struct memcache_req *req, struct memcache_res *res) {
  mcm_res_free(&mcGlobalCtxt, req, res);
}


void
mc_res_free_on_delete(struct memcache_res *res, const int fod) {
  mcm_res_free_on_delete(&mcGlobalCtxt, res, fod);
}


int
mc_res_register_fetch_cb(struct memcache_req *req, struct memcache_res *res,
			 mcResCallback cb, void *misc) {
  return mcm_res_register_fetch_cb(&mcGlobalCtxt, req, res, cb, misc);
}


int
mc_server_activate(struct memcache *mc, struct memcache_server *ms) {
  return mcm_server_activate(&mcGlobalCtxt, mc, ms);
}


int
mc_server_activate_all(struct memcache *mc) {
  return mcm_server_activate_all(&mcGlobalCtxt, mc);
}


int
mc_server_add(struct memcache *mc, const char *hostname, const char *port) {
  return mcm_server_add2(&mcGlobalCtxt, mc, hostname, (hostname != NULL ? strlen(hostname) : 0), port, (port != NULL ? strlen(port) : 0));
}


int
mc_server_add2(struct memcache *mc, const char *hostname, const size_t hostname_len,
	       const char *port, const size_t port_len) {
  return mcm_server_add2(&mcGlobalCtxt, mc, hostname, hostname_len, port, port_len);
}


int
mc_server_add3(struct memcache *mc, struct memcache_server *ms) {
  return mcm_server_add3(&mcGlobalCtxt, mc, ms);
}


int
mc_server_add4(struct memcache *mc, mc_const char *hostport) {
  return mcm_server_add5(&mcGlobalCtxt, mc, hostport, (hostport != NULL ? strlen(hostport) : 0));
}


int
mc_server_add5(struct memcache *mc, mc_const char *hostport, const size_t hostlen) {
  return mcm_server_add5(&mcGlobalCtxt, mc, hostport, hostlen);
}


void
mc_server_deactivate(struct memcache *mc, struct memcache_server *ms) {
  mcm_server_deactivate(&mcGlobalCtxt, mc, ms);
}


void
mc_server_disconnect(struct memcache_server *ms) {
  mcm_server_disconnect(&mcGlobalCtxt, ms);
}


void
mc_server_disconnect_all(const struct memcache *mc) {
  mcm_server_disconnect_all(&mcGlobalCtxt, mc);
}


struct memcache_server *
mc_server_find(struct memcache *mc, const u_int32_t hash) {
  return (struct memcache_server *)mcGlobalCtxt.mcServerFind(&mcGlobalCtxt, mc, hash);
}


void
mc_server_free(struct memcache_server *ms) {
  mcm_server_free(&mcGlobalCtxt, ms);
}


struct memcache_server *
mc_server_new(void) {
  return mcm_server_new(&mcGlobalCtxt);
}


struct memcache_server_stats *
mc_server_stats(struct memcache *mc, struct memcache_server *ms) {
  return mcm_server_stats(&mcGlobalCtxt, mc, ms);
}


int
mc_server_timeout(struct memcache_server *ms, const int sec, const int msec) {
  return mcm_server_timeout(&mcGlobalCtxt, ms, sec, msec);
}


void
mc_server_stats_free(struct memcache_server_stats *s) {
  mcm_server_stats_free(&mcGlobalCtxt, s);
}


int
mc_set(struct memcache *mc,
       char *key, const size_t key_len,
       const void *val, const size_t bytes,
       const time_t expire, const u_int16_t flags) {
  return mcm_storage_cmd(&mcGlobalCtxt, mc, str_set_cmd, str_set_len, key, key_len, val, bytes, expire, flags);
}


struct memcache_server_stats *
mc_stats(struct memcache *mc) {
  return mcm_stats(&mcGlobalCtxt, mc);
}


char *
mc_strdup(const char *str) {
  return mcm_strndup(&mcGlobalCtxt, str, strlen(str));
}


char *
mc_strnchr(mc_const char *str, const int c, const size_t len) {
  return mcm_strnchr(&mcGlobalCtxt, str, c, len);
}


char *
mc_strndup(const char *str, const size_t len) {
  return mcm_strndup(&mcGlobalCtxt, str, len);
}


void
mc_timeout(struct memcache *mc, const int sec, const int msec) {
  mcm_timeout(&mcGlobalCtxt, mc, sec, msec);
}


u_int32_t
mc_vernum(void) {
  return MEMCACHE_VERNUM;
}


const char *
mc_version(void) {
  return MEMCACHE_VER;
}
/* END OF THE SINGLE MEMORY CONTEXT API CALLS (ie: mc_*()) */


/* BEGIN MEMORY CONTEXT API (ie: mcm_*())  */
int
mcm_add(struct memcache_ctxt *ctxt, struct memcache *mc,
	char *key, const size_t key_len,
	const void *val, const size_t bytes,
	const time_t expire, const u_int16_t flags) {
  return mcm_storage_cmd(ctxt, mc, str_add_cmd, str_add_len, key, key_len, val, bytes, expire, flags);
}


/* Issues a "get" command to the memcache server that should contain
 * the key.  The result is mcMalloc(3)'ed and it is assumed that the
 * caller is required to mcFree(3) the memory. */
void *
mcm_aget(struct memcache_ctxt *ctxt, struct memcache *mc, char *key, const size_t len) {
  return mcm_aget2(ctxt, mc, key, len, NULL);
}


/* Issues a "get" command to the memcache server that should contain
 * the key.  The result is mcMalloc(3)'ed and it is assumed that the
 * caller is required to mcFree(3) the memory. */
void *
mcm_aget2(struct memcache_ctxt *ctxt, struct memcache *mc, char *key, const size_t len, size_t *retlen) {
  struct memcache_req *req;
  struct memcache_res *res;
  void *ret;

  MCM_VALIDATE_KEY_RET(key, len, NULL);
  req = mcm_req_new(ctxt);
  res = mcm_req_add_ref(ctxt, req, key, len);
  mcm_res_free_on_delete(ctxt, res, 0);
  mcm_get(ctxt, mc, req);
  if (retlen != NULL)
    *retlen = res->bytes;
  ret = res->val;
  mcm_req_free(ctxt, req);
  return ret;
}


#ifdef SEAN_HACKS
void *
mcm_alisten(struct memcache_ctxt *ctxt, struct memcache *mc, char *key, const size_t len) {
  struct memcache_req *req;
  struct memcache_res *res;
  void *ret;

  MCM_VALIDATE_KEY(key, len);
  req = mcm_req_new(ctxt);
  res = mcm_req_add_ref(ctxt, req, key, len);
  mcm_res_free_on_delete(ctxt, res, 0);
  mcm_listen(ctxt, mc, req);
  ret = res->val;
  mcm_req_free(ctxt, req);
  return ret;
}


/* Issues a "refresh" command to the memcache server that should
 * contain the key.  The result is mcMalloc(3)'ed and it is assumed
 * that the caller is required to mcFree(3) the memory. */
void *
mcm_arefresh(struct memcache_ctxt *ctxt, struct memcache *mc, char *key, const size_t len) {
  struct memcache_req *req;
  struct memcache_res *res;
  void *ret;

  MCM_VALIDATE_KEY(key, len);
  req = mcm_req_new(ctxt);
  res = mcm_req_add_ref(ctxt, req, key, len);
  mcm_res_free_on_delete(ctxt, res, 0);
  mcm_refresh(ctxt, mc, req);
  ret = res->val;
  mcm_req_free(ctxt, req);
  return ret;
}
#endif


static u_int32_t
mcm_atomic_cmd(struct memcache_ctxt *ctxt, struct memcache *mc,
	       const char *cmd, const size_t cmd_len,
	       char *key, const size_t key_len, const u_int32_t val) {
  struct memcache_server *ms;
  u_int32_t hash;
  char *cp, *cur;
  size_t i;
  u_int32_t ret;
  char numbuf[11]; /* 10 == (2 ** 32).to_s.length + '\0'.length */

  /* Reset errnum on re-entry into memcache(3). */
  ctxt->errnum = 0;

  MCM_VALIDATE_KEY(key, key_len);

  hash = ctxt->mcHashKey(ctxt, mc, key, key_len);

  ms = mcm_server_connect_next_avail(ctxt, mc, hash);
  if (ms == NULL) {
    MCM_ERRX(MCM_ERR_MC_VALID_SERVER);
    return (u_int32_t)MCM_RET_CODE(0);
  }

  mcm_buf_append(ctxt, ms->wbuf, cmd, cmd_len);
  mcm_buf_append(ctxt, ms->wbuf, key, key_len);
  mcm_buf_append_char(ctxt, ms->wbuf, ' ');

  /* Convert the value to a string */
  i = (size_t)snprintf(numbuf, sizeof(numbuf), "%u", val);
  if (i < 1) {
    MCM_ERR(MCM_ERR_LIB_SNPRINTF);
    MCM_CLEAN_BUFS(ctxt, ms);
    return (u_int32_t)MCM_RET_CODE(0);
  }

  mcm_buf_append(ctxt, ms->wbuf, numbuf, i);
  mcm_buf_append(ctxt, ms->wbuf, str_endl, str_endl_len);

  /* Send the command */
  if (mcm_server_send_cmd(ctxt, mc, ms) < 0) {
    MCM_CLEAN_BUFS(ctxt, ms);
    return 0;
  }

  cur = mcm_get_line(ctxt, mc, ms);
  if (cur != NULL && memcmp(cur, "NOT_FOUND", MCM_CSTRLEN("NOT_FOUND")) == 0) {
    ctxt->errnum = ENOENT;
    MCM_CLEAN_BUFS(ctxt, ms);
    return (u_int32_t)MCM_RET_CODE(0);
  } else if (cur == NULL) {
    MCM_CLEAN_BUFS(ctxt, ms);
    return (u_int32_t)MCM_RET_CODE(0);
  }


  /* Try converting the value to an integer. If it succeeds, we've got
   * a winner. */
  ret = (u_int32_t)strtol(cur, &cp, 10);
  if (ret == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
    MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "strtol(3) failed");
    MCM_CLEAN_BUFS(ctxt, ms);
    return (u_int32_t)MCM_RET_CODE(0);
  }

#ifdef DEBUG_MC_PROTO_ASSERT
  if (*cp != '\r') {
    MCM_ERRX(MCM_ERR_PROTO);
    MCM_CLEAN_BUFS(ctxt, ms);
    return (u_int32_t)MCM_RET_CODE(0);
  }
#endif

  MCM_CLEAN_BUFS(ctxt, ms);
  return ret;
}


u_int32_t
mcm_decr(struct memcache_ctxt *ctxt, struct memcache *mc, char *key, const size_t key_len, const u_int32_t val) {
  return mcm_atomic_cmd(ctxt, mc, str_decr_cmd, str_decr_len, key, key_len, val);
}


int
mcm_delete(struct memcache_ctxt *ctxt, struct memcache *mc,
	   char *key, const size_t key_len, const time_t hold) {
  struct memcache_server *ms;
  u_int32_t hash;
  char *cp;
  size_t i;
  char numbuf[11]; /* 10 == (2 ** 32).to_s.length + '\0'.length */

  MCM_VALIDATE_KEY(key, key_len);

  /* Reset ctxt->errnum upon entry into memcache(3). */
  ctxt->errnum = 0;

  hash = ctxt->mcHashKey(ctxt, mc, key, key_len);

  ms = mcm_server_connect_next_avail(ctxt, mc, hash);
  if (ms == NULL)
    return (int)MCM_RET_CODE(-1);

  mcm_buf_append(ctxt, ms->wbuf, str_delete_cmd, str_delete_len);
  mcm_buf_append(ctxt, ms->wbuf, key, key_len);

  /* Only send the hold timer if the value is greater than zero */
  if (hold != 0) {
    mcm_buf_append_char(ctxt, ms->wbuf, ' ');
    /* Convert the value to a string */
    i = (size_t)snprintf(numbuf, sizeof(numbuf), "%u", (u_int32_t)hold);
    if (i < 1) {
      MCM_ERR(MCM_ERR_LIB_SNPRINTF);
      MCM_CLEAN_BUFS(ctxt, ms);
      return (int)MCM_RET_CODE(-4);
    }

    mcm_buf_append(ctxt, ms->wbuf, numbuf, i);
  }

  mcm_buf_append(ctxt, ms->wbuf, str_endl, str_endl_len);

  if (mcm_server_send_cmd(ctxt, mc, ms) < 0) {
    MCM_CLEAN_BUFS(ctxt, ms);
    return (int)MCM_RET_CODE(-3);
  }

  cp = mcm_get_line(ctxt, mc, ms);
  if (cp != NULL && memcmp(cp, "DELETED", MCM_CSTRLEN("DELETED")) == 0) {
    MCM_CLEAN_BUFS(ctxt, ms);
    return 0;
  } else if (cp != NULL && memcmp(cp, "NOT_FOUND", MCM_CSTRLEN("NOT_FOUND")) == 0) {
    MCM_CLEAN_BUFS(ctxt, ms);
    return 1;
  } else {
    MCM_ERRX_MSG(MCM_ERR_PROTO, cp);
    MCM_CLEAN_BUFS(ctxt, ms);
    return (int)MCM_RET_CODE(-5);
  }
}


void
mcm_err(const struct memcache_ctxt *ctxt, const u_int32_t flags, const char *funcname, const u_int32_t lineno,
	const u_int32_t errcode, const char *msg, const u_int32_t msglen, const u_int32_t errlvl) {
  struct memcache_err_ctxt *ectxt;

  bzero(ctxt->ectxt, sizeof(struct memcache_err_ctxt));
  ectxt = ctxt->ectxt;

  ectxt->ctxt = ctxt;
  ectxt->funcname = funcname;
  ectxt->lineno = lineno;
  ectxt->errnum = ((flags & NO_ERRNO_FLAG) ? 0 : errno);
  ectxt->errcode = errcode;
  ectxt->errmsg = msg;
  ectxt->errlen = msglen;

  /* Collect all error handling into one place and dispatch handlers
   * from here. */
  switch(errcode) {
  case MCM_ERR_NONE:
    ectxt->errstr = "no error";
    ectxt->severity = MCM_ERR_LVL_NONE;
    ectxt->sysexit = EX_OK;
    break;
  case MCM_ERR_ASSERT:
    ectxt->errstr = "internal memcache(3) assertion";
    ectxt->severity = MCM_ERR_LVL_FATAL;
    ectxt->sysexit = EX_SOFTWARE;
    break;
  case MCM_ERR_LIB_SNPRINTF:
    ectxt->errstr = "snprintf(3) failed to convert the value to a string";
    ectxt->severity = MCM_ERR_LVL_ERR;
    ectxt->sysexit = EX_DATAERR;
    break;
  case MCM_ERR_LIB_STRTOL:
    ectxt->errstr = "strtol(3) failed";
    ectxt->severity = MCM_ERR_LVL_ERR;
    ectxt->sysexit = EX_DATAERR;
    break;
  case MCM_ERR_LIB_STRTOLL:
    ectxt->errstr = "strtoll(3) failed";
    ectxt->severity = MCM_ERR_LVL_ERR;
    ectxt->sysexit = EX_DATAERR;
    break;
  case MCM_ERR_MC_RECONN:
    ectxt->errstr = "connection re-established with server";
    ectxt->severity = MCM_ERR_LVL_INFO;
    ectxt->sysexit = EX_OK;
    break;
  case MCM_ERR_MC_SEND_CMD:
    ectxt->errstr = "failed to send command to the memcache server";
    ectxt->severity = MCM_ERR_LVL_NOTICE;
    ectxt->sysexit = EX_IOERR;
    break;
  case MCM_ERR_MC_SERV_LIST:
    ectxt->errstr = "no available servers in server list";
    ectxt->severity = MCM_ERR_LVL_WARN;
    ectxt->sysexit = EX_DATAERR;
    break;
  case MCM_ERR_MC_STORE:
    ectxt->errstr = "unable to store value";
    ectxt->severity = MCM_ERR_LVL_NOTICE;
    ectxt->sysexit = EX_CANTCREAT;
    break;
  case MCM_ERR_MC_VALID_SERVER:
    ectxt->errstr = "unable to find a server to connect to";
    ectxt->severity = MCM_ERR_LVL_NOTICE;
    ectxt->sysexit = EX_UNAVAILABLE;
    break;
  case MCM_ERR_MEM_MALLOC:
    ectxt->errstr = "mcMalloc(3) failed";
    ectxt->severity = MCM_ERR_LVL_ERR;
    ectxt->sysexit = EX_OSERR;
    break;
  case MCM_ERR_MEM_REALLOC:
    ectxt->errstr = "mcRealloc(3) failed";
    ectxt->severity = MCM_ERR_LVL_ERR;
    ectxt->sysexit = EX_OSERR;
    break;
  case MCM_ERR_NET_CONNECT:
    ectxt->errstr = "unable to connect to a server";
    ectxt->severity = MCM_ERR_LVL_NOTICE;
    ectxt->sysexit = EX_TEMPFAIL;
    break;
  case MCM_ERR_NET_HOST:
    ectxt->errstr = "unable to lookup/resolve host";
    ectxt->severity = MCM_ERR_LVL_WARN;
    ectxt->sysexit = EX_NOHOST;
    break;
  case MCM_ERR_PROTO:
    ectxt->errstr = "memcache(4) protocol error";
    ectxt->severity = MCM_ERR_LVL_FATAL;
    ectxt->sysexit = EX_PROTOCOL;
    break;
  case MCM_ERR_SYS_CLOSE:
    ectxt->errstr = "close(2) failed";
    ectxt->severity = MCM_ERR_LVL_ERR;
    ectxt->sysexit = EX_OSERR;
    break;
  case MCM_ERR_SYS_CONNECT:
    ectxt->errstr = "connect(2) failed";
    ectxt->severity = MCM_ERR_LVL_NOTICE;
    ectxt->sysexit = EX_OSERR;
    break;
  case MCM_ERR_SYS_FCNTL:
    ectxt->errstr = "unable to get or set file descriptor status";
    ectxt->severity = MCM_ERR_LVL_ERR;
    ectxt->sysexit = EX_OSERR;
    break;
  case MCM_ERR_SYS_READ:
    ectxt->errstr = "read(2) failed";
    ectxt->severity = MCM_ERR_LVL_ERR;
    ectxt->sysexit = EX_OSERR;
    break;
  case MCM_ERR_SYS_SELECT:
    ectxt->errstr = "select(2) failed";
    ectxt->severity = MCM_ERR_LVL_ERR;
    ectxt->sysexit = EX_OSERR;
    break;
  case MCM_ERR_SYS_SETSOCKOPT:
    ectxt->errstr = "setsockopt(2) failed";
    ectxt->severity = MCM_ERR_LVL_ERR;
    ectxt->sysexit = EX_OSERR;
    break;
  case MCM_ERR_SYS_SOCKET:
    ectxt->errstr = "socket(2) failed";
    ectxt->severity = MCM_ERR_LVL_ERR;
    ectxt->sysexit = EX_OSERR;
    break;
  case MCM_ERR_SYS_WRITEV:
    ectxt->errstr = "writev(2) failed";
    ectxt->severity = MCM_ERR_LVL_ERR;
    ectxt->sysexit = EX_OSERR;
  case MCM_ERR_TEST:
    ectxt->errstr = "internal memcache(3) test message";
    ectxt->severity = MCM_ERR_LVL_WARN;
    ectxt->sysexit = EX_OK;
    break;
  case MCM_ERR_TIMEOUT:
    ectxt->errstr = "timeout";
    ectxt->severity = MCM_ERR_LVL_WARN;
    ectxt->sysexit = EX_UNAVAILABLE;
    break;
  case MCM_ERR_TRACE:
    ectxt->errstr = "memcache(3) trace";
    ectxt->severity = MCM_ERR_LVL_INFO;
    ectxt->sysexit = EX_OK;
    break;
  case MCM_ERR_UNKNOWN_STAT:
    ectxt->errstr = "unknown stat variable";
    ectxt->severity = MCM_ERR_LVL_WARN;
    ectxt->sysexit = EX_PROTOCOL;
    break;
  default:
    ectxt->errstr = "unknown error code";
    ectxt->severity = MCM_ERR_LVL_FATAL;
    ectxt->sysexit = EX_SOFTWARE;
  }

  /* If we were passed in an error level, override the default
   * severity. */
  if (errlvl != 0)
    ectxt->severity = errlvl;

  /* Apply the error filter and ignore errors from levels that are
   * ignored. */
  if ((ctxt->MCM_ERR_MASK & ectxt->severity) != 0)
    return;

  /* Determine whether or not we continue running depending on the severity */
  switch (ectxt->severity) {
  case MCM_ERR_LVL_INFO:
  case MCM_ERR_LVL_NOTICE:
  case MCM_ERR_LVL_WARN:
    ectxt->cont = 'y';
    break;
  case MCM_ERR_LVL_ERR:
    ectxt->cont = 'n';
    break;
  case MCM_ERR_LVL_FATAL:
  default:
    ectxt->cont = 'a';
  }

  /* Call the user's handler.  Disregard the return value for now, but
   * have it there for future use.  *shrug* */
  if (ctxt->mcErr != NULL)
    (void)ctxt->mcErr(ctxt, ctxt->ectxt);

  /* There are a few error codes that require special cases for */
  switch (errcode) {
  case MCM_ERR_MC_SERV_LIST:
    if (ectxt->cont == 'n')
      ectxt->cont = 'y';
    break;
  }

  switch (ectxt->cont) {
  case 'y':
    /* Yes: do nothing */
    break;
  case 'n':
    /* No: exit with an error code */
    exit(ectxt->sysexit);
  case 'a':
    /* Abort: do just that, abort(3) */
  default:
    abort();
  }
}


int
mcm_err_filter_add(struct memcache_ctxt *ctxt, const u_int32_t err_mask) {
  if ((ctxt->MCM_ERR_MASK & err_mask) == ctxt->MCM_ERR_MASK)
    return 0;

  ctxt->MCM_ERR_MASK &= err_mask;
  return 1;
}


int
mcm_err_filter_del(struct memcache_ctxt *ctxt, const u_int32_t err_mask) {
  if ((ctxt->MCM_ERR_MASK & err_mask) == ctxt->MCM_ERR_MASK)
    return 0;

  ctxt->MCM_ERR_MASK &= ~err_mask;
  return 1;
}


u_int32_t
mcm_err_filter_get(const struct memcache_ctxt *ctxt) {
  return ctxt->MCM_ERR_MASK;
}


int
mcm_err_filter_test(const struct memcache_ctxt *ctxt, const u_int32_t err_lvl) {
  return(((ctxt->MCM_ERR_MASK & err_lvl) != 0) ? 1 : 0);
}


static int32_t
mcm_err_func(MCM_ERR_FUNC_ARGS) {
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
#ifdef DEBUG_MC_PROTO
    do {
      char *tm;
      size_t tml;
      tml = asprintf(&tm, "Unknown error severity: %d", ectxt->severity);
      if (tml > 0 && tm != NULL) {
	MCM_WARNX_MSG(MCM_ERR_TRACE, tm);
	free(tm);
      }
    } while(0);
#endif
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


void
mcm_err_test(const struct memcache_ctxt *ctxt) {
  MCM_WARNX(MCM_ERR_TEST, "per-error message specific to this line of code");
}


static void
mcm_fetch_cmd(struct memcache_ctxt *ctxt, struct memcache *mc, struct memcache_req *req,
	      const char *cmd, const size_t cmd_len) {
  struct memcache_res *res;
  struct memcache_res_cb *cb;
  struct memcache_server *ms;
  size_t bytes, len, remain;
  u_int16_t flags, retry;
  char *cp, *end;

  if (req->num_keys == 0)
    return;

  /* mcm_fetch_cmd() is now wrapped by mcm_get() so that a serial list
   * of fetch cmds are run and all keys are guaranteed to goto the
   * correct server. */
  res = TAILQ_FIRST(&req->query);
  if (res->hash == 0)
    res->hash = ctxt->mcHashKey(ctxt, mc, res->key, res->len);

  ms = mcm_server_connect_next_avail(ctxt, mc, res->hash);
  if (ms == NULL)
    return;

  mcm_buf_append(ctxt, ms->wbuf, cmd, cmd_len);

  TAILQ_FOREACH(res, &req->query, entries) {
    if (res->hash == 0)
      res->hash = ctxt->mcHashKey(ctxt, mc, res->key, res->len);

    mcm_buf_append(ctxt, ms->wbuf, res->key, res->len);

    if (res->entries.tqe_next != NULL)
      mcm_buf_append_char(ctxt, ms->wbuf, ' ');

    /* Even though we haven't sent the request, mark the response as
     * having been attempted. */
    res->_flags |= MCM_RES_ATTEMPTED;

    /* While we're looping, might as well see if we should be auto
     * deleting any of these keys. */
    if ((res->_flags & (MCM_RES_FREE_ON_DELETE | MCM_RES_NO_FREE_ON_DELETE)) ==
	(MCM_RES_FREE_ON_DELETE | MCM_RES_NO_FREE_ON_DELETE))
      mcm_res_free_on_delete(ctxt, res, (res->size > 0 ? 0 : 1));
  }
  mcm_buf_append(ctxt, ms->wbuf, str_endl, str_endl_len);

  /* Send the command to the server */
  if (mcm_server_send_cmd(ctxt, mc, ms) < 0) {
    MCM_CLEAN_BUFS(ctxt, ms);
    MCM_ERRX_MSG(MCM_ERR_ASSERT, "unable to send command");
    return;
  }

  while(1) {
    /* Grab a line of input from the server */
    cp = mcm_get_line(ctxt, mc, ms);
    if (cp == NULL) {
      MCM_ERRX_MSG(MCM_ERR_PROTO, "protocol, expected a response");
      return;
    }

    if (strncmp(cp, "VALUE ", MCM_CSTRLEN("VALUE ")) == 0) {
      cp += MCM_CSTRLEN("VALUE ");

      /* Find the length of the key */
      for (len = 0; cp[len] && cp[len] != ' ';len++);

      /* Find the response for this key */
      TAILQ_FOREACH(res, &req->query, entries) {
	if ((res->_flags & MCM_RES_FOUND) == 0 &&
	    len == res->len && memcmp(cp, res->key, res->len) == 0) {
	  res->_flags |= MCM_RES_FOUND;
	  break;
	}
      }

      /* Bail if we run across a situation where a VALUE comes back
       * for a key that we don't have a request for. */
      if (res == NULL) {
	MCM_ERR_MSG(MCM_ERR_PROTO, "server sent data for key not in request");
	goto cleanup;
      }

      cp += res->len + MCM_CSTRLEN(" ");

      /* Parse the flags */
      flags = (u_int16_t)strtol(cp, &end, 10);
      if (flags == 0 && ((errno == EINVAL && end == mcm_buf_off_ptr(ctxt, ms->rbuf)) || errno == ERANGE)) {
	MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid flags");
	mcm_server_deactivate(ctxt, mc, ms);
	goto cleanup;
      }
      res->flags = flags;
      cp += end - cp + MCM_CSTRLEN(" ");

      /* Parse the bytes */
      bytes = (size_t)strtol(cp, &end, 10);
      if (bytes == 0 && ((errno == EINVAL && end == mcm_buf_off_ptr(ctxt, ms->rbuf)) || errno == ERANGE)) {
	MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid bytes");
	mcm_server_deactivate(ctxt, mc, ms);
	goto cleanup;
      }
      res->bytes = bytes;
      cp += end - cp + MCM_CSTRLEN("\r\n");

      /* If necessary, allocate memory for the response */
      if (res->size == 0) {
	res->val = ctxt->mcMallocAtomic(res->bytes + MCM_CSTRLEN("\0"));
	if (res->val == NULL) {
	  MCM_ERRX_MSG(MCM_ERR_ASSERT, "memory was not allocated for res->val");
	  goto cleanup;
	}
	((char *)res->val)[res->bytes] = '\0';
	res->size = res->bytes;
      }

      /* Copy what data we can from the end of the buffer (potentially
       * all of it) into the value.  If we need to read(2) more data,
       * do so directly into the response object. */
      remain = mcm_buf_remain_off(ctxt, ms->rbuf);
      if (remain >= res->bytes && res->size >= res->bytes) {
	/* Response for key fully read(2).  We can copy the remaining
	 * data without having to read(2) it off the wire. */
	memcpy(res->val, cp, res->bytes);

	ms->rbuf->off += res->bytes;
	cp = mcm_get_line(ctxt, mc, ms);
	if (cp == NULL) {
	  MCM_ERRX(MCM_ERR_PROTO);
	  goto cleanup;
	}
      } else if (res->bytes >= res->size && remain >= res->bytes) {
	/* Response for key fully read(2).  We can only copy part of
	 * the data due to the response object's size limitation, but
	 * we still read(2) in everything off the wire for this given
	 * response. */
	memcpy(res->val, cp, res->size);

	/* Set the offset that way mcm_get_line() doesn't incorrectly
	 * scan through most of the response looking for a newline. */
	ms->rbuf->off += res->bytes;
	ms->rbuf->flags |= MCM_BUF_OFF_USED;

	/* Suck in the \r\n */
	cp = mcm_get_line(ctxt, mc, ms);
	if (cp == NULL) {
	  MCM_ERRX(MCM_ERR_PROTO);
	  goto cleanup;
	}
      } else if (res->size >= res->bytes && remain < res->bytes) {
	/* Response for key partially read(2).  We need to read(2) the
	 * remaining data off the wire and into the response object's
	 * value ptr. */
	memcpy(res->val, cp, remain);

	/* Need to read(2) the remaining data for a response */
	mcm_read_fd(ctxt, mc, ms, &((char *)res->val)[remain], res->bytes - remain);

	/* Suck in the "next" line that way we can scan past "\r\n" */
	mcm_buf_reset(ctxt, ms->rbuf);
	cp = mcm_get_line(ctxt, mc, ms);
	if (cp == NULL) {
	  MCM_ERRX_MSG(MCM_ERR_PROTO, "unable to read another line");
	  goto cleanup;
	}

#ifdef DEBUG_MC_PROTO_ASSERT
	if (memcmp(cp, "\r\n", MCM_CSTRLEN("\r\n")) != 0) {
	  MCM_ERRX(MCM_ERR_PROTO);
	  goto cleanup;
	}
#endif
      } else if (res->size < res->bytes && remain < res->size) {
	/* Response for key partially read(2).  We can only copy part
	 * of the data, and the remaining part of data is already in
	 * buffer.  Unwanted data needs to be read(2) off the fd, but
	 * needs to be discarded. */
	memcpy(res->val, cp, remain);

	/* Need to read(2) the remaining data for a response */
	mcm_read_fd(ctxt, mc, ms, &((char *)res->val)[remain], res->size - remain);

	/* Suck in remaining data and make it disappear */
	bytes = res->bytes - (res->size - remain);
	retry = 0;
	do {
	  bytes = mcm_read_fd(ctxt, mc, ms, mcm_buf_to_cstr(ctxt, ms->rbuf), mcm_buf_size(ctxt, ms->rbuf));
	  if (retry > 3)
	    break;
	  else
	    retry++;
	} while (bytes > 0);

	/* Suck in the "next" line that way we can scan past "\r\n" */
	mcm_buf_reset(ctxt, ms->rbuf);
	cp = mcm_get_line(ctxt, mc, ms);
	if (cp == NULL) {
	  MCM_ERRX_MSG(MCM_ERR_PROTO, "unable to read another line");
	  goto cleanup;
	}
      } else {
	MCM_ERRX(MCM_ERR_ASSERT);
	goto cleanup;
      }
    } else if (strncmp(cp, "END", MCM_CSTRLEN("END")) == 0) {
      /* This END is the result of no matches found from the request */
      goto cleanup;
    } else {
      MCM_ERRX_MSG(MCM_ERR_PROTO, cp);
      goto cleanup;
    }
  }

  /* This should never happen as we exit above while(1) via cleanup
   * goto code */
  cp = mcm_get_line(ctxt, mc, ms);
#ifdef DEBUG_MC_PROTO_ASSERT
  if (strncmp(cp, "END", MCM_CSTRLEN("END")) != 0) {
    MCM_ERRX(MCM_ERR_PROTO);
    goto cleanup;
  }
#endif

  cleanup:
  /* Now that we've finished the IO, fire off any callbacks that are
   * registered. */
  /* This is only for "shortcut" calls as the other ones don't get cb */
  TAILQ_FOREACH(cb, &req->cb, entries) {
    (*cb->cb)(cb->ctxt, cb->res, cb->misc);
  }

  MCM_CLEAN_BUFS(ctxt, ms);
  return;
}


int
mcm_flush(struct memcache_ctxt *ctxt, struct memcache *mc, struct memcache_server *ms) {
  char *cur;

  if (mcm_server_connect(ctxt, mc, ms) == -1)
    return (int)MCM_RET_CODE(-1);

  mcm_buf_append(ctxt, ms->wbuf, "flush_all\r\n", MCM_CSTRLEN("flush_all\r\n"));

  if (mcm_server_send_cmd(ctxt, mc, ms) < 0) {
    MCM_CLEAN_BUFS(ctxt, ms);
    return (int)MCM_RET_CODE(-2);
  }

  cur = mcm_get_line(ctxt, mc, ms);
  if (cur != NULL && memcmp(cur, "OK", MCM_CSTRLEN("OK")) == 0) {
    MCM_CLEAN_BUFS(ctxt, ms);
    return 0;
  } else {
    MCM_ERRX(MCM_ERR_PROTO);
    MCM_CLEAN_BUFS(ctxt, ms);
    return (int)MCM_RET_CODE(-3);
  }
}


int
mcm_flush_all(struct memcache_ctxt *ctxt, struct memcache *mc) {
  struct memcache_server *ms;
  int ret = 0,
    tret;

  for (ms = mc->server_list.tqh_first; ms != NULL; ms = ms->entries.tqe_next) {
    tret = mcm_flush(ctxt, mc, ms);

    /* Return the error code of the first non-zero value if there is
     * one.  Not sure if this is correct, but I don't have a better
     * idea right now. XXX */
    if (tret != 0 && ret == 0)
      ret = tret;
  }

  return ret;
}


void
mcm_free(struct memcache_ctxt *ctxt, struct memcache *mc) {
  struct memcache_server *ms, *tms;

  if (mc == NULL)
    return;

  tms = mc->server_list.tqh_first;
  while(tms != NULL) {
    ms = tms;
    tms = ms->entries.tqe_next;

    mcm_server_free(ctxt, ms);
  }

  if (mc->servers != NULL) {
    ctxt->mcFree(mc->servers);
  }

  ctxt->mcFree(mc);
}


void
mcm_get(struct memcache_ctxt *ctxt, struct memcache *mc, struct memcache_req *req) {
  /* At this point, we can safely assume we're performing a multi-get.
   * Pre-calculate what keys map up with which servers in order to
   * group requests where possible. Assume the worst/best case
   * scenario in that all keys will go to one server.*/
  struct memcache_req	**psq, *tsq;	/* Per-Server-reQuest */
  struct memcache_res	*psr, *trs;	/* Per-Server-Response */
  struct memcache_res_cb *cb;
  u_int16_t		 i;

  /* Reset ctxt->errnum upon entry into memcache(3), even though
   * mcm_get() and its call graph doesn't make use of ctxt->errnum. */
  ctxt->errnum = 0;

  /* Perform some trickery and call mcm_fetch_cmd() once for every
   * server that needs to be queried.  Short-circuit execution where
   * possible by invoking mcm_fetch_cmd() immediately if there is only
   * one key being queried. */
  switch (req->num_keys) {
  case 0:
    return;
  case 1:
    mcm_fetch_cmd(ctxt, mc, req, str_get_cmd, str_get_len);
    return;
  }

  /* If we're a multi-get but there is only one server, don't bother
   * with splitting out the keys to their appropriate server. */
  if (mc->num_servers == 0) {
    return;
  } else if (mc->num_servers == 1) {
    mcm_fetch_cmd(ctxt, mc, req, str_get_cmd, str_get_len);
    return;
  }

  /* Create an array of pointers to the per-server request objects.
   * Allocate one extra request object as a terminator of the pointer
   * array. */
  psq = (struct memcache_req**)ctxt->mcMalloc(sizeof(struct memcache_req*) * (mc->num_servers + 1));
  if (psq == NULL) {
    MCM_ERRX_MSG(MCM_ERR_ASSERT, "memory was not allocated for psq");
    return;
  }
  bzero(psq, sizeof(struct memcache_req*) * (mc->num_servers + 1));

  /* Make a first pass through the keys to determine which server they
   * belong to. */
  for (trs = req->query.tqh_first; trs != NULL; trs = trs->entries.tqe_next) {
    psr = mcm_res_new(ctxt);

    /* Shallow copy of trs into psr */
    psr->key = trs->key;
    psr->len = trs->len;
    psr->hash = trs->hash;
    psr->val = trs->val;
    psr->bytes = trs->bytes;
    psr->size = trs->size;
    psr->flags = trs->flags;

    /* No flags for shadow structure: we don't want the key or value
     * to be reaped when we cleanup. */
    psr->_flags = 0;

    mcm_res_free_on_delete(ctxt, psr, 0);

    if (psr->hash == 0) {
      psr->hash = trs->hash = ctxt->mcHashKey(ctxt, mc, psr->key, psr->len);
    }

    /* Store a pointer to the original object. */
    psr->misc = trs;

    /* Append onto the correct request chain for a server. */
    tsq = psq[psr->hash % mc->num_servers];
    if (tsq == NULL)
      tsq = psq[psr->hash % mc->num_servers] = mcm_req_new(ctxt);
    TAILQ_INSERT_TAIL(&tsq->query, psr, entries);
    tsq->num_keys++;
  }

  /* Make a second pass through the list of requests and execute the
   * fetch command where appropriate. */
  for (i = 0; i < mc->num_servers; i++) {
    if (psq[i] == NULL || psq[i]->num_keys == 0)
      continue;

    mcm_fetch_cmd(ctxt, mc, psq[i], str_get_cmd, str_get_len);

    /* Copy the important bits back. */
    for (psr = psq[i]->query.tqh_first; psr != NULL; psr = psr->entries.tqe_next) {
      trs = (struct memcache_res*)psr->misc;
      trs->val = psr->val;
      trs->bytes = psr->bytes;
      trs->size = psr->size;
      trs->flags = psr->flags;
      trs->_flags |= psr->_flags;
    }
  }

  /* Cleanup */
  for (i = 0; i < mc->num_servers; i++) {
    if (psq[i] != NULL)
      mcm_req_free(ctxt, psq[i]);
  }

  ctxt->mcFree(psq);

  /* Now that we've finished the IO, fire off any callbacks that are
   * registered. */
  /* This is for "non-shortcut" calls */
  TAILQ_FOREACH(cb, &req->cb, entries) {
    (*cb->cb)(cb->ctxt, cb->res, cb->misc);
  }
}


static char *
mcm_get_line(struct memcache_ctxt *ctxt, struct memcache *mc, struct memcache_server *ms) {
  size_t bytes_read = 0, bytes_scan = 0;
  char *end, *line;
  int ret;

  /* If we haven't initialized an offset, do so. */
  if ((ms->rbuf->flags & MCM_BUF_OFF_USED) != MCM_BUF_OFF_USED) {
    ms->rbuf->off = 0;
    ms->rbuf->flags |= MCM_BUF_OFF_USED;
  } else {
    bytes_read = mcm_buf_remain_off(ctxt, ms->rbuf);
  }

  /* Search for a newline starting at the offset */
  scan_for_line:
  end = memchr(mcm_buf_off_ptr(ctxt, ms->rbuf) + bytes_scan, (int)'\n', bytes_read);
  if (end == NULL) {
    /* Prevent rescanning of the buffer */
    bytes_scan += bytes_read;
  } else {
#ifdef DEBUG_MC_PROTO_ASSERT
    if (*(end - 1) != '\r') {
      MCM_ERRX_MSG(MCM_ERR_PROTO, "no \\r before \\n");
      return NULL;
    }
#endif

    line = mcm_buf_off_ptr(ctxt, ms->rbuf);
    ms->rbuf->off += end - line + 1;
    return line;
  }

  /* We were unable to scan for any bytes in our given buffer.  Need
   * to read(2) in some data. */
  read_more:
  if (mcm_server_readable(ctxt, ms, &ms->tv)) {
    bytes_read = mcm_buf_read(ctxt, ms->rbuf, ms->fd);
  } else {
    goto resend;
  }

  if (bytes_read == 0) {
    switch (errno) {
    case EAGAIN:
    case EINTR:

      /* Assume a file descriptor can be read(2), but if it can't
       * block until we can read(2) from the fd. */
      ret = mcm_server_readable(ctxt, ms, &ms->tv);
      if (ret < 0) {
	mcm_server_deactivate(ctxt, mc, ms);
	MCM_ERR_MSG(MCM_ERR_SYS_SELECT, "select returned bogus value");
	return NULL;
      } else if (ret == 0) {
	goto resend;
      } else {
	goto read_more;
      }
    case ECONNRESET:
    case EINVAL:
      resend:
      mcm_server_disconnect(ctxt, ms);

      /* Reconnect to the same server.  If this fails, get the next
       * available server. */
      if (mcm_server_connect(ctxt, mc, ms) == -1) {
	mcm_server_deactivate(ctxt, mc, ms);
	ms = mcm_server_connect_next_avail(ctxt, mc, ms->_last_hash);

	if (ms == NULL)
	  return NULL;
      } else {
	MCM_ERRX(MCM_ERR_MC_RECONN);
      }

      mcm_server_send_last_cmd(ctxt, mc, ms);
      goto read_more;
    default:
      /* This shouldn't happen and if it does, we're pooched: better
       * dump. */
      MCM_ERRX_MSG(MCM_ERR_ASSERT, strerror(errno));
      return NULL;
    }
  }

  goto scan_for_line;
}


#ifdef USE_CRC32_HASH
#include "crc32_table.h"
#endif /* USE_CRC32_HASH */


u_int32_t
mcm_hash(const struct memcache_ctxt *ctxt, const struct memcache *mc, const char *key, const size_t len) {
  return ctxt->mcHashKey(ctxt, mc, key, len);
}


u_int32_t
mcm_hash_key(const struct memcache_ctxt *ctxt, const char *key, const size_t len) {
  return ctxt->mcHashKey(ctxt, NULL, key, len);
}


static u_int32_t
mcm_hash_key_func(MCM_HASH_FUNC) {
#ifdef USE_CRC32_HASH
  const struct memcache_ctxt *ctxt;
  const struct memcache *mc;
  const char *key;
  u_int32_t crc;
  size_t len;
  size_t i;

  MCM_HASH_INIT(ctxt, mc, key, len);
  if (mc != NULL && mc->num_servers <= 1)
    return 1;

  crc = ~0;

  for (i = 0; i < len; i++)
    crc = (crc >> 8) ^ crc32tab[(crc ^ (key[i])) & 0xff];

  crc = (~crc >> 16) & 0x7fff;

  return crc == 0 ? 1 : crc;
#else
# ifdef USE_PERL_HASH
  const struct memcache_ctxt *ctxt;
  const struct memcache *mc;
  const char *key;
  u_int32_t h, i;
  size_t len;
  char *p;

  MCM_HASH_INIT(ctxt, mc, key, len);
  if (mc != NULL && mc->num_servers <= 1)
    return 1;

  i = len;	/* Work back through the key length */
  p = key;	/* Character pointer */
  h = 0;	/* The hash value */

  while (i--) {
    h += *p++;
    h += (h << 10);
    h ^= (h >> 6);
  }
  h += (h << 3);
  h ^= (h >> 11);
  h += (h << 15);

  return h == 0 ? 1 : h;
# else
#  ifdef USE_ELF_HASH
  const struct memcache_ctxt *ctxt;
  const struct memcache *mc;
  u_int32_t g, h, i;
  const char *key;
  size_t len;
  char *p;

  MCM_HASH_INIT(ctxt, mc, key, len);
  if (mc != NULL && mc->num_servers <= 1)
    return 1;

  i = len;	/* Work back through the key length */
  p = key;	/* Character pointer */
  h = 0;	/* The hash value */

  while (i--) {
    h = (h << 4) + *p++;
    if (g = h & 0xF0000000)
      h ^= g >> 24;
    h &= ~g;
  }

  return h == 0 ? 1 : h;
#  else
#   error "Please choose USE_CRC32_HASH, USE_ELF_HASH, or USE_PERL_HASH as a hashing scheme when compiling memcache"
#  endif
# endif
#endif
}


u_int32_t
mcm_incr(struct memcache_ctxt *ctxt, struct memcache *mc,
	 char *key, const size_t key_len, const u_int32_t val) {
  return mcm_atomic_cmd(ctxt, mc, str_incr_cmd, str_incr_len, key, key_len, val);
}


struct memcache *
mcm_new(struct memcache_ctxt *ctxt) {
  struct memcache *mc;

  mc = (struct memcache *)ctxt->mcMalloc(sizeof(struct memcache));
  if (mc != NULL) {
    bzero(mc, sizeof(struct memcache));

    TAILQ_INIT(&mc->server_list);

    /* Set any default values */
    mc->tv.tv_sec = 2;
    mc->tv.tv_usec = 600;
  }

  return mc;
}


static size_t
mcm_read_fd(struct memcache_ctxt *ctxt, struct memcache *mc, struct memcache_server *ms, char *buf, size_t bytes) {
  size_t bytes_read = 0;
  ssize_t rb;
  int ret;

  read_more:
  rb = read(ms->fd, buf, bytes);
  if (rb < 1) {
    switch (errno) {
    case EAGAIN:
    case EINTR:

      /* Assume a file descriptor can be read(2), but if it can't
       * block until we can read(2) from the fd. */
      ret = mcm_server_readable(ctxt, ms, &ms->tv);
      if (ret < 0) {
	mcm_server_deactivate(ctxt, mc, ms);
	MCM_ERR_MSG(MCM_ERR_SYS_SELECT, "select returned bogus value");
	return 0;
      } else if (ret == 0) {
	mcm_server_disconnect(ctxt, ms);

	/* Reconnect to the same server.  If this fails, get the next
	 * available server. */
	if (mcm_server_connect(ctxt, mc, ms) == -1) {
	  mcm_server_deactivate(ctxt, mc, ms);
	  ms = mcm_server_connect_next_avail(ctxt, mc, ms->_last_hash);

	  if (ms == NULL)
	    return 0;
	} else {
	  MCM_ERRX(MCM_ERR_MC_RECONN);
	}

	mcm_server_send_last_cmd(ctxt, mc, ms);
      } else {
	goto read_more;
      }
    default:
      /* This shouldn't happen and if it does, we're pooched: better
       * dump. */
      MCM_ERRX_MSG(MCM_ERR_ASSERT, strerror(errno));
      mcm_server_disconnect(ctxt, ms);
      return 0;
    }
  } else {
    bytes_read += rb;
    buf += rb;
  }

  /* Need to read(2) more data */
  if ((size_t)rb < bytes) {
    bytes -= rb;
    goto read_more;
  } else {
    return bytes_read;
  }
}


#ifdef SEAN_HACKS
void
mcm_listen(struct memcache_ctxt *ctxt, struct memcache *mc, struct memcache_req *req) {
  mcm_fetch_cmd(ctxt, mc, req, str_listen_cmd, str_listen_len);
}


void
mcm_refresh(struct memcache_ctxt *ctxt, struct memcache *mc, struct memcache_req *req) {
  mcm_fetch_cmd(ctxt, mc, req, str_refresh_cmd, str_refresh_len);
}
#endif


u_int32_t
mcm_reldate(const struct memcache_ctxt *ctxt) {
  return MEMCACHE_RELDATE;
}


int
mcm_replace(struct memcache_ctxt *ctxt, struct memcache *mc,
	    char *key, const size_t key_len,
	    const void *val, const size_t bytes,
	    const time_t expire, const u_int16_t flags) {
  return mcm_storage_cmd(ctxt, mc, str_replace_cmd, str_replace_len, key, key_len, val, bytes, expire, flags);
}


struct memcache_res *
mcm_req_add(const struct memcache_ctxt *ctxt, struct memcache_req *req, char *key, const size_t len) {
  struct memcache_res *res;
  res = mcm_res_new(ctxt);

  MCM_VALIDATE_KEY_RET(key, len, NULL);

  res->key = mcm_strdup(ctxt, key);
  res->_flags |= MCM_RES_NEED_FREE_KEY;
  res->len = len;

  TAILQ_INSERT_TAIL(&req->query, res, entries);
  req->num_keys++;

  return res;
}


struct memcache_res *
mcm_req_add_ref(const struct memcache_ctxt *ctxt, struct memcache_req *req, char *key, const size_t len) {
  struct memcache_res *res;
  res = mcm_res_new(ctxt);

  MCM_VALIDATE_KEY_RET(key, len, NULL);

  res->key = key;
  res->len = len;

  TAILQ_INSERT_TAIL(&req->query, res, entries);
  req->num_keys++;

  return res;
}


void
mcm_req_free(const struct memcache_ctxt *ctxt, struct memcache_req *req) {
  while (req->query.tqh_first != NULL)
    mcm_res_free(ctxt, req, req->query.tqh_first);

  while (req->cb.tqh_first != NULL)
    mcm_res_cb_free(req, req->cb.tqh_first);

  ctxt->mcFree(req);
}


struct memcache_req *
mcm_req_new(const struct memcache_ctxt *ctxt) {
  struct memcache_req *req;

  req = (struct memcache_req *)ctxt->mcMalloc(sizeof(struct memcache_req));
  if (req != NULL) {
    bzero(req, sizeof(struct memcache_req));

    TAILQ_INIT(&req->query);
    TAILQ_INIT(&req->cb);
  }

  return req;
}


int
mcm_res_attempted(const struct memcache_ctxt *ctxt,
		  const struct memcache_res *res) {
  return res->_flags & MCM_RES_ATTEMPTED ? 1 : 0;
}


int
mcm_res_found(const struct memcache_ctxt *ctxt,
	      const struct memcache_res *res) {
  return ((res->_flags & (MCM_RES_ATTEMPTED | MCM_RES_FOUND)) == (MCM_RES_ATTEMPTED | MCM_RES_FOUND) ? 1 : 0);
}


void
mcm_res_free(const struct memcache_ctxt *ctxt, struct memcache_req *req, struct memcache_res *res) {
  TAILQ_REMOVE(&req->query, res, entries);
  if ((res->_flags & MCM_RES_NEED_FREE_KEY) == MCM_RES_NEED_FREE_KEY)
    ctxt->mcFree((void *)res->key);

  if (((res->_flags & (MCM_RES_FREE_ON_DELETE | MCM_RES_NO_FREE_ON_DELETE)) ==
       (MCM_RES_FREE_ON_DELETE | MCM_RES_NO_FREE_ON_DELETE)) ||
      res->_flags & MCM_RES_FREE_ON_DELETE) {
    if (res->size > 0)
      ctxt->mcFree(res->val);
  }

  ctxt->mcFree(res);
}


void
mcm_res_free_on_delete(const struct memcache_ctxt *ctxt, struct memcache_res *res, const int fod) {
  if (fod) {
    res->_flags &= ~MCM_RES_NO_FREE_ON_DELETE;
    res->_flags |= MCM_RES_FREE_ON_DELETE;
  } else {
    res->_flags &= ~MCM_RES_FREE_ON_DELETE;
    res->_flags |= MCM_RES_NO_FREE_ON_DELETE;
  }
}


static struct memcache_res *
mcm_res_new(const struct memcache_ctxt *ctxt) {
  struct memcache_res *res;

  res = (struct memcache_res *)ctxt->mcMalloc(sizeof(struct memcache_res));
  if (res != NULL) {
    bzero(res, sizeof(struct memcache_res));

    /* Default values */
    res->_flags = MCM_RES_FREE_ON_DELETE | MCM_RES_NO_FREE_ON_DELETE; /* unset */
  }

  return res;
}


static void
mcm_res_cb_free(struct memcache_req *req, struct memcache_res_cb *cb) {
  mcFreeFunc freeFunc;

  if (cb == NULL || cb->ctxt == NULL)
    return;

  TAILQ_REMOVE(&req->cb, cb, entries);
  freeFunc = cb->ctxt->mcFree;
  (freeFunc)(cb);
}


static struct memcache_res_cb *
mcm_res_cb_new(const struct memcache_ctxt *ctxt) {
  struct memcache_res_cb *cb;

  cb = (struct memcache_res_cb *)ctxt->mcMalloc(sizeof(struct memcache_res_cb));
  if (cb != NULL) {
    bzero(cb, sizeof(struct memcache_res_cb));
  }

  return cb;
}


int
mcm_res_register_fetch_cb(struct memcache_ctxt *ctxt, struct memcache_req *req,
			  struct memcache_res *res, mcResCallback callback, void *misc) {
  struct memcache_res_cb *cb;

  if (callback == NULL || req == NULL || res == NULL || ctxt == NULL)
    return (int)MCM_RET_CODE(-1);

  cb = mcm_res_cb_new(ctxt);
  if (cb == NULL)
    return (int)MCM_RET_CODE(-2);

  cb->ctxt = ctxt;
  cb->req = req;
  cb->cb = callback;
  cb->res = res;
  cb->misc = misc;

  TAILQ_INSERT_TAIL(&req->cb, cb, entries);

  return 0;
}


int
mcm_server_activate(const struct memcache_ctxt *ctxt, struct memcache *mc, struct memcache_server *ms) {
  switch (ms->active) {
  case 'd':
    ms->active = 'u';
    return 0;
  case 'n':
    MCM_ERRX_MSG(MCM_ERR_ASSERT, "unable to activate a server that does not exist");
    return (int)MCM_RET_CODE(-1);
  case 't':
    MCM_ERRX_MSG_LVL(MCM_ERR_ASSERT, "unable to activate a server that hasn't been added to the server list", MCM_ERR_LVL_INFO);
    return (int)MCM_RET_CODE(-2);
  case 'u':
    MCM_ERRX_MSG_LVL(MCM_ERR_ASSERT, "unable to activate a server that is active", MCM_ERR_LVL_INFO);
    return (int)MCM_RET_CODE(-3);
  default:
    MCM_ERRX(MCM_ERR_ASSERT);
  }

  MCM_ERRX(MCM_ERR_ASSERT);
  return 0;
}


int
mcm_server_activate_all(const struct memcache_ctxt *ctxt, struct memcache *mc) {
  struct memcache_server *ms;

  for (ms = mc->server_list.tqh_first; ms != NULL; ms = ms->entries.tqe_next) {
    if (ms->active == 'd')
      mcm_server_activate(ctxt, mc, ms);
  }

  return 0;
}


int
mcm_server_add(struct memcache_ctxt *ctxt, struct memcache *mc, const char *hostname, const char *port) {
  return mcm_server_add2(ctxt, mc, hostname, (hostname != NULL ? strlen(hostname) : 0), port, (port != NULL ? strlen(port) : 0));
}


int
mcm_server_add2(struct memcache_ctxt *ctxt, struct memcache *mc, const char *hostname,
		const size_t hostname_len, const char *port, const size_t port_len) {
  struct memcache_server *ms;

  ms = mcm_server_new(ctxt);
  if (ms == NULL)
    return (int)MCM_RET_CODE(-1);

  if (hostname == NULL || hostname_len == 0) {
    ms->hostname = mcm_strdup(ctxt, "localhost");
  } else {
    ms->hostname = mcm_strndup(ctxt, hostname, hostname_len);
  }

  if (ms->hostname == NULL) {
    mcm_server_free(ctxt, ms);
    return (int)MCM_RET_CODE(-2);
  }


  if (port == NULL || port_len == 0) {
    ms->port = mcm_strdup(ctxt, "11211");
  } else {
    ms->port = mcm_strndup(ctxt, port, port_len);
  }

  if (ms->port == NULL) {
    mcm_server_free(ctxt, ms);
    return (int)MCM_RET_CODE(-3);
  }

  return mcm_server_add3(ctxt, mc, ms);
}


int
mcm_server_add3(struct memcache_ctxt *ctxt, struct memcache *mc, struct memcache_server *ms) {
  int ret;
  struct memcache_server **ts;

  ret = mcm_server_resolve(ctxt, ms);
  if (ret != 0) {
    MCM_ERR_MSG(MCM_ERR_NET_HOST, gai_strerror(ret));
    mcm_server_free(ctxt, ms);
    return (int)MCM_RET_CODE(-4);
  }

  /* Defaults from mc */
  if (ms->tv.tv_sec == 0 && ms->tv.tv_usec == 0) {
    ms->tv.tv_sec = mc->tv.tv_sec;
    ms->tv.tv_usec = mc->tv.tv_usec;
  }

  TAILQ_INSERT_TAIL(&mc->server_list, ms, entries);

  /* Add ms to the array of servers to try */
  if (mc->servers == NULL) {
    mc->num_servers = 1;
    mc->servers = (struct memcache_server**)ctxt->mcMalloc(sizeof(struct memcache_server*) * (mc->num_servers + 1));
    mc->servers[0] = ms;
    mc->servers[1] = NULL;
  } else {
    /* Reallocate mc->servers to fit the number of struct
     * memcache_servers entries. 2 == the new memcache server plus an
     * additional slot for a NULL server entry. */
    ts = (struct memcache_server**)ctxt->mcRealloc(mc->servers, sizeof(struct memcache_server*) * (mc->num_servers + 2));
    if (ts == NULL) {
      MCM_ERR(MCM_ERR_MEM_REALLOC);
      mcm_server_free(ctxt, ms);
      return (int)MCM_RET_CODE(-5);
    }
    mc->servers = ts;

    /* Add the new server to the end of the list */
    mc->servers[mc->num_servers] = ms;
    mc->num_servers++;
    mc->servers[mc->num_servers] = NULL;
  }

  return 0;
}


int
mcm_server_add4(struct memcache_ctxt *ctxt, struct memcache *mc, mc_const char *hostport) {
  return mcm_server_add5(ctxt, mc, hostport, (hostport != NULL ? strlen(hostport) : 0));
}


int
mcm_server_add5(struct memcache_ctxt *ctxt, struct memcache *mc,
		mc_const char *hostport, const size_t hostlen) {
  struct memcache_server *ms;
  char *cp;

  ms = mcm_server_new(ctxt);
  if (ms == NULL)
    return (int)MCM_RET_CODE(-1);

  /* Tease out the hostname and portname from a string that we expect
   * to look like "host:port". */
  if (hostport == NULL || hostlen == 0) {
    ms->hostname = mcm_strdup(ctxt, "localhost");
    if (ms->hostname == NULL) {
      mcm_server_free(ctxt, ms);
      return (int)MCM_RET_CODE(-2);
    }

    ms->port = mcm_strdup(ctxt, "11211");
    if (ms->port == NULL) {
      mcm_server_free(ctxt, ms);
      return (int)MCM_RET_CODE(-3);
    }
  } else {
    cp = mcm_strnchr(ctxt, hostport, ':', hostlen);
    if (*cp == '\0') {
      ms->hostname = mcm_strndup(ctxt, hostport, hostlen);
      if (ms->hostname == NULL) {
	mcm_server_free(ctxt, ms);
	return (int)MCM_RET_CODE(-2);
      }

      ms->port = mcm_strdup(ctxt, "11211");
      if (ms->port == NULL) {
	mcm_server_free(ctxt, ms);
	return (int)MCM_RET_CODE(-3);
      }
    } else {
      ms->hostname = mcm_strndup(ctxt, hostport, (size_t)(cp - hostport));
      if (ms->hostname == NULL) {
	mcm_server_free(ctxt, ms);
	return (int)MCM_RET_CODE(-2);
      }

      /* advance past the ':' and copy whatever is left as the port */
      cp++;
      ms->port = mcm_strndup(ctxt, cp, hostlen - (size_t)(cp - hostport));
      if (ms->port == NULL) {
	mcm_server_free(ctxt, ms);
	return (int)MCM_RET_CODE(-3);
      }
    }
  }

  return mcm_server_add3(ctxt, mc, ms);
}


static int
mcm_server_connect(struct memcache_ctxt *ctxt, struct memcache *mc, struct memcache_server *ms) {
  struct addrinfo *res;
  int flags, i;
#ifdef TCP_NODELAY
  int val;
#endif
#ifdef HAVE_SELECT
  int ret;
#endif

  if (ms->fd != -1)
    return ms->fd;

#ifdef DEBUG_MC_PROTO
  MCM_WARNX_MSG(MCM_ERR_TRACE, "Begin connect(2)");
#endif

  if (ms->active == 'd' || ms->active == 'n')
    return (int)MCM_RET_CODE(-1);

  if (ms->hostinfo == NULL || ms->hostinfo->ai_addrlen == 0) {
    i = mcm_server_resolve(ctxt, ms);
    if (i != 0) {
      MCM_ERR_MSG(MCM_ERR_NET_HOST, gai_strerror(i));
      ms->active = 'n';
      return (int)MCM_RET_CODE(-1);
    }
  }

  for (i = 0, res = ms->hostinfo; res != NULL; res = res->ai_next, i++) {
    ms->fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (ms->fd < 0) {
#ifdef AF_INET6
      if (errno == EPROTONOSUPPORT && res->ai_family == AF_INET6)
	continue;
#endif
      MCM_ERR(MCM_ERR_SYS_SOCKET);
      continue;
    }

#ifdef TCP_NODELAY
    val = 1;
    if (setsockopt(ms->fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val)) != 0) {
      MCM_WARN_MSG(MCM_ERR_SYS_SETSOCKOPT, "setsockopt(TCP_NODELAY) failed");
    }
#endif

    if (mcm_server_timeout(ctxt, ms, ms->tv.tv_sec, ms->tv.tv_usec) == 0) {
      mcm_server_disconnect(ctxt, ms);
      continue;
    }

    flags = fcntl(ms->fd, F_GETFL, 0);
    if (flags == -1) {
      MCM_ERR_MSG(MCM_ERR_SYS_FCNTL, "fcntl(F_GETFL)");
      return (int)MCM_RET_CODE(-1);
    }

    if (fcntl(ms->fd, F_SETFL, flags | O_NONBLOCK) < 0) {
      MCM_ERR_MSG(MCM_ERR_SYS_FCNTL, "fcntl(F_SETFL)");
      return (int)MCM_RET_CODE(-1);
    }

  get_conn_status:
    ret = connect(ms->fd, res->ai_addr, (socklen_t)res->ai_addrlen);
#ifdef DEBUG_MC_PROTO
    do {
      char *tm;
      size_t tml;
      char ch[256], cs[256];

      tml = getnameinfo(res->ai_addr, res->ai_addr->sa_len, ch, sizeof(ch), cs, sizeof(cs), NI_NUMERICHOST | NI_NUMERICSERV);
      if (tml != 0) {
	MCM_WARNX_MSG(MCM_ERR_TRACE, "Unable to get address");
	return (int)MCM_RET_CODE(-1);
      }

      tml = asprintf(&tm, "connect(2) return status for %s:%s: %d", ch, cs, ret);
      if (tml > 0 && tm != NULL) {
	MCM_WARN_MSG(MCM_ERR_TRACE, tm);
	free(tm);
      }
    } while (0);
#endif
    if (ret == 0) {
      return ms->fd;
    } else {
      /* Leave error handling in the event I figure out why connect(2)
       * and select(2) weren't returning when polling for a writable
       * file descriptor. */
      switch (errno) {
      case EISCONN:
	return ms->fd;
        /* Call again, if interrupted */
      case EINTR:
        goto get_conn_status;
      case EINPROGRESS:
	ret = mcm_server_writable(ctxt, ms, &ms->tv);
	if (ret == -1) {
	  MCM_ERR_MSG_LVL(MCM_ERR_SYS_SELECT, "select(2) failed for writable status", MCM_ERR_LVL_WARN);
	} else if (ret == 0) {
	  MCM_ERR_MSG_LVL(MCM_ERR_SYS_SELECT, "select(2) timed out on establishing connection", MCM_ERR_LVL_WARN);
	  printf("connect(): %d\n", connect(ms->fd, res->ai_addr, (socklen_t)res->ai_addrlen));
	} else {
	  goto get_conn_status;
	}
	/* Fall through */
      default:
	MCM_ERR(MCM_ERR_SYS_CONNECT);
	mcm_server_disconnect(ctxt, ms);
	continue;
      }
    }
  }

  /* If none of the IP addresses for this hostname work, remove the
   * server from the **server list (we assume they're live by default)
   * and return -1. */
  mcm_server_deactivate(ctxt, mc, ms);
  return (int)MCM_RET_CODE(-1);
}


static struct memcache_server *
mcm_server_connect_next_avail(struct memcache_ctxt *ctxt, struct memcache *mc, const u_int32_t hash) {
  struct memcache_server *ms, *nms;

  if (mc->num_servers == 0) {
    MCM_ERRX(MCM_ERR_MC_SERV_LIST);
    return NULL;
  }

  ms = ctxt->mcServerFind(ctxt, mc, hash);
  if (ms == NULL) {
    MCM_ERRX(MCM_ERR_MC_VALID_SERVER);
    return NULL;
  }

  while (mcm_server_connect(ctxt, mc, ms) == -1) {
    MCM_ERR(MCM_ERR_NET_CONNECT);
    mcm_server_deactivate(ctxt, mc, ms);

    nms = ctxt->mcServerFind(ctxt, mc, hash);
    if (nms == NULL) {
      MCM_ERRX(MCM_ERR_MC_SERV_LIST);
      return NULL;
    }

    nms->rbuf= ms->rbuf;
    nms->wbuf = ms->wbuf;
    ms->rbuf = ms->wbuf = NULL;
    ms = nms;
  }

  ms->_last_hash = ctxt->_last_hash = hash;

  /* If there was a present left behind by the last memcache_server,
   * assume ownership of the command. */
  if (ctxt->_rbuf != NULL || ctxt->_wbuf != NULL) {
    ms->rbuf = ctxt->_rbuf;
    ms->wbuf = ctxt->_wbuf;
  }

  return ms;
}


void
mcm_server_deactivate(struct memcache_ctxt *ctxt, struct memcache *mc, struct memcache_server *ms) {
  /* Stash this server's command in the context */
  ctxt->_rbuf = ms->rbuf;
  ctxt->_wbuf = ms->wbuf;
  ctxt->_last_hash = ms->_last_hash;

  if (ms->active == 'u' || ms->active == 't')
    ms->active = 'd';

  mcm_server_disconnect(ctxt, ms);
}


void
mcm_server_disconnect(const struct memcache_ctxt *ctxt, struct memcache_server *ms) {
#ifdef DEBUG_MC_PROTO
    MCM_WARNX_MSG(MCM_ERR_TRACE, "Attempting to disconnect");
#endif
  if (ms->fd != -1) {
#ifdef DEBUG_MC_PROTO
    MCM_WARNX_MSG(MCM_ERR_TRACE, "Closing file descriptor");
#endif
    if (close(ms->fd) != 0)
      MCM_ERR(MCM_ERR_SYS_CLOSE);
    mcm_server_init(ctxt, ms);
  }
}


void
mcm_server_disconnect_all(const struct memcache_ctxt *ctxt, const struct memcache *mc) {
  struct memcache_server *ms;

  for (ms = mc->server_list.tqh_first; ms != NULL; ms = ms->entries.tqe_next)
    mcm_server_disconnect(ctxt, ms);
}


struct memcache_server *
mcm_server_find(const struct memcache_ctxt *ctxt, struct memcache *mc, const u_int32_t hash) {
  return ((struct memcache_server *)ctxt->mcServerFind(ctxt, mc, hash));
}


static void *
mcm_server_find_func(const void *void_ctxt, void *void_mc, const u_int32_t hash) {
  const struct memcache_ctxt *ctxt;
  struct memcache_server *ms = NULL;
  struct memcache *mc;
  u_int32_t idx, i;

  ctxt = (const struct memcache_ctxt *)void_ctxt;
  mc = (struct memcache *)void_mc;

  if (mc->num_servers < 1)
    return NULL;

  idx = hash % mc->num_servers;

  for (i = 0; i < mc->num_servers; i++) {
    /* Grab the correct server from the list. */
    ms = mc->servers[idx];

    if (ms->active == 'u' || ms->active == 't') {
      /* Store the last hash value used to find this server.  In the
       * event that this server dies, we use this value to
       * automatically fall back to the next server. */
      ms->_last_hash = hash;

      return ms;
    } else if (ms->active == 'd') {
      /* Try searching for the next server in this list.  Remember:
       * idx is zero based, but num_servers is one based. */
      if (idx + 1 == mc->num_servers)
	idx = 0;
      else
	idx++;

      continue;
    } else {
      MCM_ERRX(MCM_ERR_ASSERT);
      return NULL;
    }
  }

  return NULL;
}


void
mcm_server_free(struct memcache_ctxt *ctxt, struct memcache_server *ms) {
  if (ms == NULL)
    return;

  if (ms->hostinfo != NULL)
    freeaddrinfo(ms->hostinfo);

  if (ms->hostname != NULL)
    ctxt->mcFree(ms->hostname);

  if (ms->port != NULL)
    ctxt->mcFree(ms->port);

  if (ms->rbuf != NULL)
    mcm_buf_free(ctxt, &ms->rbuf);

  if (ms->wbuf != NULL)
    mcm_buf_free(ctxt, &ms->wbuf);

  mcm_server_disconnect(ctxt, ms);

  ctxt->mcFree(ms);
}


static void
mcm_server_init(const struct memcache_ctxt *ctxt, struct memcache_server *ms) {
  ms->active = 't';
  ms->fd = -1;
  ms->startoff = ms->soff = 0;
}


struct memcache_server *
mcm_server_new(struct memcache_ctxt *ctxt) {
  struct memcache_server *ms;

  ms = (struct memcache_server *)ctxt->mcMalloc(sizeof(struct memcache_server));
  if (ms != NULL) {
    bzero(ms, sizeof(struct memcache_server));

    ms->rbuf = mcm_buf_new(ctxt);
    if (ms->rbuf == NULL) {
      mcm_server_free(ctxt, ms);
      return NULL;
    }

    ms->wbuf = mcm_buf_new(ctxt);
    if (ms->wbuf == NULL) {
      mcm_server_free(ctxt, ms);
      return NULL;
    }

    /* Set default values */
    mcm_server_init(ctxt, ms);
  }

  return ms;
}


static int
mcm_server_readable(struct memcache_ctxt *ctxt, struct memcache_server *ms, struct timeval *tv) {
#ifndef HAVE_SELECT
  return 1;
#else
  struct timeval local_tv;
  socklen_t so_err_length;
  int ret, so_err;

  retry_check_readable:

  FD_ZERO(&ms->fds);
  FD_SET(ms->fd, &ms->fds);

#ifdef DEBUG_MC_PROTO_ASSERT
  if (FD_ISSET(ms->fd, &ms->fds) == 0) {
    MCM_ERRX(MCM_ERR_ASSERT);
    return -1;
  }
#endif

  memcpy(&local_tv, tv, sizeof(struct timeval));

#ifdef DEBUG_MC_PROTO
  do {
    char *tm;
    size_t tml;
    tml = asprintf(&tm, "Begin select(2)'ing to see if fd %d is read(2)able.  Timeout %llu.%llu", ms->fd, (u_int64_t)local_tv.tv_sec, (u_int64_t)local_tv.tv_usec);
    if (tml > 0 && tm != NULL) {
      MCM_WARNX_MSG(MCM_ERR_TRACE, tm);
      free(tm);
    }
  } while (0);
#endif

  /* Before we read(2) anything, check to make sure there is data
   * available to be read(2).  No sense in wastefully calling read(2)
   * constantly in a loop. */
  ret = select(ms->fd + 1, &ms->fds, NULL, NULL, &local_tv);
#ifdef DEBUG_MC_PROTO
  do {
    char *tm;
    size_t tml;
    tml = asprintf(&tm, "fd's ready to be read(2): %d/%d", ret, FD_SETSIZE);
    if (tml > 0 && tm != NULL) {
      MCM_WARNX_MSG(MCM_ERR_TRACE, tm);
      free(tm);
    }
  } while (0);
#endif
  if (ret > 0) {
    /* Check where readable flag is set */
    if (!FD_ISSET(ms->fd, &ms->fds)) {
      MCM_ERR(MCM_ERR_SYS_SELECT);
      return 0;
    }

    /* Check for the socket errors */
    so_err_length = sizeof(so_err);
    if (getsockopt(ms->fd, SOL_SOCKET, SO_ERROR, (void *)&so_err, &so_err_length) == -1) {
      MCM_ERR(MCM_ERR_SYS_SELECT); /* Socket error */
      return 0;
    } else {
      return ret;
    }
  } else if (ret == -1) {
    switch (errno) {
    case EINTR: /* retry this check again */
      goto retry_check_readable;
    default:
      MCM_ERR(MCM_ERR_SYS_SELECT);
      return 0;
    }
  } else if (ret == 0) {
    MCM_ERR_MSG(MCM_ERR_TIMEOUT, "select(2) call timed out for read(2)able fds");
    return 0;
  }

#ifdef DEBUG_MC_PROTO
  MCM_WARNX_MSG(MCM_ERR_TRACE, "End select(2)'ing to see if fd is read(2)able");
#endif

  return ret;
#endif
}


static int
mcm_server_resolve(struct memcache_ctxt *ctxt, struct memcache_server *ms) {
  struct addrinfo hints, *res;
  int ret;

#ifdef DEBUG_MC_PROTO
  do {
    char *tm;
    size_t tml;
    tml = asprintf(&tm, "Resolving the host %s:%s", ms->hostname, ms->port);
    if (tml > 0 && tm != NULL) {
      MCM_WARNX_MSG(MCM_ERR_TRACE, tm);
      free(tm);
    }
  } while (0);
#endif

  /* Resolve the hostname ahead of time */
  bzero(&hints, sizeof(struct addrinfo));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  ret = getaddrinfo(ms->hostname, ms->port, &hints, &ms->hostinfo);
  if (ret != 0) {
#ifdef DEBUG_MC_PROTO
    do {
      char *tm;
      size_t tml;
      tml = asprintf(&tm, "getaddrinfo(): %s", gai_strerror(ret));
      if (tml > 0 && tm != NULL) {
	MCM_WARNX_MSG(MCM_ERR_TRACE, tm);
	free(tm);
      }
    } while (0);
#endif

    return ret;
  }

  for (res = ms->hostinfo; res != NULL; res = res->ai_next) {
    ms->num_addrs++;
#ifdef DEBUG_MC_PROTO
    do {
      char *tm, ch[256], cs[256];
      size_t tml;
      tml = getnameinfo(res->ai_addr, res->ai_addr->sa_len, ch, sizeof(ch), cs, sizeof(cs), NI_NUMERICHOST | NI_NUMERICSERV);
      if (tml != 0) {
	MCM_WARNX_MSG(MCM_ERR_TRACE, "Unable to get address");
	return tml;
      }

      tml = asprintf(&tm, "Resolved host to \"%s:%s\"", ch, cs);
      if (tml > 0 && tm != NULL) {
	MCM_WARNX_MSG(MCM_ERR_TRACE, tm);
	free(tm);
      }
    } while (0);
#endif

  }

  return 0;
}


static size_t
mcm_server_send_cmd(struct memcache_ctxt *ctxt, struct memcache *mc, struct memcache_server *ms) {
  ssize_t ret;

  ms->wbuf->off = 0;

#ifdef DEBUG_MC_PROTO
  MCM_WARNX_MSG(MCM_ERR_TRACE, "Sending the following data to the server:");
  write(fileno(stderr), mcm_buf_to_cstr(ctxt, ms->wbuf), mcm_buf_len(ctxt, ms->wbuf) - ms->wbuf->off);
#endif

  write_again:
  ret = write(ms->fd, mcm_buf_off_ptr(ctxt, ms->wbuf), mcm_buf_len(ctxt, ms->wbuf) - ms->wbuf->off);
#ifdef DEBUG_MC_PROTO
  do {
    char *tm;
    size_t tml;
    tml = asprintf(&tm, "%d = write(2), errno = %d", (int)ret, errno);
    if (tml > 0 && tm != NULL) {
      MCM_WARNX_MSG(MCM_ERR_TRACE, tm);
      free(tm);
    }
  } while (0);
#endif
  if (ret < 1) {
    switch (errno) {
    case EAGAIN:
    case EINTR:
    case ENOBUFS:
      goto write_again;
    case EBADF:
    case EDESTADDRREQ:
      /* Need to reconnect */
      MCM_ERR_MSG_LVL(MCM_ERR_MC_SEND_CMD, strerror(errno), MCM_ERR_LVL_INFO);
      mcm_server_disconnect(ctxt, ms);

      ms = mcm_server_connect_next_avail(ctxt, mc, ms->_last_hash);
      goto write_again;
    case EDQUOT:
    case EFAULT:
    case EFBIG:
    case EINVAL:
    case EIO:
    case ENOSPC:
    case EPIPE:
    default:
      MCM_ERR_MSG_LVL(MCM_ERR_MC_SEND_CMD, strerror(errno), MCM_ERR_LVL_FATAL);
      mcm_server_deactivate(ctxt, mc, ms);
      /* If we're here, the game's up and we can't continue. */
      return 0;
    }
  } else if ((size_t)ret == mcm_buf_len(ctxt, ms->wbuf) - ms->wbuf->off) {
    ms->wbuf->off += ret;
    return ret;
  } else {
    ms->wbuf->off += ret;
    goto write_again;
  }
}


inline static ssize_t
mcm_server_send_last_cmd(struct memcache_ctxt *ctxt, struct memcache *mc, struct memcache_server *ms) {
  mcm_buf_reset(ctxt, ms->rbuf);

  return mcm_server_send_cmd(ctxt, mc, ms);
}


struct memcache_server_stats *
mcm_server_stats(struct memcache_ctxt *ctxt, struct memcache *mc, struct memcache_server *ms) {
  struct memcache_server_stats *s;
  char *cp, *cur;

  if (mcm_server_connect(ctxt, mc, ms) == -1)
    return NULL;

  mcm_buf_append(ctxt, ms->wbuf, "stats\r\n", MCM_CSTRLEN("stats\r\n"));
  if (mcm_server_send_cmd(ctxt, mc, ms) < 0) {
    MCM_CLEAN_BUFS(ctxt, ms);
    return NULL;
  }

  s = mcm_server_stats_new(ctxt);
  if (s == NULL) {
    MCM_CLEAN_BUFS(ctxt, ms);
    return NULL;
  }

  for(;;) {
    cur = mcm_get_line(ctxt, mc, ms);

    if (cur != NULL && memcmp(cur, "STAT ", MCM_CSTRLEN("STAT ")) == 0) {
      cur = &cur[MCM_CSTRLEN("STAT ")];

      /* Time to loop through the potential stats keys.  Joy.  This is
       * going to complete in O(1 + 2 + 3 ... N) operations (currently
       * 190).  Ugh.  Don't know of a better way to handle this
       * without a hash.  Besides, this is just stats. */
      if (memcmp(cur, "pid ", MCM_CSTRLEN("pid ")) == 0) {
	cur = &cur[MCM_CSTRLEN("pid ")];
	s->pid = (pid_t)strtol(cur, &cp, 10);
	if (s->pid == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid pid");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
	}
      } else if (memcmp(cur, "uptime ", MCM_CSTRLEN("uptime ")) == 0) {
	cur = &cur[MCM_CSTRLEN("uptime ")];
	s->uptime = (time_t)strtol(cur, &cp, 10);
	if (s->uptime == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid uptime");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
	}
      } else if (memcmp(cur, "time ", MCM_CSTRLEN("time ")) == 0) {
	cur = &cur[MCM_CSTRLEN("time ")];
	s->time = (time_t)strtol(cur, &cp, 10);
	if (s->time == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid time");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
	}
      } else if (memcmp(cur, "version ", MCM_CSTRLEN("version ")) == 0) {
	cur = &cur[MCM_CSTRLEN("version ")];
	for (cp = cur; !isspace(*cp); cp++);
	s->version = (char *)ctxt->mcMallocAtomic((size_t)(cp - cur + 1));
	if (s->version == NULL) {
	  MCM_ERR(MCM_ERR_MEM_MALLOC);
	} else {
	  memcpy(s->version, cur, (size_t)(cp - cur));
	  s->version[(size_t)(cp - cur)] = '\0';
	}
      } else if (memcmp(cur, "rusage_user ", MCM_CSTRLEN("rusage_user ")) == 0) {
	cur = &cur[MCM_CSTRLEN("rusage_user ")];
	s->rusage_user.tv_sec = (int32_t)strtol(cur, &cp, 10);
	if (s->rusage_user.tv_sec == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid rusage_user seconds");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
#ifdef DEBUG_MC_PROTO_ASSERT
	  if (!(*cur == '.' || *cur == ':'))
	    MCM_WARNX_MSG(MCM_ERR_PROTO, "invalid separator");
	  else {
#endif
	    cur += 1; /* advance past colon */
	    s->rusage_user.tv_usec = (int32_t)strtol(cur, &cp, 10);
	    if (s->rusage_user.tv_usec == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	      MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid rusage_user microseconds");
	      MCM_CLEAN_BUFS(ctxt, ms);
	      return NULL;
	    } else {
	      cur = cp;
	    }
#ifdef DEBUG_MC_PROTO_ASSERT
	  }
#endif
	}

      } else if (memcmp(cur, "rusage_system ", MCM_CSTRLEN("rusage_system ")) == 0) {
	cur = &cur[MCM_CSTRLEN("rusage_system ")];
	s->rusage_system.tv_sec = (int32_t)strtol(cur, &cp, 10);
	if (s->rusage_system.tv_sec == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid rusage_system seconds");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
#ifdef DEBUG_MC_PROTO_ASSERT
	  if (!(*cur == '.' || *cur == ':')) {
	    MCM_ERR_MSG(MCM_ERR_PROTO, "invalid separator");
	    MCM_CLEAN_BUFS(ctxt, ms);
	    return NULL;
	  } else {
#endif
	    cur += 1; /* advance past colon */
	    s->rusage_system.tv_usec = (int32_t)strtol(cur, &cp, 10);
	    if (s->rusage_system.tv_usec == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	      MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid rusage_system microseconds");
	      MCM_CLEAN_BUFS(ctxt, ms);
	      return NULL;
	    } else {
	      cur = cp;
	    }
#ifdef DEBUG_MC_PROTO_ASSERT
	  }
#endif
	}
      } else if (memcmp(cur, "curr_items ", MCM_CSTRLEN("curr_items ")) == 0) {
	cur = &cur[MCM_CSTRLEN("curr_items ")];
	s->curr_items = (u_int32_t)strtol(cur, &cp, 10);
	if (s->curr_items == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid curr_items");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
	}
      } else if (memcmp(cur, "total_items ", MCM_CSTRLEN("total_items ")) == 0) {
	cur = &cur[MCM_CSTRLEN("total_items ")];
	s->total_items = (u_int64_t)strtoll(cur, &cp, 10);
	if (s->total_items == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid total_items");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
	}
      } else if (memcmp(cur, "bytes ", MCM_CSTRLEN("bytes ")) == 0) {
	cur = &cur[MCM_CSTRLEN("bytes")];
	s->bytes = (u_int64_t)strtoll(cur, &cp, 10);
	if (s->bytes == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid bytes");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
	}
      } else if (memcmp(cur, "curr_connections ", MCM_CSTRLEN("curr_connections ")) == 0) {
	cur = &cur[MCM_CSTRLEN("curr_connections ")];
	s->curr_connections = (u_int32_t)strtol(cur, &cp, 10);
	if (s->curr_connections == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid curr_connections");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
	}
      } else if (memcmp(cur, "total_connections ", MCM_CSTRLEN("total_connections ")) == 0) {
	cur = &cur[MCM_CSTRLEN("total_connections ")];
	s->total_connections = (u_int64_t)strtoll(cur, &cp, 10);
	if (s->total_connections == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid total_connections");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
	}
      } else if (memcmp(cur, "connection_structures ", MCM_CSTRLEN("connection_structures ")) == 0) {
	cur = &cur[MCM_CSTRLEN("connection_structures ")];
	s->connection_structures = (u_int32_t)strtol(cur, &cp, 10);
	if (s->connection_structures == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid connection_structures");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
	}
      } else if (memcmp(cur, "cmd_get ", MCM_CSTRLEN("cmd_get ")) == 0) {
	cur = &cur[MCM_CSTRLEN("cmd_get ")];
	s->cmd_get = (u_int64_t)strtoll(cur, &cp, 10);
	if (s->cmd_get == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid cmd_get");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
	}
#ifdef SEAN_HACKS
      } else if (memcmp(cur, "cmd_refresh ", MCM_CSTRLEN("cmd_refresh ")) == 0) {
	cur = &cur[MCM_CSTRLEN("cmd_refresh ")];
	s->cmd_refresh = (u_int64_t)strtoll(cur, &cp, 10);
	if (s->cmd_refresh == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid cmd_refresh");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
	}
#endif
      } else if (memcmp(cur, "cmd_set ", MCM_CSTRLEN("cmd_set ")) == 0) {
	cur = &cur[MCM_CSTRLEN("cmd_set ")];
	s->cmd_set = (u_int64_t)strtoll(cur, &cp, 10);
	if (s->cmd_set == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid cmd_set");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
	}
      } else if (memcmp(cur, "get_hits ", MCM_CSTRLEN("get_hits ")) == 0) {
	cur = &cur[MCM_CSTRLEN("get_hits ")];
	s->get_hits = (u_int64_t)strtoll(cur, &cp, 10);
	if (s->get_hits == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid get_hits");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
	}
      } else if (memcmp(cur, "get_misses ", MCM_CSTRLEN("get_misses ")) == 0) {
	cur = &cur[MCM_CSTRLEN("get_misses ")];
	s->get_misses = (u_int64_t)strtoll(cur, &cp, 10);
	if (s->get_misses == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid get_misses");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
	}
#ifdef SEAN_HACKS
      } else if (memcmp(cur, "refresh_hits ", MCM_CSTRLEN("refresh_hits ")) == 0) {
	cur = &cur[MCM_CSTRLEN("refresh_hits ")];
	s->refresh_hits = (u_int64_t)strtoll(cur, &cp, 10);
	if (s->refresh_hits == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid refresh_hits");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
	}
      } else if (memcmp(cur, "refresh_misses ", MCM_CSTRLEN("refresh_misses ")) == 0) {
	cur = &cur[MCM_CSTRLEN("refresh_misses ")];
	s->refresh_misses = (u_int64_t)strtoll(cur, &cp, 10);
	if (s->refresh_misses == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid refresh_misses");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
	}
#endif
      } else if (memcmp(cur, "bytes_read ", MCM_CSTRLEN("bytes_read ")) == 0) {
	cur = &cur[MCM_CSTRLEN("bytes_read ")];
	s->bytes_read = (u_int64_t)strtoll(cur, &cp, 10);
	if (s->bytes_read == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid bytes_read");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
	}
      } else if (memcmp(cur, "bytes_written ", MCM_CSTRLEN("bytes_written ")) == 0) {
	cur = &cur[MCM_CSTRLEN("bytes_written ")];
	s->bytes_written = (u_int64_t)strtoll(cur, &cp, 10);
	if (s->bytes_written == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid bytes_written");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
	}
      } else if (memcmp(cur, "limit_maxbytes ", MCM_CSTRLEN("limit_maxbytes ")) == 0) {
	cur = &cur[MCM_CSTRLEN("limit_maxbytes ")];
	s->limit_maxbytes = (u_int64_t)strtoll(cur, &cp, 10);
	if (s->limit_maxbytes == 0 && ((errno == EINVAL && cp == cur) || errno == ERANGE)) {
	  MCM_ERR_MSG(MCM_ERR_LIB_STRTOL, "invalid limit_maxbytes");
	  MCM_CLEAN_BUFS(ctxt, ms);
	  return NULL;
	} else {
	  cur = cp;
	}
      } else {
	for (cp = cur; !isspace(*cp); cp++);
	MCM_WARNX_MSGLEN(MCM_ERR_UNKNOWN_STAT, cur, (int)(cp - cur));
	MCM_CLEAN_BUFS(ctxt, ms);
	return NULL;
      }

      /* Now that we've sucked in our stats value, set our cursor to
       * the end of the value. */
      if (!mcm_buf_end(ctxt, ms->rbuf, "\r\n", MCM_CSTRLEN("\r\n"))) {
	MCM_ERR_MSG(MCM_ERR_PROTO, "anticipated end of stats value: not at end of stats value");
	mcm_server_stats_free(ctxt, s);
	mcm_server_deactivate(ctxt, mc, ms);
	MCM_CLEAN_BUFS(ctxt, ms);
	return NULL;
      }
    } else if (cur != NULL && memcmp(cur, "END", MCM_CSTRLEN("END")) == 0) {
      /* We're done reading in stats. */
      break;
    } else {
      MCM_ERRX_MSG(MCM_ERR_PROTO, "unable to handle response");
      MCM_CLEAN_BUFS(ctxt, ms);
      return NULL;
    }
  }

  MCM_CLEAN_BUFS(ctxt, ms);
  return s;
}


int
mcm_server_timeout(const struct memcache_ctxt *ctxt, struct memcache_server *ms, const int sec, const int msec) {
  ms->tv.tv_sec = sec;
  ms->tv.tv_usec = msec;

#ifdef USE_SO_SNDTIMEO
  /* If any of the setsockopt(2) calls fail, close the socket, set the
   * file descriptor to -1, and continue trying to connect to the rest
   * of the servers that match this hostname.  More than likely there
   * is only one IP per host name, but, in the event there isn't,
   * continue to the next entry. */
  if (setsockopt(ms->fd, SOL_SOCKET, SO_SNDTIMEO, &ms->tv, (socklen_t)sizeof(struct timeval)) != 0) {
    MCM_ERR_MSG(MCM_ERR_SYS_SETSOCKOPT, "setsockopt(SO_SNDTIMEO) failed");
    return 0;
  }
#endif

#ifdef USE_SO_RCVTIMEO
  if (setsockopt(ms->fd, SOL_SOCKET, SO_RCVTIMEO, &ms->tv, (socklen_t)sizeof(struct timeval)) != 0) {
    MCM_ERR_MSG(MCM_ERR_SYS_SETSOCKOPT, "setsockopt(SO_RCVTIMEO) failed");
    return 0;
  }
#endif

  return 1;
}


void
mcm_server_stats_free(const struct memcache_ctxt *ctxt, struct memcache_server_stats *s) {
  if (s->version != NULL)
    ctxt->mcFree(s->version);
  ctxt->mcFree(s);
}


static struct memcache_server_stats *
mcm_server_stats_new(const struct memcache_ctxt *ctxt) {
  struct memcache_server_stats *s;
  s = (struct memcache_server_stats *)ctxt->mcMalloc(sizeof(struct memcache_server_stats));
  if (s != NULL) {
    bzero(s, sizeof(struct memcache_server_stats));
  }

  return s;
}


static int
mcm_server_writable(struct memcache_ctxt *ctxt, struct memcache_server *ms, struct timeval *tv) {
#ifndef HAVE_SELECT
  return 1;
#else
  struct timeval local_tv;
  socklen_t so_err_length;
  int ret, so_err;

  retry_check_writable:

  FD_ZERO(&ms->fds);
  FD_SET(ms->fd, &ms->fds);

#ifdef DEBUG_MC_PROTO_ASSERT
  if (FD_ISSET(ms->fd, &ms->fds) == 0) {
    MCM_ERRX(MCM_ERR_ASSERT);
    return -1;
  }
#endif

  memcpy(&local_tv, tv, sizeof(struct timeval));

#ifdef DEBUG_MC_PROTO
  do {
    char *tm;
    size_t tml;
    tml = asprintf(&tm, "Begin select(2)'ing to see if fd %d is write(2)able.  Timeout %llu.%llu", ms->fd, (u_int64_t)local_tv.tv_sec, (u_int64_t)local_tv.tv_usec);
    if (tml > 0 && tm != NULL) {
      MCM_WARNX_MSG(MCM_ERR_TRACE, tm);
      free(tm);
    }
  } while (0);
#endif

  /* Before we writev(2) anything, check to make sure the socket is
   * ready to accept data to be written out.  No sense in wastefully
   * calling writev(2) constantly in a loop. */
  ret = select(ms->fd + 1, NULL, &ms->fds, NULL, &local_tv);
#ifdef DEBUG_MC_PROTO
  do {
    char *tm;
    size_t tml;
    tml = asprintf(&tm, "write(2)able fds: %d/%d", ret, FD_SETSIZE);
    if (tml > 0 && tm != NULL) {
      MCM_WARNX_MSG(MCM_ERR_TRACE, tm);
      free(tm);
    }
  } while (0);
#endif
  if (ret > 0) {
    /* Check where writable flag is set */
    if (!FD_ISSET(ms->fd, &ms->fds)) {
      MCM_ERR(MCM_ERR_SYS_SELECT);
      return 0;
    }

    /* Check for the socket errors */
    so_err_length = sizeof(so_err);
    if (getsockopt(ms->fd, SOL_SOCKET, SO_ERROR, (void *)&so_err, &so_err_length) == -1) {
      MCM_ERR(MCM_ERR_SYS_SELECT); /* Socket error */
      return 0;
    } else {
      return ret;
    }
  } else if (ret == -1) {
    switch (errno) {
    case EINTR: /* retry this checking again */
      goto retry_check_writable;
    default:
      MCM_ERR(MCM_ERR_SYS_SELECT);
      return 0;
    }
  } else if (ret == 0) {
    MCM_ERR_MSG(MCM_ERR_TIMEOUT, "write select(2) call timed out");
    return 0;
  }

#ifdef DEBUG_MC_PROTO
  MCM_WARNX_MSG(MCM_ERR_TRACE, "End select(2)'ing to see if fd is write(2)able");
#endif

  return ret;
#endif
}


int
mcm_set(struct memcache_ctxt *ctxt, struct memcache *mc,
	char *key, const size_t key_len,
	const void *val, const size_t bytes,
	const time_t expire, const u_int16_t flags) {
  return mcm_storage_cmd(ctxt, mc, str_set_cmd, str_set_len, key, key_len, val, bytes, expire, flags);
}


struct memcache_server_stats *
mcm_stats(struct memcache_ctxt *ctxt, struct memcache *mc) {
  struct memcache_server *ms;
  struct memcache_server_stats *s, *ts;

  s = mcm_server_stats_new(ctxt);
  for (ms = mc->server_list.tqh_first; ms != NULL; ms = ms->entries.tqe_next) {
    ts = mcm_server_stats(ctxt, mc, ms);
    if (ts == NULL)
      continue;

    /* Merge the values from ts into s.  Any per-server specific data
     * is pulled from the last server. */
    s->pid = ts->pid;
    s->uptime = ts->uptime;
    s->time = ts->time;
    if (s->version == NULL && ts->version != NULL)
      s->version = mcm_strdup(ctxt, ts->version);

    s->rusage_user.tv_sec += ts->rusage_user.tv_sec;
    s->rusage_user.tv_usec += ts->rusage_user.tv_usec;
    if (s->rusage_user.tv_usec > 1000000) {
      s->rusage_user.tv_sec += s->rusage_user.tv_usec / 1000000;
      s->rusage_user.tv_usec -= 1000000 * (s->rusage_user.tv_usec / 1000000);
    }

    s->rusage_system.tv_sec += ts->rusage_system.tv_sec;
    s->rusage_system.tv_usec += ts->rusage_system.tv_usec;
    if (s->rusage_system.tv_usec > 1000000) {
      s->rusage_system.tv_sec += s->rusage_system.tv_usec / 1000000;
      s->rusage_system.tv_usec -= 1000000 * (s->rusage_system.tv_usec / 1000000);
    }

    s->curr_items += ts->curr_items;
    s->total_items += ts->total_items;
    s->bytes = s->bytes + ts->bytes;
    s->curr_connections += ts->curr_connections;
    s->total_connections += ts->total_connections;
    s->connection_structures += ts->connection_structures;
    s->cmd_get += ts->cmd_get;
#ifdef SEAN_HACKS
    s->cmd_refresh += ts->cmd_refresh;
#endif
    s->cmd_set += ts->cmd_set;
    s->get_hits += ts->get_hits;
    s->get_misses += ts->get_misses;
#ifdef SEAN_HACKS
    s->refresh_hits += ts->refresh_hits;
    s->refresh_misses += ts->refresh_misses;
#endif
    s->bytes_read += ts->bytes_read;
    s->bytes_written += ts->bytes_written;
    s->limit_maxbytes += ts->limit_maxbytes;

    mcm_server_stats_free(ctxt, ts);
  }

  return s;
}


static int
mcm_storage_cmd(struct memcache_ctxt *ctxt, struct memcache *mc,
		const char *cmd, const size_t cmd_len,
		char *key, const size_t key_len,
		const void *val, const size_t bytes,
		const time_t expire, const u_int16_t flags) {
  char numbuf[11]; /* 10 == (2 ** 32).to_s.length + '\0'.length */
  struct memcache_server *ms;
  u_int32_t hash;
  size_t i;
  char *cp;

  MCM_VALIDATE_KEY(key, key_len);

  /* Reset ctxt->errnum upon entry into memcache(3). */
  ctxt->errnum = 0;

  hash = ctxt->mcHashKey(ctxt, mc, key, key_len);

  ms = mcm_server_connect_next_avail(ctxt, mc, hash);
  if (ms == NULL)
    return -1;

  mcm_buf_append(ctxt, ms->wbuf, cmd, cmd_len);
  mcm_buf_append(ctxt, ms->wbuf, key, key_len);
  mcm_buf_append_char(ctxt, ms->wbuf, ' ');

  /* Convert the value to a string */
  i = (size_t)snprintf(numbuf, sizeof(numbuf), "%u", (u_int32_t)flags);
  if (i < 1) {
    MCM_ERR(MCM_ERR_LIB_SNPRINTF);
    MCM_CLEAN_BUFS(ctxt, ms);
    return (int)MCM_RET_CODE(-3);
  }

  mcm_buf_append(ctxt, ms->wbuf, numbuf, i);
  mcm_buf_append_char(ctxt, ms->wbuf, ' ');

  /* Convert the value to a string */
  i = (size_t)snprintf(numbuf, sizeof(numbuf), "%lu", (long int unsigned)expire);
  if (i < 1) {
    MCM_ERR(MCM_ERR_LIB_SNPRINTF);
    MCM_CLEAN_BUFS(ctxt, ms);
    return (int)MCM_RET_CODE(-5);
  }

  mcm_buf_append(ctxt, ms->wbuf, numbuf, i);
  mcm_buf_append_char(ctxt, ms->wbuf, ' ');

  /* Convert the value to a string */
  i = (size_t)snprintf(numbuf, sizeof(numbuf), "%lu", (long int unsigned)bytes);
  if (i < 1) {
    MCM_ERR(MCM_ERR_LIB_SNPRINTF);
    MCM_CLEAN_BUFS(ctxt, ms);
    return (int)MCM_RET_CODE(-7);
  }

  mcm_buf_append(ctxt, ms->wbuf, numbuf, i);
  mcm_buf_append(ctxt, ms->wbuf, str_endl, str_endl_len);

  /* Add the data */
  mcm_buf_append(ctxt, ms->wbuf, val, bytes);

  /* Add another carriage return */
  mcm_buf_append(ctxt, ms->wbuf, str_endl, str_endl_len);

  if (mcm_server_send_cmd(ctxt, mc, ms) < 0) {
    MCM_CLEAN_BUFS(ctxt, ms);
    return (int)MCM_RET_CODE(-8);
  }

  cp = mcm_get_line(ctxt, mc, ms);
  if (cp != NULL && memcmp(cp, "STORED", MCM_CSTRLEN("STORED")) == 0) {
    /* Groovy Tuesday */
    MCM_CLEAN_BUFS(ctxt, ms);
    return 0;
  } else if (cp != NULL && memcmp(cp, "NOT_STORED", MCM_CSTRLEN("NOT_STORED")) == 0) {
    /* Fuck beans.  That was them, wasn't it? */
    MCM_ERR_MSG(MCM_ERR_MC_STORE, cmd);
    MCM_CLEAN_BUFS(ctxt, ms);
    return (int)MCM_RET_CODE(1);
  } else if (cp != NULL && memcmp(cp, "SERVER_ERROR ", MCM_CSTRLEN("SERVER_ERROR ")) == 0) {
    /* Drat!  Not enough memory on the server for this key. */
    MCM_ERR_MSG(MCM_ERR_MC_STORE, cp + MCM_CSTRLEN("SERVER_ERROR "));
    MCM_CLEAN_BUFS(ctxt, ms);
    return (int)MCM_RET_CODE(4);
  }

  if (mc->num_servers == 0) {
    MCM_ERRX(MCM_ERR_MC_SERV_LIST);
    MCM_CLEAN_BUFS(ctxt, ms);
    return (int)MCM_RET_CODE(3);
  } else {
    MCM_CLEAN_BUFS(ctxt, ms);
    return (int)MCM_RET_CODE(2);
  }
}


char *
mcm_strdup(const struct memcache_ctxt *ctxt, const char *str) {
  return mcm_strndup(ctxt, str, strlen(str));
}


char *
mcm_strnchr(const struct memcache_ctxt *ctxt, mc_const char *str, int c, const size_t len) {
  char *cp;
  size_t i;

  for (cp = str, i = 0; i < len && *cp != '\0'; i++, cp++) {
    if (c == (int)*cp)
      return cp;
  }

  return '\0';
}


char *
mcm_strndup(const struct memcache_ctxt *ctxt, const char *str, const size_t len) {
  char *cp;

  cp = ctxt->mcMallocAtomic(len + MCM_CSTRLEN("\0"));
  if (cp != NULL) {
    memcpy(cp, str, len);
    cp[len] = '\0';
  }

  return cp;
}


/*
 * Find the first occurrence of find in s, where the search is limited to the
 * first slen characters of s.
 */
char *
mcm_strnstr(const struct memcache_ctxt *ctxt, mc_const char *s, const char *find, size_t slen) {
  char c, sc;
  size_t len;

  if ((c = *find++) != '\0') {
    len = strlen(find);
    do {
      do {
	if (slen-- < 1 || (sc = *s++) == '\0')
	  return (NULL);
      } while (sc != c);
      if (len > slen)
	return (NULL);
    } while (strncmp(s, find, len) != 0);
    s--;
  }
  return ((char *)s);
}


void
mcm_timeout(const struct memcache_ctxt *ctxt, struct memcache *mc, const int sec, const int msec) {
  mc->tv.tv_sec = sec;
  mc->tv.tv_usec = msec;
}


inline static int32_t
mcm_validate_key(const struct memcache_ctxt *ctxt, char *key, size_t len) {
  return (ctxt->mcKeyValid != NULL ? ctxt->mcKeyValid(ctxt, key, len) : 0);
}


static int32_t
mcm_validate_key_func(MCM_KEY_VALID_FUNC_ARGS) {
  const struct memcache_ctxt *ctxt;
  char *cp, *key;
  size_t len;
  size_t i;

  MCM_KEY_VALID_INIT(ctxt, key, len);

  for (i = 0, cp = key; i < len; i++, cp++) {
    if (isspace(*cp)) {
      MCM_ERRX_MSG_LVL(MCM_ERR_PROTO, "isspace(3) returned true for character in key", MCM_ERR_LVL_ERR);
      return (int32_t)MCM_RET_CODE((int32_t)(i + 1));
    }
  }

  return 0;
}


u_int32_t
mcm_vernum(const struct memcache_ctxt *ctxt) {
  return MEMCACHE_VERNUM;
}


const char *
mcm_version(const struct memcache_ctxt *ctxt) {
  return MEMCACHE_VER;
}


/* BEGIN memcache memory API */
int
mcErrGet(mcErrFunc *errFunc) {
  if (errFunc != NULL)
    *errFunc = mcGlobalCtxt.mcErr;

  return 0;
}


int
mcErrSetup(mcErrFunc errFunc) {
  return mcErrSetupCtxt(&mcGlobalCtxt, errFunc);
}


int
mcErrSetupCtxt(struct memcache_ctxt *ctxt, mcErrFunc errFunc) {
  if (ctxt == NULL || errFunc == NULL)
    return 1;

  ctxt->mcErr = errFunc;

  return 0;
}


int
mcMemGet(mcFreeFunc *freeFunc, mcMallocFunc *mallocFunc, mcMallocFunc *mallocAtomicFunc,
	 mcReallocFunc *reallocFunc) {
  if (freeFunc != NULL)
    *freeFunc = mcGlobalCtxt.mcFree;

  if (mallocFunc != NULL)
    *mallocFunc = mcGlobalCtxt.mcMalloc;

  if (mallocAtomicFunc != NULL)
    *mallocAtomicFunc = mcGlobalCtxt.mcMallocAtomic;

  if (reallocFunc != NULL)
    *reallocFunc = mcGlobalCtxt.mcRealloc;

  return 0;
}


struct memcache_ctxt *
mcMemNewCtxt(mcFreeFunc freeFunc, mcMallocFunc mallocFunc, mcMallocFunc mallocAtomicFunc,
	     mcReallocFunc reallocFunc) {
  struct memcache_ctxt *ctxt;

  if (freeFunc == NULL || mallocFunc == NULL || reallocFunc == NULL)
    return NULL;

  ctxt = mallocFunc(sizeof(struct memcache_ctxt));
  if (ctxt != NULL) {
    bzero(ctxt, sizeof(struct memcache_ctxt));

    ctxt->ectxt = mallocFunc(sizeof(struct memcache_err_ctxt));
    if (ctxt->ectxt == NULL) {
      freeFunc(ctxt);
      return NULL;
    }
    bzero(ctxt->ectxt, sizeof(struct memcache_err_ctxt));

    if (mcMemSetupCtxt(ctxt, freeFunc, mallocFunc, mallocAtomicFunc, reallocFunc) != 0) {
      bzero(ctxt, sizeof(struct memcache_ctxt));
      freeFunc(ctxt->ectxt);
      freeFunc(ctxt);
      return NULL;
    }

    /* Install our default error handler */
    ctxt->mcErr = mcm_err_func;
    ctxt->mcKeyValid = mcm_validate_key_func;
    ctxt->mcHashKey = mcm_hash_key_func;
    ctxt->mcServerFind = mcm_server_find_func;

    /* By default, ignore INFO and NOTICE level messages */
    ctxt->MCM_ERR_MASK = MCM_ERR_LVL_INFO | MCM_ERR_LVL_NOTICE;
  }
  return ctxt;
}


void
mcMemFreeCtxt(struct memcache_ctxt *ctxt) {
  mcFreeFunc freeFunc;

  if (ctxt == NULL || ctxt->mcFree == NULL)
    return;

  freeFunc = ctxt->mcFree;
  freeFunc(ctxt->ectxt);
  freeFunc(ctxt);
}


int
mcMemSetup(mcFreeFunc freeFunc, mcMallocFunc mallocFunc,
	   mcMallocFunc mallocAtomicFunc, mcReallocFunc reallocFunc) {
  return mcMemSetupCtxt(&mcGlobalCtxt, freeFunc, mallocFunc, mallocAtomicFunc, reallocFunc);
}


int
mcMemSetupCtxt(struct memcache_ctxt *ctxt, mcFreeFunc freeFunc, mcMallocFunc mallocFunc,
	       mcMallocFunc mallocAtomicFunc, mcReallocFunc reallocFunc) {
  if (ctxt == NULL || freeFunc == NULL || mallocFunc == NULL || reallocFunc == NULL)
    return(1);

  ctxt->mcFree = freeFunc;
  ctxt->mcMalloc = mallocFunc;
  ctxt->mcMallocAtomic = (mallocAtomicFunc != NULL ? mallocAtomicFunc : mallocFunc);
  ctxt->mcRealloc = reallocFunc;

  return 0;
}
/* END memcache memory API */
