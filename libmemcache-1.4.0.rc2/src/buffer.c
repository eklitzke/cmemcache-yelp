/*
 * Copyright (c) 2005 Sean Chittenden <sean@chittenden.org>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
# include <limits.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/errno.h>

#include "memcache/buffer.h"


int
mcm_buf_append(struct memcache_ctxt *ctxt, struct memcache_buf *buf, const char *cp, const u_int32_t len) {
  if (len == 0)
    return 1;
  else if (mcm_buf_len(ctxt, buf) + len >= mcm_buf_size(ctxt, buf))
    mcm_buf_realloc(ctxt, buf, mcm_buf_len(ctxt, buf) + len + MCM_CSTRLEN("\0"));

  bcopy(cp, &(buf->ptr)[mcm_buf_len(ctxt, buf)], len);
  mcm_buf_len_add(ctxt, buf, len);
  buf->ptr[mcm_buf_len(ctxt, buf)] = '\0';

  return 1;
}


int
mcm_buf_append2(struct memcache_ctxt *ctxt, struct memcache_buf *buf, const char *cp) {
  return mcm_buf_append(ctxt, buf, cp, strlen(cp));
}


int
mcm_buf_append_buf(struct memcache_ctxt *ctxt, struct memcache_buf *buf, struct memcache_buf *buf2) {
  return mcm_buf_append(ctxt, buf, mcm_buf_to_cstr(ctxt, buf2), mcm_buf_len(ctxt, buf2));
}


int
mcm_buf_append_char(struct memcache_ctxt *ctxt, struct memcache_buf *buf, const char c) {
  if (mcm_buf_size(ctxt, buf) < mcm_buf_len(ctxt, buf) + sizeof(c) + MCM_CSTRLEN("\0"))
    mcm_buf_realloc(ctxt, buf, mcm_buf_size(ctxt, buf) + MCM_CSTRLEN("\0"));

  (buf->ptr)[mcm_buf_len(ctxt, buf)] = c;
  mcm_buf_len_add(ctxt, buf, 1);
  (buf->ptr)[mcm_buf_len(ctxt, buf)] = '\0';

  return 1;
}


int
mcm_buf_cmp(struct memcache_ctxt *ctxt, const struct memcache_buf *buf1, const char *buf2, const size_t buf2_len) {
  if (buf1 == NULL || buf2 == NULL)
    return 0;

  if (buf1->ptr == buf2)
    return 1;

  if (mcm_buf_len(ctxt, buf1) != buf2_len)
    return 0;

  if (memcmp(buf1->ptr, buf2, buf2_len) == 0)
    return 1;
  else
    return 0;
}


int
mcm_buf_cmp2(struct memcache_ctxt *ctxt, const struct memcache_buf *buf1, const char *buf2) {
  return mcm_buf_cmp(ctxt, buf1, buf2, strlen(buf2));
}


int
mcm_buf_cmp_buf(struct memcache_ctxt *ctxt, const struct memcache_buf *buf1, const struct memcache_buf *buf2) {
  if (buf1 == NULL || buf2 == NULL)
    return 0;

  if (buf1 == buf2)
    return 1;

  if (mcm_buf_len(ctxt, buf1) != mcm_buf_len(ctxt, buf2))
    return 0;

  if (memcmp(buf1->ptr, buf2->ptr, mcm_buf_len(ctxt, buf1)) == 0)
    return 1;
  else
    return 0;
}


int
mcm_buf_compact(struct memcache_ctxt *ctxt, struct memcache_buf *buf) {
  return mcm_buf_realloc(ctxt, buf, mcm_buf_len(ctxt, buf) + MCM_CSTRLEN("\0"));
}


struct memcache_buf *
mcm_buf_copy(struct memcache_ctxt *ctxt, struct memcache_buf *buf) {
  return mcm_buf_new2(ctxt, buf->ptr, mcm_buf_len(ctxt, buf));
}


void
mcm_buf_eat_line(struct memcache_ctxt *ctxt, struct memcache_buf *buf) {
  char *cp;

  cp = memchr(mcm_buf_off_ptr(ctxt, buf), (int)'\n', mcm_buf_remain_off(ctxt, buf));
  if (cp == NULL) {
    MCM_ERRX_MSG(MCM_ERR_ASSERT, "newline expected but not found");
    return;
  }

  buf->off += cp - mcm_buf_off_ptr(ctxt, buf) + 1;
  return;
}


int
mcm_buf_end(struct memcache_ctxt *ctxt, const struct memcache_buf *buf1, const char *buf2, const size_t buf2_len) {
  char *cp = NULL;

  if (buf1 == NULL || buf2 == NULL)
    return 0;

  if (mcm_buf_len(ctxt, buf1) < (u_int32_t)buf2_len)
    return 0;

  /* Find the last mcm_buf_len(ctxt, buf2) bytes of buf1 and memcmp(3)
   * the two memory regions to see if they're the same. */
  cp = &(buf1->ptr)[mcm_buf_len(ctxt, buf1) - buf2_len];
  if (memcmp(cp, buf2, buf2_len) == 0)
    return 1;
  else
    return 0;
}


int
mcm_buf_end2(struct memcache_ctxt *ctxt, const struct memcache_buf *buf1, const char *buf2) {
  return mcm_buf_end(ctxt, buf1, buf2, strlen(buf2));
}


int
mcm_buf_end_buf(struct memcache_ctxt *ctxt, const struct memcache_buf *buf1, struct memcache_buf *buf2) {
  return mcm_buf_end(ctxt, buf1, mcm_buf_to_cstr(ctxt, buf2), mcm_buf_len(ctxt, buf2));
}


char *
mcm_buf_find(struct memcache_ctxt *ctxt, const struct memcache_buf *buf, const char *find) {
  return mcm_buf_find2(ctxt, buf, find, strlen(find));
}


char *
mcm_buf_find2(struct memcache_ctxt *ctxt, const struct memcache_buf *buf, const char *find, const size_t len) {
  if (buf == NULL || buf->ptr == NULL || find == NULL)
    return NULL;

  return mcm_strnstr(ctxt, (char *)buf->ptr, find, len);
}


char *
mcm_buf_find_buf(struct memcache_ctxt *ctxt, const struct memcache_buf *buf, const struct memcache_buf *find) {
  return mcm_buf_find2(ctxt, buf, find->ptr, mcm_buf_len(ctxt, find));
}


struct memcache_buf *
mcm_buf_find_replace(struct memcache_ctxt *ctxt,
		     struct memcache_buf *orig,
		     struct memcache_buf *old,
		     struct memcache_buf *new) {
  struct memcache_buf *ret;
  size_t remaining;
  char *cp, *start;

  ret = mcm_buf_new(ctxt);
  start = mcm_buf_to_cstr(ctxt, orig);
  remaining = mcm_buf_len(ctxt, orig);
  while (remaining) {
    cp = mcm_strnstr(ctxt, start, mcm_buf_to_cstr(ctxt, old), remaining);
    if (cp == NULL) {
      mcm_buf_append(ctxt, ret, start, remaining);
      break;
    }

    mcm_buf_append(ctxt, ret, start, cp - start);
    mcm_buf_append_buf(ctxt, ret, new);

    cp += mcm_buf_len(ctxt, old);
    remaining -= cp - start;
    start = cp;
  }

  return ret;
}


struct memcache_buf *
mcm_buf_find_replace2(struct memcache_ctxt *ctxt, struct memcache_buf *orig,
		      const char *old, struct memcache_buf *new) {
  struct memcache_buf *wrapper;
  struct memcache_buf *ret;

  wrapper = mcm_buf_new3(ctxt, old);
  ret = mcm_buf_find_replace(ctxt, orig, wrapper, new);
  mcm_buf_free(ctxt, &wrapper);
  return ret;
}


int
mcm_buf_free(struct memcache_ctxt *ctxt, struct memcache_buf **buf) {
  if ((*buf)->ptr != NULL) {
    ctxt->mcFree((*buf)->ptr);
    (*buf)->ptr = NULL;
  }
  ctxt->mcFree(*buf);
  *buf = NULL;

  return 1;
}


inline u_int32_t
mcm_buf_len(const struct memcache_ctxt *ctxt, const struct memcache_buf *s) {
  return s->len;
}


struct memcache_buf *
mcm_buf_new(struct memcache_ctxt *ctxt) {
  struct memcache_buf *buf;

  buf = ctxt->mcMalloc(sizeof(struct memcache_buf));
  if (buf != NULL) {
    bzero(buf, sizeof(struct memcache_buf));
  }

  if (mcm_buf_realloc(ctxt, buf, INIT_GET_BUF_SIZE)) {
    buf->ptr[0] = '\0';
  } else {
    buf->ptr = NULL;
    mcm_buf_free(ctxt, &buf);
    return NULL;
  }

  return buf;
}


struct memcache_buf *
mcm_buf_new2(struct memcache_ctxt *ctxt, const char* cp, const u_int32_t len) {
  struct memcache_buf *buf;

  buf = mcm_buf_new(ctxt);
  if (mcm_buf_append(ctxt, buf, cp, len) == 1) {
    return buf;
  } else {
    mcm_buf_free(ctxt, &buf);
    return NULL;
  }
}


struct memcache_buf *
mcm_buf_new3(struct memcache_ctxt *ctxt, const char *cp) {
  return mcm_buf_new2(ctxt, cp, strlen(cp));
}


size_t
mcm_buf_read(struct memcache_ctxt *ctxt, struct memcache_buf *buf, int fd) {
  size_t bytes_read = 0, remain;
  ssize_t rb;

  read_more:
  /* Make sure we have space available to read(2) data into */
  remain = mcm_buf_remain(ctxt, buf);
  if (remain == 0) {
    if (!mcm_buf_realloc(ctxt, buf, mcm_buf_size(ctxt, buf) * 2)) /* Double our size */
      return bytes_read;
    remain = mcm_buf_remain(ctxt, buf);
  }

  rb = read(fd, mcm_buf_tail(ctxt, buf), remain);
#ifdef DEBUG_MC_PROTO
  do {
    char *tm;
    size_t tml;
    tml = asprintf(&tm, "%d = read(2)'s buf: \"%.*s\", errno = %d", (int)rb, rb, mcm_buf_tail(ctxt, buf), errno);
    if (tml > 0 && tm != NULL) {
      MCM_WARNX_MSG(MCM_ERR_TRACE, tm);
      free(tm);
    }
  } while (0);
#endif

  if (rb == -1) {
    switch (errno) {
    case EAGAIN:
    case EINTR:
      goto read_more;
    case ECONNRESET:
    case EINVAL:
      /* The server was restarted.  We return and let the caller
       * figure out if they want to resend the command or bail. */
      MCM_ERR_MSG_LVL(MCM_ERR_SYS_READ, strerror(errno), MCM_ERR_LVL_INFO);

      return bytes_read;
    case EBADF:
    case EFAULT:
      /* This shouldn't happen and if it does, we're pooched: better
       * dump. */
      MCM_ERR_MSG_LVL(MCM_ERR_SYS_READ, strerror(errno), MCM_ERR_LVL_FATAL);
      break;

    default:
      /* We shouldn't ever get here. */
      MCM_ERR_MSG(MCM_ERR_ASSERT, strerror(errno));
      return bytes_read;
    }
  } else if (rb == 0) {
    MCM_ERR_MSG(MCM_ERR_SYS_READ, "server unexpectedly closed connection");
    return bytes_read;
  } else {
    /* We read something in */
    mcm_buf_len_add(ctxt, buf, rb);
    bytes_read += rb;
  }

  return bytes_read;
}


int
mcm_buf_realloc(struct memcache_ctxt *ctxt, struct memcache_buf *buf, const u_int32_t size) {
  size_t ns;
  void *ptr;

  if (mcm_buf_size(ctxt, buf) == 0) {
    buf->ptr = ctxt->mcMalloc(size);
    if (buf->ptr == NULL) {
      MCM_ERR(MCM_ERR_MEM_MALLOC);
      return 0;
    }
    buf->size = size;
  } else if (size > mcm_buf_size(ctxt, buf)) {
    /* XXX Again, need a hint as to how big we should make the bufing.
     * Is it growing at a fast rate?  Is it shrinking?  Should we only
     * call realloc after a buffer has shrunk or on the last call to
     * reduce the number of realloc calls?  What about buffers that
     * are growing and shrinking constantly?  We need a stats object
     * that'd give us hints as to what the growth rate, frequency of
     * calling is, etc. that way we can adapt here beyond being
     * braindead and using a double or use the requested buffer
     * size. */
    ns = (size > mcm_buf_size(ctxt, buf) * 2 ? size : mcm_buf_size(ctxt, buf) * 2);
    ptr = ctxt->mcRealloc(buf->ptr, ns);
    if (ptr == NULL) {
      MCM_ERR(MCM_ERR_MEM_REALLOC);
      return 0;
    }
    buf->ptr = ptr;
    buf->size = ns;
  } else if (size == 0) {
    /* No-op, but don't raise an exception */
    return 1;
  } else if (size < mcm_buf_size(ctxt, buf)) {
    ptr = (char *)ctxt->mcRealloc(buf->ptr, size);
    if (ptr == NULL) {
      MCM_ERR(MCM_ERR_MEM_REALLOC);
      return 0;
    }
    buf->ptr = ptr;
    buf->size = size;
  } else if (size == mcm_buf_size(ctxt, buf)) {
    /* Not much to do in this case, but the action didn't fail as far
     * as the programmer is concerned... even though it was an
     * effective no-op */
    return 1;
  } else {
    MCM_ERRX_MSG(MCM_ERR_ASSERT, "realloc(3) imposibilitiy");
    return 0;
  }

  return 1;
}


inline size_t
mcm_buf_remain(const struct memcache_ctxt *ctxt, const struct memcache_buf *buf) {
  return mcm_buf_size(ctxt, buf) - mcm_buf_len(ctxt, buf);
}


inline size_t
mcm_buf_remain_off(const struct memcache_ctxt *ctxt, const struct memcache_buf *buf) {
  return mcm_buf_len(ctxt, buf) - buf->off;
}


int
mcm_buf_replace(struct memcache_ctxt *ctxt, struct memcache_buf *buf, const char *cp, const u_int32_t len) {
  if (mcm_buf_reset(ctxt, buf) == 0)
    return 0;

  return mcm_buf_append(ctxt, buf, cp, len);
}


int
mcm_buf_replace2(struct memcache_ctxt *ctxt, struct memcache_buf *buf, const char *cp) {
  if (mcm_buf_reset(ctxt, buf) == 0)
    return 0;

  return mcm_buf_append2(ctxt, buf, cp);
}


int
mcm_buf_replace_buf(struct memcache_ctxt *ctxt, struct memcache_buf *buf, struct memcache_buf *buf2) {
  if (mcm_buf_reset(ctxt, buf) == 0)
    return 0;

  return mcm_buf_append_buf(ctxt, buf, buf2);
}


int
mcm_buf_reset(struct memcache_ctxt *ctxt, struct memcache_buf *buf) {
  if (buf == NULL)
    return 0;

  buf->off = 0;
  if ((buf->flags & MCM_BUF_OFF_USED) == MCM_BUF_OFF_USED)
    buf->flags &= ~MCM_BUF_OFF_USED;

  if (buf->ptr != NULL) {
    mcm_buf_len_set(ctxt, buf, 0);
    buf->ptr[0] = '\0';
  }

  return 1;
}


int
mcm_buf_resize(struct memcache_ctxt *ctxt, struct memcache_buf *buf, const u_int32_t size) {
  if (mcm_buf_realloc(ctxt, buf, size + MCM_CSTRLEN("\0")) == 0)
    return 0;

  mcm_buf_len_set(ctxt, buf, size);

  if (mcm_buf_len(ctxt, buf) < size)
    buf->ptr[mcm_buf_len(ctxt, buf)] = '\0';

  return 1;
}


char *
mcm_buf_tail(struct memcache_ctxt *ctxt, struct memcache_buf *buf) {
  return &(buf->ptr[mcm_buf_len(ctxt, buf)]);
}


char *
mcm_buf_to_cstr(struct memcache_ctxt *ctxt, struct memcache_buf *buf) {
  if (buf == NULL)
    abort();

  return buf->ptr;
}


struct memcache_buf *
mcm_buf_to_upper(struct memcache_ctxt *ctxt, struct memcache_buf *buf) {
  struct memcache_buf *ret;
  u_int32_t i, len;

  len = mcm_buf_len(ctxt, buf);
  ret = mcm_buf_copy(ctxt, buf);
  for (i = 0; i < len; i++) {
    ret->ptr[i] = (char)toupper((int)buf->ptr[i]);
  }
  return ret;
}
