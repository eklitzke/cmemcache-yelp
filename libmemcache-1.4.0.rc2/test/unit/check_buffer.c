#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "buffer.h"
#include "memcache.h"

Suite *buffer_suite(void);
struct memcache_ctxt *ctxt = NULL;

/* Convenience macro */
#define FREE(b) fail_if(mcm_buf_free(ctxt, &b) != 1, "mcm_buf_free() failed")


START_TEST(buf_append_buf) {
  struct memcache_buf *buf1, *buf2;

  buf1 = mcm_buf_new3(ctxt, "testing");
  fail_if(buf1 == NULL, "mcm_buf_new3() returned null");
  buf2 = mcm_buf_new3(ctxt, " append");
  fail_if(buf2 == NULL, "mcm_buf_new3() returned null");
  mcm_buf_append_buf(ctxt, buf1, buf2);
  fail_if(mcm_buf_len(ctxt, buf1) != MCM_CSTRLEN("testing append"), "length incorrect");
  fail_if(memcmp("testing append", mcm_buf_to_cstr(ctxt, buf1), mcm_buf_len(ctxt, buf1)) != 0, "content different");
  fail_if(mcm_buf_to_cstr(ctxt, buf1)[mcm_buf_len(ctxt, buf1)] != '\0', "no trailing null character");

  FREE(buf1);
  FREE(buf2);
}
END_TEST


START_TEST(buf_append_char) {
  struct memcache_buf *buf;

  buf = mcm_buf_new3(ctxt, "testing");
  fail_if(buf == NULL, "mcm_buf_new3() failed");
  mcm_buf_append_char(ctxt, buf, ' ');
  mcm_buf_append_char(ctxt, buf, 'a');
  mcm_buf_append_char(ctxt, buf, 'p');
  mcm_buf_append_char(ctxt, buf, 'p');
  mcm_buf_append_char(ctxt, buf, 'e');
  mcm_buf_append_char(ctxt, buf, 'n');
  mcm_buf_append_char(ctxt, buf, 'd');
  fail_if(mcm_buf_len(ctxt, buf) != 14, "unexpected length");
  fail_if(memcmp("testing append", mcm_buf_to_cstr(ctxt, buf), mcm_buf_len(ctxt, buf)) != 0, "value not what expected");
  fail_if(mcm_buf_to_cstr(ctxt, buf)[mcm_buf_len(ctxt, buf)] != '\0', "no trailing null character");

  FREE(buf);
}
END_TEST


START_TEST(buf_append_str) {
  struct memcache_buf *buf;

  buf = mcm_buf_new3(ctxt, "testing");
  fail_if(buf == NULL, "mcm_buf_new3() returned null");
  mcm_buf_append(ctxt, buf, " append", MCM_CSTRLEN(" append"));
  fail_if(mcm_buf_len(ctxt, buf) != MCM_CSTRLEN("testing append"), "length incorrect");
  fail_if(memcmp("testing append", mcm_buf_to_cstr(ctxt, buf), mcm_buf_len(ctxt, buf)) != 0, "content different");
  fail_if(mcm_buf_to_cstr(ctxt, buf)[mcm_buf_len(ctxt, buf)] != '\0', "no trailing null character");

  FREE(buf);
}
END_TEST


START_TEST(buf_append_str2) {
  struct memcache_buf *buf;

  buf = mcm_buf_new3(ctxt, "testing");
  fail_if(buf == NULL, "mcm_buf_new3() returned null");
  mcm_buf_append2(ctxt, buf, " append");
  fail_if(mcm_buf_len(ctxt, buf) != MCM_CSTRLEN("testing append"), "length incorrect");
  fail_if(memcmp("testing append", mcm_buf_to_cstr(ctxt, buf), mcm_buf_len(ctxt, buf)) != 0, "content different");
  fail_if(mcm_buf_to_cstr(ctxt, buf)[mcm_buf_len(ctxt, buf)] != '\0', "no trailing null character");

  FREE(buf);
}
END_TEST


START_TEST(buf_cmp) {
  struct memcache_buf *buf;

  buf = mcm_buf_new3(ctxt, "asdfasdf wr4 234 \n");
  fail_if(buf == NULL, "mcm_buf_new3() returned null");
  fail_if(mcm_buf_cmp(ctxt, buf, "asdfasdf wr4 234 \n", mcm_buf_len(ctxt, buf)) != 1, "mem compare failed");

  FREE(buf);
}
END_TEST


START_TEST(buf_cmp2) {
  struct memcache_buf *buf;

  buf = mcm_buf_new3(ctxt, "asdfasdf wr4 234 \n");
  fail_if(buf == NULL, "mcm_buf_new3() returned null");
  fail_if(mcm_buf_cmp(ctxt, buf, "asdfasdf wr4 234 ", mcm_buf_len(ctxt, buf)) != 0, "mem compare failed");

  FREE(buf);
}
END_TEST


START_TEST(buf_cmp3) {
  struct memcache_buf *buf;

  buf = mcm_buf_new3(ctxt, "asdfasdf wr4 234 ");
  fail_if(buf == NULL, "mcm_buf_new3() returned null");
  fail_if(mcm_buf_cmp(ctxt, buf, "asdfasdf wr4 234 \n", mcm_buf_len(ctxt, buf)) != 1, "mem compare failed");

  FREE(buf);
}
END_TEST


START_TEST(buf_cmp_buf) {
  struct memcache_buf *buf1, *buf2;

  buf1 = mcm_buf_new3(ctxt, "asdfasdf wr4 234 ");
  fail_if(buf1 == NULL, "mcm_buf_new3() returned null");
  buf2 = mcm_buf_new3(ctxt, "asdfasdf wr4 234 ");
  fail_if(buf2 == NULL, "mcm_buf_new3() returned null");
  fail_if(mcm_buf_cmp_buf(ctxt, buf1, buf2) != 1, "cmp_buf failed");

  FREE(buf1);
  FREE(buf2);
}
END_TEST


START_TEST(buf_cmp_buf2) {
  struct memcache_buf *buf1, *buf2;

  buf1 = mcm_buf_new3(ctxt, "asdfasdf wr4 234 ");
  fail_if(buf1 == NULL, "mcm_buf_new3() returned null");
  buf2 = mcm_buf_new3(ctxt, "asdfasdf wr4 234 \n");
  fail_if(buf2 == NULL, "mcm_buf_new3() returned null");
  fail_if(mcm_buf_cmp_buf(ctxt, buf1, buf2) != 0, "cmp_buf failed");

  FREE(buf1);
  FREE(buf2);
}
END_TEST


START_TEST(buf_compact) {
  struct memcache_buf *buf;

  buf = mcm_buf_new3(ctxt, "foobar");
  fail_if(buf == NULL, "mcm_buf_new3() returned null");
  fail_if(mcm_buf_reset(ctxt, buf) == 0, "reset failed");
  mcm_buf_append_char(ctxt, buf, 'f');
  fail_if(mcm_buf_compact(ctxt, buf) == 0, "compact failed");
  fail_if(mcm_buf_size(ctxt, buf) != MCM_CSTRLEN("f\0"), "length not correct");

  FREE(buf);
}
END_TEST


START_TEST(buf_copy) {
  struct memcache_buf *buf1, *buf2;

  buf1 = mcm_buf_new3(ctxt, "foo");
  fail_if(buf1 == NULL, "mcm_buf_new3() returned null");
  buf2 = mcm_buf_copy(ctxt, buf1);
  fail_if(buf2 == NULL, "mcm_buf_copy() failed");
  fail_if(mcm_buf_cmp_buf(ctxt, buf1, buf2) == 0, "cmp failed");

  FREE(buf1);
  FREE(buf2);
}
END_TEST


START_TEST(buf_end_buf) {
  struct memcache_buf *buf1, *buf2;

  buf1 = mcm_buf_new3(ctxt, "foo bar baz test");
  fail_if(buf1 == NULL, "mcm_buf_new3() returned null");
  buf2 = mcm_buf_new3(ctxt, "baz test");
  fail_if(buf2 == NULL, "mcm_buf_copy() failed");
  fail_if(mcm_buf_end_buf(ctxt, buf1, buf2) != 1, "end failed");

  FREE(buf1);
  FREE(buf2);
}
END_TEST


START_TEST(buf_end_buf2) {
  struct memcache_buf *buf1, *buf2;

  buf1 = mcm_buf_new3(ctxt, "foo bar baz test");
  fail_if(buf1 == NULL, "mcm_buf_new3() returned null");
  buf2 = mcm_buf_new3(ctxt, "baz test\0");
  fail_if(buf2 == NULL, "mcm_buf_copy() failed");

  /* This should pass because we're explicitly checking for the
   * newline. */
  fail_if(mcm_buf_end_buf(ctxt, buf1, buf2) != 1, "end failed");

  FREE(buf1);
  FREE(buf2);
}
END_TEST


START_TEST(buf_end_buf3) {
  struct memcache_buf *buf1, *buf2;

  buf1 = mcm_buf_new3(ctxt, "foo bar baz test");
  fail_if(buf1 == NULL, "mcm_buf_new3() returned null");
  buf2 = mcm_buf_new3(ctxt, "baz test\n");
  fail_if(buf2 == NULL, "mcm_buf_copy() failed");
  fail_if(mcm_buf_end_buf(ctxt, buf1, buf2) != 0, "end failed");

  FREE(buf1);
  FREE(buf2);
}
END_TEST


START_TEST(buf_free) {
  struct memcache_buf *buf;

  buf = mcm_buf_new3(ctxt, "foo bar baz test");
  fail_if(buf == NULL, "mcm_buf_new3() returned null");
  fail_if(mcm_buf_free(ctxt, &buf) != 1, "mcm_buf_free() failed");
  fail_if(buf != NULL, "mcm_buf_free() didn't set buf to NULL");
}
END_TEST


START_TEST(buf_new) {
  struct memcache_buf *buf;

  buf = mcm_buf_new(ctxt);
  fail_if(buf == NULL, "mcm_buf_new() failed");
  fail_if(mcm_buf_len(ctxt, buf) != 0, "len not zero");
  fail_if(mcm_buf_size(ctxt, buf) != INIT_GET_BUF_SIZE, "size not zero");
  fail_if(mcm_buf_to_cstr(ctxt, buf) == NULL, "ptr not null");
  fail_if(mcm_buf_to_cstr(ctxt, buf)[0] != '\0', "ptr[0] not null");

  FREE(buf);
}
END_TEST


START_TEST(buf_new2) {
  struct memcache_buf *buf;

  buf = mcm_buf_new2(ctxt, "memcache(3)++", 8);
  fail_if(buf == NULL, "mcm_buf_new() failed");
  fail_if(mcm_buf_len(ctxt, buf) != MCM_CSTRLEN("memcache"), "len not correct");
  fail_if(memcmp("memcache", mcm_buf_to_cstr(ctxt, buf), mcm_buf_len(ctxt, buf)) != 0, "cmp failed");
  fail_if(mcm_buf_to_cstr(ctxt, buf)[MCM_CSTRLEN("memcache")] != '\0', "ptr null terminated");

  FREE(buf);
}
END_TEST


START_TEST(buf_new3) {
  struct memcache_buf *buf;

  buf = mcm_buf_new3(ctxt, "memcache(3)++");
  fail_if(buf == NULL, "mcm_buf_new() failed");
  fail_if(mcm_buf_len(ctxt, buf) != MCM_CSTRLEN("memcache(3)++"), "len not correct");
  fail_if(memcmp("memcache(3)++", mcm_buf_to_cstr(ctxt, buf), mcm_buf_len(ctxt, buf)) != 0, "cmp failed");
  fail_if(mcm_buf_to_cstr(ctxt, buf)[MCM_CSTRLEN("memcache(3)++")] != '\0', "ptr null terminated");

  FREE(buf);
}
END_TEST


START_TEST(buf_realloc) {
  struct memcache_buf *buf;

  buf = mcm_buf_new(ctxt);
  fail_if(buf == NULL, "mcm_buf_new() failed");
  fail_if(mcm_buf_realloc(ctxt, buf, 1) == 0, "realloc failed");
  fail_if(mcm_buf_len(ctxt, buf) != 0, "len not correct");
  fail_if(mcm_buf_size(ctxt, buf) != 1, "size not correct");
  fail_if(mcm_buf_realloc(ctxt, buf, 2) == 0, "realloc failed");
  fail_if(mcm_buf_len(ctxt, buf) != 0, "len not correct");
  fail_if(mcm_buf_size(ctxt, buf) != 2, "size not correct");

  FREE(buf);
}
END_TEST


START_TEST(buf_replace) {
  struct memcache_buf *buf;

  buf = mcm_buf_new3(ctxt, "baz");
  fail_if(buf == NULL, "mcm_buf_new() failed");
  fail_if(mcm_buf_replace(ctxt, buf, "bleck", 5) != 1, "replace failed");
  fail_if(mcm_buf_cmp2(ctxt, buf, "bleck") != 1, "cmp failed");

  FREE(buf);
}
END_TEST


START_TEST(buf_replace_buf) {
  struct memcache_buf *buf1, *buf2;

  buf1 = mcm_buf_new3(ctxt, "baz");
  fail_if(buf1 == NULL, "mcm_buf_new() failed");

  buf2 = mcm_buf_new3(ctxt, "bleck");
  fail_if(buf2 == NULL, "mcm_buf_new() failed");

  fail_if(mcm_buf_replace_buf(ctxt, buf1, buf2) != 1, "replace failed");
  fail_if(mcm_buf_cmp_buf(ctxt, buf1, buf2) != 1, "cmp failed");

  FREE(buf1);
  FREE(buf2);
}
END_TEST


START_TEST(buf_reset) {
  struct memcache_buf *buf;
  size_t size;

  buf = mcm_buf_new3(ctxt, "baz");
  buf->flags |= MCM_BUF_OFF_USED;
  fail_if(buf == NULL, "mcm_buf_new() failed");
  fail_if(mcm_buf_reset(ctxt, buf) != 1, "reset failed");
  size = mcm_buf_size(ctxt, buf);
  fail_if((buf->flags & MCM_BUF_OFF_USED) == MCM_BUF_OFF_USED, "flags not cleared");
  fail_if(mcm_buf_len(ctxt, buf) != 0, "len incorrect");
  fail_if(mcm_buf_size(ctxt, buf) != size, "size incorrect");

  FREE(buf);
}
END_TEST


START_TEST(buf_resize) {
  struct memcache_buf *buf;

  buf = mcm_buf_new3(ctxt, "zxcv");
  fail_if(buf == NULL, "mcm_buf_new() failed");
  fail_if(mcm_buf_resize(ctxt, buf, 2) != 1, "resize failed");
  fail_if(mcm_buf_len(ctxt, buf) != 2, "len incorrect");
  fail_if(mcm_buf_cmp2(ctxt, buf, "zx") != 1, "cmp failed");
  fail_if(mcm_buf_resize(ctxt, buf, 4) != 1, "resize failed");
  fail_if(mcm_buf_len(ctxt, buf) != 4, "len incorrect");

  FREE(buf);
}
END_TEST


Suite *
buffer_suite(void) {
  Suite *s = suite_create("Buffer");
  TCase *tc_core = tcase_create("Core");
  suite_add_tcase (s, tc_core);

  tcase_add_test(tc_core, buf_append_buf);
  tcase_add_test(tc_core, buf_append_char);
  tcase_add_test(tc_core, buf_append_str);
  tcase_add_test(tc_core, buf_append_str2);
  tcase_add_test(tc_core, buf_cmp);
  tcase_add_test(tc_core, buf_cmp2);
  tcase_add_test(tc_core, buf_cmp3);
  tcase_add_test(tc_core, buf_cmp_buf);
  tcase_add_test(tc_core, buf_cmp_buf2);
  tcase_add_test(tc_core, buf_compact);
  tcase_add_test(tc_core, buf_copy);
  tcase_add_test(tc_core, buf_end_buf);
  tcase_add_test(tc_core, buf_end_buf2);
  tcase_add_test(tc_core, buf_end_buf3);
  tcase_add_test(tc_core, buf_free);
  tcase_add_test(tc_core, buf_new);
  tcase_add_test(tc_core, buf_new2);
  tcase_add_test(tc_core, buf_new3);
  tcase_add_test(tc_core, buf_realloc);
  tcase_add_test(tc_core, buf_replace);
  tcase_add_test(tc_core, buf_replace_buf);
  tcase_add_test(tc_core, buf_reset);
  tcase_add_test(tc_core, buf_resize);

  return s;
}


int
main(void) {
  int num_failed;

  if (ctxt == NULL)
    ctxt = mc_global_ctxt();

  Suite *s = buffer_suite();
  SRunner *sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  num_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (num_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
