dnl configure.ac for memcache(3)
dnl Sean "I-hate-auto*" Chittenden <sean@gigave.com>
dnl 0. Initialization and options processing
dnl 1. Programs
dnl 2. Libraries
dnl 3. Header files
dnl 4. Types
dnl 5. Structures
dnl 6. Compiler characteristics
dnl 7. Functions, global variables
dnl 8. System services
AC_PREREQ(2.59)
AC_INIT([memcache],[1.4.0.rc2], [sean@gigave.org], [libmemcache])
AC_CONFIG_HEADER(config.h)
AC_COPYRIGHT([Copyright (c) 2004-2006 Sean Chittenden <sean@gigave.com>])
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

MEMCACHE_MAJOR_VERSION=1
MEMCACHE_MINOR_VERSION=4
MEMCACHE_MICRO_VERSION=0
MEMCACHE_MICRO_VERSION_SUFFIX=.rc2
MEMCACHE_RELDATE=20060220
MEMCACHE_VERSION=$MEMCACHE_MAJOR_VERSION.$MEMCACHE_MINOR_VERSION.$MEMCACHE_MICRO_VERSION$MEMCACHE_MICRO_VERSION_SUFFIX
MEMCACHE_VERSION_INFO=`expr $MEMCACHE_MAJOR_VERSION \* $MEMCACHE_MINOR_VERSION`:$MEMCACHE_MICRO_VERSION:$MEMCACHE_MINOR_VERSION
MEMCACHE_VERSION_NUMBER=`expr $MEMCACHE_MAJOR_VERSION \* 10000 + $MEMCACHE_MINOR_VERSION \* 100 + $MEMCACHE_MICRO_VERSION`

AC_SUBST(MEMCACHE_MAJOR_VERSION)
AC_SUBST(MEMCACHE_MINOR_VERSION)
AC_SUBST(MEMCACHE_MINOR_VERSION)
AC_SUBST(MEMCACHE_MICRO_VERSION_SUFFIX)
AC_SUBST(MEMCACHE_RELDATE)
AC_SUBST(MEMCACHE_VERSION)
AC_SUBST(MEMCACHE_VERSION_INFO)
AC_SUBST(MEMCACHE_VERSION_NUMBER)

AM_INIT_AUTOMAKE(libmemcache,${MEMCACHE_VERSION})

dnl AM_PATH_CHECK()

dnl Checks for programs.
AC_C_CONST
AC_EXEEXT
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_LN_S
AC_PATH_PROG(BIN_KILLALL, killall)
AC_PATH_PROG(BIN_MEMCACHED, memcached)
AC_PATH_PROG(BIN_MD5, md5)
AC_PATH_PROG(BIN_SVN2CL, svn2cl)

dnl Perform some evilness
if test "x$BIN_MD5" = x; then
MCM_CALLBACK_CTXT=md517e9be250407e8a37fb60180a76510d7
MCM_CALLBACK_KEY=md5c029c91da86138a5ad1489427e1d71b0
MCM_CALLBACK_LEN=md5a07b51f993c7254fcb18197565700326
MCM_CALLBACK_MC=md5897e5e464792802e78a18e0fdd437b7c
MCM_CALLBACK_PTR=md57b4ac6d3ad66bcb14ca7584f9a3eff43
MCM_CALLBACK_RES=md5e252857f6eaeebe7e61573a2a5bfa564
MCM_ERR_MASK=md51ba931bcdf1b3f122e9b86617155853e
MCM_ERR_FUNC_ERR_CTXT=md5314e69877a17018a14789a1a7fb8025c
MCM_ERR_FUNC_MC_CTXT=md57c7c80036a426539d819e35ebab5192f
MCM_KEY_VALID_CTXT=md5a142d8b02e6ad56fa56f0e27cee889a4
MCM_KEY_VALID_KEY=md5537bb21da67eb92e5898f9911c607217
MCM_KEY_VALID_LEN=md55ecd4a9c706b439f8eebaca09eeadacf
else
MCM_CALLBACK_CTXT=`$BIN_MD5 -qs "MCM_CALLBACK_CTXT${MEMCACHE_RELDATE}${MEMCACHE_VERSION_NUMBER}"`
MCM_CALLBACK_KEY=`$BIN_MD5 -qs "MCM_CALLBACK_KEY${MEMCACHE_RELDATE}${MEMCACHE_VERSION_NUMBER}"`
MCM_CALLBACK_LEN=`$BIN_MD5 -qs "MCM_CALLBACK_LEN${MEMCACHE_RELDATE}${MEMCACHE_VERSION_NUMBER}"`
MCM_CALLBACK_MC=`$BIN_MD5 -qs "MCM_CALLBACK_MC${MEMCACHE_RELDATE}${MEMCACHE_VERSION_NUMBER}"`
MCM_CALLBACK_PTR=`$BIN_MD5 -qs "MCM_CALLBACK_PTR${MEMCACHE_RELDATE}${MEMCACHE_VERSION_NUMBER}"`
MCM_CALLBACK_RES=`$BIN_MD5 -qs "MCM_CALLBACK_RES${MEMCACHE_RELDATE}${MEMCACHE_VERSION_NUMBER}"`
MCM_ERR_MASK=`$BIN_MD5 -qs "MCM_ERR_MASK${MEMCACHE_RELDATE}${MEMCACHE_VERSION_NUMBER}"`
MCM_ERR_FUNC_ERR_CTXT=`$BIN_MD5 -qs "MCM_ERR_FUNC_ERR_CTXT${MEMCACHE_RELDATE}${MEMCACHE_VERSION_NUMBER}"`
MCM_ERR_FUNC_MC_CTXT=`$BIN_MD5 -qs "MCM_ERR_FUNC_MC_CTXT${MEMCACHE_RELDATE}${MEMCACHE_VERSION_NUMBER}"`
MCM_KEY_VALID_CTXT=`$BIN_MD5 -qs "MCM_KEY_VALID_CTXT${MEMCACHE_RELDATE}${MEMCACHE_VERSION_NUMBER}"`
MCM_KEY_VALID_KEY=`$BIN_MD5 -qs "MCM_KEY_VALID_KEY${MEMCACHE_RELDATE}${MEMCACHE_VERSION_NUMBER}"`
MCM_KEY_VALID_LEN=`$BIN_MD5 -qs "MCM_KEY_VALID_LEN${MEMCACHE_RELDATE}${MEMCACHE_VERSION_NUMBER}"`
fi
AC_SUBST(MCM_CALLBACK_CTXT)
AC_SUBST(MCM_CALLBACK_KEY)
AC_SUBST(MCM_CALLBACK_LEN)
AC_SUBST(MCM_CALLBACK_MC)
AC_SUBST(MCM_CALLBACK_PTR)
AC_SUBST(MCM_CALLBACK_RES)
AC_SUBST(MCM_ERR_MASK)
AC_SUBST(MCM_ERR_FUNC_ERR_CTXT)
AC_SUBST(MCM_ERR_FUNC_MC_CTXT)
AC_SUBST(MCM_KEY_VALID_KEY)
AC_SUBST(MCM_KEY_VALID_LEN)



dnl CFLAGS crap
CFLAGS="-Wall -pipe"
DEBUG_cflags="-g -Wunused -Wshadow -Wpointer-arith -Wbad-function-cast -Wcast-qual -Wcast-align -Wwrite-strings -Wsign-compare -Waggregate-return -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wmissing-noreturn -Wformat -Wredundant-decls -Wnested-externs -Winline -pedantic"
OPTIMIZE="-O3"
PROFILE="-g -pg"

AC_MSG_CHECKING([if $CC supports -Wpacked])
CFLAGS_orig=$CFLAGS
CFLAGS="$CFLAGS -Wpacked"
AC_COMPILE_IFELSE(AC_LANG_PROGRAM(,),
  [ AC_MSG_RESULT(yes) ],
  [ CFLAGS=$CFLAGS_orig; AC_MSG_RESULT(no) ])

AC_MSG_CHECKING([if $CC supports -Wdisabled-optimization])
CFLAGS_orig=$CFLAGS
CFLAGS="$CFLAGS -Wdisabled-optimization"
AC_COMPILE_IFELSE(AC_LANG_PROGRAM(,),
  [ AC_MSG_RESULT(yes) ],
  [ CFLAGS=$CFLAGS_orig; AC_MSG_RESULT(no) ])

AC_MSG_CHECKING([if $CC supports -std=c99])
CFLAGS_orig=$CFLAGS
CFLAGS="-std=c99 $CFLAGS"
AC_COMPILE_IFELSE(AC_LANG_PROGRAM(,),
  [ AC_MSG_RESULT(yes) ],
  [ CFLAGS=$CFLAGS_orig; AC_MSG_RESULT(no) ])

dnl BEGIN variadic macro support
AC_MSG_CHECKING([if $CC supports variadic macros])
AC_COMPILE_IFELSE(AC_LANG_PROGRAM(
	[[#include <stdio.h>
#include <string.h>
#define asprint(fmt, args...) asprintf(&buf, fmt, ## args)]],
	[[char *buf;
asprint("testing %s\n", "varargs");
if (strcmp("testing varargs", buf) != 0) return (-1);]]),
  [ support_macro_varargs=yes ],
  [ support_macro_varargs=no ])
if test "x$support_macro_varargs" = xyes; then
AC_MSG_RESULT(yes)
else
AC_MSG_RESULT(no)
fi
dnl END variadic macro support

dnl Check for the int size

AC_CHECK_SIZEOF(uint16_t)
AC_CHECK_SIZEOF(u_int16_t)
AC_CHECK_SIZEOF(unsigned short int)
if test "$ac_cv_sizeof_uint16_t" = "2"; then
    mcm_uint_16="typedef uint16_t u_int16_t;"
elif test "$ac_cv_sizeof_u_int16_t" = "2"; then
    mcm_uint_16=""
elif test "$ac_cv_sizeof_unsigned_short_int" = "2"; then
    mcm_uint_16="typedef unsigned short int u_int16_t;"
else
    AC_ERROR([could not detect a 16-bit integer type])
fi


AC_CHECK_SIZEOF(uint32_t)
AC_CHECK_SIZEOF(u_int32_t)
AC_CHECK_SIZEOF(unsigned long)
if test "$ac_cv_sizeof_uint32_t" = "4"; then
    mcm_uint_32="typedef uint32_t u_int32_t;"
elif test "$ac_cv_sizeof_u_int32_t" = "4"; then
    mcm_uint_32=""
elif test "$ac_cv_sizeof_unsigned_long" = "4"; then
    mcm_uint_32="typedef unsigned long u_int32_t;"
else
    AC_ERROR([could not detect a 32-bit integer type])
fi

AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(u_int64_t)
AC_CHECK_SIZEOF(unsigned long)
AC_CHECK_SIZEOF(unsigned long long)
AC_CHECK_SIZEOF(unsigned longlong)
if test "$ac_cv_sizeof_unsigned_int" = "8"; then
    mcm_uint_64="typedef unsigned int u_int64_t;"
elif test "$ac_cv_sizeof_u_int64_t" = "8"; then
    mcm_uint_64=""
elif test "$ac_cv_sizeof_unsigned_long" = "8"; then
    mcm_uint_64="typedef unsigned long u_int64_t;"
elif test "$ac_cv_sizeof_unsigned_long_long" = "8"; then
    mcm_uint_64="typedef unsigned long long u_int64_t;"
elif test "$ac_cv_sizeof_unsigned_longlong" = "8"; then
    mcm_uint_64="typedef unsigned longlong u_int64_t;"
else
    AC_ERROR([could not detect a 64-bit integer type])
fi

AC_SUBST(MCM_UINT_16_DCL, $mcm_uint_16)
AC_SUBST(MCM_UINT_32_DCL, $mcm_uint_32)
AC_SUBST(MCM_UINT_64_DCL, $mcm_uint_64)

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h unistd.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

dnl Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_CHECK_FUNCS([bzero gettimeofday memchr memset select socket strerror strtol])

dnl check for -lsocket library
AC_CHECK_LIB(socket, setsockopt, [LIBS="$LIBS -lsocket"])

dnl BEGIN debug CFLAGS
AC_MSG_CHECKING([for enabled debug CFLAGS])
AC_ARG_ENABLE(debug,
	AC_HELP_STRING([--enable-debug], [Compile with debugging flag (no)]),
	[ use_debug=$enableval ])
if test "x$use_debug" = xyes; then
CFLAGS="$CFLAGS $DEBUG_cflags"
AC_MSG_RESULT(yes)
else
AC_MSG_RESULT(no)
fi
dnl END debug CFLAGS

AC_DEFUN([MCM_CHECK_SETSOCKOPT], [
AC_MSG_CHECKING(whether to use $1 with setsockopt())
AC_TRY_RUN([
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

int
main(void) {
  int s;
  struct timeval tv;
  tv.tv_sec  = 3;
  tv.tv_usec = 0;

#ifndef $1
  exit(3);
#else
  if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    exit(2);

  /* fails on Solaris 2.6,8,9,10 and some Linuxes because
     SO_RCVTIMEO|SO_SNDTIMEO are defined but not implemented */
  if (setsockopt(s, SOL_SOCKET, $1, (const void *)&tv, sizeof(tv)) == -1)
    exit(1);

  exit(0);
#endif
}
]
, [ AC_MSG_RESULT([yes]) AC_DEFINE(USE_$1, 1, [Define to use $1 with setsockopt()]) ]
, [ AC_MSG_RESULT([no]) ]
)
])

dnl check for SO_RCVTIMEO and SO_SNDTIMEO
MCM_CHECK_SETSOCKOPT(SO_RCVTIMEO)
MCM_CHECK_SETSOCKOPT(SO_SNDTIMEO)

dnl BEGIN default buf size
AC_ARG_ENABLE(default-buf-size,
	AC_HELP_STRING([--enable-default-buf-size], [Sets the default buffer size (4096)]),
	[ use_default_buf_size=$enableval ],
	[ use_default_buf_size=0 ])
AC_MSG_CHECKING([for default buffer size for "get" commands])
if test "x$use_default_buf_size" = xno; then
AC_MSG_ERROR([Default buffer size must be specified (ie: some value between 512 and 32768)])
elif test "x$use_default_buf_size" = x0; then
use_default_buf_size=4096
fi
AC_SUBST(INIT_GET_BUF_SIZE, $use_default_buf_size)
AC_MSG_RESULT($use_default_buf_size)
dnl END default buf size

dnl BEGIN hash type
AC_ARG_ENABLE(hash-type,
	AC_HELP_STRING([--enable-hash-type], [Sets the client side hashing algo.  Valid settings are "crc32", "elf", or "perl" (default: crc32)]),
	[ use_hash_type=$enableval ],
	[ use_hash_type=default ])
AC_MSG_CHECKING([for client side hash algo preference])
if test "x$use_hash_type" = xcrc32 -o "x$use_hash_type" = xdefault; then
AC_DEFINE(USE_CRC32_HASH)
AC_MSG_RESULT(crc32)
elif test "x$use_hash_type" = xelf; then
AC_DEFINE(USE_ELF_HASH)
AC_MSG_RESULT(elf)
elif test "x$use_hash_type" = xperl; then
AC_DEFINE(USE_PERL_HASH)
AC_MSG_RESULT(perl)
else
AC_MSG_ERROR([Invalid hash type.  Valid hash types include "crc32", "elf", and "perl".])
fi
AH_TEMPLATE([USE_CRC32_HASH], [Enables the use of the CRC32 hash algo for client-side hashing])
AH_TEMPLATE([USE_ELF_HASH], [Enables the use of the ELF/ruby(1) hash for client-side hashing])
AH_TEMPLATE([USE_PERL_HASH], [Enable use of perl(1)'s hash for client-side hashing])
dnl END hash type

dnl BEGIN protocol assertions
AC_ARG_ENABLE(mc-proto-assert,
	AC_HELP_STRING([--enable-mc-proto-assert], [Enable memcache(4) protocol assertions (yes)]),
	[ use_mc_proto_assert=$enableval ],
	[ use_mc_proto_assert=default ])
AC_MSG_CHECKING([viability of using protocol assertions])
if test "x$use_mc_proto_assert" = xyes -o "x$use_mc_proto_assert" = xdefault; then
if test "x$support_macro_varargs" = xyes; then
AC_DEFINE(DEBUG_MC_PROTO_ASSERT)
AC_MSG_RESULT(yes)
else
AC_MSG_RESULT(no (no variadic macro support))
fi
else
AC_MSG_RESULT(no)
fi
AH_TEMPLATE([DEBUG_MC_PROTO_ASSERT], [Enable runtime memcache(4) protocol assertions.  It's not strictly necessary if the client and server are sending the right data.  This should be on by default, but, for those that don't want every check done to make sure things are right, undef this.  99% of the universe should leave this as is.  If you think you're than 1% who doesn't need it, you're on crack and should definitely leave DEBUG_MC_PROTO_ASSERT on. ])
dnl END protocol assertions

dnl BEGIN protocol trace options
AC_ARG_ENABLE(mc-proto-debug,
	AC_HELP_STRING([--enable-mc-proto-debug], [Enable memcache(4) protocol debugging (no)]),
	[ if test "x$support_macro_varargs" = xyes; then
  use_mc_proto_trace=$enableval
else
  AC_MSG_WARN([No variadic macro support, disabling protocol debugging.])
  use_mc_proto_trace=no
fi])
if test "x$use_mc_proto_trace" = xyes; then
AC_MSG_WARN([Enabling protocol debugging.  *NEVER* enable this in production])
AC_DEFINE(DEBUG_MC_PROTO)
fi
AH_TEMPLATE([DEBUG_MC_PROTO], [Enable memcache(4) protocol tracing/debugging.])
dnl END protocol trace options

dnl BEGIN optimization bits
AC_MSG_CHECKING([for enabled compiler optimizations])
AC_ARG_ENABLE(optimize,
	AC_HELP_STRING([--enable-optimize], [Enable a few compile time optimizations (yes)]),
	[ use_optimize=$enableval ],
	[ use_optimize=default ])
if test "x$use_optimize" = xyes; then
CFLAGS="$OPTIMIZE $CFLAGS"
AC_MSG_RESULT(yes)
elif test "x$use_optimize" = xdefault -a ! \( "x$use_debug" = xyes -o "x$use_profile" = xyes \); then
CFLAGS="$OPTIMIZE $CFLAGS"
AC_MSG_RESULT(yes)
else
AC_MSG_RESULT(no)
fi
dnl END optimization bits

dnl BEGIN profiling CFLAGS
AC_MSG_CHECKING([for enabled profiling CFLAGS])
AC_ARG_ENABLE(profile,
	AC_HELP_STRING([--enable-profile], [Enable profiling (no)]),
	[ use_profile=$enableval ])
if test "x$use_profile" = xyes; then
CFLAGS="$CFLAGS $PROFILE"
AC_MSG_RESULT(yes)
else
AC_MSG_RESULT(no)
fi
dnl END profiling CFLAGS

AC_CONFIG_FILES([Makefile
	doc/Makefile
	include/Makefile
	include/memcache.h
	include/memcache/Makefile
	src/Makefile
	test/Makefile
	test/benchmark/Makefile
	test/buffer_recycle/Makefile
	test/long_val/Makefile
	test/regress/Makefile
	test/redundant_server/Makefile
	test/unit/Makefile])
AC_OUTPUT
