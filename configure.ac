#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.69)
AC_INIT([libisal_crypto],
        [2.24.0],
        [sg.support.isal@intel.com],
        [isa-l_crypto],
        [http://01.org/storage-acceleration-library])
AC_CONFIG_SRCDIR([])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([
	foreign
	1.11
	-Wall
	-Wno-portability
	silent-rules
	tar-pax
	no-dist-gzip
	dist-xz
	subdir-objects
])
AM_PROG_AS

AC_CANONICAL_HOST
CPU=""
AS_CASE([$host_cpu],
  [x86_64], [CPU="x86_64"],
  [amd64], [CPU="x86_64"],
  [i?86], [CPU="x86_32"],
  [aarch64], [CPU="aarch64"],
  [arm64], [CPU="aarch64"],
)
AM_CONDITIONAL([CPU_X86_64], [test "$CPU" = "x86_64"])
AM_CONDITIONAL([CPU_X86_32], [test "$CPU" = "x86_32"])
AM_CONDITIONAL([CPU_AARCH64], [test "$CPU" = "aarch64"])
AM_CONDITIONAL([CPU_UNDEFINED], [test "x$CPU" = "x"])
AM_CONDITIONAL([SAFE_PARAM], [test x"$SAFE_PARAM" = x"yes"])

if test "$CPU" = "x86_64"; then
   is_x86=yes
else
   if test "$CPU" = "x86_32"; then
      is_x86=yes
   else
      is_x86=no
   fi
fi

# Check for programs
AC_PROG_CC_STDC
AC_USE_SYSTEM_EXTENSIONS
AM_SILENT_RULES([yes])
LT_INIT
AC_PREFIX_DEFAULT([/usr])
AC_PROG_SED
AC_PROG_MKDIR_P

# Options
AC_ARG_ENABLE([debug],
        AS_HELP_STRING([--enable-debug], [enable debug messages @<:@default=disabled@:>@]),
        [], [enable_debug=no])
AS_IF([test "x$enable_debug" = "xyes"], [
        AC_DEFINE(ENABLE_DEBUG, [1], [Debug messages.])
])

AC_ARG_ENABLE([fips-mode],
        AS_HELP_STRING([--enable-fips-mode], [enable FIPS mode @<:@default=disabled@:>@]),
        [enable_fips_mode=yes], [enable_fips_mode=no])
AS_IF([test "x$enable_fips_mode" = "xyes"], [
        AC_DEFINE(FIPS_MODE, [1], [FIPS mode.])
])

AC_ARG_ENABLE([safe-data],
        AS_HELP_STRING([--disable-safe-data], [clear sensitive data @<:@default=enabled@:>@]),
        [safe_data=no], [safe_data=yes])
AS_IF([test "x$safe_data" = "xyes"], [
        AC_DEFINE(SAFE_DATA, [1], [Clear sensitive data.])
])

AC_ARG_ENABLE([safe-param],
        AS_HELP_STRING([--disable-safe-param], [enable parameter checking @<:@default=enabled@:>@]),
        [safe_param=no], [safe_param=yes])
AS_IF([test "x$safe_param" = "xyes"], [
        AC_DEFINE(SAFE_PARAM, [1], [Enable parameter checking.])
])

if test x"$CPU" = x"aarch64"; then
   AC_ARG_ENABLE([sve2],
        AS_HELP_STRING([--disable-sve2], [disable usage of SVE2]),
        , enable_sve2=yes)
   if test "$enable_sve2" = "yes"; then
      AC_MSG_CHECKING([whether compiler supports sve2])
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],
                                         [asm(".arch armv8.2-a+sve2");])],
                        [cc_support_sve2=yes],
                        [cc_support_sve2=no])
      if test x"$cc_support_sve2" = xyes ; then
         AC_MSG_RESULT([yes])
      else
         AC_MSG_RESULT([no])
         AC_MSG_ERROR([upgrade your compiler to support SVE2, or run \"./configure --disable-sve2\"])
      fi
   else
	 AC_DEFINE(NO_SVE2, 1, [Define to 1 if the compiler does not supports SVE2.])
   fi
fi

# If this build is for x86, look for nasm
if test x"$is_x86" = x"yes"; then
  AC_MSG_CHECKING([whether Intel CET is enabled])
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[
#ifndef __CET__
# error CET is not enabled
#endif]])],[AC_MSG_RESULT([yes])
                  intel_cet_enabled=yes],[AC_MSG_RESULT([no])
                  intel_cet_enabled=no])
AS_IF([test "x$intel_cet_enabled" = "xyes"], [
        AC_DEFINE(INTEL_CET_ENABLED, [1], [Intel CET enabled.])
])

# check if LD -z options are supported
LDFLAGS="\
-Wl,-z,noexecstack \
-Wl,-z,relro \
-Wl,-z,now \
"
AC_MSG_CHECKING([if $LD supports $LDFLAGS])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[
int main(int argc, char **argv)
{
       return 0;
}]])],
       [AC_MSG_RESULT([yes])],
       [AC_MSG_RESULT([no])
               LDFLAGS=""]
)

  # Pick NASM assembler
  if test x"$AS" = x""; then
    # Check for nasm and nasm features
    nasm_feature_level=0
    AC_CHECK_PROG(HAVE_NASM, nasm, yes, no)
    if test "$HAVE_NASM" = "yes"; then
       nasm_feature_level=1
    else
       AC_MSG_RESULT([no nasm])
    fi

    if test x"$nasm_feature_level" = x"1"; then
      AC_MSG_CHECKING([for modern nasm])
      AC_LANG_CONFTEST([AC_LANG_SOURCE([[pblendvb xmm2, xmm1;]])])
      sed -i -e '/pblendvb/!d' conftest.c
      if nasm -f elf64 conftest.c 2> /dev/null; then
        AC_MSG_RESULT([yes])
        nasm_feature_level=4
      else
        AC_MSG_RESULT([no])
      fi
    fi
    if test x"$nasm_feature_level" = x"4"; then
      AC_MSG_CHECKING([for optional nasm AVX512 support])
      AC_LANG_CONFTEST([AC_LANG_SOURCE([[vinserti32x8 zmm0, ymm1, 1;]])])
      sed -i -e '/vinsert/!d' conftest.c
      if nasm -f elf64  conftest.c 2> /dev/null; then
        AC_MSG_RESULT([yes])
        nasm_feature_level=6
      else
        AC_MSG_RESULT([no])
      fi
    fi
    if test x"$nasm_feature_level" = x"6"; then
      AC_MSG_CHECKING([for additional nasm AVX512 support])
      AC_LANG_CONFTEST([AC_LANG_SOURCE([[vpcompressb zmm0 {k1}, zmm1;]])])
      sed -i -e '/vpcompressb/!d' conftest.c
      if nasm -f elf64  conftest.c 2> /dev/null; then
        AC_MSG_RESULT([yes])
        nasm_feature_level=10
      else
        AC_MSG_RESULT([no])
      fi
    fi

    AS=nasm
    as_feature_level=$nasm_feature_level

  else
    # Check for $AS supported features
    as_feature_level=0
    AC_CHECK_PROG(HAVE_AS, $AS, yes, no)
    if test "$HAVE_AS" = "yes"; then
       as_feature_level=1
    else
       AC_MSG_ERROR([no $AS])
    fi

    if test x"$as_feature_level" = x"1"; then
      AC_MSG_CHECKING([for modern $AS])
      AC_LANG_CONFTEST([AC_LANG_SOURCE([[pblendvb xmm2, xmm1;]])])
      sed -i -e '/pblendvb/!d' conftest.c
      if $AS -f elf64 conftest.c 2> /dev/null; then
        AC_MSG_RESULT([yes])
        as_feature_level=4
      else
        AC_MSG_RESULT([no])
      fi
    fi
    if test x"$as_feature_level" = x"4"; then
      AC_MSG_CHECKING([for optional as AVX512 support])
      AC_LANG_CONFTEST([AC_LANG_SOURCE([[vinserti32x8 zmm0, ymm1, 1;]])])
      sed -i -e '/vinsert/!d' conftest.c
      if $AS -f elf64  conftest.c 2> /dev/null; then
        AC_MSG_RESULT([yes])
        as_feature_level=6
      else
        AC_MSG_RESULT([no])
      fi
    fi
    if test x"$as_feature_level" = x"6"; then
      AC_MSG_CHECKING([for additional as AVX512 support])
      AC_LANG_CONFTEST([AC_LANG_SOURCE([[vpcompressb zmm0, k1, zmm1;]])])
      sed -i -e '/vpcompressb/!d' conftest.c
      if $AS -f elf64  conftest.c 2> /dev/null; then
        AC_MSG_RESULT([yes])
        as_feature_level=10
      else
        AC_MSG_RESULT([no])
      fi
    fi

    AC_MSG_CHECKING([for optional nasm SHA-NI support])
    AC_LANG_CONFTEST([AC_LANG_SOURCE([[sha256rnds2 xmm2,xmm1,xmm0;]])])
    sed -i -e '/sha256rnds2/!d' conftest.c
    if $AS -f elf64  conftest.c 2> /dev/null; then
      AC_MSG_RESULT([yes])
      as_knows_shani=yes
    else
      AC_MSG_RESULT([no])
    fi

  fi

  if test $as_feature_level -lt 10 ; then
    AC_MSG_ERROR([No modern nasm found as required. Nasm should be v2.14.01 or later.])
  fi

  if test x"$as_knows_shani" = x"yes"; then
    AC_DEFINE(HAVE_AS_KNOWS_SHANI, [1], [Assembler can do SHANI.])
    have_as_knows_shani=yes
  else
    AC_MSG_RESULT([Assembler does not understand SHANI opcodes.  Consider upgrading for best performance.])
  fi

  case $host_os in
       *linux*)  arch=linux   asm_args="-f elf64";;
       *darwin*) arch=darwin  asm_args="-f macho64 --prefix=_ ";;
       *netbsd*) arch=netbsd  asm_args="-f elf64";;
       *mingw*)  arch=mingw   asm_args="-f win64";;
       *)        arch=unknown asm_args="-f elf64";;
  esac

  AC_DEFINE_UNQUOTED(AS_FEATURE_LEVEL, [$as_feature_level], [Assembler feature level.])
  if test $as_feature_level -ge 6 ; then
    AC_DEFINE(HAVE_AS_KNOWS_AVX512, [1], [Assembler can do AVX512.])
    have_as_knows_avx512=yes
  else
    AC_MSG_RESULT([Assembler does not understand AVX512 opcodes.  Consider upgrading for best performance.])
  fi

  AM_CONDITIONAL(SAFE_DATA, test x"$SAFE_DATA" = x"yes")
  AM_CONDITIONAL(FIPS_MODE, test x"$FIPS_MODE" = x"yes")
  AM_CONDITIONAL(USE_NASM, test x"$AS" = x"nasm")
  AM_CONDITIONAL(WITH_AVX512, test x"$have_as_knows_avx512" = x"yes")
  AM_CONDITIONAL(WITH_SHANI, test x"$have_as_knows_shani" = x"yes")
  AC_SUBST([asm_args])
  AM_CONDITIONAL(DARWIN, test x"$arch" = x"darwin")
  AC_MSG_RESULT([Using $AS args target "$arch" "$asm_args"])
else
  # Disable below conditionals if not x86
  AM_CONDITIONAL(SAFE_DATA, test "x" = "y")
  AM_CONDITIONAL(FIPS_MODE, test "x" = "y")
  AM_CONDITIONAL(USE_NASM, test "x" = "y")
  AM_CONDITIONAL(WITH_AVX512, test "x" = "y")
  AM_CONDITIONAL(WITH_SHANI, test "x" = "y")
  AM_CONDITIONAL(DARWIN, test "x" = "y")
fi

# Check for header files
AC_CHECK_HEADERS([limits.h stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC  # Used only in tests
AC_CHECK_FUNCS([memmove memset])

my_CFLAGS="\
-Wall \
-fPIC \
-Wchar-subscripts \
-Wformat-security \
-Wnested-externs \
-Wpointer-arith \
-Wshadow \
-Wstrict-prototypes \
-Wtype-limits \
-fstack-protector \
-D_FORTIFY_SOURCE=2 \
-DNO_COMPAT_ISAL_CRYPTO_API_2_24
"
AC_SUBST([my_CFLAGS])

AC_CONFIG_FILES([\
  Makefile\
  libisal_crypto.pc
])

AC_OUTPUT
AC_MSG_RESULT([
        $PACKAGE $VERSION
        =====

        prefix:                 ${prefix}
        sysconfdir:             ${sysconfdir}
        libdir:                 ${libdir}
        includedir:             ${includedir}

        compiler:               ${CC}
        cflags:                 ${CFLAGS}
        ldflags:                ${LDFLAGS}

        debug:                  ${enable_debug}
        safe_data:              ${safe_data}
        safe_param:             ${safe_param}
        FIPS mode:              ${enable_fips_mode}
])
