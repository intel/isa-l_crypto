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

# If this build is for x86, look for yasm and nasm
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

  # Pick an assembler yasm or nasm
  if test x"$AS" = x""; then
    # Check for yasm and yasm features
    yasm_feature_level=0
    AC_CHECK_PROG(HAVE_YASM, yasm, yes, no)
    if test "$HAVE_YASM" = "yes"; then
       yasm_feature_level=1
    else
       AC_MSG_RESULT([no yasm])
    fi
    if test x"$yasm_feature_level" = x"1"; then
       AC_MSG_CHECKING([for modern yasm])
       AC_LANG_CONFTEST([AC_LANG_SOURCE([[vmovdqa %xmm0, %xmm1;]])])
       if yasm -f elf64 -p gas conftest.c ; then
         AC_MSG_RESULT([yes])
         yasm_feature_level=4
       else
         AC_MSG_RESULT([no])
       fi
    fi
    if test x"$yasm_feature_level" = x"4"; then
       AC_MSG_CHECKING([for optional yasm AVX512 support])
       AC_LANG_CONFTEST([AC_LANG_SOURCE([[vpshufb %zmm0, %zmm1, %zmm2;]])])
       if yasm -f elf64 -p gas conftest.c 2> /dev/null; then
         AC_MSG_RESULT([yes])
         yasm_feature_level=6
       else
         AC_MSG_RESULT([no])
       fi
    fi
    if test x"$yasm_feature_level" = x"6"; then
      AC_MSG_CHECKING([for additional yasm AVX512 support])
      AC_LANG_CONFTEST([AC_LANG_SOURCE([[vpcompressb zmm0, k1, zmm1;]])])
      sed -i -e '/vpcompressb/!d' conftest.c
      if yasm -f elf64  conftest.c 2> /dev/null; then
        AC_MSG_RESULT([yes])
        yasm_feature_level=10
      else
        AC_MSG_RESULT([no])
      fi
    fi

    AC_MSG_CHECKING([for optional yasm SHA-NI support])
    AC_LANG_CONFTEST([AC_LANG_SOURCE([[sha256rnds2 %xmm0,%xmm1,%xmm2;]])])
    if yasm -f elf64 -p gas conftest.c 2> /dev/null; then
      yasm_knows_shani=yes
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi

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

    AC_MSG_CHECKING([for optional nasm SHA-NI support])
    AC_LANG_CONFTEST([AC_LANG_SOURCE([[sha256rnds2 xmm2,xmm1,xmm0;]])])
    sed -i -e '/sha256rnds2/!d' conftest.c
    if nasm -f elf64  conftest.c 2> /dev/null; then
      nasm_knows_shani=yes
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi

    if test $nasm_feature_level -ge $yasm_feature_level ; then
      AS=nasm
      as_feature_level=$nasm_feature_level
      as_knows_shani=$nasm_knows_shani
    else
      AS=yasm
      as_feature_level=$yasm_feature_level
      as_knows_shani=$yasm_knows_shani
    fi

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

  if test $as_feature_level -lt 2 ; then
    AC_MSG_ERROR([No modern nasm or yasm found as required. Nasm should be v2.11.01 or later (v2.13 for AVX512) and yasm should be 1.2.0 or later.])
  fi

  if test x"$as_knows_shani" = x"yes"; then
    AC_DEFINE(HAVE_AS_KNOWS_SHANI, [1], [Assembler can do SHANI.])
    have_as_knows_shani=yes
  else
    AC_MSG_RESULT([Assembler does not understand SHANI opcodes.  Consider upgrading for best performance.])
  fi

  case $host_os in
       *linux*)  arch=linux   yasm_args="-f elf64";;
       *darwin*) arch=darwin  yasm_args="-f macho64 --prefix=_ ";;
       *netbsd*) arch=netbsd  yasm_args="-f elf64";;
       *mingw*)  arch=mingw   yasm_args="-f win64";;
       *)        arch=unknown yasm_args="-f elf64";;
  esac

  # Fix for nasm missing windows features
  if test x"$arch" = x"mingw"; then
    AS=yasm
    as_feature_level=$yasm_feature_level
    if test $as_feature_level -lt 2 ; then
      AC_MSG_ERROR([Mingw build requires Yasm 1.2.0 or later.])
    fi
  fi

  AC_DEFINE_UNQUOTED(AS_FEATURE_LEVEL, [$as_feature_level], [Assembler feature level.])
  if test $as_feature_level -ge 6 ; then
    AC_DEFINE(HAVE_AS_KNOWS_AVX512, [1], [Assembler can do AVX512.])
    have_as_knows_avx512=yes
  else
    AC_MSG_RESULT([Assembler does not understand AVX512 opcodes.  Consider upgrading for best performance.])
  fi

  AM_CONDITIONAL(SAFE_DATA, test x"$SAFE_DATA" = x"yes")
  AM_CONDITIONAL(USE_YASM, test x"$AS" = x"yasm")
  AM_CONDITIONAL(USE_NASM, test x"$AS" = x"nasm")
  AM_CONDITIONAL(WITH_AVX512, test x"$have_as_knows_avx512" = x"yes")
  AM_CONDITIONAL(WITH_SHANI, test x"$have_as_knows_shani" = x"yes")
  AC_SUBST([yasm_args])
  AM_CONDITIONAL(DARWIN, test x"$arch" = x"darwin")
  AC_MSG_RESULT([Using $AS args target "$arch" "$yasm_args"])
else
  # Disable below conditionals if not x86
  AM_CONDITIONAL(SAFE_DATA, test "x" = "y")
  AM_CONDITIONAL(USE_YASM, test "x" = "y")
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
-Wchar-subscripts \
-Wformat-security \
-Wnested-externs \
-Wpointer-arith \
-Wshadow \
-Wstrict-prototypes \
-Wtype-limits \
-fstack-protector \
-D_FORTIFY_SOURCE=2
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
])
