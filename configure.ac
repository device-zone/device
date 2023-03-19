#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(device, 0.9.0, minfrin@sharp.fm)
AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([dist-bzip2])
LT_INIT
AC_CONFIG_FILES([Makefile device.spec])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

AC_SUBST([libexecdir], [$libexecdir])

AC_ARG_WITH(replxx,[  --with-replxx      use replxx library],
  [
    if test "$with_replxx" != "no"; then
      AC_CHECK_HEADERS(replxx.h)
      AC_CHECK_LIB(replxx,replxx_init)
      AC_CHECK_FUNCS([replxx_add_color_completion])
    fi
  ])

AC_ARG_WITH(libedit,[  --with-libedit      use libedit library],
  [
    if test "$with_libedit" != "no"; then
      AC_CHECK_HEADERS(histedit.h)
      PKG_CHECK_MODULES(libedit, libedit,,[
        AC_CHECK_LIB(edit,el_init)
      ])
    fi
  ])

AC_ARG_WITH(editline,[  --with-editline      use editline library],
  [
    if test "$with_editline" != "no"; then
      AC_CHECK_HEADERS(editline.h)
      PKG_CHECK_MODULES(editline, editline,,[
        AC_CHECK_LIB(editline,readline)
      ])
    fi
  ])

AC_ARG_WITH(linenoise,[  --with-linenoise      use linenoise library],
  [
    if test "$with_linenoise" != "no"; then
      AC_DEFINE([HAVE_LINENOISE_H], [], [Have the linenoise header files])
    fi
  ])

AC_ARG_WITH(selinux,[  --with-selinux      use selinux library],
  [
    if test "$with_selinux" != "no"; then
      AC_CHECK_HEADERS(selinux/selinux.h)
      PKG_CHECK_MODULES(selinux, selinux,,[
        AC_CHECK_LIB(selinux,getfilecon)
      ])
    fi
  ])

AC_ARG_WITH([bash-completion-dir],
    AS_HELP_STRING([--with-bash-completion-dir[=PATH]],
        [Install the bash auto-completion script in this directory. @<:@default=yes@:>@]),
    [],
    [with_bash_completion_dir=yes])

if test "x$with_bash_completion_dir" = "xyes"; then
    PKG_CHECK_MODULES([BASH_COMPLETION], [bash-completion >= 2.0],
        [BASH_COMPLETION_DIR="`pkg-config --variable=completionsdir bash-completion`"],
        [BASH_COMPLETION_DIR="$datadir/bash-completion/completions"])
else
    BASH_COMPLETION_DIR="$with_bash_completion_dir"
fi

AC_SUBST([BASH_COMPLETION_DIR])
AM_CONDITIONAL([ENABLE_BASH_COMPLETION],[test "x$with_bash_completion_dir" != "xno"])

# Checks for libraries.
PKG_CHECK_MODULES(apr, apr-1 >= 1.3)
PKG_CHECK_MODULES(apu, apr-util-1 >= 1.3)

CFLAGS="$CFLAGS $apr_CFLAGS $apu_CFLAGS $libedit_CFLAGS $libselinux_CFLAGS"
CPPFLAGS="$CPPFLAGS $apr_CPPFLAGS $apu_CPPFLAGS $libedit_CPPFLAGS $libselinux_CPPFLAGS"
LDFLAGS="$LDFLAGS $apr_LDFLAGS $apu_LDFLAGS $libedit_LDFLAGS $libselinux_LDFLAGS"
LIBS="$LIBS $apr_LIBS $apu_LIBS $libedit_LIBS $libselinux_LIBS"

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T

# Checks for headers
AC_CHECK_HEADERS([unistd.h libgen.h termios.h grp.h pwd.h locale.h langinfo.h iconv.h selinux/selinux.h])

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([tcgetattr])

AC_OUTPUT

