# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019 Mellanox Technologies. All Rights Reserved.
#

AC_INIT([rshim], [2.1.10])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_LANG(C)
AC_PROG_CC
AM_PROG_CC_C_O
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
  Makefile
  rshim.spec
  src/Makefile
  man/Makefile
  rhel/rshim.spec
  freebsd/rshim
])
AC_CANONICAL_HOST

PKG_PROG_PKG_CONFIG
AC_ARG_WITH([systemdsystemunitdir],
 [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files])],,
 [with_systemdsystemunitdir=auto])
AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"], [
  def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)
  AS_IF([test "x$def_systemdsystemunitdir" = "x"],
  [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
  [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
  with_systemdsystemunitdir=no],
  [with_systemdsystemunitdir="$def_systemdsystemunitdir"])])
AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
      [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])

AC_CHECK_HEADERS_ONCE([syslog.h])

AC_ARG_ENABLE([usb],
  AS_HELP_STRING([--enable-usb], [Enable rshim over USB (default is yes) ]),
  [build_usb=$enableval], [build_usb=yes])

AM_CONDITIONAL([BUILD_RSHIM_USB], [test "x$build_usb" = "xyes"])

AC_ARG_ENABLE([pcie],
  AS_HELP_STRING([--enable-pcie], [Enable rshim over PCIe (default is yes) ]),
  [build_pcie=$enableval], [build_pcie=yes])

AM_CONDITIONAL([BUILD_RSHIM_PCIE], [test "x$build_pcie" = "xyes"])

AC_ARG_ENABLE([fuse],
  AS_HELP_STRING([--enable-fuse], [Enable fuse / cuse (default is yes) ]),
  [build_fuse=$enableval], [build_fuse=yes])

AM_CONDITIONAL([BUILD_RSHIM_FUSE], [test "x$build_fuse" = "xyes"])

case $host in
*-linux*)
  AC_MSG_RESULT([Linux])
  backend=linux
  ;;
*-freebsd*)
  AC_MSG_RESULT([FreeBSD])
  backend=freebsd
  ;;
*)
  AC_MSG_ERROR([unsupported operating system $host])
esac

AS_IF([test "x$build_pcie" = "xyes"], [
  PKG_CHECK_MODULES(libpci, libpci, [], [AC_MSG_ERROR([Can't find libpci])])
])

AS_IF([test "x$build_usb" = "xyes"], [
  PKG_CHECK_MODULES(libusb, libusb-1.0 >= 1.0, [], [AC_MSG_ERROR([Can't find libusb-1.0])])
  if test $backend = freebsd; then
    AC_CHECK_LIB(usb, libusb_init, [], [AC_MSG_ERROR([Missing libusb_init in libusb])])
  else
    AC_CHECK_LIB(usb-1.0, libusb_init, [], [AC_MSG_ERROR([Missing libusb_init in libusb-1.0])])
  fi
  AC_CHECK_FUNCS([libusb_get_port_numbers libusb_get_device_address])
])

AS_IF([test "x$build_fuse" = "xyes"], [
  if test $backend = freebsd; then
    AC_CHECK_LIB(cuse, cuse_dev_create)
  else
    PKG_CHECK_MODULES(fuse, fuse, [], PKG_CHECK_MODULES(fuse, fuse3, [use_fuse3=yes], [AC_MSG_ERROR([Can't find fuse])]))
  fi
  if test "x$use_fuse3" = "xyes"; then
    AC_SUBST(CPPFLAGS, "$CPPFLAGS -DFUSE_USE_VERSION=30")
  else
    AC_SUBST(CPPFLAGS, "$CPPFLAGS -DFUSE_USE_VERSION=29")
  fi
])

if test $backend = freebsd; then
AC_SUBST(CPPFLAGS, "$CPPFLAGS -I${prefix}/include/libepoll-shim")
AC_SUBST(LDFLAGS, "$LDFLAGS -L${prefix}/lib")
AC_CHECK_HEADERS([sys/epoll.h],[],[AC_MSG_ERROR([Missing libepoll-shim])])
AC_CHECK_LIB(epoll-shim, epoll_create1)
AC_SUBST(CPPFLAGS, "$CPPFLAGS -DDEFAULT_RSHIM_CONFIG_FILE='\"${prefix}/etc/rshim.conf\"'")
else
AC_SUBST(CPPFLAGS, "$CPPFLAGS -DDEFAULT_RSHIM_CONFIG_FILE='\"/etc/rshim.conf\"'")
fi
AM_CONDITIONAL([OS_FREEBSD], [test "x$backend" = "xfreebsd"])

AC_CHECK_LIB(pthread, pthread_create)

AC_OUTPUT
