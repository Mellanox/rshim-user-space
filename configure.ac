# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019 Mellanox Technologies. All Rights Reserved.
#

AC_INIT([Rshim Driver for BlueField SoC], [2.0])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
  Makefile
  src/Makefile
  man/Makefile
  rshim.spec
])
AC_CANONICAL_HOST

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

AC_SUBST(CPPFLAGS, "$CPPFLAGS -D_FILE_OFFSET_BITS=64")
AC_SUBST(CPPFLAGS, "$CPPFLAGS -DHAVE_RSHIM_NET")
AC_SUBST(CPPFLAGS, "$CPPFLAGS -I/usr/local/include")

AC_CHECK_HEADERS([pci/pci.h],[],[AC_MSG_ERROR([Missing pciutils header files])])
AC_SUBST(CPPFLAGS, "$CPPFLAGS -DHAVE_RSHIM_PCIE -DHAVE_RSHIM_PCIE_LF")
AC_CHECK_LIB(pci, pci_init, [], [AC_MSG_ERROR([Missing libpci])])

if test $backend = freebsd; then
AC_CHECK_HEADERS([libusb.h],[],[AC_MSG_ERROR([Missing libusb header files])])
AC_CHECK_LIB(usb, libusb_init, [], [AC_MSG_ERROR([Missing libusb])])
else
AC_CHECK_HEADERS([libusb-1.0/libusb.h],[],[AC_MSG_ERROR([Missing libusb header files])])
AC_SUBST(CPPFLAGS, "$CPPFLAGS -I/usr/include/libusb-1.0 -I/usr/local/include/libusb-1.0")
AC_CHECK_LIB(usb-1.0, libusb_init, [], [AC_MSG_ERROR([Missing libusb-1.0])])
fi
AC_CHECK_FUNCS_ONCE([libusb_get_port_numbers libusb_get_device_address])

AC_CHECK_HEADERS([fuse/cuse_lowlevel.h],[],[AC_MSG_ERROR([Missing fuse header files])])
if test $backend = freebsd; then
AC_SUBST(CPPFLAGS, "$CPPFLAGS -DHAVE_RSHIM_CUSE")
AC_CHECK_LIB(cuse, cuse_dev_create)
else
AC_SUBST(CPPFLAGS, "$CPPFLAGS -DFUSE_USE_VERSION=30 -DHAVE_RSHIM_FUSE")
fi
AC_CHECK_LIB(fuse, cuse_lowlevel_setup, [], [AC_MSG_ERROR([Missing fuse library])])

if test $backend = freebsd; then
AC_CHECK_HEADERS([libepoll-shim/sys/epoll.h],[],[AC_MSG_ERROR([Missing libepoll-shim])])
AC_SUBST(CPPFLAGS, "$CPPFLAGS -I/usr/local/include/libepoll-shim")
AC_CHECK_LIB(epoll-shim, epoll_create1)
fi

AC_CHECK_LIB(pthread, pthread_create)

AC_OUTPUT
