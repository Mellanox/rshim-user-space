AC_INIT([bfrshim], [1.0])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
  Makefile
  src/Makefile
])
AC_CANONICAL_HOST

case $host in
*-linux*)
  AC_MSG_RESULT([Linux])
  backend=linux
  ;;
*-openbsd*)
  AC_MSG_RESULT([OpenBSD])
  backend=openbsd
  ;;
*)
  AC_MSG_ERROR([unsupported operating system $host])
esac

AC_SUBST(CPPFLAGS, "$CPPFLAGS -D_FILE_OFFSET_BITS=64")

AC_CHECK_HEADERS([pci/pci.h],[],[AC_MSG_ERROR([Missing pciutils header files])])
AC_SUBST(CPPFLAGS, "$CPPFLAGS -DHAVE_RSHIM_PCIE -DHAVE_RSHIM_PCIE_LF")
AC_CHECK_LIB(pci, pci_init, [], [AC_MSG_ERROR([Missing libpci])])

AC_CHECK_HEADERS([libusb-1.0/libusb.h],[],[AC_MSG_ERROR([Missing libusb header files])])
AC_SUBST(CPPFLAGS, "$CPPFLAGS -I/usr/include/libusb-1.0 -I/usr/local/include/libusb-1.0")
AC_SUBST(CPPFLAGS, "$CPPFLAGS -DHAVE_RSHIM_NET")
AC_CHECK_LIB(usb-1.0, libusb_init, [], [AC_MSG_ERROR([Missing libusb-1.0])])
AC_CHECK_FUNCS_ONCE([libusb_get_port_numbers libusb_get_device_address])

AC_CHECK_HEADERS([fuse/cuse_lowlevel.h],[],[AC_MSG_ERROR([Missing fuse header files])])
AC_SUBST(CPPFLAGS, "$CPPFLAGS -DFUSE_USE_VERSION=30 -DHAVE_RSHIM_FUSE")
AC_CHECK_LIB(fuse, cuse_lowlevel_setup, [], [AC_MSG_ERROR([Missing fuse library])])

AC_CHECK_LIB(pthread, pthread_create)

AC_OUTPUT
