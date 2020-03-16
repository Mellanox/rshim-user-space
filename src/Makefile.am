# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019 Mellanox Technologies. All Rights Reserved.
#

bin_PROGRAMS = bfrshim

bfrshim_SOURCES = rshim.c rshim_log.c rshim_net.c
bfrshim_CPPFLAGS = -DHAVE_RSHIM_NET

# USB (library is already added by AC_CHECK_LIB)
if BUILD_RSHIM_USB
bfrshim_SOURCES += rshim_usb.c
bfrshim_CPPFLAGS += $(libusb_CFLAGS) -DHAVE_RSHIM_USB
endif

# PCIe
if BUILD_RSHIM_PCIE
bfrshim_SOURCES += rshim_pcie.c rshim_pcie_lf.c
bfrshim_CPPFLAGS += $(libpci_CFLAGS) -DHAVE_RSHIM_PCIE
LIBS += $(libpci_LIBS)
endif

# FUSE / CUSE
if BUILD_RSHIM_FUSE
bfrshim_SOURCES += rshim_fuse.c
bfrshim_CPPFLAGS += $(fuse_CFLAGS)
LIBS += $(fuse_LIBS)
endif
