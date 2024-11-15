# SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
# Copyright (C) 2019 Mellanox Technologies. All Rights Reserved.
#

sbin_PROGRAMS = rshim

rshim_SOURCES = rshim.c rshim_log.c rshim_net.c rshim_regs.c rshim_cmdmode.c
rshim_CPPFLAGS = -Wall -DHAVE_RSHIM_NET

# USB (library is already added by AC_CHECK_LIB)
if BUILD_RSHIM_USB
rshim_SOURCES += rshim_usb.c
rshim_CPPFLAGS += $(libusb_CFLAGS) -DHAVE_RSHIM_USB
endif

# PCIe
if BUILD_RSHIM_PCIE
rshim_SOURCES += rshim_pcie.c rshim_pcie_lf.c
rshim_CPPFLAGS += $(libpci_CFLAGS) -DHAVE_RSHIM_PCIE
LIBS += $(libpci_LIBS)
endif

# FUSE / CUSE
if BUILD_RSHIM_FUSE
rshim_SOURCES += rshim_fuse.c
rshim_CPPFLAGS += $(fuse_CFLAGS) -DHAVE_RSHIM_FUSE
LIBS += $(fuse_LIBS)
endif
