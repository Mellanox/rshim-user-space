# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019 Mellanox Technologies. All Rights Reserved.
#

bin_PROGRAMS = bfrshim

bfrshim_SOURCES = rshim.c rshim_log.c rshim_net.c

if BUILD_RSHIM_USB
bfrshim_SOURCES += rshim_usb.c
endif

if BUILD_RSHIM_PCIE
bfrshim_SOURCES += rshim_pcie.c rshim_pcie_lf.c
endif
