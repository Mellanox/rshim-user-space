# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019 Mellanox Technologies. All Rights Reserved.
#

AUTOMAKE_OPTIONS = foreign
SUBDIRS = src man
dist_doc_DATA = README.md
confdir = $(sysconfdir)
dist_conf_DATA = etc/rshim.conf
dist_sbin_SCRIPTS = scripts/bfb-install scripts/bf-reg

AM_DISTCHECK_CONFIGURE_FLAGS = \
  --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)
if HAVE_SYSTEMD
systemdsystemunit_DATA = rshim.service
else
if OS_FREEBSD
init_ddir = $(sysconfdir)/rc.d/
init_d_SCRIPTS = freebsd/rshim
endif
endif

