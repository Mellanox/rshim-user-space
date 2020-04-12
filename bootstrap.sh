#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019 Mellanox Technologies. All Rights Reserved.
#

autoreconf -ivf || exit 1
rm -rf autom4te.cache
