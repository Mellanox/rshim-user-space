#!/bin/sh

autoreconf -ivf || exit 1
rm -rf autom4te.cache
