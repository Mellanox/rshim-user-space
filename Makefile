# SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
#
# Copyright 2019 Mellanox Technologies. All Rights Reserved.
#

TARGET = bfrshim

.PHONY: $(TARGET) clean

all: $(TARGET)

CC = gcc
INC = -Ilibusb-1.0
CDEF = -D_FILE_OFFSET_BITS=64 -DRSHIM_LOG_ENABLE=1 -DFUSE_USE_VERSION=30
CFLAGS = $(INC) $(CDEF) -Wfatal-errors -g
LIBS = -lusb-1.0 -lpci -lfuse -lpthread

OBJS := $(patsubst %.c,%.o,$(wildcard *.c))

$(TARGET): $(OBJS)
	$(CC) $^ -o $@ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) $(TARGET) *.o
