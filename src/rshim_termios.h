// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 */
#ifndef RSHIM_TERMIOS_H
#define RSHIM_TERMIOS_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* Internal state, never copied directly to or from an ioctl buffer. */
struct rshim_termios {
  uint32_t c_iflag, c_oflag, c_cflag, c_lflag;
  uint8_t c_line, c_cc[32];
  uint32_t c_ispeed, c_ospeed;
};

void rshim_termios_init(struct rshim_termios *state);
/* Returns the UAPI buffer size, or zero for an unhandled ioctl. */
size_t rshim_termios_size(unsigned int cmd, bool *get);
/* Caller validates cmd and the buffer size before converting. */
void rshim_termios_get(const struct rshim_termios *state, unsigned int cmd,
                      void *buf);
void rshim_termios_set(struct rshim_termios *state, unsigned int cmd,
                      const void *buf);

#endif
