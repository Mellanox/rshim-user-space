// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 */
/* Keep Linux UAPI termios definitions separate from libc's termios.h. */
#include <asm/termbits.h>
#include <asm/ioctls.h>
#include <string.h>

#include "rshim_termios.h"

/* Fail at build time if a new architecture needs a larger internal state. */
typedef char rshim_termios_cc_size[
  NCCS <= sizeof(((struct rshim_termios *)0)->c_cc) ? 1 : -1];
typedef char rshim_termios_buffer_size[
  sizeof(struct termios) <= sizeof(struct rshim_termios) ? 1 : -1];
#ifdef TCGETS2
typedef char rshim_termios2_buffer_size[
  sizeof(struct termios2) <= sizeof(struct rshim_termios) ? 1 : -1];
#endif

void rshim_termios_init(struct rshim_termios *state)
{
  static const struct rshim_termios initial = {
    .c_iflag = INLCR | ICRNL,
    .c_oflag = OPOST | ONLCR,
    .c_cflag = B115200 | HUPCL | CLOCAL | CREAD | CS8,
    .c_lflag = ISIG | ICANON | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
    .c_cc = { [VINTR] = 3, [VQUIT] = 28, [VERASE] = 127, [VKILL] = 21,
              [VEOF] = 4, [VMIN] = 1, [VSTART] = 17, [VSTOP] = 19,
              [VSUSP] = 26, [VREPRINT] = 18, [VDISCARD] = 15,
              [VWERASE] = 23, [VLNEXT] = 22 },
    .c_ispeed = 115200, .c_ospeed = 115200,
  };

  *state = initial;
}

size_t rshim_termios_size(unsigned int cmd, bool *get)
{
  *get = (cmd == TCGETS);
#ifdef TCGETS2
  *get |= (cmd == TCGETS2);
#endif
  switch (cmd) {
  case TCGETS:
  case TCSETS:
  case TCSETSW:
  case TCSETSF:
    return sizeof(struct termios);
#ifdef TCGETS2
  case TCGETS2:
  case TCSETS2:
  case TCSETSW2:
  case TCSETSF2:
    return sizeof(struct termios2);
#endif
  default:
    return 0;
  }
}

/* Explicit field conversion also avoids exposing structure padding. */
#define COPY_TERMIOS(dst, src) do { \
  (dst)->c_iflag = (src)->c_iflag; \
  (dst)->c_oflag = (src)->c_oflag; \
  (dst)->c_cflag = (src)->c_cflag; \
  (dst)->c_lflag = (src)->c_lflag; \
  (dst)->c_line = (src)->c_line; \
  memcpy((dst)->c_cc, (src)->c_cc, NCCS); \
} while (0)

/* Decode symbolic baud bits, retaining numeric rates for BOTHER. */
static unsigned int rshim_termios_speed(unsigned int baud, unsigned int other)
{
  static const struct {
    unsigned int code, speed;
  } rates[] = {
    { B0, 0 }, { B50, 50 }, { B75, 75 }, { B110, 110 },
    { B134, 134 }, { B150, 150 }, { B200, 200 }, { B300, 300 },
    { B600, 600 }, { B1200, 1200 }, { B1800, 1800 },
    { B2400, 2400 }, { B4800, 4800 }, { B9600, 9600 },
    { B19200, 19200 }, { B38400, 38400 }, { B57600, 57600 },
    { B115200, 115200 }, { B230400, 230400 }, { B460800, 460800 },
    { B500000, 500000 }, { B576000, 576000 }, { B921600, 921600 },
    { B1000000, 1000000 }, { B1152000, 1152000 },
    { B1500000, 1500000 }, { B2000000, 2000000 },
#ifdef B2500000
    { B2500000, 2500000 }, { B3000000, 3000000 },
    { B3500000, 3500000 }, { B4000000, 4000000 },
#endif
  };
  size_t i;

  for (i = 0; i < sizeof(rates) / sizeof(rates[0]); i++)
    if (rates[i].code == baud)
      return rates[i].speed;
  return other;
}

void rshim_termios_get(const struct rshim_termios *state, unsigned int cmd,
                      void *buf)
{
#ifdef TCGETS2
  if (cmd == TCGETS2) {
    struct termios2 wire = {0};

    COPY_TERMIOS(&wire, state);
    wire.c_ispeed = state->c_ispeed;
    wire.c_ospeed = state->c_ospeed;
    memcpy(buf, &wire, sizeof(wire));
  } else
#endif
  {
    struct termios wire = {0};

    COPY_TERMIOS(&wire, state);
#ifndef TCGETS2
    /* Architectures such as powerpc carry speeds in TCGETS itself. */
    wire.c_ispeed = state->c_ispeed;
    wire.c_ospeed = state->c_ospeed;
#endif
    memcpy(buf, &wire, sizeof(wire));
  }
}

void rshim_termios_set(struct rshim_termios *state, unsigned int cmd,
                      const void *buf)
{
  unsigned int ibaud;

#ifdef TCGETS2
  if (cmd == TCSETS2 || cmd == TCSETSW2 || cmd == TCSETSF2) {
    struct termios2 wire;

    memcpy(&wire, buf, sizeof(wire));
    COPY_TERMIOS(state, &wire);
    state->c_ispeed = wire.c_ispeed;
    state->c_ospeed = wire.c_ospeed;
  } else
#endif
  {
    struct termios wire;

    memcpy(&wire, buf, sizeof(wire));
    COPY_TERMIOS(state, &wire);
#ifndef TCGETS2
    state->c_ispeed = wire.c_ispeed;
    state->c_ospeed = wire.c_ospeed;
#endif
  }
  state->c_ospeed = rshim_termios_speed(state->c_cflag & CBAUD, state->c_ospeed);
  ibaud = (state->c_cflag & CIBAUD) >> IBSHIFT;
  state->c_ispeed = ibaud ? rshim_termios_speed(ibaud, state->c_ispeed) :
                         state->c_ospeed;
}
