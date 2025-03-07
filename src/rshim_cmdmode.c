// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 */
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "rshim.h"

int rshim_cmd_fd = -1;
rshim_backend_t *rshim_cmd_bd = NULL;

/* BF3 by default. */
static uint64_t scratchpad1_addr = BF3_RSH_SCRATCHPAD1;
static uint64_t scratchpad3_addr = BF3_RSH_SCRATCHPAD3;
static uint64_t scratchpad6_addr = BF3_RSH_SCRATCHPAD6;

/* Register read/write via /dev/rshim<N>/rshim. */
static int rshim_fd_rw(uint32_t chan, uint32_t addr, uint64_t *value,
                       int size, bool read)
{
  rshim_ioctl_msg2 msg;
  int rc, fd = rshim_cmd_fd;

  if (fd == -1)
    return -ENODEV;

  msg.addr = ((uint64_t)chan << 16) | addr;
  msg.data = read ? 0 : *value;
  msg.data_size = size;

  if (read) {
    rc = ioctl(fd, RSHIM_IOC_READ2, &msg);
    if (!rc)
      *value = msg.data;
  } else {
    rc = ioctl(fd, RSHIM_IOC_WRITE2, &msg);
  }

  return rc;
}

/* Register read/write via a dummy backend. */
static int rshim_bd_rw(uint32_t chan, uint32_t addr, uint64_t *value,
                       int size, bool read)
{
  rshim_backend_t *bd = rshim_cmd_bd;
  int rc;

  if (!bd)
    return -ENODEV;

  pthread_mutex_lock(&bd->mutex);

  if (read)
    rc = bd->read_rshim(bd, chan, addr, value, size);
  else
    rc = bd->write_rshim(bd,chan, addr, *value, size);

  pthread_mutex_unlock(&bd->mutex);

  return rc;
}

/* Register read/write. */
static int rshim_rw(uint32_t chan, uint32_t addr, uint64_t *value,
                    int size, bool read)
{
  if (rshim_cmd_bd)
    return rshim_bd_rw(chan, addr, value, size, read);
  else if (rshim_cmd_fd >= 0)
    return rshim_fd_rw(chan, addr, value, size, read);
  else
    return -ENODEV;
}

static int rshim_setup(void)
{
  uint64_t value = 0;
  char tmp[64];
  int rc = 0;

  if (rshim_cmd_fd != -1 || rshim_cmd_bd != NULL)
    return 0;

  /* Setup rshim to handle the commands. */
  if (rshim_static_index >= 0) {
    /* Static rshim specified by the "-i" argument. */
    sprintf(tmp, "/dev/rshim%d/rshim", rshim_static_index);
    rshim_cmd_fd = open(tmp, O_RDWR | O_SYNC);
    if (rshim_cmd_fd == -1) {
      printf("Can't open rshim\n");
      return -ENODEV;
    }
  } else {
    /* If not specified, try to connect to USB rshim. */
    rc = rshim_init(NULL, NULL);
    if (rc) {
      printf("rshim_init failed\n");
      return rc;
    }

    rc = rshim_usb_init(rshim_epoll_fd);
    if (rc) {
      perror("USB:");
      return rc;
    }

    rshim_cmd_bd = rshim_find_by_index(0);
    if (!rshim_cmd_bd) {
      printf("Can't find rshim\n");
      return -ENODEV;
    }
  }

  rc = rshim_rw(RSHIM_CHANNEL, RSH_FABRIC_DIM, &value,
                RSHIM_REG_SIZE_8B, true);
  if (rc || RSHIM_BAD_CTRL_REG(value)) {
    printf("Failed to read FABRIC_DIM (0x%x)\n", rc);
    return -ENODEV;
  }

  /* Update address for BF1/BF2. */
  if ((value & 0xff) == 0x22) {
    scratchpad1_addr = RSH_SCRATCHPAD1;
    scratchpad3_addr = RSH_SCRATCHPAD3;
    scratchpad6_addr = RSH_SCRATCHPAD6;
  }

  return 0;
}

/* Enable/Disable UEFI debug. */
static int rshim_uefi_debug(bool read, uint64_t *setting)
{
  uint64_t value = 0;
  int rc;

  rc = rshim_setup();
  if (rc)
    return rc;

  rc = rshim_rw(RSHIM_CHANNEL, RSH_BREADCRUMB1, &value,
                RSHIM_REG_SIZE_8B, true);
  if (rc) {
    printf("Failed to read debug setting (0x%x)\n", rc);
    return -1;
  }

  if (read) {
    *setting = (value & RSH_BREADCRUMB1_DBG_ENABLE_MASK) ? 1 : 0;
  } else {
    if (*setting)
      value |= RSH_BREADCRUMB1_DBG_ENABLE_MASK;
    else
      value &= ~RSH_BREADCRUMB1_DBG_ENABLE_MASK;
  }

  rc = rshim_rw(RSHIM_CHANNEL, RSH_BREADCRUMB1, &value,
                RSHIM_REG_SIZE_8B, false);

  return 0;
}

/* Poll ACK. */
static int bfdump_poll(rsh_scratchpad3_t *sp)
{
  time_t t0, t1;
  int rc;

  time(&t0);

  for (;;) {
    rc = rshim_rw(RSHIM_CHANNEL, scratchpad3_addr,
                  &sp->word, RSHIM_REG_SIZE_8B, true);
    if (rc || RSHIM_BAD_CTRL_REG(sp->word))
      return -ENODEV;

    if (!sp->dpu_own)
      break;

    time(&t1);
    if (difftime(t1, t0) > 2)
      return -ETIMEDOUT;

    usleep(1000);
  }

  return 0;
}

static int bfdump(void)
{
  uint32_t max_len = 0x100000, cur_len = 0;
  rsh_scratchpad3_t sp;
  uint64_t value = 0;
  int rc;

  rc = rshim_setup();
  if (rc)
    return rc;

  /* Take owner */
  rc = bfdump_poll(&sp);
  if (rc < 0) {
    printf("Timeout\n");
    goto done;
  }

  /* Send NONE command to reset the dump. */
  sp.dbg_cmd = RSH_DBG_CMD_NONE;
  sp.dpu_own = 1;
  rc = rshim_rw(RSHIM_CHANNEL, scratchpad3_addr,
                &sp.word, RSHIM_REG_SIZE_8B, false);
  if (rc) {
    printf("Failed to write SP3\n");
    goto done;
  }

  /* Wait for ACK. */
  rc = bfdump_poll(&sp);
  if (rc < 0) {
    printf("Timeout\n");
    goto done;
  }

  printf("Use Ctrl+C to stop it at any time...\n\n");

  for (;;) {
    /* Send BFDUMP command. */
    sp.dbg_cmd = RSH_DBG_CMD_BFDUMP;
    sp.dpu_own = 1;
    rc = rshim_rw(RSHIM_CHANNEL, scratchpad3_addr,
                  &sp.word, RSHIM_REG_SIZE_8B, false);
    if (rc) {
      printf("Failed to read SP2\n");
      goto done;
    }

    /* Poll ACK. */
    rc = bfdump_poll(&sp);
    if (rc < 0) {
      printf("Timeout\n");
      goto done;
    }

    /* Check completion. */
    if (sp.dbg_cmd != RSH_DBG_CMD_BFDUMP)
      break;

    /* Read data. */
    rc = rshim_rw(RSHIM_CHANNEL, scratchpad1_addr,
                 &value, RSHIM_REG_SIZE_8B, true);
    if (rc) {
      printf("Failed to read SP1\n");
      break;
    }

    rc = write(1, &value, sizeof(value));
    if (rc < 0) {
      printf("Failed to write: %m\n");
      goto done;
    }
    cur_len += sizeof(uint64_t);
    if (cur_len >= max_len)
        break;

    rc = rshim_rw(RSHIM_CHANNEL, scratchpad6_addr,
                  &value, RSHIM_REG_SIZE_8B, true);
    if (rc) {
      printf("Failed to write SP6\n");
      break;
    }

    rc = write(1, &value, sizeof(value));
    if (rc < 0) {
      printf("Failed to write: %m\n");
      goto done;
    }
    cur_len += sizeof(uint64_t);
    if (cur_len >= max_len)
      break;
  }

done:
  printf("bfdump completed\n");

  /* Clear scratchpad6 since it'll be used by NIC_FW reset. */
  value = 0;
  rshim_rw(RSHIM_CHANNEL, scratchpad6_addr, &value,
           RSHIM_REG_SIZE_8B, false);

  return rc;
}

/* Read 64-bit number from string. */
static int string_read64(const char *str, uint64_t *value)
{
  char *endptr;

  if (!str || !*str || !value)
    return -EINVAL;

  errno = 0;
  *value = strtoll(str, &endptr, 0);

  return (errno || endptr == str) ? -EINVAL : 0;
}

static void rshim_sig_handler(int sig)
{
  rsh_scratchpad3_t sp = { .word = 0 };
  uint64_t value;
  int rc;

  rc = rshim_rw(RSHIM_CHANNEL, scratchpad3_addr,
                &sp.word, RSHIM_REG_SIZE_8B, true);
  if (rc || RSHIM_BAD_CTRL_REG(sp.word))
    return;

  value = 0;
  rc = rshim_rw(RSHIM_CHANNEL, scratchpad6_addr,
                &value, RSHIM_REG_SIZE_8B, false);
  if (rc)
    printf("Unable to cleanup SP6\n");

  sp.dbg_cmd = RSH_DBG_CMD_NONE;
  sp.dpu_own = 1;
  rc = rshim_rw(RSHIM_CHANNEL, scratchpad3_addr,
                &sp.word, RSHIM_REG_SIZE_8B, false);
  if (rc)
    printf("Unable to cleanup SP2\n");
}

static void set_signals(void)
{
  struct sigaction sa;

  memset(&sa, 0, sizeof(struct sigaction));
  sa.sa_handler = rshim_sig_handler;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);
}

static void print_help(void)
{
  printf("Usage: rshim [options]\n");
  printf("\n");
  printf("OPTIONS:\n");
  printf("  -c, --cmdmode             run in command line mode\n");
  printf("    -g, --get-debug         get debug code\n");
  printf("    -m, --bfdump            debug dump\n");
  printf("    -r, --reg <addr.[32|64] [value]> read/write register\n");
  printf("    -s, --set-debug <0 | 1> set debug code\n");
  printf("  -h, --help                show help info\n");
  printf("  -i, --index               use device path /dev/rshim<i>/\n");
}

int rshim_cmdmode_run(int argc, char *argv[])
{
  static const char short_options[] = "cghimr:s:";
  static struct option long_options[] = {
    { "get-debug", no_argument, NULL, 'g' },
    { "help", no_argument, NULL, 'h' },
    { "index", required_argument, NULL, 'i' },
    { "bfdump", no_argument, NULL, 'm' },
    { "reg", required_argument, NULL, 'r' },
    { "set-debug", required_argument, NULL, 's' },
    { NULL, 0, NULL, 0 }
  };
  uint64_t addr = 0, value = 0;
  int c, rc = 0, size;
  char tmp[64], *p;

  set_signals();

  /* Parse arguments. */
  optind = 1;
  opterr = 1;
  while ((c = getopt_long(argc, argv, short_options, long_options, &optind))
         != -1) {
    switch (c) {
    case 'g':
      rc = rshim_uefi_debug(true, &value);
      if (rc) {
        printf("--get-debug failed\n");
        return rc;
      }
      printf("0x%llx\n", (unsigned long long)value);
      break;

    case 's':
      value = atol(optarg);
      rc = rshim_uefi_debug(false, &value);
      if (rc) {
        printf("--set-debug failed\n");
        return rc;
      }
      break;

    case 'h':
        print_help();
        break;

    case 'm':
        bfdump();
        break;

    case 'r':
      /* Syntax: <addr.[32|64]> [value] */
      strncpy(tmp, (char *)optarg, sizeof(tmp) - 1);
      p = strchr(tmp, '.');
      if (!p)
        return -EINVAL;
      *p++ = 0;
      size = atoi(p);
      if (size != 32 && size != 64)
        return -EINVAL;

      rc = string_read64(tmp, &addr);
      if (rc)
        break;
      if (optind < argc) {
        /* write */
        rc = string_read64(argv[optind], &value);
        if (rc)
          break;

        rc = rshim_rw((uint32_t)addr >> 16, addr & 0xFFFF, &value,
                      size / 8, false);
        if (rc)
          return rc;

        printf("[0x%llx] <- 0x%016llx\n", (unsigned long long)addr,
               (unsigned long long)value);
      } else {
        /* read */
        rc = rshim_rw((uint32_t)addr >> 16, addr & 0xFFFF, &value,
                      size / 8, true);
        if (rc)
          return rc;

        printf("[0x%llx] -> 0x%016llx\n", (unsigned long long)addr,
               (unsigned long long)value);
      }
      break;

    default:
      break;
    }
  }

  /* Cleanup */
  if (rshim_cmd_fd != -1)
    close(rshim_cmd_fd);

  return rc;
}
