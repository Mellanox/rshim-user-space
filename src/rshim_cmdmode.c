// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 */
#include <getopt.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "rshim.h"

int rshim_cmd_fd = -1;
rshim_backend_t *rshim_cmd_bd = NULL;

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

/* Enable/Disable UEFI debug. */
static int rshim_uefi_debug(bool read, uint64_t *setting)
{
  uint64_t value = 0;
  int rc;

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

int rshim_cmdmode_run(int argc, char *argv[])
{
  static const char short_options[] = "cgi:r:s:";
  static struct option long_options[] = {
    { "get-debug", no_argument, NULL, 'g' },
    { "index", required_argument, NULL, 'i' },
    { "reg", required_argument, NULL, 'r' },
    { "set-debug", required_argument, NULL, 's' },
    { NULL, 0, NULL, 0 }
  };
  uint64_t addr = 0, value = 0;
  int c, rc = 0, size;
  char tmp[64], *p;

  /*
   * Use the backend if specified, or else try to create the USB backend
   * which is mainly for DPU BMC.
   */
  if (rshim_static_index >= 0) {
    sprintf(tmp, "/dev/rshim%d/rshim", rshim_static_index);
    rshim_cmd_fd = open(tmp, O_RDWR | O_SYNC);
    if (rshim_cmd_fd == -1) {
      printf("Can't open rshim\n");
      return -ENODEV;
    }
  } else {
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

  /* Parse arguments. */
  optind = 1;
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
