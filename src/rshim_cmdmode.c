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

static int rshim_getset_debug(rshim_backend_t *bd, bool get, uint32_t *setting)
{
  uint64_t value = 0;
  int rc;

  pthread_mutex_lock(&bd->mutex);

  rc = bd->read_rshim(bd, RSHIM_CHANNEL, RSH_BREADCRUMB1, &value,
                      RSHIM_REG_SIZE_8B);
  if (rc) {
    RSHIM_ERR("Failed to read debug setting (0x%x)\n", rc);
    return -1;
  }

  if (get) {
    *setting = (value & RSH_BREADCRUMB1_DBG_ENABLE_MASK) ? 1 : 0;
  } else {
    if (*setting)
      value |= RSH_BREADCRUMB1_DBG_ENABLE_MASK;
    else
      value &= ~RSH_BREADCRUMB1_DBG_ENABLE_MASK;
  }

  rc = bd->write_rshim(bd, RSHIM_CHANNEL, RSH_BREADCRUMB1, value,
                       RSHIM_REG_SIZE_8B);

  pthread_mutex_unlock(&bd->mutex);

  return 0;
}

int rshim_cmdmode_run(int argc, char *argv[])
{
  static const char short_options[] = "cgs:";
  static struct option long_options[] = {
    { "get-debug", no_argument, NULL, 'g' },
    { "set-debug", required_argument, NULL, 's' },
    { NULL, 0, NULL, 0 }
  };
  int c, rc = 0, index = 0;
  uint32_t setting = 0;
  rshim_backend_t *bd;

  /* Use the backend if specified. */
  if (rshim_static_index > 0)
    index = rshim_static_index;

  rshim_lock();

  bd = rshim_find_by_index(index);
  if (!bd) {
    rc = -ENODEV;
    goto done;
  }

  /* Reset the getopt() parsing. */
  optind = 1;

  /* Parse arguments. */
  while ((c = getopt_long(argc, argv, short_options, long_options, NULL))
         != -1) {
    switch (c) {
    case 'g':
      rc = rshim_getset_debug(bd, true, &setting);
      if (rc) {
        printf("--get-debug failed\n");
        goto done;
      }
      printf("0x%x\n", setting);
      break;

    case 's':
      setting = atoi(optarg);
      rc = rshim_getset_debug(bd, false, &setting);
      if (rc) {
        printf("--set-debug failed\n");
        goto done;
      }
      break;

    default:
      break;
    }
  }

done:
  rshim_unlock();
  if (rc)
    printf("Command failed (%d)\n", rc);

  return rc;
}
