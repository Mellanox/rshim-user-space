// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright (C) 2019-2023 Mellanox Technologies. All Rights Reserved.
 *
 */

#include "rshim_regs.h"
#include "rshim.h"

const struct rshim_regs bf1_bf2_rshim_regs = {
  .boot_fifo_data = RSH_BOOT_FIFO_DATA,
  .boot_fifo_count = RSH_BOOT_FIFO_COUNT,
  .boot_fifo_count_mask = RSH_BOOT_FIFO_COUNT__BOOT_FIFO_COUNT_MASK,
  .boot_control = RSH_BOOT_CONTROL,
  .reset_control = RSH_RESET_CONTROL,
  .scratchpad1 = RSH_SCRATCHPAD1,
  .scratchpad2 = RSH_SCRATCHPAD2,
  .scratchpad6 = RSH_SCRATCHPAD6,
  .tm_htt_sts = RSH_TM_HOST_TO_TILE_STS,
  .tm_tth_sts = RSH_TM_TILE_TO_HOST_STS,
  .tm_htt_data = RSH_TM_HOST_TO_TILE_DATA,
  .tm_tth_data = RSH_TM_TILE_TO_HOST_DATA,
  .semaphore0 = RSH_SEMAPHORE0,
  .mem_acc_ctl = RSH_MEM_ACC_CTL,
  .mem_acc_rsp_cnt = RSH_MEM_ACC_RSP_CNT,
  .mem_acc_data_first_word = RSH_MEM_ACC_DATA__FIRST_WORD,
  .device_mstr_priv_lvl = RSH_DEVICE_MSTR_PRIV_LVL,
  .device_mstr_priv_lvl_shift = RSH_DEVICE_MSTR_PRIV_LVL__MEM_ACC_LVL_SHIFT,
  .fabric_dim = RSH_FABRIC_DIM,
  .uptime = RSH_UPTIME,
  .uptime_por = RSH_UPTIME_POR,
  .arm_wdg_control_wcs = RSH_ARM_WDG_CONTROL_WCS,
  .scratch_buf_dat = RSH_SCRATCH_BUF_DAT,
  .scratch_buf_ctl = RSH_SCRATCH_BUF_CTL
};

const struct rshim_regs bf3_rshim_regs = {
  .boot_fifo_data = BF3_RSH_BOOT_FIFO_DATA,
  .boot_fifo_count = BF3_RSH_BOOT_FIFO_COUNT,
  .boot_fifo_count_mask = BF3_RSH_BOOT_FIFO_COUNT__BOOT_FIFO_COUNT_MASK,
  .boot_control = BF3_RSH_BOOT_CONTROL,
  .reset_control = BF3_RSH_RESET_CONTROL,
  .scratchpad1 = BF3_RSH_SCRATCHPAD1,
  .scratchpad2 = BF3_RSH_SCRATCHPAD2,
  .scratchpad6 = BF3_RSH_SCRATCHPAD6,
  .tm_htt_sts = BF3_RSH_TM_HOST_TO_TILE_STS,
  .tm_tth_sts = BF3_RSH_TM_TILE_TO_HOST_STS,
  .tm_htt_data = BF3_RSH_TM_HOST_TO_TILE_DATA,
  .tm_tth_data = BF3_RSH_TM_TILE_TO_HOST_DATA,
  .semaphore0 = BF3_RSH_SEMAPHORE0,
  .mem_acc_ctl = BF3_RSH_MEM_ACC_CTL,
  .mem_acc_rsp_cnt = BF3_RSH_MEM_ACC_RSP_CNT,
  .mem_acc_data_first_word = BF3_RSH_MEM_ACC_DATA__FIRST_WORD,
  .device_mstr_priv_lvl = BF3_RSH_DEVICE_MSTR_PRIV_LVL,
  .device_mstr_priv_lvl_shift = BF3_RSH_DEVICE_MSTR_PRIV_LVL__MEM_ACC_LVL_SHIFT,
  .fabric_dim = BF3_RSH_FABRIC_DIM,
  .uptime = BF3_RSH_UPTIME,
  .uptime_por = BF3_RSH_UPTIME_POR,
  .arm_wdg_control_wcs = BF3_RSH_ARM_WDG_CONTROL_WCS,
  .scratch_buf_dat = BF3_RSH_SCRATCH_BUF_DAT,
  .scratch_buf_ctl = BF3_RSH_SCRATCH_BUF_CTL
};
