// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright (C) 2019-2023 Mellanox Technologies. All Rights Reserved.
 *
 */

#include <pthread.h>
#include <stdarg.h>
#include <time.h>
#include "rshim.h"

/* Log module */
const char * const rshim_log_mod[] = {
  "MISC", "BL1", "BL2", "BL2R", "BL31", "UEFI", "PSC"
};

/* Log level */
const char * const rshim_log_levels[] = { "INFO", "WARN", "ERR", "ASSERT" };

/* Log type. */
#define BF_RSH_LOG_TYPE_UNKNOWN         0x00ULL
#define BF_RSH_LOG_TYPE_PANIC           0x01ULL
#define BF_RSH_LOG_TYPE_EXCEPTION       0x02ULL
#define BF_RSH_LOG_TYPE_UNUSED          0x03ULL
#define BF_RSH_LOG_TYPE_MSG             0x04ULL

/* Utility macro. */
#define BF_RSH_LOG_MOD_MASK             0x0FULL
#define BF_RSH_LOG_MOD_SHIFT            60
#define BF_RSH_LOG_TYPE_MASK            0x0FULL
#define BF_RSH_LOG_TYPE_SHIFT           56
#define BF_RSH_LOG_LEN_MASK             0x7FULL
#define BF_RSH_LOG_LEN_SHIFT            48
#define BF_RSH_LOG_ARG_MASK             0xFFFFFFFFULL
#define BF_RSH_LOG_ARG_SHIFT            16
#define BF_RSH_LOG_HAS_ARG_MASK         0xFFULL
#define BF_RSH_LOG_HAS_ARG_SHIFT        8
#define BF_RSH_LOG_LEVEL_MASK           0xFFULL
#define BF_RSH_LOG_LEVEL_SHIFT          0
#define BF_RSH_LOG_PC_MASK              0xFFFFFFFFULL
#define BF_RSH_LOG_PC_SHIFT             0
#define BF_RSH_LOG_SYNDROME_MASK        0xFFFFFFFFULL
#define BF_RSH_LOG_SYNDROME_SHIFT       0

#define BF_RSH_LOG_HEADER_GET(f, h) \
  (((h) >> BF_RSH_LOG_##f##_SHIFT) & BF_RSH_LOG_##f##_MASK)

#define AARCH64_MRS_REG_SHIFT 5
#define AARCH64_MRS_REG_MASK  0xffff

typedef struct {
  char *name;
  uint32_t opcode;
} rshim_log_reg_t;

static rshim_log_reg_t rshim_log_regs[] = {
  {"actlr_el1", 0b1100000010000001},
  {"actlr_el2", 0b1110000010000001},
  {"actlr_el3", 0b1111000010000001},
  {"afsr0_el1", 0b1100001010001000},
  {"afsr0_el2", 0b1110001010001000},
  {"afsr0_el3", 0b1111001010001000},
  {"afsr1_el1", 0b1100001010001001},
  {"afsr1_el2", 0b1110001010001001},
  {"afsr1_el3", 0b1111001010001001},
  {"amair_el1", 0b1100010100011000},
  {"amair_el2", 0b1110010100011000},
  {"amair_el3", 0b1111010100011000},
  {"ccsidr_el1", 0b1100100000000000},
  {"clidr_el1", 0b1100100000000001},
  {"cntkctl_el1", 0b1100011100001000},
  {"cntp_ctl_el0", 0b1101111100010001},
  {"cntp_cval_el0", 0b1101111100010010},
  {"cntv_ctl_el0", 0b1101111100011001},
  {"cntv_cval_el0", 0b1101111100011010},
  {"contextidr_el1", 0b1100011010000001},
  {"cpacr_el1", 0b1100000010000010},
  {"cptr_el2", 0b1110000010001010},
  {"cptr_el3", 0b1111000010001010},
  {"vtcr_el2", 0b1110000100001010},
  {"ctr_el0", 0b1101100000000001},
  {"currentel", 0b1100001000010010},
  {"dacr32_el2", 0b1110000110000000},
  {"daif", 0b1101101000010001},
  {"dczid_el0", 0b1101100000000111},
  {"dlr_el0", 0b1101101000101001},
  {"dspsr_el0", 0b1101101000101000},
  {"elr_el1", 0b1100001000000001},
  {"elr_el2", 0b1110001000000001},
  {"elr_el3", 0b1111001000000001},
  {"esr_el1", 0b1100001010010000},
  {"esr_el2", 0b1110001010010000},
  {"esr_el3", 0b1111001010010000},
  {"esselr_el1", 0b1101000000000000},
  {"far_el1", 0b1100001100000000},
  {"far_el2", 0b1110001100000000},
  {"far_el3", 0b1111001100000000},
  {"fpcr", 0b1101101000100000},
  {"fpexc32_el2", 0b1110001010011000},
  {"fpsr", 0b1101101000100001},
  {"hacr_el2", 0b1110000010001111},
  {"har_el2", 0b1110000010001000},
  {"hpfar_el2", 0b1110001100000100},
  {"hstr_el2", 0b1110000010001011},
  {"far_el1", 0b1100001100000000},
  {"far_el2", 0b1110001100000000},
  {"far_el3", 0b1111001100000000},
  {"hcr_el2", 0b1110000010001000},
  {"hpfar_el2", 0b1110001100000100},
  {"id_aa64afr0_el1", 0b1100000000101100},
  {"id_aa64afr1_el1", 0b1100000000101101},
  {"id_aa64dfr0_el1", 0b1100000000101100},
  {"id_aa64isar0_el1", 0b1100000000110000},
  {"id_aa64isar1_el1", 0b1100000000110001},
  {"id_aa64mmfr0_el1", 0b1100000000111000},
  {"id_aa64mmfr1_el1", 0b1100000000111001},
  {"id_aa64pfr0_el1", 0b1100000000100000},
  {"id_aa64pfr1_el1", 0b1100000000100001},
  {"ifsr32_el2", 0b1110001010000001},
  {"isr_el1", 0b1100011000001000},
  {"mair_el1", 0b1100010100010000},
  {"mair_el2", 0b1110010100010000},
  {"mair_el3", 0b1111010100010000},
  {"midr_el1", 0b1100000000000000},
  {"mpidr_el1", 0b1100000000000101},
  {"nzcv", 0b1101101000010000},
  {"revidr_el1", 0b1100000000000110},
  {"rmr_el3", 0b1111011000000010},
  {"par_el1", 0b1100001110100000},
  {"rvbar_el3", 0b1111011000000001},
  {"scr_el3", 0b1111000010001000},
  {"sctlr_el1", 0b1100000010000000},
  {"sctlr_el2", 0b1110000010000000},
  {"sctlr_el3", 0b1111000010000000},
  {"sp_el0", 0b1100001000001000},
  {"sp_el1", 0b1110001000001000},
  {"spsel", 0b1100001000010000},
  {"spsr_abt", 0b1110001000011001},
  {"spsr_el1", 0b1100001000000000},
  {"spsr_el2", 0b1110001000000000},
  {"spsr_el3", 0b1111001000000000},
  {"spsr_fiq", 0b1110001000011011},
  {"spsr_irq", 0b1110001000011000},
  {"spsr_und", 0b1110001000011010},
  {"tcr_el1", 0b1100000100000010},
  {"tcr_el2", 0b1110000100000010},
  {"tcr_el3", 0b1111000100000010},
  {"tpidr_el0", 0b1101111010000010},
  {"tpidr_el1", 0b1100011010000100},
  {"tpidr_el2", 0b1110011010000010},
  {"tpidr_el3", 0b1111011010000010},
  {"tpidpro_el0", 0b1101111010000011},
  {"vbar_el1", 0b1100011000000000},
  {"vbar_el2", 0b1110011000000000},
  {"vbar_el3", 0b1111011000000000},
  {"vmpidr_el2", 0b1110000000000101},
  {"vpidr_el2", 0b1110000000000000},
  {"ttbr0_el1", 0b1100000100000000},
  {"ttbr0_el2", 0b1110000100000000},
  {"ttbr0_el3", 0b1111000100000000},
  {"ttbr1_el1", 0b1100000100000001},
  {"vtcr_el2", 0b1110000100001010},
  {"vttbr_el2", 0b1110000100001000},
  {NULL, 0b0000000000000000},
};

static char *rshim_log_get_reg_name(uint64_t opcode)
{
  rshim_log_reg_t *reg = rshim_log_regs;

  while (reg->name) {
    if (reg->opcode == opcode)
      return reg->name;
    reg++;
  }

  return "unknown";
}

static int rshim_log_show_crash(rshim_backend_t *bd, uint64_t hdr, char *buf,
                                int size)
{
  int rc = 0, i, module, type, len, n = 0;
  uint64_t opcode, data;
  char *p = buf;
  uint32_t pc, syndrome, ec;

  module = BF_RSH_LOG_HEADER_GET(MOD, hdr);
  if (module >= sizeof(rshim_log_mod) / sizeof(rshim_log_mod[0]))
    module = 0;
  type = BF_RSH_LOG_HEADER_GET(TYPE, hdr);
  len = BF_RSH_LOG_HEADER_GET(LEN, hdr);

  if (type == BF_RSH_LOG_TYPE_EXCEPTION) {
    syndrome = BF_RSH_LOG_HEADER_GET(SYNDROME, hdr);
    ec = syndrome >> 26;
    n = snprintf(p, size, " Exception(%s): syndrome = 0x%x%s\n",
                 rshim_log_mod[module], syndrome,
                 (ec == 0x24 || ec == 0x25) ? "(Data Abort)" :
                 (ec == 0x2f) ? "(SError)" : "");
  }
  else if (type == BF_RSH_LOG_TYPE_PANIC) {
    pc = BF_RSH_LOG_HEADER_GET(PC, hdr);
    n = snprintf(p, size, " PANIC(%s): PC = 0x%x\n", rshim_log_mod[module], pc);
  }
  p += n;
  size -= n;

  for (i = 0; i < len/2; i++) {
    rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->scratch_buf_dat, &opcode,
                        RSHIM_REG_SIZE_8B);
    if (rc)
      break;

    rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->scratch_buf_dat, &data,
                        RSHIM_REG_SIZE_8B);
    if (rc)
      break;

    opcode = (le64toh(opcode) >> AARCH64_MRS_REG_SHIFT) &
             AARCH64_MRS_REG_MASK;
    n = snprintf(p, size, "   %-16s0x%llx\n", rshim_log_get_reg_name(opcode),
                 (unsigned long long)data);
    p += n;
    size -= n;
  }

  return p - buf;
}

static int rshim_log_format_msg(char *buf, int len, const char* msg, ...)
{
  va_list args;

  va_start(args, msg);
  len = vsnprintf(buf, len, msg, args);
  va_end(args);

  return len;
}

static int rshim_log_show_msg(rshim_backend_t *bd, uint64_t hdr, char *buf,
                              int size)
{
  int rc;
  int module = BF_RSH_LOG_HEADER_GET(MOD, hdr);
  int len = BF_RSH_LOG_HEADER_GET(LEN, hdr);
  int level = BF_RSH_LOG_HEADER_GET(LEVEL, hdr);
  int has_arg = BF_RSH_LOG_HEADER_GET(HAS_ARG, hdr);
  uint32_t arg = BF_RSH_LOG_HEADER_GET(ARG, hdr);
  uint64_t data;
  char *msg, *p;

  if (len <= 0)
    return -EINVAL;

  if (module >= sizeof(rshim_log_mod) / sizeof(rshim_log_mod[0]))
    module = 0;
  if (level >= sizeof(rshim_log_levels) / sizeof(rshim_log_levels[0]))
    level = 0;

  msg = malloc(len * sizeof(uint64_t) + 1);
  if (!msg)
    return 0;
  p = msg;

  while (len--) {
    rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->scratch_buf_dat, &data,
                        RSHIM_REG_SIZE_8B);
    if (rc) {
      free(msg);
      return 0;
    }
    memcpy(p, &data, sizeof(data));
    p += sizeof(data);
  }
  *p = '\0';
  if (!has_arg) {
    len = snprintf(buf, size, " %s[%s]: %s\n", rshim_log_levels[level],
                   rshim_log_mod[module], msg);
  } else {
    len = snprintf(buf, size, " %s[%s]: ", rshim_log_levels[level],
                   rshim_log_mod[module]);
    // coverity[ +tainted_string_sanitize_content : arg-2 ]
    len += rshim_log_format_msg(buf + len, size - len, msg, arg);
    len += snprintf(buf + len, size - len, "\n");
  }

  free(msg);
  return len;
}

int rshim_log_show(rshim_backend_t *bd, char *buf, int size)
{
  uint64_t data, idx, hdr;
  time_t t0, t1;
  int i, n, rc, type, len;
  char *p = buf;

  n = snprintf(p, size, "---------------------------------------\n");
  p += n;
  size -= n;
  n = snprintf(p, size, "             Log Messages\n");
  p += n;
  size -= n;
  n = snprintf(p, size, "---------------------------------------\n");
  p += n;
  size -= n;

  /* Take the semaphore. */
  time(&t0);
  while (true) {
    data = 0x1;
    rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->semaphore0, &data,
                        RSHIM_REG_SIZE_8B);
    if (rc || RSHIM_BAD_CTRL_REG(data)) {
      RSHIM_ERR("rshim%d failed to read RSH_SEMAPHORE0(%d)\n", bd->index, rc);
      return p - buf;
    }

    if (!data)
      break;

    /* Add a timeout in case the semaphore is stuck. */
    time(&t1);
    if (difftime(t1, t0) > 3)
      return 0;
  }

  /* Read the current index. */
  rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->scratch_buf_ctl, &idx,
                      RSHIM_REG_SIZE_8B);
  if (rc) {
    RSHIM_ERR("rshim%d failed to read RSH_SCRATCH_BUF_CTL(%d)\n",
              bd->index, rc);
    goto done;
  }
  idx = (idx >> RSH_SCRATCH_BUF_CTL__IDX_SHIFT) & RSH_SCRATCH_BUF_CTL__IDX_MASK;
  if (idx <= 1)
    goto done;

  /* Reset the index to 0. */
  rc = bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->scratch_buf_ctl, 0,
                       RSHIM_REG_SIZE_8B);
  if (rc) {
    RSHIM_ERR("rshim%d failed to write RSH_SCRATCH_BUF_CTL(%d)\n",
              bd->index, rc);
    goto done;
  }

  i = 0;
  while (i < idx) {
    rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->scratch_buf_dat, &hdr,
                        RSHIM_REG_SIZE_8B);
    if (rc) {
      RSHIM_ERR("rshim%d failed to read RSH_SCRATCH_BUF_DAT(%d)\n",
                bd->index, rc);
      goto done;
    }
    hdr = le64toh(hdr);
    type = BF_RSH_LOG_HEADER_GET(TYPE, hdr);
    len = BF_RSH_LOG_HEADER_GET(LEN, hdr);
    i += 1 + len;
    /* Ignore if wraparounded. */
    if (i > idx)
      break;

    switch (type) {
    case BF_RSH_LOG_TYPE_PANIC:
    case BF_RSH_LOG_TYPE_EXCEPTION:
      n = rshim_log_show_crash(bd, hdr, p, size);
      p += n;
      size -= n;
      break;
    case BF_RSH_LOG_TYPE_MSG:
      n = rshim_log_show_msg(bd, hdr, p, size);
      p += n;
      size -= n;
      break;
    default:
      /* Drain this message. */
      while (len--)
        bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->scratch_buf_dat, &data,
                       RSHIM_REG_SIZE_8B);
      break;
    }
  }

  /* Clear or Restore the idx value. */
  bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->scratch_buf_ctl,
                  bd->clear_on_read ? 0 : idx, RSHIM_REG_SIZE_8B);

done:
  /* Release the semaphore. */
  bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->semaphore0, 0,
                  RSHIM_REG_SIZE_8B);

  return p - buf;
}
