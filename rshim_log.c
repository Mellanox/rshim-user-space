// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
/*
 * Copyright 2019 Mellanox Technologies. All Rights Reserved.
 *
 */

#include <pthread.h>
#include "rshim.h"

/* Log module */
const char * const rshim_log_mod[] = {
  "others", "BL1", "BL2", "BL2R", "BL31", "UEFI"
};

/* Log type. */
#define BF_RSH_LOG_TYPE_UNKNOWN         0x00ULL
#define BF_RSH_LOG_TYPE_PANIC           0x01ULL
#define BF_RSH_LOG_TYPE_EXCEPTION       0x02ULL
#define BF_RSH_LOG_TYPE_ASSERT          0x03ULL
#define BF_RSH_LOG_TYPE_MSG             0x04ULL

/* Utility macro. */
#define BF_RSH_LOG_MOD_MASK     0x0FULL
#define BF_RSH_LOG_MOD_SHIFT    60
#define BF_RSH_LOG_TYPE_MASK    0x0FULL
#define BF_RSH_LOG_TYPE_SHIFT   56
#define BF_RSH_LOG_LEN_MASK     0x7FULL
#define BF_RSH_LOG_LEN_SHIFT    48
#define BF_RSH_LOG_PC_MASK      0xFFFFFFFFULL
#define BF_RSH_LOG_PC_SHIFT     0

#define BF_RSH_LOG_HEADER_GET(f, h) \
  (((h) >> BF_RSH_LOG_##f##_SHIFT) & BF_RSH_LOG_##f##_MASK)

#define AARCH64_MRS_REG_SHIFT 5
#define AARCH64_MRS_REG_MASK  0xffff

struct rshim_log_reg {
  char *name;
  uint32_t opcode;
};

static struct rshim_log_reg rshim_log_regs[] = {
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
  struct rshim_log_reg *reg = rshim_log_regs;

  while (reg->name) {
    if (reg->opcode == opcode)
      return reg->name;
    reg++;
  }

  return "unknown";
}

static int rshim_log_show_crash(struct rshim_backend *bd, uint64_t hdr,
                                char *buf, int size)
{
  int rc = 0, i, module, type, len, n = 0;
  uint64_t opcode, data;
  char *p = buf;
  uint32_t pc;

  module = BF_RSH_LOG_HEADER_GET(MOD, hdr);
  if (module >= sizeof(rshim_log_mod)/sizeof(rshim_log_mod[0]))
    module = 0;
  type = BF_RSH_LOG_HEADER_GET(TYPE, hdr);
  len = BF_RSH_LOG_HEADER_GET(LEN, hdr);

  if (type == BF_RSH_LOG_TYPE_EXCEPTION)
    n = snprintf(p, size, "Exception(%s):\n", rshim_log_mod[module]);
  else if (type == BF_RSH_LOG_TYPE_PANIC) {
    pc = BF_RSH_LOG_HEADER_GET(PC, hdr);
    n = snprintf(p, size, "PANIC(%s): PC = 0x%x\n", rshim_log_mod[module], pc);
  }
  p += n;
  size -= n;

  for (i = 0; i < len/2; i++) {
    rc = bd->read_rshim(bd, RSHIM_CHANNEL, RSH_SCRATCH_BUF_DAT, &opcode);
    if (rc)
      break;

    rc = bd->read_rshim(bd, RSHIM_CHANNEL, RSH_SCRATCH_BUF_DAT, &data);
    if (rc)
      break;

    opcode = (le64toh(opcode) >> AARCH64_MRS_REG_SHIFT) &
             AARCH64_MRS_REG_MASK;
    n = snprintf(p, size, " %-16s0x%llx\n", rshim_log_get_reg_name(opcode),
                 (unsigned long long)data);
    p += n;
    size -= n;
  }

  return p - buf;
}

static int rshim_log_show_msg(struct rshim_backend *bd, uint64_t hdr,
                              char *buf, int size)
{
  int rc, len = BF_RSH_LOG_HEADER_GET(LEN, hdr);
  uint64_t data;
  char *tmp, *p;

  if (len <= 0)
    return -EINVAL;

  tmp = malloc(len * sizeof(uint64_t) + 1);
  if (!tmp)
    return 0;
  p = tmp;

  while (len--) {
    rc = bd->read_rshim(bd, RSHIM_CHANNEL, RSH_SCRATCH_BUF_DAT, &data);
    if (rc)
      return 0;
    memcpy(p, &data, sizeof(data));
    p += sizeof(data);
  }
  *p = '\0';
  len = snprintf(buf, size, " %s\n", tmp);

  free(tmp);
  return len;
}

int rshim_log_show(struct rshim_backend *bd, char *buf, int size)
{
  uint64_t data, idx, hdr;
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
  while (true) {
    rc = bd->read_rshim(bd, RSHIM_CHANNEL, RSH_SEMAPHORE0, &data);
    if (rc) {
      RSHIM_ERR("couldn't read RSH_SEMAPHORE0\n");
      return p - buf;
    }

    if (!data)
      break;

    usleep(10000);
  }

  /* Read the current index. */
  rc = bd->read_rshim(bd, RSHIM_CHANNEL, RSH_SCRATCH_BUF_CTL, &idx);
  if (rc) {
    RSHIM_ERR("couldn't read RSH_SCRATCH_BUF_CTL\n");
    goto done;
  }
  idx = (idx >> RSH_SCRATCH_BUF_CTL__IDX_SHIFT) & RSH_SCRATCH_BUF_CTL__IDX_MASK;
  if (idx <= 1)
    goto done;

  /* Reset the index to 0. */
  rc = bd->write_rshim(bd, RSHIM_CHANNEL, RSH_SCRATCH_BUF_CTL, 0);
  if (rc) {
    RSHIM_ERR("couldn't write RSH_SCRATCH_BUF_CTL\n");
    goto done;
  }

  i = 0;
  while (i < idx) {
    rc = bd->read_rshim(bd, RSHIM_CHANNEL, RSH_SCRATCH_BUF_DAT, &hdr);
    if (rc) {
      RSHIM_ERR("couldn't read RSH_SCRATCH_BUF_DAT\n");
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
        bd->read_rshim(bd, RSHIM_CHANNEL, RSH_SCRATCH_BUF_DAT, &data);
      break;
    }
  }

  /* Restore the idx value. */
  bd->write_rshim(bd, RSHIM_CHANNEL, RSH_SCRATCH_BUF_CTL, idx);

done:
  /* Release the semaphore. */
  bd->write_rshim(bd, RSHIM_CHANNEL, RSH_SEMAPHORE0, 0);

  return p - buf;
}
