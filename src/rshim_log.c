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

/*
 * Inner ring drain: acquire semaphore, read messages, write back ctl,
 * release.  Emits only " LEVEL[MOD]: msg\n" body lines (no banner) into
 * @buf.  When @force_clear is true the final ctl write is always 0 --
 * used by the shadow-ring drainer, which is the sole consumer of the hw
 * ring once the shadow is active.  When false the legacy behaviour
 * applies: ctl is reset to 0 if clear_on_read is set, otherwise restored
 * to the original idx.
 *
 * Must be called with bd->mutex held (read_rshim / write_rshim
 * convention).
 */
static int rshim_log_drain_to_buf(rshim_backend_t *bd, char *buf, int size,
                                  bool force_clear)
{
  uint64_t data, idx, hdr;
  time_t t0, t1;
  int i, n, rc, type, len;
  char *p = buf;

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

  /* Reset the index to 0 so subsequent scratch_buf_dat reads start
   * from word 0 of the live ring. */
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

  /* Clear or restore the idx value. */
  bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->scratch_buf_ctl,
                  (force_clear || bd->clear_on_read) ? 0 : idx,
                  RSHIM_REG_SIZE_8B);

done:
  /* Release the semaphore. */
  bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->semaphore0, 0,
                  RSHIM_REG_SIZE_8B);

  return p - buf;
}

int rshim_log_show(rshim_backend_t *bd, char *buf, int size)
{
  char *p = buf;
  int n;

  n = snprintf(p, size, "---------------------------------------\n");
  p += n;
  size -= n;
  n = snprintf(p, size, "             Log Messages\n");
  p += n;
  size -= n;
  n = snprintf(p, size, "---------------------------------------\n");
  p += n;
  size -= n;

  /* Drain into the caller's buffer with the legacy clear-or-restore
   * policy (honours bd->clear_on_read).  Used by rshim_fuse_misc_read()
   * at DISPLAY_LEVEL 2 when the shadow ring is disabled. */
  n = rshim_log_drain_to_buf(bd, p, size, false);
  p += n;

  return p - buf;
}

int rshim_log_drain(rshim_backend_t *bd)
{
  uint64_t data;
  time_t t0, t1;
  int rc;

  /*
   * Acquire semaphore0.  This is the same coordination protocol used by
   * rshim_log_show(): poll the hw semaphore until we read 0 (free), at
   * which point the read implicitly takes it.  Bail out after 3 seconds
   * so a wedged DPU doesn't block the misc read indefinitely.
   */
  time(&t0);
  while (true) {
    data = 0x1;
    rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->semaphore0, &data,
                        RSHIM_REG_SIZE_8B);
    if (rc || RSHIM_BAD_CTRL_REG(data)) {
      RSHIM_ERR("rshim%d failed to read RSH_SEMAPHORE0(%d)\n", bd->index, rc);
      return -EIO;
    }
    if (!data)
      break;

    time(&t1);
    if (difftime(t1, t0) > 3)
      return -EBUSY;
  }

  /*
   * Reset the write index.  We deliberately do not honour clear_on_read
   * here -- this function exists precisely to discard the ring contents.
   * Any data the DPU has written is dropped on the floor.
   */
  bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->scratch_buf_ctl, 0,
                  RSHIM_REG_SIZE_8B);

  /* Release the semaphore. */
  bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->semaphore0, 0,
                  RSHIM_REG_SIZE_8B);

  return 0;
}

int rshim_log_write(rshim_backend_t *bd, int module, int level,
                    const char *msg)
{
  const int mod_count = (int)(sizeof(rshim_log_mod) / sizeof(rshim_log_mod[0]));
  const int lvl_count =
      (int)(sizeof(rshim_log_levels) / sizeof(rshim_log_levels[0]));
  const int word_sz = (int)sizeof(uint64_t);
  uint64_t data, idx, hdr;
  time_t t0, t1;
  int rc, len, num, i;

  if (!bd || !msg || !*msg)
    return -EINVAL;
  if (module < 0 || module >= mod_count)
    module = 0;
  if (level < 0 || level >= lvl_count)
    level = 0;

  len = (int)strlen(msg);
  num = (len + word_sz - 1) / word_sz;

  /*
   * Acquire semaphore0 using the same poll-and-timeout protocol as
   * rshim_log_show() / rshim_log_drain().  Reading 0 from semaphore0
   * implicitly takes ownership; we bail after 3 seconds to keep a
   * wedged DPU from blocking the caller.
   */
  time(&t0);
  while (true) {
    data = 0x1;
    rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->semaphore0, &data,
                        RSHIM_REG_SIZE_8B);
    if (rc || RSHIM_BAD_CTRL_REG(data)) {
      RSHIM_ERR("rshim%d failed to read RSH_SEMAPHORE0(%d)\n", bd->index, rc);
      return -EIO;
    }
    if (!data)
      break;

    time(&t1);
    if (difftime(t1, t0) > 3)
      return -EBUSY;
  }

  /* Read the current write index. */
  rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->scratch_buf_ctl, &idx,
                      RSHIM_REG_SIZE_8B);
  if (rc) {
    RSHIM_ERR("rshim%d failed to read RSH_SCRATCH_BUF_CTL(%d)\n",
              bd->index, rc);
    rc = -EIO;
    goto done;
  }
  idx = (idx >> RSH_SCRATCH_BUF_CTL__IDX_SHIFT) & RSH_SCRATCH_BUF_CTL__IDX_MASK;

  /*
   * Truncate the payload if the ring can't hold header + num words.
   * The IDX field is 7 bits (RSH_SCRATCH_BUF_CTL__IDX_MASK = 0x7f), so
   * the absolute maximum is 128 words shared between header and body.
   * Match the legacy mlx-bootctl behaviour: keep the framing intact and
   * write a shorter message rather than refusing.
   */
  if ((int)idx + num + 1 > (int)RSH_SCRATCH_BUF_CTL__IDX_MASK)
    num = (int)RSH_SCRATCH_BUF_CTL__IDX_MASK - (int)idx - 1;
  if (num <= 0) {
    rc = -ENOSPC;
    goto done;
  }

  /*
   * Header layout (matches what rshim_log_show_msg() decodes):
   *   [63:60] module   [59:56] type   [55:48] len (8-byte words)
   *   [47:16] arg      [15:8]  has_arg [7:0]  level
   * Wire format is little-endian (reader does le64toh()).
   */
  hdr = ((uint64_t)(module & BF_RSH_LOG_MOD_MASK)  << BF_RSH_LOG_MOD_SHIFT)   |
        ((uint64_t)BF_RSH_LOG_TYPE_MSG             << BF_RSH_LOG_TYPE_SHIFT)  |
        (((uint64_t)num & BF_RSH_LOG_LEN_MASK)     << BF_RSH_LOG_LEN_SHIFT)   |
        ((uint64_t)(level & BF_RSH_LOG_LEVEL_MASK) << BF_RSH_LOG_LEVEL_SHIFT);
  hdr = htole64(hdr);
  rc = bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->scratch_buf_dat, hdr,
                       RSHIM_REG_SIZE_8B);
  if (rc) {
    RSHIM_ERR("rshim%d failed to write log header(%d)\n", bd->index, rc);
    rc = -EIO;
    goto done;
  }

  /*
   * Pack the message body 8 bytes at a time, NUL-padding the tail of
   * the last word.  The reader (rshim_log_show_msg) allocates
   * num*8 + 1 bytes and memcpys these words straight in, then NUL
   * terminates -- so any trailing zeros here become string terminator.
   */
  for (i = 0; i < num; i++) {
    data = 0;
    if (len <= word_sz) {
      memcpy(&data, msg, len);
      len = 0;
    } else {
      memcpy(&data, msg, word_sz);
      msg += word_sz;
      len -= word_sz;
    }
    rc = bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->scratch_buf_dat, data,
                         RSHIM_REG_SIZE_8B);
    if (rc) {
      RSHIM_ERR("rshim%d failed to write log payload(%d)\n", bd->index, rc);
      rc = -EIO;
      goto done;
    }
  }

  rc = 0;

done:
  /* Release the semaphore. */
  bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->semaphore0, 0,
                  RSHIM_REG_SIZE_8B);
  return rc;
}

/* --------------------------------------------------------------------------
 * DPU log shadow ring -- background drainer + cumulative reader view.
 *
 * The hw scratch ring's IDX field is 7 bits wide, so the live ring tops
 * out at 128 8-byte words (1 KiB).  Once it saturates the DPU silently
 * drops further entries (the "Updating DPU Gol" cliff).  CLEAR_ON_READ=1
 * keeps it drained but is destructive: every reader competes with every
 * other for the same bytes, which breaks bfb-install's exit-pattern
 * polling whenever the user is also tailing the misc node.
 *
 * The shadow ring decouples those two roles:
 *
 *   producer  : rshim_log_shadow_tick(), invoked from the worker every
 *               RSHIM_LOG_SHADOW_DRAIN_MS ms.  Pulls everything from the
 *               hw ring into the shadow with force_clear=true.
 *   consumer  : rshim_log_shadow_render(), called from
 *               rshim_fuse_misc_read() at DISPLAY_LEVEL 2.  Non-
 *               destructive by default; honours CLEAR_ON_READ when set.
 *
 * Both run under bd->mutex.  No additional locking required.
 * -------------------------------------------------------------------------- */

/* Polling cadence for the shadow drainer.  500 ms is well under the DPU's
 * 128-word saturation interval at typical install burst rates (~6 msgs/s
 * peak ≈ 36 words/s) while costing one register read + one semaphore
 * round-trip per tick. */
#define RSHIM_LOG_SHADOW_DRAIN_MS 500

/* Round @v up to the next power of two.  Returns 0 if v == 0. */
static size_t rshim_log_shadow_round_pow2(size_t v)
{
  size_t r = 1;

  if (!v)
    return 0;
  while (r < v)
    r <<= 1;
  return r;
}

int rshim_log_shadow_init(rshim_backend_t *bd, size_t cap)
{
  struct rshim_log_shadow *s;

  if (!bd || bd->log_shadow)
    return -EINVAL;
  if (!cap)
    return 0;   /* explicit "disabled" -- caller checked rshim_log_shadow_size */

  cap = rshim_log_shadow_round_pow2(cap);

  s = calloc(1, sizeof(*s));
  if (!s)
    return -ENOMEM;

  s->buf = calloc(1, cap);
  if (!s->buf) {
    free(s);
    return -ENOMEM;
  }
  s->cap = cap;
  s->head = 0;
  s->tail = 0;
  s->dropped_bytes = 0;
  s->next_drain_tick = 0;  /* drain on the first tick we see */

  bd->log_shadow = s;
  return 0;
}

void rshim_log_shadow_free(rshim_backend_t *bd)
{
  if (!bd || !bd->log_shadow)
    return;

  free(bd->log_shadow->buf);
  free(bd->log_shadow);
  bd->log_shadow = NULL;
}

void rshim_log_shadow_reset(rshim_backend_t *bd)
{
  struct rshim_log_shadow *s;

  if (!bd || !bd->log_shadow)
    return;

  s = bd->log_shadow;
  s->head = 0;
  s->tail = 0;
  s->dropped_bytes = 0;
  /* Leave next_drain_tick alone: cadence is a property of the drainer,
   * not the buffer.  Zeroing it would force an extra drain on the next
   * tick, which is harmless but unnecessary. */
}

/*
 * Append @n bytes from @src into the shadow ring.  When the incoming
 * data would overflow the ring we drop the *oldest* bytes (advance
 * tail) so the most recent state-of-the-world is always retained --
 * that's what an install monitor cares about.  We also track total
 * dropped bytes for the misc summary.
 */
static void rshim_log_shadow_append(rshim_backend_t *bd,
                                    const char *src, size_t n)
{
  struct rshim_log_shadow *s;
  size_t used, drop, off, first;

  if (!bd || !bd->log_shadow || !bd->log_shadow->buf || !n)
    return;

  s = bd->log_shadow;

  /* If a single chunk is larger than the entire ring, retain only the
   * trailing cap-1 bytes (leave one byte gap so head != tail meaning
   * "full" is unambiguous). */
  if (n >= s->cap) {
    s->dropped_bytes += n - (s->cap - 1);
    src += n - (s->cap - 1);
    n = s->cap - 1;
    s->head = s->tail = 0;
  }

  used = s->head - s->tail;
  if (used + n > s->cap - 1) {
    drop = used + n - (s->cap - 1);
    s->tail += drop;
    s->dropped_bytes += drop;
  }

  off = s->head & (s->cap - 1);
  first = (off + n <= s->cap) ? n : s->cap - off;
  memcpy(s->buf + off, src, first);
  if (first < n)
    memcpy(s->buf, src + first, n - first);
  s->head += n;
}

int rshim_log_shadow_flush(rshim_backend_t *bd)
{
  char tmp[1280];   /* upper bound: 128-word ring fully populated with msg text */
  int n;

  if (!bd || !bd->log_shadow || !bd->log_shadow->buf || !bd->has_rshim ||
      bd->drop_mode || bd->in_access_check ||
      bd->is_boot_open || bd->is_booting)
    return 0;

  /* Always force-clear the hw ring so the DPU never sees a near-full
   * scratch_buf_ctl IDX.  Any subsequent direct readers of the live
   * ring (display_level != 2 paths with rshim_log_drain in misc_read)
   * are independent of this drainer and don't care that we cleared. */
  n = rshim_log_drain_to_buf(bd, tmp, sizeof(tmp), true);
  if (n > 0)
    rshim_log_shadow_append(bd, tmp, (size_t)n);

  return n > 0 ? n : 0;
}

int rshim_log_shadow_msg(rshim_backend_t *bd, int module, int level,
                         const char *msg)
{
  const int mod_count = (int)(sizeof(rshim_log_mod) / sizeof(rshim_log_mod[0]));
  const int lvl_count =
      (int)(sizeof(rshim_log_levels) / sizeof(rshim_log_levels[0]));
  char line[1024];
  int n;

  if (!bd || !bd->log_shadow || !bd->log_shadow->buf || !msg || !*msg)
    return -EINVAL;
  if (module < 0 || module >= mod_count)
    module = 0;
  if (level < 0 || level >= lvl_count)
    level = 0;

  /* Match the wire format produced by rshim_log_show_msg() so a misc
   * read can't tell host-injected entries from DPU-emitted ones.  The
   * 1024 KiB scratch is more than enough; LOG_MSG line lengths in
   * practice are well under 200 bytes. */
  n = snprintf(line, sizeof(line), " %s[%s]: %s\n",
               rshim_log_levels[level], rshim_log_mod[module], msg);
  if (n <= 0)
    return -EINVAL;
  if (n >= (int)sizeof(line))
    n = (int)sizeof(line) - 1;   /* truncate, keep newline implicit */

  rshim_log_shadow_append(bd, line, (size_t)n);
  return 0;
}

void rshim_log_shadow_tick(rshim_backend_t *bd, int now_ticks)
{
  if (!bd || !bd->log_shadow)
    return;

  /* Rate-limit polling.  Tick counter is in milliseconds; signed
   * subtraction handles wrap-around. */
  if ((bd->log_shadow->next_drain_tick - now_ticks) > 0)
    return;
  bd->log_shadow->next_drain_tick = now_ticks + RSHIM_LOG_SHADOW_DRAIN_MS;

  (void)rshim_log_shadow_flush(bd);
}

int rshim_log_shadow_render(rshim_backend_t *bd, char *out, int max)
{
  struct rshim_log_shadow *s;
  char *p = out;
  size_t used, off, first;
  int n, room;

  if (!bd || !bd->log_shadow || !bd->log_shadow->buf || !out || max <= 0)
    return 0;

  s = bd->log_shadow;
  room = max;

  /* Banner -- identical to rshim_log_show() so misc output format is
   * unchanged.  Bounds-check each snprintf so a tight caller buffer
   * can't push the cursor past the end. */
  n = snprintf(p, room, "---------------------------------------\n");
  if (n < 0 || n >= room)
    return p - out;
  p += n;
  room -= n;

  n = snprintf(p, room, "             Log Messages\n");
  if (n < 0 || n >= room)
    return p - out;
  p += n;
  room -= n;

  n = snprintf(p, room, "---------------------------------------\n");
  if (n < 0 || n >= room)
    return p - out;
  p += n;
  room -= n;

  used = s->head - s->tail;
  if (used > (size_t)room)
    used = (size_t)room;   /* truncate to fit caller's buffer */

  if (used) {
    off = s->tail & (s->cap - 1);
    first = (off + used <= s->cap) ? used : s->cap - off;
    memcpy(p, s->buf + off, first);
    if (first < used)
      memcpy(p + first, s->buf, used - first);
    p += used;
  }

  /* Destructive read when clear_on_read=1: consume what we just
   * rendered.  Other readers will see only newer content from here on. */
  if (bd->clear_on_read)
    s->tail += used;

  return p - out;
}
