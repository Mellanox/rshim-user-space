// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright (C) 2019-2023 Mellanox Technologies. All Rights Reserved.
 *
 */

#include <arpa/inet.h>
#include <getopt.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/time.h>
#include <unistd.h>

#include "rshim.h"

#define PID_FILE "/var/run/rshim.pid"

/* Maximum number of devices supported (currently it's limited to 64). */
#define RSHIM_MAX_DEV 64

/* RShim timer interval in milliseconds. */
#define RSHIM_TIMER_INTERVAL 1

/* Intervals to check the locked mode. */
#define RSHIM_CHECK_LOCKED_MODE_MS      100
#define RSHIM_CHECK_LOCKED_MODE_TICKS   (RSHIM_CHECK_LOCKED_MODE_MS / RSHIM_TIMER_INTERVAL)

/* Ownership protocol timeouts in ms */
#define RSHIM_OSP_TO_REQ_MS 1000
#define RSHIM_OSP_TO_ONLINE_MS 1000

/* Cycles to poll the network initialization before timeout. */
#define RSHIM_NET_INIT_DELAY (60000 / RSHIM_TIMER_INTERVAL)

/* Console polling minimum interval in ms */
#define RSHIM_CONSOLE_POLL_MS 100
#define RSHIM_CONSOLE_POLL_TICKS (RSHIM_CONSOLE_POLL_MS / RSHIM_TIMER_INTERVAL)

/* Reserve some space to indicate full. */
#define RSHIM_FIFO_SPACE_RESERV  3

/* Keepalive period in milliseconds. */
#define RSHIM_KEEPALIVE_PERIOD 300
static int rshim_keepalive_ticks = RSHIM_KEEPALIVE_PERIOD / RSHIM_TIMER_INTERVAL;

/* Keepalive magic number. */
#define RSHIM_KEEPALIVE_MAGIC_NUM 0x5089836482ULL

/* Rshim ownership management. */
#define RSHIM_OSP_MGT_INTERVAL_MS        100 /* Ownership handler running interval */
#define RSHIM_OSP_MGT_INTERVAL_TICKS     (RSHIM_OSP_MGT_INTERVAL_MS / RSHIM_TIMER_INTERVAL)
#define RSHIM_OSP_REQ_MAGIC_NUM 0x4F53505F524551ULL /* OSP_REQ */
#define RSHIM_OSP_ACK_MAGIC_NUM 0x4F53505F41434BULL /* OSP_ACK */

const char *magic_to_str(uint64_t magic)
{
  switch(magic){
  case RSHIM_KEEPALIVE_MAGIC_NUM:
    return "MAGIC_KEEPALIVE";
  case RSHIM_OSP_REQ_MAGIC_NUM:
    return "MAGIC_OSP_REQ";
  case RSHIM_OSP_ACK_MAGIC_NUM:
    return "MAGIC_OSP_ACK";
  default:
    return "UNKNOWN";
  }
}

/* Circular buffer macros. */
#define CIRC_SPACE(head, tail, size) CIRC_CNT((tail), ((head)+1), (size))
#define CIRC_SPACE_TO_END(head, tail, size) \
  ({int end = (size) - 1 - (head); \
    int n = (end + (tail)) & ((size)-1); \
    n <= end ? n : end+1; })
#define CIRC_CNT(head, tail, size) (((head) - (tail)) & ((size)-1))
#define CIRC_CNT_TO_END(head, tail, size) \
  ({int end = (size) - (tail); \
    int n = ((head) + end) & ((size)-1); \
    n < end ? n : end; })

#define read_empty(bd, chan) \
  (CIRC_CNT((bd)->read_fifo[chan].head, \
    (bd)->read_fifo[chan].tail, READ_FIFO_SIZE) == 0)
#define read_full(bd, chan) \
  (CIRC_SPACE((bd)->read_fifo[chan].head, \
    (bd)->read_fifo[chan].tail, READ_FIFO_SIZE) == 0)
#define read_space(bd, chan) \
  CIRC_SPACE((bd)->read_fifo[chan].head, \
    (bd)->read_fifo[chan].tail, READ_FIFO_SIZE)
#define read_cnt(bd, chan) \
  CIRC_CNT((bd)->read_fifo[chan].head, \
    (bd)->read_fifo[chan].tail, READ_FIFO_SIZE)
#define read_cnt_to_end(bd, chan) \
  CIRC_CNT_TO_END((bd)->read_fifo[chan].head, \
    (bd)->read_fifo[chan].tail, READ_FIFO_SIZE)
#define read_data_ptr(bd, chan) \
  ((bd)->read_fifo[chan].data + \
    ((bd)->read_fifo[chan].tail & (READ_FIFO_SIZE - 1)))
#define read_consume_bytes(bd, chan, nbytes) \
  ((bd)->read_fifo[chan].tail = \
    ((bd)->read_fifo[chan].tail + (nbytes)) & (READ_FIFO_SIZE - 1))
#define read_space_to_end(bd, chan) \
  CIRC_SPACE_TO_END((bd)->read_fifo[chan].head, \
    (bd)->read_fifo[chan].tail, READ_FIFO_SIZE)
#define read_space_offset(bd, chan) \
  ((bd)->read_fifo[chan].head & (READ_FIFO_SIZE - 1))
#define read_space_ptr(bd, chan) \
  ((bd)->read_fifo[chan].data + read_space_offset(bd, (chan)))
#define read_add_bytes(bd, chan, nbytes) \
  ((bd)->read_fifo[chan].head = \
    ((bd)->read_fifo[chan].head + (nbytes)) & (READ_FIFO_SIZE - 1))
#define read_reset(bd, chan) \
  ((bd)->read_fifo[chan].head = (bd)->read_fifo[chan].tail = 0)

#define write_empty(bd, chan) \
  (CIRC_CNT((bd)->write_fifo[chan].head, \
    (bd)->write_fifo[chan].tail, WRITE_FIFO_SIZE) == 0)
#define write_full(bd, chan) \
  (CIRC_SPACE((bd)->write_fifo[chan].head, \
    (bd)->write_fifo[chan].tail, WRITE_FIFO_SIZE) == 0)
#define write_space(bd, chan) \
  CIRC_SPACE((bd)->write_fifo[chan].head, \
    (bd)->write_fifo[chan].tail, WRITE_FIFO_SIZE)
#define write_cnt(bd, chan) \
  CIRC_CNT((bd)->write_fifo[chan].head, \
    (bd)->write_fifo[chan].tail, WRITE_FIFO_SIZE)
#define write_cnt_to_end(bd, chan) \
  CIRC_CNT_TO_END((bd)->write_fifo[chan].head, \
    (bd)->write_fifo[chan].tail, WRITE_FIFO_SIZE)
#define write_data_offset(bd, chan) \
  ((bd)->write_fifo[chan].tail & (WRITE_FIFO_SIZE - 1))
#define write_data_ptr(bd, chan) \
  ((bd)->write_fifo[chan].data + write_data_offset(bd, (chan)))
#define write_consume_bytes(bd, chan, nbytes) \
  ((bd)->write_fifo[chan].tail = \
    ((bd)->write_fifo[chan].tail + (nbytes)) & (WRITE_FIFO_SIZE - 1))
#define write_space_to_end(bd, chan) \
  CIRC_SPACE_TO_END((bd)->write_fifo[chan].head, \
    (bd)->write_fifo[chan].tail, WRITE_FIFO_SIZE)
#define write_space_ptr(bd, chan) \
  ((bd)->write_fifo[chan].data + \
    ((bd)->write_fifo[chan].head & (WRITE_FIFO_SIZE - 1)))
#define write_add_bytes(bd, chan, nbytes) \
  ((bd)->write_fifo[chan].head = \
    ((bd)->write_fifo[chan].head + (nbytes)) & (WRITE_FIFO_SIZE - 1))
#define write_reset(bd, chan) \
  ((bd)->write_fifo[chan].head = (bd)->write_fifo[chan].tail = 0)

/*
 * Tile-to-host bits (UART 0 scratchpad).
 */
/*
 * Output write pointer mask.  Note that this is the maximum size; the
 * write pointer may be smaller if requested by the host.
 */
#define CONS_RSHIM_T2H_OUT_WPTR_MASK     0x3FF

/* Tile is done mask. */
#define CONS_RSHIM_T2H_DONE_MASK         0x400

/*
 * Input read pointer mask.  Note that this is the maximum size; the read
 * pointer may be smaller if requested by the host.
 */
#define CONS_RSHIM_T2H_IN_RPTR_MASK      0x1FF800

/* Input read pointer shift. */
#define CONS_RSHIM_T2H_IN_RPTR_SHIFT     11

/* Tile is done mask. */
#define CONS_RSHIM_T2H_DONE_MASK         0x400

/* Number of words to send as sync-data (calculated by packet MTU). */
#define TMFIFO_MAX_SYNC_WORDS            (1536 / 8)

/* Terminal characteristics for newly created consoles. */
#define INIT_C_CC "\003\034\177\025\004\0\1\0\021\023\032\0\022\017\027\026\0"
static struct termios init_console_termios = {
  .c_iflag = INLCR | ICRNL,
  .c_oflag = OPOST | ONLCR,
  .c_cflag = B115200 | HUPCL | CLOCAL | CREAD | CS8,
  .c_lflag = ISIG | ICANON | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
  .c_cc = INIT_C_CC,
};

/* RShim global mutex. */
static pthread_mutex_t rshim_mutex = PTHREAD_MUTEX_INITIALIZER;

/* RShim mutex for global fd read/write. */
static pthread_mutex_t rshim_fd_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Current timer ticks. */
static int rshim_timer_ticks;

/* File handler for the worker function. */
static int rshim_work_fd[2];

/* Current RShim backend name. */
static char *rshim_backend_name;

/* Global epoll handler. */
int rshim_epoll_fd;

/* Static rshim index (/dev/rshim<index>) and device name. */
int rshim_static_index = -1;
char *rshim_static_dev_name;

/* Default configuration file. */
const char *rshim_cfg_file = DEFAULT_RSHIM_CONFIG_FILE;
static int rshim_display_level;
static int rshim_boot_timeout = 300;
int rshim_drop_mode = -1;
int rshim_usb_reset_delay = 1;
bool rshim_has_usb_reset_delay;
int rshim_pcie_reset_delay = 5;
bool rshim_has_pcie_reset_delay;
int rshim_pcie_enable_vfio = 1;
int rshim_pcie_enable_uio = 1;
int rshim_pcie_intr_poll_interval = 10;  /* Interrupt polling in milliseconds */
bool rshim_force_mode;                   /* Keep /dev/rshim<N> & send a force cmd */
bool rshim_cmdmode;                      /* Command mode */

/* Array of devices and device names. */
rshim_backend_t *rshim_devs[RSHIM_MAX_DEV];
char *rshim_dev_names[RSHIM_MAX_DEV];
char *rshim_blocked_dev_names[RSHIM_MAX_DEV];

/* Whether to send a force command to the rshim device. */
bool rshim_force_cmd_pending[RSHIM_MAX_DEV];

/* Bitmask of the used rshim device id. */
#if RSHIM_MAX_DEV > 64
#error Need to fix the size of rshim_dev_bitmask.
#endif
uint64_t rshim_dev_bitmask;

bool rshim_no_net;
int rshim_log_level = LOG_NOTICE;
bool rshim_daemon_mode = true;
volatile bool rshim_run = true;

/* rshim stop semaphore. */
sem_t rshim_stop_sem;

static uint32_t rshim_timer_interval = RSHIM_TIMER_INTERVAL;

static void rshim_fifo_msg_update_checksum(rshim_tmfifo_msg_hdr_t *hdr);

static int rshim_update_locked_mode(rshim_backend_t *bd);

static int rshim_handle_ownership_transfer(rshim_backend_t *bd);

/* Global lock / unlock. */
void rshim_lock(void)
{
  pthread_mutex_lock(&rshim_mutex);
}

int rshim_trylock(void)
{
  return pthread_mutex_trylock(&rshim_mutex);
}

void rshim_unlock(void)
{
  pthread_mutex_unlock(&rshim_mutex);
}

static int rshim_fd_full_read(int fd, void *data, int len)
{
  char *buf = (char *)data;
  int cc, total = 0;

  pthread_mutex_lock(&rshim_fd_mutex);

  while (len > 0) {
    cc = read(fd, buf, len);
    if (cc < 0) {
      if (errno == EINTR || errno == EAGAIN) {
        usleep(1000);
        continue;
      }
      pthread_mutex_unlock(&rshim_fd_mutex);
      return -1;
    }

    if (cc == 0)
      break;

    buf += cc;
    total += cc;
    len -= cc;
  }

  pthread_mutex_unlock(&rshim_fd_mutex);
  return total;
}

static int rshim_fd_full_write(int fd, void *data, int len)
{
  char *buf = (char *)data;
  int total = 0;

  pthread_mutex_lock(&rshim_fd_mutex);

  while (len > 0) {
    ssize_t written = write(fd, buf, len);

    if (written < 0) {
      if (errno == EINTR || errno == EAGAIN) {
        usleep(1000);
        continue;
      }
      RSHIM_ERR("fd write error %d\n", (int)written);
      pthread_mutex_unlock(&rshim_fd_mutex);
      return written;
    }
    total += written;
    buf += written;
    len -= written;
  }

  pthread_mutex_unlock(&rshim_fd_mutex);
  return total;
}

/* Wake up the epoll loop or worker function. */
void rshim_work_signal(rshim_backend_t *bd)
{
  uint8_t index = (uint8_t)-1;
  bool update = true;

  if (bd) {
    if (__sync_bool_compare_and_swap(&bd->work_pending, false, true))
      index = (uint8_t)bd->index;
    else
      update = false;
  }

  if (update)
    rshim_fd_full_write(rshim_work_fd[1], &index, sizeof(index));
}

/*
 * Read some bytes from RShim.
 *
 * The provided buffer size should be multiple of 8 bytes. If not, the
 * leftover bytes (which presumably were sent as NUL bytes by the sender)
 * will be discarded.
 */
static ssize_t rshim_read_default(rshim_backend_t *bd, int devtype,
                                  char *buf, size_t count)
{
  int rc, total = 0, avail = 0;
  uint64_t reg;

  /* Read is only supported for RShim TMFIFO. */
  if (devtype != RSH_DEV_TYPE_TMFIFO) {
    RSHIM_ERR("rshim%d bad devtype %d\n", bd->index, devtype);
    return -EINVAL;
  }

  while (total < count) {
    if (avail == 0) {
      reg = 0;
      rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->tm_tth_sts, &reg,
                          RSHIM_REG_SIZE_8B);
      if (rc < 0 || RSHIM_BAD_CTRL_REG(reg))
        break;
      avail = reg & RSH_TM_TILE_TO_HOST_STS__COUNT_MASK;
      if (avail == 0)
        break;
    }
    rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->tm_tth_data, &reg,
                        RSHIM_REG_SIZE_8B);
    if (rc < 0)
      break;

    /*
     * Convert it to little endian before sending to RShim. The other side
     * should decode it as little endian as well which is usually the default
     * case.
     */
    reg = le64toh(reg);
    if (total + sizeof(reg) <= count) {
      *(uint64_t *)buf = reg;
      buf += sizeof(reg);
      total += sizeof(reg);
    } else {
      /* Copy the rest data which is less than 8 bytes. */
      memcpy(buf, &reg, count - total);
      total = count;
      break;
    }
    avail--;
  }

  return total;
}

/*
 * Write some bytes to the RShim backend.
 *
 * If count is not multiple of 8-bytes, the data will be padded to 8-byte
 * aligned which is required by RShim HW.
 */
static ssize_t rshim_write_delayed(rshim_backend_t *bd, int devtype,
                                   const uint8_t *buf, size_t count)
{
  int size_addr, size_mask, data_addr, max_size;
  uint8_t pad_buf[sizeof(uint64_t)] = { 0 };
  int rc, avail = 0, byte_cnt = 0;
  time_t t0, t1;
  uint64_t reg;

  switch (devtype) {
  case RSH_DEV_TYPE_TMFIFO:
    if (bd->is_boot_open || bd->drop_mode)
      return count;
    size_addr = bd->regs->tm_htt_sts;
    size_mask = RSH_TM_HOST_TO_TILE_STS__COUNT_MASK;
    data_addr = bd->regs->tm_htt_data;
    max_size = RSH_TM_FIFO_SIZE;
    break;

  case RSH_DEV_TYPE_BOOT:
    size_addr = bd->regs->boot_fifo_count;
    size_mask = bd->regs->boot_fifo_count_mask;
    data_addr = bd->regs->boot_fifo_data;
    max_size = RSH_BOOT_FIFO_SIZE;
    break;

  default:
    RSHIM_ERR("rshim%d bad devtype %d\n", bd->index, devtype);
    return -EINVAL;
  }

  while (byte_cnt < count) {
    /* Check the boot cancel condition. */
    if (devtype == RSH_DEV_TYPE_BOOT && !bd->boot_work_buf)
      break;

    /* Add padding if less than 8 bytes left. */
    if (byte_cnt + sizeof(uint64_t) > count) {
      memcpy(pad_buf, buf, count - byte_cnt);
      buf = (const uint8_t *)pad_buf;
    }

    time(&t0);
    while (avail <= 0) {
      /* Calculate available space in words. */
      rc = bd->read_rshim(bd, RSHIM_CHANNEL, size_addr, &reg,
                          RSHIM_REG_SIZE_8B);
      if (rc < 0 || RSHIM_BAD_CTRL_REG(reg)) {
        RSHIM_ERR("rshim%d read_rshim error addr=0x%x, reg=0x%lx, rc=%d\n",
                  bd->index, size_addr, (long unsigned int)reg, rc);
        usleep(10000);
        return count;
      }
      avail = max_size - (int)(reg & size_mask) - RSHIM_FIFO_SPACE_RESERV;
      if (avail > 0)
        break;

      if (devtype == RSH_DEV_TYPE_BOOT)
        goto done;

      time(&t1);
      if (difftime(t1, t0) > 3) {
        if (devtype == RSH_DEV_TYPE_TMFIFO && bd->is_booting)
          return count;
        else
          return -ETIMEDOUT;
      }
    }

    reg = *(uint64_t *)buf;
    /*
     * Convert to little endian before sending to RShim. The
     * receiving side should call le64toh() to convert it back.
     */
    reg = htole64(reg);
    rc = bd->write_rshim(bd, RSHIM_CHANNEL, data_addr, reg, RSHIM_REG_SIZE_8B);
    if (rc < 0) {
      RSHIM_ERR("rshim%d write_rshim error %d\n", bd->index, rc);
      break;
    }
    byte_cnt += sizeof(reg);
    if (buf == pad_buf)
      break;
    buf += sizeof(reg);
    avail--;
  }

  /* Return number shouldn't count the padded bytes. */
done:
  return (byte_cnt > count) ? count : byte_cnt;
}

static ssize_t rshim_write_default(rshim_backend_t *bd, int devtype,
                                   const char *buf, size_t count)
{
  int rc;

  switch (devtype) {
  case RSH_DEV_TYPE_TMFIFO:
    if (bd->is_boot_open)
      return count;

    /* Set the flag so there is only one outstanding request. */
    bd->spin_flags |= RSH_SFLG_WRITING;

    /* Wake up the worker. */
    bd->fifo_work_buf = (uint8_t *)buf;
    bd->fifo_work_buf_len = count;
    bd->fifo_work_devtype = devtype;
    bd->has_fifo_work = 1;
    rshim_work_signal(bd);
    return 0;

  case RSH_DEV_TYPE_BOOT:
    bd->boot_work_buf_len = count;
    bd->boot_work_buf_actual_len = 0;
    bd->boot_work_buf = (uint8_t *)buf;
    rshim_work_signal(bd);

    rc = pthread_cond_wait(&bd->boot_write_complete_cond, &bd->mutex);
    /* Cancel the request if interrupted. */
    if (rc)
      bd->boot_work_buf = NULL;

    return bd->boot_work_buf_actual_len;

  default:
    RSHIM_ERR("rshim%d bad devtype %d\n", bd->index, devtype);
    return -EINVAL;
  }
}

/* Boot file operations routines */

/*
 * Wait for boot to complete, if necessary.  Return 0 if the boot is done
 * and it's safe to continue, an error code if something went wrong.  Note
 * that this routine must be called with the device mutex held.  If it
 * returns successfully, the mutex will still be held (although it may have
 * been dropped and reacquired); if it returns unsuccessfully the mutex
 * will have been dropped.
 */
static int wait_for_boot_done(rshim_backend_t *bd)
{
  struct timespec ts;
  int rc;

  if (!bd->has_reprobe || bd->skip_boot_reset) {
    bd->is_booting = 0;
    return 0;
  }

  clock_gettime(CLOCK_REALTIME, &ts);
  ts.tv_sec += 20;

  if (!bd->has_rshim || bd->is_booting) {
    while (bd->is_booting) {
      RSHIM_INFO("rshim%d boot write, waiting for re-probe\n", bd->index);
      /*
       * FIXME: might we want a timeout here, too?  If the reprobe takes a very
       * long time, something's probably wrong.  Maybe a couple of minutes?
       */
      rc = pthread_cond_timedwait(&bd->boot_complete_cond, &bd->mutex, &ts);
      if (rc) {
        RSHIM_DBG("rshim%d failed to detect re-probe, continues.\n", bd->index);
        bd->is_booting = 0;
        return 0;
      }

      /*
       * On some systems the USB up event comes too early while the system
       * is not fully ready yet. Add a delay here to avoid race codition.
       */
      if (!bd->is_booting && bd->has_reprobe)
        sleep(bd->reset_delay);
    }

    if (!bd->has_rshim)
      return -ENODEV;
  }

  return 0;
}

static int rshim_reg_indirect_wait(rshim_backend_t *bd, uint64_t resp_count)
{
  int rc, retries = 1000;
  uint64_t count;

  while (retries--) {
    rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->mem_acc_rsp_cnt, &count,
                        RSHIM_REG_SIZE_8B);
    if (rc)
      return rc;
    if (count != resp_count)
      return 0;
  }
  RSHIM_DBG("rshim%d byte access widget timeout\n", bd->index);
  return -1;
}

static int rshim_mmio_write_common(rshim_backend_t *bd, uintptr_t pa,
                                    uint8_t size, uint64_t data)
{
  uint64_t reg, resp_count;

  bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->device_mstr_priv_lvl, &reg,
                 RSHIM_REG_SIZE_8B);
  reg |= 0x1ULL << bd->regs->device_mstr_priv_lvl_shift;
  bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->device_mstr_priv_lvl, reg,
                  RSHIM_REG_SIZE_8B);

  bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->mem_acc_rsp_cnt, &resp_count,
                 RSHIM_REG_SIZE_8B);
  bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->mem_acc_data_first_word, data,
                  RSHIM_REG_SIZE_8B);
  reg = (((uint64_t)pa & RSH_MEM_ACC_CTL__ADDRESS_RMASK) <<
           RSH_MEM_ACC_CTL__ADDRESS_SHIFT) |
        (((uint64_t)size & RSH_MEM_ACC_CTL__SIZE_RMASK) <<
          RSH_MEM_ACC_CTL__SIZE_SHIFT) |
        (1ULL << RSH_MEM_ACC_CTL__WRITE_SHIFT) |
        (1ULL << RSH_MEM_ACC_CTL__SEND_SHIFT);
  bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->mem_acc_ctl, reg,
                  RSHIM_REG_SIZE_8B);
  return rshim_reg_indirect_wait(bd, resp_count);
}

static int rshim_mmio_read_common(rshim_backend_t *bd, uintptr_t pa,
                                  uint8_t size, uint64_t *data)
{
  uint64_t reg, resp_count;

  bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->device_mstr_priv_lvl, &reg,
                 RSHIM_REG_SIZE_8B);
  reg |= 0x1ULL << bd->regs->device_mstr_priv_lvl_shift;
  bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->device_mstr_priv_lvl, reg,
                  RSHIM_REG_SIZE_8B);

  bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->mem_acc_rsp_cnt, &resp_count,
                 RSHIM_REG_SIZE_8B);

  reg = (((uint64_t)pa & RSH_MEM_ACC_CTL__ADDRESS_RMASK) <<
           RSH_MEM_ACC_CTL__ADDRESS_SHIFT) |
        (((uint64_t)size & RSH_MEM_ACC_CTL__SIZE_RMASK) <<
          RSH_MEM_ACC_CTL__SIZE_SHIFT) |
        (1ULL << RSH_MEM_ACC_CTL__SEND_SHIFT);
  bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->mem_acc_ctl, reg,
                  RSHIM_REG_SIZE_8B);

  if (rshim_reg_indirect_wait(bd, resp_count))
    return -1;

  bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->mem_acc_data_first_word, &reg,
                 RSHIM_REG_SIZE_8B);
  *data = reg;

  return 0;
}

int rshim_mmio_write32(rshim_backend_t *bd, uintptr_t addr, uint32_t value)
{
  return rshim_mmio_write_common(bd, addr, RSH_MEM_ACC_CTL__SIZE_VAL_SZ4,
                                 value);
}

int rshim_mmio_read32(rshim_backend_t *bd, uintptr_t addr, uint32_t *data)
{
  uint64_t reg;

  if (rshim_mmio_read_common(bd, addr, RSH_MEM_ACC_CTL__SIZE_VAL_SZ4, &reg)) {
    return -1;
  } else {
    *data = (uint32_t)reg;
    return 0;
  }
}

/*
 * Write to the RShim reset control register.
 */
int rshim_reset_control(rshim_backend_t *bd)
{
  uint64_t reg, val;
  uint8_t shift;
  int rc;

  rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->reset_control, &reg,
                      RSHIM_REG_SIZE_8B);
  if (rc < 0 || RSHIM_BAD_CTRL_REG(reg)) {
    RSHIM_ERR("rshim%d failed to read reset control(%d)\n", bd->index, rc);
    return rc;
  }

  val = RSH_RESET_CONTROL__RESET_CHIP_VAL_KEY;
  shift = RSH_RESET_CONTROL__RESET_CHIP_SHIFT;
  reg &= ~((uint64_t) RSH_RESET_CONTROL__RESET_CHIP_MASK);
  reg |= (val << shift);

  /*
   * The reset of the ARM can be blocked when the DISABLED bit
   * is set. The big assumption is that the DISABLED bit would
   * be hold high for a short period and only the platform code
   * can reset that bit. Thus the ARM reset can be delayed and
   * in theory this should not impact the behavior of the RShim
   * driver.
   */
  rc = bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->reset_control, reg,
                       RSHIM_REG_SIZE_8B);
  if (rc < 0) {
    RSHIM_ERR("rshim%d failed to write reset control(%d)\n", bd->index, rc);
    return rc;
  }

  return 0;
}

int rshim_boot_open(rshim_backend_t *bd)
{
  int rc;

  pthread_mutex_lock(&bd->mutex);

  if (bd->drop_mode) {
    RSHIM_INFO("rshim%d boot fail (drop mode)\n", bd->index);
    pthread_mutex_unlock(&bd->mutex);
    return -EINVAL;
  }

  if (bd->locked_mode) {
    RSHIM_ERR("rshim%d boot fail (locked mode)\n", bd->index);
    pthread_mutex_unlock(&bd->mutex);
    return -EPERM;
  }

  if (bd->is_boot_open) {
    RSHIM_INFO("rshim%d boot already open\n", bd->index);
    pthread_mutex_unlock(&bd->mutex);
    return -EBUSY;
  }

  if (!bd->has_rshim) {
    pthread_mutex_unlock(&bd->mutex);
    return -ENODEV;
  }

  RSHIM_INFO("rshim%d boot open\n", bd->index);
  bd->is_booting = 1;
  bd->boot_rem_cnt = 0;

  /*
   * Before we reset the chip, make sure we don't have any
   * outstanding writes, and flush the write and read FIFOs. (Note
   * that we can't have any outstanding reads, since we kill those
   * upon release of the TM FIFO file.)
   */
  if (bd->cancel)
    bd->cancel(bd, RSH_DEV_TYPE_TMFIFO, true);

  /* Reset the TmFifo. */
  rshim_fifo_reset(bd);

  if (!bd->skip_boot_reset) {
    /* Set RShim (external) boot mode. */
    rc = bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->boot_control,
                         RSH_BOOT_CONTROL__BOOT_MODE_VAL_NONE, RSHIM_REG_SIZE_8B);
    if (rc) {
      RSHIM_ERR("rshim%d boot failed to write boot control(%d)\n", bd->index, rc);
      bd->is_booting = 0;
      pthread_mutex_unlock(&bd->mutex);
      return rc;
    }
  }

  bd->is_boot_open = 1;

  /*
   * Disable the watchdog. The channel and offset are the same on all
   * the BlueField SoC so far.
   */
  bd->write_rshim(bd, RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_WDOG1,
                  bd->regs->arm_wdg_control_wcs, 0, RSHIM_REG_SIZE_8B);

  if (bd->skip_boot_reset)
    goto boot_open_done;

  /* SW reset. */
  rc = rshim_reset_control(bd);

  /*
   * Note that occasionally, we get various errors on writing to
   * the reset register.  This appears to be caused by the chip
   * actually resetting before the response goes out, or perhaps by
   * our noticing the device unplug before we've seen the response.
   * Either way, the chip _does_ actually reset, so we just ignore
   * the error.  Should we ever start getting these errors without
   * the chip being reset, we'll have to figure out how to handle
   * this more intelligently.  (One potential option is to not reset
   * directly, but to set up a down counter to do the reset, but that
   * seems kind of kludgy, especially since Tile software might also
   * be trying to use the down counter.)
   */
  if (rc && rc != -EPROTO && rc != -ESHUTDOWN &&
    rc != -ETIMEDOUT && rc != -EPIPE) {
    RSHIM_ERR("rshim%d boot failed to write reset control(%d)\n", bd->index, rc);
    bd->is_boot_open = 0;
    pthread_mutex_unlock(&bd->mutex);
    return rc;
  }

  if (rc)
    RSHIM_ERR("rshim%d boot reset error (%d)\n", bd->index, rc);

boot_open_done:
  rshim_ref(bd);

  /* Add a small delay for the reset (livefish needs more delay). */
  if (!bd->has_reprobe)
    usleep((bd->type == RSH_BACKEND_PCIE_LF) ? 1000000 : 500000);
  pthread_mutex_unlock(&bd->mutex);

  if (!bd->has_reprobe)
    sleep(bd->reset_delay);
  time(&bd->boot_write_time);

  return 0;
}

int rshim_boot_write(rshim_backend_t *bd, const char *user_buffer, size_t count,
                     int (*copy_in)(void *dest, const void *src, int count))
{
  int rc = 0, whichbuf = 0, len;
  time_t tm;
  size_t bytes_written = 0;

  pthread_mutex_lock(&bd->mutex);
  if (bd->is_in_boot_write) {
    pthread_mutex_unlock(&bd->mutex);
    return -EBUSY;
  }

  rc = wait_for_boot_done(bd);
  if (rc) {
    RSHIM_ERR("rshim%d boot write fail (boot not done %d)\n", bd->index, rc);
    pthread_mutex_unlock(&bd->mutex);
    return rc;
  }

  /*
   * We're going to drop the mutex while we wait for any outstanding
   * write to complete; this keeps another thread from getting in here
   * while we do that.
   */
  bd->is_in_boot_write = 1;

  while (count + bd->boot_rem_cnt >= sizeof(uint64_t)) {
    size_t buf_bytes = MIN(BOOT_BUF_SIZE,
                           (count + bd->boot_rem_cnt) & (-((size_t)8)));
    char *buf = bd->boot_buf[whichbuf];

    whichbuf ^= 1;

    /* Copy the previous remaining data first. */
    if (bd->boot_rem_cnt)
      memcpy(buf, &bd->boot_rem_data, bd->boot_rem_cnt);

    rc = copy_in(buf + bd->boot_rem_cnt, user_buffer,
                 buf_bytes - bd->boot_rem_cnt);
    if (rc < 0)
      break;

    rc = bd->write(bd, RSH_DEV_TYPE_BOOT, buf, buf_bytes);
    if (rc > bd->boot_rem_cnt) {
      len = rc - bd->boot_rem_cnt;
      count -= len;
      user_buffer += len;
      bytes_written += len;
      bd->boot_rem_cnt = 0;
    } else if (rc == 0) {
      time(&tm);
      if (difftime(tm, bd->boot_write_time) > bd->boot_timeout) {
        rc = -ETIMEDOUT;
        RSHIM_INFO("rshim%d boot timeout\n", bd->index);
      } else {
        rc = -EINTR;
      }
      break;
    }

    time(&bd->boot_write_time);

    if (rc != buf_bytes)
      break;
  }

  /* Buffer the remaining data. */
  if (count + bd->boot_rem_cnt < sizeof(bd->boot_rem_data)) {
    rc = copy_in((uint8_t *)&bd->boot_rem_data + bd->boot_rem_cnt,
                 user_buffer, count);
    bd->boot_rem_cnt += count;
    bytes_written += count;
  }

  bd->is_in_boot_write = 0;
  pthread_mutex_unlock(&bd->mutex);

  if (bytes_written > 0 || count == 0)
    return bytes_written;
  else
    return rc;
}

void rshim_boot_release(rshim_backend_t *bd)
{
  int rc;

  pthread_mutex_lock(&bd->mutex);

  /* Restore the boot mode register. */
  rc = bd->write_rshim(bd, RSHIM_CHANNEL,
                       bd->regs->boot_control,
                       RSH_BOOT_CONTROL__BOOT_MODE_VAL_EMMC,
                       RSHIM_REG_SIZE_8B);
  if (rc)
    RSHIM_ERR("rshim%d failed to write boot control(%d)\n", bd->index, rc);

  /* Flush the leftover data with zeros padded. */
  if (bd->boot_rem_cnt) {
    memset((uint8_t *)&bd->boot_rem_data + bd->boot_rem_cnt, 0,
           sizeof(uint64_t) - bd->boot_rem_cnt);
    bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->boot_fifo_data,
           bd->boot_rem_data, RSHIM_REG_SIZE_8B);
  }
  bd->is_boot_open = 0;
  bd->boot_rem_cnt = 0;
  rshim_work_signal(bd);
  pthread_mutex_unlock(&bd->mutex);

  RSHIM_INFO("rshim%d boot close\n", bd->index);
  rshim_deref(bd);
}

/* FIFO common routines */

/*
 * Signal an error on the FIFO, and wake up anyone who might need to know
 * about it.
 */
static void rshim_fifo_err(rshim_backend_t *bd, int err)
{
  int i;

  bd->tmfifo_error = err;
  pthread_cond_broadcast(&bd->fifo_write_complete_cond);
  for (i = 0; i < TMFIFO_MAX_CHAN; i++) {
    pthread_cond_broadcast(&bd->read_fifo[i].operable);
    pthread_cond_broadcast(&bd->write_fifo[i].operable);
  }
}

static int rshim_fifo_tx_avail(rshim_backend_t *bd)
{
  int rc, max_size, avail;
  uint64_t word;

  /* Get FIFO max size. */
  max_size = RSH_TM_FIFO_SIZE;

  /* Calculate available size. */
  rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->tm_htt_sts, &word,
                      RSHIM_REG_SIZE_8B);
  if (rc < 0 || RSHIM_BAD_CTRL_REG(word)) {
    RSHIM_ERR("rshim%d failed to read htt sts(%d)\n", bd->index, rc);
    usleep(10000);
    return -1;
  }
  avail = max_size - (int)(word & RSH_TM_HOST_TO_TILE_STS__COUNT_MASK) -
          RSHIM_FIFO_SPACE_RESERV;

  return avail;
}

int rshim_fifo_sync(rshim_backend_t *bd, bool drop_rx)
{
  rshim_tmfifo_msg_hdr_t hdr;
  int i, avail, rc;
  time_t t0, t1;
  uint64_t reg;

  /* Clear pending network Rx/Tx state. */
  bd->net_rx_len = 0;
  bd->net_tx_len = 0;

  /* Sync the Tx FIFO by sending padding zeros. */
  avail = rshim_fifo_tx_avail(bd);
  if (avail < 0)
    return avail;

  hdr.data = 0;
  hdr.type = VIRTIO_ID_NET;
  rshim_fifo_msg_update_checksum(&hdr);

  for (i = 0; i < avail; i++) {
    rc = bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->tm_htt_data,
                         hdr.data, RSHIM_REG_SIZE_8B);
    if (rc)
      return rc;
  }

  /* Drain the Rx FIFO until no more data in one second. */
  if (drop_rx) {
    avail = 0;

    time(&t0);

    do {
      reg = 0;
      rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->tm_tth_sts, &reg,
                          RSHIM_REG_SIZE_8B);
      if (rc < 0 || RSHIM_BAD_CTRL_REG(reg))
        break;

      avail = reg & RSH_TM_TILE_TO_HOST_STS__COUNT_MASK;
      if (avail == 0) {
        time(&t1);
        if (difftime(t1, t0) > 1)
          break;
        continue;
      }

      while (avail > 0) {
        bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->tm_tth_data, &reg,
                       RSHIM_REG_SIZE_8B);
        avail--;
      }

      time(&t0);
    } while (avail == 0);
  }

  return 0;
}

/* Just adds up all the bytes of the header. */
static uint8_t rshim_fifo_ctrl_checksum(rshim_tmfifo_msg_hdr_t *hdr)
{
  uint8_t checksum = 0;
  int i;

  for (i = 0; i < sizeof(*hdr); i++)
    checksum += ((uint8_t *)hdr)[i];

  return checksum;
}

static void rshim_fifo_msg_update_checksum(rshim_tmfifo_msg_hdr_t *hdr)
{
  uint8_t checksum;

  hdr->checksum = 0;
  checksum = rshim_fifo_ctrl_checksum(hdr);
  hdr->checksum = ~checksum + 1;
}

static bool rshim_fifo_msg_verify_checksum(rshim_tmfifo_msg_hdr_t *hdr)
{
  uint8_t checksum = 0;

  /*
   * hdr->checksum is either 0 (old version) or should have a valid checksum.
   */
  if (hdr->checksum)
    checksum = rshim_fifo_ctrl_checksum(hdr);

  return checksum ? false : true;
}

static void rshim_fifo_ctrl_rx(rshim_backend_t *bd, rshim_tmfifo_msg_hdr_t *hdr)
{
  if (!rshim_fifo_msg_verify_checksum(hdr))
    return;

  switch (hdr->type) {
  case TMFIFO_MSG_MAC_1:
    memcpy(bd->peer_mac, hdr->mac, 3);
    break;
  case TMFIFO_MSG_MAC_2:
    memcpy(bd->peer_mac + 3, hdr->mac, 3);
    break;
  case TMFIFO_MSG_VLAN_ID:
    bd->vlan[0] = ntohs(hdr->vlan[0]);
    bd->vlan[1] = ntohs(hdr->vlan[1]);
    break;
  case TMFIFO_MSG_PXE_ID:
    bd->pxe_client_id = ntohl(hdr->pxe_id);
    /* Last info to receive, set the flag. */
    bd->peer_ctrl_resp = 1;
    pthread_cond_broadcast(&bd->ctrl_wait_cond);
    break;
  default:
    return;
  }
}

static int rshim_fifo_ctrl_tx(rshim_backend_t *bd)
{
  rshim_tmfifo_msg_hdr_t hdr;
  int len = 0;

  if (bd->peer_mac_set) {
    bd->peer_mac_set = 0;
    hdr.data = 0;
    hdr.type = TMFIFO_MSG_MAC_1;
    memcpy(hdr.mac, bd->peer_mac, 3);
    rshim_fifo_msg_update_checksum(&hdr);
    memcpy(bd->write_buf, &hdr.data, sizeof(hdr.data));
    hdr.type = TMFIFO_MSG_MAC_2;
    memcpy(hdr.mac, bd->peer_mac + 3, 3);
    rshim_fifo_msg_update_checksum(&hdr);
    memcpy(bd->write_buf + sizeof(hdr.data), &hdr.data, sizeof(hdr.data));
    len = sizeof(hdr.data) * 2;
  } else if (bd->peer_pxe_id_set) {
    bd->peer_pxe_id_set = 0;
    hdr.data = 0;
    hdr.type = TMFIFO_MSG_PXE_ID;
    hdr.pxe_id = htonl(bd->pxe_client_id);
    rshim_fifo_msg_update_checksum(&hdr);
    memcpy(bd->write_buf, &hdr.data, sizeof(hdr.data));
    len = sizeof(hdr.data);
  } else if (bd->peer_vlan_set) {
    bd->peer_vlan_set = 0;
    hdr.data = 0;
    hdr.type = TMFIFO_MSG_VLAN_ID;
    hdr.vlan[0] = htons(bd->vlan[0]);
    hdr.vlan[1] = htons(bd->vlan[1]);
    rshim_fifo_msg_update_checksum(&hdr);
    memcpy(bd->write_buf, &hdr.data, sizeof(hdr.data));
    len = sizeof(hdr.data);
  } else if (bd->peer_ctrl_req) {
    bd->peer_ctrl_req = 0;
    hdr.data = 0;
    hdr.type = TMFIFO_MSG_CTRL_REQ;
    rshim_fifo_msg_update_checksum(&hdr);
    memcpy(bd->write_buf, &hdr.data, sizeof(hdr.data));
    len = sizeof(hdr.data);
  }

  return len;
}

static int rshim_got_peer_signal(void)
{
#ifdef HAVE_RSHIM_FUSE
  return rshim_fuse_got_peer_signal();
#else
  return -1;
#endif
}

static void rshim_input_notify(rshim_backend_t *bd)
{
#ifdef HAVE_RSHIM_FUSE
    rshim_fuse_input_notify(bd);
#endif
}

/* Drain the read buffer, and start another read/interrupt if needed. */
static void rshim_fifo_input(rshim_backend_t *bd)
{
  rshim_tmfifo_msg_hdr_t *hdr;
  uint8_t rx_avail = 0;
  time_t t0, t1;
  int rc;

  if (!bd->has_rshim || !bd->has_tm)
    return;

  time(&t0);

again:
  while (bd->read_buf_next < bd->read_buf_bytes) {
    int copysize;

    /*
     * If we're at the start of a packet, then extract the
     * header, and update our count of bytes remaining in the
     * packet.
     */
    if (bd->read_buf_pkt_rem == 0) {
      /* Make sure header is received. */
      if (bd->read_buf_next + sizeof(*hdr) > bd->read_buf_bytes)
        break;

      RSHIM_DBG("rshim%d read_buf_next %d\n", bd->index, bd->read_buf_next);

      hdr = (rshim_tmfifo_msg_hdr_t *)&bd->read_buf[bd->read_buf_next];

      /* Verify message size. */
      if ((hdr->type == VIRTIO_ID_NET) &&
          (ntohs(hdr->len) + sizeof(*hdr) > sizeof(rshim_net_pkt_t))) {
        bd->read_buf_next += sizeof(*hdr);
        continue;
      }

      bd->read_buf_pkt_rem = ntohs(hdr->len) + sizeof(*hdr);
      bd->read_buf_pkt_padding = (8 - (bd->read_buf_pkt_rem & 7)) & 7;

      if (hdr->type == VIRTIO_ID_NET)
        bd->rx_chan = TMFIFO_NET_CHAN;
      else if (hdr->type == VIRTIO_ID_CONSOLE) {
        bd->rx_chan = TMFIFO_CONS_CHAN;
        /* Strip off the message header for console. */
        bd->read_buf_next += sizeof(*hdr);
        bd->read_buf_pkt_rem -= sizeof(*hdr);
        if (bd->read_buf_pkt_rem == 0)
          continue;
      } else {
        RSHIM_DBG("rshim%d bad type %d, drop it\n", bd->index, hdr->type);
        bd->read_buf_pkt_rem = 0;
        bd->read_buf_pkt_padding = 0;
        if (hdr->len == 0) {
          bd->read_buf_next += sizeof(*hdr);
          rshim_fifo_ctrl_rx(bd, hdr);
          continue;
        } else {
          RSHIM_DBG("rshim%d bad type %d, drop it", bd->index, hdr->type);
          bd->read_buf_next = bd->read_buf_bytes;
          break;
        }
      }

      RSHIM_DBG("rshim%d drain: hdr, nxt %d rem %d chn %d\n", bd->index,
                bd->read_buf_next, bd->read_buf_pkt_rem, bd->rx_chan);
      bd->drop_pkt = 0;
    }

    if (bd->rx_chan == TMFIFO_CONS_CHAN &&
        !(bd->spin_flags & RSH_SFLG_CONS_OPEN)) {
      /*
       * If data is coming in for a closed console channel, we want to just
       * throw it away. Resetting the channel every time through this loop is
       * a relatively cheap way to do that.  Note that this works because the
       * read buffer is no larger than the read FIFO; thus, we know that if
       * we reset it here, we will always be able to drain the read buffer of
       * any console data, and will then launch another read.
       */
      read_reset(bd, TMFIFO_CONS_CHAN);
      bd->drop_pkt = 1;
    } else if (bd->rx_chan == TMFIFO_NET_CHAN && bd->net_notify_fd[0] < 0) {
      /* Drop if networking is not enabled. */
      read_reset(bd, TMFIFO_NET_CHAN);
      bd->drop_pkt = 1;
    }

    copysize = MIN(bd->read_buf_pkt_rem,
                   bd->read_buf_bytes - bd->read_buf_next);
    copysize = MIN(copysize, read_space_to_end(bd, bd->rx_chan));

    RSHIM_DBG("rshim%d drain: copysize %d, head %d, tail %d, remaining %d\n",
              bd->index, copysize,
              bd->read_fifo[bd->rx_chan].head,
              bd->read_fifo[bd->rx_chan].tail,
              bd->read_buf_pkt_rem);

    if (copysize == 0) {
      /* We have data, but no space to put it in, so we're done. */
      RSHIM_DBG("drain: no more space in channel %d\n",
                 bd->rx_chan);
      break;
    }

    if (!bd->drop_pkt) {
      memcpy(read_space_ptr(bd, bd->rx_chan), &bd->read_buf[bd->read_buf_next],
             copysize);
      read_add_bytes(bd, bd->rx_chan, copysize);
    }

    bd->read_buf_next += copysize;
    bd->read_buf_pkt_rem -= copysize;

    rshim_input_notify(bd);
    pthread_cond_broadcast(&bd->read_fifo[bd->rx_chan].operable);

    if (bd->read_buf_pkt_rem <= 0) {
      bd->read_buf_next = bd->read_buf_next + bd->read_buf_pkt_padding;
      rx_avail = 1;
    }
  }

  /*
   * We've processed all of the data we can, so now we decide if we
   * need to launch another I/O.  If there's still data in the read
   * buffer, or if we're already reading, don't launch any new
   * operations.  If an interrupt just completed, and said there was
   * data, or the last time we did a read we got some data, then do
   * another read.  Otherwise, do an interrupt.
   */
  if (bd->read_buf_next < bd->read_buf_bytes ||
      (bd->spin_flags & RSH_SFLG_READING)) {
    /* We're doing nothing. */
    RSHIM_DBG("rshim%d fifo_input: no new read: %s\n", bd->index,
              (bd->read_buf_next < bd->read_buf_bytes) ?
              "have data" : "already reading");
  } else {
    int len;

    /* Process it if more data is received. */
    len = bd->read(bd, RSH_DEV_TYPE_TMFIFO, (char *)bd->read_buf,
                   READ_BUF_SIZE);
    if (len > 0) {
      bd->read_buf_bytes = len;
      bd->read_buf_next = 0;
      time(&t1);
      if (difftime(t1, t0) > 2) {
        /* Reschedule it in the work handler to avoid stuck. */
        bd->has_cons_work = 1;
        rshim_work_signal(bd);
      } else {
        goto again;
      }
    }
  }

  if (rx_avail && bd->rx_chan == TMFIFO_NET_CHAN) {
    if (__sync_bool_compare_and_swap(&bd->net_rx_pending, false, true)) {
      do {
        rc = write(bd->net_notify_fd[1], &rx_avail, sizeof(rx_avail));
      } while (rc == -1 && (errno == EINTR || errno == EAGAIN));
    }
  }
}

ssize_t rshim_fifo_read(rshim_backend_t *bd, char *buffer, size_t count,
                        int chan, bool nonblock)
{
  struct timespec ts;
  size_t rd_cnt = 0;

  pthread_mutex_lock(&bd->mutex);

  while (count) {
    size_t readsize;
    int pass1;
    int pass2;

    RSHIM_DBG("rshim%d(fifo_read) top of loop, remaining count %zd\n",
              bd->index, count);

    /*
     * We check this each time through the loop since the
     * device could get disconnected while we're waiting for
     * more data in the read FIFO.
     */
    if (!bd->has_tm) {
      pthread_mutex_unlock(&bd->mutex);
      RSHIM_DBG("rshim%d(fifo_read) returning %zd/ENODEV\n", bd->index, rd_cnt);
      return rd_cnt ? rd_cnt : -ENODEV;
    }

    if (bd->tmfifo_error) {
      pthread_mutex_unlock(&bd->mutex);
      RSHIM_DBG("rshim%d(fifo_read) returning %zd/%d\n", bd->index, rd_cnt,
                bd->tmfifo_error);
      return rd_cnt ? rd_cnt : bd->tmfifo_error;
    }

    if (read_empty(bd, chan)) {
      RSHIM_DBG("rshim%d(fifo_read) fifo empty\n", bd->index);
      if (rd_cnt || nonblock) {
        if (rd_cnt == 0) {
          pthread_mutex_lock(&bd->ringlock);
          rshim_fifo_input(bd);
          pthread_mutex_unlock(&bd->ringlock);
        }
        pthread_mutex_unlock(&bd->mutex);
        RSHIM_DBG("rshim%d(fifo_read) returning %zd/EAGAIN\n",
                  bd->index, rd_cnt);
        return rd_cnt ? rd_cnt : -EAGAIN;
      }

      RSHIM_DBG("rshim%d(fifo_read) waiting for readable chan %d\n",
                bd->index, chan);
      while (read_empty(bd, chan)) {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;
        if (pthread_cond_timedwait(&bd->read_fifo[chan].operable,
            &bd->mutex, &ts)) {
          RSHIM_DBG("rshim%d(fifo_read) returning ERESTARTSYS\n", bd->index);
          pthread_mutex_unlock(&bd->mutex);
          return -EINTR;
        }

	if (rshim_got_peer_signal() == 0) {
          pthread_mutex_unlock(&bd->mutex);
          return -EINTR;
	}
      }

      /*
       * Since we dropped the mutex, we must make sure our interface is still
       * there before we do anything else.
       */
      continue;
    }

    /* Figure out how many bytes we will transfer on this pass. */
    pthread_mutex_lock(&bd->ringlock);
    readsize = MIN(count, (size_t)read_cnt(bd, chan));
    pass1 = MIN(readsize, (size_t)read_cnt_to_end(bd, chan));
    pass2 = readsize - pass1;

    RSHIM_DBG("rshim%d(fifo_read) readsize %zd, head %d, tail %d\n",
              bd->index, readsize, bd->read_fifo[chan].head,
              bd->read_fifo[chan].tail);

    memcpy(buffer, read_data_ptr(bd, chan), pass1);
    if (pass2)
      memcpy(buffer + pass1, bd->read_fifo[chan].data, pass2);

    read_consume_bytes(bd, chan, readsize);

    /* Check if there is any more incoming data. */
    rshim_fifo_input(bd);
    pthread_mutex_unlock(&bd->ringlock);

    count -= readsize;
    buffer += readsize;
    rd_cnt += readsize;
    RSHIM_DBG("rshim%d(fifo_read) transferred %zd bytes\n",
              bd->index, readsize);
  }

  pthread_mutex_unlock(&bd->mutex);

  RSHIM_DBG("rshim%d(fifo_read) returning %zd\n", bd->index, rd_cnt);
  return rd_cnt;
}

static void rshim_fifo_output(rshim_backend_t *bd)
{
  int writesize, write_buf_next = 0, write_avail;
  int chan, chan_offset, fifo_avail;
  int numchan = TMFIFO_MAX_CHAN;

  /* If we're already writing, we have nowhere to put data. */
  if (bd->spin_flags & RSH_SFLG_WRITING)
    return;

  fifo_avail = rshim_fifo_tx_avail(bd) * sizeof(uint64_t);
  if (fifo_avail <= 0) {
    bd->has_cons_work = 1;
    rshim_work_signal(bd);
    return;
  }

  write_avail = fifo_avail - write_buf_next;

  if (!bd->write_buf_pkt_rem) {
    /* Send control messages. */
    writesize = rshim_fifo_ctrl_tx(bd);
    if (writesize > 0) {
      write_avail -= writesize;
      write_buf_next += writesize;
    }
  }

  /* Walk through all the channels, sending as much data as possible. */
  for (chan_offset = 0; chan_offset < numchan && write_avail > 0;
       chan_offset++) {
    /*
     * Pick the current channel if not done, otherwise round-robin
     * to the next channel.
     */
    if (bd->write_buf_pkt_rem > 0)
      chan = bd->tx_chan;
    else {
      rshim_tmfifo_msg_hdr_t *hdr = &bd->msg_hdr;
      uint16_t cur_len;

      chan = bd->tx_chan = (bd->tx_chan + 1) % numchan;
      cur_len = write_cnt(bd, chan);

      /*
       * Set up message header for console data which is byte
       * stream. Network packets already have the message
       * header included.
       */
      if (chan == TMFIFO_CONS_CHAN) {
        if (cur_len == 0)
          continue;
        hdr->data = 0;
        hdr->type = VIRTIO_ID_CONSOLE;
        hdr->len = htons(cur_len);
      } else {
        int pass1;

        if (cur_len < sizeof(rshim_tmfifo_msg_hdr_t))
          continue;

        pass1 = write_cnt_to_end(bd, chan);
        if (pass1 >= sizeof(*hdr)) {
          hdr = (rshim_tmfifo_msg_hdr_t *) write_data_ptr(bd, chan);
        } else {
          memcpy(hdr, write_data_ptr(bd, chan), pass1);
          memcpy((uint8_t *)hdr + pass1, bd->write_fifo[chan].data,
                 sizeof(*hdr) - pass1);
        }
      }

      /* Calculate checksum for this header. */
      rshim_fifo_msg_update_checksum(hdr);

      bd->write_buf_pkt_rem = ntohs(hdr->len) + sizeof(*hdr);
    }

    /* Send out the packet header for the console data. */
    if (chan == TMFIFO_CONS_CHAN &&
        bd->write_buf_pkt_rem > ntohs(bd->msg_hdr.len)) {
      rshim_tmfifo_msg_hdr_t *hdr = &bd->msg_hdr;
      int left = bd->write_buf_pkt_rem - ntohs(hdr->len);
      uint8_t *pos = (uint8_t *)hdr + sizeof(*hdr) - left;

      writesize = MIN(write_avail, left);
      memcpy(&bd->write_buf[write_buf_next], pos, writesize);
      write_buf_next += writesize;
      bd->write_buf_pkt_rem -= writesize;
      write_avail -= writesize;

      /*
       * Don't continue if no more space for the header. It'll be picked up
       * next time.
       */
      if (left != writesize)
        break;
    }

    writesize = MIN(write_avail, (int)write_cnt(bd, chan));
    writesize = MIN(writesize, bd->write_buf_pkt_rem);

    /*
     * The write size should be aligned to 8 bytes unless for the
     * last block, which will be padded at the end.
     */
    if (bd->write_buf_pkt_rem != writesize)
      writesize &= -8;

    if (writesize > 0) {
      int pass1;
      int pass2;

      pass1 = MIN(writesize, (int)write_cnt_to_end(bd, chan));
      pass2 = writesize - pass1;

      RSHIM_DBG("rshim%d(fifo_output) chan %d, writesize %d, next %d,"
                 " head %d, tail %d\n",
                 bd->index, chan, writesize, write_buf_next,
                 bd->write_fifo[chan].head,
                 bd->write_fifo[chan].tail);

      memcpy(&bd->write_buf[write_buf_next], write_data_ptr(bd, chan), pass1);
      memcpy(&bd->write_buf[write_buf_next + pass1],
             bd->write_fifo[chan].data, pass2);

      write_consume_bytes(bd, chan, writesize);
      write_buf_next += writesize;
      bd->write_buf_pkt_rem -= writesize;
      /* Add padding at the end. */
      if (bd->write_buf_pkt_rem == 0)
        write_buf_next = (write_buf_next + 7) & -8;
      write_avail = fifo_avail - write_buf_next;

      pthread_cond_broadcast(&bd->write_fifo[chan].operable);
      RSHIM_DBG("rshim%d(fifo_output) woke up writable chan %d\n",
                bd->index, chan);
    }
  }

  /* Drop the data if it is still booting. */
  if (bd->is_boot_open || bd->drop_mode || !bd->has_rshim || !bd->has_tm)
    return;

  /* If we actually put anything in the buffer, send it. */
  if (write_buf_next)
    bd->write(bd, RSH_DEV_TYPE_TMFIFO, (char *)bd->write_buf, write_buf_next);
}

int rshim_fifo_alloc(rshim_backend_t *bd)
{
  int i;

  for (i = 0; i < TMFIFO_MAX_CHAN; i++) {
    if (!bd->read_fifo[i].data)
      bd->read_fifo[i].data = malloc(READ_FIFO_SIZE);

    if (!bd->write_fifo[i].data)
      bd->write_fifo[i].data = malloc(WRITE_FIFO_SIZE);
  }

  return 0;
}

void rshim_fifo_reset(rshim_backend_t *bd)
{
  int i;

  bd->read_buf_bytes = 0;
  bd->read_buf_pkt_rem = 0;
  bd->read_buf_next = 0;
  bd->read_buf_pkt_padding = 0;
  bd->write_buf_pkt_rem = 0;
  bd->rx_chan = bd->tx_chan = 0;

  pthread_mutex_lock(&bd->ringlock);
  bd->spin_flags &= ~(RSH_SFLG_WRITING | RSH_SFLG_READING);
  for (i = 0; i < TMFIFO_MAX_CHAN; i++) {
    read_reset(bd, i);
    write_reset(bd, i);
  }
  pthread_mutex_unlock(&bd->ringlock);
}

void rshim_fifo_free(rshim_backend_t *bd)
{
  int i;

  for (i = 0; i < TMFIFO_MAX_CHAN; i++) {
    free(bd->read_fifo[i].data);
    bd->read_fifo[i].data = NULL;
    free(bd->write_fifo[i].data);
    bd->write_fifo[i].data = NULL;
  }

  rshim_fifo_reset(bd);
  bd->has_tm = 0;
}

ssize_t rshim_fifo_write(rshim_backend_t *bd, const char *buffer,
                         size_t count, int chan, bool nonblock)
{
  size_t wr_cnt = 0;

  pthread_mutex_lock(&bd->mutex);

  while (count) {
    size_t writesize;
    int pass1;
    int pass2;

    /*
     * We check this each time through the loop since the
     * device could get disconnected while we're waiting for
     * more space in the write buffer.
     */
    if (!bd->has_tm) {
      pthread_mutex_unlock(&bd->mutex);
      RSHIM_DBG("rshim%d(fifo_write) returning %zd/ENODEV\n",
                bd->index, wr_cnt);
      return wr_cnt ? wr_cnt : -ENODEV;
    }

    if (bd->tmfifo_error) {
      pthread_mutex_unlock(&bd->mutex);
      RSHIM_DBG("rshim%d(fifo_write) returning %zd/%d\n",
                bd->index, wr_cnt, bd->tmfifo_error);
      return wr_cnt ? wr_cnt : bd->tmfifo_error;
    }

    if (write_full(bd, chan)) {
      RSHIM_DBG("rshim%d(fifo_write) fifo full\n", bd->index);
      /* Try to send more data. */
      pthread_mutex_lock(&bd->ringlock);
      rshim_fifo_output(bd);
      pthread_mutex_unlock(&bd->ringlock);
      if (nonblock) {
        pthread_mutex_unlock(&bd->mutex);
        RSHIM_DBG("rshim%d(fifo_write) returning %zd/EAGAIN\n",
                  bd->index, wr_cnt);
        return wr_cnt ? wr_cnt : -EAGAIN;
      }

      RSHIM_DBG("rshim%d(fifo_write) waiting for writable chan %d\n",
                bd->index, chan);
      while (write_full(bd, chan)) {
        if (pthread_cond_wait(&bd->write_fifo[chan].operable, &bd->mutex)) {
          RSHIM_DBG("rshim%d(fifo_write) returning %zd/ERESTARTSYS\n",
                    bd->index, wr_cnt);
          pthread_mutex_unlock(&bd->mutex);
          return wr_cnt ? wr_cnt : -EAGAIN;
        }

	if (rshim_got_peer_signal() == 0) {
          pthread_mutex_unlock(&bd->mutex);
          return -EINTR;
	}
      }

      /*
       * Since we dropped the mutex, we must make sure our interface is still
       * there before we do anything else.
       */
      continue;
    }

    pthread_mutex_lock(&bd->ringlock);
    writesize = MIN(count, (size_t)write_space(bd, chan));
    pass1 = MIN(writesize, (size_t)write_space_to_end(bd, chan));
    pass2 = writesize - pass1;
    pthread_mutex_unlock(&bd->ringlock);

    RSHIM_DBG("rshim%d(fifo_write) writesize %zd, head %d, tail %d\n",
              bd->index, writesize, bd->write_fifo[chan].head,
              bd->write_fifo[chan].tail);

    memcpy(write_space_ptr(bd, chan), buffer, pass1);
    if (pass2)
      memcpy(bd->write_fifo[chan].data, buffer + pass1, pass2);

    pthread_mutex_lock(&bd->ringlock);
    write_add_bytes(bd, chan, writesize);
    /* We have some new bytes, let's see if we can write any. */
    rshim_fifo_output(bd);
    pthread_mutex_unlock(&bd->ringlock);

    count -= writesize;
    buffer += writesize;
    wr_cnt += writesize;
    RSHIM_DBG("rshim%d(fifo_write) transferred %zd bytes this pass\n",
              bd->index, writesize);
  }

  pthread_mutex_unlock(&bd->mutex);

  RSHIM_DBG("rshim%d(fifo_write) returning %zd\n",
            bd->index, wr_cnt);
  return wr_cnt;
}

static void rshim_work_handler(rshim_backend_t *bd)
{
  int rc;

  pthread_mutex_lock(&bd->mutex);

  bd->work_pending = false;

  if (bd->keepalive && bd->has_rshim && !bd->debug_code && !bd->drop_mode &&
      !bd->in_access_check) {
    bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->scratchpad1,
                    RSHIM_KEEPALIVE_MAGIC_NUM, RSHIM_REG_SIZE_8B);
    bd->keepalive = 0;
  }

  if (bd->boot_work_buf != NULL) {
    bd->boot_work_buf_actual_len = rshim_write_delayed(bd,
                                                       RSH_DEV_TYPE_BOOT,
                                                       bd->boot_work_buf,
                                                       bd->boot_work_buf_len);
    bd->boot_work_buf = NULL;
    pthread_cond_broadcast(&bd->boot_write_complete_cond);
  }

  if (!rshim_no_net && bd->net_fd < 0 &&
      (rshim_timer_ticks - bd->net_init_time) < RSHIM_NET_INIT_DELAY) {
    rc = rshim_net_init(bd);
    if (!rc) {
      bd->is_net_open = 1;
      pthread_mutex_lock(&bd->ringlock);
      rshim_fifo_input(bd);
      pthread_mutex_unlock(&bd->ringlock);
    }
  }

  if (bd->is_boot_open || bd->is_booting) {
    if (bd->is_boot_open && bd->has_cons_work)
      rshim_fifo_input(bd);
    pthread_mutex_unlock(&bd->mutex);
    return;
  }

  if (bd->has_fifo_work) {
    int len;

    len = rshim_write_delayed(bd, bd->fifo_work_devtype,
                              bd->fifo_work_buf,
                              bd->fifo_work_buf_len);
    bd->has_fifo_work = 0;

    pthread_mutex_lock(&bd->ringlock);
    bd->spin_flags &= ~RSH_SFLG_WRITING;
    if (len == bd->fifo_work_buf_len) {
      pthread_cond_broadcast(&bd->fifo_write_complete_cond);
      rshim_fifo_output(bd);
    } else {
      RSHIM_DBG("rshim%d(fifo_write) completed abnormally (%d)\n",
                bd->index, len);
    }
    pthread_mutex_unlock(&bd->ringlock);
  }

  if (bd->has_cons_work) {
    pthread_mutex_lock(&bd->ringlock);
    /* FIFO output. */
    rshim_fifo_output(bd);
    /* FIFO input. */
    rshim_fifo_input(bd);
    pthread_mutex_unlock(&bd->ringlock);

    bd->has_cons_work = 0;
  }

  if (!bd->has_reprobe && bd->is_cons_open) {
    bd->has_cons_work = 1;
    if (bd->timer - rshim_timer_ticks > RSHIM_CONSOLE_POLL_TICKS)
      bd->timer = rshim_timer_ticks + RSHIM_CONSOLE_POLL_TICKS;
  }

  if (bd->has_locked_work) {
    bd->has_locked_work = 0;
    rshim_update_locked_mode(bd);
  }

  if (bd->has_osp_work) {
    bd->has_osp_work = 0;
    rshim_handle_ownership_transfer(bd);
  }

  pthread_mutex_unlock(&bd->mutex);
}

static int rshim_boot_done(rshim_backend_t *bd)
{
  if (bd->has_rshim && bd->has_tm) {
    /* Clear any previous errors. */
    bd->tmfifo_error = 0;

    /*
     * If someone might be waiting for the device to come up,
     * tell them it's ready.
     */
    if (bd->is_booting) {
        bd->is_booting = 0;

        RSHIM_DBG("rshim%d signaling booting complete\n", bd->index);
        pthread_cond_broadcast(&bd->boot_complete_cond);
    };

    /* If the console device is open, start the worker. */
    if (bd->is_cons_open && !bd->has_cons_work) {
      bd->has_cons_work = 1;
      RSHIM_DBG("rshim%d console_work submitted\n", bd->index);
      rshim_work_signal(bd);
    }

    /* Tell the user this device is now attached. */
    RSHIM_INFO("rshim%d attached\n", bd->index);
  }

  return 0;
}

int rshim_fifo_fsync(rshim_backend_t *bd, int chan)
{
  int rc = 0;

  pthread_mutex_lock(&bd->mutex);

  /*
   * To ensure that all of our data has actually made it to the
   * device, we first wait until the channel is empty, then we wait
   * until there is no outstanding write urb.
   */
  while (!write_empty(bd, chan)) {
    if (pthread_cond_wait(&bd->write_fifo[chan].operable, &bd->mutex)) {
      rc = -EINTR;
      break;
    }

    if (rshim_got_peer_signal() == 0) {
      rc = -EINTR;
      break;
    }
  }

  while (!rc && (bd->spin_flags & RSH_SFLG_WRITING)) {
    if (pthread_cond_wait(&bd->fifo_write_complete_cond, &bd->mutex)) {
      rc = -EINTR;
      break;
    }

    if (rshim_got_peer_signal() == 0) {
      rc = -EINTR;
      break;
    }
  }

  pthread_mutex_unlock(&bd->mutex);

  return rc;
}

void rshim_fifo_check_poll(rshim_backend_t *bd, int chan, bool *poll_rx,
                           bool *poll_tx, bool *poll_err)
{
  pthread_mutex_lock(&bd->mutex);
  pthread_mutex_lock(&bd->ringlock);

  if (!read_empty(bd, chan))
    *poll_rx = true;
  else
    *poll_rx = false;

  if (!write_full(bd, chan))
    *poll_tx = true;
  else
    *poll_tx = false;

  /*
   * We don't report POLLERR on the console so that it doesn't get
   * automatically disconnected when it fails, and so that you can
   * connect to it in the error state before rebooting the target.
   * This is inconsistent, but being consistent turns out to be very
   * annoying.  If someone tries to actually type on it, they'll
   * get an error.
   */
  if (bd->tmfifo_error && chan != TMFIFO_CONS_CHAN)
    *poll_err = true;
  else
    *poll_err = false;

  pthread_mutex_unlock(&bd->ringlock);
  pthread_mutex_unlock(&bd->mutex);
}

static int rshim_fifo_release(rshim_backend_t *bd, int chan,
                              void (*poll_handle_destroy)(rshim_backend_t *bd,
                                                          int chan))
{
  pthread_mutex_lock(&bd->mutex);

  if (chan == TMFIFO_CONS_CHAN) {
    /*
     * If we aren't the last console file, nothing to do but
     * fix the reference count.
     */
    bd->console_opens--;
    if (bd->console_opens) {
      pthread_mutex_unlock(&bd->mutex);
      return 0;
    }

    /*
     * We've told the host to stop using the TM FIFO console,
     * but there may be a lag before it does.  Unless we
     * continue to read data from the console stream, the host
     * may spin forever waiting for the console to be drained
     * and not realize that it's time to stop using it.
     * Clearing the CONS_OPEN spin flag will discard any future
     * incoming console data, but if our input buffers are full
     * now, we might not be even reading from the hardware
     * FIFO.  To avoid problems, clear the buffers and call the
     * drainer so that it knows there's space.
     */
    pthread_mutex_lock(&bd->ringlock);

    bd->spin_flags &= ~RSH_SFLG_CONS_OPEN;
    read_reset(bd, TMFIFO_CONS_CHAN);
    write_reset(bd, TMFIFO_CONS_CHAN);

    rshim_fifo_input(bd);

    pthread_mutex_unlock(&bd->ringlock);
  }

  if (chan == TMFIFO_CONS_CHAN)
    bd->is_cons_open = 0;
  else
    bd->is_net_open = 0;

  if (!bd->is_net_open && !bd->is_cons_open) {
    if (bd->cancel)
      bd->cancel(bd, RSH_DEV_TYPE_TMFIFO, false);

    pthread_mutex_lock(&bd->ringlock);
    bd->spin_flags &= ~RSH_SFLG_READING;
    pthread_mutex_unlock(&bd->ringlock);
  }

  if (poll_handle_destroy)
    poll_handle_destroy(bd, chan);

  pthread_mutex_unlock(&bd->mutex);

  return 0;
}

/* Console operations */

int rshim_console_open(rshim_backend_t *bd)
{
  pthread_mutex_lock(&bd->mutex);

  if (bd->is_cons_open) {
    pthread_mutex_unlock(&bd->mutex);
    return -EBUSY;
  }

  if (bd->locked_mode) {
    RSHIM_ERR("rshim%d failed to open console(locked mode)\n", bd->index);
    pthread_mutex_unlock(&bd->mutex);
    return -EPERM;
  }

  bd->is_cons_open = 1;

  pthread_mutex_lock(&bd->ringlock);

  bd->spin_flags |= RSH_SFLG_CONS_OPEN;

  pthread_mutex_unlock(&bd->ringlock);

  if (!bd->has_cons_work) {
    bd->has_cons_work = 1;
    rshim_work_signal(bd);
  }

  rshim_ref(bd);
  bd->console_opens++;
  pthread_mutex_unlock(&bd->mutex);

  return 0;
}

int rshim_console_release(rshim_backend_t *bd,
                          void (*poll_handle_destroy)(rshim_backend_t *bd,
                                                      int chan))
{
  int rc;

  rc = rshim_fifo_release(bd, TMFIFO_CONS_CHAN, poll_handle_destroy);
  rshim_deref(bd);

  return rc;
}

int rshim_notify(rshim_backend_t *bd, int event, int code)
{
  int rc = 0;

  switch (event) {
  case RSH_EVENT_FIFO_INPUT:
  case RSH_EVENT_FIFO_OUTPUT:
    bd->has_cons_work = 1;
    rshim_work_signal(bd);
    break;

  case RSH_EVENT_FIFO_ERR:
    rshim_fifo_err(bd, code);
    break;

  case RSH_EVENT_ATTACH:
    rshim_boot_done(bd);

    /* Sync-up the tmfifo if reprobe is not supported. */
    if (!bd->has_reprobe && bd->has_rshim)
      rshim_fifo_sync(bd, false);

    __sync_synchronize();
    bd->is_attach = 1;

    /* Init network interface. Moved to the work handler since it takes time. */
    bd->net_init_time = rshim_timer_ticks;
    break;

  case RSH_EVENT_DETACH:
    /* Shutdown network interface. */
    __sync_synchronize();
    bd->is_attach = 0;
    rshim_net_del(bd);
    rshim_fifo_release(bd, TMFIFO_NET_CHAN, NULL);
    break;
  }

  return rc;
}

static int rshim_find_index(char *dev_name)
{
  int i;

  /* Need to match static device name if configured. */
  if (rshim_static_dev_name && strcmp(rshim_static_dev_name, dev_name))
    return -1;

  /* Return static index if configured. */
  if (rshim_static_index >= 0)
    return rshim_static_index;

  /* First look for a match with a previous device name. */
  for (i = 0; i < RSHIM_MAX_DEV; i++) {
    if (rshim_dev_names[i] && !strcmp(dev_name, rshim_dev_names[i])) {
      RSHIM_DBG("Found match with previous at index %d\n", i);
      return i;
    }
  }

  /* Then look for a never-used slot. */
  for (i = 0; i < RSHIM_MAX_DEV; i++) {
    if (!rshim_dev_names[i])
      return i;
  }

  /* Finally look for a currently-unused slot. */
  for (i = 0; i < RSHIM_MAX_DEV; i++) {
    if (!rshim_devs[i]) {
      RSHIM_DBG("Found unused slot %d\n", i);
      return i;
    }
  }

  return -1;
}

rshim_backend_t *rshim_find_by_name(char *dev_name)
{
  int index = rshim_find_index(dev_name);

  /* If none of that worked, we fail. */
  if (index < 0) {
    RSHIM_ERR("No slot for new device %s\n", dev_name);
    return NULL;
  }

  return rshim_devs[index];
}

rshim_backend_t *rshim_find_by_index(int index)
{
  return (index >= 0 && index < RSHIM_MAX_DEV) ?
    rshim_devs[index] : NULL;
}

rshim_backend_t *rshim_find_by_dev(void *dev)
{
  rshim_backend_t *bd;
  int index;

  for (index = 0; index < RSHIM_MAX_DEV; index++) {
    bd = rshim_devs[index];
    if (bd && bd->dev == dev)
      return bd;
  }

  return NULL;
}

int rshim_set_drop_mode(rshim_backend_t *bd, int value)
{
  int has_bd_lock;
  int old_value;
  int rt = 0;

  has_bd_lock = !pthread_mutex_trylock(&bd->mutex);

  old_value = (int)bd->drop_mode;
  value = !!value;
  if (value == old_value) {
    if (has_bd_lock)
      pthread_mutex_unlock(&bd->mutex);
    return 0;
  }

  bd->drop_mode = 0;
  if (bd->enable_device && bd->enable_device(bd, value ? false : true))
    bd->drop_mode = 1;
  else
    bd->drop_mode = value;

  if (bd->drop_mode)
    bd->drop_pkt = 1;
  else
    rshim_fifo_sync(bd, true);

  if (has_bd_lock)
    pthread_mutex_unlock(&bd->mutex);

  /*
   * Check if another endpoint driver has already attached to the
   * same rshim device before enabling it.
   */
  if (!bd->drop_mode) {
    rshim_lock();
    has_bd_lock = !pthread_mutex_trylock(&bd->mutex);
    if (rshim_access_check(bd)) {
      RSHIM_WARN("rshim%d is not accessible\n", bd->index);
      bd->drop_mode = 1;
      rt = -EACCES;
    }
    if (has_bd_lock)
      pthread_mutex_unlock(&bd->mutex);
    rshim_unlock();
  }

  return rt;
}

static int rshim_check_locked_mode(rshim_backend_t *bd)
{
    uint64_t value = 0;
    int rc;

    rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->scratchpad1, &value,
                        RSHIM_REG_SIZE_8B);
    if (rc < 0 || RSHIM_BAD_CTRL_REG(value)) {
        RSHIM_DBG("rshim%d failed to read SP1\n", bd->index);
        return -EIO;
    }

    return (value == BF3_RSH_SECURE_NIC_MODE_MAGIC_NUM) ? 1 : 0;
}

static int rshim_update_locked_mode(rshim_backend_t *bd)
{
  int locked_mode;
  int has_bd_lock;

  /* Only do this for PCIE. */
  if (bd->type != RSH_BACKEND_PCIE)
    return 0;

  /* Skip locked-mode polling during reset. */
  if (bd->is_booting)
    return 0;

  has_bd_lock = !pthread_mutex_trylock(&bd->mutex);

  locked_mode = rshim_check_locked_mode(bd);
  if (has_bd_lock)
    pthread_mutex_unlock(&bd->mutex);
  if (locked_mode < 0)
    return -EIO;

  if (locked_mode != bd->locked_mode) {
    RSHIM_INFO("rshim%d set to %s mode\n", bd->index,
        locked_mode ? "locked" : "unlocked");
    bd->locked_mode = locked_mode;

    /*
     * When NIC has exited locked mode, other rshim driver like BMC USB rshim
     * driver may have attached RSHIM. In that case, we will enter drop mode
     */
    if (!locked_mode) {
      int rt;

      rshim_lock();
      has_bd_lock = !pthread_mutex_trylock(&bd->mutex);
      rt = rshim_access_check(bd); 
      if (has_bd_lock)
        pthread_mutex_unlock(&bd->mutex);
      rshim_unlock();
      if (rt) {
        RSHIM_INFO("rshim%d attached by another device. Entering Drop Mode\n",
            bd->index);
        rt = rshim_set_drop_mode(bd, 1);
        if (rt) {
          RSHIM_ERR("rshim%d failed to enter drop mode\n", bd->index);
          return -EIO;
        }
      }
    }
  }

  return 0;
}

static int rshim_check_sp1_magic(rshim_backend_t *bd, uint64_t magic,
    bool* result)
{
  uint64_t sp1;
  int rc;

  rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->scratchpad1, &sp1,
                      RSHIM_REG_SIZE_8B);
  if (rc || RSHIM_BAD_CTRL_REG(sp1)) {
    RSHIM_ERR("rshim%d failed to read sp1(%d)\n", bd->index, rc);
    *result = false;
    return rc;
  }

  *result = (sp1 == magic);

  return 0;
}

static int rshim_write_sp1_magic(rshim_backend_t *bd, uint64_t magic)
{
  int rc;

  RSHIM_INFO("rshim%d writing sp1 magic %s (0x%llx)\n", bd->index,
      magic_to_str(magic), (unsigned long long)magic);

  rc = bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->scratchpad1, magic,
      RSHIM_REG_SIZE_8B);
  if (rc) {
    RSHIM_ERR("rshim%d failed to write sp1(%s)\n", bd->index, strerror(-rc));
    return -ENODEV;
  }

  return 0;
}

static int rshim_handle_ownership_transfer(rshim_backend_t *bd)
{
  bool has_ack, has_req;
  int i, rt;

  if (bd->drop_mode) {
    if (rshim_force_cmd_pending[bd->index]) {
      RSHIM_INFO("rshim%d executing Force command\n", bd->index);
      rshim_force_cmd_pending[bd->index] = 0;
      bd->requesting_rshim = 1;

      if (bd->enable_device && bd->enable_device(bd, true)) {
        RSHIM_ERR("rshim%d failed to enable device\n", bd->index);
        return -EIO;
      }

      /* sending req and checking ack multiple times to ensure the transfer */
      for (i = 0; i < 10; i++) {
        rt = rshim_write_sp1_magic(bd, RSHIM_OSP_REQ_MAGIC_NUM);
        if (rt) {
          RSHIM_ERR("rshim%d failed to write ownership transfer req\n",
              bd->index);
          usleep(RSHIM_OSP_TO_REQ_MS * 1000 / 10);
          continue;
        }

        usleep(RSHIM_OSP_TO_REQ_MS * 1000 / 10);

        has_ack = false;
        rt = rshim_check_sp1_magic(bd, RSHIM_OSP_ACK_MAGIC_NUM, &has_ack);

        if (!rt && has_ack)
          break;
      }

      if (rt || !has_ack) {
        RSHIM_WARN("rshim%d failed to receive ownership transfer ack\n",
            bd->index);
        bd->requesting_rshim = 0;
        return -EIO;
      }
      RSHIM_INFO("rshim%d received ownership transfer ack\n", bd->index);

      rt = rshim_set_drop_mode(bd, 0);
      if (rt) {
        RSHIM_ERR("rshim%d failed to exit drop mode\n", bd->index);
        bd->requesting_rshim = 0;
        return rt;
      }
      bd->requesting_rshim = 0;
      RSHIM_INFO("rshim%d regained ownership successfully\n", bd->index);
    }
  } else {
    if (rshim_force_cmd_pending[bd->index]) {
      RSHIM_INFO("rshim%d skipping Force command (already attached)\n",
                 bd->index);
      rshim_force_cmd_pending[bd->index] = 0;
    }

    has_req = false;
    rt = rshim_check_sp1_magic(bd, RSHIM_OSP_REQ_MAGIC_NUM, &has_req);

    if (!rt && has_req) {
      RSHIM_INFO("rshim%d received ownership transfer request\n", bd->index);

      RSHIM_INFO("rshim%d notifying the requester with ACK\n", bd->index);
      for (i = 0; i < 10; i++) {
        rt = rshim_write_sp1_magic(bd, RSHIM_OSP_ACK_MAGIC_NUM);
        usleep(RSHIM_OSP_TO_REQ_MS * 1000 / 10);
        if (rt) {
          RSHIM_ERR("rshim%d failed to write ownership transfer ack\n",
              bd->index);
          continue;
        }
      }

      usleep(RSHIM_OSP_TO_ONLINE_MS * 1000);

      RSHIM_INFO("rshim%d entering drop mode\n", bd->index);
      rt = rshim_set_drop_mode(bd, 1);
      if (rt) {
        RSHIM_ERR("rshim%d failed to enter drop mode\n", bd->index);
        return rt;
      }

      RSHIM_INFO("rshim%d passed to the requester successfully\n", bd->index);
    }
  }
  return 0;
}

/* House-keeping timer. */
static void rshim_timer_func(rshim_backend_t *bd) {
  int ticks = rshim_keepalive_ticks;

  if (bd->has_cons_work)
    rshim_work_signal(bd);

  /* Request keepalive update and restart the ~300ms timer. */
  if (rshim_timer_ticks - (bd->last_keepalive + ticks) > 0) {
    bd->keepalive = 1;
    bd->last_keepalive = rshim_timer_ticks;
    rshim_work_signal(bd);

    /* Piggy-back the keepalive update for locked mode update as well */
    rshim_update_locked_mode(bd);
  }

#ifdef __linux__
  /* Some checking for PCIe backend. */
  if (bd->type == RSH_BACKEND_PCIE)
    rshim_pcie_check(bd);
#endif

  bd->timer = rshim_timer_ticks + ticks;
}

static void rshim_timer_run(void)
{
  rshim_backend_t *bd;
  int i;

  rshim_timer_ticks++;

  for (i = 0; i < RSHIM_MAX_DEV; i++) {
    bd = rshim_devs[i];
    if (bd) {
      if (rshim_timer_ticks - bd->timer > 0)
        rshim_timer_func(bd);

      if (rshim_timer_ticks % RSHIM_CHECK_LOCKED_MODE_TICKS == 0) {
        if (bd->type == RSH_BACKEND_PCIE) {
          bd->has_locked_work = 1;
          rshim_work_signal(bd);
        }
      }

      if (rshim_timer_ticks % RSHIM_OSP_MGT_INTERVAL_TICKS == 0) {
        bd->has_osp_work = 1;
        rshim_work_signal(bd);
      }

      /* Push out remaining data if not sent out in the epoll loop. */
      if (bd->net_fd >= 0) {
        rshim_net_tx(bd);
        rshim_net_rx(bd);
      }
    }
  }
}

/*
 * For some BF-1 SmartNIC cards with UART connected to the same RSim host, the
 * BOO_MODE comes up with 0 after power-cycle thus not able to boot from eMMC.
 * This function provides a workaround to detect such case and reset the card
 * with the correct boot mode.
 */
static void rshim_boot_workaround_check(rshim_backend_t *bd)
{
  uint64_t value, uptime_sw, uptime_hw;
  int rc;

  /* This issue is only seen on BF-1 card. */
  if (bd->ver_id != RSHIM_BLUEFIELD_1)
    return;

  /* Check boot mode 0, which supposes to be set externally. */
  rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->boot_control, &value,
                      RSHIM_REG_SIZE_8B);
  if (rc || value != RSH_BOOT_CONTROL__BOOT_MODE_VAL_NONE)
    return;

  /*
   * The logic below detects whether it's a hard reset. Register
   * RSH_UPTIME_POR has the value of cycles since hw reset, register
   * RSH_UPTIME has value of the most recent reset (sw or hard reset).
   * If the gap between these two values is less than 1G, we treat it
   * as hard reset.
   *
   * If boot mode is 0 after hard-reset, we update the boot mode and
   * initiate sw reset so the chip could boot up.
   */
  rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->uptime_por, &uptime_hw,
                      RSHIM_REG_SIZE_8B);
  if (rc)
    return;

  rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->uptime, &uptime_sw,
                      RSHIM_REG_SIZE_8B);
  if (rc)
    return;

  if (uptime_sw - uptime_hw < 1000000000ULL) {
    rc = bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->boot_control,
                         RSH_BOOT_CONTROL__BOOT_MODE_VAL_EMMC,
                         RSHIM_REG_SIZE_8B);
    if (!rc) {
      /* SW reset. */
      RSHIM_INFO("rshim%d boot/wa reset\n", bd->index);
      rc = rshim_reset_control(bd);
      if (!rc)
        usleep(100000);
    }
  }
}

int rshim_access_check(rshim_backend_t *bd)
{
  rshim_backend_t *other_bd;
  uint64_t value = 0;
  int i, rc;

  /*
   * Command mode could start even when the rshim driver is running,
   * thus no need for access check.
   */
  if (rshim_cmdmode)
    return 0;

  bd->in_access_check = 1;  /* must be cleared before return */

  /*
   * Add a check and delay to make sure rshim is ready.
   * It's mainly used in BlueField-2+ where the rshim (like USB) access is
   * enabled in boot ROM which might happen after external host detects the
   * rshim device.
   */
  for (i = 0; i < 10; i++) {
    rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->fabric_dim, &value,
                        RSHIM_REG_SIZE_8B);
    if (!rc && value && !RSHIM_BAD_CTRL_REG(value))
      break;
    usleep(100000);
  }
  if (RSHIM_BAD_CTRL_REG(value)) {
    RSHIM_ERR("rshim%d unable to read from rshim\n", bd->index);
    bd->in_access_check = 0;
    return -ETIMEDOUT;
  }

  rshim_boot_workaround_check(bd);

  /* Write value 0 to RSH_SCRATCHPAD1. */
  rc = bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->scratchpad1, 0,
                       RSHIM_REG_SIZE_8B);
  if (rc < 0) {
    RSHIM_ERR("rshim%d failed to write sp1(%d)\n", bd->index, rc);
    bd->in_access_check = 0;
    return -ENODEV;
  }

  /* Write magic number to all the other backends. */
  for (i = 0; i < RSHIM_MAX_DEV; i++) {
    other_bd = rshim_devs[i];
    if (!other_bd || other_bd == bd)
      continue;
    pthread_mutex_lock(&other_bd->mutex);
    other_bd->write_rshim(other_bd, RSHIM_CHANNEL, bd->regs->scratchpad1,
                    RSHIM_KEEPALIVE_MAGIC_NUM, RSHIM_REG_SIZE_8B);
    pthread_mutex_unlock(&other_bd->mutex);
  }

  /*
   * Poll RSH_SCRATCHPAD1 up to one second to check whether it's reset to
   * the keepalive magic value, which indicates another backend driver has
   * already attached to this target.
   */
  value = 0;
  for (i = 0; i < 100; i++) {
    usleep(10000);
    rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->scratchpad1, &value,
                        RSHIM_REG_SIZE_8B);

    if (!rc && value == RSHIM_KEEPALIVE_MAGIC_NUM) {
      RSHIM_INFO("another backend already attached\n");
      bd->in_access_check = 0;
      return -EEXIST;
    }
  }

  // Write RSHIM_KEEPALIVE_MAGIC_NUM to SP1 in case the other backend is also
  // running the previous checking loop. This magic number isn't otherwise
  // written during this function by the timer handler due to in_access_check.
  rc = bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->scratchpad1,
                       RSHIM_KEEPALIVE_MAGIC_NUM, RSHIM_REG_SIZE_8B);
  if (rc < 0 || RSHIM_BAD_CTRL_REG(value)) {
    RSHIM_ERR("rshim%d access check failed (unable to write sp1)\n", bd->index);
    bd->in_access_check = 0;
    return -ENODEV;
  }

  /* One more read to make sure it's ready. */
  rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->scratchpad1, &value,
                      RSHIM_REG_SIZE_8B);
  if (rc < 0 || RSHIM_BAD_CTRL_REG(value)) {
    RSHIM_ERR("rshim%d access check failed(not able to read sp1)\n", bd->index);
    bd->in_access_check = 0;
    return -ENODEV;
  }

  bd->in_access_check = 0;

  return 0;
}

int rshim_register(rshim_backend_t *bd)
{
  int i, rc, index;

  if (bd->registered)
    return 0;

  index = rshim_find_index(bd->dev_name);
  if (index < 0)
    return -ENODEV;

  if (!bd->read_rshim || !bd->write_rshim) {
    RSHIM_ERR("rshim%d read_rshim/write_rshim missing\n", bd->index);
    return -EINVAL;
  }

  rc = rshim_access_check(bd);
  if (rc) {
    RSHIM_INFO("rshim%d entering drop mode\n", index);
    bd->drop_mode = 1;
    if (!rshim_force_mode)
      return rc;
  }

  if (!bd->write)
    bd->write = rshim_write_default;
  if (!bd->read)
    bd->read = rshim_read_default;

  pthread_mutex_init(&bd->ringlock, NULL);

  for (i = 0; i < TMFIFO_MAX_CHAN; i++) {
    pthread_cond_init(&bd->read_fifo[i].operable, NULL);
    pthread_cond_init(&bd->write_fifo[i].operable, NULL);
  }

  pthread_cond_init(&bd->fifo_write_complete_cond, NULL);
  pthread_cond_init(&bd->boot_complete_cond, NULL);
  pthread_cond_init(&bd->boot_write_complete_cond, NULL);
  pthread_cond_init(&bd->ctrl_wait_cond, NULL);
  memcpy(&bd->cons_termios, &init_console_termios,
         sizeof(init_console_termios));

  bd->index = index;
  if (rshim_dev_names[index])
    free(rshim_dev_names[index]);
  rshim_dev_names[index] = strdup(bd->dev_name);
  rshim_devs[index] = bd;

  for (i = 0; i < 2; i++) {
    bd->boot_buf[i] = malloc(BOOT_BUF_SIZE);
    if (!bd->boot_buf[i]) {
      if (i == 1) {
        free(bd->boot_buf[0]);
        bd->boot_buf[0] = NULL;
      }
    }
  }

  rshim_fifo_alloc(bd);

  if (!bd->read_buf)
    bd->read_buf = calloc(1, READ_BUF_SIZE);

  if (!bd->write_buf)
    bd->write_buf = calloc(1, WRITE_BUF_SIZE);

  bd->net_fd = -1;
  bd->net_notify_fd[0] = -1;
  bd->net_notify_fd[1] = -1;
  bd->registered = 1;
  bd->boot_timeout = rshim_boot_timeout;
  bd->display_level = rshim_display_level;

  /* Start the keepalive timer. */
  bd->last_keepalive = rshim_timer_ticks;
  bd->timer = rshim_timer_ticks + 1;

  /* Create character devices (except for command mode). */
#ifdef HAVE_RSHIM_FUSE
  if (!rshim_cmdmode) {
    rc = rshim_fuse_init(bd);
    if (rc) {
      rshim_deregister(bd);
      return rc;
    }
  }
#endif

  rshim_dev_bitmask |= (1ULL << index);

  return 0;
}

void rshim_deregister(rshim_backend_t *bd)
{
  int i;

  if (!bd->registered)
    return;

  rshim_dev_bitmask &= ~(1ULL << bd->index);

#ifdef HAVE_RSHIM_FUSE
  rshim_fuse_del(bd);
#endif

  for (i = 0; i < 2; i++) {
    free(bd->boot_buf[i]);
    bd->boot_buf[i] = NULL;
  }

  free(bd->read_buf);
  bd->read_buf = NULL;

  free(bd->write_buf);
  bd->write_buf = NULL;

  rshim_fifo_free(bd);

  rshim_devs[bd->index] = NULL;
  bd->registered = 0;
}

void rshim_ref(rshim_backend_t *bd)
{
  __sync_add_and_fetch(&bd->ref, 1);
}

void rshim_deref(rshim_backend_t *bd)
{
  if (__sync_sub_and_fetch(&bd->ref, 1) == 0) {
    if (bd->destroy)
      bd->destroy(bd);
  }
}

bool rshim_allow_device(const char *devname)
{
  int i;

  if (rshim_static_dev_name && strcmp(rshim_static_dev_name, devname))
    return false;

  for (i = 0; i < RSHIM_MAX_DEV; i++) {
    if (rshim_blocked_dev_names[i] &&
        !strcmp(rshim_blocked_dev_names[i], devname))
      return false;
  }

  return true;
}

/* Force to kill if not able to cleanup in time. */
static void *rshim_force_stop(void *arg)
{
  sleep(3);
  kill(0, SIGKILL);
  return NULL;
}

/* Thread waiting for stop signal. */
static void *rshim_stop_thread(void *arg)
{
  sem_wait(&rshim_stop_sem);
  sleep(3);
  rshim_force_stop(NULL);
  return NULL;
}

static void rshim_stop(void)
{
  rshim_backend_t *bd;
  pthread_t thread;
  int i, rc;

  rc = pthread_create(&thread, NULL, rshim_force_stop, NULL);
  if (rc) {
    kill(0, SIGKILL);
    return;
  }

  rshim_lock();

  for (i = 0; i < RSHIM_MAX_DEV; i++) {
    bd = rshim_devs[i];
    if (!bd)
      continue;
    pthread_mutex_lock(&bd->mutex);
    if (bd->enable_device)
      bd->enable_device(bd, false);
    rshim_deregister(bd);
    pthread_mutex_unlock(&bd->mutex);
  }

  rshim_unlock();
}

static void rshim_set_timer(int timer_fd, int interval)
{
  struct itimerspec ts;

  ts.it_interval.tv_sec = 0;
  ts.it_interval.tv_nsec = (long)interval * 1000000;
  ts.it_value.tv_sec = 0;
  ts.it_value.tv_nsec = ts.it_interval.tv_nsec;
  rshim_timer_interval = interval;
  timerfd_settime(timer_fd, 0, &ts, NULL);
}

static void rshim_main(int argc, char *argv[])
{
  int i, fd, num, rc, epoll_fd, timer_fd;
  bool rshim_pcie_lf_init_done = false;
  uint8_t index;
#ifdef __FreeBSD__
  const int MAXEVENTS = 16;
#else
  const int MAXEVENTS = 64;
#endif
  struct epoll_event events[MAXEVENTS];
  struct epoll_event event;
  rshim_backend_t *bd;
  time_t t0, t1;
  uint8_t tmp;

  sem_init(&rshim_stop_sem, 0, 0);

  memset(&event, 0, sizeof(event));
  memset(events, 0, sizeof(events));

#ifdef HAVE_RSHIM_FUSE
#ifdef __linux__
  rc = system("modprobe cuse");
  if (rc == -1)
    RSHIM_DBG("Failed the load cuse: %m\n");
#endif

#ifdef __FreeBSD__
  if (feature_present("cuse") == 0)
    if (system("kldload cuse") == -1)
      RSHIM_DBG("Failed the load cuse\n");
#endif
#endif

  /* Create the epoll fd */
  epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (epoll_fd == -1) {
    RSHIM_ERR("epoll_create1 failed: %m\n");
    exit(-1);
  }
  rshim_epoll_fd = epoll_fd;

  /* Create and add work fd. */
  if (pipe(rshim_work_fd) == -1) {
    RSHIM_ERR("Failed to create pipe");
    exit(-1);
  }
  if (fcntl(rshim_work_fd[0], F_SETFL, O_NONBLOCK) < 0) {
    RSHIM_ERR("Failed to set nonblock pipe");
    exit(-1);
  }
  event.data.fd = rshim_work_fd[0];
  event.events = EPOLLIN;
  rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, rshim_work_fd[0], &event);
  if (rc == -1) {
    RSHIM_ERR("epoll_ctl failed\n");
    exit(-1);
  }

  /* Add periodic timer. */
  timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
  if (timer_fd == -1) {
    fprintf(stderr, "timerfd_create failed: %m\n");
    exit(1);
  }
  rshim_set_timer(timer_fd, RSHIM_TIMER_INTERVAL);
  event.data.fd = timer_fd;
  event.events = EPOLLIN | EPOLLOUT;
  rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &event);
  if (rc == -1) {
    fprintf(stderr, "epoll_ctl failed: %m\n");
    exit(1);
  }

  /* Scan rshim backends. */
  rc = 0;
  if (!rshim_backend_name && rshim_static_dev_name) {
    if (!strncmp(rshim_static_dev_name, "usb", 3))
      rshim_backend_name = "usb";
    else if (!strncmp(rshim_static_dev_name, "pcie-lf", 7))
      rshim_backend_name = "pcie-lf";
    else if (!strncmp(rshim_static_dev_name, "pcie", 4))
      rshim_backend_name = "pcie";
  }
  if (!rshim_backend_name) {
    if (!rshim_cmdmode)
      rshim_pcie_init();
    rshim_usb_init(epoll_fd);
  } else {
    if (!strcmp(rshim_backend_name, "usb"))
      rc = rshim_usb_init(epoll_fd);
    else if (!strcmp(rshim_backend_name, "pcie-lf") && !rshim_cmdmode)
      rc = rshim_pcie_lf_init();
    else if (!strcmp(rshim_backend_name, "pcie") && !rshim_cmdmode)
      rc = rshim_pcie_init();
  }
  if (rc) {
    RSHIM_ERR("Failed to initialize rshim backend\n");
    exit(-1);
  }

  /* Run command mode if specified. */
  if (rshim_cmdmode) {
    rshim_cmdmode_run(argc, argv);
    return;
  }

  time(&t0);

  while (rshim_run) {
    num = epoll_wait(epoll_fd, events, MAXEVENTS, -1);
    if (num <= 0) {
      if (num < 0)
        RSHIM_DBG("epoll_wait failed; %m\n");
      continue;
    }

    for (i = 0; i < num; i++) {
      fd = events[i].data.fd;

      if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)) {
        RSHIM_DBG("epoll error\n");
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        continue;
      }

      if (fd == timer_fd) {
        uint64_t res;

        rshim_fd_full_read(timer_fd, &res, sizeof(res));
        rshim_timer_run();
      } else if (fd == rshim_work_fd[0]) {
        rc = rshim_fd_full_read(rshim_work_fd[0], &index, sizeof(index));
        if (rc == sizeof(index) && index >=0 && index < RSHIM_MAX_DEV) {
          bd = rshim_devs[index];
          if (bd)
            rshim_work_handler(bd);
        }
        continue;
      } else {
        /* Network. */
        for (index = 0; index < RSHIM_MAX_DEV; index++) {
          bd = rshim_devs[index];
          if (!bd)
            continue;

          if (fd == bd->net_notify_fd[0]) {
            /* Rx. */
            if (read(fd, &tmp, sizeof(tmp)) == sizeof(tmp))
              rshim_net_rx(bd);
            break;
          } else if (fd == rshim_devs[index]->net_fd) {
            /* Tx. */
            rshim_net_tx(bd);
            break;
          }
        }
        if (index != RSHIM_MAX_DEV)
          continue;
      }
    }

    /* Delayed initialization for livefish probe. */
    if (!rshim_pcie_lf_init_done && !rshim_cmdmode) {
      time(&t1);
      if (difftime(t1, t0) > 3) {
        if (!rshim_backend_name)
          rshim_pcie_lf_init();
        rshim_pcie_lf_init_done = true;
      }
    } else {
      /* Disable the timer if no rshim devices are found. */
      if (rshim_dev_bitmask) {
        if (!rshim_timer_interval)
          rshim_set_timer(timer_fd, RSHIM_TIMER_INTERVAL);
      } else if (rshim_timer_interval) {
          rshim_set_timer(timer_fd, 0);
      }

      /* Check USB for timeout or unhandled fd. */
      rshim_usb_poll(rshim_dev_bitmask ? false : true);
    }
  }

  rshim_stop();
}

int rshim_fifo_size(rshim_backend_t *bd, int chan, bool is_rx)
{
  return is_rx ? read_cnt(bd, chan) : write_cnt(bd, chan);
}

int rshim_get_opn(rshim_backend_t *bd, char *opn, int len)
{
  uint32_t value32 = 0;
  uint64_t value64 = 0;
  int i, rc;

  if (len)
    opn[0] = 0;

  switch (bd->ver_id) {
  case RSHIM_BLUEFIELD_2:
    for (i = 0;
         i < RSHIM_YU_BOOT_RECORD_OPN_SIZE && len >= 4;
         i += 4, len -= 4) {
      rc = rshim_mmio_read32(bd, RSHIM_YU_BASE_ADDR +
                             RSHIM_YU_BOOT_RECORD_OPN + i, &value32);
      if (rc)
        return rc;
      value32 = le32toh(value32);
      opn[i] = (value32 >> 24) & 0xff;
      opn[i + 1] = (value32 >> 16) & 0xff;
      opn[i + 2] = (value32 >> 8) & 0xff;
      opn[i + 3] = value32 & 0xff;
    }
    break;

  case RSHIM_BLUEFIELD_3:
    for (i = 0;
         i < RSHIM_YU_BOOT_RECORD_OPN_SIZE && len >= 4;
         i += 4, len -= 4) {
      rc = bd->read_rshim(bd, YU_CHANNEL, RSHIM_YU_BF3_BOOT_RECORD_OPN + i,
                          &value64, RSHIM_REG_SIZE_4B);
      if (rc)
        return rc;
      value32 = value64 & 0xFFFFFFFF;
      value32 = le32toh(value32);
      opn[i] = (value32 >> 24) & 0xff;
      opn[i + 1] = (value32 >> 16) & 0xff;
      opn[i + 2] = (value32 >> 8) & 0xff;
      opn[i + 3] = value32 & 0xff;
    }
    break;

  default:
    return -EOPNOTSUPP;
  }

  return 0;
}

int rshim_set_opn(rshim_backend_t *bd, const char *opn, int len)
{
  uint32_t value32;
  uint64_t value64;
  int i, rc;

  switch (bd->ver_id) {
  case RSHIM_BLUEFIELD_2:
    for (i = 0;
         i < RSHIM_YU_BOOT_RECORD_OPN_SIZE && len >= 4;
         i += 4, len -= 4) {
      value32 = htole32((opn[i] << 24) | (opn[i + 1] << 16) | (opn[i + 2] << 8) |
                        opn[i + 3]);
      rc = rshim_mmio_write32(bd, RSHIM_YU_BASE_ADDR + RSHIM_YU_BOOT_RECORD_OPN + i,
                              value32);
      if (rc)
        return rc;
    }
    break;

  case RSHIM_BLUEFIELD_3:
    for (i = 0;
         i < RSHIM_YU_BOOT_RECORD_OPN_SIZE && len >= 4;
         i += 4, len -= 4) {
      value32 = htole32((opn[i] << 24) | (opn[i + 1] << 16) | (opn[i + 2] << 8) |
                        opn[i + 3]);
      value64 = value32;
      rc = bd->write_rshim(bd, YU_CHANNEL, RSHIM_YU_BF3_BOOT_RECORD_OPN + i,
                           value64, RSHIM_REG_SIZE_4B);
      if (rc)
        return rc;
    }
    break;

  default:
    return -EOPNOTSUPP;
  }

  return 0;
}

static int rshim_load_cfg(void)
{
  char key[32] = "", value[64] = "";
  char *buf = NULL;
  size_t n = 0;
  FILE *file;
  int index;

  file = fopen(rshim_cfg_file, "r");
  if (!file)
    return -ENOENT;

  while (getline(&buf, &n, file) != -1) {
    if (sscanf(buf, "%31s%63s", key, value) != 2)
      continue;

    if (!strcmp(key, "DISPLAY_LEVEL")) {
      rshim_display_level = atoi(value);
      continue;
    } else if (!strcmp(key, "BOOT_TIMEOUT")) {
      rshim_boot_timeout = atoi(value);
      continue;
    } else if (!strcmp(key, "DROP_MODE")) {
      rshim_drop_mode = (atoi(value) > 0) ? 1 : 0;
      continue;
    } else if (!strcmp(key, "FORCE_MODE")) {
      rshim_force_mode = (atoi(value) > 0) ? true : false;
      continue;
    } else if (!strcmp(key, "USB_TIMEOUT")) {
      rshim_usb_timeout = atoi(value);
      continue;
    } else if (!strcmp(key, "USB_RESET_DELAY")) {
      rshim_usb_reset_delay = atoi(value);
      rshim_has_usb_reset_delay = true;
      continue;
    } else if (!strcmp(key, "PCIE_RESET_DELAY")) {
      rshim_pcie_reset_delay = atoi(value);
      rshim_has_pcie_reset_delay = true;
      continue;
    } else if (!strcmp(key, "PCIE_INTR_POLL_INTERVAL")) {
      rshim_pcie_intr_poll_interval = atoi(value);
      continue;
    } else if (!strcmp(key, "PCIE_HAS_VFIO")) {
      rshim_pcie_enable_vfio = atoi(value);
      continue;
    } else if (!strcmp(key, "PCIE_HAS_UIO")) {
      rshim_pcie_enable_uio = atoi(value);
      continue;
    }

    if (strncmp(key, "rshim", 5) && strcmp(key, "none"))
      continue;

    if (strncmp(value, "usb-", 4) && strncmp(value, "pcie-", 5))
      continue;

    /* Blocked devices. */
    if (!strcmp(key, "none")) {
      for (index = 0; index < RSHIM_MAX_DEV; index++) {
        if (!rshim_blocked_dev_names[index]) {
          rshim_blocked_dev_names[index] = strdup(value);
          break;
        }
      }
      continue;
    }

    /* Static mapping of rshim device to index. */
    index = atoi(key + 5);
    if (index < 0 || index >= RSHIM_MAX_DEV)
      continue;
    if (rshim_dev_names[index])
      free(rshim_dev_names[index]);
    rshim_dev_names[index] = strdup(value);
  }

  if (buf)
    free(buf);
  fclose(file);

  return 0;
}

void rshim_sig_hup(int sig)
{
  rshim_backend_t *bd;
  int index;
  int i;

  for (index = 0; index != RSHIM_MAX_DEV; index++) {
    bd = rshim_devs[index];
    if (bd == NULL)
      continue;
    for (i = 0; i < TMFIFO_MAX_CHAN; i++) {
      pthread_cond_broadcast(&bd->read_fifo[i].operable);
      pthread_cond_broadcast(&bd->write_fifo[i].operable);
    }
  }
}

static void rshim_sig_handler(int sig)
{
  switch (sig) {
  case SIGHUP:
    rshim_sig_hup(sig);
    break;

  case SIGTERM:
    rshim_run = false;
    __sync_synchronize();
    rshim_work_signal(NULL);

    /* Wake up the thread to force to stop if stuck. */
    sem_post(&rshim_stop_sem);
    break;
  }
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

int create_pid_file(const char *pidfile)
{
  int fd;
  char buf[16];

  fd = open(pidfile, O_RDWR | O_CREAT, 0600);
  if (fd < 0) {
    RSHIM_ERR("Failed to open PID file\n");
    return -1;
  }

  if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
    if (errno == EWOULDBLOCK) {
      RSHIM_ERR("Another rshim instance is already running\n");
      close(fd);
      return -1;
    } else {
      RSHIM_ERR("Failed to lock PID file\n");
      close(fd);
      return -1;
    }
  }

  snprintf(buf, sizeof(buf), "%d\n", getpid());
  if (ftruncate(fd, 0) < 0 || write(fd, buf, strlen(buf)) < 0) {
    RSHIM_ERR("Failed to write to PID file\n");
    close(fd);
    return -1;
  }

  RSHIM_INFO("Created PID file: %s\n", pidfile);

  return fd;
}

void cleanup_pid_file(const char *pidfile, int fd)
{
    close(fd);
    unlink(pidfile);
}

static void print_help(void)
{
  printf("Usage: rshim [options]\n");
  printf("\n");
  printf("OPTIONS:\n");
  printf("  -b, --backend             backend name (usb, pcie or pcie-lf)\n");
  printf("  -c, --cmdmode             run in command line mode\n");
  printf("    -g, --get-debug         get debug mode\n");
  printf("    -s, --set-debug <0 | 1> set debug mode\n");
  printf("  -d, --device              device to attach\n");
  printf("  -f, --foreground          run in foreground\n");
  printf("  -F, --force               run in force mode\n");
  printf("  -i, --index               use device path /dev/rshim<i>/\n");
  printf("  -l, --log-level           log level");
  printf("(0:none, 1:error, 2:warning, 3:notice, 4:debug)\n");
  printf("  -n, --nonet               no network interface\n");
  printf("  -v, --version             version\n");
}

int main(int argc, char *argv[])
{
  static const char short_options[] = "b:cd:fgFhi:l:nsv";
  static struct option long_options[] = {
    { "backend", required_argument, NULL, 'b' },
    { "cmdmode", no_argument, NULL, 'c' },
    { "device", required_argument, NULL, 'd' },
    { "foreground", no_argument, NULL, 'f' },
    { "force", no_argument, NULL, 'F' },
    { "get-debug", no_argument, NULL, 'g' },
    { "help", no_argument, NULL, 'h' },
    { "index", required_argument, NULL, 'i' },
    { "log-level", required_argument, NULL, 'l' },
    { "nonet", no_argument, NULL, 'n' },
    { "set-debug", required_argument, NULL, 's' },
    { "version", no_argument, NULL, 'v' },
    { NULL, 0, NULL, 0 }
  };
  int c, rc, pid_fd = -1;
  pthread_t thread;

  /* Parse arguments. */
  while ((c = getopt_long(argc, argv, short_options, long_options, NULL))
         != -1) {
    switch (c) {
    case 'b':
      rshim_backend_name = optarg;
      break;
    case 'c':
      rshim_cmdmode = true;
      rshim_no_net = true;
      rshim_daemon_mode = false;
      rshim_log_level = LOG_ERR;
      break;
    case 'd':
      rshim_static_dev_name = optarg;
      break;
    case 'f':
      rshim_daemon_mode = false;
      break;
    case 'F':
      rshim_force_mode = true;
      break;
    case 'i':
      rshim_static_index = atoi(optarg);
      if (rshim_static_index >= RSHIM_MAX_DEV) {
        fprintf(stderr, "Index exceeds max value %d\n", RSHIM_MAX_DEV - 1);
        return -EINVAL;
      }
      break;
    case 'l':
      rshim_log_level = atoi(optarg);
      if (rshim_log_level == 1)
        rshim_log_level = LOG_ERR;
      else if (rshim_log_level == 2)
        rshim_log_level = LOG_WARNING;
      else if (rshim_log_level == 3)
        rshim_log_level = LOG_NOTICE;
      else if (rshim_log_level >= 4)
        rshim_log_level = LOG_DEBUG;
      break;
    case 'n':
      rshim_no_net = true;
      break;
    case 'v':
#if defined(PACKAGE_NAME) && defined(VERSION)
      printf(PACKAGE_NAME " " VERSION "\n");
#else
      printf("Rshim Driver for BlueField SoC 2.0\n");
#endif
      return 0;
    case 'h':
    default:
      if (!rshim_cmdmode) {
        print_help();
        return 0;
      }
    }
  }

  /* Put into daemon mode. */
  if (rshim_daemon_mode && !rshim_cmdmode) {
    int pid = fork();

    if (pid < 0) {
      perror("fork failed: %m\n");
      return -1;
    } else if (pid > 0) {
      return 0;
    }

    umask(0);
    if (setsid() < 0) {
      perror("setsid failed: %m\n");
      return -1;
    }
    signal(SIGCHLD, SIG_IGN);
    if (chdir("/") == -1)
      perror("chdir failed: %m\n");
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
  }

#ifdef HAVE_SYSLOG_H
  openlog("rshim", LOG_CONS, LOG_USER);
#endif

  /* Allow multiple instances in the following cases:
   *
   * 1. Command mode
   * 2. Direct device attachment ('-d')
   */
  if (!rshim_cmdmode && !rshim_static_dev_name) {
    // Single instance otherwise
    pid_fd = create_pid_file(PID_FILE);
    if (pid_fd < 0) {
      exit(EXIT_FAILURE);
    }
  }

  rshim_load_cfg();

  /* In force mode, we will send a one-time ownership request command for each
   * rshim backend if they are found to be detached (aka. in drop mode) */
  if (rshim_force_mode) {
    int i;

    for (i = 0; i < RSHIM_MAX_DEV; i++)
      rshim_force_cmd_pending[i] = 1;
  }

  set_signals();

  rc = pthread_create(&thread, NULL, rshim_stop_thread, NULL);
  if (rc) {
      RSHIM_ERR("Fail to create stop thread\n");
  }

  rshim_main(argc, argv);

  if (!rshim_cmdmode) {
    cleanup_pid_file(PID_FILE, pid_fd);
  }

  closelog();

  return 0;
}
