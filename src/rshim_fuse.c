// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright (C) 2019 Mellanox Technologies. All Rights Reserved.
 *
 */

#include <arpa/inet.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/timerfd.h>

#ifdef __linux__
#if FUSE_USE_VERSION >= 30
#include <fuse3/cuse_lowlevel.h>
#include <fuse3/fuse_opt.h>
#else
#include <fuse/cuse_lowlevel.h>
#include <fuse/fuse_opt.h>
#endif
#include <unistd.h>
#elif defined(__FreeBSD__)
#include <termios.h>
#include <sys/stat.h>
#include <sys/filio.h>
#include <cuse.h>
#else
#error "Unsupport OS for fuse"
#endif

#include "rshim.h"

/* Name of the sub-device types. */
char *rshim_dev_minor_names[RSH_DEV_TYPES] = {
    [RSH_DEV_TYPE_RSHIM] = "rshim",
    [RSH_DEV_TYPE_BOOT] = "boot",
    [RSH_DEV_TYPE_TMFIFO] = "console",
    [RSH_DEV_TYPE_MISC] = "misc",
};

/* BF3 ref clock. */
#define BF3_REF_CLK_IN_HZ 200000000

#ifdef __linux__
static void rshim_fuse_boot_open(fuse_req_t req, struct fuse_file_info *fi)
{
  rshim_backend_t *bd = fuse_req_userdata(req);
  int rc = -ENODEV;

  if (bd)
    rc = rshim_boot_open(bd);

  if (rc)
    fuse_reply_err(req, -rc);
  else
    fuse_reply_open(req, fi);
}
#elif defined(__FreeBSD__)
static int rshim_fuse_boot_open(struct cuse_dev *cdev, int fflags)
{
  rshim_backend_t *bd = cuse_dev_get_priv0(cdev);
  int rc;

  rc = rshim_boot_open(bd);

  switch (rc) {
  case 0:
    return CUSE_ERR_NONE;
  case -EBUSY:
    return CUSE_ERR_BUSY;
  case -ENODEV:
    return CUSE_ERR_INVALID;
  default:
    return CUSE_ERR_OTHER;
  }
}
#endif

#ifdef __linux__
static int rshim_fuse_copy_in(void *dest, const void *src, int count)
{
  memcpy(dest, src, count);
  return 0;
}

static void rshim_fuse_boot_write(fuse_req_t req, const char *user_buffer,
                                  size_t count, off_t off,
                                  struct fuse_file_info *fi)
{
  rshim_backend_t *bd = fuse_req_userdata(req);
  int rc = -ENODEV;

  if (bd)
    rc = rshim_boot_write(bd, user_buffer, count, rshim_fuse_copy_in);

  if (rc >= 0)
    fuse_reply_write(req, rc);
  else
    fuse_reply_err(req, -rc);
}
#elif defined(__FreeBSD__)
static int rshim_fuse_copy_in(void *dest, const void *src, int count)
{
  return cuse_copy_in(src, dest, count);
}

static int rshim_fuse_boot_write(struct cuse_dev *cdev, int fflags,
                                 const void *user_buffer, int count)
{
  rshim_backend_t *bd = cuse_dev_get_priv0(cdev);
  int rc;

  rc = rshim_boot_write(bd, user_buffer, count, rshim_fuse_copy_in);

  switch (rc) {
  case 0:
    return CUSE_ERR_NONE;
  case -EBUSY:
    return CUSE_ERR_BUSY;
  case -ENODEV:
    return CUSE_ERR_INVALID;
  default:
    return CUSE_ERR_OTHER;
  }
}
#endif

#ifdef __linux__
static void rshim_fuse_boot_release(fuse_req_t req, struct fuse_file_info *fi)
{
  rshim_backend_t *bd = fuse_req_userdata(req);

  if (bd) 
    rshim_boot_release(bd);

  fuse_reply_err(req, 0);
}
#elif defined(__FreeBSD__)
static int rshim_fuse_boot_release(struct cuse_dev *cdev, int fflags)
{
  rshim_backend_t *bd = cuse_dev_get_priv0(cdev);

  rshim_boot_release(bd);
  return CUSE_ERR_NONE;
}
#endif

#ifdef __linux__
static const struct cuse_lowlevel_ops rshim_boot_fops = {
  .open = rshim_fuse_boot_open,
  .write = rshim_fuse_boot_write,
  .release = rshim_fuse_boot_release,
};
#elif defined(__FreeBSD__)
static const struct cuse_methods rshim_boot_fops = {
  .cm_open = rshim_fuse_boot_open,
  .cm_write = rshim_fuse_boot_write,
  .cm_close = rshim_fuse_boot_release,
};
#endif

void rshim_fuse_input_notify(rshim_backend_t *bd)
{
  int chan = bd->rx_chan;

  RSHIM_DBG("rshim%d(fuse_input_notify) woke up readable chan %d\n",
            bd->index, chan);

#ifdef __linux__
  if (bd->fuse_poll_handle[chan])
    fuse_lowlevel_notify_poll(bd->fuse_poll_handle[chan]);
#elif defined(__FreeBSD__)
  cuse_poll_wakeup();
#endif
}

/* Console operations */

#ifdef __linux__
static void rshim_fuse_console_open(fuse_req_t req, struct fuse_file_info *fi)
{
  rshim_backend_t *bd = fuse_req_userdata(req);
  int rc = -ENODEV;

  if (bd)
    rc = rshim_console_open(bd);

  if (!rc)
    fuse_reply_open(req, fi);
  else
    fuse_reply_err(req, -rc);
}
#elif defined(__FreeBSD__)
static int rshim_fuse_console_open(struct cuse_dev *cdev, int fflags)
{
  rshim_backend_t *bd = cuse_dev_get_priv0(cdev);
  int rc;

  rc = rshim_console_open(bd);
  switch (rc) {
  case CUSE_ERR_NONE:
    return CUSE_ERR_NONE;
  case -EBUSY:
    return CUSE_ERR_BUSY;
  default:
    return CUSE_ERR_OTHER;
  }
}
#endif

#ifdef __linux__
static void rshim_fuse_console_read(fuse_req_t req, size_t size, off_t off,
                                    struct fuse_file_info *fi)
{
  rshim_backend_t *bd = fuse_req_userdata(req);
  char buf[512];
  int rc;

  if (!bd) {
    fuse_reply_err(req, ENODEV);
    return;
  }

  if (off) {
    fuse_reply_err(req, EINVAL);
    return;
  }

  if (size > sizeof(buf))
    size = sizeof(buf);

  rc = rshim_fifo_read(bd, buf, size, TMFIFO_CONS_CHAN,
                       fi->flags & O_NONBLOCK);
  if (rc < 0)
    fuse_reply_err(req, -rc);
  else
    fuse_reply_buf(req, buf, rc);
}
#elif defined(__FreeBSD__)
static int rshim_fuse_console_read(struct cuse_dev *cdev, int fflags,
                                   void *peer_ptr, int size)
{
  rshim_backend_t *bd = cuse_dev_get_priv0(cdev);
  bool nonblock = fflags & CUSE_FFLAG_NONBLOCK;
  char buf[4096];
  int len = 0;
  int delta;
  int err;
  int rc;

  while (size > 0) {
    delta = sizeof(buf);
    if (delta > size)
      delta = size;
    err = rshim_fifo_read(bd, buf, delta, TMFIFO_CONS_CHAN, nonblock);
    if (err < 0) {
      if (err == -EAGAIN) {
        if (len != 0)
          return len;
        else
          return CUSE_ERR_WOULDBLOCK;
      } else if (err == -EINTR) {
        if (len != 0)
          return len;
        else
          return CUSE_ERR_SIGNAL;
      } else {
        return CUSE_ERR_OTHER;
      }
    }
    rc = cuse_copy_out(buf, peer_ptr, err);
    if (rc != CUSE_ERR_NONE)
      return rc;

    size -= err;
    peer_ptr = (char *)peer_ptr + err;
    len += err;

    /* return on short read */
    if (err != delta)
      break;
  }
  return len;
}
#endif

#ifdef __linux__
static void rshim_fuse_console_write(fuse_req_t req, const char *buf,
                                     size_t size, off_t off,
                                     struct fuse_file_info *fi)
{
  rshim_backend_t *bd = fuse_req_userdata(req);
  int rc;

  if (!bd) {
    fuse_reply_err(req, ENODEV);
    return;
  }

  if (off) {
    fuse_reply_err(req, EINVAL);
    return;
  }

  rc = rshim_fifo_write(bd, buf, size, TMFIFO_CONS_CHAN,
                        fi->flags & O_NONBLOCK);
  if (rc >= 0)
    fuse_reply_write(req, rc);
  else
    fuse_reply_err(req, -rc);
}
#elif defined(__FreeBSD__)
static int rshim_fuse_console_write(struct cuse_dev *cdev, int fflags,
                                    const void *peer_ptr, int size)
{
  rshim_backend_t *bd = cuse_dev_get_priv0(cdev);
  char buf[4096];
  bool nonblock = fflags & CUSE_FFLAG_NONBLOCK;
  int len = 0;
  int rc;
  int err;

  while (size > 0) {
    rc = sizeof(buf);
    if (rc > size)
	rc = size;
    err = cuse_copy_in(peer_ptr, buf, rc);
    if (err != CUSE_ERR_NONE)
      return err;
    rc = rshim_fifo_write(bd, buf, rc, TMFIFO_CONS_CHAN, nonblock);
    if (rc < 0) {
      if (rc == -EAGAIN) {
        if (len != 0)
          return len;
        else
          return CUSE_ERR_WOULDBLOCK;
      } else if (rc == -EINTR) {
        if (len != 0)
          return len;
        else
         return CUSE_ERR_SIGNAL;
      } else {
        return CUSE_ERR_OTHER;
      }
    }
    size -= rc;
    peer_ptr = (char *)peer_ptr + rc;
    len += rc;
  }
  return len;
}
#endif

#ifdef __linux__
static void rshim_fuse_console_fsync(fuse_req_t req, int datasync,
                                     struct fuse_file_info *fi)
{
  rshim_backend_t *bd = fuse_req_userdata(req);
  int rc = -ENODEV;

  if (bd)
    rc = rshim_fifo_fsync(bd, TMFIFO_CONS_CHAN);

  fuse_reply_err(req, -rc);
}

static void rshim_fuse_console_ioctl(fuse_req_t req, int cmd, void *arg,
                                     struct fuse_file_info *fi,
                                     unsigned int flags, const void *in_buf,
                                     size_t in_bufsz, size_t out_bufsz)
{
  rshim_backend_t *bd = fuse_req_userdata(req);

  if (!bd) {
    fuse_reply_err(req, ENODEV);
    return;
  }

  pthread_mutex_lock(&bd->mutex);

  switch (cmd) {
  case TCGETS:
    if (!out_bufsz) {
      struct iovec iov = { arg, sizeof(struct termio) };

      fuse_reply_ioctl_retry(req, NULL, 0, &iov, 1);
    } else {
      fuse_reply_ioctl(req, 0, &bd->cons_termios, sizeof(struct termio));
    }
    break;

  case TCSETS:
  case TCSETSW:
  case TCSETSF:
    if (!in_bufsz) {
      struct iovec iov = {arg, sizeof(bd->cons_termios)};

      fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
    } else {
      memcpy(&bd->cons_termios, in_buf, sizeof(bd->cons_termios));
      fuse_reply_ioctl(req, 0, NULL, 0);
    }
    break;

  default:
    fuse_reply_err(req, ENOSYS);
    break;
  }

  pthread_mutex_unlock(&bd->mutex);
}
#elif defined(__FreeBSD__)
static int rshim_fuse_console_ioctl(struct cuse_dev *cdev, int fflags,
                                    unsigned long cmd, void *peer_data)
{
  rshim_backend_t *bd = cuse_dev_get_priv0(cdev);
  int rc = CUSE_ERR_INVALID;
  int value;

  pthread_mutex_lock(&bd->mutex);

  switch (cmd) {
  case TIOCGETA:
    rc = cuse_copy_out(&bd->cons_termios, peer_data,
                           sizeof(struct termios));
    break;

  case TIOCSETA:
  case TIOCSETAW:
  case TIOCSETAF:
    rc = cuse_copy_in(peer_data, &bd->cons_termios,
                          sizeof(struct termios));
    break;

  case TIOCEXCL:
  case TIOCNXCL:
  case FIONBIO:
  case FIOASYNC:
    rc = 0;
    break;

  case FIONREAD:
    pthread_mutex_lock(&bd->ringlock);
    value = rshim_fifo_size(bd, TMFIFO_CONS_CHAN, true) ? 1 : 0;
    pthread_mutex_unlock(&bd->ringlock);
    rc = cuse_copy_out(&value, peer_data, sizeof(value));
    break;

  default:
    break;
  }

  pthread_mutex_unlock(&bd->mutex);
  return rc;
}
#endif

#ifdef __linux__
static void rshim_fuse_console_poll(fuse_req_t req, struct fuse_file_info *fi,
                                    struct fuse_pollhandle *ph)
{
  rshim_backend_t *bd = fuse_req_userdata(req);
  unsigned int revents = 0;
  bool poll_rx = false, poll_tx = false, poll_err = false;

  if (!bd) {
    fuse_reply_err(req, ENODEV);
    return;
  }

  rshim_fifo_check_poll(bd, TMFIFO_CONS_CHAN, &poll_rx, &poll_tx, &poll_err);

  if (poll_rx)
    revents |= POLLIN | POLLRDNORM;

  if (poll_tx)
    revents |= POLLOUT | POLLWRNORM;

  if (poll_err)
    revents |= POLLERR;

  if (ph) {
    if (!bd->fuse_poll_handle[TMFIFO_CONS_CHAN])
      bd->fuse_poll_handle[TMFIFO_CONS_CHAN] = ph;
    else if (ph != bd->fuse_poll_handle[TMFIFO_CONS_CHAN])
      fuse_pollhandle_destroy(ph);
  }
  fuse_reply_poll(req, revents);
}
#elif defined(__FreeBSD__)
static int rshim_fuse_console_poll(struct cuse_dev *cdev, int fflags,
                                   int events)
{
  rshim_backend_t *bd = cuse_dev_get_priv0(cdev);
  unsigned int revents = 0;
  bool poll_rx = false, poll_tx = false, poll_err = false;

  rshim_fifo_check_poll(bd, TMFIFO_CONS_CHAN, &poll_rx, &poll_tx, &poll_err);

  if (poll_rx)
    revents |= CUSE_POLL_READ;

  if (poll_tx)
    revents |= CUSE_POLL_WRITE;

  if (poll_err)
    revents |= CUSE_POLL_ERROR;

  return revents;
}
#endif

#ifdef __linux__
static void rshim_fuse_poll_handle_destroy(rshim_backend_t *bd, int chan)
{
  if (bd->fuse_poll_handle[chan]) {
    fuse_pollhandle_destroy(bd->fuse_poll_handle[chan]);
    bd->fuse_poll_handle[chan] = NULL;
  }
}

static void rshim_fuse_console_release(fuse_req_t req,
                                       struct fuse_file_info *fi)
{
  rshim_backend_t *bd = fuse_req_userdata(req);

  if (bd)
    rshim_console_release(bd, rshim_fuse_poll_handle_destroy);

  fuse_reply_err(req, 0);
}
#elif defined(__FreeBSD__)
static int rshim_fuse_console_release(struct cuse_dev *cdev, int fflags)
{
  rshim_backend_t *bd = cuse_dev_get_priv0(cdev);

  rshim_console_release(bd, NULL);
  return CUSE_ERR_NONE;
}
#endif

#ifdef __linux__
static const struct cuse_lowlevel_ops rshim_console_fops = {
  .open = rshim_fuse_console_open,
  .read = rshim_fuse_console_read,
  .write = rshim_fuse_console_write,
  .fsync = rshim_fuse_console_fsync,
  .ioctl = rshim_fuse_console_ioctl,
  .poll = rshim_fuse_console_poll,
  .release = rshim_fuse_console_release,
};
#elif defined(__FreeBSD__)
static const struct cuse_methods rshim_console_fops = {
    .cm_open = rshim_fuse_console_open,
    .cm_read = rshim_fuse_console_read,
    .cm_write = rshim_fuse_console_write,
    .cm_ioctl = rshim_fuse_console_ioctl,
    .cm_poll = rshim_fuse_console_poll,
    .cm_close = rshim_fuse_console_release,
};
#endif

/* Misc file operations routines */

struct rshim_misc {
  char buffer[4069];
  off_t len;
  off_t offset;
  int ready;
};

#ifdef __linux__
static void rshim_fuse_misc_open(fuse_req_t req, struct fuse_file_info *fi)
{
  rshim_backend_t *bd = fuse_req_userdata(req);

  if (bd) {
    struct rshim_misc *ptr = calloc(1, sizeof(*ptr));

    fi->fh = (uintptr_t)ptr;
    fuse_reply_open(req, fi);
    rshim_ref(bd);
  } else {
    fuse_reply_err(req, ENODEV);
  }
}
#elif defined(__FreeBSD__)
static int rshim_fuse_misc_open(struct cuse_dev *cdev, int fflags)
{
  rshim_backend_t *bd = cuse_dev_get_priv0(cdev);
  struct rshim_misc *ptr = calloc(1, sizeof(*ptr));

  if (ptr == NULL)
    return CUSE_ERR_NO_MEMORY;
  cuse_dev_set_per_file_handle(cdev, ptr);
  rshim_ref(bd);
  return CUSE_ERR_NONE;
}
#endif

const char* bf3_bf_mode_str[] = {
  "Unknown",
  "DPU mode",
  "NIC mode",
  "Reserved"
};

const char* bf3_get_bf_mode(rshim_backend_t* bd) {
  uint64_t value;

  int rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->scratchpad2, &value,
                          RSHIM_REG_SIZE_8B);
  if (rc || RSHIM_BAD_CTRL_REG(value)) {
    RSHIM_ERR("rshim%d failed to read SCRATCHPAD2 (%d)\n", bd->index, rc);
    return bf3_bf_mode_str[0];
  }
  return bf3_bf_mode_str[BF3_RSH_SCRATCHPAD2__BF_MODE(value)];
}

#ifdef __linux__
static void rshim_fuse_misc_read(fuse_req_t req, size_t size, off_t off,
                                 struct fuse_file_info *fi)
#elif defined(__FreeBSD__)
static int rshim_fuse_misc_read(struct cuse_dev *cdev, int fflags,
                                void *peer_ptr, int size)
#endif
{
#ifdef __linux__
  rshim_backend_t *bd = fuse_req_userdata(req);
  struct rshim_misc *rm = (void *)(uintptr_t)fi->fh;
#elif defined(__FreeBSD__)
  rshim_backend_t *bd = cuse_dev_get_priv0(cdev);
  struct rshim_misc *rm = cuse_dev_get_per_file_handle(cdev);
  off_t off;
#endif
  char opn[RSHIM_YU_BOOT_RECORD_OPN_SIZE + 1] = "";
  uint8_t *mac = bd->peer_mac;
  int rc, len = sizeof(rm->buffer), n;
  struct timespec ts;
  struct timeval tp;
  uint64_t value;
  char *p;

  if (rm->ready) {
#ifdef __linux__
    fuse_reply_buf(req, NULL, 0);
    return;
#elif defined(__FreeBSD__)
    goto ready;
#endif
  }
  rm->ready = 1;

  if (!bd) {
#ifdef __linux__
    fuse_reply_err(req, ENODEV);
    return;
#elif defined(__FreeBSD__)
    return CUSE_ERR_INVALID;
#endif
  }

  pthread_mutex_lock(&bd->mutex);

  /* Boot mode. */
  rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->boot_control, &value,
                      RSHIM_REG_SIZE_8B);
  if (rc) {
    RSHIM_ERR("rshim%d failed to read BOOT_CONTROL(%d)\n", bd->index, rc);
    value = 0;
  }

  p = rm->buffer;

  n = snprintf(p, len, "%-16s%d (0:basic, 1:advanced, 2:log)\n",
               "DISPLAY_LEVEL", bd->display_level);
  p += n;
  len -= n;

  if (bd->ver_id == RSHIM_BLUEFIELD_3) {
    n = snprintf(p, len, "%-16s%s\n",
        "BF_MODE",
        bf3_get_bf_mode(bd));
    p += n;
    len -= n;
  }

  n = snprintf(p, len, "%-16s%lld (0:rshim, 1:emmc, 2:emmc-boot-swap)\n",
               "BOOT_MODE",
               (unsigned long long)value & RSH_BOOT_CONTROL__BOOT_MODE_MASK);
  p += n;
  len -= n;

  n = snprintf(p, len, "%-16s%d (seconds)\n", "BOOT_TIMEOUT",
               bd->boot_timeout);
  p += n;
  len -= n;

  n = snprintf(p, len, "%-16s%d (seconds)\n", "USB_TIMEOUT",
               rshim_usb_timeout);
  p += n;
  len -= n;

  n = snprintf(p, len, "%-16s%d (0:normal, 1:drop)\n", "DROP_MODE",
               bd->drop_mode);
  p += n;
  len -= n;

  /* SW reset flag is always 0. */
  n = snprintf(p, len, "%-16s%d (1: reset)\n", "SW_RESET", 0);
  p += n;
  len -= n;

  /* Display the driver name. */
  n = snprintf(p, len, "%-16s%s\n", "DEV_NAME", bd->dev_name);
  p += n;
  len -= n;

  /* Display device info. */
  n = snprintf(p, len, "%-16sBlueField-%d(Rev %d)\n", "DEV_INFO", bd->ver_id,
               bd->rev_id);
  p += n;
  len -= n;

  /* Display OPN info (for BlueField-2 and above). */
  if (bd->ver_id >= RSHIM_BLUEFIELD_2) {
    rshim_get_opn(bd, opn, RSHIM_YU_BOOT_RECORD_OPN_SIZE);
    if (!strlen(opn))
      strcpy(opn, "N/A");
    n = snprintf(p, len, "%-16s%s\n", "OPN_STR", opn);
    p += n;
    len -= n;
  }

  if (bd->ver_id == RSHIM_BLUEFIELD_3) {
    rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->uptime,
                        &value, RSHIM_REG_SIZE_8B);
    if (!rc) {
      n = snprintf(p, len, "%-16s%lld(s)\n", "UP_TIME",
                   (unsigned long long)value/BF3_REF_CLK_IN_HZ);
      p += n;
      len -= n;
    }

    n = snprintf(p, len, "%-16s%d (0:no, 1:yes)\n", "SECURE_NIC_MODE",
                 bd->locked_mode);
    p += n;
    len -= n;
  }

  n = snprintf(p, len, "%-16s%d (1: send Force command)\n", "FORCE_CMD",
      rshim_force_cmd_pending[bd->index]);
  p += n;
  len -= n;

  if (bd->display_level == 1) {
    gettimeofday(&tp, NULL);

    /* Skip SW_RESET while pushing boot stream. */
    n = snprintf(p, len, "%-16s%d (1: skip)\n", "BOOT_RESET_SKIP",
                 bd->skip_boot_reset);
    p += n;
    len -= n;

    /*
     * Display the target-side information. Send a request and wait for
     * some time for the response.
     */
    bd->peer_ctrl_req = 1;
    bd->peer_ctrl_resp = 0;
    memset(mac, 0, 6);
    bd->has_cons_work = 1;
    rshim_work_signal(bd);

    ts.tv_sec  = tp.tv_sec + 1;
    ts.tv_nsec = tp.tv_usec * 1000;
    rc = pthread_cond_timedwait(&bd->ctrl_wait_cond, &bd->mutex, &ts);
    if (rc)
      RSHIM_DBG("rshim%d timeout in getting peer response\n", bd->index);
    n = snprintf(p, len, "%-16s%02x:%02x:%02x:%02x:%02x:%02x (rw)\n",
                   "PEER_MAC", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    p += n;
    len -= n;

    n = snprintf(p, len, "%-16s0x%08x (rw)\n",
                   "PXE_ID", htonl(bd->pxe_client_id));
    p += n;
    len -= n;

    n = snprintf(p, len, "%-16s%d %d (rw)\n",
                   "VLAN_ID", bd->vlan[0], bd->vlan[1]);
    p += n;
    len -= n;

    n = snprintf(p, len, "%-16s%d (0:no, 1:yes)\n", "CLEAR_ON_READ",
                 bd->clear_on_read);
    p += n;
  } else if (bd->display_level == 2) {
    n = rshim_log_show(bd, p, len);
    p += n;
  }

  rm->len = p - rm->buffer;

#ifdef __linux__
  if (size > (int)(rm->len - off))
    size = rm->len - off;
  pthread_mutex_unlock(&bd->mutex);
  fuse_reply_buf(req, rm->buffer + off, size);
  return;
#elif defined(__FreeBSD__)
ready:
  if (size > (int)(rm->len - rm->offset))
    size = rm->len - rm->offset;
  off = rm->offset;
  rm->offset += size;
  pthread_mutex_unlock(&bd->mutex);
  rc = cuse_copy_out(rm->buffer + off, peer_ptr, size);
  if (rc != CUSE_ERR_NONE)
    return rc;
  else
    return size;
#endif
}

#ifdef __linux__
static void rshim_fuse_misc_write(fuse_req_t req, const char *user_buffer,
                                  size_t size, off_t off,
                                  struct fuse_file_info *fi)
#elif defined(__FreeBSD__)
static int rshim_fuse_misc_write(struct cuse_dev *cdev, int fflags,
                                 const void *user_buffer, int size)
#endif
{
  char buf[4096];
#ifdef __linux__
  rshim_backend_t *bd = fuse_req_userdata(req);
  const char *p = buf;
#elif defined(__FreeBSD__)
  rshim_backend_t *bd = cuse_dev_get_priv0(cdev);
  const char *p = buf;
#endif
  int i, rc = 0, value = 0, mac[6], vlan[2] = {0};
  char opn[RSHIM_YU_BOOT_RECORD_OPN_SIZE + 1] = "";
  uint64_t val64 = 0;
  char key[32];

  if (!bd) {
#ifdef __linux__
    fuse_reply_err(req, ENODEV);
    return;
#elif defined(__FreeBSD__)
    return CUSE_ERR_INVALID;
#endif
  }

  if (size >= sizeof(buf))
    size = sizeof(buf) - 1;
#ifdef __linux__
  if (off)
    goto invalid;
  memcpy(buf, user_buffer, size);
#elif defined(__FreeBSD__)
  rc = cuse_copy_in(user_buffer, buf, size);
  if (rc != CUSE_ERR_NONE)
    return rc;
#endif
  buf[size] = 0;

  if (sscanf(buf, "%s", key) != 1)
    goto invalid;

  p += strlen(key);

  if (strcmp(key, "DISPLAY_LEVEL") == 0) {
    if (sscanf(p, "%d", &value) != 1)
      goto invalid;
    bd->display_level = value;
  } else if (strcmp(key, "BOOT_TIMEOUT") == 0) {
    if (sscanf(p, "%d", &value) != 1)
      goto invalid;
    bd->boot_timeout = value;
  } else if (strcmp(key, "USB_TIMEOUT") == 0) {
    if (sscanf(p, "%d", &value) != 1)
      goto invalid;
    if (value < 0 || value > 300)
      goto invalid;
    if (value == 0) {
      // restore default value
      rshim_usb_timeout = RSHIM_USB_TIMEOUT;
    } else {
      rshim_usb_timeout = value;
    }
  } else if (strcmp(key, "DROP_MODE") == 0) {
    if (sscanf(p, "%d", &value) != 1)
      goto invalid;
    rc = rshim_set_drop_mode(bd, value);
  } else if (strcmp(key, "CLEAR_ON_READ") == 0) {
    if (sscanf(p, "%d", &value) != 1)
      goto invalid;
    bd->clear_on_read = !!value;
  } else if (strcmp(key, "BOOT_MODE") == 0) {
    if (sscanf(p, "%x", &value) != 1)
      goto invalid;

    pthread_mutex_lock(&bd->mutex);
    rc = bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->boot_control,
                         value & RSH_BOOT_CONTROL__BOOT_MODE_MASK,
                         RSHIM_REG_SIZE_8B);
    pthread_mutex_unlock(&bd->mutex);
  } else if (strcmp(key, "SW_RESET") == 0) {
    if (sscanf(p, "%x", &value) != 1)
      goto invalid;

    if (value) {
      if (!bd->has_reprobe) {
        /* Detach, which shouldn't hold bd->mutex. */
        rshim_notify(bd, RSH_EVENT_DETACH, 0);

        pthread_mutex_lock(&bd->mutex);
        /* Reset the TmFifo. */
        rshim_fifo_reset(bd);
        bd->is_booting = 1;
        pthread_mutex_unlock(&bd->mutex);
      }

      /* SW reset. */
      RSHIM_INFO("rshim%d SW RESET\n", bd->index);
      pthread_mutex_lock(&bd->mutex);
      rc = rshim_reset_control(bd);
      pthread_mutex_unlock(&bd->mutex);

      if (!bd->has_reprobe) {
        /* Attach. */
        sleep(bd->reset_delay);
        pthread_mutex_lock(&bd->mutex);
        bd->is_booting = 0;
        rshim_notify(bd, RSH_EVENT_ATTACH, 0);
        pthread_mutex_unlock(&bd->mutex);
      }
    }
  } else if (strcmp(key, "BOOT_RESET_SKIP") == 0) {
    if (sscanf(p, "%x", &value) != 1)
      goto invalid;
    bd->skip_boot_reset = !!value;
  } else if (strcmp(key, "PEER_MAC") == 0) {
    if (sscanf(p, "%x:%x:%x:%x:%x:%x",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6)
      goto invalid;
    pthread_mutex_lock(&bd->mutex);
    for (i = 0; i < 6; i++)
      bd->peer_mac[i] = mac[i];
    bd->peer_mac_set = 1;
    bd->has_cons_work = 1;
    rshim_work_signal(bd);
    pthread_mutex_unlock(&bd->mutex);
  } else if (strcmp(key, "PXE_ID") == 0) {
    if (sscanf(p, "%x", &value) != 1)
      goto invalid;
    pthread_mutex_lock(&bd->mutex);
    bd->pxe_client_id = ntohl(value);
    bd->peer_pxe_id_set = 1;
    bd->has_cons_work = 1;
    rshim_work_signal(bd);
    pthread_mutex_unlock(&bd->mutex);
  } else if (strcmp(key, "VLAN_ID") == 0) {
    if (sscanf(p, "%d %d", &vlan[0], &vlan[1]) == EOF)
      goto invalid;
    pthread_mutex_lock(&bd->mutex);
    bd->vlan[0] = vlan[0];
    bd->vlan[1] = vlan[1];
    bd->peer_vlan_set = 1;
    bd->has_cons_work = 1;
    rshim_work_signal(bd);
    pthread_mutex_unlock(&bd->mutex);
  } else if (!strcmp(key, "OPN_STR")) {
    if (sscanf(p, "%16s", opn) != 1)
      goto invalid;
    rshim_set_opn(bd, opn, RSHIM_YU_BOOT_RECORD_OPN_SIZE);
  } else if (!strcmp(key, "DEBUG_CODE")) {
    if (sscanf(p, " 0x%llx", (unsigned long long *)&val64) != 1)
      goto invalid;
    pthread_mutex_lock(&bd->mutex);
    rc = bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->scratchpad1,
                         val64, RSHIM_REG_SIZE_8B);
    if (!rc)
      bd->debug_code = val64;
    pthread_mutex_unlock(&bd->mutex);
  } else if (strcmp(key, "FORCE_CMD") == 0) {
    if (sscanf(p, "%x", &value) != 1)
      goto invalid;
    if (value) {
      if (!bd->drop_mode)
        rc = -EINVAL;
      else
        rshim_force_cmd_pending[bd->index] = 1;
    }
  } else {
invalid:
#ifdef __linux__
    fuse_reply_err(req, EINVAL);
    return;
#elif defined(__FreeBSD__)
    return CUSE_ERR_INVALID;
#endif
  }

#ifdef __linux__
  if (!rc)
    fuse_reply_write(req, size);
  else
    fuse_reply_err(req, -rc);
#elif defined(__FreeBSD__)
  return size;
#endif
}

#ifdef __linux__
static void rshim_fuse_misc_release(fuse_req_t req, struct fuse_file_info *fi)
{
  rshim_backend_t *bd = fuse_req_userdata(req);

  free((void *)(uintptr_t)fi->fh);
  fuse_reply_err(req, 0);

  if (bd)
    rshim_deref(bd);
}
#elif defined(__FreeBSD__)
static int rshim_fuse_misc_release(struct cuse_dev *cdev, int fflags)
{
  rshim_backend_t *bd = cuse_dev_get_priv0(cdev);
  struct rshim_misc *rm = cuse_dev_get_per_file_handle(cdev);

  free(rm);
  if (bd)
    rshim_deref(bd);
  return CUSE_ERR_NONE;
}
#endif

#ifdef __linux__
static const struct cuse_lowlevel_ops rshim_misc_fops = {
  .open = rshim_fuse_misc_open,
  .read = rshim_fuse_misc_read,
  .write = rshim_fuse_misc_write,
  .release = rshim_fuse_misc_release,
};
#elif defined(__FreeBSD__)
static const struct cuse_methods rshim_misc_fops = {
  .cm_open = rshim_fuse_misc_open,
  .cm_read = rshim_fuse_misc_read,
  .cm_write = rshim_fuse_misc_write,
  .cm_close = rshim_fuse_misc_release,
};
#endif

/* Rshim file operations routines */

/* ioctl message header. */
typedef struct {
  uint32_t addr;
  uint64_t data;
} __attribute__((packed)) rshim_ioctl_msg;

/* ioctl message header for Mustang. Unlike BF1 and BF2, Mustang
 * HW enables different USB transfer sizes: 1B, 2B, 4B and 8B.
 */
typedef struct {
  uint32_t addr;
  uint64_t data;
  uint8_t data_size;
} __attribute__((packed)) rshim_ioctl_msg2;

enum {
  RSHIM_IOC_READ = _IOWR('R', 0, rshim_ioctl_msg),
  RSHIM_IOC_WRITE = _IOWR('R', 1, rshim_ioctl_msg),
  RSHIM_IOC_READ2 = _IOWR('R', 0, rshim_ioctl_msg2),
  RSHIM_IOC_WRITE2 = _IOWR('R', 1, rshim_ioctl_msg2),
};

#ifdef __linux__
static void rshim_fuse_rshim_ioctl(fuse_req_t req, int cmd, void *arg,
                                   struct fuse_file_info *fi,
                                   unsigned int flags, const void *in_buf,
                                   size_t in_bufsz, size_t out_bufsz)
{
  rshim_backend_t *bd = fuse_req_userdata(req);
  rshim_ioctl_msg msg;
  rshim_ioctl_msg2 msg2;
  struct iovec iov;
  uint64_t data = 0;
  uint16_t chan, offset;
  int rc = 0;

  if (!bd) {
    fuse_reply_err(req, ENODEV);
    return;
  }

  switch (cmd) {
  case RSHIM_IOC_READ:
  case RSHIM_IOC_WRITE:
    iov.iov_base = arg;
    iov.iov_len = sizeof(msg);

    if (!in_bufsz) {
      fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
      return;
    }

    if (in_bufsz != sizeof(msg)) {
      fuse_reply_err(req, EINVAL);
      return;
    }

    if (!out_bufsz) {
      fuse_reply_ioctl_retry(req, &iov, 1, &iov, 1);
      return;
    }

    memcpy(&msg, in_buf, sizeof(msg));

    /*
     * Get channel and offset from the 32-bit address.
     * For BlueField-3 USB, it also supports passing the linear CR-space
     * address where upper 16-bit is saved in 'chan' and lower 16-bit is
     * saved in 'offset'.
     */
    chan = msg.addr >> 16;
    offset = msg.addr & 0xFFFF;
    if ((bd->ver_id <= RSHIM_BLUEFIELD_2) || (bd->type != RSH_BACKEND_USB))
      chan &= 0xF;

    if (cmd == RSHIM_IOC_WRITE) {
      pthread_mutex_lock(&bd->mutex);
      rc = bd->write_rshim(bd, chan, offset, msg.data, RSHIM_REG_SIZE_8B);
      pthread_mutex_unlock(&bd->mutex);
    } else {
      pthread_mutex_lock(&bd->mutex);
      rc = bd->read_rshim(bd, chan, offset, &data, RSHIM_REG_SIZE_8B);
      msg.data = data;
      pthread_mutex_unlock(&bd->mutex);
    }

    if (!rc)
      fuse_reply_ioctl(req, 0, &msg, sizeof(msg));
    else
      fuse_reply_err(req, -rc);
    break;

  case RSHIM_IOC_READ2:
  case RSHIM_IOC_WRITE2:
    iov.iov_base = arg;
    iov.iov_len = sizeof(msg2);

    if (!in_bufsz) {
      fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
      return;
    }

    if (in_bufsz != sizeof(msg2)) {
      fuse_reply_err(req, EINVAL);
      return;
    }

    if (!out_bufsz) {
      fuse_reply_ioctl_retry(req, &iov, 1, &iov, 1);
      return;
    }

    memcpy(&msg2, in_buf, sizeof(msg2));

    /*
     * Get channel and offset from the 32-bit address.
     * For BlueField-3 USB, it also supports passing the linear CR-space
     * address where upper 16-bit is saved in 'chan' and lower 16-bit is
     * saved in 'offset'.
     */
    chan = msg2.addr >> 16;
    offset = msg2.addr & 0xFFFF;
    if (bd->ver_id <= RSHIM_BLUEFIELD_2)
      chan &= 0xF;

    if (cmd == RSHIM_IOC_WRITE2) {
      pthread_mutex_lock(&bd->mutex);
      rc = bd->write_rshim(bd, chan, offset, msg2.data, msg2.data_size);
      pthread_mutex_unlock(&bd->mutex);
    } else {
      pthread_mutex_lock(&bd->mutex);
      rc = bd->read_rshim(bd, chan, offset, &data, msg2.data_size);
      msg2.data = data;
      pthread_mutex_unlock(&bd->mutex);
    }

    if (!rc)
      fuse_reply_ioctl(req, 0, &msg2, sizeof(msg2));
    else
      fuse_reply_err(req, -rc);
    break;

  default:
    fuse_reply_err(req, ENOSYS);
    break;
  }
}
#elif defined(__FreeBSD__)
static int rshim_fuse_rshim_ioctl(struct cuse_dev *cdev, int fflags,
                                  unsigned long cmd, void *peer_data)
{
  rshim_backend_t *bd = cuse_dev_get_priv0(cdev);
  int rc = CUSE_ERR_INVALID;
  rshim_ioctl_msg msg;
  rshim_ioctl_msg2 msg2;
  uint64_t data;

  pthread_mutex_lock(&bd->mutex);

  switch (cmd) {
  case RSHIM_IOC_READ:
    rc = cuse_copy_in(peer_data, &msg, sizeof(msg));
    if (rc == CUSE_ERR_NONE) {
      data = msg.data;
      rc = bd->read_rshim(bd,
                           (msg.addr >> 16) & 0xF, /* channel # */
                           msg.addr & 0xFFFF, /* addr */
                           &data, RSHIM_REG_SIZE_8B);
      if (!rc)
        rc = cuse_copy_out(&msg, peer_data, sizeof(msg));
      else
        rc = CUSE_ERR_INVALID;
    }
    break;

  case RSHIM_IOC_WRITE:
    rc = cuse_copy_in(peer_data, &msg, sizeof(msg));

    rc = bd->write_rshim(bd,
                         (msg.addr >> 16) & 0xF, /* channel # */
                         msg.addr & 0xFFFF, /* addr */
                         msg.data, RSHIM_REG_SIZE_8B);
    if (rc)
      rc = CUSE_ERR_INVALID;
    break;

  case RSHIM_IOC_READ2:
    rc = cuse_copy_in(peer_data, &msg2, sizeof(msg2));
    if (rc == CUSE_ERR_NONE) {
      data = msg2.data;
      rc = bd->read_rshim(bd,
                           msg2.addr >> 16, /* channel # */
                           msg2.addr & 0xFFFF, /* addr */
                           &data, msg2.data_size);
      if (!rc)
        rc = cuse_copy_out(&msg2, peer_data, sizeof(msg2));
      else
        rc = CUSE_ERR_INVALID;
    }
    break;

  case RSHIM_IOC_WRITE2:
    rc = cuse_copy_in(peer_data, &msg2, sizeof(msg2));

    rc = bd->write_rshim(bd,
                         msg2.addr >> 16, /* channel # */
                         msg2.addr & 0xFFFF, /* addr */
                         msg2.data, msg2.data_size);
    if (rc)
      rc = CUSE_ERR_INVALID;
    break;

  default:
    break;
  }

  pthread_mutex_unlock(&bd->mutex);
  return rc;
}
#endif

int rshim_fuse_got_peer_signal(void)
{
#if defined(__FreeBSD__)
  return cuse_got_peer_signal();
#else
  return -1;
#endif
}

#ifdef __linux__
static const struct cuse_lowlevel_ops rshim_rshim_fops = {
  .open = rshim_fuse_misc_open,
  .ioctl = rshim_fuse_rshim_ioctl,
  .release = rshim_fuse_misc_release,
};
#elif defined(__FreeBSD__)
static const struct cuse_methods rshim_rshim_fops = {
  .cm_open = rshim_fuse_misc_open,
  .cm_ioctl = rshim_fuse_rshim_ioctl,
  .cm_close = rshim_fuse_misc_release,
};
#endif

static void *cuse_worker(void *arg)
{
#ifdef __linux__
  struct fuse_session *se = arg;
  int rc;

  rc = fuse_session_loop(se);
  fuse_session_destroy(se);

  return (void *)(unsigned long)rc;
#elif defined(__FreeBSD__)
  signal(SIGHUP, &rshim_sig_hup);

  while (cuse_wait_and_process() == CUSE_ERR_NONE)
    ;
  return NULL;
#endif
}

int rshim_fuse_init(rshim_backend_t *bd)
{
  char buf[128], *name;
#ifdef __linux__
  time_t t0, t1;
  const char *bufp[] = {buf};
  struct cuse_info ci = {.dev_info_argc = 1,
                         .dev_info_argv = bufp,
                         .flags = CUSE_UNRESTRICTED_IOCTL};
  static const struct cuse_lowlevel_ops *ops[RSH_DEV_TYPES] =
#elif defined(__FreeBSD__)
  static const struct cuse_methods *ops[RSH_DEV_TYPES] =
#endif
  {
                          [RSH_DEV_TYPE_BOOT] = &rshim_boot_fops,
                          [RSH_DEV_TYPE_TMFIFO] = &rshim_console_fops,
                          [RSH_DEV_TYPE_RSHIM] = &rshim_rshim_fops,
                          [RSH_DEV_TYPE_MISC] = &rshim_misc_fops,
                          };
  int i, rc;

#if defined(__FreeBSD__)
  if (cuse_init() != CUSE_ERR_NONE)
    return -1;
#endif

  for (i = 0; i < RSH_DEV_TYPES; i++) {
#ifdef __linux__
    static const char * const argv[] = {"./rshim", "-f"};
    int multithreaded = 0;

    name = rshim_dev_minor_names[i];

    /*
     * Check whether path already exists. Adding a loop in case the
     * device was re-ceated during SW_RESET.
     */
    snprintf(buf, sizeof(buf), "/dev/rshim%d/%s", bd->index, name);
    time(&t0);
    while (!access(buf, F_OK)) {
      time(&t1);
      if (difftime(t1, t0) > 5) {
        RSHIM_ERR("%s already exists\n", buf);
        return -1;
      }
    }
    snprintf(buf, sizeof(buf), "DEVNAME=rshim%d/%s", bd->index, name);
    if (!ops[i])
      continue;
    bd->fuse_session[i] = cuse_lowlevel_setup(sizeof(argv)/sizeof(char *),
                                      (char **)argv,
                                      &ci, ops[i], &multithreaded, bd);
    if (!bd->fuse_session[i]) {
      RSHIM_ERR("rshim%d failed to setup CUSE %s\n", bd->index, name);
      return -1;
    }
    fuse_remove_signal_handlers(bd->fuse_session[i]);
    rc = pthread_create(&bd->fuse_thread[i], NULL, cuse_worker,
                        bd->fuse_session[i]);
    if (rc) {
      RSHIM_ERR("rshim%d failed to create cuse thread\n", bd->index);
      return rc;
    }
#elif defined(__FreeBSD__)
    name = rshim_dev_minor_names[i];
    snprintf(buf, sizeof(buf), "rshim%d/%s", bd->index, name);
    if (!ops[i])
      continue;
    bd->fuse_session[i] =
      cuse_dev_create(ops[i], bd, NULL, 0 /* UID_ROOT */, 0 /* GID_WHEEL */,
                      0600, "rshim%d/%s", bd->index, name);
    if (!bd->fuse_session[i]) {
      RSHIM_ERR("rshim%d failed to setup CUSE %s\n", bd->index, name);
      return -1;
    }
    rc = pthread_create(&bd->fuse_thread[i], NULL, cuse_worker,
                        bd->fuse_session[i]);
    if (rc) {
      RSHIM_ERR("rshim%d failed to create cuse thread\n", bd->index);
      return rc;
    }
#endif
  }

  return 0;
}

int rshim_fuse_del(rshim_backend_t *bd)
{
  int i;

  for (i = 0; i < RSH_DEV_TYPES; i++) {
    if (bd->fuse_session[i]) {
#ifdef __linux__
      fuse_session_exit(bd->fuse_session[i]);
#elif defined(__FreeBSD__)
      cuse_dev_destroy(bd->fuse_session[i]);
#endif
      bd->fuse_session[i] = NULL;
    }
  }

  for (i = 0; i < RSH_DEV_TYPES; i++) {
    if (bd->fuse_thread[i]) {
      pthread_kill(bd->fuse_thread[i], SIGINT);
      pthread_join(bd->fuse_thread[i], NULL);
      bd->fuse_thread[i] = 0;
    }
  }
  return 0;
}
