/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright (C) 2019-2023 Mellanox Technologies. All Rights Reserved.
 *
 */

#ifndef _RSHIM_H
#define _RSHIM_H

#ifdef __linux__
#include <endian.h>
#else
#include <sys/endian.h>
#endif
#include <errno.h>
#include <fcntl.h>
#ifdef __linux__
#include <linux/virtio_ids.h>
#else
#define	VIRTIO_ID_NET 1
#define	VIRTIO_ID_CONSOLE 3
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#include "rshim_regs.h"

/* Global variables. */
extern int rshim_log_level;
extern bool rshim_daemon_mode;
extern int rshim_drop_mode;
extern bool rshim_force_mode;
extern int rshim_usb_timeout;
extern int rshim_usb_reset_delay;
extern bool rshim_has_usb_reset_delay;
extern int rshim_pcie_reset_delay;
extern bool rshim_has_pcie_reset_delay;
extern int rshim_pcie_intr_poll_interval;
extern int rshim_pcie_enable_vfio;
extern int rshim_pcie_enable_uio;
extern bool rshim_force_cmd_pending[];
extern bool rshim_cmdmode;
extern int rshim_static_index;

#ifndef offsetof
#define offsetof(TYPE, MEMBER)	((size_t)&((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({ \
  void *__mptr = (void *)(ptr); \
  ((type *)(__mptr - offsetof(type, member))); })
#endif

#ifdef HAVE_SYSLOG_H
#define RSHIM_SYSLOG(level, fmt...) syslog(level, fmt)
#else
#define LOG_ERR 1
#define LOG_WARNING 2
#define LOG_NOTICE 3
#define LOG_DEBUG 4
#define RSHIM_SYSLOG(level, fmt...)
#endif

#define RSHIM_LOG(log_level, fmt...) do { \
  if (rshim_log_level >= log_level) { \
    if (rshim_daemon_mode) \
      RSHIM_SYSLOG(log_level, fmt); \
    else \
      printf(fmt); \
  } \
} while (0)

#define RSHIM_ERR(fmt...)      RSHIM_LOG(LOG_ERR, fmt)
#define RSHIM_WARN(fmt...)     RSHIM_LOG(LOG_WARNING, fmt)
#define RSHIM_INFO(fmt...)     RSHIM_LOG(LOG_NOTICE, fmt)
#define RSHIM_DBG(fmt...)      RSHIM_LOG(LOG_DEBUG, fmt)

/* Spin flag values. */
#define RSH_SFLG_READING    0x1  /* read is active. */
#define RSH_SFLG_WRITING    0x2  /* write_urb is active. */
#define RSH_SFLG_CONS_OPEN  0x4  /* console stream is open. */

/*
 * Buffer/FIFO sizes.  Note that the FIFO sizes must be powers of 2; also,
 * the read and write buffers must be no larger than the corresponding
 * FIFOs.
 */
#define READ_BUF_SIZE     2048
#define WRITE_BUF_SIZE    2048
#define READ_FIFO_SIZE    (4 * 1024)
#define WRITE_FIFO_SIZE   (4 * 1024)
#define BOOT_BUF_SIZE     (16 * 1024)

#define BF3_MAX_BOOT_FIFO_SIZE 8192 /* bytes */

/*
 * Possible error code during resetting, which can be used to check against
 * registers with known values.
 */
#define RSHIM_BAD_CTRL_REG(v) \
  (((v) == 0xbad00acce55) || ((v) == (uint64_t)-1) || ((v) == 0xbadacce55))

/* Backend type. */
typedef enum {
  RSH_BACKEND_NONE,
  RSH_BACKEND_USB,
  RSH_BACKEND_PCIE,
  RSH_BACKEND_PCIE_LF
} rshim_backend_type_t;

/* Sub-device types. */
enum {
  RSH_DEV_TYPE_RSHIM,
  RSH_DEV_TYPE_BOOT,
  RSH_DEV_TYPE_TMFIFO,
  RSH_DEV_TYPE_MISC,
  RSH_DEV_TYPES
};

/* Event types used in rshim_notify(). */
enum {
  RSH_EVENT_FIFO_INPUT,   /* fifo ready for input */
  RSH_EVENT_FIFO_OUTPUT,    /* fifo ready for output */
  RSH_EVENT_FIFO_ERR,   /* fifo error */
  RSH_EVENT_ATTACH,   /* backend attaching */
  RSH_EVENT_DETACH,   /* backend detaching */
};

/* Internal message types in addition to the standard VIRTIO_ID_xxx types. */
enum {
  TMFIFO_MSG_VLAN_ID = 0xFB,      /* vlan id */
  TMFIFO_MSG_PXE_ID = 0xFC,       /* pxe client identifier */
  TMFIFO_MSG_CTRL_REQ = 0xFD,     /* ctrl request */
  TMFIFO_MSG_MAC_1 = 0xFE,        /* mac[0:2] */
  TMFIFO_MSG_MAC_2 = 0xFF,        /* mac[3:4] */
};

/* TMFIFO message header. */
typedef union {
  struct {
    uint8_t type;   /* message type */
    uint16_t len;   /* payload length in network order */
    union {
      uint8_t mac[3];      /* 3-bytes of the MAC address */
      uint32_t pxe_id;     /* pxe identifier in network order */
      uint16_t vlan[2];    /* up to two vlan id */
    };
    uint8_t checksum;      /* header checksum */
  } __attribute__((packed));
  uint64_t data;
} rshim_tmfifo_msg_hdr_t;

/* TMFIFO demux channels. */
enum {
  TMFIFO_CONS_CHAN, /* Console */
  TMFIFO_NET_CHAN,  /* Network */
  TMFIFO_MAX_CHAN   /* Number of channels */
};

#define RSH_BYTE_ACC_READ_TRIGGER 0x50
#define RSH_BYTE_ACC_SIZE_4BYTE   0x10
#define RSH_BYTE_ACC_PENDING      0x20

#define BOOT_CHANNEL        RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_BOOT
#define RSHIM_CHANNEL       RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_RSHIM
#define MMC_CHANNEL         RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_MMC
#define YU_CHANNEL          RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_TYU
#define UART0_CHANNEL       RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_UART0
#define UART1_CHANNEL       RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_UART1
#define DIAGUART_CHANNEL    RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_DIAG_UART
#define OOB_CHANNEL         RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_TYU_EXT1
#define TIMER_ARM_CHANNEL   RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_TIMER
#define RSH_HUB_CHANNEL     RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_USB
#define TIMER_EXT_CHANNEL   RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_TIMER_EXT
#define WDOG0_CHANNEL       RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_WDOG0
#define WDOG1_CHANNEL       RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_WDOG1
#define GIC_CHANNEL         RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_TYU_EXT2
#define MCH_CORE_CHANNEL    RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_TYU_EXT3

/* Base RShim Address */
#define RSH_BASE_ADDR 0x80000000
#define RSH_CHANNEL_BASE(chan) (RSH_BASE_ADDR | (chan << 16))

#define RSH_BOOT_FIFO_SIZE   512
#define RSH_TM_FIFO_SIZE     256

/* Retry time in seconds. */
#define RSHIM_LOCK_RETRY_TIME  2

/* YU boot record OPN offset/size */
#define RSHIM_YU_BASE_ADDR             0x2800000
#define RSHIM_YU_BOOT_RECORD_OPN       0xfd8
#define RSHIM_YU_BOOT_RECORD_OPN_SIZE  16
#define RSHIM_YU_BF3_BOOT_RECORD_OPN   0x9bdc

#define YU_RESET_MODE_TRIGGER   0x0011
#define YU_BOOT_DEVID           0x0014
#define YU_BOOT                 0x0068
#define YU_POWER_CLK_DELAY      0x0c24
#define YU_RESET_8_CLK_EN       0x2800
#define YU_RESET_13_CLK_EN      0x2d00
#define YU_CLK_EN_COUNT         16
#define YU_RESET_8_RESET_EN     0x2840
#define YU_RESET_13_RESET_EN    0x2d40
#define YU_RESET_EN_COUNT       8
#define YU_RESET_8_POWERDOWN    0x2860
#define YU_RESET_13_POWERDOWN   0x2d60
#define YU_POWERDOWN_COUNT      8
#define YU_RESET_ACTIVATION_13  0x30b4
#define YU_MAIN_CLK_GATE_EN     0x30c8

/* FIFO structure. */
typedef struct {
  unsigned char *data;
  unsigned int head;
  unsigned int tail;
  pthread_cond_t operable;
} rshim_fifo_t;

/* RShim network packet. */
#define ETH_PKT_SIZE 1536
typedef struct {
  rshim_tmfifo_msg_hdr_t hdr;   /* message header */
  char buf[ETH_PKT_SIZE];       /* packet buffer */
} rshim_net_pkt_t;

#define RSHIM_DEV_NAME_LEN   64

/* Bluefield Version. */
#define RSHIM_BLUEFIELD_1 1
#define RSHIM_BLUEFIELD_2 2
#define RSHIM_BLUEFIELD_3 3

/* Bluefield Revision ID. */
#define BLUEFIELD_REV0 0
#define BLUEFIELD_REV1 1

/* Timeout for libusb operations in seconds. */
#define RSHIM_USB_TIMEOUT  40

/* RShim backend. */
typedef struct rshim_backend rshim_backend_t;
struct rshim_backend {
  /* Device name. */
  char dev_name[RSHIM_DEV_NAME_LEN];

  /* Backend device. */
  void *dev;

  /* BlueField version / revision. */
  uint16_t ver_id;
  uint16_t rev_id;

  /* FUSE sessions & poll handles. */
  void *fuse_session[RSH_DEV_TYPES];
  pthread_t fuse_thread[RSH_DEV_TYPES];
  void *fuse_poll_handle[TMFIFO_MAX_CHAN];

  /* Networking handler and packets. */
  int net_fd, net_notify_fd[2];
  rshim_net_pkt_t net_rx_pkt;
  rshim_net_pkt_t net_tx_pkt;
  int net_tx_len;
  int net_rx_len;
  bool net_rx_pending;

  /* State flags. */
  uint32_t is_booting : 1;        /* Waiting for device to come back. */
  uint32_t is_boot_open : 1;      /* Boot device is open. */
  uint32_t is_net_open : 1;       /* Network device is open. */
  uint32_t is_cons_open : 1;      /* Console device is open. */
  uint32_t is_attach : 1;         /* Service ready to attach. */
  uint32_t is_in_boot_write : 1;  /* A thread is in boot_write(). */
  uint32_t has_cons_work : 1;     /* Console worker thread running. */
  uint32_t has_debug : 1;         /* Debug enabled for this device. */
  uint32_t has_tm : 1;            /* TM FIFO found. */
  uint32_t has_rshim : 1;         /* RSHIM found. */
  uint32_t has_fifo_work : 1;     /* FIFO output to be done in worker. */
  uint32_t has_reprobe : 1;       /* Reprobe support after SW reset. */
  uint32_t drop_pkt : 1;          /* Drop the rest of the packet. */
  uint32_t registered : 1;        /* Backend has been registered. */
  uint32_t keepalive : 1;         /* A flag to update keepalive. */
  uint32_t peer_ctrl_req : 1;     /* A flag to send ctrl request. */
  uint32_t peer_ctrl_resp : 1;    /* A flag to indicate MAC response rcvd. */
  uint32_t peer_mac_set : 1;      /* A flag to send MAC-set request. */
  uint32_t peer_pxe_id_set : 1;   /* A flag to send pxe-id-set request. */
  uint32_t peer_vlan_set : 1;     /* A flag to set vlan IDs. */
  uint32_t drop_mode : 1;         /* A flag to drop all input/output. */
  uint32_t skip_boot_reset : 1;   /* Skip SW_RESET while pushing boot stream. */
  uint32_t locked_mode : 1;       /* Secure NIC mode Management. No RSHIM HW access */
  uint32_t clear_on_read : 1;     /* Clear rshim log after read */
  uint32_t has_locked_work : 1;   /* Need to check locked mode in worker. */
  uint32_t has_osp_work : 1;      /* Need to run ownership (osp) state machine. */
  uint32_t requesting_rshim : 1;  /* Mode that a request is being made to other end */
  uint32_t in_access_check : 1;   /* Access check is in progress */

  /* type. */
  rshim_backend_type_t type;

  /* reference count. */
  volatile int ref;

  /* Last keepalive time. */
  int last_keepalive;
  int net_init_time;

  /* timer. */
  int timer;

  /* Last boot write time. */
  time_t boot_write_time;

  /* State flag bits from RSH_SFLG_xxx (see above). */
  int spin_flags;

  /* Total bytes in the read buffer. */
  int read_buf_bytes;
  /* Offset of next unread byte in the read buffer. */
  int read_buf_next;
  /* Bytes left in the current packet, or 0 if no current packet. */
  int read_buf_pkt_rem;
  /* Padded bytes in the read buffer. */
  int read_buf_pkt_padding;

  /* Bytes left in the current packet pending to write. */
  int write_buf_pkt_rem;

  /* Current message header. */
  rshim_tmfifo_msg_hdr_t msg_hdr;

  /* Read FIFOs. */
  rshim_fifo_t read_fifo[TMFIFO_MAX_CHAN];

  /* Write FIFOs. */
  rshim_fifo_t write_fifo[TMFIFO_MAX_CHAN];

  /* Read buffer. */
  unsigned char *read_buf;

  /* Write buffer. */
  unsigned char *write_buf;

  /* Current Tx FIFO channel. */
  int tx_chan;

  /* Current Rx FIFO channel. */
  int rx_chan;

  /* First error encountered during read or write. */
  int tmfifo_error;

  /* Buffers used for boot writes.  Allocated at startup. */
  char *boot_buf[2];

  /* Buffer to store the remaining data when it's not 8B unaligned. */
  uint8_t boot_rem_cnt;
  uint64_t boot_rem_data;

  /* Debug code passed in scratchpad1. */
  uint64_t debug_code;

  /*
   * This mutex is used to prevent the interface pointers and the
   * device pointer from disappearing while a driver entry point
   * is using them.  It's held throughout a read or write operation
   * (at least the parts of those operations which depend upon those
   * pointers) and is also held whenever those pointers are modified.
   * It also protects state flags, and boot_complete_cond.
   */
  pthread_mutex_t mutex;

  /* Mutex to protect the ring buffer. */
  pthread_mutex_t ringlock;

  bool work_pending;

  /* We'll signal completion on this when FLG_BOOTING is turned off. */
  pthread_cond_t boot_complete_cond;

  /*
   * This wait queue supports fsync; it's woken up whenever an
   * outstanding USB write URB is done.  This will need to be more
   * complex if we start doing write double-buffering.
   */
  pthread_cond_t fifo_write_complete_cond;

  /* State for our outstanding boot write. */
  pthread_cond_t boot_write_complete_cond;

  /* Wait condition for control messages. */
  pthread_cond_t ctrl_wait_cond;

  /* Current termios settings for the console. */
  struct termios cons_termios;

  /* Pending boot & fifo request for the worker. */
  uint8_t *boot_work_buf;
  uint32_t boot_work_buf_len;
  uint32_t boot_work_buf_actual_len;
  uint8_t *fifo_work_buf;
  uint32_t fifo_work_buf_len;
  int fifo_work_devtype;

  /* Number of open console files. */
  long console_opens;

  /* Index in rshim_devs[]. */
  int index;

  /* Display level in the misc output. */
  int display_level;

  /* Boot timeout in seconds. */
  int boot_timeout;

  /* Delay after reset. */
  int reset_delay;

  /* Configured MAC address of the peer-side. */
  uint8_t peer_mac[6];

  /* Configured PXE client identifier. */
  uint32_t pxe_client_id;

  /* Up to two VLAN IDs for PXE purpose. */
  uint16_t vlan[2];

  /* APIs provided by backend. */

  /* API to write bulk data to RShim via the backend. */
  ssize_t (*write)(rshim_backend_t *bd, int devtype,
       const char *buf, size_t count);

  /* API to read bulk data from RShim via the backend. */
  ssize_t (*read)(rshim_backend_t *bd, int devtype, char *buf, size_t count);

  /* API to cancel a read / write request (optional). */
  void (*cancel)(rshim_backend_t *bd, int devtype, bool is_write);

  /* API to destroy the backend. */
  void (*destroy)(rshim_backend_t *bd);

  /* API to read <size> bytes from RShim. */
  int (*read_rshim)(rshim_backend_t *bd, uint32_t chan, uint32_t addr,
                    uint64_t *value, int size);

  /* API to write <size> bytes to RShim. */
  int (*write_rshim)(rshim_backend_t *bd, uint32_t chan, uint32_t addr,
                     uint64_t value, int size);

  /* API to enable the device. */
  int (*enable_device)(rshim_backend_t *bd, bool enable);

  /* Platform specific register addresses */
  const struct rshim_regs *regs;
};

#define RSHIM_REG_SIZE_4B 4
#define RSHIM_REG_SIZE_8B 8

struct rshim_regs {
  uint32_t boot_fifo_data;
  uint32_t boot_fifo_count;
  uint32_t boot_fifo_count_mask;
  uint32_t boot_control;
  uint32_t reset_control;
  uint32_t scratchpad1;
  uint32_t scratchpad2;
  uint32_t scratchpad6;
  uint32_t tm_htt_sts;
  uint32_t tm_tth_sts;
  uint32_t tm_htt_data;
  uint32_t tm_tth_data;
  uint32_t semaphore0;
  uint32_t mem_acc_ctl;
  uint32_t mem_acc_rsp_cnt;
  uint32_t mem_acc_data_first_word;
  uint32_t device_mstr_priv_lvl;
  uint32_t device_mstr_priv_lvl_shift;
  uint32_t fabric_dim;
  uint32_t uptime;
  uint32_t uptime_por;
  uint32_t arm_wdg_control_wcs;
  uint32_t scratch_buf_dat;
  uint32_t scratch_buf_ctl;
};

extern const struct rshim_regs bf1_bf2_rshim_regs;
extern const struct rshim_regs bf3_rshim_regs;

/* Global variables. */
extern int rshim_epoll_fd;
extern volatile bool rshim_run;

/* Common APIs. */

/* Register/unregister backend. */
int rshim_register(rshim_backend_t *bd);
void rshim_deregister(rshim_backend_t *bd);

/* Find backend by name. */
rshim_backend_t *rshim_find_by_name(char *dev_name);

/* Find backend by device. */
rshim_backend_t *rshim_find_by_dev(void *dev);

/* Find backend by index. */
rshim_backend_t *rshim_find_by_index(int index);

/* RShim global lock. */
void rshim_lock(void);
int rshim_trylock(void);
void rshim_unlock(void);

/* Event notification. */
int rshim_notify(rshim_backend_t *bd, int event, int code);

/*
 * FIFO APIs.
 *
 * FIFO is demuxed into two channels, one for network interface
 * (TMFIFO_NET_CHAN), one for console (TMFIFO_CONS_CHAN).
 */

/* Write / read some bytes to / from the FIFO via the backend. */
ssize_t rshim_fifo_read(rshim_backend_t *bd, char *buffer,
                        size_t count, int chan, bool nonblock);
ssize_t rshim_fifo_write(rshim_backend_t *bd, const char *buffer,
                         size_t count, int chan, bool nonblock);

/* Alloc/free the FIFO. */
int rshim_fifo_alloc(rshim_backend_t *bd);
void rshim_fifo_free(rshim_backend_t *bd);

/* Console APIs. */
/* Enable early console. */
int rshim_cons_early_enable(rshim_backend_t *bd);

/* Network APIs. */
#ifdef HAVE_RSHIM_NET
int rshim_net_init(rshim_backend_t *bd);
int rshim_net_del(rshim_backend_t *bd);
void rshim_net_rx(rshim_backend_t *bd);
void rshim_net_tx(rshim_backend_t *bd);
#else
static inline int rshim_net_init(rshim_backend_t *bd)
{
  return 0;
}
static inline int rshim_net_del(rshim_backend_t *bd)
{
  return 0;
}
static inline void rshim_net_rx(rshim_backend_t *bd)
{
}
static inline void rshim_net_tx(rshim_backend_t *bd)
{
}
#endif

void rshim_ref(rshim_backend_t *bd);
void rshim_deref(rshim_backend_t *bd);
int rshim_boot_open(rshim_backend_t *bd);
int rshim_boot_write(rshim_backend_t *bd, const char *user_buffer, size_t count,
                     int (*copy_in)(void *dest, const void *src, int count));
void rshim_boot_release(rshim_backend_t *bd);
int rshim_console_open(rshim_backend_t *bd);
int rshim_console_release(rshim_backend_t *bd,
                void (*poll_handle_destroy)(rshim_backend_t *bd, int chan));
void rshim_fifo_check_poll(rshim_backend_t *bd, int chan, bool *poll_rx,
                           bool *poll_tx, bool *poll_err);
int rshim_fifo_size(rshim_backend_t *bd, int chan, bool is_rx);
void rshim_sig_hup(int sig);
void rshim_fifo_reset(rshim_backend_t *bd);
int rshim_reset_control(rshim_backend_t *bd);
void rshim_work_signal(rshim_backend_t *bd);
int rshim_fifo_fsync(rshim_backend_t *bd, int chan);

/* Display the rshim logging buffer. */
int rshim_log_show(rshim_backend_t *bd, char *buf, int len);

bool rshim_allow_device(const char *devname);

/* USB backend APIs. */
#ifdef HAVE_RSHIM_USB
int rshim_usb_init(int epoll_fd);
void rshim_usb_poll(bool blocking);
#else
static inline int rshim_usb_init(int epoll_fd)
{
  return -1;
}
static inline void rshim_usb_poll(bool blocking)
{
  (void)blocking;
}
#endif

/* PCIe & PCIe livefish backend APIs. */
#ifdef HAVE_RSHIM_PCIE
int rshim_pcie_init(void);
int rshim_pcie_lf_init(void);
void rshim_pcie_check(rshim_backend_t *bd);
#else
static inline int rshim_pcie_init(void)
{
  return -1;
}

static inline int rshim_pcie_lf_init(void)
{
  return -1;
}

static inline void rshim_pcie_check(rshim_backend_t *bd)
{
  (void)bd;
}
#endif

#ifdef HAVE_RSHIM_FUSE
int rshim_fuse_init(rshim_backend_t *bd);
int rshim_fuse_del(rshim_backend_t *bd);
void rshim_fuse_input_notify(rshim_backend_t *bd);
int rshim_fuse_got_peer_signal(void);
#endif

/*
 * Get/Set the OPN string from the YU boot record, which means setting
 * the value only persists during warm resets.
 */
int rshim_get_opn(rshim_backend_t *bd, char *opn, int len);
int rshim_set_opn(rshim_backend_t *bd, const char *opn, int len);

/* Check whether rshim backend is accessible or not. */
int rshim_access_check(rshim_backend_t *bd);

/* Sync up with the peer side. */
int rshim_fifo_sync(rshim_backend_t *bd, bool drop_rx);

/* Enable or disable drop mode */
int rshim_set_drop_mode(rshim_backend_t *bd, int value);

/* Run rshim command mode. */
int rshim_cmdmode_run(int argc, char *argv[]);

#endif /* _RSHIM_H */
