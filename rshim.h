/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0) */
/*
 * Copyright 2019 Mellanox Technologies. All Rights Reserved.
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

#include "rshim_regs.h"

/* Debug Macros. */
extern int rshim_log_level;

#ifdef RSHIM_LOG_ENABLE
#define RSHIM_LOG(level, fmt...) \
do { \
  if ((level) <= rshim_log_level) \
    printf(fmt); \
} while (0)
#else
#define RSHIM_LOG(level, fmt...)
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER)	((size_t)&((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({ \
  void *__mptr = (void *)(ptr); \
  ((type *)(__mptr - offsetof(type, member))); })
#endif

#define RSHIM_ERR(fmt...)      RSHIM_LOG(1, fmt)
#define RSHIM_WARN(fmt...)     RSHIM_LOG(2, fmt)
#define RSHIM_INFO(fmt...)     RSHIM_LOG(3, fmt)
#define RSHIM_DBG(fmt...)      RSHIM_LOG(4, fmt)

/* Spin flag values. */
#define RSH_SFLG_READING  0x1  /* read is active. */
#define RSH_SFLG_WRITING  0x2  /* write_urb is active. */
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
typedef union rshim_tmfifo_msg_hdr {
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

/* Various rshim definitions. */
#define RSH_INT_VEC0_RTC__SWINT3_MASK 0x8

#define RSH_BYTE_ACC_READ_TRIGGER 0x50
#define RSH_BYTE_ACC_SIZE_4BYTE   0x10
#define RSH_BYTE_ACC_PENDING      0x20

#define BOOT_CHANNEL        RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_BOOT
#define RSHIM_CHANNEL       RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_RSHIM
#define UART0_CHANNEL       RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_UART0
#define UART1_CHANNEL       RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_UART1

/* Base RShim Address */
#define RSH_BASE_ADDR 0x80000000
#define RSH_CHANNEL_BASE(chan) (RSH_BASE_ADDR | (chan << 16))

#define RSH_BOOT_FIFO_SIZE   512

#define LOCK_RETRY_CNT       100000

/* FIFO structure. */
struct rshim_fifo {
  unsigned char *data;
  unsigned int head;
  unsigned int tail;
  pthread_cond_t operable;
};

/* RShim network packet. */
#define ETH_PKT_SIZE 1536
typedef struct {
  rshim_tmfifo_msg_hdr_t hdr;   /* message header */
  char buf[ETH_PKT_SIZE];       /* packet buffer */
} rshim_net_pkt_t;

/* RShim backend. */
struct rshim_backend {
  /* Device name. */
  char *dev_name;

  /* Driver name. */
  char *drv_name;

  /* Backend device. */
  void *dev;

  /* FUSE sessions. */
  void *fuse_session[RSH_DEV_TYPES];
  pthread_t thread[RSH_DEV_TYPES];

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
  uint32_t is_tm_open : 1;        /* TM FIFO device is open. */
  uint32_t is_cons_open : 1;      /* Console device is open. */
  uint32_t is_in_boot_write : 1;  /* A thread is in boot_write(). */
  uint32_t has_cons_work : 1;     /* Console worker thread running. */
  uint32_t has_debug : 1;         /* Debug enabled for this device. */
  uint32_t has_tm : 1;            /* TM FIFO found. */
  uint32_t has_rshim : 1;         /* RSHIM found. */
  uint32_t has_fifo_work : 1;     /* FIFO output to be done in worker. */
  uint32_t has_reprobe : 1;       /* Reprobe support after SW reset. */
  uint32_t drop : 1;              /* Drop the rest of the packet. */
  uint32_t registered : 1;        /* Backend has been registered. */
  uint32_t keepalive : 1;         /* A flag to update keepalive. */
  uint32_t peer_ctrl_req : 1;     /* A flag to send ctrl request. */
  uint32_t peer_ctrl_resp : 1;    /* A flag to indicate MAC response rcvd. */
  uint32_t peer_mac_set : 1;      /* A flag to send MAC-set request. */
  uint32_t peer_pxe_id_set : 1;   /* A flag to send pxe-id-set request. */
  uint32_t peer_vlan_set : 1;     /* A flag to set vlan IDs. */

  /* reference count. */
  volatile int ref;

  /* Last keepalive time. */
  int last_keepalive;

  /* timer. */
  int timer;

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
  union rshim_tmfifo_msg_hdr msg_hdr;

  /* Read FIFOs. */
  struct rshim_fifo read_fifo[TMFIFO_MAX_CHAN];

  /* Write FIFOs. */
  struct rshim_fifo write_fifo[TMFIFO_MAX_CHAN];

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

#ifdef HAVE_RSHIM_FUSE
  /* Rx poll handle. */
  void *rx_poll_handle[TMFIFO_MAX_CHAN];
#endif

  /*
   * Our index in rshim_devs, which is also the high bits of our
   * minor number.
   */
  int dev_index;

  /* Configured MAC address of the peer-side. */
  uint8_t peer_mac[6];

  /* Configured PXE client identifier. */
  uint32_t pxe_client_id;

  /* Up to two VLAN IDs for PXE purpose. */
  uint16_t vlan[2];

  /* APIs provided by backend. */

  /* API to write bulk data to RShim via the backend. */
  ssize_t (*write)(struct rshim_backend *bd, int devtype,
       const char *buf, size_t count);

  /* API to read bulk data from RShim via the backend. */
  ssize_t (*read)(struct rshim_backend *bd, int devtype,
      char *buf, size_t count);

  /* API to cancel a read / write request (optional). */
  void (*cancel)(struct rshim_backend *bd, int devtype, bool is_write);

  /* API to destroy the backend. */
  void (*destroy)(struct rshim_backend *bd);

  /* API to read 8 bytes from RShim. */
  int (*read_rshim)(struct rshim_backend *bd, int chan, int addr,
                    uint64_t *value);

  /* API to write 8 bytes to RShim. */
  int (*write_rshim)(struct rshim_backend *bd, int chan, int addr,
                     uint64_t value);
};

/* RShim service. */
struct rshim_service {
  /* Service type RSH_SVC_xxx. */
  int type;

  /* Create service. */
  int (*create)(struct rshim_backend *bd);

  /* Delete service. */
  int (*delete)(struct rshim_backend *bd);

  /* Notify service Rx is ready. */
  void (*rx_notify)(struct rshim_backend *bd);
};

/* Global variables. */

extern int rshim_epoll_fd;

/* Common APIs. */

/* Register/unregister backend. */
int rshim_register(struct rshim_backend *bd);
void rshim_deregister(struct rshim_backend *bd);

/* Find backend by name. */
struct rshim_backend *rshim_find_by_name(char *dev_name);

/* Find backend by device. */
struct rshim_backend *rshim_find_by_dev(void *dev);

/* RShim global lock. */
void rshim_lock(void);
void rshim_unlock(void);

/* Event notification. */
int rshim_notify(struct rshim_backend *bd, int event, int code);

/*
 * FIFO APIs.
 *
 * FIFO is demuxed into two channels, one for network interface
 * (TMFIFO_NET_CHAN), one for console (TMFIFO_CONS_CHAN).
 */

/* Write / read some bytes to / from the FIFO via the backend. */
ssize_t rshim_fifo_read(struct rshim_backend *bd, char *buffer,
                        size_t count, int chan, bool nonblock);
ssize_t rshim_fifo_write(struct rshim_backend *bd, const char *buffer,
                         size_t count, int chan, bool nonblock);

/* Alloc/free the FIFO. */
int rshim_fifo_alloc(struct rshim_backend *bd);
void rshim_fifo_free(struct rshim_backend *bd);

/* Console APIs. */
/* Enable early console. */
int rshim_cons_early_enable(struct rshim_backend *bd);

/* Network APIs. */
#ifdef HAVE_RSHIM_NET
int rshim_net_init(struct rshim_backend *bd);
int rshim_net_del(struct rshim_backend *bd);
void rshim_net_rx(struct rshim_backend *bd);
void rshim_net_tx(struct rshim_backend *bd);
#else
static inline int rshim_net_init(struct rshim_backend *bd)
{
  return 0;
}
static inline int rshim_net_del(struct rshim_backend *bd)
{
  return 0;
}
static inline void rshim_net_rx(struct rshim_backend *bd)
{
}
static inline void rshim_net_tx(struct rshim_backend *bd)
{
}
#endif

void rshim_ref(struct rshim_backend *bd);

void rshim_deref(struct rshim_backend *bd);

/* USB backend APIs. */
bool rshim_usb_init(int epoll_fd);
void rshim_usb_poll(void);

/* PCIe backend APIs. */
#ifdef HAVE_RSHIM_PCIE
int rshim_pcie_init(void);
void rshim_pcie_exit(void);
#else
static inline int rshim_pcie_init(void)
{
  return -1;
}
static void rshim_pcie_exit(void)
{
}
#endif

/* PCIe livefish backend APIs. */
#ifdef HAVE_RSHIM_PCIE_LF
int rshim_pcie_lf_init(void);
void rshim_pcie_lf_exit(void);
#else
static inline int rshim_pcie_lf_init(void)
{
  return -1;
}
static inline void rshim_pcie_lf_exit(void)
{
}
#endif

#endif /* _RSHIM_H */
