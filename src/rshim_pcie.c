// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright (C) 2019 Mellanox Technologies. All Rights Reserved.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <pci/pci.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __FreeBSD__
#include <cuse.h>
#include <sys/pciio.h>
#include <vm/vm.h>
#endif

#ifdef __linux__
#include <dirent.h>
#include <linux/vfio.h>
#include <pci/header.h>
#include <sys/eventfd.h>
#include <sys/vfs.h>
#include <unistd.h>
#endif

#include "rshim.h"

/* Our Vendor/Device IDs. */
#define TILERA_VENDOR_ID            0x15b3
#define BLUEFIELD1_DEVICE_ID        0xc2d2
#define BLUEFIELD2_DEVICE_ID        0xc2d3
#define BLUEFIELD3_DEVICE_ID        0xc2d4
#define BLUEFIELD3_DEVICE_ID2       0xc2d5

/* The size the RShim region. */
#define PCI_RSHIM_WINDOW_SIZE       0x100000
#define BF3_PCI_RSHIM_WINDOW_SIZE   0x800000

#define VFIO_GET_REGION_ADDR(x)     ((uint64_t) x << 40ULL)

#define SYS_CLASS_IOMMU_PATH        "/sys/class/iommu"
#define SYS_CLASS_VFIO_PCI_PATH     "/sys/module/vfio_pci"
#define SYS_BUS_PCI_PATH            "/sys/bus/pci/devices"
#define SYS_VFIO_PCI_PATH           "/sys/bus/pci/drivers/vfio-pci"
#define SYS_CLASS_UIO_PCI_PATH      "/sys/module/uio_pci_generic"
#define SYS_UIO_PCI_PATH            "/sys/bus/pci/drivers/uio_pci_generic"

#define RSHIM_PCI_COMMAND           (PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER)

#define RSHIM_PATH_MAX              256
#define RSHIM_CMD_MAX               256

#define RSHIM_PCIE_NIC_RESET_WAIT   2
#define RSHIM_PCIE_NIC_IRQ_RATE     32

/* Different modes of memory map. */
typedef enum {
  RSHIM_PCIE_MMAP_DIRECT,
  RSHIM_PCIE_MMAP_UIO,
  RSHIM_PCIE_MMAP_VFIO
} rshim_pcie_mmap_mode_t;

/* Reset state stored in scratchpad6. */
enum {
  RSHIM_PCIE_RST_STATE_NONE,
  RSHIM_PCIE_RST_STATE_REQUEST,
  RSHIM_PCIE_RST_STATE_START,
  RSHIM_PCIE_RST_STATE_ABORT
};

/* Reset reply stored in scratchpad6. */
enum {
  RSHIM_PCIE_RST_REPLY_NONE,
  RSHIM_PCIE_RST_REPLY_ACK,
  RSHIM_PCIE_RST_REPLY_NACK,
  RSHIM_PCIE_RST_START_ACK,
};

/* Reset type stored in scratchpad6. */
enum {
  RSHIM_PCIE_RST_TYPE_NONE,
  RSHIM_PCIE_RST_TYPE_DPU_RESET,
  RSHIM_PCIE_RST_TYPE_NIC_RESET
};

/* Min delay in seconds after RSHIM_PCIE_RST_START_ACK */
#define RSHIM_PCIE_RST_START_MIN_DELAY    4

/* Interrupt information between NIC_FW and rshim driver. */
typedef union {
  struct {
    uint64_t unused_0 : 32;

    /* RSHIM_PCIE_RST_STATE_xxx (RO) */
    uint64_t rst_state : 4;

    uint64_t unused_1 : 2;

    /* RSHIM_PCIE_RST_REPLY_xxx (WO) */
    uint64_t rst_reply : 2;

    /* 10’s of ms between the PCI link disable and PCI link enable (RO) */
    uint64_t rst_downtime : 8;

    uint64_t unused_2 : 4;

    /* RSHIM_PCIE_RST_TYPE_xxx */
    uint64_t rst_type : 3;

    uint64_t unused_3 : 8;

    /* rshim running over pcie */
    uint64_t pcie : 1;
  };

  uint64_t word;
} rshim_pcie_intr_info_t;

static rshim_pcie_mmap_mode_t rshim_pcie_mmap_mode = RSHIM_PCIE_MMAP_DIRECT;
static const char *rshim_pcie_mmap_name[] = {"direct", "uio", "vfio"};
#ifdef __linux__
static const char *rshim_sys_pci_path;
static bool rshim_pcie_has_uio(void);
#endif

static inline uint64_t
readq(const volatile void *addr)
{
  uint64_t value = *(const volatile uint64_t *)addr;
  __sync_synchronize();
  return value;
}

static inline void
writeq(uint64_t value, volatile void *addr)
{
  __sync_synchronize();
  *(volatile uint64_t *)addr = value;
}

static inline uint32_t
readl(const volatile void *addr)
{
  uint32_t value = *(const volatile uint32_t *)addr;
  __sync_synchronize();
  return value;
}

static inline void
writel(uint32_t value, volatile void *addr)
{
  __sync_synchronize();
  *(volatile uint32_t *)addr = value;
}

typedef struct {
  /* RShim backend structure. */
  rshim_backend_t bd;

  /* Device info */
  int domain;
  uint16_t device_id;
  uint8_t bus;
  uint8_t dev;
  uint8_t func;

  /* Address of the RShim registers. */
  volatile uint8_t *rshim_regs;

  /* Keep track of number of 8-byte word writes */
  uint8_t write_count;

  /* Device file handle */
  int device_fd;

  /* VFIO container/group file handle */
  int container_fd;
  int group_fd;

  /* Interrupt handle and read length */
  volatile int intr_fd;
  volatile int intr_reset_seq;
  uint32_t intr_len;

  /* Interrupt thread */
  pthread_t intr_thread;

  /* State to indicate NIC is resetting. */
  volatile bool nic_reset;

  /* Last irq time */
  time_t last_intr_time;

  /* Number of interrupts since last irq time */
  uint32_t intr_cnt;

  /* Memory map and PCI sysfs path. */
  int mmap_mode;
  const char *pci_path;

  /* BAR size */
  uint32_t bar_size;
} rshim_pcie_t;

static const int bf3_rshim_pcie_chan_map[] = {
	[RSHIM_CHANNEL] = 0,
	[UART0_CHANNEL] = 0x10000,
	[UART1_CHANNEL] = 0x11000,
	[DIAGUART_CHANNEL] = 0x12000,
	[RSH_HUB_CHANNEL] = 0x12400,
	[WDOG0_CHANNEL] = 0x20000,
	[WDOG1_CHANNEL] = 0x40000,
	[MCH_CORE_CHANNEL] = 0x60000,
	[TIMER_ARM_CHANNEL] = 0x80000,
	[TIMER_EXT_CHANNEL] = 0xa0000,
	[OOB_CHANNEL] = 0xa1000,
	[YU_CHANNEL] = 0x400000,
};

static bool rshim_is_bluefield1(uint16_t device_id)
{
  return (device_id == BLUEFIELD1_DEVICE_ID);
}

static bool rshim_is_bluefield2(uint16_t device_id)
{
  return (device_id == BLUEFIELD2_DEVICE_ID);
}

static bool rshim_is_bluefield3(uint16_t device_id)
{
  return ((device_id == BLUEFIELD3_DEVICE_ID) ||
          (device_id == BLUEFIELD3_DEVICE_ID2));
}

#ifdef __linux__

static int rshim_pcie_enable_irq(rshim_pcie_t *dev, bool enable);

static uint16_t rshim_pci_read_word(rshim_pcie_t *dev, int pos)
{
  char path[RSHIM_PATH_MAX];
  uint16_t data = 0xFFFF;
  int fd;

  snprintf(path, sizeof(path), "%s/%04x:%02x:%02x.%1u/config",
           SYS_BUS_PCI_PATH, dev->domain, dev->bus,
           dev->dev, dev->func);
  fd = open(path, O_RDWR | O_SYNC);
  if (fd != -1) {
    if (pread(fd, &data, sizeof(data), pos) != sizeof(data)) {
      data = 0xFFFF;
    }
    data = le16toh(data);
    close(fd);
  } else {
    RSHIM_WARN("Unable to open %s\n", path);
  }
  return data;
}

int rshim_pci_write_word(rshim_pcie_t *dev, int pos, uint16_t data)
{
  char path[RSHIM_PATH_MAX];
  int fd, len = 0;

  snprintf(path, sizeof(path), "%s/%04x:%02x:%02x.%1u/config",
           SYS_BUS_PCI_PATH, dev->domain, dev->bus,
           dev->dev, dev->func);
  fd = open(path, O_RDWR | O_SYNC);
  if (fd != -1) {
    data = htole16(data);
    len = pwrite(fd, &data, sizeof(data), pos);
    close(fd);
  } else {
    RSHIM_WARN("Unable to open %s\n", path);
  }

  return len;
}

/* Release pcie resource. */
static void rshim_pcie_mmap_release(rshim_pcie_t *dev)
{
  volatile void *ptr;
  rshim_pcie_enable_irq(dev, false);

  ptr = dev->rshim_regs;
  if (ptr) {
    dev->rshim_regs = NULL;
    __sync_synchronize();
    munmap((void *)ptr, dev->bar_size);
  }

  if (dev->device_fd >= 0) {
    close(dev->device_fd);
    dev->device_fd = -1;
  }

  if (dev->group_fd >= 0) {
    close(dev->group_fd);
    dev->group_fd = -1;
  }

  if (dev->container_fd >= 0) {
    close(dev->container_fd);
    dev->container_fd = -1;
  }
}

static void rshim_pcie_bind(rshim_pcie_t *dev, bool enable)
{
  uint16_t device_id[] = {BLUEFIELD1_DEVICE_ID, BLUEFIELD2_DEVICE_ID,
                          BLUEFIELD3_DEVICE_ID, BLUEFIELD3_DEVICE_ID2};
  char cmd[RSHIM_CMD_MAX];
  int i, rc;

  /*
   * Linux kernel prior 4.18 has a bug which could cause crash when uio is
   * unregistered (see commit 57c5f4df0a5a uio: fix crash after the device
   * is unregistered). Below is a workaround to avoid such crash for uio.
   * The rshim probing order is vfio->uio->direct. The uio unbind won't
   * affect the operation of direct mapping.
   */
  if (!enable && (dev->mmap_mode == RSHIM_PCIE_MMAP_UIO))
    return;

  if (dev->mmap_mode == RSHIM_PCIE_MMAP_VFIO ||
      dev->mmap_mode == RSHIM_PCIE_MMAP_UIO) {
    if (!enable) {
      snprintf(cmd, sizeof(cmd),
               "echo %04x:%02x:%02x.%1u > %s/unbind 2>/dev/null",
               dev->domain, dev->bus, dev->dev, dev->func,
               dev->pci_path);
      if (system(cmd) == -1)
        RSHIM_DBG("Failed to unbind device\n");
    } else if (dev->mmap_mode == RSHIM_PCIE_MMAP_VFIO) {
      /* Clear driver_override. */
      snprintf(cmd, sizeof(cmd),
               "echo \"\" > %s/%04x:%02x:%02x.%1u/driver_override 2>/dev/null",
               SYS_BUS_PCI_PATH, dev->domain, dev->bus,
               dev->dev, dev->func);
      if (system(cmd) == -1)
        RSHIM_DBG("Failed to enable pcie\n");
    }

    for (i = 0; i < sizeof(device_id) / sizeof(uint16_t); i++) {
      snprintf(cmd, sizeof(cmd), "echo '%x %x' > %s/%s 2>/dev/null",
               TILERA_VENDOR_ID, device_id[i], dev->pci_path,
               enable ? "new_id" : "remove_id");
      rc = system(cmd);
      if (rc == -1)
        RSHIM_DBG("Failed to write device id %m\n");
    }

    if (enable) {
      snprintf(cmd, sizeof(cmd),
               "echo %04x:%02x:%02x.%1u > %s/bind 2>/dev/null",
               dev->domain, dev->bus, dev->dev, dev->func,
               dev->pci_path);
      if (system(cmd) == -1)
        RSHIM_DBG("Failed to bind device\n");
    }
  } else if (dev->mmap_mode == RSHIM_PCIE_MMAP_DIRECT) {
    if (enable) {
      snprintf(cmd, sizeof(cmd), "echo 1 > %s/%04x:%02x:%02x.%1u/enable",
               SYS_BUS_PCI_PATH, dev->domain, dev->bus,
               dev->dev, dev->func);
      if (system(cmd) == -1)
        RSHIM_DBG("Failed to enable pcie\n");
    }

    /*
     * There is no driver in direct map mode. Set a faked driver name here
     * to prevent the "new_id" command from reassigning driver automatically
     * for this rshim PF. This is to avoid issues when there multiple rshim
     * devices exist with mixed mode.
     */
    snprintf(cmd, sizeof(cmd),
             "echo %s > %s/%04x:%02x:%02x.%1u/driver_override 2>/dev/null",
             enable ? "rshim" : "",
             SYS_BUS_PCI_PATH, dev->domain, dev->bus,
             dev->dev, dev->func);
    if (system(cmd) == -1)
      RSHIM_DBG("Failed to enable pcie\n");
  }
}

/* Memory map over sysfs. */
static int rshim_pcie_mmap_direct(rshim_pcie_t *dev)
{
  char path[RSHIM_PATH_MAX];
  uint16_t reg;

  snprintf(path, sizeof(path), "%s/%04x:%02x:%02x.%1u/resource0",
           SYS_BUS_PCI_PATH, dev->domain, dev->bus,
           dev->dev, dev->func);

  dev->device_fd = open(path, O_RDWR | O_SYNC);
  if (dev->device_fd < 0) {
    RSHIM_ERR("rshim%d failed to open %s\n", dev->bd.index, path);
    return -ENODEV;
  }
  dev->rshim_regs = mmap(NULL, dev->bar_size,
                         PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_LOCKED,
                         dev->device_fd,
                         0);
  if (dev->rshim_regs == MAP_FAILED) {
    dev->rshim_regs = NULL;
    RSHIM_ERR("rshim%d failed to map RShim registers\n", dev->bd.index);
    return -ENOMEM;
  }

  /* Set PCI bus mastering */
  reg = rshim_pci_read_word(dev, PCI_COMMAND);
  if (reg != 0xFFFF)
    rshim_pci_write_word(dev, PCI_COMMAND, reg | RSHIM_PCI_COMMAND);

  return 0;
}

#define IRQ_SET_BUF_LEN  (sizeof(struct vfio_irq_set) + sizeof(int))
struct {
  struct vfio_irq_set irq_set;
  int32_t intr_fd;
} irq_set_buf;

static int rshim_pcie_enable_irq(rshim_pcie_t *dev, bool enable)
{
  struct vfio_irq_set *irq_set = (struct vfio_irq_set *) &irq_set_buf;
  int len, ret;
  uint16_t reg;

  if (dev->mmap_mode == RSHIM_PCIE_MMAP_UIO) {
    reg = rshim_pci_read_word(dev, PCI_COMMAND);
    if (reg != 0xFFFF) {
      if (enable && (reg & PCI_COMMAND_DISABLE_INTx))
        rshim_pci_write_word(dev, PCI_COMMAND, reg & ~PCI_COMMAND_DISABLE_INTx);
      else if (!enable && !(reg & PCI_COMMAND_DISABLE_INTx))
        rshim_pci_write_word(dev, PCI_COMMAND, reg | PCI_COMMAND_DISABLE_INTx);
    }
    return 0;
  } else if (dev->mmap_mode != RSHIM_PCIE_MMAP_VFIO) {
    return 0;
  }

  /* VFIO interrupt enable/disable */
  if (dev->device_fd == -1)
    return 0;

  /* Mask interrupts before disabling. */
  if (!enable) {
    len = sizeof(struct vfio_irq_set);
    memset(irq_set, 0, len);
    irq_set->argsz = len;
    irq_set->count = 1;
    irq_set->flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_MASK;
    irq_set->index = VFIO_PCI_INTX_IRQ_INDEX;
    irq_set->start = 0;

    ret = ioctl(dev->device_fd, VFIO_DEVICE_SET_IRQS, irq_set);
    if (ret) {
      RSHIM_ERR("rshim%d failed to mask INTx\n", dev->bd.index);
      return -1;
    }
  }

  /* Enable INTx */
  irq_set->argsz = sizeof(irq_set_buf);
  irq_set->count = 1;
  irq_set->flags = enable ? VFIO_IRQ_SET_DATA_EVENTFD : VFIO_IRQ_SET_DATA_NONE;
  irq_set->flags |= VFIO_IRQ_SET_ACTION_TRIGGER;
  irq_set->index = VFIO_PCI_INTX_IRQ_INDEX;
  irq_set->start = 0;
  irq_set_buf.intr_fd = dev->intr_fd;

  ret = ioctl(dev->device_fd, VFIO_DEVICE_SET_IRQS, irq_set);
  if (ret) {
    RSHIM_ERR("rshim%d failed to enable INTx\n", dev->bd.index);
    return -1;
  }

  /* Unmask INTx after enabling. */
  if (enable) {
    len = sizeof(struct vfio_irq_set);
    memset(irq_set, 0, len);
    irq_set->argsz = len;
    irq_set->count = 1;
    irq_set->flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_UNMASK;
    irq_set->index = VFIO_PCI_INTX_IRQ_INDEX;
    irq_set->start = 0;

    ret = ioctl(dev->device_fd, VFIO_DEVICE_SET_IRQS, irq_set);
    if (ret) {
      RSHIM_ERR("rshim%d failed to unmask INTx\n", dev->bd.index);
      return -1;
    }
  }

  return 0;
}

/* Memory map over VFIO. */
static int rshim_pcie_mmap_vfio(rshim_pcie_t *dev)
{
  int rc, group_id, container_fd = -1, group_fd = -1, device_fd = -1;
  struct vfio_irq_info irq = { .argsz = sizeof(irq) };
  char path[RSHIM_PATH_MAX], name[PATH_MAX], *p;

  struct vfio_group_status group_status = {
    .argsz = sizeof(group_status)
  };

  struct vfio_device_info device_info = {
    .argsz = sizeof(device_info)
  };

  struct vfio_region_info region_info = {
    .argsz = sizeof(region_info)
  };

  container_fd = open("/dev/vfio/vfio", O_RDWR);
  if (container_fd < 0) {
    RSHIM_DBG("Failed to open /dev/vfio/vfio, %d (%s)\n",
           container_fd, strerror(errno));
    rc = container_fd;
    goto fail;
  }

  if (ioctl(container_fd, VFIO_GET_API_VERSION) != VFIO_API_VERSION) {
    RSHIM_WARN("Unknown vfio API version\n");
    rc = -EPROTONOSUPPORT;
    goto fail;
  }

  if (!ioctl(container_fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU)) {
    RSHIM_WARN("IOMMU version not supported\n");
    rc = -EPROTONOSUPPORT;
    goto fail;
  }

  /* Find the group_id. */
  snprintf(path, sizeof(path), "%s/%04x:%02x:%02x.%1u/iommu_group",
           SYS_BUS_PCI_PATH, dev->domain, dev->bus,
           dev->dev, dev->func);
  rc = readlink(path, name, sizeof(name));
  if (rc < 0 || !name[0] || rc >= sizeof(name)) {
    RSHIM_ERR("rshim%d failed to read iommu link %s\n", dev->bd.index, path);
    goto fail;
  }
  name[rc] = 0;
  p = strrchr(name, '/');
  if (!p) {
    RSHIM_ERR("rshim%d failed to find vfio group\n", dev->bd.index);
    rc = -ENOENT;
    goto fail;
  }
  group_id = atoi(p + 1);

  snprintf(path, sizeof(path), "/dev/vfio/%d", group_id);
  group_fd = open(path, O_RDWR);
  if (group_fd < 0) {
    RSHIM_DBG("Failed to open %s, %d (%s)\n",
              path, group_fd, strerror(errno));
    rc = group_fd;
    goto fail;
  }

  rc = ioctl(group_fd, VFIO_GROUP_GET_STATUS, &group_status);
  if (rc) {
    RSHIM_ERR("rshim%d VFIO_GROUP_GET_STATUS failed\n", dev->bd.index);
    goto fail;
  }

  if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
    RSHIM_DBG("VFIO group not viable\n");
    rc = -1;
    goto fail;
  }

  if (!(group_status.flags & VFIO_GROUP_FLAGS_CONTAINER_SET)) {
    ioctl(group_fd, VFIO_GROUP_SET_CONTAINER, &container_fd);
    ioctl(container_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU);
  }

  snprintf(path, sizeof(path), "%04x:%02x:%02x.%d", dev->domain,
           dev->bus, dev->dev, dev->func);
  device_fd = ioctl(group_fd, VFIO_GROUP_GET_DEVICE_FD, path);
  if (device_fd < 0) {
    RSHIM_ERR("rshim%d: failed to get vfio device %s\n", dev->bd.index, path);
    rc = device_fd;
    goto fail;
  }

  rc = ioctl(device_fd, VFIO_DEVICE_GET_INFO, &device_info);
  if (rc) {
    RSHIM_ERR("rshim%d failed to get vfio device info\n", dev->bd.index);
    goto fail;
  }

  if (!device_info.num_regions) {
    rc = -1;
    goto fail;
  }

  region_info.index = 0;
  rc = ioctl(device_fd, VFIO_DEVICE_GET_REGION_INFO, &region_info);
  if (rc) {
    RSHIM_ERR("rshim%d failed to get vfio region info\n", dev->bd.index);
    goto fail;
  }

  if (region_info.flags & VFIO_REGION_INFO_FLAG_MMAP) {
    void *map = mmap(NULL, (size_t)region_info.size,
                     PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_LOCKED,
                     device_fd,
                     (off_t)region_info.offset);
    if (map == MAP_FAILED) {
      RSHIM_ERR("rshim%d vfio mmap failed\n", dev->bd.index);
      rc = -1;
      goto fail;
    } else {
      uint16_t reg = 0;

      /* Set PCI bus mastering */
      rc = pread(device_fd, &reg, sizeof(reg),
                 VFIO_GET_REGION_ADDR(VFIO_PCI_CONFIG_REGION_INDEX) +
                 PCI_COMMAND);
      if (rc != sizeof(reg)) {
        RSHIM_ERR("rshim%d failed to read command from PCI config space!\n",
                  dev->bd.index);
        rc = -1;
        goto fail;
      }
      reg |= RSHIM_PCI_COMMAND;
      rc = pwrite(device_fd, &reg, sizeof(reg),
                  VFIO_GET_REGION_ADDR(VFIO_PCI_CONFIG_REGION_INDEX) +
                  PCI_COMMAND);
      if (rc != sizeof(reg)) {
        RSHIM_ERR("rshim%d failed to set PCI bus mastering!\n", dev->bd.index);
        rc = -1;
        goto fail;
      }

      dev->device_fd = device_fd;
      dev->group_fd = group_fd;
      dev->container_fd = container_fd;
      dev->rshim_regs = map;

      /* Enable interrupt */
      irq.index = VFIO_PCI_INTX_IRQ_INDEX;
      rc = ioctl(device_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq);
      if (rc < 0 || (irq.flags & VFIO_IRQ_INFO_EVENTFD) == 0) {
        RSHIM_WARN("Unable to get vfio IRQ\n");
      } else {
        if (dev->intr_fd < 0)
          dev->intr_fd = eventfd(0, EFD_CLOEXEC);
        dev->intr_len = sizeof(uint64_t);
        if (dev->intr_fd >= 0)
          rshim_pcie_enable_irq(dev, true);
      }
    }
  }

  return 0;

fail:
  if (device_fd >= 0)
    close(device_fd);
  if (group_fd >= 0)
    close(group_fd);
  if (container_fd >= 0)
    close(container_fd);
  return rc;
}

/* Memory map over UIO. */
static int rshim_pcie_mmap_uio(rshim_pcie_t *dev)
{
  char dirname[RSHIM_PATH_MAX], devname[RSHIM_PATH_MAX], *str = NULL;
  struct dirent *e;
  int uio_num, rc;
  DIR *dir;

  /* Find the uio number. */
  snprintf(dirname, sizeof(dirname), "%s/%04x:%02x:%02x.%1u/uio",
           SYS_BUS_PCI_PATH, dev->domain, dev->bus,
           dev->dev, dev->func);
  dir = opendir(dirname);
  if (!dir) {
    snprintf(dirname, sizeof(dirname), "%s/%04x:%02x:%02x.%1u",
             SYS_BUS_PCI_PATH, dev->domain, dev->bus,
             dev->dev, dev->func);
    dir = opendir(dirname);
    if (!dir)
      return -ENOENT;
  }
  while ((e = readdir(dir)) != NULL) {
    if ((str = strstr(e->d_name, "uio:uio")) != NULL)
      str += strlen("uio:uio");
    else if ((str = strstr(e->d_name, "uio")) != NULL)
      str += strlen("uio");

    if (str)
      break;
  }

  if (str)
    uio_num = atoi(str);

  closedir(dir);

  if (!str)
    return -ENOENT;

  /* Memory map. */
  rc = rshim_pcie_mmap_direct(dev);
  if (rc)
    return rc;

  /* Open the control fd to handle interrupt. */
  snprintf(devname, sizeof(devname), "/dev/uio%u", uio_num);
  if (dev->intr_fd >= 0) {
    dev->intr_reset_seq++;
    __sync_synchronize();
    close(dev->intr_fd);
  }
  dev->intr_fd = open(devname, O_RDWR);
  dev->intr_len = sizeof(uint32_t);
  rshim_pcie_enable_irq(dev, true);

  return 0;
}

static int rshim_pcie_mmap(rshim_pcie_t *dev, bool enable)
{
  int rc = -EINVAL;

  if (!enable) {
    rshim_pcie_mmap_release(dev);
    return 0;
  }

  if (dev->mmap_mode == RSHIM_PCIE_MMAP_VFIO)
    rc = rshim_pcie_mmap_vfio(dev);
  else if (dev->mmap_mode == RSHIM_PCIE_MMAP_UIO)
    rc = rshim_pcie_mmap_uio(dev);
  else if (dev->mmap_mode == RSHIM_PCIE_MMAP_DIRECT)
    rc = rshim_pcie_mmap_direct(dev);

  return rc;
}

/*
 * Check and set the pcie bit.
 * This function is called from timer callback since the pcie bit
 * could be cleared during ARM reset.
 */
void rshim_pcie_check(rshim_backend_t *bd)
{
  rshim_pcie_intr_info_t info = {.word = 0};
  int rc;

  pthread_mutex_lock(&bd->mutex);

  rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->scratchpad6,
                      &info.word, RSHIM_REG_SIZE_8B);
  if (!rc && !RSHIM_BAD_CTRL_REG(info.word) && !info.pcie) {
    info.pcie = 1;
    bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->scratchpad6,
                    info.word, RSHIM_REG_SIZE_8B);
  }

  pthread_mutex_unlock(&bd->mutex);
}

static void rshim_pcie_intr(rshim_pcie_t *dev)
{
  rshim_pcie_intr_info_t info = {.word = 0};
  rshim_backend_t *bd = &dev->bd;
  int rc, drop_mode, delay;
  time_t t;

  /* Add some protection for interrupt flooding. */
  time(&t);
  if (difftime(t, dev->last_intr_time) > 1) {
    dev->last_intr_time = t;
    dev->intr_cnt = 0;
  }
  dev->intr_cnt++;
  if (dev->intr_cnt > RSHIM_PCIE_NIC_IRQ_RATE)
    return;

  pthread_mutex_lock(&bd->mutex);

  rc = bd->read_rshim(bd, RSHIM_CHANNEL, bd->regs->scratchpad6,
                      &info.word, RSHIM_REG_SIZE_8B);
  if (rc || RSHIM_BAD_CTRL_REG(info.word)) {
    if (!bd->drop_mode)
      RSHIM_WARN("rshim%d failed to read irq request\n", bd->index);
    goto intr_done;
  }

  /* Only handles NIC reset for now. */
  if (info.rst_type != RSHIM_PCIE_RST_TYPE_NIC_RESET &&
      info.rst_type != RSHIM_PCIE_RST_TYPE_DPU_RESET) {
    goto intr_done;
  }

  RSHIM_INFO("rshim%d receive interrupt for %s reset\n", bd->index,
    (info.rst_type == RSHIM_PCIE_RST_TYPE_NIC_RESET) ? "NIC" :
    ((info.rst_type == RSHIM_PCIE_RST_TYPE_DPU_RESET) ? "DPU" : ""));

  switch (info.rst_state) {
  case RSHIM_PCIE_RST_STATE_REQUEST:
    RSHIM_INFO("rshim%d NIC reset ACK\n", bd->index);
    info.pcie = 1;
    info.rst_reply = RSHIM_PCIE_RST_REPLY_ACK;
    __sync_synchronize();
    bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->scratchpad6,
                    info.word, RSHIM_REG_SIZE_8B);
    break;

  case RSHIM_PCIE_RST_STATE_ABORT:
    RSHIM_INFO("rshim%d NIC reset ABORT\n", bd->index);
    info.pcie = 1;
    info.word &= 0xFFFFFFFFUL;
    bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->scratchpad6,
                    info.word, RSHIM_REG_SIZE_8B);
    break;

  case RSHIM_PCIE_RST_STATE_START:
    RSHIM_INFO("rshim%d NIC reset START\n", bd->index);

    info.rst_reply = RSHIM_PCIE_RST_START_ACK;
    info.pcie = 1;
    dev->nic_reset = true;
    __sync_synchronize();
    bd->write_rshim(bd, RSHIM_CHANNEL, bd->regs->scratchpad6,
                    info.word, RSHIM_REG_SIZE_8B);

    /*
     * Both NIC and ARM reset.
     * - Set drop_mode to prevent further read/write;
     * - Take the mutex so the main thread is not in Rx/Tx loop;
     * - Clear FIFO state;
     * - Add a small delay for ARM to be ready;
     */
    __sync_synchronize();
    drop_mode = bd->drop_mode;
    bd->drop_mode = 1;
    rshim_fifo_reset(bd);
    delay = (info.rst_downtime * 10 + 999) / 1000;
    if (delay < RSHIM_PCIE_RST_START_MIN_DELAY)
      delay = RSHIM_PCIE_RST_START_MIN_DELAY;
    sleep(delay);
    bd->drop_mode = drop_mode;
    dev->nic_reset = false;
    break;

  default:
    break;
  }

  if (!bd->drop_mode)
    rshim_pcie_enable_irq(dev, true);

intr_done:
    pthread_mutex_unlock(&bd->mutex);
}

static void rshim_pcie_intr_poll(rshim_pcie_t *dev)
{
  uint16_t reg;

  usleep(rshim_pcie_intr_poll_interval * 1000);

  reg = rshim_pci_read_word(dev, PCI_STATUS);
  if ((reg != 0xFFFF) && (reg & PCI_STATUS_INTx))
    rshim_pcie_intr(dev);
}

static void *rshim_pcie_intr_thread(void *arg)
{
  rshim_pcie_t *dev = arg;
  uint8_t intr_buf[16];
  int rc, reset_seq;

  reset_seq = dev->intr_reset_seq;

  while (rshim_run) {
    if (dev->intr_fd < 0) {
      if (dev->mmap_mode == RSHIM_PCIE_MMAP_DIRECT)
        rshim_pcie_intr_poll(dev);
      else
        sleep(1);
      continue;
    }

    rc = read(dev->intr_fd, intr_buf, dev->intr_len);
    if (rc < 0) {
      if (errno == EINTR)
        continue;
    } else if (rc == 0) {
      sleep(1);
      continue;
    }

    __sync_synchronize();
    if (reset_seq != dev->intr_reset_seq) {
      reset_seq = dev->intr_reset_seq;
      continue;
    }

    /* Interrupt handler. */
    rshim_pcie_intr(dev);
  }

  return NULL;
}

#elif defined(__FreeBSD__)

static int rshim_pcie_mmap(rshim_pcie_t *dev, bool enable)
{
  struct pci_bar_mmap pbm = {
    .pbm_sel.pc_func = dev->func,
    .pbm_sel.pc_dev = dev->dev,
    .pbm_sel.pc_bus = dev->bus,
    .pbm_sel.pc_domain = dev->domain,
    .pbm_reg = 0x10,
    .pbm_flags = PCIIO_BAR_MMAP_RW,
    .pbm_memattr = VM_MEMATTR_UNCACHEABLE,
  };
  int rc;

  if (!enable) {
    if (dev->device_fd >= 0) {
      close(dev->device_fd);
      dev->device_fd = -1;
      return 0;
    }
  }

  dev->device_fd = open("/dev/pci", O_RDWR, 0);
  if (dev->device_fd < 0) {
    RSHIM_ERR("rshim%d failed to open /dev/pci\n", dev->bd.index);
    return -ENODEV;
  }

  if (ioctl(dev->device_fd, PCIOCBARMMAP, &pbm) < 0) {
    RSHIM_ERR("rshim%d PCIOCBARMMAP IOCTL failed\n", dev->bd.index);
    rc = -ENODEV;
    goto rshim_map_failed;
  }

  dev->rshim_regs = (void *)((uintptr_t)pbm.pbm_map_base +
      (uintptr_t)pbm.pbm_bar_off);
  if (pbm.pbm_bar_length < dev->bar_size) {
    dev->rshim_regs = NULL;
    RSHIM_ERR("rshim%d BAR length is too small\n", dev->bd.index);
    rc = -ENOMEM;
    goto rshim_map_failed;
  }

  return 0;

rshim_map_failed:
  close(dev->device_fd);
  dev->device_fd = -1;
  return rc;
}

#else
#error "Platform not supported"
#endif /* __linux__ */

static uint32_t
rshim_pcie_bf3_chan_addr_convert(uint32_t chan, uint32_t addr)
{
  if (chan < 0xF)
    addr += bf3_rshim_pcie_chan_map[chan] + BF3_RSH_BASE_ADDR;
  else
    addr = (chan << 16) + addr;

  return addr;
}

/* RShim read/write routines */
static int __attribute__ ((noinline))
rshim_pcie_read(rshim_backend_t *bd, uint32_t chan, uint32_t addr,
                uint64_t *result, int size)
{
  rshim_pcie_t *dev = container_of(bd, rshim_pcie_t, bd);
  int rc = 0;

  if (dev->nic_reset &&
      (chan != RSHIM_CHANNEL || addr != bd->regs->scratchpad6))
    sleep(RSHIM_PCIE_NIC_RESET_WAIT);

  if (bd->drop_mode && !bd->requesting_rshim) {
    *result = 0;
    return 0;
  }

  if (!bd->has_rshim || !bd->has_tm || !dev->rshim_regs)
    return -ENODEV;

  dev->write_count = 0;

  if (rshim_is_bluefield3(dev->device_id)) {
    addr = rshim_pcie_bf3_chan_addr_convert(chan, addr);
    if (addr < BF3_RSH_BASE_ADDR ||
        addr >= (BF3_RSH_BASE_ADDR + BF3_PCI_RSHIM_WINDOW_SIZE))
      return -EINVAL;
    addr -= BF3_RSH_BASE_ADDR;
  } else {
    addr = addr | (chan << 16);
  }

  if (size == 4)
    *result = readl(dev->rshim_regs + addr);
  else if (size == 8)
    *result = readq(dev->rshim_regs + addr);
  else
    rc = -EINVAL;

  return rc;
}

static int __attribute__ ((noinline))
rshim_pcie_write(rshim_backend_t *bd, uint32_t chan, uint32_t addr,
                 uint64_t value, int size)
{
  rshim_pcie_t *dev = container_of(bd, rshim_pcie_t, bd);
  uint64_t result;
  int rc = 0;

  if (dev->nic_reset &&
      (chan != RSHIM_CHANNEL || addr != bd->regs->scratchpad6))
    sleep(RSHIM_PCIE_NIC_RESET_WAIT);

  if (bd->drop_mode && !bd->requesting_rshim)
    return 0;

  if (!bd->has_rshim || !bd->has_tm || !dev->rshim_regs)
    return -ENODEV;

  /*
   * We cannot stream large numbers of PCIe writes to the RShim's BAR.
   * Instead, we must write no more than 15 8-byte words before
   * doing a read from another register within the BAR,
   * which forces previous writes to drain.
   */
  if (rshim_is_bluefield1(dev->device_id)) {
    if (dev->write_count == 15) {
      __sync_synchronize();
      rshim_pcie_read(bd, chan, RSH_SCRATCHPAD1, &result, rc);
    }
    dev->write_count++;
  }

  if (rshim_is_bluefield3(dev->device_id)) {
    addr = rshim_pcie_bf3_chan_addr_convert(chan, addr);
    if (addr < BF3_RSH_BASE_ADDR ||
        addr >= (BF3_RSH_BASE_ADDR + BF3_PCI_RSHIM_WINDOW_SIZE))
      return -EINVAL;
    addr -= BF3_RSH_BASE_ADDR;
  } else {
    addr = addr | (chan << 16);
  }

  if (size == 4)
    writel(value, dev->rshim_regs + addr);
  else if (size == 8)
    writeq(value, dev->rshim_regs + addr);
  else
    rc = -EINVAL;

  return rc;
}

static void rshim_pcie_delete(rshim_backend_t *bd)
{
  rshim_pcie_t *dev = container_of(bd, rshim_pcie_t, bd);

  rshim_deregister(bd);
  free(dev);
}

/* Enable RSHIM PF and setup memory map. */
static int rshim_pcie_enable(rshim_backend_t *bd, bool enable)
{
  rshim_pcie_t *dev = container_of(bd, rshim_pcie_t, bd);
  int rc = 0;

#ifdef __linux__
  if (!dev->device_id)
    return -ENODEV;

  /*
   * Clear scratchpad1 since it's checked by FW for rshim driver.
   * This needs to be done before the resources are unmapped.
   */
  if (!enable) {
    rshim_pcie_write(bd, RSHIM_CHANNEL, bd->regs->scratchpad1, 0,
                     RSHIM_REG_SIZE_8B);
    rshim_pcie_write(bd, RSHIM_CHANNEL, bd->regs->scratchpad6, 0,
                     RSHIM_REG_SIZE_8B);
  }

  /* Unmap existing resource first. */
  rshim_pcie_mmap(dev, false);

  /* Bind/unbind the device. */
  rshim_pcie_bind(dev, enable);

  /* Remap the resource. */
  if (enable) {
    rc = rshim_pcie_mmap(dev, true);

    /* Fall-back to uio if failed. */
    if (rc < 0 && dev->mmap_mode == RSHIM_PCIE_MMAP_VFIO &&
        rshim_pcie_has_uio()) {
      RSHIM_INFO("rshim%d fall-back to uio\n", bd->index);
      rshim_pcie_bind(dev, false);
      dev->pci_path = SYS_UIO_PCI_PATH;
      dev->mmap_mode = RSHIM_PCIE_MMAP_UIO;
      rshim_pcie_bind(dev, true);
      rc = rshim_pcie_mmap(dev, true);
    }

    /* Fall-back to direct map if failed. */
    if (rc < 0 && dev->mmap_mode != RSHIM_PCIE_MMAP_DIRECT) {
      RSHIM_INFO("rshim%d fall-back to direct io\n", bd->index);
      rshim_pcie_bind(dev, false);
      dev->pci_path = NULL;
      dev->mmap_mode = RSHIM_PCIE_MMAP_DIRECT;
      rshim_pcie_bind(dev, true);
      rc = rshim_pcie_mmap(dev, true);
    }
  }
#else
  /* Unmap existing resource then remap it. */
  rshim_pcie_mmap(dev, false);

  if (enable)
    rc = rshim_pcie_mmap(dev, true);
#endif /* __linux__ */

  RSHIM_INFO("%s %s\n", bd->dev_name, enable ? "enable" : "disable");

  return rc;
}

/* Probe routine */
static int rshim_pcie_probe(struct pci_dev *pci_dev)
{
  char dev_name[RSHIM_DEV_NAME_LEN];
  rshim_backend_t *bd;
  rshim_pcie_t *dev;
  int rc = 0;

  snprintf(dev_name, sizeof(dev_name) - 1, "pcie-%04x:%02x:%02x.%x",
           pci_dev->domain, pci_dev->bus, pci_dev->dev, pci_dev->func);

  if (!rshim_allow_device(dev_name))
    return -EACCES;

  RSHIM_INFO("Probing %s(%s)\n", dev_name,
             rshim_pcie_mmap_name[rshim_pcie_mmap_mode]);

  rshim_lock();

  bd = rshim_find_by_name(dev_name);
  if (bd) {
    RSHIM_INFO("Found %s\n", dev_name);
    dev = container_of(bd, rshim_pcie_t, bd);
  } else {
    RSHIM_INFO("Create rshim %s\n", dev_name);
    dev = calloc(1, sizeof(*dev));
    if (dev == NULL) {
      rshim_unlock();
      return -ENOMEM;
    }

    bd = &dev->bd;
    strcpy(bd->dev_name, dev_name);
    bd->type = RSH_BACKEND_PCIE;
    bd->drop_mode = (rshim_drop_mode >= 0) ? rshim_drop_mode : 0;
    bd->locked_mode = 0;
    bd->read_rshim = rshim_pcie_read;
    bd->write_rshim = rshim_pcie_write;
    bd->destroy = rshim_pcie_delete;
    bd->enable_device = rshim_pcie_enable;
    dev->write_count = 0;
    dev->device_fd = -1;
    dev->group_fd = -1;
    dev->container_fd = -1;
    dev->intr_fd = -1;
    dev->mmap_mode = rshim_pcie_mmap_mode;
#ifdef __linux__
    dev->pci_path = rshim_sys_pci_path;
#endif
    time(&dev->last_intr_time);
    pthread_mutex_init(&bd->mutex, NULL);
  }

  rshim_ref(bd);

  switch (pci_dev->device_id) {
    case BLUEFIELD3_DEVICE_ID:
    case BLUEFIELD3_DEVICE_ID2:
      bd->regs = &bf3_rshim_regs;
      bd->ver_id = RSHIM_BLUEFIELD_3;
      dev->bar_size = BF3_PCI_RSHIM_WINDOW_SIZE;
      break;
    case BLUEFIELD2_DEVICE_ID:
      bd->regs = &bf1_bf2_rshim_regs;
      bd->ver_id = RSHIM_BLUEFIELD_2;
      dev->bar_size = PCI_RSHIM_WINDOW_SIZE;
      break;
    default:
      bd->regs = &bf1_bf2_rshim_regs;
      bd->ver_id = RSHIM_BLUEFIELD_1;
      dev->bar_size = PCI_RSHIM_WINDOW_SIZE;
      break;
  }
  bd->rev_id = pci_read_byte(pci_dev, PCI_REVISION_ID);

  if (rshim_has_pcie_reset_delay || bd->ver_id < RSHIM_BLUEFIELD_3)
    bd->reset_delay = rshim_pcie_reset_delay;
  else
    bd->reset_delay = 3; /* minimum delay for BF3 */

  /* Initialize object */
  dev->device_id = pci_dev->device_id;
  dev->domain = pci_dev->domain;
  dev->bus = pci_dev->bus;
  dev->dev = pci_dev->dev;
  dev->func = pci_dev->func;

  /* Enable the device and setup memory map. */
  if (!bd->drop_mode) {
    pthread_mutex_lock(&bd->mutex);
    rc = bd->enable_device(bd, true);
    pthread_mutex_unlock(&bd->mutex);
    if (rc)
      goto rshim_probe_failed;
  }

  pthread_mutex_lock(&bd->mutex);
  /*
   * Register rshim here since it needs to detect whether other backend
   * has already registered or not, which involves reading/writting rshim
   * registers and has assumption that the under layer is working.
   */
  bd->has_rshim = 1;
  bd->has_tm = 1;
  rc = rshim_register(bd);
  /* Notify that the device is attached */
  if (!rc && !bd->drop_mode)
    rc = rshim_notify(bd, RSH_EVENT_ATTACH, 0);
  pthread_mutex_unlock(&bd->mutex);
  if (rc)
    goto rshim_probe_failed;

#ifdef __linux__
  /* Create interrupt handling thread for BlueField-2 and above. */
  if (pci_dev->device_id != BLUEFIELD1_DEVICE_ID) {
    rc = pthread_create(&dev->intr_thread, NULL, rshim_pcie_intr_thread, dev);
    if (rc)
      RSHIM_ERR("rshim%d failed to create intr thread\n", bd->index);
  }
#endif

  rshim_unlock();
  return 0;

rshim_probe_failed:
   rshim_deref(bd);
   rshim_unlock();
   return rc;
}

#ifdef __linux__
static bool rshim_pcie_has_vfio(void)
{
  struct dirent* d;
  DIR* dir;
  int rc;

  if (!rshim_pcie_enable_vfio)
    return false;

  rc = system("modprobe vfio_pci");
  if (rc == -1)
    RSHIM_DBG("Failed to load the vfio_pci module %m\n");
  dir = opendir(SYS_CLASS_VFIO_PCI_PATH);
  if (!dir)
    return false;
  closedir(dir);

  dir = opendir(SYS_CLASS_IOMMU_PATH);
  if (!dir)
    return false;
  while ((d = readdir(dir)) != NULL) {
    if (strcmp(d->d_name, ".") && strcmp(d->d_name, ".."))
      break;
  }
  closedir(dir);

  return (d != NULL);
}

static bool rshim_pcie_has_uio(void)
{
  DIR* dir;
  int rc;

  if (!rshim_pcie_enable_uio)
    return false;

  rc = system("modprobe uio_pci_generic");
  if (rc == -1)
    RSHIM_DBG("Failed to load the uio_pci_generic module %m\n");
  dir = opendir(SYS_CLASS_UIO_PCI_PATH);
  if (!dir)
    return false;
  closedir(dir);

  return true;
}

static bool kernel_lock_down_enabled(void)
{
  char buf[64] = { 0 }, *p;
  FILE *file;

  file = fopen("/sys/kernel/security/lockdown", "rt");
  if (!file)
    return false;
  p = fgets(buf, sizeof(buf), file);
  fclose(file);

  return (p != NULL && (strstr(buf, "[integrity]") != NULL ||
          strstr(buf, "[confidentiality]") != NULL));
}
#endif /* __linux__ */

int rshim_pcie_init(void)
{
  bool dev_present = false;
  struct pci_access *pci;
  struct pci_dev *dev;
  int rc;

#ifdef __linux__
  if (rshim_pcie_has_vfio()) {
    rshim_pcie_mmap_mode = RSHIM_PCIE_MMAP_VFIO;
    rshim_sys_pci_path = SYS_VFIO_PCI_PATH;
  } else {
    /* Linux kernel lock_down requires VFIO. */
    if (kernel_lock_down_enabled()) {
      RSHIM_ERR("Need to enable IOMMU/VFIO for kernel lock-down\n");
      return -ENOTSUP;
    }

    if (rshim_pcie_has_uio()) {
      rshim_pcie_mmap_mode = RSHIM_PCIE_MMAP_UIO;
      rshim_sys_pci_path = SYS_UIO_PCI_PATH;
    }
  }

#endif /* __linux__ */

  pci = pci_alloc();
  if (!pci)
    return -ENOMEM;

  pci_init(pci);

  pci_scan_bus(pci);

  /* Iterate over the devices */
  for (dev = pci->devices; dev; dev = dev->next) {
    pci_fill_info(dev, PCI_FILL_IDENT | PCI_FILL_BASES | PCI_FILL_CLASS);

    if (dev->vendor_id != TILERA_VENDOR_ID ||
        (!rshim_is_bluefield1(dev->device_id) &&
         !rshim_is_bluefield2(dev->device_id) &&
         !rshim_is_bluefield3(dev->device_id)))
      continue;

    rc = rshim_pcie_probe(dev);
    if (rc)
      continue;

    dev_present = true;
  }

  pci_cleanup(pci);

  if (!dev_present)
    return -ENODEV;

  return 0;
}
