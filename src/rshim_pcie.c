// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2019 Mellanox Technologies. All Rights Reserved.
 *
 */

#include <sys/epoll.h>
#include <sys/mman.h>
#include <pci/pci.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <pthread.h>

#ifdef __FreeBSD__
#include <sys/pciio.h>
#include <sys/ioctl.h>
#include <vm/vm.h>
#include <cuse.h>
#endif

#include "rshim.h"

/* Our Vendor/Device IDs. */
#define TILERA_VENDOR_ID            0x15b3
#define BLUEFIELD1_DEVICE_ID        0xc2d2
#define BLUEFIELD2_DEVICE_ID        0xc2d3
#define BLUEFIELD2_DEVICE_ID2       0xc2d6

/* The offset in BAR2 of the RShim region. */
#define PCI_RSHIM_WINDOW_OFFSET     0x0

/* The size the RShim region. */
#define PCI_RSHIM_WINDOW_SIZE       0x100000

#ifdef __linux__
#include <dirent.h>
#define SYS_BUS_PCI "/sys/bus/pci/devices"
#endif

#ifndef __LP64__
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
#else
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
#endif

typedef struct {
  /* RShim backend structure. */
  rshim_backend_t bd;

  struct pci_dev *pci_dev;

  /* Address of the RShim registers. */
  volatile uint8_t *rshim_regs;

  /* Keep track of number of 8-byte word writes */
  uint8_t write_count;

  /* File handle for PCI BAR */
  int pci_fd;
} rshim_pcie_t;

static bool rshim_is_bluefield1(uint16_t device_id)
{
  return (device_id == BLUEFIELD1_DEVICE_ID);
}

static bool rshim_is_bluefield2(uint16_t device_id)
{
  return (device_id == BLUEFIELD2_DEVICE_ID) ||
         (device_id == BLUEFIELD2_DEVICE_ID2);
}

#ifndef __LP64__
/* Wait until the RSH_BYTE_ACC_CTL pending bit is cleared */
static int rshim_byte_acc_pending_wait(rshim_pcie_t *dev)
{
  uint32_t read_value;
  int retry = 0;

  do {
    read_value = readl(dev->rshim_regs +
                       (RSH_BYTE_ACC_CTL | (RSHIM_CHANNEL << 16)));

    if (++retry > LOCK_RETRY_CNT)
      return -ETIMEDOUT;

  } while (read_value & RSH_BYTE_ACC_PENDING);

  return 0;
}

/* Acquire BAW Interlock */
static int rshim_byte_acc_lock_acquire(rshim_pcie_t *dev)
{
  uint32_t read_value;
  int retry = 0;

  do {
    if (++retry > LOCK_RETRY_CNT)
      return -ETIMEDOUT;

    read_value = readl(dev->rshim_regs +
                      (RSH_BYTE_ACC_INTERLOCK | (RSHIM_CHANNEL << 16)));
  } while (!(read_value & 0x1));

  return 0;
}

/* Release BAW Interlock */
static void rshim_byte_acc_lock_release(rshim_pcie_t *dev)
{
  writel(0, dev->rshim_regs + (RSH_BYTE_ACC_INTERLOCK | (RSHIM_CHANNEL << 16)));
}

/*
 * RShim read/write methods for 32-bit systems
 * Mechanism to do an 8-byte access to the Rshim using
 * two 4-byte accesses through the Rshim Byte Access Widget.
 */
static int rshim_byte_acc_read(rshim_pcie_t *dev, int addr, uint64_t *result)
{
  uint64_t read_result;
  uint32_t read_value;
  int rc;

  /* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
  rc = rshim_byte_acc_pending_wait(dev);
  if (rc)
    return rc;

  if (rshim_is_bluefield2(dev->pci_dev->device_id)) {
    /* Acquire RSH_BYTE_ACC_INTERLOCK */
    rc = rshim_byte_acc_lock_acquire(dev);
    if (rc)
      return rc;
  }

  /* Write target address to RSH_BYTE_ACC_ADDR */
  writel(addr, dev->rshim_regs + (RSH_BYTE_ACC_ADDR | (RSHIM_CHANNEL << 16)));

  /* Write control and trigger bits to perform read */
  writel(RSH_BYTE_ACC_SIZE_4BYTE | RSH_BYTE_ACC_READ_TRIGGER,
         dev->rshim_regs + (RSH_BYTE_ACC_CTL | (RSHIM_CHANNEL << 16)));

  /* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
  rc = rshim_byte_acc_pending_wait(dev);
  if (rc)
    goto exit_read;

  /* Read RSH_BYTE_ACC_RDAT to read lower 32-bits of data */
  read_value = readl(dev->rshim_regs +
                     (RSH_BYTE_ACC_RDAT | (RSHIM_CHANNEL << 16)));

  read_result = (uint64_t)read_value << 32;

  /* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
  rc = rshim_byte_acc_pending_wait(dev);
  if (rc)
    goto exit_read;

  /* Read RSH_BYTE_ACC_RDAT to read upper 32-bits of data */
  read_value = readl(dev->rshim_regs +
                     (RSH_BYTE_ACC_RDAT | (RSHIM_CHANNEL << 16)));

  read_result |= (uint64_t)read_value;
  *result = be64toh(read_result);

exit_read:
  /* Release RSH_BYTE_ACC_INTERLOCK */
  if (rshim_is_bluefield2(dev->pci_dev->device_id))
    rshim_byte_acc_lock_release(dev);

  return rc;
}

static int rshim_byte_acc_write(rshim_pcie_t *dev, int addr, uint64_t value)
{
  int rc;

  /* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
  rc = rshim_byte_acc_pending_wait(dev);
  if (rc)
    return rc;

  if (rshim_is_bluefield2(dev->pci_dev->device_id)) {
    /* Acquire RSH_BYTE_ACC_INTERLOCK */
    rc = rshim_byte_acc_lock_acquire(dev);
    if (rc)
      return rc;
  }

  /* Write target address to RSH_BYTE_ACC_ADDR */
  writel(addr, dev->rshim_regs +
         (RSH_BYTE_ACC_ADDR | (RSHIM_CHANNEL << 16)));

  /* Write control bits to RSH_BYTE_ACC_CTL */
  writel(RSH_BYTE_ACC_SIZE_4BYTE, dev->rshim_regs +
         (RSH_BYTE_ACC_CTL | (RSHIM_CHANNEL << 16)));

  /* Write lower 32 bits of data to TRIO_CR_GW_DATA */
  writel((uint32_t)(value >> 32), dev->rshim_regs +
         (RSH_BYTE_ACC_WDAT | (RSHIM_CHANNEL << 16)));

  /* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
  rc = rshim_byte_acc_pending_wait(dev);
  if (rc)
    goto exit_write;

  /* Write upper 32 bits of data to TRIO_CR_GW_DATA */
  writel((uint32_t)(value), dev->rshim_regs +
         (RSH_BYTE_ACC_WDAT | (RSHIM_CHANNEL << 16)));

exit_write:
  /* Release RSH_BYTE_ACC_INTERLOCK */
  if (rshim_is_bluefield2(dev->pci_dev->device_id))
    rshim_byte_acc_lock_release(dev);

  return rc;
}
#endif

/* RShim read/write routines */
static int __attribute__ ((noinline))
rshim_pcie_read(rshim_backend_t *bd, int chan, int addr, uint64_t *result)
{
  rshim_pcie_t *dev = container_of(bd, rshim_pcie_t, bd);
  int rc = 0;

  if (!bd->has_rshim)
    return -ENODEV;
  if (bd->drop_mode) {
    *result = 0;
    return 0;
  }

  dev->write_count = 0;

#ifndef __LP64__
  rc = rshim_byte_acc_read(dev, RSH_CHANNEL_BASE(chan) + addr, result);
#else
  *result = readq(dev->rshim_regs + (addr | (chan << 16)));
#endif

  return rc;
}

static int __attribute__ ((noinline))
rshim_pcie_write(rshim_backend_t *bd, int chan, int addr, uint64_t value)
{
  rshim_pcie_t *dev = container_of(bd, rshim_pcie_t, bd);
  uint64_t result;
  int rc = 0;

  if (!bd->has_rshim)
    return -ENODEV;
  if (bd->drop_mode)
    return 0;

  /*
   * We cannot stream large numbers of PCIe writes to the RShim's BAR.
   * Instead, we must write no more than 15 8-byte words before
   * doing a read from another register within the BAR,
   * which forces previous writes to drain.
   */
  if (rshim_is_bluefield1(dev->pci_dev->device_id)) {
    if (dev->write_count == 15) {
      __sync_synchronize();
      rshim_pcie_read(bd, chan, RSH_SCRATCHPAD, &result);
    }
    dev->write_count++;
  }
#ifndef __LP64__
  rc = rshim_byte_acc_write(dev, RSH_CHANNEL_BASE(chan) + addr, value);
#else
  writeq(value, dev->rshim_regs + (addr | (chan << 16)));
#endif

  return rc;
}

static void rshim_pcie_delete(rshim_backend_t *bd)
{
  rshim_pcie_t *dev = container_of(bd, rshim_pcie_t, bd);

  rshim_deregister(bd);
  free(dev);
}

static int rshim_pcie_enable_device(rshim_backend_t *bd, bool enable)
{
  rshim_pcie_t *dev = container_of(bd, rshim_pcie_t, bd);
  int rc = 0;

  if (dev->pci_dev)
    rc = rshim_pcie_enable(dev->pci_dev, enable);

  return rc;
}

/* Probe routine */
static int rshim_pcie_probe(struct pci_dev *pci_dev)
{
  char dev_name[RSHIM_DEV_NAME_LEN];
  rshim_backend_t *bd;
  rshim_pcie_t *dev;
#ifdef __linux__
  char path[256];
#endif
  int ret = 0;

  snprintf(dev_name, sizeof(dev_name) - 1, "pcie-%04x:%02x:%02x.%x",
           pci_dev->domain, pci_dev->bus, pci_dev->dev, pci_dev->func);

  if (!rshim_allow_device(dev_name))
    return -EACCES;

  RSHIM_INFO("Probing %s\n", dev_name);

  rshim_lock();

  bd = rshim_find_by_name(dev_name);
  if (bd) {
    RSHIM_INFO("found %s\n", dev_name);
    dev = container_of(bd, rshim_pcie_t, bd);
  } else {
    RSHIM_INFO("create rshim %s\n", dev_name);
    dev = calloc(1, sizeof(*dev));
    if (dev == NULL) {
      ret = -ENOMEM;
      goto error;
    }

    bd = &dev->bd;
    strcpy(bd->dev_name, dev_name);
    bd->read_rshim = rshim_pcie_read;
    bd->write_rshim = rshim_pcie_write;
    bd->destroy = rshim_pcie_delete;
    bd->enable_device = rshim_pcie_enable_device;
    dev->write_count = 0;
    pthread_mutex_init(&bd->mutex, NULL);
  }

  rshim_ref(bd);

  switch (pci_dev->device_id) {
    case BLUEFIELD2_DEVICE_ID:
    case BLUEFIELD2_DEVICE_ID2:
      bd->bf_ver = RSHIM_BLUEFIELD_2;
      break;
    default:
      bd->bf_ver = RSHIM_BLUEFIELD_1;
  }

  /* Initialize object */
  dev->pci_dev = pci_dev;

#ifdef __linux__
  if (!pci_dev->size[0]) {
    RSHIM_ERR("BAR[0] unassigned, run 'lspci -v'\n");
    ret = -ENOMEM;
    goto rshim_map_failed;
  }
  if (pci_dev->size[0] < PCI_RSHIM_WINDOW_SIZE) {
    RSHIM_ERR("BAR[0] size 0x%x too small\n", (int)pci_dev->size[0]);
    goto rshim_map_failed;
  }

  /* Map in the RShim registers. */
  snprintf(path, sizeof(path), "%s/%04x:%02x:%02x.%1u/resource0",
           SYS_BUS_PCI, pci_dev->domain, pci_dev->bus,
           pci_dev->dev, pci_dev->func);
  dev->pci_fd = open(path, O_RDWR | O_SYNC);
  if (dev->pci_fd < 0) {
    RSHIM_ERR("Failed to open %s\n", path);
    ret = -errno;
    goto rshim_map_failed;
  }

  dev->rshim_regs = mmap(NULL, PCI_RSHIM_WINDOW_SIZE,
                         PROT_READ | PROT_WRITE | MAP_LOCKED,
                         MAP_SHARED, dev->pci_fd,
                         PCI_RSHIM_WINDOW_OFFSET);
  if (dev->rshim_regs == MAP_FAILED) {
    RSHIM_ERR("Failed to map RShim registers\n");
    ret = -ENOMEM;
    goto rshim_map_failed;
  }
#elif defined(__FreeBSD__)
  struct pci_bar_mmap pbm = {
    .pbm_sel.pc_func = pci_dev->func,
    .pbm_sel.pc_dev = pci_dev->dev,
    .pbm_sel.pc_bus = pci_dev->bus,
    .pbm_sel.pc_domain = pci_dev->domain_16,
    .pbm_reg = 0x10,
    .pbm_flags = PCIIO_BAR_MMAP_RW,
    .pbm_memattr = VM_MEMATTR_UNCACHEABLE,
  };

  dev->pci_fd = open("/dev/pci", O_RDWR, 0);
  if (dev->pci_fd < 0) {
    RSHIM_ERR("Failed to open /dev/pci\n");
    ret = -ENOMEM;
    goto rshim_map_failed;
  }

  if (ioctl(dev->pci_fd, PCIOCBARMMAP, &pbm) < 0) {
    RSHIM_ERR("PCIOCBARMMAP IOCTL failed\n");
    ret = -ENOMEM;
    goto rshim_map_failed;
  }
  dev->rshim_regs = (void *)((uintptr_t)pbm.pbm_map_base +
      (uintptr_t)pbm.pbm_bar_off + PCI_RSHIM_WINDOW_OFFSET);
  if (pbm.pbm_bar_length < PCI_RSHIM_WINDOW_SIZE) {
    RSHIM_ERR("BAR length is too small\n");
    ret = -ENOMEM;
    goto rshim_map_failed;
  }
#else
#error "Platform not supported"
#endif

  pthread_mutex_lock(&bd->mutex);

  /*
   * Register rshim here since it needs to detect whether other backend
   * has already registered or not, which involves reading/writting rshim
   * registers and has assumption that the under layer is working.
   */
  bd->has_rshim = 1;
  bd->has_tm = 1;
  ret = rshim_register(bd);
  if (ret) {
    pthread_mutex_unlock(&bd->mutex);
    goto rshim_map_failed;
  }

  /* Notify that the device is attached */
  ret = rshim_notify(bd, RSH_EVENT_ATTACH, 0);
  pthread_mutex_unlock(&bd->mutex);
  if (ret)
    goto rshim_map_failed;

  rshim_unlock();
  return 0;

 rshim_map_failed:
   rshim_deref(bd);
 error:
   rshim_unlock();
   return ret;
}

int rshim_pcie_enable(void *dev, bool enable)
{
#ifdef __linux__
  struct pci_dev *pci_dev = (struct pci_dev *)dev;
  char path[256];
  int fd, rc = 0;
  DIR* dir;

  /* Check whether it's being attached by other driver. */
  snprintf(path, sizeof(path), "%s/%04x:%02x:%02x.%1u/driver",
           SYS_BUS_PCI, pci_dev->domain, pci_dev->bus,
           pci_dev->dev, pci_dev->func);
  dir = opendir(path);
  if (dir) {
    closedir(dir);
    return -EBUSY;
  }

  /* Set the enable attribute in sysfs. */
  snprintf(path, sizeof(path), "%s/%04x:%02x:%02x.%1u/enable",
           SYS_BUS_PCI, pci_dev->domain, pci_dev->bus,
           pci_dev->dev, pci_dev->func);
  fd = open(path, O_RDWR | O_CLOEXEC);
  if (fd == -1)
    return -errno;
  if (write(fd, enable ? "1" : "0", 1) < 0)
    rc = -errno;
  close(fd);
  if (rc)
    return rc;

  pci_write_word(pci_dev, PCI_COMMAND, PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
  return rc;
#else
  return 0;
#endif
}

int rshim_pcie_init(void)
{
  struct pci_access *pci;
  struct pci_dev *dev;
  int rc;

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
         !rshim_is_bluefield2(dev->device_id)))
      continue;

    rc = rshim_pcie_enable(dev, true);
    if (rc)
      continue;

    rshim_pcie_probe(dev);
  }

  return 0;
}
