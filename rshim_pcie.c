/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 * Copyright 2019 Mellanox Technologies. All Rights Reserved.
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
#endif

#include "rshim.h"

/* Our Vendor/Device IDs. */
#define TILERA_VENDOR_ID            0x15b3
#define BLUEFIELD_DEVICE_ID         0xc2d2

/* The offset in BAR2 of the RShim region. */
#define PCI_RSHIM_WINDOW_OFFSET     0x0

/* The size the RShim region. */
#define PCI_RSHIM_WINDOW_SIZE       0x100000

#if 1
static inline uint64_t
readq(const volatile void *addr)
{
  return *(const volatile uint64_t *)addr;
}

static inline void
writeq(uint64_t value, volatile void *addr)
{
  *(volatile uint64_t *)addr = value;
}
#endif

struct rshim_pcie {
  /* RShim backend structure. */
  struct rshim_backend bd;

  struct pci_dev *pci_dev;

  /* Address of the RShim registers. */
  volatile u8 *rshim_regs;

  /* Keep track of number of 8-byte word writes */
  u8 write_count;

  /* File handle for PCI BAR */
  int pci_fd;
};

#ifndef __LP64__
/* Wait until the RSH_BYTE_ACC_CTL pending bit is cleared */
static int rshim_byte_acc_pending_wait(struct rshim_pcie *dev, int chan)
{
  uint32_t read_value;

  do {
    read_value = readl(dev->rshim_regs +
      (RSH_BYTE_ACC_CTL | (chan << 16)));

    if (signal_pending(current))
      return -EINTR;

  } while (read_value & RSH_BYTE_ACC_PENDING);

  return 0;
}

/*
 * RShim read/write methods for 32-bit systems
 * Mechanism to do an 8-byte access to the Rshim using
 * two 4-byte accesses through the Rshim Byte Access Widget.
 */
static int rshim_byte_acc_read(struct rshim_pcie *dev, int chan, int addr,
                               uint64_t *result)
{
  uint64_t read_result;
  uint32_t read_value;
  int rc;

  /* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
  rc = rshim_byte_acc_pending_wait(dev, chan);
  if (rc)
    return rc;

  /* Write control bits to RSH_BYTE_ACC_CTL */
  writel(RSH_BYTE_ACC_SIZE, dev->rshim_regs +
         (RSH_BYTE_ACC_CTL | (chan << 16)));

  /* Write target address to RSH_BYTE_ACC_ADDR */
  writel(addr, dev->rshim_regs + (RSH_BYTE_ACC_ADDR | (chan << 16)));

  /* Write trigger bits to perform read */
  writel(RSH_BYTE_ACC_READ_TRIGGER, dev->rshim_regs +
         (RSH_BYTE_ACC_CTL | (chan << 16)));

  /* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
  rc = rshim_byte_acc_pending_wait(dev, chan);
  if (rc)
    return rc;

  /* Read RSH_BYTE_ACC_RDAT to read lower 32-bits of data */
  read_value = readl(dev->rshim_regs + (RSH_BYTE_ACC_RDAT | (chan << 16)));

  read_result = (uint64_t)read_value << 32;

  /* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
  rc = rshim_byte_acc_pending_wait(dev, chan);
  if (rc)
    return rc;

  /* Read RSH_BYTE_ACC_RDAT to read upper 32-bits of data */
  read_value = readl(dev->rshim_regs + (RSH_BYTE_ACC_RDAT | (chan << 16)));

  read_result |= (uint64_t)read_value;
  *result = be64_to_cpu(read_result);

  return 0;
}

static int rshim_byte_acc_write(struct rshim_pcie *dev, int chan, int addr,
                                uint64_t value)
{
  int rc;

  /* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
  rc = rshim_byte_acc_pending_wait(dev, chan);
  if (rc)
    return rc;

  /* Write control bits to RSH_BYTE_ACC_CTL */
  writel(RSH_BYTE_ACC_SIZE, dev->rshim_regs +
         (RSH_BYTE_ACC_CTL | (chan << 16)));

  /* Write target address to RSH_BYTE_ACC_ADDR */
  writel(addr, dev->rshim_regs + (RSH_BYTE_ACC_ADDR | (chan << 16)));

  /* Write control bits to RSH_BYTE_ACC_CTL */
  writel(RSH_BYTE_ACC_SIZE, dev->rshim_regs +
         (RSH_BYTE_ACC_CTL | (chan << 16)));

  /* Write lower 32 bits of data to TRIO_CR_GW_DATA */
  writel((uint32_t)(value >> 32), dev->rshim_regs +
         (RSH_BYTE_ACC_WDAT | (chan << 16)));

  /* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
  rc = rshim_byte_acc_pending_wait(dev, chan);
  if (rc)
    return rc;

  /* Write upper 32 bits of data to TRIO_CR_GW_DATA */
  writel((uint32_t)(value), dev->rshim_regs +
         (RSH_BYTE_ACC_WDAT | (chan << 16)));

  return 0;
}
#endif

/* RShim read/write routines */
static int rshim_pcie_read(struct rshim_backend *bd, int chan, int addr,
                           uint64_t *result)
{
  struct rshim_pcie *dev = container_of(bd, struct rshim_pcie, bd);
  int rc = 0;

  if (!bd->has_rshim)
    return -ENODEV;

  dev->write_count = 0;

#ifndef __LP64__
  rc = rshim_byte_acc_read(dev, chan, addr, result);
#else
  *result = readq(dev->rshim_regs + (addr | (chan << 16)));
#endif
  return rc;
}

static int rshim_pcie_write(struct rshim_backend *bd, int chan, int addr,
                            uint64_t value)
{
  struct rshim_pcie *dev = container_of(bd, struct rshim_pcie, bd);
  uint64_t result;
  int rc = 0;

  if (!bd->has_rshim)
    return -ENODEV;

  /*
   * We cannot stream large numbers of PCIe writes to the RShim's BAR.
   * Instead, we must write no more than 15 8-byte words before
   * doing a read from another register within the BAR,
   * which forces previous writes to drain.
   */
  if (dev->write_count == 15) {
    __sync_synchronize();
    rshim_pcie_read(bd, chan, RSH_SCRATCHPAD, &result);
  }
  dev->write_count++;
#ifndef __LP64__
  rc = rshim_byte_acc_write(dev, chan, addr, value);
#else
  writeq(value, dev->rshim_regs + (addr | (chan << 16)));
#endif

  return rc;
}

static void rshim_pcie_delete(struct rshim_backend *bd)
{
  struct rshim_pcie *dev = container_of(bd, struct rshim_pcie, bd);

  rshim_deregister(bd);
  free(dev);
}

/* Probe routine */
static int rshim_pcie_probe(struct pci_dev *pci_dev)
{
  const int max_name_len = 64;
  int ret;
  struct rshim_backend *bd;
  struct rshim_pcie *dev;
  char *pcie_dev_name;
#ifdef __linux__
  pciaddr_t bar0;
#endif

  pcie_dev_name = malloc(max_name_len);
  snprintf(pcie_dev_name, max_name_len, "pcie-lf-%d-%d-%d-%d",
           pci_dev->domain_16, pci_dev->bus, pci_dev->dev, pci_dev->func);

  RSHIM_INFO("Probing %s\n", pcie_dev_name);

  rshim_lock();

  bd = rshim_find_by_name(pcie_dev_name);
  if (bd) {
    dev = container_of(bd, struct rshim_pcie, bd);
  } else {
    dev = calloc(1, sizeof(*dev));
    if (dev == NULL) {
      ret = -ENOMEM;
      rshim_unlock();
      goto error;
    }

    bd = &dev->bd;
    bd->has_rshim = 1;
    bd->has_tm = 1;
    bd->dev_name = pcie_dev_name;
    bd->drv_name = "rshim_pcie";
    bd->read_rshim = rshim_pcie_read;
    bd->write_rshim = rshim_pcie_write;
    bd->destroy = rshim_pcie_delete;
    dev->write_count = 0;
    pthread_mutex_init(&bd->mutex, NULL);
  }

  rshim_ref(bd);

  rshim_unlock();

  /* Initialize object */
  dev->pci_dev = pci_dev;

#ifdef __linux__
  if (!pci_dev->size[0]) {
    RSHIM_ERR("BAR[0] unassigned, run 'lspci -v'.");
    ret = -ENOMEM;
    goto rshim_map_failed;
  }

  /* Map in the RShim registers. */
  dev->pci_fd = open("/dev/mem", O_RDWR | O_SYNC);
  bar0 = (pci_dev->base_addr[0] & PCI_BASE_ADDRESS_MEM_MASK) &
         ~(getpagesize() - 1);
  dev->rshim_regs = mmap(NULL, PCI_RSHIM_WINDOW_SIZE, PROT_READ | PROT_WRITE,
                         MAP_SHARED, dev->pci_fd, bar0 + PCI_RSHIM_WINDOW_OFFSET);
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

  /*
   * Register rshim here since it needs to detect whether other backend
   * has already registered or not, which involves reading/writting rshim
   * registers and has assumption that the under layer is working.
   */
  rshim_lock();
  if (!bd->registered) {
    ret = rshim_register(bd);
    if (ret) {
      rshim_unlock();
      goto rshim_map_failed;
    } else {
      pcie_dev_name = NULL;
    }
  }
  rshim_unlock();

  /* Notify that the device is attached */
  pthread_mutex_lock(&bd->mutex);
  ret = rshim_notify(bd, RSH_EVENT_ATTACH, 0);
  pthread_mutex_unlock(&bd->mutex);
  if (ret)
    goto rshim_map_failed;

  return 0;

 rshim_map_failed:
 enable_failed:
   rshim_lock();
   rshim_deref(bd);
   rshim_unlock();
 error:
   free(pcie_dev_name);
   return ret;
}

#if 0
/* Called via pci_unregister_driver() when the module is removed. */
static void rshim_pcie_remove(struct pci_dev *pci_dev)
{
  struct rshim_pcie *dev = dev_get_drvdata(&pci_dev->dev);
  int flush_wq;

  if (!dev)
    return;

  /*
   * Reset TRIO_PCIE_INTFC_RX_BAR0_ADDR_MASK and TRIO_MAP_RSH_BASE.
   * Otherwise, upon host reboot, the two registers will retain previous
   * values that don't match the new BAR0 address that is assigned to
   * the PCIe ports, causing host MMIO access to RShim to fail.
   */
  rshim_pcie_write(&dev->bd, (RSH_SWINT >> 16) & 0xF,
                   RSH_SWINT & 0xFFFF, RSH_INT_VEC0_RTC__SWINT3_MASK);

  /* Clear the flags before unmapping rshim registers to avoid race. */
  dev->bd.has_rshim = 0;
  dev->bd.has_tm = 0;
  mb();

  if (dev->rshim_regs)
    iounmap(dev->rshim_regs);

  rshim_notify(&dev->bd, RSH_EVENT_DETACH, 0);
  pthread_mutex_lock(&dev->bd.mutex);
  flush_wq = !cancel_delayed_work(&dev->bd.work);
  if (flush_wq)
    flush_workqueue(rshim_wq);
  dev->bd.has_cons_work = 0;
  pthread_mutex_unlock(&dev->bd.mutex);

  rshim_lock();
  rshim_deref(bd);
  rshim_unlock();
}
#endif

int rshim_pcie_init(void)
{
  struct pci_access *pci;
  struct pci_dev *dev;

  pci = pci_alloc();
  if (!pci)
    return -ENOMEM;

  pci_init(pci);

  pci_scan_bus(pci);

  /* Iterate over the devices */
  for (dev = pci->devices; dev; dev = dev->next) {
    pci_fill_info(dev, PCI_FILL_IDENT | PCI_FILL_BASES | PCI_FILL_CLASS);

    if (dev->vendor_id != TILERA_VENDOR_ID ||
        dev->device_id != BLUEFIELD_DEVICE_ID)
      continue;

    rshim_pcie_probe(dev);
  }

  // pci_cleanup(pci);

  return 0;
}

void rshim_pcie_exit(void)
{
}
