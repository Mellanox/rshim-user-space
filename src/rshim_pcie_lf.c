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

#include <netinet/in.h>

#include <pthread.h>

#include "rshim.h"

/** Our Vendor/Device IDs. */
#define TILERA_VENDOR_ID            0x15b3
#define BLUEFIELD1_DEVICE_ID        0x0211
#define BLUEFIELD2_DEVICE_ID        0x0214

/* Mellanox Address & Data Capabilities */
#define MELLANOX_ADDR               0x58
#define MELLANOX_DATA               0x5c
#define MELLANOX_CAP_READ           0x1

/* TRIO_CR_GATEWAY registers */
#define TRIO_CR_GW_LOCK             0xe38a0
#define TRIO_CR_GW_LOCK_CPY         0xe38a4
#define TRIO_CR_GW_DATA_UPPER       0xe38ac
#define TRIO_CR_GW_DATA_LOWER       0xe38b0
#define TRIO_CR_GW_CTL              0xe38b4
#define TRIO_CR_GW_ADDR_UPPER       0xe38b8
#define TRIO_CR_GW_ADDR_LOWER       0xe38bc
#define TRIO_CR_GW_LOCK_ACQUIRED    0x80000000
#define TRIO_CR_GW_LOCK_RELEASE     0x0
#define TRIO_CR_GW_BUSY             0x60000000
#define TRIO_CR_GW_TRIGGER          0xe0000000
#define TRIO_CR_GW_READ_4BYTE       0x6
#define TRIO_CR_GW_WRITE_4BYTE      0x2

#define CRSPACE_RSH_CHANNEL1_BASE   0x310000

typedef struct {
  /* RShim backend structure. */
  struct rshim_backend bd;

  struct pci_dev *pci_dev;

  /* Keep track of number of 8-byte word writes */
  u8 write_count;
} rshim_pcie_lf_t;

/* Mechanism to access the CR space using hidden PCI capabilities */
static int pci_cap_read(struct pci_dev *pci_dev, int offset, uint32_t *result)
{
  int rc;

  /*
   * Write target offset to MELLANOX_ADDR.
   * Set LSB to indicate a read operation.
   */
  rc = pci_write_long(pci_dev, MELLANOX_ADDR, offset | MELLANOX_CAP_READ);
  if (rc < 0)
    return rc;

  /* Read result from MELLANOX_DATA */
  *result = pci_read_long(pci_dev, MELLANOX_DATA);

  return 0;
}

static int pci_cap_write(struct pci_dev *pci_dev, int offset, uint32_t value)
{
  int rc;

  /* Write data to MELLANOX_DATA */
  rc = pci_write_long(pci_dev, MELLANOX_DATA, value);
  if (rc < 0)
    return rc;

  /*
   * Write target offset to MELLANOX_ADDR.
   * Leave LSB clear to indicate a write operation.
   */
  rc = pci_write_long(pci_dev, MELLANOX_ADDR, offset);
  if (rc < 0)
    return rc;

  return 0;
}

/* Acquire and release the TRIO_CR_GW_LOCK. */
static int trio_cr_gw_lock_acquire(struct pci_dev *pci_dev)
{
  uint32_t read_value;
  time_t t0, t1;
  int rc;

  /* Wait until TRIO_CR_GW_LOCK is free */
  time(&t0);
  do {
    rc = pci_cap_read(pci_dev, TRIO_CR_GW_LOCK, &read_value);
    if (rc)
      return rc;

    time(&t1);
    if (difftime(t1, t0) > RSHIM_LOCK_RETRY_TIME)
      return -ETIMEDOUT;
  } while (read_value & TRIO_CR_GW_LOCK_ACQUIRED);

  /* Acquire TRIO_CR_GW_LOCK */
  rc = pci_cap_write(pci_dev, TRIO_CR_GW_LOCK, TRIO_CR_GW_LOCK_ACQUIRED);
  if (rc)
    return rc;

  return 0;
}

static int trio_cr_gw_lock_release(struct pci_dev *pci_dev)
{
  int rc;

  /* Release TRIO_CR_GW_LOCK */
  rc = pci_cap_write(pci_dev, TRIO_CR_GW_LOCK, TRIO_CR_GW_LOCK_RELEASE);

  return rc;
}

/*
 * Mechanism to access the RShim from the CR space using the TRIO_CR_GATEWAY.
 */
static int crspace_rsh_gw_read(struct pci_dev *pci_dev, int addr,
                               uint32_t *result)
{
  int rc;

  if (pci_dev->device_id == BLUEFIELD2_DEVICE_ID) {
    addr = (addr & 0xffff) + CRSPACE_RSH_CHANNEL1_BASE;
    rc = pci_cap_read(pci_dev, addr, result);
    return rc;
  }

  addr += RSH_CHANNEL_BASE(RSHIM_CHANNEL);

  /* Acquire TRIO_CR_GW_LOCK */
  rc = trio_cr_gw_lock_acquire(pci_dev);
  if (rc)
    return rc;

  /* Write addr to TRIO_CR_GW_ADDR_LOWER */
  rc = pci_cap_write(pci_dev, TRIO_CR_GW_ADDR_LOWER, addr);
  if (rc)
    return rc;

  /* Set TRIO_CR_GW_READ_4BYTE */
  rc = pci_cap_write(pci_dev, TRIO_CR_GW_CTL, TRIO_CR_GW_READ_4BYTE);
  if (rc)
    return rc;

  /* Trigger TRIO_CR_GW to read from addr */
  rc = pci_cap_write(pci_dev, TRIO_CR_GW_LOCK, TRIO_CR_GW_TRIGGER);
  if (rc)
    return rc;

  /* Read 32-bit data from TRIO_CR_GW_DATA_LOWER */
  rc = pci_cap_read(pci_dev, TRIO_CR_GW_DATA_LOWER, result);
  if (rc)
    return rc;

  *result = ntohl(*result);

  /* Release TRIO_CR_GW_LOCK */
  rc = trio_cr_gw_lock_release(pci_dev);
  if (rc)
    return rc;

  return 0;
}

static int crspace_rsh_gw_write(struct pci_dev *pci_dev, int addr,
                                uint32_t value)
{
  int rc;

  if (pci_dev->device_id == BLUEFIELD2_DEVICE_ID) {
    addr = (addr & 0xffff) + CRSPACE_RSH_CHANNEL1_BASE;
    rc = pci_cap_write(pci_dev, addr, value);
    return rc;
  }

  /*
   * All Rshim accesses except writes to the BOOT_FIFO_DATA go through
   * the Byte Access Widget and hence need to use the RSHIM_CHANNEL.
   */
  if ((addr & 0xffff) != RSH_BOOT_FIFO_DATA)
    addr += RSH_CHANNEL_BASE(RSHIM_CHANNEL);

  /* Acquire TRIO_CR_GW_LOCK */
  rc = trio_cr_gw_lock_acquire(pci_dev);
  if (rc)
    return rc;

  /* Write 32-bit data to TRIO_CR_GW_DATA_LOWER */
  rc = pci_cap_write(pci_dev, TRIO_CR_GW_DATA_LOWER, htonl(value));
  if (rc)
    return rc;

  /* Write addr to TRIO_CR_GW_ADDR_LOWER */
  rc = pci_cap_write(pci_dev, TRIO_CR_GW_ADDR_LOWER, addr);
  if (rc)
    return rc;

  /* Set TRIO_CR_GW_WRITE_4BYTE */
  rc = pci_cap_write(pci_dev, TRIO_CR_GW_CTL, TRIO_CR_GW_WRITE_4BYTE);
  if (rc)
    return rc;

  /* Trigger CR gateway to write to RShim */
  rc = pci_cap_write(pci_dev, TRIO_CR_GW_LOCK, TRIO_CR_GW_TRIGGER);
  if (rc)
    return rc;

  /* Release TRIO_CR_GW_LOCK */
  rc = trio_cr_gw_lock_release(pci_dev);
  if (rc)
    return rc;

  return 0;
}

/* Wait until the RSH_BYTE_ACC_CTL pending bit is cleared */
static int rshim_byte_acc_pending_wait(struct pci_dev *pci_dev)
{
  uint32_t read_value = 0;
  time_t t0, t1;
  int rc;

  time(&t0);
  do {
    rc = crspace_rsh_gw_read(pci_dev, RSH_BYTE_ACC_CTL, &read_value);
    if (rc)
      return rc;

    time(&t1);
    if (difftime(t1, t0) > RSHIM_LOCK_RETRY_TIME)
      return -ETIMEDOUT;
  } while (read_value & RSH_BYTE_ACC_PENDING);

  return 0;
}

/* Acquire BAW Interlock */
static int rshim_byte_acc_lock_acquire(struct pci_dev *pci_dev)
{
  uint32_t read_value = 0;
  int rc;
  time_t t0, t1;

  time(&t0);
  do {
    time(&t1);
    if (difftime(t1, t0) > RSHIM_LOCK_RETRY_TIME)
      return -ETIMEDOUT;

    rc = crspace_rsh_gw_read(pci_dev, RSH_BYTE_ACC_INTERLOCK,
                             &read_value);
    if (rc)
      return rc;
  } while (!(read_value & 0x1));

  return 0;
}

/* Release BAW Interlock */
static int rshim_byte_acc_lock_release(struct pci_dev *pci_dev)
{
  return crspace_rsh_gw_write(pci_dev,
                              RSH_BYTE_ACC_INTERLOCK, 0);
}

/*
 * Mechanism to do an 8-byte access to the Rshim using
 * two 4-byte accesses through the Rshim Byte Access Widget.
 */
static int rshim_byte_acc_read(struct pci_dev *pci_dev, int addr,
                               uint64_t *result)
{
  uint64_t read_result;
  uint32_t read_value = 0;
  int rc;

  /* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
  rc = rshim_byte_acc_pending_wait(pci_dev);
  if (rc)
    return rc;

  /* Acquire RSH_BYTE_ACC_INTERLOCK */
  if (pci_dev->device_id == BLUEFIELD2_DEVICE_ID) {
    rc = rshim_byte_acc_lock_acquire(pci_dev);
    if (rc)
      return rc;
  }

  /* Write target address to RSH_BYTE_ACC_ADDR */
  rc = crspace_rsh_gw_write(pci_dev, RSH_BYTE_ACC_ADDR, addr);
  if (rc)
    goto exit_read;

  /* Write control and trigger bits to perform read */
  rc = crspace_rsh_gw_write(pci_dev, RSH_BYTE_ACC_CTL,
                            RSH_BYTE_ACC_READ_TRIGGER |
                            RSH_BYTE_ACC_SIZE_4BYTE);
  if (rc)
    goto exit_read;

  /* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
  rc = rshim_byte_acc_pending_wait(pci_dev);
  if (rc)
    goto exit_read;

  /* Read RSH_BYTE_ACC_RDAT to read lower 32-bits of data */
  rc = crspace_rsh_gw_read(pci_dev, RSH_BYTE_ACC_RDAT, &read_value);
  if (rc)
    goto exit_read;

  read_result = (uint64_t)read_value;

  /* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
  rc = rshim_byte_acc_pending_wait(pci_dev);
  if (rc)
    goto exit_read;

  /* Read RSH_BYTE_ACC_RDAT to read upper 32-bits of data */
  rc = crspace_rsh_gw_read(pci_dev, RSH_BYTE_ACC_RDAT, &read_value);
  if (rc)
    goto exit_read;

  read_result |= ((u64)read_value << 32);
  *result = read_result;

exit_read:
  /* Release RSH_BYTE_ACC_INTERLOCK */
  if (pci_dev->device_id == BLUEFIELD2_DEVICE_ID)
    rc = rshim_byte_acc_lock_release(pci_dev);

  return rc;
}

static int rshim_byte_acc_write(struct pci_dev *pci_dev, int addr,
                                uint64_t value)
{
  int rc;

  /* Acquire RSH_BYTE_ACC_INTERLOCK */
  if (pci_dev->device_id == BLUEFIELD2_DEVICE_ID) {
    rc = rshim_byte_acc_lock_acquire(pci_dev);
    if (rc)
      return rc;
  }

  /* Write target address to RSH_BYTE_ACC_ADDR */
  rc = crspace_rsh_gw_write(pci_dev, RSH_BYTE_ACC_ADDR, addr);
  if (rc)
    return rc;

  /* Write control bits to RSH_BYTE_ACC_CTL */
  rc = crspace_rsh_gw_write(pci_dev, RSH_BYTE_ACC_CTL, RSH_BYTE_ACC_SIZE_4BYTE);
  if (rc)
    goto exit_write;

  /* Write lower 32 bits of data to TRIO_CR_GW_DATA */
  rc = crspace_rsh_gw_write(pci_dev, RSH_BYTE_ACC_WDAT, (uint32_t)value);
  if (rc)
    goto exit_write;

  /* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
  rc = rshim_byte_acc_pending_wait(pci_dev);
  if (rc)
    goto exit_write;

  /* Write upper 32 bits of data to TRIO_CR_GW_DATA */
  rc = crspace_rsh_gw_write(pci_dev, RSH_BYTE_ACC_WDAT,
                            (uint32_t)(value >> 32));
  if (rc)
    goto exit_write;

exit_write:
  /* Release RSH_BYTE_ACC_INTERLOCK */
  if (pci_dev->device_id == BLUEFIELD2_DEVICE_ID)
    rc = rshim_byte_acc_lock_release(pci_dev);
  return rc;
}

/*
 * The RShim Boot FIFO has a holding register which can couple
 * two consecutive 4-byte writes into a single 8-byte write
 * before pushing the data into the FIFO.
 * Hence the RShim Byte Access Widget is not necessary to write
 * to the BOOT FIFO using 4-byte writes.
 */
static int rshim_boot_fifo_write(struct pci_dev *pci_dev, int addr,
                                 uint64_t value)
{
  int rc;

  /* Write lower 32 bits of data to RSH_BOOT_FIFO_DATA */
  rc = crspace_rsh_gw_write(pci_dev, addr, (uint32_t)value);
  if (rc)
    return rc;

  /* Write upper 32 bits of data to RSH_BOOT_FIFO_DATA */
  rc = crspace_rsh_gw_write(pci_dev, addr, (uint32_t)(value >> 32));
  if (rc)
    return rc;

  return 0;
}

/* RShim read/write routines */
static int __attribute__ ((noinline))
rshim_pcie_read(struct rshim_backend *bd, int chan, int addr, uint64_t *result)
{
  rshim_pcie_lf_t *dev = container_of(bd, rshim_pcie_lf_t, bd);
  struct pci_dev *pci_dev = dev->pci_dev;
  int rc = 0;

  if (!bd->has_rshim || !bd->has_tm)
    return -ENODEV;

  if (bd->drop_mode && !rshim_drop_mode_access(addr)) {
    *result = 0;
    return 0;
  }

  dev->write_count = 0;

  rc = rshim_byte_acc_read(pci_dev, RSH_CHANNEL_BASE(chan) + addr, result);

  return rc;
}

static int __attribute__ ((noinline))
rshim_pcie_write(struct rshim_backend *bd, int chan, int addr, uint64_t value)
{
  rshim_pcie_lf_t *dev = container_of(bd, rshim_pcie_lf_t, bd);
  struct pci_dev *pci_dev = dev->pci_dev;
  bool is_boot_stream = (addr == RSH_BOOT_FIFO_DATA);
  uint64_t result;
  int rc = 0;

  if (!bd->has_rshim || !bd->has_tm)
    return -ENODEV;

  if (bd->drop_mode && !rshim_drop_mode_access(addr))
    return 0;

  /*
   * Limitation in BlueField-1
   * We cannot stream large numbers of PCIe writes to the RShim's BAR.
   * Instead, we must write no more than 15 8-byte words before
   * doing a read from another register within the BAR,
   * which forces previous writes to drain.
   * Note that we allow a max write_count of 7 since each 8-byte
   * write is done using 2 4-byte writes in the boot fifo case.
   */
  if (pci_dev->device_id == BLUEFIELD1_DEVICE_ID) {
    if (dev->write_count == 7) {
      __sync_synchronize();
      rshim_pcie_read(bd, chan, RSH_SCRATCHPAD, &result);
    }
  dev->write_count++;
  }

  if (is_boot_stream)
    rc = rshim_boot_fifo_write(pci_dev, RSH_CHANNEL_BASE(chan) + addr, value);
  else
    rc = rshim_byte_acc_write(pci_dev, RSH_CHANNEL_BASE(chan) + addr, value);

  return rc;
}

static void rshim_pcie_delete(struct rshim_backend *bd)
{
  rshim_pcie_lf_t *dev = container_of(bd, rshim_pcie_lf_t, bd);

  rshim_deregister(bd);
  free(dev);
}

static int rshim_pcie_enable_device(rshim_backend_t *bd, bool enable)
{
  rshim_pcie_lf_t *dev = container_of(bd, rshim_pcie_lf_t, bd);
  int rc = 0;

  if (dev->pci_dev)
    rc = rshim_pcie_enable(dev->pci_dev, enable);

  return rc;
}

/* Probe routine */
static int rshim_pcie_probe(struct pci_dev *pci_dev)
{
  char dev_name[RSHIM_DEV_NAME_LEN];
  struct rshim_backend *bd;
  rshim_pcie_lf_t *dev;
  int ret;

  snprintf(dev_name, sizeof(dev_name) - 1, "pcie-lf-%04x:%02x:%02x.%d",
           pci_dev->domain, pci_dev->bus, pci_dev->dev, pci_dev->func);

  if (!rshim_allow_device(dev_name))
    return -EACCES;

  RSHIM_INFO("Probing %s\n", dev_name);

  rshim_lock();

  bd = rshim_find_by_name(dev_name);
  if (bd) {
    dev = container_of(bd, rshim_pcie_lf_t, bd);
  } else {
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
      bd->ver_id = RSHIM_BLUEFIELD_2;
      break;
    default:
      bd->ver_id = RSHIM_BLUEFIELD_1;
  }
  bd->rev_id = pci_read_byte(pci_dev, PCI_REVISION_ID);

  /* Initialize object */
  dev->pci_dev = pci_dev;

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

  /* Enable drop mode by default for livefish. */
  bd->drop_mode = 1;

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

int rshim_pcie_lf_init(void)
{
  struct pci_access *pci;
  struct pci_dev *dev;
  int rc;
  bool dev_present = false;

  pci = pci_alloc();
  if (!pci)
    return -ENOMEM;

  pci_init(pci);

  pci_scan_bus(pci);

  /* Iterate over the devices */
  for (dev = pci->devices; dev; dev = dev->next) {
    pci_fill_info(dev, PCI_FILL_IDENT | PCI_FILL_BASES | PCI_FILL_CLASS);

    if (dev->vendor_id != TILERA_VENDOR_ID ||
        (dev->device_id != BLUEFIELD1_DEVICE_ID &&
         dev->device_id != BLUEFIELD2_DEVICE_ID))
      continue;

    rc = rshim_pcie_enable(dev, true);
    if (rc)
      continue;
    rshim_pcie_probe(dev);
    dev_present = true;
  }

  if (!dev_present)
	  return -1;

  return 0;
}
