// SPDX-License-Identifier: GPL-2.0-only
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
#include <sys/vfs.h>
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

#define SYS_CLASS_IOMMU_PATH        "/sys/class/iommu"
#define SYS_CLASS_VFIO_PCI_PATH     "/sys/module/vfio_pci"
#define SYS_BUS_PCI_PATH            "/sys/bus/pci/devices"
#define SYS_VFIO_PCI_PATH           "/sys/bus/pci/drivers/vfio-pci"

typedef enum {
  RSHIM_PCIE_MMAP_DIRECT,
  RSHIM_PCIE_MMAP_UIO,
  RSHIM_PCIE_MMAP_VFIO
} rshim_pcie_mmap_mode_t;

static rshim_pcie_mmap_mode_t rshim_pcie_mmap_mode = RSHIM_PCIE_MMAP_DIRECT;

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

typedef struct {
  /* RShim backend structure. */
  rshim_backend_t bd;

  struct pci_dev *pci_dev;

  /* Address of the RShim registers. */
  volatile uint8_t *rshim_regs;

  /* Keep track of number of 8-byte word writes */
  uint8_t write_count;

  /* Device file handle */
  int device_fd;

  /* VFIO container/group file handle */
  int container_fd;
  int group_fd;
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

#ifdef __linux__

int rshim_pcie_mmap_direct(rshim_pcie_t *dev, bool enable)
{
  char path[256];
  struct pci_dev *pci_dev = dev->pci_dev;

  if (!enable) {
    if (dev->device_fd >= 0) {
      close(dev->device_fd);
      dev->device_fd = -1;
    }

    if (dev->rshim_regs) {
      munmap((void *)dev->rshim_regs, PCI_RSHIM_WINDOW_SIZE);
      dev->rshim_regs = NULL;
    }
    return 0;
  }

  snprintf(path, sizeof(path), "%s/%04x:%02x:%02x.%1u/resource0",
           SYS_BUS_PCI_PATH, pci_dev->domain, pci_dev->bus,
           pci_dev->dev, pci_dev->func);

  dev->device_fd = open(path, O_RDWR | O_SYNC);
  if (dev->device_fd < 0) {
    RSHIM_ERR("Failed to open %s\n", path);
    return -ENODEV;
  }
  dev->rshim_regs = mmap(NULL, PCI_RSHIM_WINDOW_SIZE,
                         PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_LOCKED,
                         dev->device_fd,
                         PCI_RSHIM_WINDOW_OFFSET);
  if (dev->rshim_regs == MAP_FAILED) {
    RSHIM_ERR("Failed to map RShim registers\n");
    return -ENOMEM;
  }

  return 0;
}

int rshim_pcie_mmap_vfio(rshim_pcie_t *dev, int enable)
{
  int i, rc, group_id, container_fd = -1, group_fd = -1, device_fd = -1;
  char path[PATH_MAX], name[PATH_MAX], *p;
  struct pci_dev *pci_dev = dev->pci_dev;

  struct vfio_group_status group_status = {
    .argsz = sizeof(group_status)
  };

  struct vfio_device_info device_info = {
    .argsz = sizeof(device_info)
  };

  struct vfio_region_info region_info = {
    .argsz = sizeof(region_info)
  };

  if (!enable) {
    if (dev->rshim_regs) {
      munmap((void *)dev->rshim_regs, PCI_RSHIM_WINDOW_SIZE);
      dev->rshim_regs = NULL;
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

    return 0;
  }

  container_fd = open("/dev/vfio/vfio", O_RDWR);
  if (container_fd < 0) {
    printf("Failed to open /dev/vfio/vfio, %d (%s)\n",
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
           SYS_BUS_PCI_PATH, pci_dev->domain, pci_dev->bus,
           pci_dev->dev, pci_dev->func);
  rc = readlink(path, name, sizeof(name));
  if (rc < 0 || !name[0] || rc >= sizeof(name)) {
    RSHIM_ERR("%s: failed to read iommu link\n", path);
    goto fail;
  }
  name[rc] = 0;
  p = strrchr(name, '/');
  if (!p) {
    RSHIM_ERR("Failed to find vfio group\n");
    rc = -ENOENT;
    goto fail;
  }
  group_id = atoi(p + 1);

  snprintf(path, sizeof(path), "/dev/vfio/%d", group_id);
  group_fd = open(path, O_RDWR);
  if (group_fd < 0) {
    RSHIM_ERR("Failed to open %s, %d (%s)\n",
              path, group_fd, strerror(errno));
    rc = group_fd;
    goto fail;
  }

  rc = ioctl(group_fd, VFIO_GROUP_GET_STATUS, &group_status);
  if (rc) {
    RSHIM_ERR("VFIO_GROUP_GET_STATUS failed\n");
    goto fail;
  }

  if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
    RSHIM_ERR("VFIO group not viable\n");
    rc = -1;
    goto fail;
  }

  if (!(group_status.flags & VFIO_GROUP_FLAGS_CONTAINER_SET)) {
    ioctl(group_fd, VFIO_GROUP_SET_CONTAINER, &container_fd);
    ioctl(container_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU);
  }

  snprintf(path, sizeof(path), "%04x:%02x:%02x.%d", pci_dev->domain,
           pci_dev->bus, pci_dev->dev, pci_dev->func);
  device_fd = ioctl(group_fd, VFIO_GROUP_GET_DEVICE_FD, path);
  if (device_fd < 0) {
    RSHIM_ERR("Failed to get vfio device %s\n", path);
    rc = device_fd;
    goto fail;
  }

  rc = ioctl(device_fd, VFIO_DEVICE_GET_INFO, &device_info);
  if (rc) {
    RSHIM_ERR("Failed to get vfio device info\n");
    goto fail;
  }

  if (!device_info.num_regions) {
    rc = -1;
    goto fail;
  }

  region_info.index = 0;
  rc = ioctl(device_fd, VFIO_DEVICE_GET_REGION_INFO, &region_info);
  if (rc) {
    RSHIM_ERR("Failed to get vfio region info\n");
    return -1;
  }

  if (region_info.flags & VFIO_REGION_INFO_FLAG_MMAP) {
    void *map = mmap(NULL, (size_t)region_info.size,
                     PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_LOCKED,
                     device_fd,
                     (off_t)region_info.offset);
    if (map == MAP_FAILED) {
      RSHIM_ERR("Vfio mmap failed %m\n");
      rc = -1;
      goto fail;
    } else {
      dev->device_fd = device_fd;
      dev->group_fd = group_fd;
      dev->container_fd = container_fd;
      dev->rshim_regs = map;
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

int rshim_pcie_mmap(rshim_pcie_t *dev, bool enable)
{
  if (rshim_pcie_mmap_mode == RSHIM_PCIE_MMAP_VFIO)
    return rshim_pcie_mmap_vfio(dev, enable);
  else
    return rshim_pcie_mmap_direct(dev, enable);
}

#elif defined(__FreeBSD__)

int rshim_pcie_mmap(rshim_pcie_t *dev, bool enable)
{
  struct pci_dev *pci_dev = dev->pci_dev;
  struct pci_bar_mmap pbm = {
    .pbm_sel.pc_func = pci_dev->func,
    .pbm_sel.pc_dev = pci_dev->dev,
    .pbm_sel.pc_bus = pci_dev->bus,
    .pbm_sel.pc_domain = pci_dev->domain_16,
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
    RSHIM_ERR("Failed to open /dev/pci\n");
    return -ENODEV;
  }

  if (ioctl(dev->device_fd, PCIOCBARMMAP, &pbm) < 0) {
    RSHIM_ERR("PCIOCBARMMAP IOCTL failed\n");
    rc = -ENODEV;
    goto rshim_map_failed;
  }

  dev->rshim_regs = (void *)((uintptr_t)pbm.pbm_map_base +
      (uintptr_t)pbm.pbm_bar_off + PCI_RSHIM_WINDOW_OFFSET);
  if (pbm.pbm_bar_length < PCI_RSHIM_WINDOW_SIZE) {
    RSHIM_ERR("BAR length is too small\n");
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

/* RShim read/write routines */
static int __attribute__ ((noinline))
rshim_pcie_read(rshim_backend_t *bd, int chan, int addr, uint64_t *result)
{
  rshim_pcie_t *dev = container_of(bd, rshim_pcie_t, bd);
  int rc = 0;

  if (!bd->has_rshim || !bd->has_tm)
    return -ENODEV;

  if (bd->drop_mode) {
    *result = 0;
    return 0;
  }

  dev->write_count = 0;

  *result = readq(dev->rshim_regs + (addr | (chan << 16)));

  return rc;
}

static int __attribute__ ((noinline))
rshim_pcie_write(rshim_backend_t *bd, int chan, int addr, uint64_t value)
{
  rshim_pcie_t *dev = container_of(bd, rshim_pcie_t, bd);
  uint64_t result;
  int rc = 0;

  if (!bd->has_rshim || !bd->has_tm)
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
      rshim_pcie_read(bd, chan, RSH_SCRATCHPAD1, &result);
    }
    dev->write_count++;
  }
  writeq(value, dev->rshim_regs + (addr | (chan << 16)));

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
  int rc = 0;
  rshim_pcie_t *dev = container_of(bd, rshim_pcie_t, bd);
#ifdef __linux__
  struct pci_dev *pci_dev = dev->pci_dev;
  char path[256];
  DIR* dir;
  int fd;

  if (!pci_dev)
    return -ENODEV;

  /* Unmap existing resource first. */
  rshim_pcie_mmap(dev, false);

  if (rshim_pcie_mmap_mode == RSHIM_PCIE_MMAP_DIRECT) {
    /* Some sanity check. */
    if (!pci_dev->size[0]) {
      RSHIM_ERR("BAR[0] unassigned, run 'lspci -v'\n");
      return -ENOMEM;
    }
    if (pci_dev->size[0] < PCI_RSHIM_WINDOW_SIZE) {
      RSHIM_ERR("BAR[0] size 0x%x too small\n", (int)pci_dev->size[0]);
      return -ENOMEM;
    }

    /* Check whether it's being attached by other driver. */
    snprintf(path, sizeof(path), "%s/%04x:%02x:%02x.%1u/driver",
             SYS_BUS_PCI_PATH, pci_dev->domain, pci_dev->bus,
             pci_dev->dev, pci_dev->func);
    dir = opendir(path);
    if (dir) {
      RSHIM_ERR("Rshim is used by %s\n", path);
      closedir(dir);
      return -EBUSY;
    }

    /* Set the enable attribute in sysfs. */
    snprintf(path, sizeof(path), "%s/%04x:%02x:%02x.%1u/enable",
             SYS_BUS_PCI_PATH, pci_dev->domain, pci_dev->bus,
             pci_dev->dev, pci_dev->func);
    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd == -1) {
      RSHIM_ERR("Failed to open %s\n", path);
      return -errno;
    }
    if (write(fd, enable ? "1" : "0", 1) < 0)
      rc = -errno;
    close(fd);
    if (rc) {
      RSHIM_ERR("Failed to write to %s\n", path);
      return rc;
    }

    /* Enable Master and BAR access. */
    pci_write_word(pci_dev, PCI_COMMAND, PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
  } else if (rshim_pcie_mmap_mode == RSHIM_PCIE_MMAP_VFIO) {
    snprintf(path, sizeof(path),
             "echo %04x:%02x:%02x.%1u > " SYS_VFIO_PCI_PATH "/%s 2>/dev/null",
             pci_dev->domain, pci_dev->bus, pci_dev->dev, pci_dev->func,
             enable ? "bind" : "unbind");
    if (system(path) == -1)
      RSHIM_DBG("Failed to bind/unbind device\n");
  } else {
    RSHIM_ERR("Unknown PCIE mmap mode\n");
    return -EINVAL;
  }

  /* Remap the resource. */
  if (enable) {
    rc = rshim_pcie_mmap(dev, true);
  }
#else
  /* Unmap existing resource then remap it. */
  rshim_pcie_mmap(dev, false);
  if (enable)
    rc = rshim_pcie_mmap(dev, true);
#endif /* __linux__ */

  RSHIM_INFO("rshim%d %s\n", bd->index, enable ? "enable" : "disable");

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

  RSHIM_INFO("Probing %s%s\n", dev_name,
    (rshim_pcie_mmap_mode == RSHIM_PCIE_MMAP_VFIO) ? " (vfio)":"");

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
    bd->drop_mode = (rshim_drop_mode >= 0) ? rshim_drop_mode : 0;
    bd->read_rshim = rshim_pcie_read;
    bd->write_rshim = rshim_pcie_write;
    bd->destroy = rshim_pcie_delete;
    bd->enable_device = rshim_pcie_enable;
    dev->write_count = 0;
    dev->device_fd = -1;
    dev->group_fd = -1;
    dev->container_fd = -1;
    pthread_mutex_init(&bd->mutex, NULL);
  }

  rshim_ref(bd);

  switch (pci_dev->device_id) {
    case BLUEFIELD2_DEVICE_ID:
    case BLUEFIELD2_DEVICE_ID2:
      bd->regs = &bf1_bf2_rshim_regs;
      bd->ver_id = RSHIM_BLUEFIELD_2;
      break;
    default:
      bd->regs = &bf1_bf2_rshim_regs;
      bd->ver_id = RSHIM_BLUEFIELD_1;
      break;
  }
  bd->rev_id = pci_read_byte(pci_dev, PCI_REVISION_ID);

  /* Initialize object */
  dev->pci_dev = pci_dev;

  /* Enable the device and setup memory map. */
  if (!bd->drop_mode) {
    rc = bd->enable_device(bd, true);
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
  if (!rc)
    rc = rshim_notify(bd, RSH_EVENT_ATTACH, 0);
  pthread_mutex_unlock(&bd->mutex);
  if (rc)
    goto rshim_probe_failed;

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
  int rc;
  struct dirent* d;
  DIR* dir;

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

static bool kernel_lock_down_enabled(void)
{
  FILE *file;
  char buf[64] = { 0 }, *p;

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
  struct pci_access *pci;
  struct pci_dev *dev;
  int rc;
  bool dev_present = false;

#ifdef __linux__
  if (rshim_pcie_has_vfio()) {
    rshim_pcie_mmap_mode = RSHIM_PCIE_MMAP_VFIO;
    rc = system("echo 15b3 c2d3 > " SYS_VFIO_PCI_PATH "/new_id 2>/dev/null");
    if (rc == -1)
      RSHIM_DBG("Failed to vdio device id %m\n");
    rc = system("echo 15b3 c2d2 > " SYS_VFIO_PCI_PATH "/new_id 2>/dev/null");
    if (rc == -1)
      RSHIM_DBG("Failed to vdio device id %m\n");
  } else if (kernel_lock_down_enabled()) {
    RSHIM_ERR("Need to enable IOMMU/VFIO for kernel lock-down\n");
    return -ENOTSUP;
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
         !rshim_is_bluefield2(dev->device_id)))
      continue;

    rc = rshim_pcie_probe(dev);
    if (rc)
      continue;

    dev_present = true;
  }

  if (!dev_present)
    return -ENODEV;

  return 0;
}
