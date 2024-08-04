// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright (C) 2019-2023 Mellanox Technologies. All Rights Reserved.
 *
 */

#include <arpa/inet.h>
#ifdef __linux__
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>
#endif
#ifdef __FreeBSD__
#include <net/if.h>
#include <net/if_tap.h>
#include <net/ethernet.h>
#endif
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "rshim.h"

static uint8_t rshim_net_default_mac[6] = {0x00, 0x1A, 0xCA, 0xFF, 0xFF, 0x02};

/* Set non-blocking. */
static int rshim_if_set_non_blocking(int fd)
{
  int flags, err;

  flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    RSHIM_ERR("fcntl %m\n");
    return -1;
  }

  flags |= O_NONBLOCK;
  err = fcntl(fd, F_SETFL, flags);
  if (err == -1) {
      RSHIM_ERR("fcntl %m\n");
      return -1;
  }

  return 0;
}

#ifdef __linux__
/* Open tun/tap interface. */
static int rshim_if_open(char *ifname, int index)
{
  char cmd[128];
  struct ifreq ifr;
  int s, fd, rc;

  fd = open("/dev/net/tun", O_RDWR);
  if (fd < 0) {
    rc = system("modprobe tun");
    if (rc == -1)
      RSHIM_DBG("Failed to load the tun module %m\n");

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
      RSHIM_ERR("rshim%d can't open %s\n", index, ifname);
      return -1;
    }
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

  rc = ioctl(fd, TUNSETIFF, (void *) &ifr);
  if (rc < 0) {
    RSHIM_ERR("rshim%d ioctl failed(%d)\n", index, errno);
    close(fd);
    return -1;
  }

  memcpy(ifr.ifr_hwaddr.sa_data, rshim_net_default_mac, 6);
  ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
  ifr.ifr_hwaddr.sa_data[5] += index * 2;
  if (ioctl(fd, SIOCSIFHWADDR, &ifr)) {
    RSHIM_ERR("rshim%d ioctl SIOCSIFHWADDR failed", index);
    close(fd);
    return -1;
  }

  s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) {
    RSHIM_ERR("rshim%d socket failed\n", index);
    close(fd);
    return -1;
  }

  if (ioctl(s, SIOCGIFFLAGS, &ifr) >= 0) {
    ifr.ifr_flags |= IFF_UP;
    ioctl(s, SIOCSIFFLAGS, &ifr);
  }
  close(s);

  rshim_if_set_non_blocking(fd);

  sprintf(cmd, "ifup %s 2>/dev/null&", ifname);
  if (system(cmd) == -1)
    RSHIM_DBG("rshim%d failed to call ifup\n", index);

  return fd;
}
#elif defined(__FreeBSD__)
/* Open tun/tap interface. */
static int rshim_if_open(char *ifname, int index)
{
  struct ifreq ifr;
  int s, fd;

  s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) {
    RSHIM_ERR("rshim%d socket failed\n", index);
    return -1;
  }

  fd = open("/dev/tap", O_RDWR);
  if (fd < 0) {
    system("kldload -qn if_tap");
    fd = open("/dev/tap", O_RDWR);
    if (fd < 0) {
      RSHIM_ERR("rshim%d failed to open %s\n", index, ifname);
      close(s);
      return -1;
    }
  }

  memset(&ifr, 0, sizeof(ifr));
  if (ioctl(fd, TAPGIFNAME, &ifr) < 0) {
    RSHIM_ERR("rshim%d ioctl TAPGIFNAME failed", index);
    close(fd);
    close(s);
    return -1;
  }

  ifr.ifr_data = ifname;
  if (ioctl(s, SIOCSIFNAME, &ifr) < 0) {
    char temp[sizeof(ifr.ifr_name)];

    memcpy(temp, ifr.ifr_name, sizeof(temp));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

    /* cleanup old device */
    if (ioctl(s, SIOCIFDESTROY, &ifr) < 0) {
      RSHIM_ERR("rshim%d SIOCIFDESTROY failed\n", index);
      close(s);
      close(fd);
      return -1;
    }

    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", temp);

    /* try to rename device again */
    if (ioctl(s, SIOCSIFNAME, &ifr) < 0) {
      RSHIM_ERR("rshim%d SIOCIFNAME failed\n", index);
      close(s);
      close(fd);
      return -1;
    }
  }

  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

  ifr.ifr_mtu = ETHERMTU;
  if (ioctl(s, SIOCSIFMTU, &ifr) < 0) {
    RSHIM_ERR("rshim%d ioctl SIOCSIMTU failed", index);
    close(s);
    close(fd);
    return -1;
  }

  memcpy(ifr.ifr_addr.sa_data, rshim_net_default_mac, 6);
  ifr.ifr_addr.sa_family = AF_LINK;
  ifr.ifr_addr.sa_len = 6;
  ifr.ifr_addr.sa_data[5] += index * 2;
  if (ioctl(s, SIOCSIFLLADDR, &ifr) < 0) {
    RSHIM_ERR("rshim%d ioctl SIOCSIFLLADDR failed", index);
    close(s);
    close(fd);
    return -1;
  }

  if (ioctl(s, SIOCGIFFLAGS, &ifr) >= 0) {
    ifr.ifr_flags |= IFF_UP;
    ioctl(s, SIOCSIFFLAGS, &ifr);
  }

  close(s);
  rshim_if_set_non_blocking(fd);
  return fd;
}
#else
#error "Unsupported platform"
#endif

static int rshim_if_read(int fd, char *buf, size_t len)
{
  return read(fd, buf, len);
}

static int rshim_if_write(int fd, const char *buf, size_t len)
{
  return write(fd, buf, len);
}

#ifdef __linux__
static void rshim_if_close(int fd)
{
  struct ifreq ifr;
  char cmd[128];
  int rc;

  memset(&ifr, 0, sizeof(ifr));
  rc = ioctl(fd, TUNGETIFF, (void *) &ifr);

  if (!rc && ifr.ifr_name[0]) {
    sprintf(cmd, "ifdown %s 2>/dev/null&", ifr.ifr_name);
    if (system(cmd) == -1)
      RSHIM_DBG("Failed to call ifdown\n");
  }

  ioctl(fd, TUNSETPERSIST, 0);
  close(fd);
}
#elif defined(__FreeBSD__)
static void rshim_if_close(int fd)
{
  struct ifreq ifr;
  int s;

  memset(&ifr, 0, sizeof(ifr));
  if (ioctl(fd, TAPGIFNAME, &ifr) < 0) {
    close(fd);
    return;
  }
  close(fd);

  s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) {
    RSHIM_ERR("socket failed: %m\n");
    return;
  }

  if (ioctl(s, SIOCIFDESTROY, &ifr) < 0) {
    RSHIM_ERR("SIOCIFDESTROY failed: %m\n");
    close(s);
    return;
  }
  close(s);
}
#else
#error "Platform not supported"
#endif

int rshim_net_init(rshim_backend_t *bd)
{
  struct epoll_event event;
  char ifname[IFNAMSIZ];
  int rc, fd[2];

  snprintf(ifname, sizeof(ifname), "tmfifo_net%d", bd->index);
  bd->net_fd = rshim_if_open(ifname, bd->index);

  if (bd->net_fd < 0)
    return bd->net_fd;

  memset(&event, 0, sizeof(event));

  event.data.fd = bd->net_fd;
  event.events = EPOLLIN;
  rc = epoll_ctl(rshim_epoll_fd, EPOLL_CTL_ADD, bd->net_fd, &event);
  if (rc == -1) {
    RSHIM_ERR("rshim%d epoll_ctl failed: %d %d\n", bd->index,
              rshim_epoll_fd, bd->net_fd);
    goto fail;
  }

  rc = pipe(fd);
  if (rc == -1) {
    RSHIM_ERR("rshim%d failed to create net pipe", bd->index);
    goto fail;
  }

  event.data.fd = fd[0];
  event.events = EPOLLIN;
  rc = epoll_ctl(rshim_epoll_fd, EPOLL_CTL_ADD, fd[0], &event);
  if (rc == -1) {
    RSHIM_ERR("rshim%d epoll_ctl failed: %d %d\n", bd->index,
              rshim_epoll_fd, fd[0]);
    goto fail;
  }
  bd->net_notify_fd[0] = fd[0];
  bd->net_notify_fd[1] = fd[1];

  return 0;
fail:
  rshim_if_close(bd->net_fd);
  bd->net_fd = -1;
  return rc;
}

int rshim_net_del(rshim_backend_t *bd)
{
  struct epoll_event event;

  if (bd->net_notify_fd[0] >= 0) {
    memset(&event, 0, sizeof(event));
    event.data.fd = bd->net_notify_fd[0];
    epoll_ctl(rshim_epoll_fd, EPOLL_CTL_DEL, bd->net_notify_fd[0], &event);
    close(bd->net_notify_fd[0]);
    close(bd->net_notify_fd[1]);
    bd->net_notify_fd[0] = -1;
    bd->net_notify_fd[1] = -1;
  }

  if (bd->net_fd >= 0) {
    memset(&event, 0, sizeof(event));
    event.data.fd = bd->net_fd;
    epoll_ctl(rshim_epoll_fd, EPOLL_CTL_DEL, bd->net_fd, &event);
    rshim_if_close(bd->net_fd);
    bd->net_fd = -1;
  }
  return 0;
}

void rshim_net_rx(rshim_backend_t *bd)
{
  rshim_net_pkt_t *pkt = &bd->net_rx_pkt;
  int len, total_len;

  bd->net_rx_pending = false;

  for (;;) {
    total_len = sizeof(pkt->hdr);
    while (bd->net_rx_len < total_len) {
      len = rshim_fifo_read(bd, (char *)pkt + bd->net_rx_len,
                            total_len - bd->net_rx_len,
                            TMFIFO_NET_CHAN, true);
      if (len <= 0)
        return;
      bd->net_rx_len += len;
    }

    total_len = ntohs(pkt->hdr.len) + sizeof(pkt->hdr);
    /* Drop invalid data. */
    if (total_len > sizeof(*pkt)) {
      bd->net_rx_len = 0;
      continue;
    }
    while (bd->net_rx_len < total_len) {
      len = rshim_fifo_read(bd, (char *)pkt + bd->net_rx_len,
                            total_len - bd->net_rx_len,
                            TMFIFO_NET_CHAN, true);
      if (len <= 0)
        return;
      bd->net_rx_len += len;
    }

    if (pkt->hdr.len) {
      rshim_if_write(bd->net_fd, pkt->buf, ntohs(pkt->hdr.len));
      pkt->hdr.len = 0;
    }

    bd->net_rx_len = 0;
  }
}

void rshim_net_tx(rshim_backend_t *bd)
{
  rshim_net_pkt_t *pkt = &bd->net_tx_pkt;
  int len, written;

  do {
    if (!pkt->hdr.len ||
        bd->net_tx_len >= sizeof(pkt->hdr) + ntohs(pkt->hdr.len)) {
      bd->net_tx_len = 0;
      pkt->hdr.len = 0;

      len = rshim_if_read(bd->net_fd, pkt->buf, sizeof(pkt->buf));
      if (len <= 0)
        return;

      pkt->hdr.data = 0;
      pkt->hdr.type = VIRTIO_ID_NET;
      pkt->hdr.len = htons(len);
    }

    len = ntohs(pkt->hdr.len) + sizeof(pkt->hdr) - bd->net_tx_len;
    written = rshim_fifo_write(bd, (char *)pkt + bd->net_tx_len,
                               len, TMFIFO_NET_CHAN, true);
    if (written > 0)
      bd->net_tx_len += written;
  } while (written == len);
}
