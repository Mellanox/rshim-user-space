// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
/*
 * Copyright 2019 Mellanox Technologies. All Rights Reserved.
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
#endif
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "rshim.h"

#define ETH_PKT_SIZE            1536 /* maximum non-jumbo ethernet frame size */

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
  struct ifreq ifr;
  int s, fd;

  system("modprobe tun");

  fd = open("/dev/net/tun", O_RDWR);
  if (fd < 0) {
    RSHIM_ERR("Can't open %s: %m\n", ifname);
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

  if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
    RSHIM_ERR("ioctl failed: %m\n");
    close(fd);
    return -1;
  }

  memcpy(ifr.ifr_hwaddr.sa_data, rshim_net_default_mac, 6);
  ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
  ifr.ifr_hwaddr.sa_data[5] += index * 2;
  if (ioctl(fd, SIOCSIFHWADDR, &ifr)) {
    perror("SIOCSIFHWADDR");
    close(fd);
    return -1;
  }

  s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) {
    RSHIM_ERR("socket failed: %m\n");
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
#elif defined(__FreeBSD__)
/* Open tun/tap interface. */
static int rshim_if_open(char *ifname, int index)
{
  struct ifreq ifr;
  int s, fd;

  s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) {
    RSHIM_ERR("socket failed: %m\n");
    return -1;
  }

  fd = open("/dev/tap", O_RDWR);
  if (fd < 0) {
    system("kldload -qn if_tap");
    fd = open("/dev/tap", O_RDWR);
    if (fd < 0) {
      RSHIM_ERR("Can't open %s: %m\n", ifname);
      close(s);
      return -1;
    }
  }

  memset(&ifr, 0, sizeof(ifr));
  if (ioctl(fd, TAPGIFNAME, &ifr) < 0) {
    perror("TAPGIFNAME");
    close(fd);
    close(s);
    return -1;
  }

  ifr.ifr_data = ifname;
  if (ioctl(s, SIOCSIFNAME, &ifr) < 0) {
    char temp[sizeof(ifr.ifr_name)];

    memcpy(temp, ifr.ifr_name, sizeof(temp));
    strncpy(ifr.ifr_name, ifname, sizeof(temp));

    /* cleanup old device */
    if (ioctl(s, SIOCIFDESTROY, &ifr) < 0) {
      RSHIM_ERR("SIOCIFDESTROY failed: %m\n");
      close(s);
      close(fd);
      return -1;
    }

    strncpy(ifr.ifr_name, temp, sizeof(temp));

    /* try to rename device again */
    if (ioctl(s, SIOCSIFNAME, &ifr) < 0) {
      RSHIM_ERR("SIOCIFNAME failed: %m\n");
      close(s);
      close(fd);
      return -1;
    }
  }

  strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

  ifr.ifr_mtu = ETH_PKT_SIZE;
  if (ioctl(s, SIOCSIFMTU, &ifr) < 0) {
    perror("SIOCSIMTU");
    close(s);
    close(fd);
    return -1;
  }

  memcpy(ifr.ifr_addr.sa_data, rshim_net_default_mac, 6);
  ifr.ifr_addr.sa_family = AF_LINK;
  ifr.ifr_addr.sa_len = 6;
  ifr.ifr_addr.sa_data[5] += index * 2;
  if (ioctl(s, SIOCSIFLLADDR, &ifr) < 0) {
    perror("SIOCSIFLLADDR");
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
  if (fd >= 0) {
    ioctl(fd, TUNSETPERSIST, 0);
    close(fd);
  }
}
#elif defined(__FreeBSD__)
static void rshim_if_close(int fd)
{
  struct ifreq ifr;
  int s;

  if (fd < 0)
    return;

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

int rshim_net_init(struct rshim_backend *bd)
{
  struct epoll_event event;
  char ifname[64];
  int rc;

  snprintf(ifname, sizeof(ifname), "tmfifo_net%d", bd->dev_index);
  bd->net_fd = rshim_if_open(ifname, bd->dev_index);

  if (bd->net_fd < 0)
    return bd->net_fd;

  memset(&event, 0, sizeof(event));

  event.data.fd = bd->net_fd;
  event.events = EPOLLIN;
  rc = epoll_ctl(rshim_epoll_fd, EPOLL_CTL_ADD, bd->net_fd, &event);
  if (rc == -1) {
    RSHIM_ERR("epoll_ctl failed: %m %d %d\n", rshim_epoll_fd, bd->net_fd);
    return rc;
  }

  rc = pipe(bd->net_notify_fd);
  if (rc == -1) {
    perror("Failed to create pipe %m");
    return rc;
  }

  event.data.fd = bd->net_notify_fd[0];
  event.events = EPOLLIN;
  rc = epoll_ctl(rshim_epoll_fd, EPOLL_CTL_ADD, bd->net_notify_fd[0], &event);
  if (rc == -1) {
    RSHIM_ERR("epoll_ctl failed: %m %d %d\n",
              rshim_epoll_fd, bd->net_notify_fd[0]);
    bd->net_notify_fd[0] = -1;
    return rc;
  }

  return 0;
}

int rshim_net_del(struct rshim_backend *bd)
{
  struct epoll_event event;

  memset(&event, 0, sizeof(event));

  if (bd->net_fd >= 0) {
    event.data.fd = bd->net_fd;
    epoll_ctl(rshim_epoll_fd, EPOLL_CTL_DEL, bd->net_fd, &event);
  }

  if (bd->net_notify_fd[0] >= 0) {
    event.data.fd = bd->net_notify_fd[0];
    epoll_ctl(rshim_epoll_fd, EPOLL_CTL_DEL, bd->net_notify_fd[0], &event);
  }

  rshim_if_close(bd->net_fd);
  bd->net_fd = -1;
  return 0;
}

void rshim_net_rx(struct rshim_backend *bd)
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

void rshim_net_tx(struct rshim_backend *bd)
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
