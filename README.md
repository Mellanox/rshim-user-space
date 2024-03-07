                  BlueField Rshim Host Driver

The rshim driver provides a way to access the rshim resources on the BlueField
target from external host machine. The current version implements device files
for boot image push and virtual console access. It also creates virtual network
interface to connect to the BlueField target and provides a way to access the
internal rshim registers.

*) Build

  Linux:

  Make sure autoconf/automake/pkg-config tools are available. Run bootstrap.sh
  for the first time to generate the configure file. Then run the ./configure
  script followed by make & make install to build and install it.

  FreeBSD:

  Require FreeBSD 12.0+ with packages autoconf, automake, gmake, libepoll-shim,
  libpciaccess, libpci, pkgconf.

  Follow the same steps above to build it. Use 'gmake install' to install it.

*) Usage

rshim -h
syntax: rshim [--help|-h] [--backend|-b usb|pcie|pcie_lf]
                [--device|-d device-name] [--foreground|-f]
                [--debug-level|-l <0~4>]

*) Device Files

  Each rshim target will create a directory /dev/rshim\<N\>/ with the
  following device files. \<N\> is the device id, which could be 0, 1, etc.

  - /dev/rshim\<N\>/boot
  
  Boot device file used to push boot stream to the ARM side, for example,
  
    cat install.bfb > /dev/rshim<N>/boot

  - /dev/rshim\<N\>/console
  
  Console device, which can be used by console apps to connect to the ARM side,
  such as
  
    screen /dev/rshim<N>/console

  - /dev/rshim\<N\>/rshim
  
  Device file used to access the rshim registers. The read/write offset is
  encoded as "((rshim_channel << 16) | register_offset)".

  - /dev/rshim\<N\>/misc
  
  Key/Value pairs used to read/write misc information. For example,

  Display the content:

    cat /dev/rshim<N>/misc
      DISPLAY_LEVEL   0 (0:basic, 1:advanced, 2:log)
      BOOT_MODE       1 (0:rshim, 1:emmc, 2:emmc-boot-swap)
      BOOT_TIMEOUT    100 (seconds)
      DROP_MODE       0 (0:normal, 1:drop)
      SW_RESET        0 (1: reset)
      DEV_NAME        usb-3.3
      DEV_INFO        BlueField-3(Rev 1)
      OPN_STR         9009D3B400ENEA
      UP_TIME         179752(s)
      SECURE_NIC_MODE 1 (0:no, 1:yes)

  Display more infomation:

    echo "DISPLAY_LEVEL 1" > cat /dev/rshim<N>/misc
    cat /dev/rshim<N>/misc
      ...
      PEER_MAC  00:1a:ca:ff:ff:01   # Target-side MAC address
      PXE_ID    0x01020304          # PXE DHCP-client-identifier

    The 'PEER_MAC' attribute can be used to display and set the target-side MAC
    address of the rshim network interface. It works when the target-side is in
    UEFI BootManager or in Linux where the tmfifo has been loaded. The new MAC
    address will take effect in next boot.

  Initiate a SW reset:
    
    echo "SW_RESET 1" > /dev/rshim<N>/misc

  When 'SECURE_NIC_MODE' is shown as 1, the NIC firmware is in Secure NIC mode
  and most rshim functionalities are disabled. This mode applies to PCIe rshim
  backend only. PCIe LF and USB rshim backends are not affected.

*) Multiple Boards Support

  Multiple boards could connect to the same host machine. Each of them has its
  own device directory /dev/rshim<N>/. Network subnet needs to be set properly
  just like any other standard NIC.

*) How to change the MAC address of the ARM side interface

  Update the 'PEER_MAC' attribute in the misc file like below. Display the value
  to confirm it's set. Reboot the device to take effect.

    echo "PEER_MAC 00:1a:ca:ff:ff:10" > /dev/rshim\<N\>/misc
