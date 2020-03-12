                  BlueField Rshim Host Driver

The rshim driver provides a way to access the rshim resources on the BlueField
target from external host machine. The current version implements device files
for boot image push and virtual console access. It also creates virtual network
interface to connect to the BlueField target and provides a way to access
internal rshim registers.

*) Build

  Linux:

  Make sure autoconf/automake tools are available. Run ./bootstrap.sh for the
  first time to generate the configure file. Then run ./configure and make to
  generate the bfrshim and 'make install' to install it.

  FreeBSD:

  Require FreeBSD 12.0+ with packages autoconf, automake, gmake, libepoll-shim,
  libpciaccess, libpci, pkgconf.

  Follow the same steps above to build it. Use 'gmake install' to install it.

*) Usage

bfrshim -h
syntax: bfrshim [--help|-h] [--backend|-b usb|pcie|pcie_lf]
                [--device|-d device-name] [--foreground|-f]
                [--debug-level|-l <0~4>]

*) Device Files

  Each rshim target will create a directory /dev/rshim\<N\>/ with the
  following files. \<N\> is the device id, which could be 0, 1, etc.

  - /dev/rshim\<N\>/boot
  
  Boot device file used to push boot stream to the ARM side, for example,
  
    cat install.bfb > /dev/rshim<N>/boot

  - /dev/rshim\<N\>/console
  
  Console device, which can be used by console tools to connect to the ARM side,
  such as
  
    screen /dev/rshim<N>/console

  - /dev/rshim\<N\>/rshim
  
  Device file used to access rshim register space. When reading / writing to
  this file, encode the offset as "((rshim_channel << 16) | register_offset)".

  - /dev/rshim\<N\>/misc:
  
  Key/Value pairs used to read/write misc information. For example,

    cat /dev/rshim<N>/misc
      DISPLAY_LEVEL   0 (0:basic, 1:advanced, 2:log)
      BOOT_MODE       1 (0:rshim, 1:emmc, 2:emmc-boot-swap)
      BOOT_TIMEOUT    100 (seconds)
      SW_RESET        0 (1: reset)
      DEV_NAME        usb-3.3

  Set display level to advanced will show more information.

    echo "DISPLAY_LEVEL 1" > cat /dev/rshim<N>/misc
    
    cat /dev/rshim<N>/misc
      ...
      PEER_MAC  00:1a:ca:ff:ff:01   # Target-side MAC address
      PXE_ID    0x01020304          # PXE DHCP-client-identifier

    The 'PEER_MAC' attribute can be used to display/set the target-side MAC
    address of the rshim network interface. It works when the target-side is in
    UEFI BootManager or in Linux where the tmfifo has been loaded. The new MAC
    address will take effect in next boot.

  Initiate a SW reset.
    
    echo "SW_RESET 1" > /dev/rshim<N>/misc

*) Multiple Boards Support

  Multiple boards could connect to the same host machine. Each of them has its
  own device directory /dev/rshim<N>. Below are some guidelines how to set up
  rshim networking properly in such case.

  - The host rshim network interface should have different MAC address and IP
    address, which can be configured with ifconfig like below or save it in
    configuration.
    
      `ifconfig tmfifo_net0 192.168.100.2/24 hw ether 02:02:02:02:02:02`

  - The ARM side tmfifo interface should have unique MAC and IP as well, which
    can be done in the console.

*) How to change the MAC address of the ARM side interface to be persistent

  Below is an example to change the MAC address from 00:1a:ca:ff:ff:01 to
  00:1a:ca:ff:ff:10.

  Turning on the 'rshim_adv_cfg' flag.
  
  cat /dev/rshim\<N\>/misc
  
    ...
    PEER_MAC  00:1a:ca:ff:ff:01   # This is the current configured MAC address
    ...
    
  echo "PEER_MAC 00:1a:ca:ff:ff:10" > /dev/rshim\<N\>/misc
