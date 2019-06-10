                  BlueField Rshim Host Driver

The rshim driver provides a way to access the rshim resources on the BlueField
target from external host machine. The current version implements device files
for boot image push and virtual console access. It also creates virtual network
interface to connect to the BlueField target and provides a way to access
internal rshim registers.

*) Build

  Type 'make' to generate executable bfrshim.
  TBD: Use configure to generate platform indepent Makefile.

*) Usage

./rshim [options]
  -a                     advanced options
  -b <usb|pcie|pcie_lf>  driver name
  -k                     skip sw_reset
  -l <0~4>               debug level

*) Device Files

  Each rshim target will create a directory /dev/rshim<N>/ with the
  following files. '<N>' is the device id, which could be 0, 1, etc.

  - /dev/rshim<N>/boot
  
  Boot device file used to send boot stream to the ARM side, for example,
  
    cat install.bfb > /dev/rshim<N>/boot

  - /dev/rshim<N>/console
  
  Console device, which can be used by console tools to connect to the ARM side,
  such as
  
    screen /dev/rshim<N>/console

  - /dev/rshim<N>/rshim
  
  Device file used to access rshim register space. When reading / writing to
  this file, encode the offset as "((rshim_channel << 16) | register_offset)".

  - /dev/rshim<N>/misc:
  
  Key/Value pairs used to read/write misc information. For example,

    cat /dev/rshim<N>/misc
      BOOT_MODE 1                   # eMMC boot mode (0:USB/PCIe, 1: eMMC)
      SW_RESET  0                   # Set to 1 to initiate SW RESET
      DRV_NAME  rshim_usb           # Backend driver name (display-only)

    Turning on the 'rshim_adv_cfg' flag with the '-a' command line argument
    could display more parameters.
    
    cat /dev/rshim<N>/misc
      ...
      PEER_MAC  00:1a:ca:ff:ff:01   # Target-side MAC address
      PXE_ID    0x01020304          # PXE DHCP-client-identifier

    Initiate a SW reset.
    
    echo "SW_RESET 1" > /dev/rshim<N>/misc

    The 'PEER_MAC' attribute can be used to display/set the target-side MAC
    address of the rshim network interface. It works when the target-side is in
    UEFI BootManager or in Linux where the tmfifo has been loaded. The new MAC
    address will take effect in next boot.

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

  echo 1 > /sys/module/rshim/parameters/rshim_adv_cfg
  
  cat /dev/rshim<N>/misc
  
    ...
    PEER_MAC  00:1a:ca:ff:ff:01   # This is the current configured MAC address
    ...
    
  echo "PEER_MAC 00:1a:ca:ff:ff:10" > /dev/rshim<N>/misc
