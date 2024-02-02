#!/bin/sh
#
# This script reads from a named pipe and writes to the rshim device.
#
# It is intended to be run on BMC to forward data from the host to the BMC RSHIM
# device. 
#
# Known Issues:
#  - This script must be copied over to the BMC and run from there. We need to 
#    change it to SSH-run this script from the host.

HOST_PIPE="/tmp/mypipe"         # Must be defined same in bfb-install

if [ ! -p "$HOST_PIPE" ]; then
  echo "Named pipe $HOST_PIPE doesn't exist. Creating it."
  mkfifo /tmp/mypipe
fi

RSHIM_NODE="/dev/rshim0/boot"
BLOCK_SIZE=2048000  # You can adjust the block size as needed

# Ensure the named pipe exists
if ! [ -p $HOST_PIPE ]; then
    echo "Named pipe $HOST_PIPE does not exist."
    exit 1
fi

echo "Continuously read from pipe and write to rshim device..."
if dd if=$HOST_PIPE of=$RSHIM_NODE bs=$BLOCK_SIZE; then
    echo "Successfully forwarded data from $HOST_PIPE to $RSHIM_NODE"
else
    echo "Error occurred in dd command"
    exit 1
fi
