#!/bin/bash

################################################################################
# Copyright (c) 2023 Microsoft Corporation
################################################################################

#usage: run sudo ./add_sk_to_initramfs.sh <path_to_optee> (i.e. ../optee-os)
export OUT_DIR=$1
export SKERNEL_LOAD_FILE="$1/skloader.bin"
export SKERNEL_FILE="$1/vmlinux.bin"
export SKERNEL_LOAD_FILE_ABSPATH="$(readlink -f $SKERNEL_LOAD_FILE)"
export SKERNEL_FILE_ABSPATH="$(readlink -f $SKERNEL_FILE)"
export SKERNEL_HOOK_FILE="/usr/share/initramfs-tools/hooks/skernel"

# If skloader.bin file does not exist, exit
if [[ ! -f $SKERNEL_LOAD_FILE ]]
then
   echo "Error: $SKERNEL_LOAD_FILE_ABSPATH does not exist."
   echo "Compile skloader.bin and then re-try."
   exit 0
fi

# If skloader.bin file does not exist, exit
if [[ ! -f $SKERNEL_FILE ]]
then
   echo "Error: $SKERNEL_FILE_ABSPATH does not exist."
   echo "Compile secure linux kernel(vmlinux.bin) and then re-try."
   exit 0
fi

# If hook script file does not already exist, create it and set its permissions
if [[ ! -f $SKERNEL_HOOK_FILE ]]
then
   touch $SKERNEL_HOOK_FILE
   chmod 755 $SKERNEL_HOOK_FILE
fi

# Copy mkinitramfs hook script to add tee.bin to initramfs
cat > $SKERNEL_HOOK_FILE <<EOF
#!/bin/sh

PREREQ=""
prereqs()
{
   echo "\$PREREQ"
}

case \$1 in
prereqs)
   prereqs
   exit 0
   ;;
esac

. /usr/share/initramfs-tools/hook-functions
# Begin real processing below this line

cp $SKERNEL_LOAD_FILE_ABSPATH "\${DESTDIR}/lib/firmware"
cp $SKERNEL_FILE_ABSPATH "\${DESTDIR}/lib/firmware"

exit 0
EOF
