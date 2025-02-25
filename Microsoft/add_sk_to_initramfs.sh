#!/bin/bash

################################################################################
# Copyright (c) 2023 Microsoft Corporation
################################################################################

#usage: run sudo ./add_sk_to_initramfs.sh <path_to_optee> (i.e. ../optee-os)
export OUT_DIR=$1
export SKERNEL_LOAD_FILE="$1/skloader.bin"
export SKERNEL_LOAD_FILE_ABSPATH="$(readlink -f $SKERNEL_LOAD_FILE)"
export SKERNEL_FILE="$1/vmlinux.bin"
export SKERNEL_FILE_ABSPATH="$(readlink -f $SKERNEL_FILE)"
export SKERNEL_LOAD_SIG_FILE="$1/skloader.bin.p7s"
export SKERNEL_LOAD_SIG_FILE_ABSPATH="$(readlink -f $SKERNEL_LOAD_SIG_FILE)"
export SKERNEL_SIG_FILE="$1/vmlinux.bin.p7s"
export SKERNEL_SIG_FILE_ABSPATH="$(readlink -f $SKERNEL_SIG_FILE)"
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

# If skloader.bin.p7s file does not exist, print warning
if [[ ! -f $SKERNEL_LOAD_SIG_FILE ]]
then
   echo "Warning: $SKERNEL_LOAD_SIG_FILE_ABSPATH does not exist."
   echo "Set kernel config CONFIG_HYPERV_VSM_DISABLE_IMG_VERIFY. Otherwise, VTL1 will not boot."
fi

# If skloader.bin.p7s file does not exist, print warning
if [[ ! -f $SKERNEL_SIG_FILE ]]
then
   echo "Warning: $SKERNEL_SIG_FILE_ABSPATH does not exist."
   echo "Set kernel config CONFIG_HYPERV_VSM_DISABLE_IMG_VERIFY. Otherwise, VTL1 will not boot."
fi

# If hook script file does not already exist, create it and set its permissions
if [[ ! -f $SKERNEL_HOOK_FILE ]]
then
   touch $SKERNEL_HOOK_FILE
   chmod 755 $SKERNEL_HOOK_FILE
fi

# Copy mkinitramfs hook script to add binaries to initramfs
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

if [ -f $SKERNEL_LOAD_SIG_FILE_ABSPATH ]
then
    cp $SKERNEL_LOAD_SIG_FILE_ABSPATH "\${DESTDIR}/lib/firmware"
else
    echo "Warning: No signature file for Secure Loader is added in the initramfs."
fi

if [ -f $SKERNEL_SIG_FILE_ABSPATH ]
then
    cp $SKERNEL_SIG_FILE_ABSPATH "\${DESTDIR}/lib/firmware"
else
    echo "Warning: No signature file for Secure Kernel is added in the initramfs."
fi

exit 0
EOF
