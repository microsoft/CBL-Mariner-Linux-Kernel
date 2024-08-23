#!/bin/bash
# Install the software necessary to run and graph the tests in
# this directory. Tested on Ubuntu Linux.

set -x  # print commands before executing
set -e  # exit upon error

# Quick and dirty installation of netperf:
wget https://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/l/lksctp-tools-1.0.19-9.fc41.x86_64.rpm
wget https://fr2.rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/n/netperf-2.7.0-9.20210803git3bc455b.fc41.x86_64.rpm
sudo dnf install -y --nogpgcheck lksctp-tools-1.0.19-9.fc41.x86_64.rpm
sudo dnf install -y --nogpgcheck netperf-2.7.0-9.20210803git3bc455b.fc41.x86_64.rpm

# Quick and dirty installation pahole which is needed to compile the kernel:
wget https://rpmfind.net/linux/openmandriva/cooker/repository/x86_64/main/release/pahole-1.25-1-omv2390.x86_64.rpm
sudo dnf install -y --nogpgcheck pahole-1.25-1-omv2390.x86_64.rpm

# On Ubuntu 18.04.2 LTS, there are issues with the iproute2 binaries:
#  (1) the 'tc' binary  has a bug and cannot parse netem random loss rates
#  (2) the 'ss' tool is missing recent socket stats
# In addition, all off-the-shelf iproute2 binaries lack support for features
# added in BBRv3.
# So to use this testing tool we build our own iproute2 tools
# from the iproute2 sources, with patches from the BBRv3
# source tree:

# Install other tools which are needed to compile the kernel.
sudo dnf install -y pkg-config make bison flex git gcc binutils glibc-devel kernel-headers openssl-devel elfutils-libelf-devel zlib-devel

# Our project's patches for the iproute2 package are in this directory:
PATCH_DIR=`pwd`

sudo bash -c  "\
  mkdir -p /root/iproute2/; \
  cd /root/iproute2; \
  git clone git://git.kernel.org/pub/scm/network/iproute2/iproute2.git; \
  cd ./iproute2/ ; \
  git checkout v6.4.0 ; \
  git am ${PATCH_DIR}/*patch ; \
  ./configure ; \
  make"
