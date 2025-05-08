# Quickstart Guide: Building and Installing the CBL-Mariner Linux Kernel

This guide walks you through the steps to build and install the CBL-Mariner Linux Kernel on AzureLinux.

---

## Prerequisites

### Install Build Dependencies
Run the following command to install all necessary build dependencies:

```bash
sudo dnf install -y audit-devel build-essential cpio diffutils dwarves elfutils-libelf-devel flex gettext git glib-devel kbd kmod-devel libcap-devel libdnet-devel libmspack-devel ncurses-devel openssl openssl-devel pam-devel procps-ng-devel python3-devel pciutils-devel
```

---

## Step 1: Clone the Kernel Source

Replace `<kernel-version>` with the version of the kernel you want to build. For example: `rolling-lts/mariner-3/6.6.44.1`.

```bash
git clone https://github.com/microsoft/CBL-Mariner-Linux-Kernel.git -b <kernel-version> --depth=1
cd CBL-Mariner-Linux-Kernel/
```

---

## Step 2: Download the Configuration File

> **Note**: The examples below use the latest AzureLinux 3.0 development configuration for the generic kernel. Ensure you select a configuration file that matches your specific use case and kernel version.

<details>
<summary><strong>For x86_64 Architecture</strong></summary>

```bash
wget https://raw.githubusercontent.com/microsoft/azurelinux/3.0-dev/SPECS/kernel/config
cp config .config
```

</details>

<details>
<summary><strong>For AArch64 (arm64) Architecture</strong></summary>

```bash
wget https://raw.githubusercontent.com/microsoft/azurelinux/3.0-dev/SPECS/kernel/config_aarch64
cp config_aarch64 .config
```

</details>

---

## Step 3: Update Configuration

Resolve unexpected configuration differences between your build environment and the default configuration:

```bash
make oldconfig
```

For additional configuration changes, use the menu-based configuration tool:
```bash
make menuconfig
```

This will update the `.config` file with your changes.

---

## Step 4: Build the Kernel

Compile the kernel using all available CPU cores:
```bash
make -j$(nproc)
```

---

## Step 5: Install the Kernel and Configure GRUB
> **Note**: While developing, ensure Secure Boot is disabled in your BIOS/UEFI firmware settings, as it may prevent the system from loading unsigned kernels.

<details>
<summary><strong>For Mariner 2.0</strong></summary>

1. Install `installkernel` and the kernel modules:
    ```bash
    sudo tdnf install -y installkernel
    sudo make modules_install
    sudo make install
    ```
2. Reboot your system:
    ```bash
    sudo reboot
    ```
   Your system should now boot into the new kernel.

</details>

<details>
<summary><strong>For Azure Linux 3.0</strong></summary>

1. Install the kernel modules:
    ```bash
    sudo make modules_install
    ```

2. Manually copy the kernel image to `/boot`:
    ```bash
    # For x86_64 Architecture:
    sudo cp arch/x86/boot/bzImage /boot/vmlinuz-<kernel-version>

    # For AArch64 (arm64) Architecture:
    sudo cp arch/arm64/boot/Image /boot/vmlinuz-<kernel-version>
    ```

3. Rebuild the initramfs and ensure it is placed in `/boot`:
    ```bash
    sudo dracut /boot/initramfs-<kernel-version>.img <kernel-version>
    ```

4. Rebuild the GRUB configuration:
    ```bash
    sudo grub2-mkconfig -o /boot/grub2/grub.cfg
    ```

5. Set the desired GRUB entry as default:
    ```bash
    sudo vim /boot/grub2/grub.cfg
    # Copy the name of the menu entry you want as default
    # Example: "AzureLinux GNU/Linux, with Linux <kernel-version>"

    sudo vim /etc/default/grub
    # Add GRUB_DEFAULT="desiredmenuentryname"
    ```
    > **Note**: Setting the desired GRUB entry as default ensures the system automatically boots into the new kernel during subsequent restarts. This is especially helpful when multiple kernel versions are installed, as it prevents the system from inadvertently booting into an older version.

6. Set a GRUB timeout to enable the menu entry list:
    ```bash
    sudo vim /etc/default/grub
    # Add or modify the following line:
    GRUB_TIMEOUT=30
    ```
    > **Note**: Setting a longer GRUB timeout allows you to select a previous kernel during boot if something goes wrong with the new kernel. This is helpful for rollback and troubleshooting.

7. Rebuild GRUB after selecting the desired boot entry and setting the timeout:
    ```bash
    sudo grub2-mkconfig -o /boot/grub2/grub.cfg
    ```

8. Reboot your system:
    ```bash
    sudo reboot
    ```
   Your system should now boot into the new kernel.

</details>

---

## Step 6: Verification Steps

After rebooting, verify that the new kernel is active:

1. **Check Active Kernel Version**:
    Run the following command to confirm the currently running kernel version:
    ```bash
    uname -r
    ```
    Ensure the output matches the `<kernel-version>` you built and installed.

2. **Check Boot Logs**:
    Use the following command to review the system logs for any boot issues:
    ```bash
    journalctl -b
    ```
    Look for any errors or warnings related to the new kernel.

3. **Check GRUB Configuration**:
    Confirm that the new kernel is listed in the GRUB menu:
    ```bash
    sudo grep menuentry /boot/grub2/grub.cfg
    ```
    Verify that the `<kernel-version>` is present in the output.

4. **Test Functionality**:
    Perform basic checks to ensure system stability:
    - Verify that all hardware (e.g., network adapters, disks) is functioning as expected.
    - Confirm that critical services are running:
      ```bash
      systemctl status
      ```

5. **Fallback to Previous Kernel (Optional)**:
    If issues arise, reboot the system and select a previous kernel from the GRUB menu during boot.

---

If you encounter issues, consult the project documentation or raise a query in the repository's issues section.
