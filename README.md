# CBL-Mariner-Linux-Kernel Documentation

Welcome to the documentation branch of the CBL-Mariner-Linux-Kernel repository! This branch is dedicated to providing comprehensive resources for understanding and working with the customized Linux kernel developed by Microsoft for AzureLinux (formerly known as CBL-Mariner).

AzureLinux is a lightweight and secure Linux distribution designed by Microsoft for cloud and edge computing. 

To learn more about how this kernel powers AzureLinux, visit the [AzureLinux](https://github.com/microsoft/azurelinux/) repository.

## Tag Usage

> **⚠️ Use Tags!**  
> When accessing specific versions of the kernel source, **you must check out tags rather than branches** to ensure you are working with the correct version.

To see the list of features added to each tag, see the `MSFT-Merge/log` file.

### Tag Format

The tags follow a specific format to denote the versioning information:

```
rolling-lts/mariner-<AzL3 version>/<kernel LTS version>.<AzL kernel version>
```

### Example

For example, a tag might look like:

```
rolling-lts/mariner-3/6.6.85.1
```

In this example:
- **AzL3 version**: `3`
- **LTS version**: `6.6.85`
- **AzL kernel version**: `1`

### How to Check Out a Tag

To check out a specific tag, use the following Git commands:

```bash
# Fetch all tags from the remote repository
git fetch --all --tags

# Check out the desired tag
git checkout tags/<tag_name> -b <optional_branch_name>
```

Replace `<tag_name>` with the desired tag (e.g., `rolling-lts/mariner-3/6.6.85.1`), and optionally provide a branch name if you want to create a branch from the tag.

## Building

To build the kernel on AzureLinux, refer to the [BUILDING.md](BUILDING.md) guide. It includes step-by-step instructions, prerequisites, and helpful tips to get started quickly.

## Contribution

If you wish to contribute to the documentation, feel free to open a pull request on this branch. Please ensure that your contributions align with the versioning and tagging conventions described above.

## Additional Resources

For more information about CBL-Mariner and its kernel:
- [AzureLinux GitHub Repository](https://github.com/microsoft/azurelinux/)
- [AzureLinux Tutorial Documentation](https://github.com/microsoft/azurelinux-tutorials/blob/main/docs/kernel/modify_kernel.md#build-a-custom-kernel-rpm)

---

Thank you for using **CBL-Mariner-Linux-Kernel**! If you have any questions or issues, please feel free to raise them in the repository's issue tracker.
