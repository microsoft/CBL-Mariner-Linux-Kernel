KCL_LINUXINCLUDE=$(subst -I ,-I,$(strip $(LINUXINCLUDE)))
LINUX_SRCTREE_INCLUDE := \
	$(filter-out -I%/uapi "-include %/kconfig.h",$(KCL_LINUXINCLUDE))
USER_INCLUDE := $(filter-out $(LINUX_SRCTREE_INCLUDE), $(KCL_LINUXINCLUDE))

LINUXINCLUDE := \
	-I$(src)/../include \
	-I$(src)/../include/kcl/header \
	-include $(src)/../include/kcl/kcl_version.h \
	-include $(src)/../include/rename_symbol.h \
	-include $(src)/../amd/dkms/config/config.h \
	$(LINUX_SRCTREE_INCLUDE) \
	-I$(src)/../include/uapi \
	$(USER_INCLUDE)

amddrm_ttm_helper-y := amddrm_gem_ttm_helper.o
obj-$(CONFIG_DRM_BUDDY) += amddrm_buddy.o
obj-$(CONFIG_DRM_TTM_HELPER) += amddrm_ttm_helper.o