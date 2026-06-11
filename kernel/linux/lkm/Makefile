# kernel/linux/lkm/Makefile
# Role: Out-of-tree Kbuild Makefile for the horkos LKM.
# Target platform: Linux (non-Deck path; guarded by HORKOS_LINUX_LKM).
# Interface: Invoked by CMake custom target horkos_lkm when HORKOS_LINUX_LKM=ON.
#
# Build with: make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
# Clean with: make -C /lib/modules/$(uname -r)/build M=$(pwd) clean

# When this file is re-entered from the kernel build system KERNELRELEASE is
# defined; that branch sets up the module sources.  The top-level branch
# drives the recursive make invocation so the caller does not have to supply
# the -C / M= flags manually.

ifneq ($(KERNELRELEASE),)

# ----- Kbuild context -------------------------------------------------------

# Extra C flags: treat all warnings as errors (guardrail #6).
# -Wno-unused-function is intentional: stub helpers that are conditionally
# used by future phases should not break the build.
# -Wall -Werror on OUR objects. -Wextra is deliberately NOT forced here: an
# out-of-tree module compiles the kernel headers under these flags too, and the
# mainline headers are not -Wextra-clean (they trip -Wunused-parameter etc.),
# which would fail the build inside the kernel tree rather than in our code. For
# stricter per-source checking use the kernel's own `make W=1`. -Wno-unused-
# function keeps conditionally-used stub helpers from breaking the build.
ccflags-y := -Wall -Werror -Wno-unused-function

# horkos.o is the module; module_crc.o is the signal-95 read-only debugfs export
# (CONFIG_DEBUG_FS=y probed at init, graceful when absent). A multi-object module
# uses the <module>-objs (a.k.a. <module>-y) list with obj-m naming the module.
obj-m := horkos.o
horkos-y := horkos_main.o module_crc.o

else

# ----- Driver context (invoked directly or by CMake) -----------------------

KDIR  ?= /lib/modules/$(shell uname -r)/build
MDIR  := $(shell pwd)

.PHONY: modules clean

modules:
	$(MAKE) -C "$(KDIR)" M="$(MDIR)" modules

clean:
	$(MAKE) -C "$(KDIR)" M="$(MDIR)" clean

endif
