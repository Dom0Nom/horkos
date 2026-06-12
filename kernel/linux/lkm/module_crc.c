/*
 * Role: Signal 95 in-memory half — a READ-ONLY debugfs seq_file
 *       (horkos/module_crcs) that emits one "(name, build-id-or-crc-digest)" line
 *       per loaded module, for userspace (ModuleDiskDrift.cpp) to compare against
 *       the on-disk .ko. NO text writes, no symbol patching: this only reads the
 *       module list. Separate TU from horkos.c (the tracepoint TU) to keep that
 *       file focused; horkos.c calls init/exit here.
 * Target platform: Linux (LKM; gated by HORKOS_LINUX_LKM). Never compiled on
 *                   Windows/macOS; never shares a TU with userspace (guardrail #4).
 * Interface: implements horkos_module_crc_init/exit (module_crc.h). Requires
 *            CONFIG_DEBUG_FS=y (probed; degrades gracefully if absent).
 *
 * Guardrail compliance:
 *   #1  No raw platform macros — Makefile/CMake gate compilation to Linux.
 *   #3  This module comment covers role/platform/interface.
 *   #4  Pure kernel TU — no userspace headers.
 *   #5  Only safe string helpers (scnprintf); every kernel return is checked.
 *   #6  -Wall -Wextra -Werror via the Makefile ccflags-y.
 *   #13 The struct-module field reads + list locking are FLAGGED UNCERTAIN (§7-B)
 *       and are NOT guessed — see the HK-UNCERTAIN block in the seq show().
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>

#include "module_crc.h"

/* The debugfs dir + file handles. dir is NULL when debugfs is absent or init
 * failed; exit() tolerates that. */
static struct dentry *g_horkos_dir;
static struct dentry *g_crc_file;

/*
 * The seq_file iterator over the module list.
 *
 * HK-UNCERTAIN(module-list-walk-95): walking the kernel module list and reading
 * per-module identity fields is the FLAGGED §7-B item. Specifically UNVERIFIED on
 * the target kernel(s):
 *   1. LOCKING. The module list must be walked under the correct discipline.
 *      `module_mutex` is NOT exported to out-of-tree modules on modern kernels,
 *      and `for_each_module` / the module list head (`modules`) are likewise not
 *      module-accessible. Whether a safe RCU accessor exists for an out-of-tree
 *      module on the target kernel is UNCONFIRMED. A wrong lock is a deadlock or
 *      a use-after-free walking a module mid-unload — an oops, not a logic bug.
 *   2. FIELD LAYOUT. `struct module` internals (`crcs`, `syms`, `num_syms`,
 *      `state`) and the memory-layout members (`core_layout` → `module_memory[]`
 *      around 6.4) have changed across versions and `struct module` is not a
 *      stable module ABI.
 *   3. BUILD-ID. There is no stable exported accessor to a loaded module's GNU
 *      build-id from a module; the notes section is exposed to USERSPACE via
 *      /sys/module/<m>/notes (which ModuleDiskDrift.cpp already reads) but not
 *      cleanly to in-kernel module code.
 *
 * Per guardrail #13 (a BSOD/oops is worse than an unfinished function) this show()
 * does NOT guess any of the above. It emits a single honest header line so the
 * debugfs surface, the seq_file plumbing, the registration/teardown, and the
 * userspace reader path are all real and testable, while the actual per-module
 * field reads remain unimplemented pending on-box verification of the locking +
 * field layout for the target kernel. ModuleDiskDrift.cpp's build-id half (via
 * sysfs) fully covers substitution detection in the meantime (§7-B fallback:
 * "ship build-id-only").
 */
static int horkos_module_crcs_show(struct seq_file *m, void *v)
{
	(void)v;

	seq_puts(m,
		 "# horkos module_crcs (read-only). Per-module in-memory CRC export is\n"
		 "# UNIMPLEMENTED pending on-box verification of struct module layout +\n"
		 "# module-list locking (impl-plan 7-B). Build-id substitution detection\n"
		 "# is provided by the userspace sysfs/.ko half (ModuleDiskDrift).\n");
	return 0;
}

static int horkos_module_crcs_open(struct inode *inode, struct file *file)
{
	/* single_open returns 0 or a negative errno; the caller (VFS) handles the
	 * error, but we still propagate it (guardrail #5: check every return). */
	return single_open(file, horkos_module_crcs_show, NULL);
}

static const struct file_operations horkos_module_crcs_fops = {
	.owner   = THIS_MODULE,
	.open    = horkos_module_crcs_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

int horkos_module_crc_init(void)
{
	/* debugfs_create_dir returns an ERR_PTR on failure and NULL when debugfs is
	 * not compiled in (CONFIG_DEBUG_FS=n). Treat both as "no export"; this is
	 * non-fatal for the module. */
	g_horkos_dir = debugfs_create_dir("horkos", NULL);
	if (IS_ERR_OR_NULL(g_horkos_dir)) {
		int err = g_horkos_dir ? (int)PTR_ERR(g_horkos_dir) : -ENODEV;
		g_horkos_dir = NULL;
		pr_info("horkos: debugfs unavailable (%d); module_crcs export disabled\n",
			err);
		return err;
	}

	g_crc_file = debugfs_create_file("module_crcs", 0400, g_horkos_dir, NULL,
					 &horkos_module_crcs_fops);
	if (IS_ERR_OR_NULL(g_crc_file)) {
		int err = g_crc_file ? (int)PTR_ERR(g_crc_file) : -ENODEV;
		pr_err("horkos: failed to create module_crcs debugfs file: %d\n", err);
		debugfs_remove_recursive(g_horkos_dir);
		g_horkos_dir = NULL;
		g_crc_file = NULL;
		return err;
	}

	pr_info("horkos: module_crcs read-only debugfs export created\n");
	return 0;
}

void horkos_module_crc_exit(void)
{
	/* debugfs_remove_recursive tolerates a NULL/ERR dir and removes children, so
	 * the single recursive remove cleans up both file and dir. */
	if (g_horkos_dir) {
		debugfs_remove_recursive(g_horkos_dir);
		g_horkos_dir = NULL;
		g_crc_file = NULL;
	}
}
