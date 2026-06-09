/*
 * kernel/linux/lkm/module_crc.h
 * Role: Read-only per-module symbol-version CRC / build-id export for signal 95's
 *       in-memory half. Declares the init/exit the main horkos.c calls to create
 *       and tear down a debugfs seq_file under horkos/module_crcs. NO text writes,
 *       no symbol patching — read-only module-list iteration only.
 * Target platform: Linux (LKM; gated by HORKOS_LINUX_LKM). Never compiled on
 *                   Windows or macOS; never shares a TU with userspace.
 * Interface: declares horkos_module_crc_init / horkos_module_crc_exit, invoked
 *            from horkos.c's module_init/exit.
 */

#ifndef HORKOS_MODULE_CRC_H
#define HORKOS_MODULE_CRC_H

/*
 * horkos_module_crc_init — create the read-only debugfs node horkos/module_crcs.
 * Returns 0 on success, a negative errno on failure (debugfs absent / alloc
 * fail). A failure is NON-FATAL for the module as a whole (the caller logs and
 * continues without the CRC export); the build-id userspace half (ModuleDiskDrift)
 * still works.
 */
int horkos_module_crc_init(void);

/*
 * horkos_module_crc_exit — remove the debugfs node. Idempotent; safe to call when
 * init failed or was never called.
 */
void horkos_module_crc_exit(void);

#endif /* HORKOS_MODULE_CRC_H */
