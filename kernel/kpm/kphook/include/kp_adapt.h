/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Adaptation shim between KernelPatch LKM source files (copied under
 * kernel/kpm/kphook/) and the symbol/text-patch helpers Ultra's fork already
 * ships under kernel/infra and kernel/hook. By defining these as macros we
 * keep hook.c/hook_runtime.c unchanged, so future resyncs from
 * bmax121/KernelPatch are a plain file drop.
 */
#ifndef _KP_ADAPT_H_
#define _KP_ADAPT_H_

#include "../../../infra/symbol_resolver.h"
#include "../../../hook/patch_memory.h"

/* KernelPatch kp_resolve_symbol(name) -> fork's find_kernel_symbol_exact(name).
 * Both return 0 on miss and a kernel address on hit. */
#define kp_resolve_symbol(name) find_kernel_symbol_exact(name)

/* KernelPatch kp_patch_text(dst, src, size, flags) ->
 * fork's ksu_patch_text(dst, src, size, flags). Flag bits match. */
#define kp_patch_text(dst, src, size, flags) ksu_patch_text((dst), (src), (size), (flags))

#define KP_PATCH_TEXT_FLUSH_DCACHE KSU_PATCH_TEXT_FLUSH_DCACHE
#define KP_PATCH_TEXT_FLUSH_ICACHE KSU_PATCH_TEXT_FLUSH_ICACHE

#endif /* _KP_ADAPT_H_ */
