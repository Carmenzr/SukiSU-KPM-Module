#include <linux/export.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/kernfs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/elf.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <asm/elf.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <asm/cacheflush.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/set_memory.h>
#include <linux/version.h>
#include <linux/export.h>
#include <linux/slab.h>
#include "infra/symbol_resolver.h"
#include "kpm.h"
#include "compact.h"
#include "policy/allowlist.h"
#include "manager/manager_identity.h"

static int sukisu_is_su_allow_uid(uid_t uid)
{
    return ksu_is_allow_uid_for_current(uid) ? 1 : 0;
}

static int sukisu_get_ap_mod_exclude(uid_t uid)
{
    return 0; /* Not supported */
}

static int sukisu_is_uid_should_umount(uid_t uid)
{
    return ksu_uid_should_umount(uid) ? 1 : 0;
}

static int sukisu_is_current_uid_manager(void)
{
    return is_manager();
}

static uid_t sukisu_get_manager_uid(void)
{
    return ksu_manager_appid;
}

static void sukisu_set_manager_uid(uid_t uid, int force)
{
    if (force || ksu_manager_appid == -1)
        ksu_manager_appid = uid;
}

/*
 * KernelPatch environment symbols that KPM modules reference as UND
 * (demo-hello: kpver / kf_strncat / compat_copy_to_user). The upstream
 * patch environment provides them; module form serves them from here.
 */
static int kpm_kpver = 5;

static char *kpm_kf_strncat(char *dest, const char *src, size_t count)
{
    return strncat(dest, src, count);
}

static int kpm_compat_copy_to_user(void __user *to, const void *from, int n)
{
    return copy_to_user(to, from, n) ? -EFAULT : n;
}

static int kpm_compat_strncpy_from_user(char *dst, const char __user *src, int n)
{
    long r = strncpy_from_user(dst, src, n);
    return (int)r;
}

/*
 * KernelPatch runtime shims that KPMs reference as UND:
 *   kf_memcpy / kf_memset / kf_memcmp / kf_strcmp / kf_strncmp / kf_strlen
 * The kernel exports memcpy/memset/etc, but their arm64 assembly entry may
 * not be callable with the plain ABI (kcfi, bti). Wrap them.
 */
static void *kpm_kf_memcpy(void *dest, const void *src, size_t n)
{
    return memcpy(dest, src, n);
}

static void *kpm_kf_memset(void *s, int c, size_t n)
{
    return memset(s, c, n);
}

static int kpm_kf_memcmp(const void *a, const void *b, size_t n)
{
    return memcmp(a, b, n);
}

static int kpm_kf_strcmp(const char *a, const char *b)
{
    return strcmp(a, b);
}

static int kpm_kf_strncmp(const char *a, const char *b, size_t n)
{
    return strncmp(a, b, n);
}

static size_t kpm_kf_strlen(const char *s)
{
    return strlen(s);
}

/*
 * KernelPatch exposes current_uid() returning uid_t to KPMs.
 * from_kuid() must be called on the kuid_t the task_struct holds.
 */
static uid_t kpm_current_uid(void)
{
    return from_kuid(&init_user_ns, current_uid());
}

/*
 * arm64 GKI kernels always use the SYSCALL_WRAPPER convention
 * (syscall handlers take a single struct pt_regs *). Return 1.
 */
static int kpm_has_syscall_wrapper(void)
{
    return 1;
}

/*
 * Inline-hook runtime wiring. hook_wrap / unhook live in the ported
 * KernelPatch base kernel/kpm/kphook/hook.c (included via hook_engine.c).
 * KPMs also ask for fp_wrap_syscalln / fp_unwrap_syscalln as separate UND
 * symbols; the LKM port maps them onto hook_wrap(sys_call_table[nr]) —
 * same approach as bmax121/KernelPatch's lkm/kpm/symbols.c.
 *
 * The earlier panic that pushed us to stubs was NOT inside hook_wrap at
 * all; it was the KPM's `BL hook_wrap` immediate branching into the slot
 * array (kpm loader routed every UND sym through a slot, so CALL26 reloc
 * built a PC-relative branch to the slot bytes). Fix moved to kploader.c:
 * CALL26/JUMP26 symbols now get st_value = real addr, slot path is kept
 * only for GOT-form (adrp+ldr+blr) references.
 */
#include "kphook/include/hook.h"
#include "kphook/hook_runtime.h"

static void **kpm_sys_call_table;

static int kpm_resolve_sys_call_table(void)
{
    if (!kpm_sys_call_table)
        kpm_sys_call_table = (void **)find_kernel_symbol_exact("sys_call_table");
    return kpm_sys_call_table ? 0 : -ENOENT;
}

static int kpm_fp_wrap_syscalln(int nr, int narg, void *before, void *after,
                                void *udata)
{
    if (kpm_resolve_sys_call_table())
        return -ENOENT;
    return hook_wrap(kpm_sys_call_table[nr], narg, before, after, udata);
}

static void kpm_fp_unwrap_syscalln(int nr, void *before, void *after)
{
    if (kpm_resolve_sys_call_table())
        return;
    hook_unwrap(kpm_sys_call_table[nr], before, after);
}

/*
 * KernelPatch's inline_wrap_syscalln hooks the syscall function itself (as
 * opposed to the sys_call_table slot that fp_wrap_syscalln targets). On this
 * fork we only have one hook engine (hook_wrap), so inline_* and fp_* end up
 * at the same target: sys_call_table[nr]. Matches lkm/kpm/symbols.c upstream.
 * The is_compat arg is accepted but ignored (arm64 GKI has no compat table).
 */
static int kpm_inline_wrap_syscalln(int nr, int narg, int is_compat,
                                    void *before, void *after, void *udata)
{
    (void)is_compat;
    if (kpm_resolve_sys_call_table())
        return -ENOENT;
    /* has_syscall_wrapper is always true on arm64 GKI: syscall takes pt_regs. */
    return hook_wrap(kpm_sys_call_table[nr], 1, before, after, udata);
}

static void kpm_inline_unwrap_syscalln(int nr, int is_compat,
                                       void *before, void *after)
{
    (void)is_compat;
    if (kpm_resolve_sys_call_table())
        return;
    hook_unwrap(kpm_sys_call_table[nr], before, after);
}

struct CompactAddressSymbol {
    const char *symbol_name;
    void *addr;
};

unsigned long sukisu_compact_find_symbol(const char *name);

static struct CompactAddressSymbol address_symbol[] = {
    { "kallsyms_lookup_name", &kallsyms_lookup_name },
    { "compact_find_symbol", &sukisu_compact_find_symbol },
    { "is_run_in_sukisu_ultra", (void *)1 },
    { "is_su_allow_uid", &sukisu_is_su_allow_uid },
    { "get_ap_mod_exclude", &sukisu_get_ap_mod_exclude },
    { "is_uid_should_umount", &sukisu_is_uid_should_umount },
    { "is_current_uid_manager", &sukisu_is_current_uid_manager },
    { "get_manager_uid", &sukisu_get_manager_uid },
    { "sukisu_set_manager_uid", &sukisu_set_manager_uid },
    { "kpver", &kpm_kpver },
    { "kf_strncat", &kpm_kf_strncat },
    { "compat_copy_to_user", &kpm_compat_copy_to_user },
    { "compat_strncpy_from_user", &kpm_compat_strncpy_from_user },
    { "kf_memcpy", &kpm_kf_memcpy },
    { "kf_memset", &kpm_kf_memset },
    { "kf_memcmp", &kpm_kf_memcmp },
    { "kf_strcmp", &kpm_kf_strcmp },
    { "kf_strncmp", &kpm_kf_strncmp },
    { "kf_strlen", &kpm_kf_strlen },
    { "current_uid", &kpm_current_uid },
    { "has_syscall_wrapper", &kpm_has_syscall_wrapper },
    { "hook_wrap", &hook_wrap },
    { "unhook", &unhook },
    { "hook_unwrap_remove", &hook_unwrap_remove },
    { "fp_wrap_syscalln", &kpm_fp_wrap_syscalln },
    { "fp_unwrap_syscalln", &kpm_fp_unwrap_syscalln },
    { "inline_wrap_syscalln", &kpm_inline_wrap_syscalln },
    { "inline_unwrap_syscalln", &kpm_inline_unwrap_syscalln },
};

/*
 * KernelPatch exposes a handful of integer-valued "symbols" (not functions,
 * not pointers) that describe the running kernel's layout — thread_size,
 * task_in_thread_info_offset, sp_el0_is_current, etc. KPMs reference these
 * as `extern int foo;` and the compiler emits `movz Xn, #G0; movk Xn, G1`
 * reloc pairs (R_AARCH64_MOVW_UABS_G*_NC) that bake the symbol VALUE
 * directly into the instruction stream.
 *
 * These need st_value = the raw integer value, NOT a slot pointer and NOT a
 * function address. GKI arm64 is always CONFIG_THREAD_INFO_IN_TASK, so sp_el0
 * holds `current` (struct task_struct *) directly and thread_info lives at
 * task offset 0; task_in_thread_info_offset is then just 0.
 */
struct CompactValueSymbol {
    const char *symbol_name;
    unsigned long value;
};

static struct CompactValueSymbol value_symbol[] = {
    { "thread_size", 16384 },               /* THREAD_SIZE on arm64 GKI */
    { "thread_info_in_task", 1 },           /* GKI arm64 */
    { "sp_el0_is_current", 1 },             /* GKI arm64 */
    { "sp_el0_is_thread_info", 0 },
    { "task_in_thread_info_offset", 0 },    /* task IS the thread_info container */
    { "stack_in_task_offset", 0 },
    { "stack_end_offset", 16 },             /* thread_info has 2 u64 then stack */
};

bool sukisu_compact_find_value(const char *name, unsigned long *out_value)
{
    size_t i;
    for (i = 0; i < ARRAY_SIZE(value_symbol); i++) {
        if (!strcmp(name, value_symbol[i].symbol_name)) {
            *out_value = value_symbol[i].value;
            return true;
        }
    }
    return false;
}
EXPORT_SYMBOL(sukisu_compact_find_value);

unsigned long sukisu_compact_find_symbol(const char *name)
{
    int i;
    unsigned long addr;

    for (i = 0;
         i < (sizeof(address_symbol) / sizeof(struct CompactAddressSymbol));
         i++) {
        struct CompactAddressSymbol *symbol = &address_symbol[i];

        if (strcmp(name, symbol->symbol_name) == 0)
            return (unsigned long)symbol->addr;
    }

    addr = find_kernel_symbol_exact(name);
    if (addr)
        return addr;

    return 0;
}
EXPORT_SYMBOL(sukisu_compact_find_symbol);
