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

#include <linux/delay.h>

static int kpm_fp_wrap_syscalln(int nr, int narg, void *before, void *after,
                                void *udata)
{
    int rc;
    pr_emerg("kpm: fp_wrap_syscalln enter nr=%d narg=%d before=%px after=%px\n",
             nr, narg, before, after);
    mdelay(50);
    if (kpm_resolve_sys_call_table()) {
        pr_emerg("kpm: fp_wrap_syscalln sys_call_table=NULL\n");
        mdelay(50);
        return -ENOENT;
    }
    pr_emerg("kpm: fp_wrap_syscalln table=%px target=%px calling hook_wrap\n",
             kpm_sys_call_table, kpm_sys_call_table[nr]);
    mdelay(50);
    rc = hook_wrap(kpm_sys_call_table[nr], narg, before, after, udata);
    pr_emerg("kpm: fp_wrap_syscalln returned rc=%d\n", rc);
    mdelay(50);
    return rc;
}

static void kpm_fp_unwrap_syscalln(int nr, void *before, void *after)
{
    pr_emerg("kpm: fp_unwrap_syscalln enter nr=%d\n", nr);
    mdelay(50);
    if (kpm_resolve_sys_call_table())
        return;
    hook_unwrap(kpm_sys_call_table[nr], before, after);
    pr_emerg("kpm: fp_unwrap_syscalln returned\n");
    mdelay(50);
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
    { "fp_wrap_syscalln", &kpm_fp_wrap_syscalln },
    { "fp_unwrap_syscalln", &kpm_fp_unwrap_syscalln },
};

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
