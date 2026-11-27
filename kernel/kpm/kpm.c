/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2025 Liankong (xhsw.new@outlook.com). All Rights Reserved.
 * 本代码由GPL-2授权
 * 
 * 适配KernelSU的KPM 内核模块加载器兼容实现
 * 
 * 集成了 ELF 解析、内存布局、符号处理、重定位（支持 ARM64 重定位类型）
 * 并参照KernelPatch的标准KPM格式实现加载和控制
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/kernfs.h>
#include <linux/file.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/elf.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <asm/elf.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <asm/cacheflush.h>
#include <linux/module.h>
#include <linux/set_memory.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <asm/insn.h>
#include <linux/kprobes.h>
#include <linux/stacktrace.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0) && defined(CONFIG_MODULES)
#include <linux/moduleloader.h>
#endif
#include "kpm.h"
#include "compact.h"
#include "kploader.h"

#define KPM_NAME_LEN 32
#define KPM_ARGS_LEN 1024

#ifndef NO_OPTIMIZE
#if defined(__GNUC__) && !defined(__clang__)
#define NO_OPTIMIZE __attribute__((optimize("O0")))
#elif defined(__clang__)
#define NO_OPTIMIZE __attribute__((optnone))
#else
#define NO_OPTIMIZE
#endif
#endif

/*
 * Upstream keeps these as stubs to be runtime-hooked by the KernelPatch
 * patch (SukiSU_KernelPatch_patch kernel/patch/sukisu/sukisu.c); in
 * module form we call the real loader directly (kpm/kploader.c).
 */
noinline void sukisu_kpm_load_module_path(const char *path,
                                           const char *args,
                                           void *ptr, int *result)
{
    if (result)
        *result = (int)kpm_load_module_path(path, args, ptr);
}
EXPORT_SYMBOL(sukisu_kpm_load_module_path);

noinline void sukisu_kpm_unload_module(const char *name, void *ptr,
                                       int *result)
{
    if (result)
        *result = (int)kpm_unload_module(name, ptr);
}
EXPORT_SYMBOL(sukisu_kpm_unload_module);

noinline void sukisu_kpm_num(int *result)
{
    if (result)
        *result = kpm_get_module_nums();
}
EXPORT_SYMBOL(sukisu_kpm_num);

noinline void sukisu_kpm_info(const char *name, char *buf,
                              int bufferSize, int *size)
{
    if (size)
        *size = kpm_get_module_info(name, buf, bufferSize);
}
EXPORT_SYMBOL(sukisu_kpm_info);

noinline void sukisu_kpm_list(void *out, int bufferSize,
                              int *result)
{
    if (result)
        *result = kpm_list_modules(out, bufferSize);
}
EXPORT_SYMBOL(sukisu_kpm_list);

noinline void sukisu_kpm_control(const char *name, const char *args,
                                 long arg_len, int *result)
{
    if (!result)
        return;
    if (arg_len <= 0) {
        *result = -EINVAL;
        return;
    }
    *result = (int)kpm_module_control0(name, args, NULL, 0);
}
EXPORT_SYMBOL(sukisu_kpm_control);

noinline void sukisu_kpm_version(char *buf, int bufferSize)
{
    if (!buf || bufferSize <= 0)
        return;
    snprintf(buf, bufferSize - 1, "5.0.0 (KernelPatch-port 2026-09-27)");
}
EXPORT_SYMBOL(sukisu_kpm_version);

noinline int sukisu_handle_kpm(unsigned long control_code, unsigned long arg1,
                               unsigned long arg2, unsigned long result_code)
{
    int res = -1;
    if (control_code == SUKISU_KPM_LOAD) {
        char kernel_load_path[256];
        char kernel_args_buffer[256] = { 0 };

        if (arg1 == 0) {
            res = -EINVAL;
            goto exit;
        }

        if (!access_ok(arg1, 255)) {
            goto invalid_arg;
        }

        strncpy_from_user((char *)&kernel_load_path, (const char *)arg1, 255);

        if (arg2 != 0) {
            if (!access_ok(arg2, 255)) {
                goto invalid_arg;
            }

            strncpy_from_user((char *)&kernel_args_buffer, (const char *)arg2,
                              255);
        }

        sukisu_kpm_load_module_path((const char *)&kernel_load_path,
                                    (const char *)&kernel_args_buffer, NULL,
                                    &res);
    } else if (control_code == SUKISU_KPM_UNLOAD) {
        char kernel_name_buffer[256];

        if (arg1 == 0) {
            res = -EINVAL;
            goto exit;
        }

        if (!access_ok(arg1, sizeof(kernel_name_buffer))) {
            goto invalid_arg;
        }

        strncpy_from_user((char *)&kernel_name_buffer, (const char *)arg1,
                          sizeof(kernel_name_buffer));

        sukisu_kpm_unload_module((const char *)&kernel_name_buffer, NULL, &res);
    } else if (control_code == SUKISU_KPM_NUM) {
        sukisu_kpm_num(&res);
    } else if (control_code == SUKISU_KPM_INFO) {
        char kernel_name_buffer[256];
        char buf[256];
        int size;

        if (arg1 == 0 || arg2 == 0) {
            res = -EINVAL;
            goto exit;
        }

        if (!access_ok(arg1, sizeof(kernel_name_buffer))) {
            goto invalid_arg;
        }

        strncpy_from_user((char *)&kernel_name_buffer,
                          (const char __user *)arg1,
                          sizeof(kernel_name_buffer));

        sukisu_kpm_info((const char *)&kernel_name_buffer, (char *)&buf,
                        sizeof(buf), &size);

        if (!access_ok(arg2, size)) {
            goto invalid_arg;
        }

        res = copy_to_user(arg2, &buf, size);

    } else if (control_code == SUKISU_KPM_LIST) {
        char buf[1024];
        int len = (int)arg2;

        if (len <= 0) {
            res = -EINVAL;
            goto exit;
        }

        if (!access_ok(arg2, len)) {
            goto invalid_arg;
        }

        sukisu_kpm_list((char *)&buf, sizeof(buf), &res);

        if (res > len) {
            res = -ENOBUFS;
            goto exit;
        }

        if (copy_to_user(arg1, &buf, len) != 0)
            pr_info("kpm: Copy to user failed.");

    } else if (control_code == SUKISU_KPM_CONTROL) {
        char kpm_name[KPM_NAME_LEN] = { 0 };
        char kpm_args[KPM_ARGS_LEN] = { 0 };

        if (!access_ok(arg1, sizeof(kpm_name))) {
            goto invalid_arg;
        }

        if (!access_ok(arg2, sizeof(kpm_args))) {
            goto invalid_arg;
        }

        long name_len = strncpy_from_user(
            (char *)&kpm_name, (const char __user *)arg1, sizeof(kpm_name));
        if (name_len <= 0) {
            res = -EINVAL;
            goto exit;
        }

        long arg_len = strncpy_from_user(
            (char *)&kpm_args, (const char __user *)arg2, sizeof(kpm_args));

        sukisu_kpm_control((const char *)&kpm_name, (const char *)&kpm_args,
                           arg_len, &res);

    } else if (control_code == SUKISU_KPM_VERSION) {
        char buffer[256] = { 0 };

        sukisu_kpm_version((char *)&buffer, sizeof(buffer));

        unsigned int outlen = (unsigned int)arg2;
        int len = strlen(buffer);
        if (len >= outlen)
            len = outlen - 1;

        res = copy_to_user(arg1, &buffer, len + 1);
    }

exit:
    if (copy_to_user(result_code, &res, sizeof(res)) != 0)
        pr_info("kpm: Copy to user failed.");

    return 0;
invalid_arg:
    pr_err("kpm: invalid pointer detected! arg1: %px arg2: %px\n", (void *)arg1,
           (void *)arg2);
    res = -EFAULT;
    goto exit;
}
EXPORT_SYMBOL(sukisu_handle_kpm);

int sukisu_is_kpm_control_code(unsigned long control_code)
{
    return (control_code >= CMD_KPM_CONTROL &&
            control_code <= CMD_KPM_CONTROL_MAX) ?
               1 :
               0;
}

__visible int do_kpm(void __user *arg)
{
    struct ksu_kpm_cmd cmd;

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        pr_err("kpm: copy_from_user failed\n");
        return -EFAULT;
    }

    if (!access_ok(cmd.control_code, sizeof(int))) {
        pr_err("kpm: invalid control_code pointer %px\n",
               (void *)cmd.control_code);
        return -EFAULT;
    }

    if (!access_ok(cmd.result_code, sizeof(int))) {
        pr_err("kpm: invalid result_code pointer %px\n",
               (void *)cmd.result_code);
        return -EFAULT;
    }

    return sukisu_handle_kpm(cmd.control_code, cmd.arg1, cmd.arg2,
                             cmd.result_code);
}

struct kpm_ext_payload {
    __u64 control_code;
    __u64 arg1;
    __u64 arg2;
    __u64 result_code;
};

/* 4.3.0+ hands KPM through the unified extension ioctl instead of a
 * dedicated command number; unwrap it here and reuse the same core. */
struct kpm_ext_entry {
    __u32 id;
    const char *name;
};

/* Extensions this kernel advertises to a 4.3.0 manager. KPM is real; the
 * others are lightweight handlers so the manager can offer their pages.
 *
 * id=1 cpu_spoof and id=2 umount_paths both have real ioctls elsewhere
 * (SET_SPOOF_CPU 'K'/105, ADD_TRY_UMOUNT 'K'/18); they just need an enum
 * entry here so the Ultra 4.3.0 manager stops drawing the pages as
 * "not supported" and lets the user interact with them. */
static const struct kpm_ext_entry kpm_ext_entries[] = {
    { 0, "kpm" },
    { 1, "cpu_spoof" },
    { 2, "umount_paths" },
    { 3, "dynamic_manager" },
    { 4, "susfs" },
    { 5, "version_spoof" },
};

static const struct kpm_ext_entry *kpm_ext_find(__u32 id)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(kpm_ext_entries); i++) {
        if (kpm_ext_entries[i].id == id)
            return &kpm_ext_entries[i];
    }
    return NULL;
}

int do_extension(void __user *arg)
{
    struct ksu_extension_cmd ext;
    const struct kpm_ext_entry *ent;

    if (copy_from_user(&ext, arg, sizeof(ext)))
        return -EFAULT;

    if (ext.id == KSU_EXTENSION_ABI_PROBE_ID &&
        ext.op == KSU_EXTENSION_ABI) {
        ext.supported = 1;
        ext.api_version = KSU_EXTENSION_API_VERSION;
        ext.value = 0;
        return copy_to_user(arg, &ext, sizeof(ext)) ? -EFAULT : 0;
    }

    if (ext.id == KSU_EXTENSION_ABI_PROBE_ID &&
        ext.op == KSU_EXTENSION_ENUM) {
        struct ksu_extension_desc desc;
        __u32 index = (__u32)ext.value;

        if (!ext.user_ptr)
            return -EINVAL;
        if (index >= ARRAY_SIZE(kpm_ext_entries))
            return -ENOENT;
        memset(&desc, 0, sizeof(desc));
        desc.id = kpm_ext_entries[index].id;
        desc.caps = 1; /* KSU_FEATURE_FLAG_SUPPORTED */
        desc.min_api_version = 0;
        desc.forced = 0;
        strscpy(desc.name, kpm_ext_entries[index].name, sizeof(desc.name));
        return copy_to_user(u64_to_user_ptr(ext.user_ptr), &desc,
                            sizeof(desc)) ? -EFAULT : 0;
    }

    ent = kpm_ext_find(ext.id);
    if (!ent)
        return -EOPNOTSUPP;

    if (ext.op == KSU_EXTENSION_GET) {
        ext.supported = 1;
        ext.api_version = KSU_EXTENSION_API_VERSION;
        /* value: 0/1 "feature present+enabled" bit the manager renders.
         *   susfs(4): wired through the guard LKM.
         *   cpu_spoof(1), umount_paths(2): the kernel has their IOCTLs
         *     (SET_SPOOF_CPU, ADD_TRY_UMOUNT) and the pages should offer
         *     their controls. We report "present" and let the per-page
         *     ioctl path decide what's actually in effect.
         *   kpm(0), dynamic_manager(3), version_spoof(5): existing
         *     behaviour — 0. */
        switch (ext.id) {
        case 1:
        case 2:
        case 4:
            ext.value = 1;
            break;
        default:
            ext.value = 0;
            break;
        }
        return copy_to_user(arg, &ext, sizeof(ext)) ? -EFAULT : 0;
    }

    if (ext.op == KSU_EXTENSION_SET)
        return 0;

    if (ext.op != KSU_EXTENSION_IO || ext.id != 0)
        return -EOPNOTSUPP;

    if (!ext.user_ptr)
        return -EINVAL;

    {
        struct kpm_ext_payload p;

        if (copy_from_user(&p, u64_to_user_ptr(ext.user_ptr), sizeof(p)))
            return -EFAULT;

        /* 4.3.0 sends SUKISU_KPM_LOAD_EVENT (8) with a {args, event} pair instead of a
         * plain args string. Fold it back into the 4.2.0 core's LOAD shape. */
        if (p.control_code == 8) {
            struct {
                __u64 args;
                __u64 event;
            } ev;

            if (!p.arg2)
                return -EINVAL;
            if (copy_from_user(&ev, u64_to_user_ptr(p.arg2), sizeof(ev)))
                return -EFAULT;

            return sukisu_handle_kpm(1, (unsigned long)p.arg1,
                                     (unsigned long)ev.args,
                                     (unsigned long)p.result_code);
        }

        return sukisu_handle_kpm((unsigned long)p.control_code,
                                 (unsigned long)p.arg1,
                                 (unsigned long)p.arg2,
                                 (unsigned long)p.result_code);
    }
}