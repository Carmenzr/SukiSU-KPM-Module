#ifndef __SUKISU_KPM_COMPACT_H
#define __SUKISU_KPM_COMPACT_H

#include <linux/types.h>

extern unsigned long sukisu_compact_find_symbol(const char *name);

/*
 * Lookup for integer-valued KernelPatch environment symbols (thread_size,
 * sp_el0_is_current, ...). Returns true and writes *out_value on hit, false
 * if the name is not an integer-value symbol.
 */
extern bool sukisu_compact_find_value(const char *name, unsigned long *out_value);

#endif
