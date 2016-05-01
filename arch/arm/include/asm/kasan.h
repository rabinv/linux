#ifndef __ARM_ASM_KASM_H
#define __ARM_ASM_KASM_H

#include <asm/memory.h>

#ifdef CONFIG_KASAN
#define KASAN_SHADOW_SIZE	(SZ_512M)
#else
#define KASAN_SHADOW_SIZE	(0)
#endif

#define KASAN_SHADOW_START	VMALLOC_END
#define KASAN_SHADOW_END	(KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
#define KASAN_SHADOW_OFFSET	VMALLOC_END

#define KASAN_NUM_ZERO_PTES	(PTRS_PER_PTE * 2)

#ifndef __ASSEMBLY__

#ifdef CONFIG_KASAN
asmlinkage void kasan_early_init(void);
void kasan_init(void);
#else
static inline void kasan_init(void) { }
#endif
#endif

#endif
