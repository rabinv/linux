#define pr_fmt(fmt) "kasan: " fmt
#include <linux/kernel.h>
#include <linux/memblock.h>
#include <linux/start_kernel.h>
#include <linux/kasan.h>
#include <linux/init_task.h>

#include <asm/mmu_context.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/sections.h>
#include <asm/tlbflush.h>
#include <asm/proc-fns.h>
#include <asm/procinfo.h>
#include "mm.h"

static pgd_t tmp_pg_dir[PTRS_PER_PGD] __initdata __aligned(PTRS_PER_PGD * sizeof(pgd_t));

asmlinkage void __init kasan_early_init(void)
{
	pmdval_t pmdval = __pa(kasan_zero_pte) | _PAGE_KERNEL_TABLE;
	pteval_t pteval = __pa(kasan_zero_page) | PTE_EXT_AP0 | PTE_TYPE_SMALL | PTE_CACHEABLE | PTE_BUFFERABLE;
	unsigned long start = KASAN_SHADOW_START;
	unsigned long end = KASAN_SHADOW_END;
	unsigned long addr;
	int i;

	BUILD_BUG_ON(KASAN_SHADOW_OFFSET != KASAN_SHADOW_END - (1UL << (32 - 3)));
	BUILD_BUG_ON(!IS_ALIGNED(KASAN_SHADOW_START, PGDIR_SIZE));
	BUILD_BUG_ON(!IS_ALIGNED(KASAN_SHADOW_END, PGDIR_SIZE));

	for (addr = start; addr < end; addr += PGDIR_SIZE) {
		pmd_t *pmd = pmd_offset(pud_offset(pgd_offset_k(addr), addr), addr);

		pmd[0] = __pmd(pmdval);
		pmd[1] = __pmd(pmdval + 256 * sizeof(pte_t));
	}

	for (i = 0; i < PTRS_PER_PTE; i++)
		kasan_zero_pte[i] = __pte(pteval);
}

static void kasan_unmap_early_shadow(void)
{
	unsigned long start = KASAN_SHADOW_START;
	unsigned long end = KASAN_SHADOW_END;
	unsigned long addr;

	for (addr = start; addr < end; addr += PMD_SIZE)
		pmd_clear(pmd_off_k(addr));
}

/*
 * There are many casts needed in kasan_init(), we use these to make the code a
 * bit more readable.
 */
static void *l2p(unsigned long addr)
{
	return (void *)addr;
}

static unsigned long p2l(void *addr)
{
	return (unsigned long)addr;
}

void __init kasan_init(void)
{
	void *modvaddr_shadow = kasan_mem_to_shadow(l2p(MODULES_VADDR));
	void *modend_shadow = kasan_mem_to_shadow(l2p(MODULES_END));
	void *pageoff_shadow = kasan_mem_to_shadow(l2p(PAGE_OFFSET));
	struct memblock_region *region;
	int i;

	/*
	 * Instrumented code can't execute with a shadow memory so switch to a
	 * temporary page table while we unmap the early shadow and set up the
	 * final shadow.
	 */
	memcpy(tmp_pg_dir, swapper_pg_dir, sizeof(tmp_pg_dir));
	dsb(ishst);
	cpu_switch_mm(tmp_pg_dir, &init_mm);

	kasan_unmap_early_shadow();

	/* Userspace is not tracked so it only needs a zero shadow */
	kasan_populate_zero_shadow(l2p(KASAN_SHADOW_START), modvaddr_shadow);

	/*
	 * Any gap between the end of the modues and the start of the kernel
	 * (used by HIGHMEM) is also untracked.
	 */
	if (MODULES_END != PAGE_OFFSET)
		kasan_populate_zero_shadow(modend_shadow, pageoff_shadow);

	/* Module memory is tracked */
	vmemmap_populate_basepages(p2l(modvaddr_shadow), p2l(modend_shadow),
				   pfn_to_nid(virt_to_pfn(MODULES_VADDR)));

	for_each_memblock(memory, region) {
		void *start = l2p(__phys_to_virt(region->base));
		void *end = l2p(__phys_to_virt(region->base + region->size));
		void *shadowstart = kasan_mem_to_shadow(start);
		void *shadowend = kasan_mem_to_shadow(end);

		if (start >= end)
			break;

		/*
		 * end + 1 here is intentional. We check several shadow bytes in
		 * advance to slightly speed up fastpath. In some rare cases
		 * we could cross boundary of mapped shadow, so we just map
		 * some more here.
		 */
		vmemmap_populate_basepages(p2l(shadowstart),
					   p2l(shadowend) + 1,
					   pfn_to_nid(virt_to_pfn(start)));
	}

	/* vmalloc memory is not tracked */
	kasan_populate_zero_shadow(kasan_mem_to_shadow(l2p(VMALLOC_START)),
				   l2p(KASAN_SHADOW_END));

	for (i = 0; i < PTRS_PER_PTE; i++) {
		pte_t pte = pfn_pte(virt_to_pfn(kasan_zero_page),
				    PAGE_KERNEL_RO);

		set_pte_ext(&kasan_zero_pte[i], pte, 0);
	}

	memset(kasan_zero_page, 0x0, PAGE_SIZE);
	cpu_switch_mm(swapper_pg_dir, &init_mm);
	local_flush_tlb_all();

	init_task.kasan_depth = 0;
	pr_info("KernelAddressSanitizer initialized\n");
}
