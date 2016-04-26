#define TRACE_MMIO_HELPERS
#include <linux/io.h>

#define CREATE_TRACE_POINTS
#include <trace/events/mmio.h>

#define DEFINE_MMIO_RW_TRACE(c, type)					\
type read ## c ## _trace(const volatile void __iomem *addr,		\
		    const char *addrexp, bool relaxed,			\
		    unsigned long caller)				\
{									\
	type value;							\
									\
	if (relaxed)							\
		value = read ## c ## _relaxed_notrace(addr);		\
	else								\
		value = read ## c ## _notrace(addr);			\
									\
	trace_mmio_read(addr, addrexp, value,				\
			sizeof(value), relaxed, caller);		\
									\
	return value;							\
}									\
									\
void write ## c ##_trace(volatile void __iomem *addr,			\
		    const char *addrexp,				\
		    type value, const char *valueexp,			\
		    bool relaxed, unsigned long caller)			\
{									\
	trace_mmio_write(addr, addrexp, value, valueexp,		\
			 sizeof(value), relaxed, caller);		\
									\
	if (relaxed)							\
		write ## c ## _relaxed_notrace(value, addr);		\
	else								\
		write ## c ## _notrace(value, addr);			\
}

DEFINE_MMIO_RW_TRACE(b, u8)
DEFINE_MMIO_RW_TRACE(w, u16)
DEFINE_MMIO_RW_TRACE(l, u32)
#ifdef CONFIG_64BIT
DEFINE_MMIO_RW_TRACE(q, u64)
#endif

