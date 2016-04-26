#ifndef _ASM_GENERIC_TRACE_MMIO_HELPERS_H
#define _ASM_GENERIC_TRACE_MMIO_HELPERS_H

#define DECLARE_MMIO_RW_TRACE(c, type)					\
static inline type							\
read ## c ## _notrace(const volatile void __iomem *addr)		\
{									\
	return read ## c(addr);						\
}									\
									\
static inline type							\
read ## c ## _relaxed_notrace(const volatile void __iomem *addr)	\
{									\
	return read ## c ## _relaxed(addr);				\
}									\
									\
static inline void							\
write ## c ## _notrace(type value, volatile void __iomem *addr)		\
{									\
	write ## c(value, addr);					\
}									\
									\
static inline void							\
write ## c ## _relaxed_notrace(type value,				\
			       volatile void __iomem *addr)		\
{									\
	write ## c ## _relaxed(value, addr);				\
}									\
									\
type read ## c ## _trace(const volatile void __iomem *addr,		\
		    const char *addrexp, bool relaxed,			\
		    unsigned long caller);				\
									\
void write ## c ##_trace(volatile void __iomem *addr,			\
		    const char *addrexp,				\
		    type value, const char *valueexp,			\
		    bool relaxed, unsigned long caller);		\

DECLARE_MMIO_RW_TRACE(b, u8)
DECLARE_MMIO_RW_TRACE(w, u16)
DECLARE_MMIO_RW_TRACE(l, u32)
#ifdef CONFIG_64BIT
DECLARE_MMIO_RW_TRACE(q, u64)
#endif

#undef readb
#undef readw
#undef readl
#undef readq

#undef readb_relaxed
#undef readw_relaxed
#undef readl_relaxed
#undef readq_relaxed

#undef writeb
#undef writew
#undef writel
#undef writeq

#undef writeb_relaxed
#undef writew_relaxed
#undef writel_relaxed
#undef writeq_relaxed

#define readb(addr) readb_trace(addr, #addr, false, _THIS_IP_)
#define readw(addr) readw_trace(addr, #addr, false, _THIS_IP_)
#define readl(addr) readl_trace(addr, #addr, false, _THIS_IP_)
#define readq(addr) readq_trace(addr, #addr, false, _THIS_IP_)

#define readb_relaxed(addr) readb_trace(addr, #addr, true, _THIS_IP_)
#define readw_relaxed(addr) readw_trace(addr, #addr, true, _THIS_IP_)
#define readl_relaxed(addr) readl_trace(addr, #addr, true, _THIS_IP_)
#define readq_relaxed(addr) readq_trace(addr, #addr, true, _THIS_IP_)

#define writeb(value, addr) \
		writeb_trace(addr, #addr, value, #value, false, _THIS_IP_)
#define writew(value, addr) \
		writew_trace(addr, #addr, value, #value, false, _THIS_IP_)
#define writel(value, addr) \
		writel_trace(addr, #addr, value, #value, false, _THIS_IP_)
#define writeq(value, addr) \
		writeq_trace(addr, #addr, value, #value, false, _THIS_IP_)

#define writeb_relaxed(value, addr) \
		writeb_trace(addr, #addr, value, #value, true, _THIS_IP_)
#define writew_relaxed(value, addr) \
		writew_trace(addr, #addr, value, #value, true, _THIS_IP_)
#define writel_relaxed(value, addr) \
		writel_trace(addr, #addr, value, #value, true, _THIS_IP_)
#define writeq_relaxed(value, addr) \
		writeq_trace(addr, #addr, value, #value, true, _THIS_IP_)

#endif
