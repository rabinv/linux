#undef TRACE_SYSTEM
#define TRACE_SYSTEM mmio

#if !defined(_TRACE_MMIO_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_MMIO_H

#include <linux/tracepoint.h>
#include <linux/trace_events.h>

TRACE_EVENT(mmio_read,
	TP_PROTO(const volatile void __iomem *addr,
		 const char *addrexp, unsigned long value,
		 unsigned char size, bool relaxed,
		 unsigned long caller),

	TP_ARGS(addr, addrexp, value, size, relaxed, caller),

	TP_STRUCT__entry(
		__field(const volatile void __iomem *, addr)
		__field(const char *, addrexp)
		__field(unsigned long, value)
		__field(unsigned char, size)
		__field(bool, relaxed)
		__field(unsigned long, caller)
	),

	TP_fast_assign(
		__entry->addr = addr;
		__entry->addrexp = addrexp;
		__entry->value = value;
		__entry->size = size;
		__entry->relaxed = relaxed;
		__entry->caller = caller;
	),

	TP_printk("%pf: 0x%p [%s] %c> 0x%0*lx",
		(void *) __entry->caller,
		__entry->addr, __entry->addrexp,
		__entry->relaxed ? '-' : '=',
		__entry->size * 2,
		__entry->value)
);

TRACE_EVENT(mmio_write,
	TP_PROTO(volatile void __iomem *addr,
		 const char *addrexp, unsigned long value,
		 const char *valueexp,
		 unsigned char size, bool relaxed,
		 unsigned long caller),

	TP_ARGS(addr, addrexp, value, valueexp, size, relaxed, caller),

	TP_STRUCT__entry(
		__field(volatile void __iomem *, addr)
		__field(const char *, addrexp)
		__field(unsigned long, value)
		__field(const char *, valueexp)
		__field(unsigned char, size)
		__field(bool, relaxed)
		__field(unsigned long, caller)
	),

	TP_fast_assign(
		__entry->caller = caller;
		__entry->addr = addr;
		__entry->addrexp = addrexp;
		__entry->value = value;
		__entry->valueexp = valueexp;
		__entry->size = size;
		__entry->relaxed = relaxed;
	),

	TP_printk("%pf: 0x%p [%s] <%c 0x%0*lx [%s]",
		(void *) __entry->caller,
		__entry->addr, __entry->addrexp,
		__entry->relaxed ? '-' : '=',
		__entry->size * 2,
		__entry->value, __entry->valueexp)
);

#endif /* _TRACE_MMIO_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
