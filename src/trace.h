#ifndef _SCOUTFS_TRACE_H_
#define _SCOUTFS_TRACE_H_

#include <linux/compiler.h>
#include <linux/sched.h>

#define __scoutfs_trace_section __attribute__((section("__scoutfs_trace_fmt")))

extern char scoutfs_trace_first_format[];
extern char scoutfs_trace_last_format[];

/*
 * What a beautifully baffling construct!  First our arguments are added
 * to a reverse sequence of numbers.  Then all the arguments are handed
 * to a macro that only returns its 64th argument.  The presence of our
 * arguments before the sequence means that the 64th argument will be
 * the number in the reverse sequence that matches the number of our
 * initial arguments.
 *
 * h/t to:
 * https://groups.google.com/forum/#!topic/comp.std.c/d-6Mj5Lko_s
 */
#define NR_VA_ARGS(...) \
	_ONLY_64TH(__VA_ARGS__, _reverse_sequence())
#define _ONLY_64TH(...) \
	__ONLY_64TH(__VA_ARGS__)
#define __ONLY_64TH( \
	_1, _2, _3, _4, _5, _6, _7, _8, _9,_10, \
	_11,_12,_13,_14,_15,_16,_17,_18,_19,_20, \
	_21,_22,_23,_24,_25,_26,_27,_28,_29,_30, \
	_31,_32,_33,_34,_35,_36,_37,_38,_39,_40, \
	_41,_42,_43,_44,_45,_46,_47,_48,_49,_50, \
	_51,_52,_53,_54,_55,_56,_57,_58,_59,_60, \
	_61,_62,_63,N,...) N
#define _reverse_sequence() \
	63,62,61,60,                   \
	59,58,57,56,55,54,53,52,51,50, \
	49,48,47,46,45,44,43,42,41,40, \
	39,38,37,36,35,34,33,32,31,30, \
	29,28,27,26,25,24,23,22,21,20, \
	19,18,17,16,15,14,13,12,11,10, \
	9,8,7,6,5,4,3,2,1,0


/*
 * surround each arg with  (u64)( .. ),
 *
 * A 'called object not a function' error can mean there's too many args.
 *
 * XXX doesn't yet work with no args
 */
#define CAST_ARGS_U64(...) \
	EXPAND_MACRO(__VA_ARGS__,CU_16,CU_15,CU_14,CU_13,CU_12,\
		     CU_11,CU_10,CU_9,CU_8,CU_7,CU_6,CU_5,CU_4,\
		     CU_3,CU_2,CU_1)(__VA_ARGS__)
#define EXPAND_MACRO(_1,_2,_3,_4,_5,_6,_7,_8,\
		     _9,_10,_11,_12,_13,_14,_15,_16,NAME,...) NAME
#define CU_1(X) (u64)(X)
#define CU_2(X, ...) (u64)(X),CU_1(__VA_ARGS__)
#define CU_3(X, ...) (u64)(X),CU_2(__VA_ARGS__)
#define CU_4(X, ...) (u64)(X),CU_3(__VA_ARGS__)
#define CU_5(X, ...) (u64)(X),CU_4(__VA_ARGS__)
#define CU_6(X, ...) (u64)(X),CU_5(__VA_ARGS__)
#define CU_7(X, ...) (u64)(X),CU_6(__VA_ARGS__)
#define CU_8(X, ...) (u64)(X),CU_7(__VA_ARGS__)
#define CU_9(X, ...) (u64)(X),CU_8(__VA_ARGS__)
#define CU_10(X, ...) (u64)(X),CU_9(__VA_ARGS__)
#define CU_11(X, ...) (u64)(X),CU_10(__VA_ARGS__)
#define CU_12(X, ...) (u64)(X),CU_11(__VA_ARGS__)
#define CU_13(X, ...) (u64)(X),CU_12(__VA_ARGS__)
#define CU_14(X, ...) (u64)(X),CU_13(__VA_ARGS__)
#define CU_15(X, ...) (u64)(X),CU_14(__VA_ARGS__)
#define CU_16(X, ...) (u64)(X),CU_15(__VA_ARGS__)

struct super_block;
void scoutfs_trace_write(char *fmt, int nr, ...);

__attribute__((format(printf, 1, 2)))
static inline void only_check_format(const char *fmt, ...)
{
}

#define __trace_write(fmtp, args...) 				 \
	scoutfs_trace_write(fmtp, NR_VA_ARGS(args), ##args)

/*
 * Record an unstructured trace message for debugging.
 *
 * The arguments can only be scalar integers and will be cast to u64 so
 * only %llu formats can be used.
 *
 * This can only be called from task context.
 *
 * The super block is only used to indicate which mount initiated the
 * trace and it can be null for trace messages not associated with
 * mounts.
 */
#define scoutfs_trace(sb, fmt, ...) 					\
do {									\
	static char __scoutfs_trace_section __fmt[] = 			\
		"ns %llu sb %llx pid %llu cpu %llu "fmt; 		\
									\
	BUILD_BUG_ON(fmt[sizeof(fmt) - 2] == '\n');			\
									\
	/* check the caller's format before we prepend things to it */	\
	only_check_format(fmt, CAST_ARGS_U64(__VA_ARGS__));		\
									\
	__trace_write(__fmt, 						\
		      CAST_ARGS_U64(sched_clock(), (long)(sb),		\
				    current->pid, get_cpu(),		\
				    __VA_ARGS__));			\
	put_cpu();							\
} while (0)

int __init scoutfs_trace_init(void);
void __exit scoutfs_trace_exit(void);

#endif
