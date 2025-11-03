// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/kernel/panic.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * This function is used through-out the kernel (including mm and fs)
 * to indicate a major problem.
 */
#include <linux/debug_locks.h>
#include <linux/sched/debug.h>
#include <linux/interrupt.h>
#include <linux/kgdb.h>
#include <linux/kmsg_dump.h>
#include <linux/kallsyms.h>
#include <linux/notifier.h>
#include <linux/vt_kern.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/utsname.h>
#include <linux/version.h>
/* UTS namespace functions are in utsname.h */
#include <linux/ftrace.h>
#include <linux/reboot.h>
#include <linux/delay.h>
#include <linux/kexec.h>
#include <asm/io.h>
#include <linux/panic_notifier.h>
#include <linux/sched.h>
#include <linux/string_helpers.h>
#include <linux/sysrq.h>
#include <linux/init.h>
#include <linux/nmi.h>
#include <linux/console.h>
#include <linux/bug.h>
#include <linux/ratelimit.h>
#include <linux/debugfs.h>
#include <linux/sysfs.h>
#include <linux/context_tracking.h>
#include <linux/seq_buf.h>
#include <linux/sys_info.h>
#include <trace/events/error_report.h>
#include <asm/sections.h>

#define PANIC_TIMER_STEP 100
#define PANIC_BLINK_SPD 18

#ifdef CONFIG_SMP
/*
 * Should we dump all CPUs backtraces in an oops event?
 * Defaults to 0, can be changed via sysctl.
 */
static unsigned int __read_mostly sysctl_oops_all_cpu_backtrace;
#else
#define sysctl_oops_all_cpu_backtrace 0
#endif /* CONFIG_SMP */

int panic_on_oops = IS_ENABLED(CONFIG_PANIC_ON_OOPS);
static unsigned long tainted_mask =
	IS_ENABLED(CONFIG_RANDSTRUCT) ? (1 << TAINT_RANDSTRUCT) : 0;
static int pause_on_oops;
static int pause_on_oops_flag;
static DEFINE_SPINLOCK(pause_on_oops_lock);
bool crash_kexec_post_notifiers;
int panic_on_warn __read_mostly;
unsigned long panic_on_taint;
bool panic_on_taint_nousertaint = false;
static unsigned int warn_limit __read_mostly;
static bool panic_console_replay;

bool panic_triggering_all_cpu_backtrace;
static bool panic_this_cpu_backtrace_printed;

int panic_timeout = CONFIG_PANIC_TIMEOUT;
EXPORT_SYMBOL_GPL(panic_timeout);

unsigned long panic_print;

ATOMIC_NOTIFIER_HEAD(panic_notifier_list);

EXPORT_SYMBOL(panic_notifier_list);

static void panic_print_deprecated(void)
{
	pr_info_once("Kernel: The 'panic_print' parameter is now deprecated. Please use 'panic_sys_info' and 'panic_console_replay' instead.\n");
}

#ifdef CONFIG_SYSCTL

/*
 * Taint values can only be increased
 * This means we can safely use a temporary.
 */
static int proc_taint(const struct ctl_table *table, int write,
			       void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table t;
	unsigned long tmptaint = get_taint();
	int err;

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	t = *table;
	t.data = &tmptaint;
	err = proc_doulongvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;

	if (write) {
		int i;

		/*
		 * If we are relying on panic_on_taint not producing
		 * false positives due to userspace input, bail out
		 * before setting the requested taint flags.
		 */
		if (panic_on_taint_nousertaint && (tmptaint & panic_on_taint))
			return -EINVAL;

		/*
		 * Poor man's atomic or. Not worth adding a primitive
		 * to everyone's atomic.h for this
		 */
		for (i = 0; i < TAINT_FLAGS_COUNT; i++)
			if ((1UL << i) & tmptaint)
				add_taint(i, LOCKDEP_STILL_OK);
	}

	return err;
}

static int sysctl_panic_print_handler(const struct ctl_table *table, int write,
			   void *buffer, size_t *lenp, loff_t *ppos)
{
	panic_print_deprecated();
	return proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
}

static const struct ctl_table kern_panic_table[] = {
#ifdef CONFIG_SMP
	{
		.procname       = "oops_all_cpu_backtrace",
		.data           = &sysctl_oops_all_cpu_backtrace,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
#endif
	{
		.procname	= "tainted",
		.maxlen		= sizeof(long),
		.mode		= 0644,
		.proc_handler	= proc_taint,
	},
	{
		.procname	= "panic",
		.data		= &panic_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "panic_on_oops",
		.data		= &panic_on_oops,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "panic_print",
		.data		= &panic_print,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= sysctl_panic_print_handler,
	},
	{
		.procname	= "panic_on_warn",
		.data		= &panic_on_warn,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname       = "warn_limit",
		.data           = &warn_limit,
		.maxlen         = sizeof(warn_limit),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
#if (defined(CONFIG_X86_32) || defined(CONFIG_PARISC)) && \
	defined(CONFIG_DEBUG_STACKOVERFLOW)
	{
		.procname	= "panic_on_stackoverflow",
		.data		= &sysctl_panic_on_stackoverflow,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
	{
		.procname	= "panic_sys_info",
		.data		= &panic_print,
		.maxlen         = sizeof(panic_print),
		.mode		= 0644,
		.proc_handler	= sysctl_sys_info_handler,
	},
};

static __init int kernel_panic_sysctls_init(void)
{
	register_sysctl_init("kernel", kern_panic_table);
	return 0;
}
late_initcall(kernel_panic_sysctls_init);
#endif

/* The format is "panic_sys_info=tasks,mem,locks,ftrace,..." */
static int __init setup_panic_sys_info(char *buf)
{
	/* There is no risk of race in kernel boot phase */
	panic_print = sys_info_parse_param(buf);
	return 1;
}
__setup("panic_sys_info=", setup_panic_sys_info);

static atomic_t warn_count = ATOMIC_INIT(0);

#ifdef CONFIG_SYSFS
static ssize_t warn_count_show(struct kobject *kobj, struct kobj_attribute *attr,
			       char *page)
{
	return sysfs_emit(page, "%d\n", atomic_read(&warn_count));
}

static struct kobj_attribute warn_count_attr = __ATTR_RO(warn_count);

static __init int kernel_panic_sysfs_init(void)
{
	sysfs_add_file_to_group(kernel_kobj, &warn_count_attr.attr, NULL);
	return 0;
}
late_initcall(kernel_panic_sysfs_init);
#endif

static long no_blink(int state)
{
	return 0;
}

/* Returns how long it waited in ms */
long (*panic_blink)(int state);
EXPORT_SYMBOL(panic_blink);

/*
 * Stop ourself in panic -- architecture code may override this
 */
void __weak __noreturn panic_smp_self_stop(void)
{
	while (1)
		cpu_relax();
}

/*
 * Stop ourselves in NMI context if another CPU has already panicked. Arch code
 * may override this to prepare for crash dumping, e.g. save regs info.
 */
void __weak __noreturn nmi_panic_self_stop(struct pt_regs *regs)
{
	panic_smp_self_stop();
}

/*
 * Stop other CPUs in panic.  Architecture dependent code may override this
 * with more suitable version.  For example, if the architecture supports
 * crash dump, it should save registers of each stopped CPU and disable
 * per-CPU features such as virtualization extensions.
 */
void __weak crash_smp_send_stop(void)
{
	static int cpus_stopped;

	/*
	 * This function can be called twice in panic path, but obviously
	 * we execute this only once.
	 */
	if (cpus_stopped)
		return;

	/*
	 * Note smp_send_stop is the usual smp shutdown function, which
	 * unfortunately means it may not be hardened to work in a panic
	 * situation.
	 */
	smp_send_stop();
	cpus_stopped = 1;
}

atomic_t panic_cpu = ATOMIC_INIT(PANIC_CPU_INVALID);

bool panic_try_start(void)
{
	int old_cpu, this_cpu;

	/*
	 * Only one CPU is allowed to execute the crash_kexec() code as with
	 * panic().  Otherwise parallel calls of panic() and crash_kexec()
	 * may stop each other.  To exclude them, we use panic_cpu here too.
	 */
	old_cpu = PANIC_CPU_INVALID;
	this_cpu = raw_smp_processor_id();

	return atomic_try_cmpxchg(&panic_cpu, &old_cpu, this_cpu);
}
EXPORT_SYMBOL(panic_try_start);

void panic_reset(void)
{
	atomic_set(&panic_cpu, PANIC_CPU_INVALID);
}
EXPORT_SYMBOL(panic_reset);

bool panic_in_progress(void)
{
	return unlikely(atomic_read(&panic_cpu) != PANIC_CPU_INVALID);
}
EXPORT_SYMBOL(panic_in_progress);

/* Return true if a panic is in progress on the current CPU. */
bool panic_on_this_cpu(void)
{
	/*
	 * We can use raw_smp_processor_id() here because it is impossible for
	 * the task to be migrated to the panic_cpu, or away from it. If
	 * panic_cpu has already been set, and we're not currently executing on
	 * that CPU, then we never will be.
	 */
	return unlikely(atomic_read(&panic_cpu) == raw_smp_processor_id());
}
EXPORT_SYMBOL(panic_on_this_cpu);

/*
 * Return true if a panic is in progress on a remote CPU.
 *
 * On true, the local CPU should immediately release any printing resources
 * that may be needed by the panic CPU.
 */
bool panic_on_other_cpu(void)
{
	return (panic_in_progress() && !panic_on_this_cpu());
}
EXPORT_SYMBOL(panic_on_other_cpu);

/*
 * A variant of panic() called from NMI context. We return if we've already
 * panicked on this CPU. If another CPU already panicked, loop in
 * nmi_panic_self_stop() which can provide architecture dependent code such
 * as saving register state for crash dump.
 */
void nmi_panic(struct pt_regs *regs, const char *msg)
{
	if (panic_try_start())
		panic("%s", msg);
	else if (panic_on_other_cpu())
		nmi_panic_self_stop(regs);
}
EXPORT_SYMBOL(nmi_panic);

void check_panic_on_warn(const char *origin)
{
	unsigned int limit;

	if (panic_on_warn)
		panic("%s: panic_on_warn set ...\n", origin);

	limit = READ_ONCE(warn_limit);
	if (atomic_inc_return(&warn_count) >= limit && limit)
		panic("%s: system warned too often (kernel.warn_limit is %d)",
		      origin, limit);
}

static void panic_trigger_all_cpu_backtrace(void)
{
	/* Temporary allow non-panic CPUs to write their backtraces. */
	panic_triggering_all_cpu_backtrace = true;

	if (panic_this_cpu_backtrace_printed)
		trigger_allbutcpu_cpu_backtrace(raw_smp_processor_id());
	else
		trigger_all_cpu_backtrace();

	panic_triggering_all_cpu_backtrace = false;
}

/*
 * Helper that triggers the NMI backtrace (if set in panic_print)
 * and then performs the secondary CPUs shutdown - we cannot have
 * the NMI backtrace after the CPUs are off!
 */
static void panic_other_cpus_shutdown(bool crash_kexec)
{
	if (panic_print & SYS_INFO_ALL_CPU_BT)
		panic_trigger_all_cpu_backtrace();

	/*
	 * Note that smp_send_stop() is the usual SMP shutdown function,
	 * which unfortunately may not be hardened to work in a panic
	 * situation. If we want to do crash dump after notifier calls
	 * and kmsg_dump, we will need architecture dependent extra
	 * bits in addition to stopping other CPUs, hence we rely on
	 * crash_smp_send_stop() for that.
	 */
	if (!crash_kexec)
		smp_send_stop();
	else
		crash_smp_send_stop();
}

/**
 * vpanic - halt the system
 * @fmt: The text string to print
 * @args: Arguments for the format string
 *
 * Display a message, then perform cleanups. This function never returns.
 */
void vpanic(const char *fmt, va_list args)
{
	static char buf[1024];
	long i, i_next = 0, len;
	int state = 0;
	bool _crash_kexec_post_notifiers = crash_kexec_post_notifiers;
	/* No color or VGA buffer initialization */

	if (panic_on_warn) {
		panic_on_warn = 0;
	}

	local_irq_disable();
	preempt_disable_notrace();

	if (panic_try_start()) {
		/* go ahead */
	} else if (panic_on_other_cpu()) {
		panic_smp_self_stop();
	}

	/* Switch to text mode and clear screen */
	console_verbose();
	bust_spinlocks(1);

	/* Format the panic message */
	len = vscnprintf(buf, sizeof(buf), fmt, args);
	if (len && buf[len - 1] == '\n')
		buf[len - 1] = '\0';

	/* No screen clearing or header printing with colors */

	/* Print the error message */
	pr_emerg("\n\n  ");
	pr_emerg("%s\n\n", buf);

	/* Print system information in a box */
	pr_emerg("  +-----------------------------------------+\n");
	pr_emerg("  | System Information:                     |\n");
	pr_emerg("  +-----------------------------------------+\n");
	
	struct new_utsname *uts = utsname();
	char kernel_buf[64];
	snprintf(kernel_buf, sizeof(kernel_buf), "%s %s %s",
		 uts->sysname, uts->release, uts->machine);
	pr_emerg("  | Kernel:  %-30s |\n", kernel_buf);
	pr_emerg("  | Host:    %-30s |\n", uts->nodename);

	/* Show taint information if applicable */
	if (test_taint(TAINT_PROPRIETARY_MODULE) || test_taint(TAINT_FORCED_MODULE) ||
	    test_taint(TAINT_CPU_OUT_OF_SPEC) || test_taint(TAINT_FORCED_RMMOD) ||
	    test_taint(TAINT_MACHINE_CHECK) || test_taint(TAINT_BAD_PAGE) ||
	    test_taint(TAINT_USER) || test_taint(TAINT_DIE) ||
	    test_taint(TAINT_OVERRIDDEN_ACPI_TABLE) || test_taint(TAINT_WARN) ||
	    test_taint(TAINT_CRAP) || test_taint(TAINT_FIRMWARE_WORKAROUND) ||
	    test_taint(TAINT_OOT_MODULE) || test_taint(TAINT_UNSIGNED_MODULE) ||
	    test_taint(TAINT_SOFTLOCKUP) || test_taint(TAINT_LIVEPATCH) ||
	    test_taint(TAINT_AUX) || test_taint(TAINT_RANDSTRUCT) ||
	    test_taint(TAINT_TEST) || test_taint(TAINT_FWCTL)) {
		pr_emerg("System state: ");
		print_tainted();
		pr_cont("\n");
	}

	pr_emerg("\nCPU: %d, Process: %s (PID: %d)\n",
		smp_processor_id(), current->comm, current->pid);

	pr_emerg("\nTechnical details follow:\n");
	pr_emerg("----------------------\n");
	/*
	 * Avoid nested stack-dumping if a panic occurs during oops processing
	 */
	if (test_taint(TAINT_DIE) || oops_in_progress > 1) {
		panic_this_cpu_backtrace_printed = true;
	} else if (IS_ENABLED(CONFIG_DEBUG_BUGVERBOSE)) {
		dump_stack();
		panic_this_cpu_backtrace_printed = true;
	}

	/*
	 * If kgdb is enabled, give it a chance to run before we stop all
	 * the other CPUs or else we won't be able to debug processes left
	 * running on them.
	 */
	kgdb_panic(buf);

	/*
	 * If we have crashed and we have a crash kernel loaded let it handle
	 * everything else.
	 * If we want to run this after calling panic_notifiers, pass
	 * the "crash_kexec_post_notifiers" option to the kernel.
	 *
	 * Bypass the panic_cpu check and call __crash_kexec directly.
	 */
	if (!_crash_kexec_post_notifiers)
		__crash_kexec(NULL);

	panic_other_cpus_shutdown(_crash_kexec_post_notifiers);

	printk_legacy_allow_panic_sync();

	/*
	 * Run any panic handlers, including those that might need to
	 * add information to the kmsg dump output.
	 */
	atomic_notifier_call_chain(&panic_notifier_list, 0, buf);

	sys_info(panic_print);

	kmsg_dump_desc(KMSG_DUMP_PANIC, buf);

	/* Run panic notifiers */
	pr_emerg("\nSystem state:\n");
	pr_emerg("------------\n");

	/* Run panic notifiers to collect additional information */
	atomic_notifier_call_chain(&panic_notifier_list, 0, buf);

	/* Dump kernel log if configured */
	kmsg_dump_desc(KMSG_DUMP_PANIC, buf);

	/* Attempt kdump if configured */
	if (_crash_kexec_post_notifiers)
		__crash_kexec(NULL);

	/* Ensure console is in a good state */
	console_unblank();

	/* Flush any pending console output */
	debug_locks_off();
	console_flush_on_panic(CONSOLE_FLUSH_PENDING);

	if ((panic_print & SYS_INFO_PANIC_CONSOLE_REPLAY) || panic_console_replay)
		console_flush_on_panic(CONSOLE_REPLAY_ALL);

	/* Set up panic blink function if not already set */
	if (!panic_blink)
		panic_blink = no_blink;

	/* Show user what's happening */
	pr_emerg("\nSystem is halting...\n\n");

	if (panic_timeout > 0) {
		pr_emerg("System will attempt to reboot in %d seconds...\n\n", panic_timeout);
		pr_emerg("What to do next:\n");
		pr_emerg("1. If this is the first time you've seen this error, try rebooting\n");
		pr_emerg("2. If the problem persists, note down the error message above\n");
		pr_emerg("3. Check system logs for more information\n");
		pr_emerg("4. If the system doesn't recover, consider booting with 'single' or 'emergency'\n\n");

		for (i = 0; i < panic_timeout * 1000; i += PANIC_TIMER_STEP) {
			touch_nmi_watchdog();
			if (i >= i_next) {
				i += panic_blink(state ^= 1);
				i_next = i + 3600 / PANIC_BLINK_SPD;
				
				// Update countdown message
				if (i % 1000 == 0) {
					pr_emerg("\rRebooting in %2ld seconds...", 
						(panic_timeout * 1000L - i) / 1000L);
				}
			}
			mdelay(PANIC_TIMER_STEP);
		}
	}
	if (panic_timeout != 0) {
		/*
		 * This will not be a clean reboot, with everything
		 * shutting down.  But if there is a chance of
		 * rebooting the system it will be rebooted.
		 */
		if (panic_reboot_mode != REBOOT_UNDEFINED)
			reboot_mode = panic_reboot_mode;
		emergency_restart();
	}
#ifdef __sparc__
	{
		extern int stop_a_enabled;
		/* Make sure the user can actually press Stop-A (L1-A) */
		stop_a_enabled = 1;
		pr_emerg("Press Stop-A (L1-A) from sun keyboard or send break\n"
			 "twice on console to return to the boot prom\n");
	}
#endif
#if defined(CONFIG_S390)
	disabled_wait();
#endif

	// Print error message in white on black
	pr_emerg("\n\n  System has encountered a critical error and needs to stop.\n\n");

	// Print the actual error message with context
	pr_emerg("  Error: %s\n\n", buf);

	// Print system information in a box
	pr_emerg("  +-----------------------------------------+\n");
	pr_emerg("  | System Information:                     |\n");
	pr_emerg("  +-----------------------------------------+\n");
	pr_emerg("  | Kernel: %-31s |\n", utsname()->release);
	pr_emerg("  | Hostname: %-28s |\n", utsname()->nodename);
	pr_emerg("  | Machine: %-28s |\n", utsname()->machine);
	pr_emerg("  +-----------------------------------------+\n\n");

	// Print guidance for the user
	pr_emerg("  What to do next:\n");
	if (panic_timeout > 0) {
		pr_emerg("  1. The system will automatically reboot in %d seconds.\n", 
			panic_timeout);
	} else if (panic_timeout == 0) {
		pr_emerg("  1. The system will halt and require manual power cycle.\n");
	} else {
		pr_emerg("  1. The system is waiting for manual intervention.\n");
	}
	pr_emerg("  2. Note down the error message above.\n");
	pr_emerg("  3. If this is the first time you've seen this message, try rebooting.\n");
	pr_emerg("  4. If the problem persists, contact your system administrator.\n");
	pr_emerg("  5. Provide the complete error message when requesting support.\n\n");

	// Print the original message for compatibility in a less prominent way
	pr_emerg("  ---[ Technical details: %s ]---\n", buf);

	/* Do not scroll important messages printed above */
	suppress_printk = 1;

	/*
	 * The final messages may not have been printed if in a context that
	 * defers printing (such as NMI) and irq_work is not available.
	 * Explicitly flush the kernel log buffer one last time.
	 */
	console_flush_on_panic(CONSOLE_FLUSH_PENDING);
	nbcon_atomic_flush_unsafe();

	local_irq_enable();
	for (i = 0; ; i += PANIC_TIMER_STEP) {
		touch_softlockup_watchdog();
		if (i >= i_next) {
			i += panic_blink(state ^= 1);
			i_next = i + 3600 / PANIC_BLINK_SPD;
		}
		mdelay(PANIC_TIMER_STEP);
	}
}
EXPORT_SYMBOL(vpanic);

/* Identical to vpanic(), except it takes variadic arguments instead of va_list */
void panic(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vpanic(fmt, args);
	va_end(args);
}
EXPORT_SYMBOL(panic);

#define TAINT_FLAG(taint, _c_true, _c_false, _module)			\
	[ TAINT_##taint ] = {						\
		.c_true = _c_true, .c_false = _c_false,			\
		.module = _module,					\
		.desc = #taint,						\
	}

/*
 * TAINT_FORCED_RMMOD could be a per-module flag but the module
 * is being removed anyway.
 */
const struct taint_flag taint_flags[TAINT_FLAGS_COUNT] = {
	TAINT_FLAG(PROPRIETARY_MODULE,		'P', 'G', true),
	TAINT_FLAG(FORCED_MODULE,		'F', ' ', true),
	TAINT_FLAG(CPU_OUT_OF_SPEC,		'S', ' ', false),
	TAINT_FLAG(FORCED_RMMOD,		'R', ' ', false),
	TAINT_FLAG(MACHINE_CHECK,		'M', ' ', false),
	TAINT_FLAG(BAD_PAGE,			'B', ' ', false),
	TAINT_FLAG(USER,			'U', ' ', false),
	TAINT_FLAG(DIE,				'D', ' ', false),
	TAINT_FLAG(OVERRIDDEN_ACPI_TABLE,	'A', ' ', false),
	TAINT_FLAG(WARN,			'W', ' ', false),
	TAINT_FLAG(CRAP,			'C', ' ', true),
	TAINT_FLAG(FIRMWARE_WORKAROUND,		'I', ' ', false),
	TAINT_FLAG(OOT_MODULE,			'O', ' ', true),
	TAINT_FLAG(UNSIGNED_MODULE,		'E', ' ', true),
	TAINT_FLAG(SOFTLOCKUP,			'L', ' ', false),
	TAINT_FLAG(LIVEPATCH,			'K', ' ', true),
	TAINT_FLAG(AUX,				'X', ' ', true),
	TAINT_FLAG(RANDSTRUCT,			'T', ' ', true),
	TAINT_FLAG(TEST,			'N', ' ', true),
	TAINT_FLAG(FWCTL,			'J', ' ', true),
};

#undef TAINT_FLAG

static void print_tainted_seq(struct seq_buf *s, bool verbose)
{
	const char *sep = "";
	int i;

	if (!tainted_mask) {
		seq_buf_puts(s, "Not tainted");
		return;
	}

	seq_buf_printf(s, "Tainted: ");
	for (i = 0; i < TAINT_FLAGS_COUNT; i++) {
		const struct taint_flag *t = &taint_flags[i];
		bool is_set = test_bit(i, &tainted_mask);
		char c = is_set ? t->c_true : t->c_false;

		if (verbose) {
			if (is_set) {
				seq_buf_printf(s, "%s[%c]=%s", sep, c, t->desc);
				sep = ", ";
			}
		} else {
			seq_buf_putc(s, c);
		}
	}
}

static const char *_print_tainted(bool verbose)
{
	/* FIXME: what should the size be? */
	static char buf[sizeof(taint_flags)];
	struct seq_buf s;

	BUILD_BUG_ON(ARRAY_SIZE(taint_flags) != TAINT_FLAGS_COUNT);

	seq_buf_init(&s, buf, sizeof(buf));

	print_tainted_seq(&s, verbose);

	return seq_buf_str(&s);
}

/**
 * print_tainted - return a string to represent the kernel taint state.
 *
 * For individual taint flag meanings, see Documentation/admin-guide/sysctl/kernel.rst
 *
 * The string is overwritten by the next call to print_tainted(),
 * but is always NULL terminated.
 */
const char *print_tainted(void)
{
	return _print_tainted(false);
}

/**
 * print_tainted_verbose - A more verbose version of print_tainted()
 */
const char *print_tainted_verbose(void)
{
	return _print_tainted(true);
}

int test_taint(unsigned flag)
{
	return test_bit(flag, &tainted_mask);
}
EXPORT_SYMBOL(test_taint);

unsigned long get_taint(void)
{
	return tainted_mask;
}

/**
 * add_taint: add a taint flag if not already set.
 * @flag: one of the TAINT_* constants.
 * @lockdep_ok: whether lock debugging is still OK.
 *
 * If something bad has gone wrong, you'll want @lockdebug_ok = false, but for
 * some notewortht-but-not-corrupting cases, it can be set to true.
 */
void add_taint(unsigned flag, enum lockdep_ok lockdep_ok)
{
	if (lockdep_ok == LOCKDEP_NOW_UNRELIABLE && __debug_locks_off())
		pr_warn("Disabling lock debugging due to kernel taint\n");

	set_bit(flag, &tainted_mask);

	if (tainted_mask & panic_on_taint) {
		panic_on_taint = 0;
		panic("panic_on_taint set ...");
	}
}
EXPORT_SYMBOL(add_taint);

static void spin_msec(int msecs)
{
	int i;

	for (i = 0; i < msecs; i++) {
		touch_nmi_watchdog();
		mdelay(1);
	}
}

/*
 * It just happens that oops_enter() and oops_exit() are identically
 * implemented...
 */
static void do_oops_enter_exit(void)
{
	unsigned long flags;
	static int spin_counter;

	if (!pause_on_oops)
		return;

	spin_lock_irqsave(&pause_on_oops_lock, flags);
	if (pause_on_oops_flag == 0) {
		/* This CPU may now print the oops message */
		pause_on_oops_flag = 1;
	} else {
		/* We need to stall this CPU */
		if (!spin_counter) {
			/* This CPU gets to do the counting */
			spin_counter = pause_on_oops;
			do {
				spin_unlock(&pause_on_oops_lock);
				spin_msec(MSEC_PER_SEC);
				spin_lock(&pause_on_oops_lock);
			} while (--spin_counter);
			pause_on_oops_flag = 0;
		} else {
			/* This CPU waits for a different one */
			while (spin_counter) {
				spin_unlock(&pause_on_oops_lock);
				spin_msec(1);
				spin_lock(&pause_on_oops_lock);
			}
		}
	}
	spin_unlock_irqrestore(&pause_on_oops_lock, flags);
}

/*
 * Return true if the calling CPU is allowed to print oops-related info.
 * This is a bit racy..
 */
bool oops_may_print(void)
{
	return pause_on_oops_flag == 0;
}

/*
 * Called when the architecture enters its oops handler, before it prints
 * anything.  If this is the first CPU to oops, and it's oopsing the first
 * time then let it proceed.
 *
 * This is all enabled by the pause_on_oops kernel boot option.  We do all
 * this to ensure that oopses don't scroll off the screen.  It has the
 * side-effect of preventing later-oopsing CPUs from mucking up the display,
 * too.
 *
 * It turns out that the CPU which is allowed to print ends up pausing for
 * the right duration, whereas all the other CPUs pause for twice as long:
 * once in oops_enter(), once in oops_exit().
 */
void oops_enter(void)
{
	nbcon_cpu_emergency_enter();
	tracing_off();
	/* can't trust the integrity of the kernel anymore: */
	debug_locks_off();
	do_oops_enter_exit();

	if (sysctl_oops_all_cpu_backtrace)
		trigger_all_cpu_backtrace();
}

static void print_oops_end_marker(void)
{
	pr_warn("---[ end trace %016llx ]---\n", 0ULL);
}

/*
 * Called when the architecture exits its oops handler, after printing
 * everything.
 */
void oops_exit(void)
{
	do_oops_enter_exit();
	print_oops_end_marker();
	nbcon_cpu_emergency_exit();
	kmsg_dump(KMSG_DUMP_OOPS);
}

struct warn_args {
	const char *fmt;
	va_list args;
};

void __warn(const char *file, int line, void *caller, unsigned taint,
	    struct pt_regs *regs, struct warn_args *args)
{
	nbcon_cpu_emergency_enter();
	disable_trace_on_warning();

	// Print warning header
	pr_emerg("\n\n=== KERNEL WARNING DETECTED ===\n\n");

	// Print warning message with some spacing
	pr_emerg("\n\n  System has detected a potential issue. Please review the details below.\n\n");

	// Print warning message
	if (args) {
		char buf[256];
		va_list args_copy;

		va_copy(args_copy, args->args);
		vsnprintf(buf, sizeof(buf), args->fmt, args_copy);
		va_end(args_copy);

		pr_emerg("%s\n\n", buf);
	} else {
		pr_emerg("Unknown warning\n\n");
	}

	// Print system information in a box
	pr_emerg("  +-----------------------------------------+\n");
	pr_emerg("  | Warning Details:                         |\n");
	pr_emerg("  +-----------------------------------------+\n");

	// Print location information
	if (file) {
		pr_emerg("  | Location: %-29s |\n", file);
		pr_emerg("  | Line:    %-29d |\n", line);
	}

	if (caller) {
		char caller_buf[32];
		snprintf(caller_buf, sizeof(caller_buf), "%pS", caller);
		pr_emerg("  | Caller:  %-29s |\n", caller_buf);
	}

	// Print process information
	char pid_buf[32];
	snprintf(pid_buf, sizeof(pid_buf), "%s (PID: %d)", current->comm, current->pid);
	pr_emerg("  | Process: %-29s |\n", pid_buf);

	// Print CPU information
	pr_emerg("  | CPU:     %-29d |\n", raw_smp_processor_id());

	// Print taint information if applicable
	if (taint) {
		char taint_buf[64];
		snprintf(taint_buf, sizeof(taint_buf), "System state: %s", print_tainted());
		pr_emerg("  | %-39s |\n", taint_buf);
	}

	// Print timestamp
	char time_buf[64];
	snprintf(time_buf, sizeof(time_buf), "Time: %lld", ktime_get_real_seconds());
	pr_emerg("  | %-39s |\n", time_buf);

	pr_emerg("  +-----------------------------------------+\n\n");
	pr_emerg("  Technical details follow:\n");
	pr_emerg("  ---------------------------------------\n");

	// Print modules information
	print_modules();

	// Show register state if available
	if (regs) {
		show_regs(regs);
	} else {
		// If no register state, show stack trace
		dump_stack();
	}

	// Check if we should panic based on warning
	check_panic_on_warn("kernel");

	// Print IRQ trace events
	print_irqtrace_events(current);

	// Print end marker and complete error reporting
	print_oops_end_marker();
	trace_error_report_end(ERROR_DETECTOR_WARN, (unsigned long)caller);

	// Add taint mark to the kernel
	add_taint(taint, LOCKDEP_STILL_OK);

	// Print recovery information in a box
	pr_emerg("\n  +-----------------------------------------+\n");
	pr_emerg("  | What to do next:                       |\n");
	pr_emerg("  +-----------------------------------------+\n");
	pr_emerg("  | 1. This is a non-fatal warning. The     |\n");
	pr_emerg("  |    system can continue running.         |\n");
	pr_emerg("  | 2. If this warning persists, consider   |\n");
	pr_emerg("  |    reporting it to your system admin.   |\n");
	pr_emerg("  | 3. Include this complete message when   |\n");
	pr_emerg("  |    reporting the issue.                 |\n");
	pr_emerg("  +-----------------------------------------+\n\n");
	pr_emerg("  The system will continue...\n\n");

	nbcon_cpu_emergency_exit();
}

#ifdef CONFIG_BUG
#ifndef __WARN_FLAGS
void warn_slowpath_fmt(const char *file, int line, unsigned taint,
		       const char *fmt, ...)
{
	bool rcu = warn_rcu_enter();
	struct warn_args args;

	pr_warn(CUT_HERE);

	if (!fmt) {
		__warn(file, line, __builtin_return_address(0), taint,
		       NULL, NULL);
		warn_rcu_exit(rcu);
		return;
	}

	args.fmt = fmt;
	va_start(args.args, fmt);
	__warn(file, line, __builtin_return_address(0), taint, NULL, &args);
	va_end(args.args);
	warn_rcu_exit(rcu);
}
EXPORT_SYMBOL(warn_slowpath_fmt);
#else
void __warn_printk(const char *fmt, ...)
{
	bool rcu = warn_rcu_enter();
	va_list args;

	pr_warn(CUT_HERE);

	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);
	warn_rcu_exit(rcu);
}
EXPORT_SYMBOL(__warn_printk);
#endif

/* Support resetting WARN*_ONCE state */

static int clear_warn_once_set(void *data, u64 val)
{
	generic_bug_clear_once();
	memset(__start_once, 0, __end_once - __start_once);
	return 0;
}

DEFINE_DEBUGFS_ATTRIBUTE(clear_warn_once_fops, NULL, clear_warn_once_set,
			 "%lld\n");

static __init int register_warn_debugfs(void)
{
	/* Don't care about failure */
	debugfs_create_file_unsafe("clear_warn_once", 0200, NULL, NULL,
				   &clear_warn_once_fops);
	return 0;
}

device_initcall(register_warn_debugfs);
#endif

#ifdef CONFIG_STACKPROTECTOR

/*
 * Called when gcc's -fstack-protector feature is used, and
 * gcc detects corruption of the on-stack canary value
 */
__visible noinstr void __stack_chk_fail(void)
{
	unsigned long flags;

	instrumentation_begin();
	flags = user_access_save();

	panic("stack-protector: Kernel stack is corrupted in: %pB",
		__builtin_return_address(0));

	user_access_restore(flags);
	instrumentation_end();
}
EXPORT_SYMBOL(__stack_chk_fail);

#endif

core_param(panic, panic_timeout, int, 0644);
core_param(pause_on_oops, pause_on_oops, int, 0644);
core_param(panic_on_warn, panic_on_warn, int, 0644);
core_param(crash_kexec_post_notifiers, crash_kexec_post_notifiers, bool, 0644);
core_param(panic_console_replay, panic_console_replay, bool, 0644);

static int panic_print_set(const char *val, const struct kernel_param *kp)
{
	panic_print_deprecated();
	return  param_set_ulong(val, kp);
}

static int panic_print_get(char *val, const struct kernel_param *kp)
{
	panic_print_deprecated();
	return  param_get_ulong(val, kp);
}

static const struct kernel_param_ops panic_print_ops = {
	.set	= panic_print_set,
	.get	= panic_print_get,
};
__core_param_cb(panic_print, &panic_print_ops, &panic_print, 0644);

static int __init oops_setup(char *s)
{
	if (!s)
		return -EINVAL;
	if (!strcmp(s, "panic"))
		panic_on_oops = 1;
	return 0;
}
early_param("oops", oops_setup);

static int __init panic_on_taint_setup(char *s)
{
	char *taint_str;

	if (!s)
		return -EINVAL;

	taint_str = strsep(&s, ",");
	if (kstrtoul(taint_str, 16, &panic_on_taint))
		return -EINVAL;

	/* make sure panic_on_taint doesn't hold out-of-range TAINT flags */
	panic_on_taint &= TAINT_FLAGS_MAX;

	if (!panic_on_taint)
		return -EINVAL;

	if (s && !strcmp(s, "nousertaint"))
		panic_on_taint_nousertaint = true;

	pr_info("panic_on_taint: bitmask=0x%lx nousertaint_mode=%s\n",
		panic_on_taint, str_enabled_disabled(panic_on_taint_nousertaint));

	return 0;
}
early_param("panic_on_taint", panic_on_taint_setup);
