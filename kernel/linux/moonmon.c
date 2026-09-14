// SPDX-License-Identifier: GPL-2.0
/*
 * moonmon — kernel-level inspection module for the Moon anti-cheat checker.
 * ---------------------------------------------------------------------------
 * Exposes /proc/moonmon. On read it walks the kernel task list
 * (for_each_process) and prints one "KPID <pid> <comm>" line per task. Because
 * this list comes straight from the scheduler, a user-mode rootkit that hides a
 * PID from /proc cannot hide it here — the Java checker (KernelBridge +
 * KernelCheck) can diff this against /proc to reveal hidden processes, and also
 * matches each comm against the cheat signatures.
 *
 * BUILD (on Linux, needs kernel headers for the running kernel):
 *   sudo apt install linux-headers-$(uname -r)   # or your distro equivalent
 *   make                                         # builds moonmon.ko
 *   sudo insmod moonmon.ko                        # load (root)
 *   cat /proc/moonmon                             # verify
 *   sudo rmmod moonmon                            # unload
 * Without the module loaded, KernelCheck uses its user-mode fallback
 * (/proc/modules, kernel taint, /etc/ld.so.preload).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/rcupdate.h>
#include <linux/version.h>

#define MOON_PROC "moonmon"

static int moon_show(struct seq_file *m, void *v)
{
    struct task_struct *task;

    seq_printf(m, "MOONMON kernel report\n");

    rcu_read_lock();
    for_each_process(task) {
        seq_printf(m, "KPID %d %s\n", task->pid, task->comm);
    }
    rcu_read_unlock();

    return 0;
}

static int moon_open(struct inode *inode, struct file *file)
{
    return single_open(file, moon_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops moon_ops = {
    .proc_open    = moon_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations moon_ops = {
    .owner   = THIS_MODULE,
    .open    = moon_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};
#endif

static int __init moon_init(void)
{
    if (!proc_create(MOON_PROC, 0440, NULL, &moon_ops))
        return -ENOMEM;
    pr_info("moonmon: loaded, /proc/%s ready\n", MOON_PROC);
    return 0;
}

static void __exit moon_exit(void)
{
    remove_proc_entry(MOON_PROC, NULL);
    pr_info("moonmon: unloaded\n");
}

module_init(moon_init);
module_exit(moon_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cs2-moon.ru / shadow");
MODULE_DESCRIPTION("Moon anti-cheat kernel-level inspection helper");
MODULE_VERSION("1.0.0");
