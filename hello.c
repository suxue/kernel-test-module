#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/spinlock_types.h>
#include <linux/ctype.h>
#include <linux/kprobes.h>
#include <asm/uaccess.h>

static char proc_entry_name[] = "hello";
static const unsigned int perm = 0644;
static DEFINE_SPINLOCK(the_lock);
static unsigned long the_lock_flags;

#define LOCK() spin_lock_irqsave(&the_lock, the_lock_flags)
#define UNLOCK() spin_unlock_irqrestore(&the_lock, the_lock_flags)

struct record_head {
    struct list_head list;
    unsigned long addr;
    unsigned int count;
    struct kprobe kprobe;
};

struct list_head record_list;

static void set_kprobe(struct kprobe *kp, unsigned long addr);

static struct record_head *
record_find(unsigned long addr)
{
    struct record_head *ret = NULL;
    LOCK();
    if (!list_empty(&record_list)) {
        struct list_head *p;
        struct record_head *r;
        list_for_each(p, &record_list) {
            r = list_entry(p, struct record_head, list);
            if (r->addr == addr) {
                ret = r;
                goto end;
            }
        }
    }
end:
    UNLOCK();
    return ret;
}

static int
record_add(unsigned long addr)
{
    int ret;
    if (record_find(addr)) {
        pr_err("%s: address %lx exists\n", proc_entry_name, addr);
        ret = EEXIST;
    } else {
        struct record_head *new = kmalloc(sizeof(struct record_head), GFP_KERNEL);
        new->addr = addr;
        new->count = 0;
        set_kprobe(&new->kprobe, addr);
        ret = register_kprobe(&new->kprobe);
        if (ret < 0) {
            pr_err("%s: [%d]failed to register_kprobe at %lx\n", proc_entry_name, ret, addr);
            kfree(new);
        } else {
            INIT_LIST_HEAD(&new->list);
            LOCK();
            list_add(&new->list, &record_list);
            UNLOCK();
            ret = 0;
        }
    }
    return ret;
}

static int
record_remove(struct record_head *r)
{
    LOCK();
    list_del(&r->list);
    UNLOCK();
    unregister_kprobe(&r->kprobe);
    kfree(r);
    return 0;
}

static int
record_remove_by_addr(unsigned long addr)
{
    struct record_head *r = record_find(addr);
    if (!r) {
        pr_err("%s: address %lx not exists\n", proc_entry_name, addr);
        return -EINVAL;
    } else {
        return record_remove(r);
    }
}

static int
proc_show(struct seq_file *m, void *v)
{
    char *buf = kmalloc(KSYM_SYMBOL_LEN, GFP_KERNEL);
    if (!buf) {
        pr_err("%s: failed to allocate memory\n", proc_entry_name);
        return -ENOMEM;
    }

    LOCK();
    if (!list_empty(&record_list)) {
        struct record_head *r;
        struct list_head *p = record_list.next;
        struct list_head *next;
        do {
            next = p->next;
            r = list_entry(p, struct record_head, list);
            if (!sprint_symbol_no_offset(buf, r->addr) || !buf[0]) {
                record_remove(r);
            } else {
                seq_printf(m, "%lx %s [%u]\n", r->addr, buf, r->count);
            }
            p = next;
        } while (p != &record_list);
    }
    UNLOCK();

    kfree(buf);
	return 0;
}

static int
handler_pre(struct kprobe *kprobe, struct pt_regs* _)
{
    struct record_head *r = record_find((unsigned long)kprobe->addr);
    if (r) {
        LOCK();
        r->count += 1;
        UNLOCK();
    }
    return 0;
}

void
set_kprobe(struct kprobe *kp, unsigned long addr)
{
    memset(kp, 0, sizeof(*kp));
    kp->pre_handler = &handler_pre;
    kp->addr = (kprobe_opcode_t*)addr;
}

static int
proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_show, NULL);
}

static int
register_func_by_name(const char *name)
{
    unsigned long addr = kallsyms_lookup_name(name);
    if (!addr) {
        pr_warning("%s: %s is not a valid kernel name\n", proc_entry_name, name);
        return -EINVAL;
    } else {
        return record_add(addr);
    }
}

static int
deregister_func_by_name(const char* name)
{
    unsigned long addr = kallsyms_lookup_name(name);
    if (!addr) {
        pr_warning("%s: %s is not a valid kernel name\n", proc_entry_name, name);
        return -EINVAL;
    } else {
        return record_remove_by_addr(addr);
    }
}

static int
write_dispatcher(const char *name)
{
    if (isalpha(name[0])) {
        return register_func_by_name(name);
    } else if (name[0] == '-'){
        if (isalpha(name[1]))
            return deregister_func_by_name(name+1);
        else
            return -EINVAL;
    } else {
        return -EINVAL;
    }
}

static ssize_t
proc_write(struct file *file, const char *inbuf, size_t len, loff_t* off)
{
    char *b = kmalloc(len+1, GFP_KERNEL);
    int r;
    if (!b) {
        pr_err("%s: failed to allocate memory\n", proc_entry_name);
        return -ENOMEM;
    }
    if (copy_from_user(b, inbuf, len)) {
        pr_err("%s: failed to copy from userland memory\n", proc_entry_name);
        r = - EFAULT;
        goto end;
    }

    if (b[len-1] == '\n')
        b[len-1] = '\0';
    else
        b[len] = '\0';

    r = write_dispatcher(b);
    if (r == 0)
        r = len;
end:
    kfree(b);
    return len;
}

static const struct file_operations proc_class = {
    .write = proc_write,
	.open = proc_open,
	.read =seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int __init
module_init_func(void)
{
    printk("%s: init proc\n", proc_entry_name);
    INIT_LIST_HEAD(&record_list);
	proc_create(proc_entry_name, perm, NULL, &proc_class);
	return 0;
}

static void __exit
module_cleanup_func(void)
{
    remove_proc_entry(proc_entry_name,NULL);
    if (!list_empty(&record_list)) {
        struct list_head *p = record_list.next;
        struct list_head *next;
        do {
            next = p->next;
            record_remove(list_entry(p, struct record_head, list));
            p = next;
        } while (p != &record_list);
    }
    printk("%s: cleanup proc\n", proc_entry_name);
}

module_init(module_init_func);
module_exit(module_cleanup_func);

MODULE_LICENSE("GPL");
