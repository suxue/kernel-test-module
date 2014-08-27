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
#include <linux/ctype.h>
#include <asm/uaccess.h>

static char proc_entry_name[] = "hello";
static const unsigned int perm = 0644;

struct record_head {
    struct list_head list;
    unsigned long addr;
};

struct list_head record_list;

static struct record_head *
record_find(unsigned long addr)
{
    if (list_empty(&record_list)) {
        return NULL;
    } else {
        struct list_head *p;
        struct record_head *r;
        list_for_each(p, &record_list) {
            r = list_entry(p, struct record_head, list);
            if (r->addr == addr)
                return r;
        }
        return NULL;
    }
}

static int
record_add(unsigned long addr)
{
    if (record_find(addr)) {
        return EEXIST;
    } else {
        struct record_head *new = kmalloc(sizeof(struct record_head), GFP_KERNEL);
        new->addr = addr;
        INIT_LIST_HEAD(&new->list);
        list_add(&new->list, &record_list);
        return 0;
    }
}

static int
record_remove(unsigned long addr)
{
    struct record_head *r = record_find(addr);
    if (!r) {
        return -EINVAL;
    } else {
        list_del(&r->list);
        kfree(r);
        return 0;
    }
}

static int
proc_show(struct seq_file *m, void *v)
{
    char *buf = kmalloc(KSYM_SYMBOL_LEN, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    if (!list_empty(&record_list)) {
        struct record_head *r;
        struct list_head *p = record_list.next;
        struct list_head *next;
        do {
            next = p->next;
            r = list_entry(p, struct record_head, list);
            if (!sprint_symbol_no_offset(buf, r->addr) || !buf[0]) {
                list_del(p);
                kfree(list_entry(p, struct record_head, list));
            } else {
                seq_printf(m, "%lx %s\n", r->addr, buf);
            }
            p = next;
        } while (p != &record_list);
    }

    kfree(buf);
	return 0;
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
    if (!addr)
        return -EINVAL;
    else
        return record_add(addr);
}

static int
deregister_func_by_name(const char* name)
{
    unsigned long addr = kallsyms_lookup_name(name);
    if (!addr)
        return -EINVAL;
    else
        return record_remove(addr);
}

static int
write_dispatcher(const char *name)
{
    if (isalpha(name[0])) {
        return register_func_by_name(name);
    } else if (name[0] == '-'){
        if (isalpha(name[1])) {
            return deregister_func_by_name(name+1);
        } else {
            return -EINVAL;
        }
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
        return -ENOMEM;
    }
    if (copy_from_user(b, inbuf, len)) {
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
    printk("init proc: %s\n", proc_entry_name);
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
            kfree(list_entry(p, struct record_head, list));
            p = next;
        } while (p != &record_list);
    }
    printk("cleanup proc: %s\n", proc_entry_name);
}

module_init(module_init_func);
module_exit(module_cleanup_func);

MODULE_LICENSE("GPL");
