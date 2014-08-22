
/* hello world module - Eric McCreath 2005,2006,2008,2010,2012 */
/* to compile use:
    make -C  /usr/src/linux-headers-`uname -r` SUBDIRS=$PWD modules
   to install into the kernel use :
    insmod hello.ko
   to test :
    cat /proc/hello
   to remove :
    rmmod hello
*/

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

static unsigned long procfs_buffer_size = 0;
static char *buffer;

static int hello_proc_show(struct seq_file *m, void *v)
{
    if (procfs_buffer_size == 0) {
	    seq_printf(m, "hello world\n");
    } else {
    	seq_printf(m, "%s", buffer);
    }
    //printk( "print\n");
	return 0;
}

static int hello_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, hello_proc_show, NULL);
}


static ssize_t
procfs_write(struct file *file, const char *inbuf, size_t len, loff_t* off)
{
	if (len + 1 > procfs_buffer_size) {
        if (procfs_buffer_size != 0) {
            kfree(buffer);
        }
        buffer = kmalloc(len + 1, GFP_KERNEL);
        if (buffer == ZERO_SIZE_PTR) {
            printk("kmalloc return ZERO_SIZE_PTR\n");
            procfs_buffer_size = 0;
        } else {
            printk("allocate %lu bytes\n", len + 1);
            procfs_buffer_size = len + 1;
        }
	}

    if (procfs_buffer_size != 0) {
        if ( copy_from_user(buffer, inbuf, len) ) {
            return -EFAULT;
        }
        buffer[len] = 0;
	    printk(KERN_INFO "procfs_write: write %lu bytes at offset %ld\n", len, *off);
        *off += len;
    } else {
        printk("failed to allocate by kmalloc\n");
    }

	return len;
}

static const struct file_operations hello_proc_fops = {
    .write = procfs_write,
	.open		= hello_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_hello_init(void)
{
    printk("init proc hello\n");
	proc_create("hello", 0600, NULL, &hello_proc_fops);
	return 0;
}
static void __exit cleanup_hello_module(void)
{
  remove_proc_entry("hello",NULL);
  if (procfs_buffer_size) {
    kfree(buffer);
  }
  printk("cleanup proc hello\n");
}

module_init(proc_hello_init);
module_exit(cleanup_hello_module);



