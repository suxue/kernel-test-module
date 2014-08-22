
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
#include <asm/uaccess.h>
#define BUFSIZE 256

static unsigned long procfs_buffer_size = 13;
static char buffer[BUFSIZE + 1] = "hello world!\n";

static int hello_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s", buffer);
    //printk( "print\n");
	return 0;
}

static int hello_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, hello_proc_show, NULL);
}


static ssize_t
procfs_write(struct file *file, const char *inbuf, size_t len, loff_t * off)
{
	if ( len > BUFSIZE)	{
		procfs_buffer_size = BUFSIZE;
	}
	else	{
		procfs_buffer_size = len;
	}

	if ( copy_from_user(buffer, inbuf, procfs_buffer_size) ) {
		return -EFAULT;
	}
    buffer[procfs_buffer_size] = 0;

	printk(KERN_INFO "procfs_write: write %lu bytes\n", procfs_buffer_size);
	return procfs_buffer_size;
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

  printk("cleanup proc hello\n");
}


module_init(proc_hello_init);
module_exit(cleanup_hello_module);



