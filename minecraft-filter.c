#include <linux/module.h>
#include <linux/kernel.h>

int init_module(void)
{
    printk(KERN_INFO "Loading minecraft netfilter kernel module!\n");
    return 0;
}

void cleanup_module(void)
{
    printk(KERN_INFO "Cleaning up minecraft netfilter kernel module...\n");
}
