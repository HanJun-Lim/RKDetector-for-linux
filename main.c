#include "main.h"
#include "rkdetect.h"
#include "utility.h"
#include <linux/module.h>
#include <linux/kernel.h>


int init_module(void)
{
	printk(KERN_NOTICE "Janitor: loaded by insmod\n");

	// --------------- detect LKM Rootkit ---------------
	detect_rk_lkm();

	// --------------- detect User-mode Rootkit ---------------
	detect_rk_usermode();


	return 0;
}


void cleanup_module(void)
{
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Configure");
MODULE_DESCRIPTION("Linux-based Rootkit Detection Tool");
