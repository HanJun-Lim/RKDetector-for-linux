#include "rkdetect.h"
#include "utility.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/slab.h>



// sys_call_table: the symbol of System call table
unsigned long* sct;


void detect_rk_lkm(void)
{
	struct module* mod;
	struct kobject kobj;
	unsigned long addy;

	sct = kprobe_find_sct();



	// --------------- Step 1: check sys_call_table ---------------

	if(sct != 0)
	{
		/*
		 * check if sys_call_table contains any pointers to a module for a couple of often hooked functions
		 * 		warn if the syscall entry point address in range MODULES_VADDR ~ MODULES_END
		 */

		// system call to open file
		if((sct[__NR_open] > MODULES_VADDR) && (sct[__NR_open] < MODULES_END))
		{
			printk(KERN_WARNING "Janitor: [WARNING] syscall table <sys_open> entry points to a module\n");
		}

		// system call to get directory entries
		if((sct[__NR_getdents] > MODULES_VADDR) && (sct[__NR_getdents] < MODULES_END))
		{
			printk(KERN_WARNING "Janitor: [WARNING] syscall table <sys_getdents> entry points to a module\n");
		}
		if((sct[__NR_getdents64] > MODULES_VADDR) && (sct[__NR_getdents64] < MODULES_END))
		{
			printk(KERN_WARNING "Janitor: [WARNING] syscall table <sys_getdents64> entry points to a module\n");
		}

		// system call to read value of a symbolic link
		if((sct[__NR_readlink] > MODULES_VADDR) && (sct[__NR_readlink] < MODULES_END))
		{
			printk(KERN_WARNING "Janitor: [WARNING] syscall table <sys_readlink> entry points to a module\n");
		}

		// system call to write file
		if((sct[__NR_write] > MODULES_VADDR) && (sct[__NR_write] < MODULES_END))
		{
			printk(KERN_WARNING "Janitor: [WARNING] syscall table <sys_write> entry points to a module\n");
		}
	}	// sys_call_table check end


	// --------------- Step 2: check kernel module space ---------------
	//
	// 		Kernel modules inserted via insmod are placed here using dynamic mappings
	//		search page by page (default page size is 4KB)
	for(addy = MODULES_VADDR; addy < MODULES_END; addy += PAGE_SIZE_DEFAULT)
	{
		// __module_address(): get the module which contains an address; does this memory region to a module?
		if(__module_address(addy) != 0)
		{
			mod = __module_address(addy);

			printk(KERN_INFO "Janitor: [INFO] checking module %s / size: %d\n", mod->name, mod->core_layout.size);

			// --------------- 2-1: check hidden module (rootkit) ---------------

			// some modules are hidden from /proc/modules & tools like 'lsmod' using code like:
			//
			//		list_del_init(&__this_module.list);
			//
			//	list_del_init simply juggles some pointers about which we can look for
			//	* /proc manages objects with linked-list
			//
			if(mod->list.next == mod->list.prev)
			{
				// mod->list is the member of list of modules (double-linked list)
				printk(KERN_WARNING "Janitor: [WARNING] module (0x%pX - size: %d / %s) suspect list pointers\n", 
						(void*)mod->core_layout.base, mod->core_layout.size, mod->name);
			}


			// some modules are hidden (/proc & lsmod etc) with code like:
			//
			//		list_del(&THIS_MODULE->list);
			//
			//	list_del marks prev and next pointers with a (non null) 'poison' value
			//
			if((mod->list.next == LIST_POISON1) || (mod->list.prev == LIST_POISON2))
			{
				printk(KERN_WARNING "Janitor: [WARNING] module (0x%pX - size: %d / %s) has poison pointer in list\n", 
						(void*)mod->core_layout.base, mod->core_layout.size, mod->name);
			}


			// some modules are hidden from sysfs (/sys/modules/) with code like
			//		
			//		kobject_del(&THIS_MODULE->mkobj.kobj);
			//
			//	the underlying __kobject_del does a bunch of cleanup and sets a marker so lets look for the marker
			//	* /sys gets the information of module from kernel object info
			//
			kobj = mod->mkobj.kobj;

			if(kobj.state_in_sysfs == 0)		// means not in sysfs: unmounted
			{
				printk(KERN_WARNING "Janitor: [WARNING] module (0x%pX - size: %d / %s) suspect sysfs state\n", 
						(void*)mod->core_layout.base, mod->core_layout.size, mod->name);
			}


			// structure misc weirdness:
			//		Are the symbol and string tables for kallsyms removed?
			//
			//	something that a couple of rootkits do is to:
			//
			//		kfree(THIS_MODULE->sect_attrs);
			//		THIS_MODULE->sect_attrs = NULL;
			//
			//	(or possibly the same/similar with the notes_attrs);
			//
			if((mod->sect_attrs == NULL) || (mod->notes_attrs == NULL))
			{
				printk(KERN_WARNING "Janitor: [WARNING] module (0x%pX - size: %d / %s) suspect attribute state\n", 
						(void*)mod->core_layout.base, mod->core_layout.size, mod->name);
			}


			// --------------- 2-2: check the code/data signature ---------------
			if(lkm_code_check(mod->core_layout.base, mod->core_layout.text_size) != 0)
			{
					printk(KERN_WARNING "Janitor: [WARNING] module %s contains suspect instruction sequence\n", mod->name);
			}

			if(lkm_data_check((mod->core_layout.base + mod->core_layout.text_size), 
						   	  mod->core_layout.ro_size - mod->core_layout.text_size) != 0)
			{
				// except "Janitor" itself
				if(THIS_MODULE->core_layout.base != mod->core_layout.base)
				{
					printk(KERN_WARNING "Janitor: [WARNING] module %s contains suspect data sequence\n", mod->name);
				}
			}
			
			addy += mod->core_layout.size;
		}	
	}	// kernel module pool loop end
}



// __access_remote_vm: access another process's address space as given in memory map(mm)
//		allows that the kernel read from/write to virtual memory address of other(remote) process
static int (*arvm)(struct task_struct* tsk, struct mm_struct* mm, unsigned long addr,
				   void* buf			  , int len				, int write);


void detect_rk_usermode(void)
{
	int x;
	struct task_struct* ts;			// struct task_struct: process descriptor; task control block
	char tskname[TASK_COMM_LEN];	// TASK_COMM_LEN: task command(CMD) name length, 16
	struct mm_struct* mem;			// struct mm_struct: memory descriptor for a task
	void* envspace;				
	char* ldp = "LD_PRELOAD";		// LD_PRELOAD: loads the library set in LD_PRELOAD before the existing library is loaded
	

	arvm = (void*)kprobe_find_arvm();

	// --------------- 1. a check for userspace roootkits working via LD_PRELOAD in the environment ---------------
	//
	//		LD_PRELOAD used to pre-load the specific library
	if(arvm !=0)
	{
		// check all process except PID 0, 1
		//		PID 0: swapper, PID 1: init
		//		PID_MAX_DEFAULT controls the default maximum pid allocated to a process
		for(x = 2; x < PID_MAX_DEFAULT; x++)
		{
			// ts = first task structure associated with pid structure
			ts = pid_task(find_vpid(x), PIDTYPE_PID);

			if(ts != 0)
			{
				printk(KERN_INFO "Janitor: [INFO] checking process %d (%s)\n", x, tskname);


				// get task command(CMD) name into tskname
				get_task_comm(tskname, ts);

				/////////////////////////////////////////////
				// CRITICAL SECTION START: spin_lock(ts) -> block the access to task from other task
				task_lock(ts);
				/////////////////////////////////////////////


				if(ts->mm != 0)
				{
					mem = ts->mm;

					// check environment variable field size (env_start ~ env_end)
					// allocate memory for environment variable field
					//		GFP_KERNEL used usually for kernel driver
					envspace = kmalloc((mem->env_end - mem->env_start), GFP_KERNEL);


					// arvm: access_remote_vm
					//		FOLL_FORCE: get_user_pages read/write w/o permission
					//		fetch the environment/envp for the process
					arvm(ts			, mem								, mem->env_start,
						 envspace	, (mem->env_end - mem->env_start)	, FOLL_FORCE);


					// search for the LD_PRELOAD environment variable
					if(memsrch(envspace, (mem->env_end - mem->env_start), ldp, strlen(ldp)) != 0)
					{
						printk(KERN_WARNING "Janitor: [WARNING] process %d (%s) has LD_PRELOAD environment var\n", x, tskname);
					}

					kfree(envspace);
				}

				
				/////////////////////////////////////////////
				// CRITICAL SECTION END: spin_unlock(ts)
				task_unlock(ts);
				/////////////////////////////////////////////
			}
		}	// all task check loop end
	}
	else 
	{
		printk(KERN_NOTICE "Janitor: [NOTICE] __access_remote_vm not found. environment check skipped\n");
	}
	

	// --------------- 2. there may be entries in a global ld preload file ---------------
	//
	//		/etc/ld.so.preload used to specify the library which pre-load
	if(get_filesz_by_path("/etc/ld.so.preload") > 0)
	{
		printk(KERN_WARNING "Janitor: [WARNING] found /etc/ld.so.preload exists and is not empty\n");
	}
}



static struct kprobe sct_kp;			// for System call table monitoring

unsigned long* kprobe_find_sct(void)
{
	unsigned long* table_addr;

	// --------------- registers kprobe for sys_call_table ---------------
	sct_kp.symbol_name = "sys_call_table";
	register_kprobe(&sct_kp);


	// --------------- is sys_call_table found? ---------------
	table_addr = (void*)sct_kp.addr;

	if(table_addr != NULL)
	{
		printk(KERN_NOTICE "Janitor: [NOTICE] sys_call_table at 0x%pX\n", (void*)table_addr);
	}
	else
	{
		printk(KERN_NOTICE "Janitor: [NOTICE] sys_call_table not found\n");
	}

	return table_addr;
}


static struct kprobe arvm_kp;			// for another process's address space monitoring

unsigned long* kprobe_find_arvm(void)
{
	unsigned long* access_rem_vm;

	// --------------- registers kprobe for __access_remote_vm ---------------
	arvm_kp.symbol_name = "__access_remote_vm";

	if(register_kprobe(&arvm_kp) == 0)
	{
		unregister_kprobe(&arvm_kp);
	}

	access_rem_vm = (void*)arvm_kp.addr;	// access_rem_vm: location of the probe point

	if(access_rem_vm != 0)
	{
		printk(KERN_NOTICE "Janitor: [NOTICE] __access_remote_vm at 0x%pX\n", (void*)access_rem_vm);
	}
	else
	{
		printk(KERN_NOTICE "Janitor: [NOTICE] __access_remote_vm not found\n");
	}


	return access_rem_vm;
}


int lkm_code_check(unsigned long* addr, int len)
{
	int x;

	// code signature
	//
	// 0F 20 C0		mov eax, cr0		; get write permission by modifying WP bit of cr0 register
	// 0F 22 C0		mov rax, cr0		; get write permission by modifying WP bit of cr0 register (64-bit)
	char* cr0_read_opcode[] = {
		"\x0f\x20\xc0",
		"\x0f\x22\xc0"
	};


	for(x = 0; x < sizeof(cr0_read_opcode)/sizeof(char*); x++)
	{
		// check the signature in code(text) area
		if(memsrch(addr, len, cr0_read_opcode[x], sizeof(cr0_read_opcode[x])) != 0)
		{
			return -1;
		}
	}

	return 0;
}


int lkm_data_check(unsigned long* addr, int len)
{
	int x;

	// data signatures
	char* data_sig[24] = {
		// signature of reptile rootkit
		"/reptile/reptile", "KHOOK_", "is_proc_invisible",

		// signature of rootfoo rootkit
		"ROOTKIT syscall_table", "ROOTKIT sys_call_table", "un_hijack_execve",

		// signature of sutekh rootkit
		"Giving r00t", "[?] SCT:", "Example Rootkit",

		// signature of lilyofthevalley rootkit
		"givemeroot", "lilyofthevally", " u want to hide",

		// signature of diamorphine rootkit
		"diamorphine_", "m0nad", "LKM rootkit",

		// signature of honeypot bears rootkit
		"_backdoor_user", "/home/haxor", "/etc/secretshadow",

		// signature of nuk3gh0stbeta rootkit
		"hide pid command", "hide file command", "asm_hook_remove_all",

		// signature of generic rootkit in general
		"r00tkit", "r00tk1t", "module_hide"
	};


	// check the signature in data area
	for(x = 0; x < (sizeof(data_sig)/sizeof(char*)); x++)
	{
		if(memsrch(addr, len, (char*)data_sig[x], strlen((char*)data_sig[x])) != 0)
		{
			return -1;
		}
	}

	return 0;
}



MODULE_LICENSE("GPL");
