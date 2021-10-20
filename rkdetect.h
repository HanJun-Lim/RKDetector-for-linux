#ifndef __RKDETECT_H__
#define __RKDETECT_H__

#define __NO_VERSION__

#include <linux/kernel.h>
#include <linux/kprobes.h>


// =============== Macro ===============

#define PAGE_SIZE_DEFAULT			4096



// =============== Functions ===============

// search Rootkit
void detect_rk_lkm(void);					// for LKM rootkit detection
void detect_rk_usermode(void);				// for Userspace rootkit detection

unsigned long* kprobe_find_sct(void);		// for detect_rk_lkm()
unsigned long* kprobe_find_arvm(void);		// for detect_rk_userspace()
int lkm_code_check(unsigned long* addr, int len);
int lkm_data_check(unsigned long* addr, int len);


#endif
