#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/xmister.h>

#define PROC_DIR "xmister"
extern unsigned int ANDROID_BUF_NUM = 16; //Default value should be changed here
static struct proc_dir_entry *xm_dir = NULL;

void xm_init() {
	xm_dir = proc_mkdir(PROC_DIR, NULL);
}

struct proc_dir_entry* xm_add(const char* name) {
	if ( xm_dir == NULL ) xm_init();
	return create_proc_entry(name, 0644, xm_dir);
}

void xm_remove(const char* name) {
	remove_proc_entry(name,xm_dir);
}
