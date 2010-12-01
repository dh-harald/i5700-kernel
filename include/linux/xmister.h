#ifndef _XMISTER_H
#define _XMISTER_H

extern unsigned int ANDROID_BUF_NUM;
struct proc_dir_entry* xm_add(const char* name);
void xm_remove(const char* name);

#endif
