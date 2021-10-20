#ifndef __UTILITY_H__
#define __UTILITY_H__

#define __NO_VERSION__


// =============== Functions ===============

void* memsrch(const void* s1, size_t len1, const void* s2, size_t len2);
int get_filesz_by_path(const char* pathname);

#endif
