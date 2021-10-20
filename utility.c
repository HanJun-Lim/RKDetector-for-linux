#include <linux/fs.h>
#include <linux/namei.h>
#include "utility.h"


// returns location(start address) of match pattern
// 		s2 is comparison target
void* memsrch(const void* s1, size_t len1, const void* s2, size_t len2)
{
	// size of comparison target is 0 -> nothing to search
	if(!len2) 
	{
		return (void*)s1;
	}


	// linear search for the pattern
	while(len1 >= len2)
	{
		len1--;

		// pattern match found
		if(!memcmp(s1, s2, len2))
		{
			return (void*)s1;
		}

		// go to next pattern
		s1++;
	}


	// pattern not match. returns NULL
	return NULL;
}


int get_filesz_by_path(const char* pathname)
{
	struct path 	path;
	struct inode* 	inode;
	int				size = -1;


	// if the file exists..
	if(kern_path(pathname, 0, &path) == 0)
	{
		inode = path.dentry->d_inode;
		size = inode->i_size;

		mark_inode_dirty_sync(inode);		// inode is dirty, but doesn't have to be written on (it just reads)
		path_put(&path);					// decrease reference_count to unmount
	}

	return size;
}



