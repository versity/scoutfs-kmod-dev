#ifndef _SCOUTFS_NAME_H_
#define _SCOUTFS_NAME_H_

u64 scoutfs_name_hash(const char *data, unsigned int len);
int scoutfs_names_equal(const char *name_a, int len_a,
			const char *name_b, int len_b);

#endif
