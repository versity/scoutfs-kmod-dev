#ifndef _SCOUTFS_HASH_H_
#define _SCOUTFS_HASH_H_

/*
 * We're using FNV1a for now.  It's fine.  Ish.
 *
 * The longer term plan is xxh3 but it looks like it'll take just a bit
 * more time to be declared stable and then it needs to be ported to the
 * kernel.
 *
 *  - https://fastcompression.blogspot.com/2019/03/presenting-xxh3.html
 *  - https://github.com/Cyan4973/xxHash/releases/tag/v0.7.4
 */

static inline u32 fnv1a32(const void *data, unsigned int len)
{
	u32 hash = 0x811c9dc5;

	while (len--) {
		hash ^= *(u8 *)(data++);
		hash *= 0x01000193;
	}

	return hash;
}

static inline u64 fnv1a64(const void *data, unsigned int len)
{
	u64 hash = 0xcbf29ce484222325ULL;

	while (len--) {
		hash ^= *(u8 *)(data++);
		hash *= 0x100000001b3ULL;
	}

	return hash;
}

static inline u32 scoutfs_hash32(const void *data, unsigned int len)
{
	return fnv1a32(data, len);
}

static inline u64 scoutfs_hash64(const void *data, unsigned int len)
{
	return fnv1a64(data, len);
}

#endif
