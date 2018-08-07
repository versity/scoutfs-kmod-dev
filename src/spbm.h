#ifndef _SCOUTFS_SPBM_H_
#define _SCOUTFS_SPBM_H_

struct scoutfs_spbm {
	struct rb_root root;
};

void scoutfs_spbm_init(struct scoutfs_spbm *spbm);
void scoutfs_spbm_destroy(struct scoutfs_spbm *spbm);

int scoutfs_spbm_set(struct scoutfs_spbm *spbm, u64 bit);
int scoutfs_spbm_test(struct scoutfs_spbm *spbm, u64 bit);
void scoutfs_spbm_clear(struct scoutfs_spbm *spbm, u64 bit);

#endif
