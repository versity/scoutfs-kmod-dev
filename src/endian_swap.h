#ifndef _SCOUTFS_ENDIAN_SWAP_H_
#define _SCOUTFS_ENDIAN_SWAP_H_

#define le64_to_be64(x) cpu_to_be64(le64_to_cpu(x))
#define le32_to_be32(x) cpu_to_be32(le32_to_cpu(x))
#define le16_to_be16(x) cpu_to_be16(le16_to_cpu(x))

#define be64_to_le64(x) cpu_to_le64(be64_to_cpu(x))
#define be32_to_le32(x) cpu_to_le32(be32_to_cpu(x))
#define be16_to_le16(x) cpu_to_le16(be16_to_cpu(x))

#endif
