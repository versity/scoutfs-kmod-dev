#ifndef _SCOUTFS_SERVER_H_
#define _SCOUTFS_SERVER_H_

#define SI4_FMT		"%u.%u.%u.%u:%u"

#define si4_trace_define(name)		\
	__field(__u32, name##_addr)	\
	__field(__u16, name##_port)

#define si4_trace_assign(name, sin)					\
do {									\
	__typeof__(sin) _sin = (sin);					\
									\
	__entry->name##_addr = be32_to_cpu(_sin->sin_addr.s_addr);	\
	__entry->name##_port = be16_to_cpu(_sin->sin_port);		\
} while(0)

#define si4_trace_args(name)			\
	(__entry->name##_addr >> 24),		\
	(__entry->name##_addr >> 16) & 255,	\
	(__entry->name##_addr >> 0) & 255,	\
	__entry->name##_addr & 255,		\
	__entry->name##_port

#define SNH_FMT	"id %llu data_len %u type %u status %u"

#define snh_trace_define(name)		\
	__field(__u64, name##_id)	\
	__field(__u16, name##_data_len)	\
	__field(__u8, name##_type)	\
	__field(__u8, name##_status)

#define snh_trace_assign(name, nh)				\
do {								\
	__typeof__(nh) _nh = (nh);				\
								\
	__entry->name##_id = le64_to_cpu(_nh->id);		\
	__entry->name##_data_len = le16_to_cpu(_nh->data_len);	\
	__entry->name##_type = _nh->type;			\
	__entry->name##_status = _nh->status;			\
} while (0)

#define snh_trace_args(name) \
	__entry->name##_id, __entry->name##_data_len, __entry->name##_type, \
	__entry->name##_status

void scoutfs_init_ment_to_net(struct scoutfs_net_manifest_entry *net_ment,
			      struct scoutfs_manifest_entry *ment);
void scoutfs_init_ment_from_net(struct scoutfs_manifest_entry *ment,
				struct scoutfs_net_manifest_entry *net_ment);

int scoutfs_client_get_compaction(struct super_block *sb, void *curs);
int scoutfs_client_finish_compaction(struct super_block *sb, void *curs,
				     void *list);
int scoutfs_server_free_segno(struct super_block *sb, u64 segno);

int scoutfs_server_setup(struct super_block *sb);
void scoutfs_server_destroy(struct super_block *sb);

#endif
