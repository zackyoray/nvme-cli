#ifndef _JSON_UTIL_H
#define _JSON_UTIL_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <json-c/json.h>

#include "libnvme.h"
#include "nvme.h"

enum nvme_print_flags {
	_NVME_JSON_HUMAN,
	_NVME_JSON_HIDE_UNSUPPORTED,
	_NVME_JSON_DECODE_COMPLEX,
	_NVME_JSON_TABULAR,
	_NVME_JSON_COMPACT,
	_NVME_JSON_BINARY,
	_NVME_JSON_TREE,

	NVME_JSON_HUMAN			= 1 << _NVME_JSON_HUMAN,
	NVME_JSON_HIDE_UNSUPPORTED	= 1 << _NVME_JSON_HIDE_UNSUPPORTED,
	NVME_JSON_DECODE_COMPLEX	= 1 << _NVME_JSON_DECODE_COMPLEX,
	NVME_JSON_TABULAR		= 1 << _NVME_JSON_TABULAR,
	NVME_JSON_COMPACT		= 1 << _NVME_JSON_COMPACT,
	NVME_JSON_BINARY		= 1 << _NVME_JSON_BINARY,
	NVME_JSON_TREE			= 1 << _NVME_JSON_TREE,
};

struct json_object *nvme_identify_directives_to_json(
	struct nvme_id_directives *idd, unsigned long flags);

struct json_object *nvme_streams_status_to_json(
	struct nvme_streams_directive_status *sds, unsigned long flags);

struct json_object *nvme_streams_params_to_json(
	struct nvme_streams_directive_params *sdp, unsigned long flags);

struct json_object *nvme_streams_allocated_to_json(__u16 nsa, unsigned long flags);

struct json_object *nvme_endurance_group_log_to_json(
	struct nvme_endurance_group_log *eg, unsigned long flags);

struct json_object *nvme_telemetry_log_to_json(
	struct nvme_telemetry_log *telem, unsigned long flags);

struct json_object *nvme_dev_self_test_log_to_json(
	struct nvme_self_test_log *st, unsigned long flags);

struct json_object *nvme_cmd_effects_log_to_json(
	struct nvme_cmd_effects_log *effects, unsigned long flags);

struct json_object *nvme_fw_slot_log_to_json(
	struct nvme_firmware_slot *fw, unsigned long flags);

struct json_object *nvme_smart_log_to_json(
	struct nvme_smart_log *smart, unsigned long flags);

struct json_object *nvme_identify_to_json(void *id, __u8 cns,
	unsigned long flags);

struct json_object *nvme_feature_to_json(__u8 fid, __u32 value, unsigned len,
	void *data, unsigned long flags);

struct json_object *nvme_props_to_json(void *regs, unsigned long flags);

const char *nvme_feature_to_string(int feature);

struct json_object *nvme_ctrl_list_to_json(
	struct nvme_ctrl_list *list, unsigned long flags);

struct json_object *nvme_lba_status_desc_list_to_json(
	struct nvme_lba_status *lbas, unsigned long flags);

struct json_object *nvme_id_ns_to_json(struct nvme_id_ns *id_ns,
	unsigned long flags);

struct json_object *nvme_id_ctrl_to_json(
	struct nvme_id_ctrl *id_ctrl, unsigned long flags);

struct json_object *nvme_id_ns_desc_list_to_json(void *list,
	unsigned long flags);

struct json_object *nvme_id_ns_granularity_list_to_json(
	struct nvme_id_ns_granularity_list *glist, unsigned long flags);

struct json_object *nvme_id_nvm_set_list_to_json(
	struct nvme_id_nvmset_list *nvmset, unsigned long flags);

struct json_object *nvme_id_primary_ctrl_cap_to_json(
	struct nvme_primary_ctrl_cap *cap, unsigned long flags);

struct json_object *nvme_id_secondary_ctrl_list_to_json(
	struct nvme_secondary_ctrl_list *list, unsigned long flags);

struct json_object *nvme_id_uuid_list_to_json(
	struct nvme_id_uuid_list *list, unsigned long flags);

struct json_object *nvme_ana_log_to_json(
	struct nvme_ana_log *ana, unsigned long flags);

struct json_object *nvme_discovery_log_to_json(
	struct nvmf_discovery_log *log, unsigned long flags);

struct json_object *nvme_resv_notify_log_to_json(
	struct nvme_resv_notification_log *resv, unsigned long flags);

struct json_object *nvme_nvmset_predictable_lat_log_to_json(
	struct nvme_nvmset_predictable_lat_log *pl, unsigned long flags);

struct json_object *nvme_aggr_predictable_lat_log_to_json(
	struct nvme_aggregate_predictable_lat_event *pl, unsigned long flags);

struct json_object *nvme_sanitize_log_to_json(
	struct nvme_sanitize_log_page *san, unsigned long flags);

struct json_object *nvme_lba_status_log_to_json(
	struct nvme_lba_status_log *lbas, unsigned long flags);

struct json_object *nvme_ege_aggregate_log(
	struct nvme_eg_event_aggregate_log *eglog, unsigned long flags);

struct json_object *nvme_persistent_event_log_to_json(
	struct nvme_persistent_event_log *pel, unsigned long flags);

struct json_object *nvme_error_log_to_json(
	struct nvme_error_log_page *log, int entries, unsigned long flags);

struct json_object *nvme_ns_list_to_json(
	struct nvme_ns_list *list, unsigned long flags);

struct json_object *nvme_resv_report_to_json(
	struct nvme_reservation_status *status, bool ext,
	unsigned long flags);

struct json_object *nvme_json_new_str_len(const char *v, int len);
struct json_object *nvme_json_new_str_len_flags(const void *v, int len, unsigned long flags);
struct json_object *nvme_json_new_str(const char *v, unsigned long flags);
struct json_object *nvme_json_new_int128(uint8_t *v);
struct json_object *nvme_json_new_int64(uint64_t v);
struct json_object *nvme_json_new_int(uint32_t v);
struct json_object *nvme_json_new_bool(bool v);
struct json_object *nvme_json_new_object(unsigned long flags);
struct json_object *nvme_json_new_array();

struct json_object *nvme_json_new_storage_128(uint8_t *v, unsigned long flags);
struct json_object *nvme_json_new_storage(uint64_t v, unsigned long flags);
struct json_object *nvme_json_new_size(uint64_t v, unsigned long flags);
struct json_object *nvme_json_new_memory(uint64_t v, unsigned long flags);
struct json_object *nvme_json_new_hex_array(uint8_t *v, uint32_t len);
struct json_object *nvme_json_new_hex(uint64_t v, unsigned long flags);
struct json_object *nvme_json_new_0x(uint64_t v, unsigned long flags);
struct json_object *nvme_json_new_percent(uint8_t v, unsigned long flags);
struct json_object *nvme_json_new_temp(uint16_t v, unsigned long flags);
struct json_object *nvme_json_new_time_us(uint64_t v, unsigned long flags);
struct json_object *nvme_json_new_time_s(uint64_t v, unsigned long flags);
struct json_object *nvme_json_new_hecto_uwatts(uint64_t v, unsigned long flags);
struct json_object *nvme_json_new_uuid(uint8_t *v, unsigned long flags);
struct json_object *nvme_json_new_oui(uint8_t *v, int len, unsigned long flags);
struct json_object *nvme_json_new_bool_terse(bool v);

#define bit_set(a, b) !!(a[b / 8] & (b % 8))
#define is_set(v, f) !!(v & f)

static inline __u64 unalign_int(uint8_t *data, int len)
{
	__u32 ret = 0;
	int i;

	for (i = len - 1; i >= 0; i--)
	        ret = ret * 256 + data[i];
	return ret;
}

static inline uint64_t int48_to_long(__u8 *data)
{
	return (uint64_t)unalign_int((uint8_t *)data, 6);
}

static inline __u64 read64(void *addr)
{
	__le32 *p = addr;
	return le32_to_cpu(*p) | ((__u64)le32_to_cpu(*(p + 1)) << 32);
}

static inline __u32 read32(void *addr)
{
	__le32 *p = addr;
	return le32_to_cpu(*p);
}

static inline void nvme_json_add_str_len(struct json_object *j, const char *n,
					 const char *v, int l, unsigned long flags)
{
	json_object_object_add(j, n, nvme_json_new_str_len_flags(v, l, flags));
}

static inline void nvme_json_add_str(struct json_object *j, const char *n,
				     const char *v, unsigned long flags)
{
	json_object_object_add(j, n, nvme_json_new_str(v, flags));
}

static inline void nvme_json_add_int128(struct json_object *j, const char *n,
				       uint8_t *v)
{
	json_object_object_add(j, n, nvme_json_new_int128(v));
}

static inline void nvme_json_add_int64(struct json_object *j, const char *n,
				       uint64_t v)
{
	json_object_object_add(j, n, nvme_json_new_int64(v));
}

static inline void nvme_json_add_int(struct json_object *j, const char *n,
				     uint32_t v)
{
	json_object_object_add(j, n, nvme_json_new_int(v));
}

static inline void nvme_json_add_bool(struct json_object *j, const char *n,
				      bool v)
{
	json_object_object_add(j, n, nvme_json_new_bool(v));
}

static inline void nvme_json_add_flag(struct json_object *j, const char *n,
				      uint64_t v, int f)
{
	nvme_json_add_bool(j, n, is_set(v, f));
}

static inline void nvme_json_add_le64_ptr(struct json_object *j, const char *n,
					  void *addr)
{
	__u64 v = read64(addr);
	nvme_json_add_int64(j, n, v);
}

static inline void nvme_json_add_le32_ptr(struct json_object *j, const char *n,
					  void *addr)
{
	__u32 v = read32(addr);
	nvme_json_add_int(j, n, v);
}

static inline void nvme_json_add_storage_128(struct json_object *j, const char *n,
					 uint8_t *v, unsigned long flags)
{
	json_object_object_add(j, n, nvme_json_new_storage_128(v, flags));
}

static inline void nvme_json_add_storage(struct json_object *j, const char *n,
					 uint64_t v, unsigned long flags)
{
	json_object_object_add(j, n, nvme_json_new_storage(v, flags));
}

static inline void nvme_json_add_size(struct json_object *j, const char *n,
				      uint64_t v, unsigned long flags)
{
	json_object_object_add(j, n, nvme_json_new_size(v, flags));
}

static inline void nvme_json_add_memory(struct json_object *j, const char *n,
					uint64_t v, unsigned long flags)
{
	json_object_object_add(j, n, nvme_json_new_memory(v, flags));
}

static inline void nvme_json_add_hex_array(struct json_object *j, const char *n,
					   uint8_t *v, uint32_t l)
{
	json_object_object_add(j, n, nvme_json_new_hex_array(v, l));
}

static inline void nvme_json_add_0x(struct json_object *j, const char *n,
				       uint64_t v, unsigned long flags)
{
	json_object_object_add(j, n, nvme_json_new_0x(v, flags));
}

static inline void nvme_json_add_hex(struct json_object *j, const char *n,
				     uint64_t v, unsigned long flags)
{
	json_object_object_add(j, n, nvme_json_new_hex(v, flags));
}

static inline void nvme_json_add_percent(struct json_object *j, const char *n,
					 uint8_t v, unsigned long flags)
{
	json_object_object_add(j, n, nvme_json_new_percent(v, flags));
}

static inline void nvme_json_add_temp(struct json_object *j, const char *n,
				      uint16_t v, unsigned long flags)
{
	json_object_object_add(j, n, nvme_json_new_temp(v, flags));
}

static inline void nvme_json_add_time_us(struct json_object *j, const char *n,
					 uint64_t v, unsigned long flags)
{
	json_object_object_add(j, n, nvme_json_new_time_us(v, flags));
}

static inline void nvme_json_add_time_100us(struct json_object *j, const char *n,
					    uint64_t v)
{
	nvme_json_add_time_us(j, n, 100 * v, 0);
}

static inline void nvme_json_add_time_s(struct json_object *j, const char *n,
					uint64_t v, unsigned long flags)
{
	json_object_object_add(j, n, nvme_json_new_time_s(v, flags));
}

static inline void nvme_json_add_power(struct json_object *j, const char *n,
					 uint64_t v, unsigned long flags)
{
	json_object_object_add(j, n, nvme_json_new_hecto_uwatts(v, flags));
}

static inline void nvme_json_add_uuid(struct json_object *j, const char *n,
				      uint8_t *v, unsigned long flags)
{
	json_object_object_add(j, n, nvme_json_new_uuid(v, flags));
}

static inline void nvme_json_add_oui(struct json_object *j, const char *n,
				     uint8_t *v, int l, unsigned long flags)
{
	json_object_object_add(j, n, nvme_json_new_oui(v, l, flags));
}

static inline void nvme_json_add_le64(struct json_object *j,
				      const char *n, __le64 v)
{
	nvme_json_add_int64(j, n, le64_to_cpu(v));
}

static inline void nvme_json_add_le32(struct json_object *j,
				      const char *n, __le32 v)
{
	nvme_json_add_int(j, n, le32_to_cpu(v));
}

static inline void nvme_json_add_le16(struct json_object *j,
				      const char *n, __le16 v)
{
	nvme_json_add_int(j, n, le16_to_cpu(v));
}

static inline void nvme_json_add_hex_le64(struct json_object *j,
					  const char *n, __le32 v, unsigned long flags)
{
	nvme_json_add_hex(j, n, le64_to_cpu(v), flags);
}

static inline void nvme_json_add_hex_le32(struct json_object *j,
					  const char *n, __le32 v, unsigned long flags)
{
	nvme_json_add_hex(j, n, le32_to_cpu(v), flags);
}

static inline void nvme_json_add_hex_le16(struct json_object *j,
					  const char *n, __le16 v, unsigned long flags)
{
	nvme_json_add_hex(j, n, le16_to_cpu(v), flags);
}

static void chomp(char *s, int l)
{
	while (l && (s[l] == '\0' || s[l] == ' '))
		s[l--] = '\0';
}

static inline void nvme_json_add_str_flags(struct json_object *j, const char *n,
					  const char *v, int l, unsigned long flags)
{
        char buf[l + 1];

	if (!(flags & NVME_JSON_HUMAN)) {
		nvme_json_add_str_len(j, n, v, l, flags);
		return;
	}

        snprintf(buf, sizeof(buf), "%-.*s", l, v);
	chomp(buf, l);

	nvme_json_add_str(j, n, buf, flags);
}

static inline void nvme_json_add_storage_128_flags(struct json_object *j, const char *n,
					 uint8_t *v, unsigned long flags)
{
	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_storage_128(j, n, v, flags);
	else
		nvme_json_add_int128(j, n, v);
}

static inline void nvme_json_add_storage_flags(struct json_object *j, const char *n,
					 uint64_t v, unsigned long flags)
{
	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_storage(j, n, v, flags);
	else
		nvme_json_add_int64(j, n, v);
}

static inline void nvme_json_add_size_flags(struct json_object *j, const char *n,
					    uint64_t v, unsigned long flags)
{
	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_size(j, n, v, flags);
	else
		nvme_json_add_int64(j, n, v);
}

static inline void nvme_json_add_hex_flags(struct json_object *j, const char *n,
				     uint64_t v, unsigned long flags)
{
	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_hex(j, n, v, flags);
	else
		nvme_json_add_int64(j, n, v);
}

static inline void nvme_json_add_time_us_flags(struct json_object *j, const char *n,
					       uint64_t v, unsigned long flags)
{
	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_time_us(j, n, v, flags);
	else
		nvme_json_add_int(j, n, v);
}

static inline void nvme_json_add_time_100us_flags(struct json_object *j, const char *n,
					    uint64_t v, unsigned long flags)
{
	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_time_us(j, n, 100 * v, flags);
	else
		nvme_json_add_int(j, n, v);
}

static inline void nvme_json_add_time_m_flags(struct json_object *j, const char *n,
					uint64_t v, unsigned long flags)
{
	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_time_s(j, n, 60 * v, flags);
	else
		nvme_json_add_int(j, n, v);
}

static inline void nvme_json_add_time_s_flags(struct json_object *j, const char *n,
					uint64_t v, unsigned long flags)
{
	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_time_s(j, n, v, flags);
	else
		nvme_json_add_int(j, n, v);
}

static inline void nvme_json_add_hex_le16_flags(struct json_object *j,
						const char *n, __le16 v,
						unsigned long flags)
{
	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_hex_le16(j, n, v, flags);
	else
		nvme_json_add_le16(j, n, v);
}

static inline void nvme_json_add_hex_le32_flags(struct json_object *j,
						const char *n, __le16 v,
						unsigned long flags)
{
	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_hex_le32(j, n, v, flags);
	else
		nvme_json_add_le32(j, n, v);
}

static inline void nvme_json_add_hex_le64_flags(struct json_object *j,
						const char *n, __le16 v,
						unsigned long flags)
{
	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_hex_le64(j, n, v, flags);
	else
		nvme_json_add_le64(j, n, v);
}

static inline int nvme_ieee_to_int(__u8 ieee[])
{
	/* nvme defines the ieee byte order order this way */
	return ieee[2] << 16 | ieee[1] << 8 | ieee[0];
}

static inline void nvme_json_add_flag_flags(struct json_object *j, const char *n,
				      uint64_t v, int f, unsigned long flags)
{
	if (flags & NVME_JSON_TABULAR && flags & NVME_JSON_COMPACT)
		json_object_object_add(j, n, nvme_json_new_bool_terse(is_set(v, f)));
	else
		nvme_json_add_bool(j, n, is_set(v, f));
}

static inline void nvme_json_add_object(struct json_object *j, const char *n,
				      struct json_object *o)
{
	json_object_object_add(j, n, o);
}

static inline void nvme_json_add_not_zero(struct json_object *j, const char *n,
					   uint64_t v, unsigned long flags)
{
	if (v || !(flags & NVME_JSON_HIDE_UNSUPPORTED))
		nvme_json_add_int(j, n, v);
}

static inline void nvme_json_object_print(FILE *f, struct json_object *j,
	unsigned long jflags)
{
	if (j)
		fprintf(f, "%s", json_object_to_json_string_ext(j, jflags));
}

const char *nvme_status_to_string(int status, bool fabrics);
const char *nvme_get_feature_select_to_string(__u8 sel);
void d(unsigned char *buf, int len, int width, int group);
void d_raw(unsigned char *buf, unsigned len);

#endif /* _JSON_UTIL_H */
