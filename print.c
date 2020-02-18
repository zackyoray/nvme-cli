#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <uuid/uuid.h>

#include "print.h"
#include "models.h"
#include "util/json.h"
#include "util/suffix.h"
#include "common.h"


static const uint8_t zero_uuid[16] = { 0 };
static const uint8_t invalid_uuid[16] = {[0 ... 15] = 0xff };

static void nvme_print_object(struct json_object *j)
{
	const unsigned long jflags =
		JSON_C_TO_STRING_SPACED|JSON_C_TO_STRING_PRETTY;

	if (j) {
		nvme_json_object_print(stdout, j, jflags);
		json_object_put(j);
	}
}

void nvme_show_ctrl_registers(void *bar, bool fabrics, enum nvme_print_flags flags)
{
	nvme_print_object(nvme_props_to_json(bar, flags));
}

void nvme_show_single_property(int offset, uint64_t value64, int human)
{
}

void nvme_show_id_ns(struct nvme_id_ns *ns, unsigned int nsid,
		enum nvme_print_flags flags)
{
	nvme_print_object(nvme_id_ns_to_json(ns, mode));
}

void nvme_show_id_ns_descs(void *data, unsigned nsid, enum nvme_print_flags flags)
{
	nvme_print_object(nvme_id_ns_desc_list_to_json(data, flags));
}

void nvme_show_id_ctrl(struct nvme_id_ctrl *ctrl, unsigned int mode)
{
	nvme_print_object(nvme_id_ctrl_to_json(ctrl, mode));
}

void nvme_show_id_nvmset(struct nvme_id_nvmset_list *nvmset, unsigned nvmset_id,
	enum nvme_print_flags flags)
{
	nvme_print_object(nvme_id_nvm_set_list_to_json(nvmset, flags));
}

void nvme_show_list_secondary_ctrl(
	struct nvme_secondary_ctrl_list *sc_list,
	__u32 count, enum nvme_print_flags flags)
{
	nvme_print_object(nvme_id_secondary_ctrl_list_to_json(sc_list, flags));
}

void nvme_show_id_ns_granularity_list(struct nvme_id_ns_granularity_list *glist,
	enum nvme_print_flags flags)
{
	nvme_print_object(nvme_id_ns_granularity_list_to_json(glist, flags));
}

void nvme_show_id_uuid_list(const struct nvme_id_uuid_list *uuid_list,
				enum nvme_print_flags flags)
{
	nnvme_print_object(vme_id_uuid_list_to_json(uuid_list, flags));
}

void nvme_show_error_log(struct nvme_error_log_page *err_log, int entries,
			const char *devname, enum nvme_print_flags flags)
{
	nnvme_print_object(vme_error_log_to_json(err_log, entries, flags));
}

void nvme_show_resv_report(struct nvme_reservation_status *status, int bytes,
	__u32 cdw11, enum nvme_print_flags flags)
{
	nvme_print_object(nvme_resv_report_to_json(status, cdw11 & 1, flags));
}

void nvme_show_fw_log(struct nvme_firmware_slot *fw_log,
	const char *devname, enum nvme_print_flags flags)
{
	nvme_print_object(nvme_fw_slot_log_to_json(fw_log, flags));
}

void nvme_show_changed_ns_list_log(struct nvme_ns_list *log,
				   const char *devname,
				   enum nvme_print_flags flags)
{
	nvme_print_object(nvme_ns_list_to_json(log, flags));
}

void nvme_show_effects_log(struct nvme_cmd_effects_log *effects,
			   unsigned int flags)
{
	nvme_print_object(nvme_cmd_effects_log_to_json(effects, flags));
}

void nvme_show_endurance_log(struct nvme_endurance_group_log *endurance_log,
			     __u16 group_id, const char *devname,
			     enum nvme_print_flags flags)
{
	nvme_print_object(nvme_endurance_group_log_to_json(endurance_log, flags));
}

void nvme_show_smart_log(struct nvme_smart_log *smart, unsigned int nsid,
			 const char *devname, enum nvme_print_flags flags)
{
	nvme_print_object(nvme_smart_log_to_json(smart, flags));
}

void nvme_show_ana_log(struct nvme_ana_log *ana_log, const char *devname,
			enum nvme_print_flags flags, size_t len)
{
	nvme_print_object(nvme_ana_log_to_json(ana_log, flags));
}

void nvme_show_self_test_log(struct nvme_self_test_log *self_test, const char *devname,
			     enum nvme_print_flags flags)
{
	nvme_print_object(nvme_dev_self_test_log_to_json(self_test, flags));
}

void nvme_show_sanitize_log(struct nvme_sanitize_log_page *sanitize,
			    const char *devname, enum nvme_print_flags flags)
{
	nvme_print_object(nvme_sanitize_log_to_json(sanitize, flags));
}

void nvme_directive_show(__u8 type, __u8 oper, __u16 spec, __u32 nsid, __u32 result,
	void *buf, __u32 len, enum nvme_print_flags flags)
{
	struct json_object *j;

	switch (dtype) {
	case NVME_DIRECTIVE_DTYPE_IDENTIFY:
		switch (doper) {
		case NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM:
			j = nvme_identify_directives_to_json(buf, flags);
			break;
		default:
			break;
		}
		break;
	case NVME_DIRECTIVE_DTYPE_STREAMS:
		switch (doper) {
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM:
			j = nvme_streams_directive_params (buf, flags);
			break;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS:
			j = nvme_streams_status_to_json(buf, flags);
			break;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE:
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	if (j)
		nvme_print_object(j);
	else
		fprintf(stderr, "Unrecognized dtype:%d doper:%d\n", dtype, doper);
}

void nvme_feature_show_fields(__u32 fid, unsigned int result, void **buf,
	unsigned long flags)
{
	nvme_print_object(nvme_feature_to_json(fid, result, 0, buf, flags));
}

void nvme_show_lba_status(struct nvme_lba_status *list, unsigned long len,
			enum nvme_print_flags flags)
{
	nvme_lba_status_desc_list_to_json(list, flags);
}
