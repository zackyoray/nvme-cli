#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "nvme.h"
#include "plugin.h"

#include "argconfig.h"
#include "suffix.h"

#define CREATE_CMD
#include "memblaze-nvme.h"

enum {
	TOTAL_WRITE,
	TOTAL_READ,
	THERMAL_THROTTLE,
	TEMPT_SINCE_RESET,
	POWER_CONSUMPTION,
	TEMPT_SINCE_BOOTUP,
	POWER_LOSS_PROTECTION,
	WEARLEVELING_COUNT,
	HOST_WRITE,
	THERMAL_THROTTLE_CNT,
	CORRECT_PCIE_PORT0,
	CORRECT_PCIE_PORT1,
	REBUILD_FAIL,
	ERASE_FAIL,
	PROGRAM_FAIL,
	READ_FAIL,
	NR_SMART_ITEMS,
};

enum {
	MB_FEAT_POWER_MGMT = 0xc6,
};

#pragma pack(push, 1)
struct nvme_memblaze_smart_log_item {
	__u8 id[3];
	union {
		__u8	__nmval[2];
		__le16  nmval;
	};
	union {
		__u8 rawval[6];
		struct temperature {
			__le16 max;
			__le16 min;
			__le16 curr;
		} temperature;
		struct power {
			__le16 max;
			__le16 min;
			__le16 curr;
		} power;
		struct thermal_throttle_mb {
			__u8 on;
			__u32 count;
		} thermal_throttle;
		struct temperature_p {
			__le16 max;
			__le16 min;
		} temperature_p;
		struct power_loss_protection {
			__u8 curr;
		} power_loss_protection;
		struct wearleveling_count {
			__le16 min;
			__le16 max;
			__le16 avg;
		} wearleveling_count;
		struct thermal_throttle_cnt {
			__u8 active;
			__le32 cnt;
		} thermal_throttle_cnt;
	};
	__u8 resv;
};
#pragma pack(pop)

struct nvme_memblaze_smart_log {
	struct nvme_memblaze_smart_log_item items[NR_SMART_ITEMS];
	__u8 resv[512 - sizeof(struct nvme_memblaze_smart_log_item) * NR_SMART_ITEMS];
};

/*
 * Return -1 if @fw1 < @fw2
 * Return 0 if @fw1 == @fw2
 * Return 1 if @fw1 > @fw2
 */
static int compare_fw_version(const char *fw1, const char *fw2)
{
	while (*fw1 != '\0') {
		if (*fw2 == '\0' || *fw1 > *fw2)
			return 1;
		if (*fw1 < *fw2)
			return -1;
		fw1++;
		fw2++;
	}

	if (*fw2 != '\0')
		return -1;

	return 0;
}

static __u32 item_id_2_u32(struct nvme_memblaze_smart_log_item *item)
{
	__le32	__id = 0;
	memcpy(&__id, item->id, 3);
	return le32_to_cpu(__id);
}

static __u64 raw_2_u64(const __u8 *buf, size_t len)
{
	__le64	val = 0;
	memcpy(&val, buf, len);
	return le64_to_cpu(val);
}

static int show_memblaze_smart_log(int fd, __u32 nsid, const char *devname,
		struct nvme_memblaze_smart_log *smart)
{
	struct nvme_id_ctrl ctrl;
	char fw_ver[10];
	int err = 0;
	struct nvme_memblaze_smart_log_item *item;

	err = nvme_identify_ctrl(fd, &ctrl);
	if (err)
		return err;
	snprintf(fw_ver, sizeof(fw_ver), "%c.%c%c.%c%c%c%c",
		ctrl.fr[0], ctrl.fr[1], ctrl.fr[2], ctrl.fr[3],
		ctrl.fr[4], ctrl.fr[5], ctrl.fr[6]);

	printf("Additional Smart Log for NVME device:%s namespace-id:%x\n", devname, nsid);

	printf("Total write in GB since last factory reset			: %"PRIu64"\n",
		int48_to_long(smart->items[TOTAL_WRITE].rawval));
	printf("Total read in GB since last factory reset			: %"PRIu64"\n",
		int48_to_long(smart->items[TOTAL_READ].rawval));

	printf("Thermal throttling status[1:HTP in progress]			: %u\n",
		smart->items[THERMAL_THROTTLE].thermal_throttle.on);
	printf("Total thermal throttling minutes since power on			: %u\n",
		smart->items[THERMAL_THROTTLE].thermal_throttle.count);

	printf("Maximum temperature in Kelvin since last factory reset		: %u\n",
		le16_to_cpu(smart->items[TEMPT_SINCE_RESET].temperature.max));
	printf("Minimum temperature in Kelvin since last factory reset		: %u\n",
		le16_to_cpu(smart->items[TEMPT_SINCE_RESET].temperature.min));
	if (compare_fw_version(fw_ver, "0.09.0300") != 0) {
		printf("Maximum temperature in Kelvin since power on			: %u\n",
			le16_to_cpu(smart->items[TEMPT_SINCE_BOOTUP].temperature_p.max));
		printf("Minimum temperature in Kelvin since power on			: %u\n",
			le16_to_cpu(smart->items[TEMPT_SINCE_BOOTUP].temperature_p.min));
	}
	printf("Current temperature in Kelvin					: %u\n",
		le16_to_cpu(smart->items[TEMPT_SINCE_RESET].temperature.curr));

	printf("Maximum power in watt since power on				: %u\n",
		le16_to_cpu(smart->items[POWER_CONSUMPTION].power.max));
	printf("Minimum power in watt since power on				: %u\n",
		le16_to_cpu(smart->items[POWER_CONSUMPTION].power.min));
	printf("Current power in watt						: %u\n",
		le16_to_cpu(smart->items[POWER_CONSUMPTION].power.curr));

	item = &smart->items[POWER_LOSS_PROTECTION];
	if (item_id_2_u32(item) == 0xEC)
		printf("Power loss protection normalized value				: %u\n",
			item->power_loss_protection.curr);

	item = &smart->items[WEARLEVELING_COUNT];
	if (item_id_2_u32(item) == 0xAD) {
		printf("Percentage of wearleveling count left				: %u\n",
				le16_to_cpu(item->nmval));
		printf("Wearleveling count min erase cycle				: %u\n",
				le16_to_cpu(item->wearleveling_count.min));
		printf("Wearleveling count max erase cycle				: %u\n",
				le16_to_cpu(item->wearleveling_count.max));
		printf("Wearleveling count avg erase cycle				: %u\n",
				le16_to_cpu(item->wearleveling_count.avg));
	}

	item = &smart->items[HOST_WRITE];
	if (item_id_2_u32(item) == 0xF5)
		printf("Total host write in GiB since device born 			: %llu\n",
				(unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));
		
	item = &smart->items[THERMAL_THROTTLE_CNT];
	if (item_id_2_u32(item) == 0xEB)
		printf("Thermal throttling count since device born 			: %u\n",
				item->thermal_throttle_cnt.cnt);

	item = &smart->items[CORRECT_PCIE_PORT0];
	if (item_id_2_u32(item) == 0xED)
		printf("PCIE Correctable Error Count of Port0    			: %llu\n",
				(unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));

	item = &smart->items[CORRECT_PCIE_PORT1];
	if (item_id_2_u32(item) == 0xEE)
		printf("PCIE Correctable Error Count of Port1 	        		: %llu\n",
				(unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));

	item = &smart->items[REBUILD_FAIL];
	if (item_id_2_u32(item) == 0xEF)
		printf("End-to-End Error Detection Count 	        		: %llu\n",
				(unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));

	item = &smart->items[ERASE_FAIL];
	if (item_id_2_u32(item) == 0xF0)
		printf("Erase Fail Count 		                        	: %llu\n",
				(unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));

    item = &smart->items[PROGRAM_FAIL];
	if (item_id_2_u32(item) == 0xF1)
		printf("Program Fail Count 		                        	: %llu\n",
				(unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));

	item = &smart->items[READ_FAIL];
	if (item_id_2_u32(item) == 0xF2)
		printf("Read Fail Count	                                 		: %llu\n",
				(unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));
	return err;
}

static int get_additional_smart_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_memblaze_smart_log smart_log;
	int err, fd;
	char *desc = "Get Memblaze vendor specific additional smart log (optionally, "\
		      "for the specified namespace), and show it.";
	const char *namespace = "(optional) desired namespace";
	const char *raw = "dump output in binary format";
	struct config {
		__u32 namespace_id;
		int   raw_binary;
	};

	struct config cfg = {
		.namespace_id = NVME_NSID_ALL,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return fd;

	err = nvme_get_log(fd, 0xca, cfg.namespace_id, 0, 0, 0, false, 0,
			   sizeof(smart_log), &smart_log);
	if (!err) {
		if (!cfg.raw_binary)
			err = show_memblaze_smart_log(fd, cfg.namespace_id, devicename, &smart_log);
		else
			d_raw((unsigned char *)&smart_log, sizeof(smart_log));
	}
	if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(err, false), err);

	return err;
}

#if 0
static char *mb_feature_to_string(int feature)
{
	switch (feature) {
	case MB_FEAT_POWER_MGMT: return "Memblaze power management";
	default:	return "Unknown";
	}
}
#endif
