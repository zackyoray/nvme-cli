#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/shannon/shannon-nvme

#if !defined(SHANNON_NVME) || defined(CMD_HEADER_MULTI_READ)
#define SHANNON_NVME

#include "cmd.h"

PLUGIN(NAME("shannon", "Shannon vendor specific extensions"),
	COMMAND_LIST(
		ENTRY("smart-log-add", "Retrieve Shannon SMART Log, show it", get_additional_smart_log)
	)
);

#endif

#include "define_cmd.h"
