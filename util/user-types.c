#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/param.h>
#include <json-c/json.h>
#include <uuid/uuid.h>

#include "user-types.h"

static const char dash[101] = {[0 ... 99] = '-'};

void d(unsigned char *buf, int len, int width, int group)
{
	int i, offset = 0;
	char ascii[32 + 1];
	bool line_done = false;

	printf("     ");
	for (i = 0; i <= 15; i++)
		printf("%3x", i);

	for (i = 0; i < len; i++) {
		line_done = false;
		if (i % width == 0)
			printf( "\n%04x:", offset);
		if (i % group == 0)
			printf( " %02x", buf[i]);
		else
			printf( "%02x", buf[i]);
		ascii[i % width] = (buf[i] >= '!' && buf[i] <= '~') ? buf[i] : '.';
		if (((i + 1) % width) == 0) {
			ascii[i % width + 1] = '\0';
			printf( " \"%.*s\"", width, ascii);
			offset += width;
			line_done = true;
		}
	}

	if (!line_done) {
		unsigned b = width - (i % width);

		ascii[i % width + 1] = '\0';
		printf( " %*s \"%.*s\"",
				2 * b + b / group + (b % group ? 1 : 0), "",
				width, ascii);
	}
	printf( "\n");
}

void d_raw(unsigned char *buf, unsigned len)
{
	unsigned i;
	for (i = 0; i < len; i++)
		putchar(*(buf+i));
}

#define ARRAY_SIZE(x) sizeof(x) / sizeof(*x)
#define ARGSTR(s, i) arg_str(s, ARRAY_SIZE(s), i)

static const char *arg_str(const char * const *strings,
		size_t array_size, size_t idx)
{
	if (idx < array_size && strings[idx])
		return strings[idx];
	return "unrecognized";
}

static const char * const features_sels[] = {
	[NVME_GET_FEATURES_SEL_CURRENT]	= "current",
	[NVME_GET_FEATURES_SEL_DEFAULT]	= "default",
	[NVME_GET_FEATURES_SEL_SAVED]	= "saved",
};

const char *nvme_get_feature_select_to_string(__u8 sel)
{
	return ARGSTR(features_sels, sel);
}

static const char * const cntrltypes[] = {
	[NVME_CTRL_CNTRLTYPE_IO]	= "io",
	[NVME_CTRL_CNTRLTYPE_DISCOVERY]	= "discovery",
	[NVME_CTRL_CNTRLTYPE_ADMIN]	= "administrative",
};

const char *nvme_id_ctrl_cntrltype_str(__u8 cntrltype)
{
	return ARGSTR(cntrltypes, cntrltype);
}

static const char * const rbtypes[] = {
	[NVME_NS_DLFEAT_RB_NR]		= "not-reported",
	[NVME_NS_DLFEAT_RB_ALL_0S]	= "all-0s",
	[NVME_NS_DLFEAT_RB_ALL_FS]	= "all-fs",
};

const char *id_ns_dlfeat_rb_str(__u8 rb)
{
	return ARGSTR(rbtypes, rb);
}

static const char * const dpstypes[] = {
	[NVME_NS_DPS_PI_NONE]	= "none",
	[NVME_NS_DPS_PI_TYPE1]	= "type1",
	[NVME_NS_DPS_PI_TYPE2]	= "type2",
	[NVME_NS_DPS_PI_TYPE3]	= "type3",
};

const char *nvme_id_ns_dps_str(__u8 dps)
{
	return ARGSTR(dpstypes, dps);
}

static const char * const rptypes[] = {
	[NVME_LBAF_RP_BEST]	= "best",
	[NVME_LBAF_RP_BETTER]	= "better",
	[NVME_LBAF_RP_GOOD]	= "good",
	[NVME_LBAF_RP_DEGRADED]	= "degraded",
};

const char *nvme_id_ns_lbaf_rp_str(__u8 rp)
{
	return ARGSTR(rptypes, rp);
}

static const char * const featuretypes[] = {
	[NVME_FEAT_FID_ARBITRATION]		= "Arbitration",
	[NVME_FEAT_FID_POWER_MGMT]		= "Power Management",
	[NVME_FEAT_FID_LBA_RANGE]		=  "LBA Range Type",
	[NVME_FEAT_FID_TEMP_THRESH]		= "Temperature Threshold",
	[NVME_FEAT_FID_ERR_RECOVERY]		= "Error Recovery",
	[NVME_FEAT_FID_VOLATILE_WC]		= "Volatile Write Cache",
	[NVME_FEAT_FID_NUM_QUEUES]		= "Number of Queues",
	[NVME_FEAT_FID_IRQ_COALESCE]		= "Interrupt Coalescing",
	[NVME_FEAT_FID_IRQ_CONFIG]		= "Interrupt Vector Configuration",
	[NVME_FEAT_FID_WRITE_ATOMIC]		= "Write Atomicity Normal",
	[NVME_FEAT_FID_ASYNC_EVENT]		= "Async Event Configuration",
	[NVME_FEAT_FID_AUTO_PST]		= "Autonomous Power State Transition",
	[NVME_FEAT_FID_HOST_MEM_BUF]		= "Host Memory Buffer",
	[NVME_FEAT_FID_TIMESTAMP]		= "Timestamp",
	[NVME_FEAT_FID_KATO]			= "Keep Alive Timer",
	[NVME_FEAT_FID_HCTM]			= "Host Controlled Thermal Management",
	[NVME_FEAT_FID_NOPSC]			= "Non-Operational Power State Config",
	[NVME_FEAT_FID_RRL]			= "Read Recovery Level Config",
	[NVME_FEAT_FID_PLM_CONFIG]		= "Predicatable Latency Mode Config",
	[NVME_FEAT_FID_PLM_WINDOW]		= "Predicatable Latency Mode Window",
	[NVME_FEAT_FID_LBA_STS_INTERVAL]	= "LBA Status Infomration Report Interval",
	[NVME_FEAT_FID_HOST_BEHAVIOR]		= "Host Behavior Support",
	[NVME_FEAT_FID_SANITIZE]		= "Sanitize Config",
	[NVME_FEAT_FID_ENDURANCE_EVT_CFG]	= "Endurance Group Event Configuration",
	[NVME_FEAT_FID_SW_PROGRESS]		= "Software Progress",
	[NVME_FEAT_FID_HOST_ID]			= "Host Identifier",
	[NVME_FEAT_FID_RESV_MASK]		= "Reservation Notification Mask",
	[NVME_FEAT_FID_RESV_PERSIST]		= "Reservation Persistence",
	[NVME_FEAT_FID_WRITE_PROTECT]		= "Namespce Write Protection Config",
};

const char *nvme_feature_str(__u8 fid)
{
	return ARGSTR(featuretypes, fid);
}

static const char * const nidttypes[] = {
	[NVME_NIDT_EUI64]	= "eui64",
	[NVME_NIDT_NGUID]	= "nguid",
	[NVME_NIDT_UUID]	= "uuid",
};

const char *nvme_id_nsdesc_nidt_str(__u8 nidt)
{
	return ARGSTR(nidttypes, nidt);
}

static const char * const associationtypes[] = {
	[NVME_ID_UUID_ASSOCIATION_NONE]			= "none",
	[NVME_ID_UUID_ASSOCIATION_VENDOR]		= "vendor",
	[NVME_ID_UUID_ASSOCIATION_SUBSYSTEM_VENDOR]	= "subsystem-vendor",
};

const char *nvme_id_uuid_assoc_str(__u8 assoc)
{
	return ARGSTR(associationtypes, assoc);
}

static const char * const trtypes[] = {
	[NVMF_TRTYPE_UNSPECIFIED]	= "unspecified",
	[NVMF_TRTYPE_RDMA]		= "rdma",
	[NVMF_TRTYPE_FC]		= "fc",
	[NVMF_TRTYPE_TCP]		= "tcp",
	[NVMF_TRTYPE_LOOP]		= "loop",
};

const char *nvmf_trtype_str(__u8 trtype)
{
	return ARGSTR(trtypes, trtype);
}

static const char * const adrfams[] = {
	[NVMF_ADDR_FAMILY_PCI]	= "pci",
	[NVMF_ADDR_FAMILY_IP4]	= "ipv4",
	[NVMF_ADDR_FAMILY_IP6]	= "ipv6",
	[NVMF_ADDR_FAMILY_IB]	= "infiniband",
	[NVMF_ADDR_FAMILY_FC]	= "fibre-channel",
};

const char *nvmf_adrfam_str(__u8 adrfam)
{
	return ARGSTR(adrfams, adrfam);
}

static const char * const subtypes[] = {
	[NVME_NQN_DISC]		= "discovery subsystem",
	[NVME_NQN_NVME]		= "nvme subsystem",
};

const char *nvmf_subtype_str(__u8 subtype)
{
	return ARGSTR(subtypes, subtype);
}

static const char * const treqs[] = {
	[NVMF_TREQ_NOT_SPECIFIED]	= "not specified",
	[NVMF_TREQ_REQUIRED]		= "required",
	[NVMF_TREQ_NOT_REQUIRED]	= "not required",
	[NVMF_TREQ_DISABLE_SQFLOW]	= "not specified, sq flow control disable supported",
};

const char *nvmf_treq_str(__u8 treq)
{
	return ARGSTR(treqs, treq);
}

static const char * const sectypes[] = {
	[NVMF_TCP_SECTYPE_NONE]		= "none",
	[NVMF_TCP_SECTYPE_TLS]		= "tls",
};

const char *nvmf_sectype_str(__u8 sectype)
{
	return ARGSTR(sectypes, sectype);
}

static const char * const prtypes[] = {
	[NVMF_RDMA_PRTYPE_NOT_SPECIFIED]	= "not specified",
	[NVMF_RDMA_PRTYPE_IB]			= "infiniband",
	[NVMF_RDMA_PRTYPE_ROCE]			= "roce",
	[NVMF_RDMA_PRTYPE_ROCEV2]		= "roce-v2",
	[NVMF_RDMA_PRTYPE_IWARP]		= "iwarp",
};

const char *nvmf_prtype_str(__u8 prtype)
{
	return ARGSTR(prtypes, prtype);
}

static const char * const qptypes[] = {
	[NVMF_RDMA_QPTYPE_CONNECTED]	= "connected",
	[NVMF_RDMA_QPTYPE_DATAGRAM]	= "datagram",
};

const char *nvmf_qptype_str(__u8 qptype)
{
	return ARGSTR(qptypes, qptype);
}

static const char * const cms[] = {
	[NVMF_RDMA_CMS_RDMA_CM]	= "rdma-cm",
};

const char *nvmf_cms_str(__u8 cm)
{
	return ARGSTR(cms, cm);
}

static const char * const generic_status[] = {
	[NVME_SC_SUCCESS]		  = "Successful Completion: The command completed without error",
	[NVME_SC_INVALID_OPCODE]	  = "Invalid Command Opcode: A reserved coded value or an unsupported value in the command opcode field",
	[NVME_SC_INVALID_FIELD]		  = "Invalid Field in Command: A reserved coded value or an unsupported value in a defined field",
	[NVME_SC_CMDID_CONFLICT]	  = "Command ID Conflict: The command identifier is already in use",
	[NVME_SC_DATA_XFER_ERROR]	  = "Data Transfer Error: Transferring the data or metadata associated with a command experienced an error",
	[NVME_SC_POWER_LOSS]		  = "Commands Aborted due to Power Loss Notification: Indicates that the command was aborted due to a power loss notification",
	[NVME_SC_INTERNAL]		  = "Internal Error: The command was not completed successfully due to an internal error",
	[NVME_SC_ABORT_REQ]		  = "Command Abort Requested: The command was aborted due to an Abort command",
	[NVME_SC_ABORT_QUEUE]		  = "Command Aborted due to SQ Deletion: The command was aborted due to a Delete I/O Submission Queue",
	[NVME_SC_FUSED_FAIL]		  = "Command Aborted due to Failed Fused Command: The command was aborted due to the other command in a fused operation failing",
	[NVME_SC_FUSED_MISSING]		  = "Command Aborted due to Missing Fused Command: The fused command was aborted due to the adjacent submission queue entry not containing a fused command",
	[NVME_SC_INVALID_NS]		  = "Invalid Namespace or Format: The namespace or the format of that namespace is invalid",
	[NVME_SC_CMD_SEQ_ERROR]		  = "Command Sequence Error: The command was aborted due to a protocol violation in a multi- command sequence",
	[NVME_SC_SGL_INVALID_LAST]	  = "Invalid SGL Segment Descriptor: The command includes an invalid SGL Last Segment or SGL Segment descriptor",
	[NVME_SC_SGL_INVALID_COUNT]	  = "Invalid Number of SGL Descriptors: There is an SGL Last Segment descriptor or an SGL Segment descriptor in a location other than the last descriptor of a segment based on the length indicated",
	[NVME_SC_SGL_INVALID_DATA]	  = "Data SGL Length Invalid: The length of a Data SGL is too short or too long and the controller does not support SGL transfers longer than the amount of data to be transferred",
	[NVME_SC_SGL_INVALID_METADATA]	  = "Metadata SGL Length Invalid: The length of a Metadata SGL is too short or too long and the controller does not support SGL transfers longer than the amount of data to be transferred",
	[NVME_SC_SGL_INVALID_TYPE]	  = "SGL Descriptor Type Invalid: The type of an SGL Descriptor is a type that is not supported by the controller",
	[NVME_SC_CMB_INVALID_USE]	  = "Invalid Use of Controller Memory Buffer: The attempted use of the Controller Memory Buffer is not supported by the controller",
	[NVME_SC_PRP_INVALID_OFFSET]	  = "PRP Offset Invalid: The Offset field for a PRP entry is invalid",
	[NVME_SC_AWU_EXCEEDED]		  = "Atomic Write Unit Exceeded: The length specified exceeds the atomic write unit size",
	[NVME_SC_OP_DENIED]		  = "Operation Denied: The command was denied due to lack of access rights",
	[NVME_SC_SGL_INVALID_OFFSET]	  = "SGL Offset Invalid: The offset specified in a descriptor is invalid",
	[NVME_SC_HOSTID_FORMAT]		  = "Host Identifier Inconsistent Format: The NVM subsystem detected the simultaneous use of 64- bit and 128-bit Host Identifier values on different controllers",
	[NVME_SC_KAT_EXPIRED]		  = "Keep Alive Timer Expired: The Keep Alive Timer expired",
	[NVME_SC_KAT_INVALID]		  = "Keep Alive Timeout Invalid: The Keep Alive Timeout value specified is invalid",
	[NVME_SC_CMD_ABORTED_PREMEPT]	  = "Command Aborted due to Preempt and Abort: The command was aborted due to a Reservation Acquire command",
	[NVME_SC_SANITIZE_FAILED]	  = "Sanitize Failed: The most recent sanitize operation failed and no recovery action has been successfully completed",
	[NVME_SC_SANITIZE_IN_PROGRESS]	  = "Sanitize In Progress: The requested function is prohibited while a sanitize operation is in progress",
	[NVME_SC_SGL_INVALID_GRANULARITY] = "SGL Data Block Granularity Invalid: The Address alignment or Length granularity for an SGL Data Block descriptor is invalid",
	[NVME_SC_CMD_IN_CMBQ_NOT_SUPP]	  = "Command Not Supported for Queue in CMB: The controller does not support Submission Queue in the Controller Memory Buffer or Completion Queue in the Controller Memory Buffer",
	[NVME_SC_NS_WRITE_PROTECTED]	  = "Namespace is Write Protected: The command is prohibited while the namespace is write protected",
	[NVME_SC_CMD_INTERRUPTED]	  = "Command Interrupted: Command processing was interrupted and the controller is unable to successfully complete the command",
	[NVME_SC_TRAN_TPORT_ERROR]	  = "Transient Transport Error: A transient transport error was detected",
	[NVME_SC_LBA_RANGE]		  = "LBA Out of Range: The command references an LBA that exceeds the size of the namespace",
	[NVME_SC_CAP_EXCEEDED]		  = "Capacity Exceeded: Execution of the command has caused the capacity of the namespace to be exceeded",
	[NVME_SC_NS_NOT_READY]		  = "Namespace Not Ready: The namespace is not ready to be accessed",
	[NVME_SC_RESERVATION_CONFLICT]	  = "Reservation Conflict: The command was aborted due to a conflict with a reservation held on the accessed namespace",
	[NVME_SC_FORMAT_IN_PROGRESS]	  = "Format In Progress: A Format NVM command is in progress on the namespace",
};

static const char * const cmd_spec_status[] = {
	[NVME_SC_CQ_INVALID]		 = "Completion Queue Invalid: The Completion Queue identifier specified in the command does not exist",
	[NVME_SC_QID_INVALID]		 = "Invalid Queue Identifier: The creation of the I/O Completion Queue failed due to an invalid queue identifier specified as part of the command",
	[NVME_SC_QUEUE_SIZE]		 = "Invalid Queue Size: The host attempted to create an I/O Completion Queue with an invalid number of entries",
	[NVME_SC_ABORT_LIMIT]		 = "Abort Command Limit Exceeded: The number of concurrently outstanding Abort commands has exceeded the limit indicated in the Identify Controller data structure",
	[NVME_SC_ASYNC_LIMIT]		 = "Asynchronous Event Request Limit Exceeded: The number of concurrently outstanding Asynchronous Event Request commands has been exceeded",
	[NVME_SC_FIRMWARE_SLOT]		 = "Invalid Firmware Slot: The firmware slot indicated is invalid or read only",
	[NVME_SC_FIRMWARE_IMAGE]	 = "Invalid Firmware Image: The firmware image specified for activation is invalid and not loaded by the controller",
	[NVME_SC_INVALID_VECTOR]	 = "Invalid Interrupt Vector: The creation of the I/O Completion Queue failed due to an invalid interrupt vector specified as part of the command",
	[NVME_SC_INVALID_LOG_PAGE]	 = "Invalid Log Page: The log page indicated is invalid",
	[NVME_SC_INVALID_FORMAT]	 = "Invalid Format: The LBA Format specified is not supported",
	[NVME_SC_FW_NEEDS_CONV_RESET] 	 = "Firmware Activation Requires Conventional Reset: The firmware commit was successful, however, activation of the firmware image requires a conventional reset",
	[NVME_SC_INVALID_QUEUE]		 = "Invalid Queue Deletion: Invalid I/O Completion Queue specified to delete",
	[NVME_SC_FEATURE_NOT_SAVEABLE]	 = "Feature Identifier Not Saveable: The Feature Identifier specified does not support a saveable value",
	[NVME_SC_FEATURE_NOT_CHANGEABLE] = "Feature Not Changeable: The Feature Identifier is not able to be changed",
	[NVME_SC_FEATURE_NOT_PER_NS]	 = "Feature Not Namespace Specific: The Feature Identifier specified is not namespace specific",
	[NVME_SC_FW_NEEDS_SUBSYS_RESET]  = "Firmware Activation Requires NVM Subsystem Reset: The firmware commit was successful, however, activation of the firmware image requires an NVM Subsystem",
	[NVME_SC_FW_NEEDS_RESET]	 = "Firmware Activation Requires Controller Level Reset: The firmware commit was successful; however, the image specified does not support being activated without a reset",
	[NVME_SC_FW_NEEDS_MAX_TIME]	 = "Firmware Activation Requires Maximum Time Violation: The image specified if activated immediately would exceed the Maximum Time for Firmware Activation (MTFA) value reported in Identify Controller",
	[NVME_SC_FW_ACTIVATE_PROHIBITED] = "Firmware Activation Prohibited: The image specified is being prohibited from activation by the controller for vendor specific reasons",
	[NVME_SC_OVERLAPPING_RANGE]	 = "Overlapping Range: The downloaded firmware image has overlapping ranges",
	[NVME_SC_NS_INSUFFICIENT_CAP]	 = "Namespace Insufficient Capacity: Creating the namespace requires more free space than is currently available",
	[NVME_SC_NS_ID_UNAVAILABLE]	 = "Namespace Identifier Unavailable: The number of namespaces supported has been exceeded",
	[NVME_SC_NS_ALREADY_ATTACHED]	 = "Namespace Already Attached: The controller is already attached to the namespace specified",
	[NVME_SC_NS_IS_PRIVATE]		 = "Namespace Is Private: The namespace is private and is already attached to one controller",
	[NVME_SC_NS_NOT_ATTACHED]	 = "Namespace Not Attached: The request to detach the controller could not be completed because the controller is not attached to the namespace",
	[NVME_SC_THIN_PROV_NOT_SUPP]	 = "Thin Provisioning Not Supported: Thin provisioning is not supported by the controller",
	[NVME_SC_CTRL_LIST_INVALID]	 = "Controller List Invalid: The controller list provided contains invalid controller ids",
	[NVME_SC_SELF_TEST_IN_PROGRESS]  = "Device Self-test In Progress",
	[NVME_SC_BP_WRITE_PROHIBITED]	 = "Boot Partition Write Prohibited: The command tried to modify a locked Boot Partition",
	[NVME_SC_INVALID_CTRL_ID]	 = "Invalid Controller Identifier: An invalid controller id was specified",
	[NVME_SC_INVALID_SEC_CTRL_STATE] = "Invalid Secondary Controller State: The requested secondary controller action is invalid based on the secondary and primary controllers current states",
	[NVME_SC_INVALID_CTRL_RESOURCES] = "Invalid Number of Controller Resources: The specified number of Flexible Resources is invalid",
	[NVME_SC_INVALID_RESOURCE_ID]	 = "Invalid Resource Identifier: At least one of the specified resource identifiers was invalid",
	[NVME_SC_PMR_SAN_PROHIBITED]	 = "Sanitize Prohibited While Persistent Memory Region is Enabled",
	[NVME_SC_ANA_GROUP_ID_INVALID]	 = "ANA Group Identifier Invalid",
	[NVME_SC_ANA_ATTACH_FAILED]	 = "ANA Attach Failed: The command's specified ANA Group Identifier is not supported",
};

static const char * const nvm_status[] = {
	[NVME_SC_BAD_ATTRIBUTES] = "Conflicting Attributes: The attributes specified in the command are conflicting",
	[NVME_SC_INVALID_PI]	 = "Invalid Protection Information: The command's Protection Information Field settings are invalid for the namespace's Protection Information format",
	[NVME_SC_READ_ONLY]	 = "Attempted Write to Read Only Range: The LBA range specified contains read-only blocks",
};

static const char * const nvmf_status[] = {
	[NVME_SC_CONNECT_FORMAT]	   = "Incompatible Format: The NVM subsystem does not support the record format specified by the host",
	[NVME_SC_CONNECT_CTRL_BUSY]	   = "Controller Busy: The controller is already associated with a host",
	[NVME_SC_CONNECT_INVALID_PARAM]    = "Connect Invalid Parameters: One or more of the command parameters",
	[NVME_SC_CONNECT_RESTART_DISC]	   = "Connect Restart Discovery: The NVM subsystem requested is not available",
	[NVME_SC_CONNECT_INVALID_HOST]	   = "Connect Invalid Host: The host is not allowed to establish an association to either any controller in the NVM subsystem or the specified controller",
	[NVME_SC_DISCONNECT_INVALID_QTYPE] = "Invalid Queue Type: The command was sent on the wrong queue type",
	[NVME_SC_DISCOVERY_RESTART]	   = "Discover Restart: The snapshot of the records is now invalid or out of date",
	[NVME_SC_AUTH_REQUIRED]		   = "Authentication Required: NVMe in-band authentication is required and the queue has not yet been authenticated",
};

static const char * const media_status[] = {
	[NVME_SC_WRITE_FAULT]	  = "Write Fault: The write data could not be committed to the media",
	[NVME_SC_READ_ERROR]	  = "Unrecovered Read Error: The read data could not be recovered from the media",
	[NVME_SC_GUARD_CHECK]	  = "End-to-end Guard Check Error: The command was aborted due to an end-to-end guard check failure",
	[NVME_SC_APPTAG_CHECK]	  = "End-to-end Application Tag Check Error: The command was aborted due to an end-to-end application tag check failure",
	[NVME_SC_REFTAG_CHECK]	  = "End-to-end Reference Tag Check Error: The command was aborted due to an end-to-end reference tag check failure",
	[NVME_SC_COMPARE_FAILED]  = "Compare Failure: The command failed due to a miscompare during a Compare command",
	[NVME_SC_ACCESS_DENIED]	  = "Access Denied: Access to the namespace and/or LBA range is denied due to lack of access rights",
	[NVME_SC_UNWRITTEN_BLOCK] = "Deallocated or Unwritten Logical Block: The command failed due to an attempt to read from or verify an LBA range containing a deallocated or unwritten logical block",
};

static const char * const path_status[] = {
	[NVME_SC_ANA_INTERNAL_PATH_ERROR] = "Internal Path Error: An internal error specific to the controller processing the commmand prevented completion",
	[NVME_SC_ANA_PERSISTENT_LOSS]	  = "Asymmetric Access Persistent Loss: The controller is in a persistent loss state with the requested namespace",
	[NVME_SC_ANA_INACCESSIBLE]	  = "Asymmetric Access Inaccessible: The controller is in an inaccessible state with the requested namespace",
	[NVME_SC_ANA_TRANSITION]	  = "Asymmetric Access Transition: The controller is currently transitioning states with the requested namespace",
	[NVME_SC_CTRL_PATH_ERROR]	  = "Controller Pathing Error: A pathing error was detected by the controller",
	[NVME_SC_HOST_PATH_ERROR]	  = "Host Pathing Error: A pathing error was detected by the host",
	[NVME_SC_CMD_ABORTED_BY_HOST]	  = "Command Aborted By Host: The command was aborted as a result of host action",
};

const char *nvme_status_to_string(int status, bool fabrics)
{
	const char *s = NULL;
	__u16 sc, sct;

	if (status < 0)
		return strerror(errno);

	sc = status & NVME_SC_MASK;
	sct = status & NVME_SCT_MASK;

	switch (sct) {
	case NVME_SCT_GENERIC:
		s = ARGSTR(generic_status, sc);
		break;
	case NVME_SCT_CMD_SPECIFIC:
		if (sc < ARRAY_SIZE(cmd_spec_status))
			s = ARGSTR(cmd_spec_status, sc);
		 else if (fabrics)
			s = ARGSTR(nvmf_status, sc);
		else
			s = ARGSTR(nvm_status, sc);
		break;
	case NVME_SCT_MEDIA:
		s = ARGSTR(media_status, sc);
		break;
	case NVME_SCT_PATH:
		s = ARGSTR(path_status, sc);
		break;
	case NVME_SCT_VS:
		s = "Vendor Specific Status";
		break;
	default:
		s = "Unknown status";
		break;
	}

	return s;
}

static const char *iec[] = {
	"B",
	"KiB",
	"MiB",
	"GiB",
	"TiB",
	"PiB",
	"EiB",
	"ZiB",
	"YiB",
};

static const char *jedec[] = {
	"B",
	"KB",
	"MB",
	"GB",
	"TB",
	"PB",
	"EB",
	"ZB",
	"YB",
};

static void util_split(uint64_t v, uint16_t *idx,  uint16_t *major,
	uint16_t *minor, uint16_t *jmajor, uint16_t *jminor)
{
	uint64_t lower = 0, upper = v, mag = 1;
	int i, j;

	for (i = 0; i < ARRAY_SIZE(iec) - 1 && upper > 1024; i++)
		upper >>= 10;
	if (i)
		lower = (((v - (upper << (10 * i))) >> ((i - 1) * 10)) * 100) >> 10;;

	*major = upper;
	*minor = lower;
	*idx = i;

	if (!jmajor)
		return;

	for (j = 0; j < i; j++)
		mag *= 1000;
	upper = v / mag;

	if (j)
		lower = (v % mag) / (mag / 1000);
	*jmajor = upper;
	*jminor = lower;
}

static int __display_human_size128(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	uint16_t i = 0,  major = 0, minor = 0, jmajor = 0, jminor = 0, bias = 0;
	uint8_t *s = (uint8_t *)json_object_get_string(o);
	uint64_t upper = 0, lower = 0, v;
	int j;

        for (j = 7; j >= 0; j--) {
                lower = lower * 256 + s[j];
		upper = upper * 256 + s[j + 8];
	}

	if (upper) {
		if (upper >= (1 << 16)) {
			v = upper >> 6;
			bias = 7;
		} else if (upper >= (1 << 6)) {
			v = (upper << 4) | (lower >> 60);
			bias = 6;
		} else {
			v = (upper << 14) | (lower >> 50);
			bias = 5;
		}
	} else
		v = lower;

	util_split(v, &i, &major, &minor, &jmajor, &jminor);
	return sprintbuf(p, "%u.%02u %s (%lu.%03lu %s)", major, minor,
		iec[i + bias], jmajor, jminor, jedec[i + bias]);
}

static int __display_human_size128_str(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	printbuf_memappend(p, "\"", 1);
	__display_human_size128(o, p, l, f);
	printbuf_memappend(p, "\"", 1);

	return 0;
}

static int __display_human_size(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	uint16_t i = 0, major = 0, minor = 0, jmajor = 0, jminor = 0;
	uint64_t v = json_object_get_int64(o);
	
	util_split(v, &i, &major, &minor, &jmajor, &jminor);
	return sprintbuf(p, "%u.%02u %s (%lu.%03lu %s)", major, minor, iec[i],
		jmajor, jminor, jedec[i]);
}

static int __display_human_size_str(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	printbuf_memappend(p, "\"", 1);
	__display_human_size(o, p, l, f);
	printbuf_memappend(p, "\"", 1);

	return 0;
}

static int _display_human_size(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	uint64_t v = json_object_get_int64(o);
	uint16_t i = 0, major = 0, minor = 0;
	
	util_split(v, &i, &major, &minor, NULL, NULL);
	if (minor)
		return sprintbuf(p, "%u.%02u %s", major, minor, iec[i]);
	return sprintbuf(p, "%u %s", major, iec[i]);
}

static int _display_human_size_str(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	printbuf_memappend(p, "\"", 1);
	_display_human_size(o, p, l, f);
	printbuf_memappend(p, "\"", 1);

	return 0;
}

static int display_human_size(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	uint16_t i = 0, major = 0, minor = 0;
	uint64_t v = json_object_get_int64(o);

	util_split(v, &i, &major, &minor, NULL, NULL);
	return sprintbuf(p, "%u %s", major, iec[i]);
}

static int display_human_size_str(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	printbuf_memappend(p, "\"", 1);
	display_human_size(o, p, l, f);
	printbuf_memappend(p, "\"", 1);

	return 0;
}

static int display_binary(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	void *s = (void *)json_object_get_string(o);
	int len = json_object_get_string_len(o);

	d_raw(s, len);
	return 0;
}

static int display_hex_array(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	uint8_t *s = (uint8_t *)json_object_get_string(o);
	int i, len = json_object_get_string_len(o);

	for (i = 0; i < len; i++)
		sprintbuf(p, "%02x", s[i]);
	return 0;
}

static int display_hex_array_str(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	printbuf_memappend(p, "\"", 1);
	display_hex_array(o, p, l, f);
	printbuf_memappend(p, "\"", 1);

	return 0;
}

static void util_wrap_string(struct printbuf *pb, const char *s, int indent)
{
	const int width = 76;
	const char *c, *t;
	char *p, *wrap = malloc(strlen(s) * 4);
	int next_space = -1;
	int last_line = indent;

	p = wrap;
	for (c = s; *c != 0; c++) {
		if (*c == '\n')
			goto new_line;

		if (*c == ' ' || next_space < 0) {
			next_space = 0;
			for (t = c + 1; *t != 0 && *t != ' '; t++)
				next_space++;

			if (((int)(c - s) + indent + next_space) >
			    (last_line - indent + width)) {
new_line:
				if (*(c + 1) == 0)
					continue;
				last_line = (int) (c-s) + indent;
				p += sprintf(p, "\n%-*s",  indent, "");
				continue;
			}
		}
		p += sprintf(p, "%c", *c);
	}
	p += sprintf(p, "\n");
	printbuf_memappend(pb, wrap, strlen(wrap));
	free(wrap);
}

static int util_count_child_primitive_objects(struct json_object *j)
{
	int i = 0;

	json_object_object_foreach(j, key, val) {
		(void)key;

		switch (json_object_get_type(val)) {
		case json_type_boolean:
		case json_type_double:
		case json_type_int:
		case json_type_string:
			i++;
			break;
		default:
			break;
		}
	}

	return i;
}

static void util_set_column_widths(struct json_object *j, int *widths)
{
	int i = 0;

	json_object_object_foreach(j, key, val) {
		(void)key;

		switch (json_object_get_type(val)) {
		case json_type_boolean:
		case json_type_double:
		case json_type_int:
		case json_type_string:
			if (strlen(json_object_to_json_string(val)) + 2 > widths[i]) {
				widths[i] =
					strlen(json_object_to_json_string(val)) + 2;
			}
			i++;
			break;
		default:
			break;
		}
	}
}

static void util_init_column_widths(struct json_object *j, int *widths)
{
	int i = 0;

	json_object_object_foreach(j, key, val) {
		switch (json_object_get_type(val)) {
		case json_type_boolean:
		case json_type_double:
		case json_type_int:
		case json_type_string:
			break;
		default:
			continue;;
		}

		widths[i++] = strlen(key);
	}
}

static void util_print_column_widths(struct json_object *j, int *widths,
	int indent, struct printbuf *p)
{
	int i = 0;

	json_object_object_foreach(j, key, val) {
		switch (json_object_get_type(val)) {
		case json_type_boolean:
		case json_type_double:
		case json_type_int:
		case json_type_string:
			break;
		default:
			continue;
		}

		sprintbuf(p, "%-*s%*s", i ? 1 : 0, "", widths[i], key);
		i++;
	}
	printbuf_memappend(p, "\n", 1);

	i = 0;
	sprintbuf(p, "%-.*s : ", indent, dash);
	json_object_object_foreach(j, _key, _val) {
		(void)_key;

		switch (json_object_get_type(_val)) {
		case json_type_boolean:
		case json_type_double:
		case json_type_int:
		case json_type_string:
			break;
		default:
			continue;
		}

		sprintbuf(p, "%-*s%-.*s", i ? 1 : 0, "", widths[i], dash);
		i++;
	}
	printbuf_memappend(p, "\n", 1);
}

static void util_print_values(struct json_object *j, int *widths,
	struct printbuf *p)
{
	int i = 0;

	json_object_object_foreach(j, key, val) {
		(void)key;

		switch (json_object_get_type(val)) {
		case json_type_boolean:
		case json_type_double:
		case json_type_int:
		case json_type_string:
			break;
		default:
			continue;
		}

		sprintbuf(p, "%-*s%*s", i ? 1 : 0, "", widths[i], json_object_to_json_string(val));
		i++;
	}
	printbuf_memappend(p, "\n", 1);
}

static void nvme_print_compact_json_array(struct printbuf *p, struct json_object *o, char *key, int space)
{
	size_t i, len = json_object_array_length(o);
	int *widths, indent = strlen(key);
	struct json_object *jso;

	if (!len)
		return;

	jso = json_object_array_get_idx(o, 0);
	if (json_object_get_type(jso) != json_type_object)
		return;

	i = util_count_child_primitive_objects(jso);
	if (!i)
		return;

	widths = calloc(i, sizeof(*widths));
	if (!widths)
		return;

	widths = calloc(i, sizeof(*widths));
	util_init_column_widths(jso, widths);
	for (i = 0; i < len; i++) {
		jso = json_object_array_get_idx(o, i);
		util_set_column_widths(jso, widths);
	}

	sprintbuf(p, "%-*s : ", space, key);
	jso = json_object_array_get_idx(o, 0);
	util_print_column_widths(jso, widths, indent, p);
	for (i = 0; i < len; i++) {
		jso = json_object_array_get_idx(o, i);
		sprintbuf(p, "%*d : ", indent, i);
		util_print_values(jso, widths, p);
	}
}

int display_compact_object(struct json_object *jso, struct printbuf *p,
				  int level, int flags)
{
	int ret, l = 0, i = 0;
	char *buf;

	json_object_object_foreach(jso, key, val) {
		switch (json_object_get_type(val)) {
		case json_type_boolean:
		case json_type_double:
		case json_type_int:
		case json_type_string:
			sprintbuf(p, "%s%s:%s", i ? " " : "", key,
				json_object_to_json_string(val));
			i++;
			break;
		case json_type_object:
			sprintbuf(p, "\n%-*s:",  l, key);
			l++;
			ret = asprintf(&buf, "%*s%s", l * 2, "",
				json_object_to_json_string(val));
			l--;
			if (ret < 0  || !buf)
				break;
			util_wrap_string(p, buf, (l + 1) * 2);
			free(buf);
			break;
		case json_type_array:
			nvme_print_compact_json_array(p, val, key, l + 2);
			break;
		default:
			break;
		}
	}
	printbuf_memappend(p, "\n", 1);

	return 0;
}

int display_compact_object_str(struct json_object *jso, struct printbuf *p,
				  int level, int flags)
{
	int i = 0;

	json_object_object_foreach(jso, key, val) {
		switch (json_object_get_type(val)) {
		case json_type_boolean:
		case json_type_double:
		case json_type_int:
		case json_type_string:
			sprintbuf(p, "%s\"%s\":%s", i ? ", " : "", key,
				json_object_to_json_string(val));
			i++;
			break;
		default:
			break;
		}
	}
	return 0;
}

static void nvme_print_json_array(struct printbuf *p, struct json_object *o, char *key, int space)
{
	size_t i, len = json_object_array_length(o);
	char *buf;

	for (i = 0; i < len; i++) {
		int ret;

		sprintbuf(p, "%-*s%3lu : ", space - 6, key, i);
		ret = asprintf(&buf, "%s", json_object_to_json_string(
			json_object_array_get_idx(o, i)));
		if (ret < 0  || !buf)
			break;
		util_wrap_string(p, buf, space);
		free(buf);
	}
}

static int l = 0;

int display_tabular(struct json_object *jso, struct printbuf *p,
				  int level, int flags)
{
	int ret, len = 0;
	char *buf;

	json_object_object_foreach(jso, tkey, tval) {
		(void)tkey;

		if (strlen(tkey) + 1 > len)
			len = strlen(tkey) + 1;
	}

	json_object_object_foreach(jso, key, val) {
		switch (json_object_get_type(val)) {
		case json_type_boolean:
		case json_type_double:
		case json_type_int:
		case json_type_string:
			sprintbuf(p, "%-*s: %s\n", len, key,
				json_object_to_json_string(val));
			break;
		case json_type_object:
			sprintbuf(p, "%-*s:\n",  len, key);
			l++;
			ret = asprintf(&buf, "%*s%s", l * 2, "",
				json_object_to_json_string(val));
			l--;
			if (ret < 0  || !buf)
				break;
			util_wrap_string(p, buf, (l + 1) * 2);
			free(buf);
			break;
		case json_type_array:
			nvme_print_json_array(p, val, key, len + 2);
			break;
		default:
			break;
		}
	}
	return 0;
}

int display_tree(struct json_object *jso, struct printbuf *p,
		 int level, int flags)
{
	static char char_stack[16];
	int j, i = 0;

	if (l == 0)
		printbuf_memappend(p, ".\n", 2);
	if (l >= sizeof(char_stack))
		return 0;

	json_object_object_foreach(jso, tkey, tval) {
		(void)tkey;

		switch (json_object_get_type(tval)) {
		case json_type_object:
			i++;
			break;
		default:
			break;
		}
	}

	if (i > 1)
		char_stack[l] = '|';
	else	
		char_stack[l] = ' ';

	printf("%s %d child objects\n", __func__, i);
	json_object_object_foreach(jso, key, val) {
		switch (json_object_get_type(val)) {
		case json_type_boolean:
		case json_type_double:
		case json_type_int:
		case json_type_string:
			sprintbuf(p, " %s:%s%s", key,
				json_object_to_json_string(val),
				(i > 1)  ? " " : "");
			break;
		case json_type_object:
			for (j = 0; j < l; j++)
				sprintbuf(p, "%c   ", char_stack[j]);

			l++;
			sprintbuf(p, "%c-- %s - %s\n",  (i > 1) ? '|' : '`',
				key, json_object_to_json_string(val));
			l--;
			break;
		case json_type_array:
			l++;
			sprintbuf(p, "%c-- %s - %s\n",  (i > 1) ? '|' : '`',
				key, json_object_to_json_string(val));
			l--;
			break;
		default:
			break;
		}
	}
	return 0;
}

static int display_str(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	const char *s = json_object_get_string(o);
	return printbuf_memappend(p, s, strlen(s));
}

static int display_int128(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	uint8_t *s = (uint8_t *)json_object_get_string(o);
	long double result = 0;
	char buf[40];
	int i;

	for (i = 15; i >= 0; i--)
		result = result * 256 + s[i];

	snprintf(buf, sizeof(buf), "%.0Lf", result);
	return printbuf_memappend(p, buf, strlen(buf));
}

static int display_0x(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	return sprintbuf(p, "%#llx", json_object_get_int64(o));
}

static int display_0x_str(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	printbuf_memappend(p, "\"", 1);
	display_0x(o, p, l, f);
	printbuf_memappend(p, "\"", 1);

	return 0;
}

static int display_hex(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	return sprintbuf(p, "%llx", json_object_get_int64(o));
}

static int display_hex_str(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	printbuf_memappend(p, "\"", 1);
	display_hex(o, p, l, f);
	printbuf_memappend(p, "\"", 1);

	return 0;
}

static int display_percent(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	return sprintbuf(p, "%u%%", json_object_get_int(o));
}

static int display_percent_str(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	printbuf_memappend(p, "\"", 1);
	display_percent(o, p, l, f);
	printbuf_memappend(p, "\"", 1);

	return 0;
}

static int display_temp_k(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	uint16_t k = json_object_get_int(o);
	return sprintbuf(p, "%uC (%.2fF %uK)", k - 273,
		((k - 273.15) * 9.0 / 5.0) + 32, k);
}

static int display_temp_k_str(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	printbuf_memappend(p, "\"", 1);
	display_temp_k(o, p, l, f);
	printbuf_memappend(p, "\"", 1);

	return 0;
}

static const char *tsuffix[] = {
	"µsec",
	"msec",
	"sec",
};

static int display_time_us(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	uint64_t d = 1, t, v = json_object_get_int64(o);
	int i = 0;

	t = v;
	for (i = 0; i < 2 && (t / d) >= 1000; i++)
		d *= 1000;

	t /= d;
	if (v % d)
		return sprintbuf(p, "%u.%u %s", t, v % d, tsuffix[i]);
	else
		return sprintbuf(p, "%u %s", t, tsuffix[i]);
}

static int display_time_us_str(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	printbuf_memappend(p, "\"", 1);
	display_time_us(o, p, l, f);
	printbuf_memappend(p, "\"", 1);

	return 0;
}

static int display_time_s(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	uint64_t m, h, d, v = json_object_get_int64(o);

	if (!v) {
		printbuf_memappend(p, "0", 1);
		return 0;
	}

	d = v / (24 * 60 * 60);
	v %= (24 * 60 * 60);

	h = v / (60 * 60);
	v %= (60 * 60);

	m = v / 60;
	v %= 60;

	if (d)
		sprintbuf(p, "%d day%s ", d, d > 1 ? "s" : "");
	if (h)
		sprintbuf(p, "%d hour%s ", h, h > 1 ? "s" : "");
	if (m)
		sprintbuf(p, "%d minute%s ", m, m > 1 ? "s" : "");
	if (v)
		sprintbuf(p, "%d second%s", v, v > 1 ? "s" : "");

	return 0;
}

static int display_time_s_str(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	printbuf_memappend(p, "\"", 1);
	display_time_s(o, p, l, f);
	printbuf_memappend(p, "\"", 1);

	return 0;
}

static int display_hu_watts(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	uint64_t v = json_object_get_int64(o);

	if (v % 1000)
		return sprintbuf(p, "%u.%04uW", v / 10000, v % 10000);
	return sprintbuf(p, "%u.%02uW", v / 10000, (v % 10000) / 100);
}

static int display_hu_watts_str(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	printbuf_memappend(p, "\"", 1);
	display_hu_watts(o, p, l, f);
	printbuf_memappend(p, "\"", 1);

	return 0;
}

static int display_bool_terse(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	return sprintbuf(p, "%c", json_object_get_boolean(o) ? '+' : '-');
}

static int display_uuid(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	char buf[40];
        uuid_t uuid;

	memcpy((void *)uuid, json_object_get_string(o),
		sizeof(uuid_t));
        uuid_unparse(uuid, buf);
	return printbuf_memappend(p, buf, strlen(buf));
}

static int display_uuid_str(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	printbuf_memappend(p, "\"", 1);
	display_uuid(o, p, l, f);
	printbuf_memappend(p, "\"", 1);

	return 1;
}

static int display_oui(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	uint8_t *value = (uint8_t *)json_object_get_string(o);
	int i, len = json_object_get_string_len(o);

	for (i = 0; i < len; i++)
		sprintbuf(p, "%s%02x", i ? "-" : "", value[i]);
	return 1;
}

static int display_oui_str(struct json_object *o, struct printbuf *p,
	int l, int f)
{
	printbuf_memappend(p, "\"", 1);
	display_oui(o, p, l, f);
	printbuf_memappend(p, "\"", 1);

	return 1;
}

static inline void fail_and_notify(void *o)
{
	if (o)
		return;
	fprintf(stderr,
		"Allocation of memory for json object failed, aborting\n");
	abort();
}

struct json_object *nvme_json_new_str_len(const char *v, int l)
{
	struct json_object *o = json_object_new_string_len(v, l);
	fail_and_notify(o);
	return o;
}

struct json_object *nvme_json_new_str_len_flags(const void *v, int l, unsigned long flags)
{
	struct json_object *o = nvme_json_new_str_len(v, l);
	if (flags & NVME_JSON_BINARY)
		json_object_set_serializer(o, display_binary, NULL, NULL);
	else if (flags & NVME_JSON_TABULAR)
		json_object_set_serializer(o, display_str, NULL, NULL);
	return o;
}

struct json_object *nvme_json_new_str(const char *v, unsigned long flags)
{
	struct json_object *o = json_object_new_string(v);
	fail_and_notify(o);
	if (flags & NVME_JSON_TABULAR)
		json_object_set_serializer(o, display_str, NULL, NULL);
	return o;
}

struct json_object *nvme_json_new_int128(uint8_t *v)
{
	struct json_object *o = nvme_json_new_str_len((const char *)v, 16);
	json_object_set_serializer(o, display_int128, NULL, NULL);
	return o;
}

struct json_object *nvme_json_new_int64(uint64_t v)
{
	struct json_object *o = json_object_new_int64(v);
	fail_and_notify(o);
	return o;
}

struct json_object *nvme_json_new_int(uint32_t v)
{
	struct json_object *o = json_object_new_int(v);
	fail_and_notify(o);
	return o;
}

struct json_object *nvme_json_new_bool(bool v)
{
	struct json_object *o = json_object_new_boolean(v);
	fail_and_notify(o);
	return o;
}

struct json_object *nvme_json_new_object(unsigned long flags)
{
	struct json_object *o = json_object_new_object();
	fail_and_notify(o);

	if (flags & NVME_JSON_COMPACT) {
		if (flags & NVME_JSON_TABULAR)
			json_object_set_serializer(o, display_compact_object, NULL, NULL);
		else
			json_object_set_serializer(o, display_compact_object_str, NULL, NULL);
	} else if (flags & NVME_JSON_TABULAR)
		json_object_set_serializer(o, display_tabular, NULL, NULL);

	return o;
}

struct json_object *nvme_json_new_array()
{
	struct json_object *o = json_object_new_array();
	fail_and_notify(o);
	return o;
}

struct json_object *nvme_json_new_storage_128(uint8_t *v, unsigned long flags)
{
	struct json_object *o = nvme_json_new_int128(v);

	if (flags & NVME_JSON_TABULAR)
		json_object_set_serializer(o, __display_human_size128, NULL, NULL);
	else
		json_object_set_serializer(o, __display_human_size128_str, NULL, NULL);
	return o;
}

struct json_object *nvme_json_new_storage(uint64_t v, unsigned long flags)
{
	struct json_object *o = nvme_json_new_int64(v);
	if (flags & NVME_JSON_TABULAR)
		json_object_set_serializer(o, __display_human_size, NULL, NULL);
	else
		json_object_set_serializer(o, __display_human_size_str, NULL, NULL);
	return o;
}

struct json_object *nvme_json_new_size(uint64_t v, unsigned long flags)
{
	struct json_object *o = nvme_json_new_int64(v);

	if (flags & NVME_JSON_TABULAR)
		json_object_set_serializer(o, _display_human_size, NULL, NULL);
	else
		json_object_set_serializer(o, _display_human_size_str, NULL, NULL);
	return o;
}

struct json_object *nvme_json_new_memory(uint64_t v, unsigned long flags)
{
	struct json_object *o = nvme_json_new_int64(v);

	if (flags & NVME_JSON_TABULAR)
		json_object_set_serializer(o, display_human_size, NULL, NULL);
	else
		json_object_set_serializer(o, display_human_size_str, NULL, NULL);
	return o;
}

struct json_object *nvme_json_new_hex_array(uint8_t *v, uint32_t l)
{
	struct json_object *o = nvme_json_new_str_len((const char *)v, l);
	json_object_set_serializer(o, display_hex_array_str, NULL, NULL);
	return o;
}

struct json_object *nvme_json_new_hex(uint64_t v, unsigned long flags)
{
	struct json_object *o = nvme_json_new_int64(v);

	if (flags & NVME_JSON_TABULAR)
		json_object_set_serializer(o, display_hex, NULL, NULL);
	else
		json_object_set_serializer(o, display_hex_str, NULL, NULL);
	return o;
}

struct json_object *nvme_json_new_0x(uint64_t v, unsigned long flags)
{
	struct json_object *o = nvme_json_new_int64(v);

	if (v && (flags & NVME_JSON_HUMAN)) {
		if (flags & NVME_JSON_TABULAR)
			json_object_set_serializer(o, display_0x, NULL, NULL);
		else
			json_object_set_serializer(o, display_0x_str, NULL, NULL);
	}
	return o;
}

struct json_object *nvme_json_new_percent(uint8_t v, unsigned long flags)
{
	struct json_object *o = nvme_json_new_int(v);
	if (flags & NVME_JSON_HUMAN) {
		if (flags & NVME_JSON_TABULAR)
			json_object_set_serializer(o, display_percent, NULL, NULL);
		else
			json_object_set_serializer(o, display_percent_str, NULL, NULL);
	}
	return o;
}

struct json_object *nvme_json_new_temp(uint16_t v, unsigned long flags)
{
	struct json_object *o = nvme_json_new_int(v);
	if (flags & NVME_JSON_HUMAN) {
		if (flags & NVME_JSON_TABULAR)
			json_object_set_serializer(o, display_temp_k, NULL, NULL);
		else
			json_object_set_serializer(o, display_temp_k_str, NULL, NULL);
	}
	return o;
}

struct json_object *nvme_json_new_time_us(uint64_t v, unsigned long flags)
{
	struct json_object *o = nvme_json_new_int64(v);

	if (flags & NVME_JSON_TABULAR)
		json_object_set_serializer(o, display_time_us, NULL, NULL);
	else
		json_object_set_serializer(o, display_time_us_str, NULL, NULL);
	return o;
}

struct json_object *nvme_json_new_time_s(uint64_t v, unsigned long flags)
{
	struct json_object *o = nvme_json_new_int64(v);

	if (flags & NVME_JSON_TABULAR)
		json_object_set_serializer(o, display_time_s, NULL, NULL);
	else
		json_object_set_serializer(o, display_time_s_str, NULL, NULL);
	return o;
}

struct json_object *nvme_json_new_hecto_uwatts(uint64_t v, unsigned long flags)
{
	struct json_object *o = nvme_json_new_int64(v);
	if (flags & NVME_JSON_TABULAR)
		json_object_set_serializer(o, display_hu_watts, NULL, NULL);
	else
		json_object_set_serializer(o, display_hu_watts_str, NULL, NULL);
	return o;
}

struct json_object *nvme_json_new_uuid(uint8_t *v, unsigned long flags)
{
	struct json_object *o = nvme_json_new_str_len((const char *)v, 16);

	if (flags & NVME_JSON_HUMAN) {
		if (flags & NVME_JSON_TABULAR)
			json_object_set_serializer(o, display_uuid, NULL, NULL);
		else
			json_object_set_serializer(o, display_uuid_str, NULL, NULL);
	} else {
		if (flags & NVME_JSON_TABULAR)
			json_object_set_serializer(o, display_hex_array, NULL, NULL);
		else
			json_object_set_serializer(o, display_hex_array_str, NULL, NULL);
	}
	return o;
}

struct json_object *nvme_json_new_oui(uint8_t *v, int len, unsigned long flags)
{
	struct json_object *o = nvme_json_new_str_len((const char *)v, len);
	if (flags & NVME_JSON_HUMAN) {
		if (flags & NVME_JSON_TABULAR)
			json_object_set_serializer(o, display_oui, NULL, NULL);
		else
			json_object_set_serializer(o, display_oui_str, NULL, NULL);
	} else {
		if (flags & NVME_JSON_TABULAR)
			json_object_set_serializer(o, display_hex_array, NULL, NULL);
		else
			json_object_set_serializer(o, display_hex_array_str, NULL, NULL);
	}
	return o;
}

struct json_object *nvme_json_new_bool_terse(bool v)
{
	struct json_object *o = nvme_json_new_bool(v);
	json_object_set_serializer(o, display_bool_terse, NULL, NULL);
	return o;
}

struct json_object *nvme_identify_directives_to_json(
	struct nvme_id_directives *idd, unsigned long flags)
{
	struct json_object *jidd, *js, *je;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(idd, sizeof(*idd), flags);

	jidd = nvme_json_new_object(flags);
	js = nvme_json_new_object(flags);
	je = nvme_json_new_object(flags);

	nvme_json_add_bool(js, "id", bit_set(idd->supported, NVME_ID_DIR_ID_BIT));
	nvme_json_add_bool(js, "sd", bit_set(idd->supported, NVME_ID_DIR_SD_BIT));
	json_object_object_add(jidd, "supported", js);

	nvme_json_add_bool(je, "id", bit_set(idd->enabled, NVME_ID_DIR_ID_BIT));
	nvme_json_add_bool(je, "sd", bit_set(idd->enabled, NVME_ID_DIR_SD_BIT));
	json_object_object_add(jidd, "enabled", je);

	return jidd;
}

struct json_object *nvme_streams_status_to_json(
	struct nvme_streams_directive_status *sds, unsigned long flags)
{
	struct json_object *jsds, *jsids;
	int i, psid = -1, osc = le16_to_cpu(sds->osc);

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(sds, sizeof(*sds), flags);

	jsds = nvme_json_new_object(flags);
	if (!jsds)
		return NULL;

	jsids = json_object_new_array();
	if (!jsids) {
		json_object_put(jsds);
		return NULL;
	}

	nvme_json_add_int(jsds, "osc", osc);
	for (i = 0; i < osc; i++) {
		struct json_object *jsid;
		__u16 sid;

		sid = le16_to_cpu(sds->sid[i]);
		if ((int)sid <= psid)
			break;

		psid = sid;
		jsid = json_object_new_int(sid);
		if (!jsid)
			break;

		json_object_array_add(jsids, jsid);
	}
	json_object_object_add(jsds, "sids", jsids);

	return jsds;
}

struct json_object *nvme_streams_params_to_json(
	struct nvme_streams_directive_params *sdp, unsigned long flags)
{
	struct json_object *jsdp;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(sdp, sizeof(*sdp), flags);

	jsdp = nvme_json_new_object(flags);
	if (!jsdp)
		return NULL;

	nvme_json_add_le16(jsdp, "msl", sdp->msl);
	nvme_json_add_le16(jsdp, "nssa", sdp->nssa);
	nvme_json_add_le16(jsdp, "nsso", sdp->nsso);
	nvme_json_add_int(jsdp, "nssc", sdp->nssc);
	nvme_json_add_le32(jsdp, "sws", sdp->sws);
	nvme_json_add_le16(jsdp, "sgs", sdp->sgs);
	nvme_json_add_le16(jsdp, "nsa", sdp->nsa);
	nvme_json_add_le16(jsdp, "nso", sdp->nso);

	return jsdp;
}

struct json_object *nvme_streams_allocated_to_json(__u16 nsa, unsigned long flags)
{
	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(&nsa, sizeof(nsa), flags);
	return nvme_json_new_int(nsa);
}

static json_object *nvme_feat_simple_to_json(__u8 fid, __u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_json_new_object(flags);
	nvme_json_add_int(jf, "feature-id", fid);
	nvme_json_add_str(jf, "feature", nvme_feature_str(fid), flags);
	nvme_json_add_int(jf, "value", value);

	return jf;
}

static json_object *nvme_feat_arbitration_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_ARBITRATION, value, flags);
	nvme_json_add_int(jf, "ab", NVME_FEAT_ARB_BURST(value));
	nvme_json_add_int(jf, "lpw", NVME_FEAT_ARB_LPW(value));
	nvme_json_add_int(jf, "mpw", NVME_FEAT_ARB_MPW(value));
	nvme_json_add_int(jf, "hpw", NVME_FEAT_ARB_HPW(value));

	return jf;
}

static json_object *nvme_feat_power_mgmt_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_POWER_MGMT, value, flags);
	nvme_json_add_int(jf, "ps", NVME_FEAT_PM_PS(value));
	nvme_json_add_int(jf, "wh", NVME_FEAT_PM_WH(value));

	return jf;
}

static json_object *nvme_lba_range_to_json(struct nvme_lba_range_type_entry *lbar,
	unsigned long flags)
{
	struct json_object *jlbar;

	jlbar = nvme_json_new_object(flags);

	nvme_json_add_int(jlbar, "type", lbar->type);
	nvme_json_add_int(jlbar, "attrs", lbar->attributes);
	nvme_json_add_le64(jlbar, "slba", lbar->slba);
	nvme_json_add_le64(jlbar, "nlb", lbar->nlb);
	nvme_json_add_hex_array(jlbar, "guid", (void *)lbar->guid, sizeof(lbar->guid));

	return jlbar;
}

static json_object *nvme_feat_lba_range_to_json(__u32 value,
	struct nvme_lba_range_type *lbar, unsigned long flags)
{
	struct json_object *jf, *jlbars;
	int i, num = NVME_FEAT_LBAR_NR(value);

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_LBA_RANGE, value, flags);
	nvme_json_add_int(jf, "num", num);

	jlbars = nvme_json_new_array();
	for (i = 0; i <= num; i++) {
		struct json_object *jlbar;

		jlbar = nvme_lba_range_to_json(&lbar->entry[i], flags);
		if (!jlbar)
			break;

		json_object_array_add(jlbars, jlbar);
	}
	json_object_object_add(jf, "ranges", jlbars);

	return jf;
}

static json_object *nvme_feat_temp_thresh_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_TEMP_THRESH, value, flags);
	nvme_json_add_int(jf, "tmpth", NVME_FEAT_TT_TMPTH(value));
	nvme_json_add_int(jf, "tmpsel", NVME_FEAT_TT_TMPSEL(value));
	nvme_json_add_int(jf, "thsel", NVME_FEAT_TT_THSEL(value));

	return jf;
}

static json_object *nvme_feat_err_recovery_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_ERR_RECOVERY, value, flags);
	nvme_json_add_int(jf, "tler", NVME_FEAT_ER_TLER(value));
	nvme_json_add_bool(jf, "dulbe", NVME_FEAT_ER_DULBE(value));

	return jf;
}

static json_object *nvme_feat_volatile_wc_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_VOLATILE_WC, value, flags);
	nvme_json_add_bool(jf, "wce", NVME_FEAT_VWC_WCE(value));

	return jf;
}

static json_object *nvme_feat_num_queues_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_NUM_QUEUES, value, flags);
	nvme_json_add_int(jf, "nsqr", NVME_FEAT_NRQS_NSQR(value));
	nvme_json_add_int(jf, "ncqr", NVME_FEAT_NRQS_NCQR(value));

	return jf;
}

static json_object *nvme_feat_irq_coalesce_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_IRQ_COALESCE, value, flags);
	nvme_json_add_int(jf, "thr", NVME_FEAT_ICOAL_THR(value));
	nvme_json_add_int(jf, "time", NVME_FEAT_ICOAL_TIME(value));

	return jf;
}

static json_object *nvme_feat_irq_config_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_IRQ_CONFIG, value, flags);
	nvme_json_add_int(jf, "iv", NVME_FEAT_ICFG_IV(value));
	nvme_json_add_bool(jf, "cd", NVME_FEAT_ICFG_CD(value));

	return jf;
}

static json_object *nvme_feat_write_atomic_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_WRITE_ATOMIC, value, flags);
	nvme_json_add_bool(jf, "dn", NVME_FEAT_WA_DN(value));

	return jf;
}

static json_object *nvme_feat_async_event_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_ASYNC_EVENT, value, flags);
	nvme_json_add_int(jf, "smart", NVME_FEAT_AE_SMART(value));
	nvme_json_add_bool(jf, "nan", NVME_FEAT_AE_NAN(value));
	nvme_json_add_bool(jf, "fw", NVME_FEAT_AE_FW(value));
	nvme_json_add_bool(jf, "telem", NVME_FEAT_AE_TELEM(value));
	nvme_json_add_bool(jf, "ana", NVME_FEAT_AE_ANA(value));
	nvme_json_add_bool(jf, "pla", NVME_FEAT_AE_PLA(value));
	nvme_json_add_bool(jf, "lbas", NVME_FEAT_AE_LBAS(value));
	nvme_json_add_bool(jf, "ega", NVME_FEAT_AE_EGA(value));

	return jf;
}

static json_object *nvme_apst_to_json(__u64 value, unsigned long flags)
{
	struct json_object *japst;

	japst = nvme_json_new_object(flags);
	nvme_json_add_int(japst, "itps", (value & NVME_APST_ENTRY_ITPS_MASK) >>
					  NVME_APST_ENTRY_ITPS_SHIFT);
	nvme_json_add_int(japst, "itpt", (value & NVME_APST_ENTRY_ITPT_MASK) >>
					  NVME_APST_ENTRY_ITPT_SHIFT);

	return japst;
}

static json_object *nvme_feat_auto_pst_to_json(__u32 value,
	struct nvme_feat_auto_pst *apst, unsigned long flags)
{
	struct json_object *jf, *japsts;
	int i;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_AUTO_PST, value, flags);
	nvme_json_add_bool(jf, "apste", NVME_FEAT_APST_APSTE(value));

	japsts = nvme_json_new_array();
	for (i = 0; i < 32; i++) {
		struct json_object *japst;

		japst = nvme_apst_to_json(le64_to_cpu(apst->apst_entry[i]), flags);
		if (!japst)
			break;

		json_object_array_add(japsts, japst);
	}
	json_object_object_add(jf, "entries", japsts);

	return jf;
}

static json_object *nvme_feat_host_mem_buf_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_HOST_MEM_BUF, value, flags);
	nvme_json_add_bool(jf, "ehm", NVME_FEAT_HMEM_EHM(value));

	return jf;
}

static json_object *nvme_feat_timestamp_to_json(__u32 value,
	struct nvme_timestamp *ts, unsigned long flags)
{
	int timestamp = unalign_int(ts->timestamp, sizeof(ts->timestamp));
	struct json_object *jf, *jtimestamp;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_TIMESTAMP, value, flags);
	jtimestamp = nvme_json_new_object(flags);

	nvme_json_add_int(jtimestamp, "timestamp", timestamp);
	nvme_json_add_int(jtimestamp, "sync", ts->attr & 1);
	nvme_json_add_int(jtimestamp, "origin", (ts->attr >> 1) & 0x7);

	return jf;
}

static json_object *nvme_feat_kato_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_KATO, value, flags);

	return jf;
}

static json_object *nvme_feat_hctm_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_HCTM, value, flags);
	nvme_json_add_int(jf, "tmt2", NVME_FEAT_HCTM_TMT2(value));
	nvme_json_add_int(jf, "tmt1", NVME_FEAT_HCTM_TMT1(value));

	return jf;
}

static json_object *nvme_feat_nopsc_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_NOPSC, value, flags);
	nvme_json_add_bool(jf, "noppme", NVME_FEAT_NOPS_NOPPME(value));

	return jf;
}

static json_object *nvme_feat_rrl_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_RRL, value, flags);
	nvme_json_add_int(jf, "rrl", NVME_FEAT_RRL_RRL(value));

	return jf;
}

static json_object *nvme_feat_plm_config_to_json(__u32 value,
	struct nvme_plm_config *plm, unsigned long flags)
{
	struct json_object *jf, *jplm;

	jplm = nvme_json_new_object(flags);
	nvme_json_add_le16(jplm, "ee", plm->ee);
	nvme_json_add_le64(jplm, "dtwinrt", plm->dtwinrt);
	nvme_json_add_le64(jplm, "dwtinwt", plm->dtwinwt);
	nvme_json_add_le64(jplm, "dwtintt", plm->dtwintt);

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_PLM_CONFIG, value, flags);
	nvme_json_add_bool(jf, "plme", NVME_FEAT_PLM_PLME(value));
	json_object_object_add(jf, "plmcfg", jplm);

	return jf;
}

static json_object *nvme_feat_plm_window_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_PLM_WINDOW, value, flags);
	nvme_json_add_int(jf, "ws", NVME_FEAT_PLMW_WS(value));

	return jf;
}

static json_object *nvme_feat_lba_sts_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_LBA_STS_INTERVAL, value, flags);
	nvme_json_add_int(jf, "lsiri", NVME_FEAT_LBAS_LSIRI(value));
	nvme_json_add_int(jf, "lsipi", NVME_FEAT_LBAS_LSIPI(value));

	return jf;
}

static json_object *nvme_feat_host_behavior_to_json(__u32 value,
	struct nvme_feat_host_behavior *host, unsigned long flags)
{
	struct json_object *jf, *jhost;

	jhost = nvme_json_new_object(flags);
	nvme_json_add_le16(jhost, "acre", host->acre);

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_HOST_BEHAVIOR, value, flags);
	json_object_object_add(jf, "hbs", jhost);

	return jf;
}

static json_object *nvme_feat_sanitize_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_SANITIZE, value, flags);
	nvme_json_add_bool(jf, "nodrm", NVME_FEAT_SC_NODRM(value));

	return jf;
}

static json_object *nvme_feat_endurance_evt_cfg_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_ENDURANCE_EVT_CFG, value, flags);
	nvme_json_add_int(jf, "endgid", NVME_FEAT_EG_ENDGID(value));
	nvme_json_add_int(jf, "endgcw", NVME_FEAT_EG_EGCW(value));

	return jf;
}

static json_object *nvme_feat_sw_progress_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_SW_PROGRESS, value, flags);
	nvme_json_add_int(jf, "pbslc", NVME_FEAT_SPM_PBSLC(value));

	return jf;
}

static json_object *nvme_feat_host_id_to_json(__u32 value,
	uint8_t *hostid, unsigned long flags)
{
	bool exhid = NVME_FEAT_HOSTID_EXHID(value);
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_HOST_ID, value, flags);
	nvme_json_add_bool(jf, "exhid", exhid);

	if (exhid)
		nvme_json_add_int128(jf, "hostid", (void *)hostid);
	else
		nvme_json_add_int64(jf, "hostid", read64(hostid));

	return jf;
}

static json_object *nvme_feat_resv_mask_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_RESV_MASK, value, flags);
	nvme_json_add_bool(jf, "regpre", NVME_FEAT_RM_REGPRE(value));
	nvme_json_add_bool(jf, "resrel", NVME_FEAT_RM_RESREL(value));
	nvme_json_add_bool(jf, "respre", NVME_FEAT_RM_RESPRE(value));

	return jf;
}

static json_object *nvme_feat_resv_persist_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_RESV_PERSIST, value, flags);
	nvme_json_add_bool(jf, "ptpl", NVME_FEAT_RP_PTPL(value));

	return jf;
}

static json_object *nvme_feat_write_protect_to_json(__u32 value,
	unsigned long flags)
{
	struct json_object *jf;

	jf = nvme_feat_simple_to_json(NVME_FEAT_FID_WRITE_PROTECT, value, flags);
	nvme_json_add_int(jf, "wps", NVME_FEAT_WP_WPS(value));

	return jf;
}

struct json_object *nvme_feature_to_json(__u8 fid, __u32 value, unsigned len,
	void *data, unsigned long flags)
{
	if (!(flags & NVME_JSON_DECODE_COMPLEX))
		return nvme_feat_simple_to_json(fid, value, flags);

	switch (fid) {
	case NVME_FEAT_FID_ARBITRATION:
		return nvme_feat_arbitration_to_json(value, flags);
	case NVME_FEAT_FID_POWER_MGMT:
		return nvme_feat_power_mgmt_to_json(value, flags);
	case NVME_FEAT_FID_LBA_RANGE:
		return nvme_feat_lba_range_to_json(value, data, flags);
	case NVME_FEAT_FID_TEMP_THRESH:
		return nvme_feat_temp_thresh_to_json(value, flags);
	case NVME_FEAT_FID_ERR_RECOVERY:
		return nvme_feat_err_recovery_to_json(value, flags);
	case NVME_FEAT_FID_VOLATILE_WC:
		return nvme_feat_volatile_wc_to_json(value, flags);
	case NVME_FEAT_FID_NUM_QUEUES:
		return nvme_feat_num_queues_to_json(value, flags);
	case NVME_FEAT_FID_IRQ_COALESCE:
		return nvme_feat_irq_coalesce_to_json(value, flags);
	case NVME_FEAT_FID_IRQ_CONFIG:
		return nvme_feat_irq_config_to_json(value, flags);
	case NVME_FEAT_FID_WRITE_ATOMIC:
		return nvme_feat_write_atomic_to_json(value, flags);
	case NVME_FEAT_FID_ASYNC_EVENT:
		return nvme_feat_async_event_to_json(value, flags);
	case NVME_FEAT_FID_AUTO_PST:
		return nvme_feat_auto_pst_to_json(value, data, flags);
	case NVME_FEAT_FID_HOST_MEM_BUF:
		return nvme_feat_host_mem_buf_to_json(value, flags);
	case NVME_FEAT_FID_TIMESTAMP:
		return nvme_feat_timestamp_to_json(value, data, flags);
	case NVME_FEAT_FID_KATO:
		return nvme_feat_kato_to_json(value, flags);
	case NVME_FEAT_FID_HCTM:
		return nvme_feat_hctm_to_json(value, flags);
	case NVME_FEAT_FID_NOPSC:
		return nvme_feat_nopsc_to_json(value, flags);
	case NVME_FEAT_FID_RRL:
		return nvme_feat_rrl_to_json(value, flags);
	case NVME_FEAT_FID_PLM_CONFIG:
		return nvme_feat_plm_config_to_json(value, data, flags);
	case NVME_FEAT_FID_PLM_WINDOW:
		return nvme_feat_plm_window_to_json(value, flags);
	case NVME_FEAT_FID_LBA_STS_INTERVAL:
		return nvme_feat_lba_sts_to_json(value, flags);
	case NVME_FEAT_FID_HOST_BEHAVIOR:
		return nvme_feat_host_behavior_to_json(value, data, flags);
	case NVME_FEAT_FID_SANITIZE:
		return nvme_feat_sanitize_to_json(value, flags);
	case NVME_FEAT_FID_ENDURANCE_EVT_CFG:
		return nvme_feat_endurance_evt_cfg_to_json(value, flags);
	case NVME_FEAT_FID_SW_PROGRESS:
		return nvme_feat_sw_progress_to_json(value, flags);
	case NVME_FEAT_FID_HOST_ID:
		return nvme_feat_host_id_to_json(value, data, flags);
	case NVME_FEAT_FID_RESV_MASK:
		return nvme_feat_resv_mask_to_json(value, flags);
	case NVME_FEAT_FID_RESV_PERSIST:
		return nvme_feat_resv_persist_to_json(value, flags);
	case NVME_FEAT_FID_WRITE_PROTECT:
		return nvme_feat_write_protect_to_json(value, flags);
	default:
		return NULL;
	}
}

static void nvme_json_add_id_ctrl_psd_human(struct json_object *j,
	struct nvme_id_psd *psd, unsigned long flags)
{
	struct json_object *jpsd = nvme_json_new_object(flags);

	bool mxps = is_set(psd->flags, NVME_PSD_FLAGS_MXPS);
	uint8_t ips = nvme_psd_power_scale(psd->ips);
	uint8_t aps = nvme_psd_power_scale(psd->aps);
	uint16_t mp = le16_to_cpu(psd->mp);
	uint16_t idlp = le16_to_cpu(psd->idlp);
	uint16_t actp = le16_to_cpu(psd->actp);

	switch (ips) {
	case 1:
		break;
	case 2:	
		idlp *= 100;
		break;
	default:
		idlp = 0;
		break;
	}

	switch (aps) {
	case 1:
		break;
	case 2:	
		actp *= 100;
		break;
	default:
		actp = 0;
		break;
	}

	if (!mxps)
		mp *= 100;

	nvme_json_add_power(jpsd, "mp", mp, flags);
	nvme_json_add_bool(jpsd, "mxps", mxps);
	nvme_json_add_flag(jpsd, "nops", psd->flags, NVME_PSD_FLAGS_NOPS);
	nvme_json_add_time_us_flags(jpsd, "enlat", le32_to_cpu(psd->enlat), flags);
	nvme_json_add_time_us_flags(jpsd, "exlat", le32_to_cpu(psd->exlat), flags);
	nvme_json_add_int(jpsd, "rrt", psd->rrt);
	nvme_json_add_int(jpsd, "rrl", psd->rrl);
	nvme_json_add_int(jpsd, "rwt", psd->rwt);
	nvme_json_add_int(jpsd, "rwl", psd->rwl);

	if (ips)
		nvme_json_add_power(jpsd, "idlp", idlp, flags);
	else
		nvme_json_add_bool(jpsd, "idlp", false);
	nvme_json_add_int(jpsd, "ips", ips);

	if (aps)
		nvme_json_add_power(jpsd, "actp", actp, flags);
	else
		nvme_json_add_bool(jpsd, "actp", false);
	nvme_json_add_int(jpsd, "apw", psd->apw);
	nvme_json_add_int(jpsd, "aps", aps);

	json_object_array_add(j, jpsd);
}

static void nvme_id_ctrl_psd_to_json(struct json_object *j,
	struct nvme_id_psd *psd, unsigned long flags)
{
	struct json_object *jpsd = nvme_json_new_object(flags);

	nvme_json_add_le16(jpsd, "mp", psd->mp);
	nvme_json_add_flag_flags(jpsd, "mxps", psd->flags, NVME_PSD_FLAGS_MXPS, flags);
	nvme_json_add_flag_flags(jpsd, "nops", psd->flags, NVME_PSD_FLAGS_NOPS, flags);
	nvme_json_add_le32(jpsd, "enlat", psd->enlat);
	nvme_json_add_le32(jpsd, "exlat", psd->exlat);
	nvme_json_add_int(jpsd, "rrt", psd->rrt);
	nvme_json_add_int(jpsd, "rrl", psd->rrl);
	nvme_json_add_int(jpsd, "rwt", psd->rwt);
	nvme_json_add_int(jpsd, "rwl", psd->rwl);
	nvme_json_add_le16(jpsd, "idlp", psd->idlp);
	nvme_json_add_int(jpsd, "ips", nvme_psd_power_scale(psd->ips));
	nvme_json_add_le16(jpsd, "actp", psd->actp);
	nvme_json_add_int(jpsd, "apw", psd->apw);
	nvme_json_add_int(jpsd, "aps", nvme_psd_power_scale(psd->aps));

	json_object_array_add(j, jpsd);
}

static void nvme_json_add_id_ctrl_psd(struct json_object *j,
	struct nvme_id_psd *psd, unsigned long flags)
{
	if (flags & NVME_JSON_HUMAN)
		return nvme_json_add_id_ctrl_psd_human(j, psd, flags);
	return nvme_id_ctrl_psd_to_json(j, psd, flags);
}

static void nvme_json_add_id_ctrl_ieee(struct json_object *j, const char *n,
					     __u8 *ieee, unsigned long flags)
{
	/*
	 * See nvme specification 1.4 section 7.10.3 for why this byte swapping
	 * is done.
	 */
	uint8_t i[3] = { ieee[2], ieee[1], ieee[0] };

	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_oui(j, n, i, 3, flags);
	else
		nvme_json_add_int(j, n, nvme_ieee_to_int(ieee));
}

static void nvme_json_add_id_ctrl_cmic(struct json_object *j, const char *n,
					      __u8 cmic, unsigned long flags)
{
	struct json_object *jcmic;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, cmic, flags);
		return;
	}

	jcmic = nvme_json_new_object(flags);

	nvme_json_add_0x(jcmic, "value", cmic, flags);
	nvme_json_add_flag_flags(jcmic, "mport", cmic, NVME_CTRL_CMIC_MULTI_PORT, flags);
	nvme_json_add_flag_flags(jcmic, "mctrl", cmic, NVME_CTRL_CMIC_MULTI_CTRL, flags);
	nvme_json_add_flag_flags(jcmic, "virtual", cmic, NVME_CTRL_CMIC_MULTI_SRIOV, flags);
	nvme_json_add_flag_flags(jcmic, "anarep", cmic, NVME_CTRL_CMIC_MULTI_ANA_REPORTING, flags);

	json_object_object_add(j, n, jcmic);
}

static void nvme_json_add_id_ctrl_mdts(struct json_object *j, const char *n,
				__u8 mdts, unsigned long flags)
{
	uint64_t m = mdts ? (1ULL << (12ULL + mdts)) : 0;

	if (!(flags & NVME_JSON_HUMAN))
		nvme_json_add_int(j, n, mdts);
	else if (m)
		nvme_json_add_memory(j, n, m, flags);
	else
		nvme_json_add_str(j, n, "No Limit", flags);
}

static void nvme_json_add_id_ctrl_ver(struct json_object *j, const char *n,
				__u32 ver, unsigned long flags)
{
	char buf[16];

	if (!(flags & NVME_JSON_HUMAN)) {
		nvme_json_add_int(j, n, ver);
		return;
	}

	if (NVME_TERTIARY(ver))
		sprintf(buf, "%u.%u.%u", NVME_MAJOR(ver), NVME_MINOR(ver),
			NVME_TERTIARY(ver));
	else
		sprintf(buf, "%u.%u", NVME_MAJOR(ver), NVME_MINOR(ver));
	nvme_json_add_str(j, n, buf, flags);
}

static void nvme_json_add_id_ctrl_oaes(struct json_object *j, const char *n,
				      __u32 oaes, unsigned long flags)
{
	struct json_object *joaes;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, oaes, flags);
		return;
	}

	joaes = nvme_json_new_object(flags);

	nvme_json_add_0x(joaes, "value", oaes, flags);
	nvme_json_add_flag_flags(joaes, "nsattr", oaes, NVME_CTRL_OAES_NA, flags);
	nvme_json_add_flag_flags(joaes, "frmwa", oaes, NVME_CTRL_OAES_FA, flags);
	nvme_json_add_flag_flags(joaes, "anachg", oaes, NVME_CTRL_OAES_ANA, flags);
	nvme_json_add_flag_flags(joaes, "ple", oaes, NVME_CTRL_OAES_PLEA, flags);
	nvme_json_add_flag_flags(joaes, "lbasts", oaes, NVME_CTRL_OAES_LBAS, flags);
	nvme_json_add_flag_flags(joaes, "ege", oaes, NVME_CTRL_OAES_EGE, flags);

	json_object_object_add(j, n, joaes);
}

static void nvme_json_add_id_ctrl_ctratt(struct json_object *j, const char *n,
				      __u32 ctratt, unsigned long flags)
{
	struct json_object *jctratt;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, ctratt, flags);
		return;
	}

	jctratt = nvme_json_new_object(flags);

	nvme_json_add_0x(jctratt, "value", ctratt, flags);
	nvme_json_add_flag_flags(jctratt, "hostid-128", ctratt, NVME_CTRL_CTRATT_128_ID, flags);
	nvme_json_add_flag_flags(jctratt, "nopspm", ctratt, NVME_CTRL_CTRATT_NON_OP_PSP, flags);
	nvme_json_add_flag_flags(jctratt, "nvmsets", ctratt, NVME_CTRL_CTRATT_NVM_SETS, flags);
	nvme_json_add_flag_flags(jctratt, "rrl", ctratt, NVME_CTRL_CTRATT_READ_RECV_LVLS, flags);
	nvme_json_add_flag_flags(jctratt, "eg", ctratt, NVME_CTRL_CTRATT_ENDURANCE_GROUPS, flags);
	nvme_json_add_flag_flags(jctratt, "plm", ctratt, NVME_CTRL_CTRATT_PREDICTABLE_LAT, flags);
	nvme_json_add_flag_flags(jctratt, "tbkas", ctratt, NVME_CTRL_CTRATT_TBKAS, flags);
	nvme_json_add_flag_flags(jctratt, "ng", ctratt, NVME_CTRL_CTRATT_NAMESPACE_GRANULARITY, flags);
	nvme_json_add_flag_flags(jctratt, "sqa", ctratt, NVME_CTRL_CTRATT_SQ_ASSOCIATIONS, flags);
	nvme_json_add_flag_flags(jctratt, "uuid", ctratt, NVME_CTRL_CTRATT_UUID_LIST, flags);

	json_object_object_add(j, n, jctratt);
}

static void nvme_json_add_id_ctrl_cntrltype(struct json_object *j, const char *n,
					    __u8 cntrltype, unsigned long flags)
{
	const char *type;

	if (!(flags & NVME_JSON_HUMAN)) {
		nvme_json_add_int(j, n, cntrltype);
		return;
	}

	type = nvme_id_ctrl_cntrltype_str(cntrltype);
	nvme_json_add_str(j, n, type, flags);
}
static void nvme_json_add_id_ctrl_oacs(struct json_object *j, const char *n,
				__u16 oacs, unsigned long flags)
{
	struct json_object *joacs;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, oacs, flags);
		return;
	}

	joacs = nvme_json_new_object(flags);

	nvme_json_add_0x(joacs, "value", oacs, flags);
	nvme_json_add_flag_flags(joacs, "security", oacs, NVME_CTRL_OACS_SECURITY, flags);
	nvme_json_add_flag_flags(joacs, "format-nvm", oacs, NVME_CTRL_OACS_FORMAT, flags);
	nvme_json_add_flag_flags(joacs, "firmware", oacs, NVME_CTRL_OACS_FW, flags);
	nvme_json_add_flag_flags(joacs, "ns-mgmt", oacs, NVME_CTRL_OACS_NS_MGMT, flags);
	nvme_json_add_flag_flags(joacs, "dev-self-test", oacs, NVME_CTRL_OACS_SELF_TEST, flags);
	nvme_json_add_flag_flags(joacs, "directives", oacs, NVME_CTRL_OACS_DIRECTIVES, flags);
	nvme_json_add_flag_flags(joacs, "nvme-mi", oacs, NVME_CTRL_OACS_NVME_MI, flags);
	nvme_json_add_flag_flags(joacs, "virt-mgmt", oacs, NVME_CTRL_OACS_VIRT_MGMT, flags);
	nvme_json_add_flag_flags(joacs, "doorbell-buf-cfg", oacs, NVME_CTRL_OACS_DBBUF_CFG, flags);
	nvme_json_add_flag_flags(joacs, "get-lba-status", oacs, NVME_CTRL_OACS_LBA_STATUS, flags);

	json_object_object_add(j, n, joacs);
}

static void nvme_json_add_id_ctrl_frmw(struct json_object *j, const char *n,
				__u8 frmw, unsigned long flags)
{
	struct json_object *jfrmw;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, frmw, flags);
		return;
	}

	jfrmw = nvme_json_new_object(flags);

	nvme_json_add_0x(jfrmw, "value", frmw, flags);
	nvme_json_add_flag_flags(jfrmw, "first-slot-ro", frmw, NVME_CTRL_FRMW_1ST_RO, flags);
	nvme_json_add_int(jfrmw, "num-slots", (frmw & NVME_CTRL_FRMW_NR_SLOTS) >> 1);
	nvme_json_add_flag_flags(jfrmw, "activate-no-reset", frmw, NVME_CTRL_FRMW_FW_ACT_NO_RESET, flags);

	json_object_object_add(j, n, jfrmw);
}

static void nvme_json_add_id_ctrl_lpa(struct json_object *j, const char *n,
				__u8 lpa, unsigned long flags)
{
	struct json_object *jlpa;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, lpa, flags);
		return;
	}

	jlpa = nvme_json_new_object(flags);

	nvme_json_add_0x(jlpa, "value", lpa, flags);
	nvme_json_add_flag_flags(jlpa, "smart-per-namespace", lpa, NVME_CTRL_LPA_SMART_PER_NS, flags);
	nvme_json_add_flag_flags(jlpa, "command-effects", lpa, NVME_CTRL_LPA_CMD_EFFECTS, flags);
	nvme_json_add_flag_flags(jlpa, "extended", lpa, NVME_CTRL_LPA_EXTENDED, flags);
	nvme_json_add_flag_flags(jlpa, "telemetry", lpa, NVME_CTRL_LPA_TELEMETRY, flags);
	nvme_json_add_flag_flags(jlpa, "persistent-event", lpa, NVME_CTRL_LPA_PERSETENT_EVENT, flags);

	json_object_object_add(j, n, jlpa);
}

static void nvme_json_add_id_ctrl_avscc(struct json_object *j, const char *n,
				__u8 avscc, unsigned long flags)
{
	struct json_object *javscc;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, avscc, flags);
		return;
	}

	javscc = nvme_json_new_object(flags);

	nvme_json_add_0x(javscc, "value", avscc, flags);
	nvme_json_add_flag_flags(javscc, "avs-format", avscc, NVME_CTRL_AVSCC_AVS, flags);

	json_object_object_add(j, n, javscc);
}

static void nvme_json_add_id_ctrl_apsta(struct json_object *j, const char *n,
				__u8 apsta, unsigned long flags)
{
	struct json_object *japsta;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, apsta, flags);
		return;
	}

	japsta = nvme_json_new_object(flags);

	nvme_json_add_0x(japsta, "value", apsta, flags);
	nvme_json_add_flag_flags(japsta, "apst", apsta, NVME_CTRL_APSTA_APST, flags);

	json_object_object_add(j, n, japsta);
}

static void nvme_json_add_id_ctrl_4k_mem(struct json_object *j, const char *n,
				__u32 size, unsigned long flags)
{
	uint64_t m = size * 4096;
	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_memory(j, n, m, flags);
	else
		nvme_json_add_int(j, n, size);
}

static void nvme_json_add_id_ctrl_64k_mem(struct json_object *j, const char *n,
				__u32 size, unsigned long flags)
{
	uint64_t m = size * 64 * 1024ULL;
	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_memory(j, n, m, flags);
	else
		nvme_json_add_int(j, n, size);
}

static void nvme_json_add_id_ctrl_16_mem(struct json_object *j, const char *n,
				__u32 size, unsigned long flags)
{
	uint64_t m = size * 16;
	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_memory(j, n, m, flags);
	else
		nvme_json_add_int(j, n, size);
}

static void nvme_json_add_id_ctrl_rpmbs(struct json_object *j, const char *n,
				__u32 rpmbs, unsigned long flags)
{
	struct json_object *jrpmbs;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, rpmbs, flags);
		return;
	}

	jrpmbs = nvme_json_new_object(flags);

	nvme_json_add_0x(jrpmbs, "value", rpmbs, flags);
	nvme_json_add_int(jrpmbs, "number-of-units", rpmbs & NVME_CTRL_RPMBS_NR_UNITS);
	nvme_json_add_int(jrpmbs, "authentication-method", (rpmbs & NVME_CTRL_RPMBS_AUTH_METHOD) >> 3);
	nvme_json_add_int(jrpmbs, "total-size", (rpmbs & NVME_CTRL_RPMBS_TOTAL_SIZE) >> 16);
	nvme_json_add_int(jrpmbs, "access-size", (rpmbs & NVME_CTRL_RPMBS_ACCESS_SIZE) >> 24);

	json_object_object_add(j, n, jrpmbs);
}

static void nvme_json_add_id_ctrl_dsto(struct json_object *j, const char *n,
				__u8 dsto, unsigned long flags)
{
	struct json_object *jdsto;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, dsto, flags);
		return;
	}

	jdsto = nvme_json_new_object(flags);

	nvme_json_add_0x(jdsto, "value", dsto, flags);
	nvme_json_add_flag_flags(jdsto, "one-dst", dsto, NVME_CTRL_DSTO_ONE_DST, flags);

	json_object_object_add(j, n, jdsto);
}

static void nvme_json_add_id_ctrl_hctma(struct json_object *j, const char *n,
				__u32 hctma, unsigned long flags)
{
	struct json_object *jhctma;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, hctma, flags);
		return;
	}

	jhctma = nvme_json_new_object(flags);

	nvme_json_add_0x(jhctma, "value", hctma, flags);
	nvme_json_add_flag_flags(jhctma, "hctm", hctma, NVME_CTRL_HCTMA_HCTM, flags);

	json_object_object_add(j, n, jhctma);
}

static void nvme_json_add_id_ctrl_sanicap(struct json_object *j, const char *n,
				__u32 sanicap, unsigned long flags)
{
	struct json_object *jsanicap;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, sanicap, flags);
		return;
	}

	jsanicap = nvme_json_new_object(flags);

	nvme_json_add_0x(jsanicap, "value", sanicap, flags);
	nvme_json_add_flag_flags(jsanicap, "ces", sanicap, NVME_CTRL_SANICAP_CES, flags);
	nvme_json_add_flag_flags(jsanicap, "bes", sanicap, NVME_CTRL_SANICAP_BES, flags);
	nvme_json_add_flag_flags(jsanicap, "ows", sanicap, NVME_CTRL_SANICAP_OWS, flags);
	nvme_json_add_flag_flags(jsanicap, "ndi", sanicap, NVME_CTRL_SANICAP_NDI, flags);
	nvme_json_add_int(jsanicap, "nodmmas", (sanicap & NVME_CTRL_SANICAP_NODMMAS) >> 30);

	json_object_object_add(j, n, jsanicap);
}

static void nvme_json_add_id_ctrl_anacap(struct json_object *j, const char *n,
				__u8 anacap, unsigned long flags)
{
	struct json_object *janacap;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, anacap, flags);
		return;
	}

	janacap = nvme_json_new_object(flags);

	nvme_json_add_0x(janacap, "value", anacap, flags);
	nvme_json_add_flag_flags(janacap, "optimal", anacap, NVME_CTRL_ANACAP_OPT, flags);
	nvme_json_add_flag_flags(janacap, "non-optimal", anacap, NVME_CTRL_ANACAP_NON_OPT, flags);
	nvme_json_add_flag_flags(janacap, "inaccessible", anacap, NVME_CTRL_ANACAP_INACCESSIBLE, flags);
	nvme_json_add_flag_flags(janacap, "persistent-loss", anacap, NVME_CTRL_ANACAP_PERSISTENT_LOSS, flags);
	nvme_json_add_flag_flags(janacap, "change", anacap, NVME_CTRL_ANACAP_CHANGE, flags);
	nvme_json_add_flag_flags(janacap, "grpid-not-changable", anacap, NVME_CTRL_ANACAP_GRPID_NO_CHG, flags);
	nvme_json_add_flag_flags(janacap, "grpid-ns-mgmt", anacap, NVME_CTRL_ANACAP_GRPID_MGMT, flags);

	json_object_object_add(j, n, janacap);
}

static void nvme_json_add_id_ctrl_sqes(struct json_object *j, const char *n,
				__u8 sqes, unsigned long flags)
{
	struct json_object *jsqes;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, sqes, flags);
		return;
	}

	jsqes = nvme_json_new_object(flags);

	nvme_json_add_0x(jsqes, "value", sqes, flags);
	nvme_json_add_int(jsqes, "sqes-min", sqes & NVME_CTRL_SQES_MIN);
	nvme_json_add_int(jsqes, "sqes-max", (sqes & NVME_CTRL_SQES_MAX) >> 4);

	json_object_object_add(j, n, jsqes);
}

static void nvme_json_add_id_ctrl_cqes(struct json_object *j, const char *n,
				__u8 cqes, unsigned long flags)
{
	struct json_object *jcqes;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, cqes, flags);
		return;
	}

	jcqes = nvme_json_new_object(flags);

	nvme_json_add_0x(jcqes, "value", cqes, flags);
	nvme_json_add_int(jcqes, "cqes-min", cqes & NVME_CTRL_CQES_MIN);
	nvme_json_add_int(jcqes, "cqes-max", (cqes & NVME_CTRL_CQES_MAX) >> 4);

	json_object_object_add(j, n, jcqes);
}

static void nvme_json_add_id_ctrl_oncs(struct json_object *j, const char *n,
				__u16 oncs, unsigned long flags)
{
	struct json_object *joncs;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, oncs, flags);
		return;
	}

	joncs = nvme_json_new_object(flags);

	nvme_json_add_0x(joncs, "value", oncs, flags);
	nvme_json_add_flag_flags(joncs, "compare", oncs, NVME_CTRL_ONCS_COMPARE, flags);
	nvme_json_add_flag_flags(joncs, "write-uncorrectable", oncs, NVME_CTRL_ONCS_WRITE_UNCORRECTABLE, flags);
	nvme_json_add_flag_flags(joncs, "data-set-mgmt", oncs, NVME_CTRL_ONCS_DSM, flags);
	nvme_json_add_flag_flags(joncs, "write-zeroes", oncs, NVME_CTRL_ONCS_WRITE_ZEROES, flags);
	nvme_json_add_flag_flags(joncs, "save-features", oncs, NVME_CTRL_ONCS_SAVE_FEATURES, flags);
	nvme_json_add_flag_flags(joncs, "reservations", oncs, NVME_CTRL_ONCS_RESERVATIONS, flags);
	nvme_json_add_flag_flags(joncs, "timestamp", oncs, NVME_CTRL_ONCS_TIMESTAMP, flags);
	nvme_json_add_flag_flags(joncs, "verify", oncs, NVME_CTRL_ONCS_VERIFY, flags);

	json_object_object_add(j, n, joncs);
}

static void nvme_json_add_id_ctrl_fuses(struct json_object *j, const char *n,
				__u16 fuses, unsigned long flags)
{
	struct json_object *jfuses;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, fuses, flags);
		return;
	}

	jfuses = nvme_json_new_object(flags);

	nvme_json_add_0x(jfuses, "value", fuses, flags);
	nvme_json_add_flag_flags(jfuses, "compare", fuses, NVME_CTRL_FUSES_COMPARE_AND_WRITE, flags);

	json_object_object_add(j, n, jfuses);
}

static void nvme_json_add_id_ctrl_fna(struct json_object *j, const char *n,
				__u8 fna, unsigned long flags)
{
	struct json_object *jfna;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, fna, flags);
		return;
	}

	jfna = nvme_json_new_object(flags);

	nvme_json_add_0x(jfna, "value", fna, flags);
	nvme_json_add_flag_flags(jfna, "format-all-ns", fna, NVME_CTRL_FNA_FMT_ALL_NAMESPACES, flags);
	nvme_json_add_flag_flags(jfna, "secure-erase-all-ns", fna, NVME_CTRL_FNA_SEC_ALL_NAMESPACES, flags);
	nvme_json_add_flag_flags(jfna, "crypto-erasens", fna, NVME_CTRL_FNA_CRYPTO_ERASE, flags);

	json_object_object_add(j, n, jfna);
}

static void nvme_json_add_id_ctrl_vwc(struct json_object *j, const char *n,
				__u8 vwc, unsigned long flags)
{
	struct json_object *jvwc;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, vwc, flags);
		return;
	}

	jvwc = nvme_json_new_object(flags);

	nvme_json_add_0x(jvwc, "value", vwc, flags);
	nvme_json_add_flag_flags(jvwc, "present", vwc, NVME_CTRL_VWC_PRESENT, flags);
	nvme_json_add_flag_flags(jvwc, "flush-behavior", vwc, NVME_CTRL_VWC_FLUSH, flags);

	json_object_object_add(j, n, jvwc);
}

static void nvme_json_add_id_ctrl_nvscc(struct json_object *j, const char *n,
				__u8 nvscc, unsigned long flags)
{
	struct json_object *jnvscc;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, nvscc, flags);
		return;
	}

	jnvscc = nvme_json_new_object(flags);

	nvme_json_add_0x(jnvscc, "value", nvscc, flags);
	nvme_json_add_flag_flags(jnvscc, "nvmvs-format", nvscc, NVME_CTRL_NVSCC_FMT, flags);

	json_object_object_add(j, n, jnvscc);
}

static void nvme_json_add_id_ctrl_nwpc(struct json_object *j, const char *n,
				__u8 nwpc, unsigned long flags)
{
	struct json_object *jnwpc;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, nwpc, flags);
		return;
	}

	jnwpc = nvme_json_new_object(flags);

	nvme_json_add_0x(jnwpc, "value", nwpc, flags);
	nvme_json_add_flag_flags(jnwpc, "wp", nwpc, NVME_CTRL_NWPC_WRITE_PROTECT, flags);
	nvme_json_add_flag_flags(jnwpc, "wpupc", nwpc, NVME_CTRL_NWPC_WRITE_PROTECT_POWER_CYCLE, flags);
	nvme_json_add_flag_flags(jnwpc, "pwp", nwpc, NVME_CTRL_NWPC_WRITE_PROTECT_PERMANENT, flags);

	json_object_object_add(j, n, jnwpc);
}

static void nvme_json_add_id_ctrl_sgls(struct json_object *j, const char *n,
				__u32 sgls, unsigned long flags)
{
	struct json_object *jsgls;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, sgls, flags);
		return;
	}

	jsgls = nvme_json_new_object(flags);

	nvme_json_add_0x(jsgls, "value", sgls, flags);
	nvme_json_add_int(jsgls, "supports", sgls & NVME_CTRL_SGLS_SUPPORTED);
	nvme_json_add_flag_flags(jsgls, "keyed", sgls, NVME_CTRL_SGLS_KEYED, flags);
	nvme_json_add_flag_flags(jsgls, "bitbucket", sgls, NVME_CTRL_SGLS_BIT_BUCKET, flags);
	nvme_json_add_flag_flags(jsgls, "aligned", sgls, NVME_CTRL_SGLS_MPTR_BYTE_ALIGNED, flags);
	nvme_json_add_flag_flags(jsgls, "oversize", sgls, NVME_CTRL_SGLS_OVERSIZE, flags);
	nvme_json_add_flag_flags(jsgls, "mptrsgl", sgls, NVME_CTRL_SGLS_MPTR_SGL, flags);
	nvme_json_add_flag_flags(jsgls, "offets", sgls, NVME_CTRL_SGLS_OFFSET, flags);
	nvme_json_add_flag_flags(jsgls, "tportdesc", sgls, NVME_CTRL_SGLS_TPORT, flags);

	json_object_object_add(j, n, jsgls);
}

static void nvme_json_add_id_ctrl_fcatt(struct json_object *j, const char *n,
				__u8 fcatt, unsigned long flags)
{
	struct json_object *jfcatt;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, fcatt, flags);
		return;
	}

	jfcatt = nvme_json_new_object(flags);

	nvme_json_add_0x(jfcatt, "value", fcatt, flags);
	nvme_json_add_flag_flags(jfcatt, "dynamic-subsystem", fcatt, NVME_CTRL_FCATT_DYNAMIC, flags);

	json_object_object_add(j, n, jfcatt);
}

static void nvme_json_add_id_ctrl_ofcs(struct json_object *j, const char *n,
				__u8 ofcs, unsigned long flags)
{
	struct json_object *jofcs;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, ofcs, flags);
		return;
	}

	jofcs = nvme_json_new_object(flags);

	nvme_json_add_0x(jofcs, "value", ofcs, flags);
	nvme_json_add_flag_flags(jofcs, "disconnect-support", ofcs, NVME_CTRL_OFCS_DISCONNECT, flags);

	json_object_object_add(j, n, jofcs);
}

struct json_object *nvme_id_ctrl_to_json(
	struct nvme_id_ctrl *id, unsigned long flags)
{
	struct json_object *jctrl, *jpsds;
	int i;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(id, sizeof(*id), flags);

	jctrl = nvme_json_new_object(flags);

	nvme_json_add_hex_le16_flags(jctrl, "vid", id->vid, flags);
	nvme_json_add_hex_le16_flags(jctrl, "ssvid", id->ssvid, flags);
	nvme_json_add_str_flags(jctrl, "sn", id->sn, sizeof(id->sn), flags);
	nvme_json_add_str_flags(jctrl, "mn", id->mn, sizeof(id->mn), flags);
	nvme_json_add_str_flags(jctrl, "fr", id->fr, sizeof(id->fr), flags);
	nvme_json_add_int(jctrl, "rab", id->rab);
	nvme_json_add_id_ctrl_ieee(jctrl, "ieee", id->ieee, flags);
	nvme_json_add_id_ctrl_cmic(jctrl, "cmic", id->cmic, flags);
	nvme_json_add_id_ctrl_mdts(jctrl, "mdts", id->mdts, flags);
	nvme_json_add_le16(jctrl, "cntlid", id->cntlid);
	nvme_json_add_id_ctrl_ver(jctrl, "ver", le32_to_cpu(id->ver), flags);
	nvme_json_add_time_us_flags(jctrl, "rtd3r", le32_to_cpu(id->rtd3r), flags);
	nvme_json_add_time_us_flags(jctrl, "rtd3e", le32_to_cpu(id->rtd3e), flags);
	nvme_json_add_id_ctrl_oaes(jctrl, "oaes", le32_to_cpu(id->oaes), flags);
	nvme_json_add_id_ctrl_ctratt(jctrl, "ctratt", le32_to_cpu(id->ctratt), flags);
	nvme_json_add_0x(jctrl, "rrls", le16_to_cpu(id->rrls), flags);
	nvme_json_add_id_ctrl_cntrltype(jctrl, "cntrltype", id->cntrltype, flags);
	nvme_json_add_uuid(jctrl, "fguid", id->fguid, flags);
	nvme_json_add_time_100us_flags(jctrl, "crdt1", le16_to_cpu(id->crdt1), flags);
	nvme_json_add_time_100us_flags(jctrl, "crdt2", le16_to_cpu(id->crdt2), flags);
	nvme_json_add_time_100us_flags(jctrl, "crdt3", le16_to_cpu(id->crdt3), flags);
	nvme_json_add_0x(jctrl, "nvmsr", id->nvmsr, flags);
	nvme_json_add_0x(jctrl, "vwci", id->vwci, flags);
	nvme_json_add_0x(jctrl, "mec", id->mec, flags);
	nvme_json_add_id_ctrl_oacs(jctrl, "oacs", le16_to_cpu(id->oacs), flags);
	nvme_json_add_int(jctrl, "acl", id->acl);
	nvme_json_add_int(jctrl, "aerl", id->aerl);
	nvme_json_add_id_ctrl_frmw(jctrl, "frmw", id->frmw, flags);
	nvme_json_add_id_ctrl_lpa(jctrl, "lpa", id->lpa, flags);
	nvme_json_add_int(jctrl, "elpe", id->elpe);
	nvme_json_add_int(jctrl, "npss", id->npss);
	nvme_json_add_id_ctrl_avscc(jctrl, "avscc", id->avscc, flags);
	nvme_json_add_id_ctrl_apsta(jctrl, "apsta", id->apsta, flags);
	nvme_json_add_temp(jctrl, "wctemp", id->wctemp, flags);
	nvme_json_add_temp(jctrl, "cctemp", id->cctemp, flags);
	nvme_json_add_time_100us_flags(jctrl, "mtfa", le32_to_cpu(id->mtfa), flags);
	nvme_json_add_id_ctrl_4k_mem(jctrl, "hmpre",  le32_to_cpu(id->hmpre), flags);
	nvme_json_add_id_ctrl_4k_mem(jctrl, "hmmin",  le32_to_cpu(id->hmmin), flags);
	nvme_json_add_storage_128_flags(jctrl, "tnvmcap", id->tnvmcap, flags);
	nvme_json_add_storage_128_flags(jctrl, "unvmcap", id->unvmcap, flags);
	nvme_json_add_id_ctrl_rpmbs(jctrl, "rpmbs",  le32_to_cpu(id->rpmbs), flags);
	nvme_json_add_time_m_flags(jctrl, "edstt", le16_to_cpu(id->edstt), flags);
	nvme_json_add_id_ctrl_dsto(jctrl, "dsto", id->dsto, flags);
	nvme_json_add_id_ctrl_4k_mem(jctrl, "fwug", id->fwug, flags);
	nvme_json_add_time_100us_flags(jctrl, "kas", le16_to_cpu(id->kas), flags);
	nvme_json_add_id_ctrl_hctma(jctrl, "hctma", le16_to_cpu(id->hctma), flags);
	nvme_json_add_temp(jctrl, "mntmt", le16_to_cpu(id->mntmt), flags);
	nvme_json_add_temp(jctrl, "mxtmt", le16_to_cpu(id->mxtmt), flags);
	nvme_json_add_id_ctrl_sanicap(jctrl, "sanicap", le32_to_cpu(id->sanicap), flags);
	nvme_json_add_id_ctrl_4k_mem(jctrl, "hmminds", le32_to_cpu(id->hmminds), flags);
	nvme_json_add_le16(jctrl, "hmmaxd", id->hmmaxd);
	nvme_json_add_le16(jctrl, "nsetidmax", id->nsetidmax);
	nvme_json_add_le16(jctrl, "endgidmax", id->endgidmax);
	nvme_json_add_time_s_flags(jctrl, "anatt", id->anatt, flags);
	nvme_json_add_id_ctrl_anacap(jctrl, "anacap", id->anacap, flags);
	nvme_json_add_le32(jctrl, "anagrpmax", id->anagrpmax);
	nvme_json_add_le32(jctrl, "nanagrpid", id->nanagrpid);
	nvme_json_add_id_ctrl_64k_mem(jctrl, "pels", le32_to_cpu(id->pels), flags);
	nvme_json_add_id_ctrl_sqes(jctrl, "sqes", id->sqes, flags);
	nvme_json_add_id_ctrl_cqes(jctrl, "cqes", id->cqes, flags);
	nvme_json_add_le16(jctrl, "maxcmd", id->maxcmd);
	nvme_json_add_le32(jctrl, "nn", id->nn);
	nvme_json_add_id_ctrl_oncs(jctrl, "oncs", le16_to_cpu(id->oncs), flags);
	nvme_json_add_id_ctrl_fuses(jctrl, "fuses", le16_to_cpu(id->fuses), flags);
	nvme_json_add_id_ctrl_fna(jctrl, "fna", id->fna, flags);
	nvme_json_add_id_ctrl_vwc(jctrl, "vwc", id->vwc, flags);
	nvme_json_add_le16(jctrl, "awun", id->awun);
	nvme_json_add_le16(jctrl, "awupf", id->awupf);
	nvme_json_add_id_ctrl_nvscc(jctrl, "nvscc", id->nvscc, flags);
	nvme_json_add_id_ctrl_nwpc(jctrl, "nwpc", id->nwpc, flags);
	nvme_json_add_le16(jctrl, "acwu", id->acwu);
	nvme_json_add_id_ctrl_sgls(jctrl, "sgls", le32_to_cpu(id->sgls), flags);
	nvme_json_add_le32(jctrl, "mnan", id->mnan);
	nvme_json_add_str_flags(jctrl, "subnqn", id->subnqn, strnlen(id->subnqn, sizeof(id->subnqn)), flags);
	nvme_json_add_id_ctrl_16_mem(jctrl, "ioccsz", le32_to_cpu(id->ioccsz), flags);
	nvme_json_add_id_ctrl_16_mem(jctrl, "iorcsz", le32_to_cpu(id->iorcsz), flags);
	nvme_json_add_id_ctrl_16_mem(jctrl, "icdoff", le16_to_cpu(id->icdoff), flags);
	nvme_json_add_id_ctrl_fcatt(jctrl, "fcatt", id->fcatt, flags);
	nvme_json_add_int(jctrl, "msdbd", id->msdbd);
	nvme_json_add_id_ctrl_ofcs(jctrl, "ofcs", le16_to_cpu(id->ofcs), flags);

	jpsds = nvme_json_new_array();
	for (i = 0; i <= id->npss; i++)
		nvme_json_add_id_ctrl_psd(jpsds, &id->psd[i], flags | NVME_JSON_COMPACT);
	json_object_object_add(jctrl, "psd", jpsds);

	return jctrl;
}

static void nvme_json_add_id_ns_lbaf(struct json_object *j,
	struct nvme_lbaf *lbaf, bool in_use, unsigned long flags)
{
	struct json_object *jlbaf = nvme_json_new_object(flags);

	nvme_json_add_size_flags(jlbaf, "ms", le16_to_cpu(lbaf->ms), flags);

	if (flags & NVME_JSON_HUMAN) {
		nvme_json_add_size_flags(jlbaf, "lbads", 1 << lbaf->ds, flags);
		nvme_json_add_str(jlbaf, "rp",
			nvme_id_ns_lbaf_rp_str(lbaf->rp & NVME_LBAF_RP_MASK),
			flags);
	} else {
		nvme_json_add_int(jlbaf, "lbads", lbaf->ds);
		nvme_json_add_int(jlbaf, "rp", lbaf->rp);
	}

	nvme_json_add_bool(jlbaf, "in-use", in_use);

	json_object_array_add(j, jlbaf);
}

static void nvme_json_add_id_ns_nsfeat(struct json_object *j, const char *n, __u8 nsfeat, unsigned long flags)
{
	struct json_object *jnsfeat;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, nsfeat, flags);
		return;
	}

	jnsfeat = nvme_json_new_object(flags);

	nvme_json_add_0x(jnsfeat, "value", nsfeat, flags);
	nvme_json_add_flag_flags(jnsfeat, "thin-provisioning", nsfeat, NVME_NS_FEAT_THIN, flags);
	nvme_json_add_flag_flags(jnsfeat, "ns-atomics", nsfeat, NVME_NS_FEAT_NATOMIC, flags);
	nvme_json_add_flag_flags(jnsfeat, "unwritten-blk-err", nsfeat, NVME_NS_FEAT_DULBE, flags);
	nvme_json_add_flag_flags(jnsfeat, "id-reuse", nsfeat, NVME_NS_FEAT_ID_REUSE, flags);
	nvme_json_add_flag_flags(jnsfeat, "preferred-access", nsfeat, NVME_NS_FEAT_IO_OPT, flags);

	json_object_object_add(j, n, jnsfeat);
}

static void nvme_json_add_id_ns_flbas(struct json_object *j, const char *n, __u8 flbas, unsigned long flags)
{
	struct json_object *jflbas;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, flbas, flags);
		return;
	}

	jflbas = nvme_json_new_object(flags);

	nvme_json_add_0x(jflbas, "value", flbas, flags);
	nvme_json_add_int(jflbas, "lba-index", flbas & NVME_NS_FLBAS_LBA_MASK);
	nvme_json_add_flag_flags(jflbas, "extended-metadata", flbas, NVME_NS_FLBAS_META_EXT, flags);

	json_object_object_add(j, n, jflbas);
}

static void nvme_json_add_id_ns_mc(struct json_object *j, const char *n, __u8 mc, unsigned long flags)
{
	struct json_object *jmc;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, mc, flags);
		return;
	}

	jmc = nvme_json_new_object(flags);

	nvme_json_add_0x(jmc, "value", mc, flags);
	nvme_json_add_flag_flags(jmc, "extended", mc, NVME_NS_MC_EXTENDED, flags);
	nvme_json_add_flag_flags(jmc, "separate", mc, NVME_NS_MC_SEPARATE, flags);

	json_object_object_add(j, n, jmc);
}

static void nvme_json_add_id_ns_dpc(struct json_object *j, const char *n, __u8 dpc, unsigned long flags)
{
	struct json_object *jdpc;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, dpc, flags);
		return;
	}

	jdpc = nvme_json_new_object(flags);

	nvme_json_add_0x(jdpc, "value", dpc, flags);
	nvme_json_add_flag_flags(jdpc, "type1", dpc, NVME_NS_DPC_PI_TYPE1, flags);
	nvme_json_add_flag_flags(jdpc, "type2", dpc, NVME_NS_DPC_PI_TYPE2, flags);
	nvme_json_add_flag_flags(jdpc, "type3", dpc, NVME_NS_DPC_PI_TYPE3, flags);
	nvme_json_add_flag_flags(jdpc, "first", dpc, NVME_NS_DPC_PI_FIRST, flags);
	nvme_json_add_flag_flags(jdpc, "last", dpc, NVME_NS_DPC_PI_LAST, flags);

	json_object_object_add(j, n, jdpc);
}

static void nvme_json_add_id_ns_dps(struct json_object *j, const char *n, __u8 dps, unsigned long flags)
{
	struct json_object *jdps;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, dps, flags);
		return;
	}

	jdps = nvme_json_new_object(flags);

	nvme_json_add_0x(jdps, "value", dps, flags);

	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_str(jdps, "pi",
			nvme_id_ns_dps_str(dps & NVME_NS_DPS_PI_MASK),
			flags);
	else
		nvme_json_add_int(jdps, "pi", dps & NVME_NS_DPS_PI_MASK);

	nvme_json_add_flag_flags(jdps, "first", dps, NVME_NS_DPS_PI_FIRST, flags);

	json_object_object_add(j, n, jdps);
}

static void nvme_json_add_id_ns_nmic(struct json_object *j, const char *n, __u8 nmic, unsigned long flags)
{
	struct json_object *jnmic;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, nmic, flags);
		return;
	}

	jnmic = nvme_json_new_object(flags);

	nvme_json_add_0x(jnmic, "value", nmic, flags);
	nvme_json_add_flag_flags(jnmic, "shared", nmic, NVME_NS_NMIC_SHARED, flags);

	json_object_object_add(j, n, jnmic);
}

static void nvme_json_add_id_ns_rescap(struct json_object *j, const char *n, __u8 rescap, unsigned long flags)
{
	struct json_object *jrescap;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, rescap, flags);
		return;
	}

	jrescap = nvme_json_new_object(flags);

	nvme_json_add_0x(jrescap, "value", rescap, flags);
	nvme_json_add_flag_flags(jrescap, "ptpl", rescap, NVME_NS_RESCAP_PTPL, flags);
	nvme_json_add_flag_flags(jrescap, "we", rescap, NVME_NS_RESCAP_WE, flags);
	nvme_json_add_flag_flags(jrescap, "ea", rescap, NVME_NS_RESCAP_EA, flags);
	nvme_json_add_flag_flags(jrescap, "wero", rescap, NVME_NS_RESCAP_WERO, flags);
	nvme_json_add_flag_flags(jrescap, "earo", rescap, NVME_NS_RESCAP_EARO, flags);
	nvme_json_add_flag_flags(jrescap, "wear", rescap, NVME_NS_RESCAP_WEAR, flags);
	nvme_json_add_flag_flags(jrescap, "eaar", rescap, NVME_NS_RESCAP_EAAR, flags);
	nvme_json_add_flag_flags(jrescap, "iek13", rescap, NVME_NS_RESCAP_IEK_13, flags);

	json_object_object_add(j, n, jrescap);
}

static void nvme_json_add_id_ns_fpi(struct json_object *j, const char *n, __u8 fpi, unsigned long flags)
{
	struct json_object *jfpi;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, fpi, flags);
		return;
	}

	jfpi = nvme_json_new_object(flags);
	nvme_json_add_0x(jfpi, "value", fpi, flags);
	nvme_json_add_percent(jfpi, "remaining", fpi & NVME_NS_FPI_REMAINING, flags);
	nvme_json_add_flag_flags(jfpi, "supported", fpi, NVME_NS_FPI_SUPPORTED, flags);

	json_object_object_add(j, n, jfpi);
}

static void nvme_json_add_id_ns_dlfeat(struct json_object *j, const char *n, __u8 dlfeat, unsigned long flags)
{
	struct json_object *jdlfeat;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, dlfeat, flags);
		return;
	}

	jdlfeat = nvme_json_new_object(flags);

	nvme_json_add_0x(jdlfeat, "value", dlfeat, flags);

	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_str(jdlfeat, "read-behavior",
			id_ns_dlfeat_rb_str(dlfeat & NVME_NS_DLFEAT_RB), flags);
	else
		nvme_json_add_int(jdlfeat, "read-behavior", dlfeat & NVME_NS_DLFEAT_RB);

	nvme_json_add_flag_flags(jdlfeat, "write-zeroes", dlfeat, NVME_NS_DLFEAT_WRITE_ZEROES, flags);
	nvme_json_add_flag_flags(jdlfeat, "crc-guard", dlfeat, NVME_NS_DLFEAT_CRC_GUARD, flags);

	json_object_object_add(j, n, jdlfeat);
}

static void nvme_json_add_id_ns_nsattr(struct json_object *j, const char *n, __u8 nsattr, unsigned long flags)
{
	struct json_object *jnsattr;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, n, nsattr, flags);
		return;
	}

	jnsattr = nvme_json_new_object(flags);

	nvme_json_add_0x(jnsattr, "value", nsattr, flags);
	nvme_json_add_flag_flags(jnsattr, "write-protected", nsattr, NVME_NS_NSATTR_WRITE_PROTECTED, flags);

	json_object_object_add(j, n, jnsattr);
}

static void nvme_json_add_blocks(struct json_object *j, const char *n, __u64 blocks,
	uint32_t bs, unsigned long flags)
{
	uint64_t size = blocks * bs;

	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_size(j, n, size, flags);
	else
		nvme_json_add_int(j, n, blocks);
}

struct json_object *nvme_id_ns_to_json(struct nvme_id_ns *ns,
	unsigned long flags)
{
	uint8_t lbaf = ns->flbas & NVME_NS_FLBAS_LBA_MASK;
	uint32_t bs = 1 << ns->lbaf[lbaf].ds;
	struct json_object *jns, *jlbafs;
	int i;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(ns, sizeof(*ns), flags);

	jns = nvme_json_new_object(flags);

	if (flags & NVME_JSON_HUMAN) {
		nvme_json_add_storage_flags(jns, "nsze", bs * le64_to_cpu(ns->nsze), flags);
		nvme_json_add_storage_flags(jns, "ncap", bs * le64_to_cpu(ns->ncap), flags);
		nvme_json_add_storage_flags(jns, "nuse", bs * le64_to_cpu(ns->nuse), flags);
	} else {
		nvme_json_add_le64(jns, "nsze", ns->nsze);
		nvme_json_add_le64(jns, "ncap", ns->ncap);
		nvme_json_add_le64(jns, "nuse", ns->nuse);
	}

	nvme_json_add_id_ns_nsfeat(jns, "nsfeat", ns->nsfeat, flags);
	nvme_json_add_int(jns, "nlbaf", ns->nlbaf);
	nvme_json_add_id_ns_flbas(jns, "flbas", ns->flbas, flags);
	nvme_json_add_id_ns_mc(jns, "mc", ns->mc, flags);
	nvme_json_add_id_ns_dpc(jns, "dpc", ns->dpc, flags);
	nvme_json_add_id_ns_dps(jns, "dps", ns->dps, flags);
	nvme_json_add_id_ns_nmic(jns, "nmic", ns->nmic, flags);
	nvme_json_add_id_ns_rescap(jns, "rescap", ns->rescap, flags);
	nvme_json_add_id_ns_fpi(jns, "fpi", ns->fpi, flags);
	nvme_json_add_id_ns_dlfeat(jns, "dlfeat", ns->dlfeat, flags);
	nvme_json_add_blocks(jns, "nawun", le16_to_cpu(ns->nawun), bs, flags);
	nvme_json_add_blocks(jns, "nawupf", le16_to_cpu(ns->nawupf), bs, flags);
	nvme_json_add_blocks(jns, "nacwu", le16_to_cpu(ns->nacwu), bs, flags);
	nvme_json_add_blocks(jns, "nabsn", le16_to_cpu(ns->nabsn), bs, flags);
	nvme_json_add_blocks(jns, "nabo", le16_to_cpu(ns->nabo), bs, flags);
	nvme_json_add_blocks(jns, "nabspf", le16_to_cpu(ns->nabspf), bs, flags);
	nvme_json_add_blocks(jns, "noiob", le16_to_cpu(ns->noiob), bs, flags);
	nvme_json_add_storage_128_flags(jns, "nvmcap", ns->nvmcap, flags);
	nvme_json_add_blocks(jns, "npwg", le16_to_cpu(ns->npwg), bs, flags);
	nvme_json_add_blocks(jns, "npwa", le16_to_cpu(ns->npwa), bs, flags);
	nvme_json_add_blocks(jns, "npdg", le16_to_cpu(ns->npdg), bs, flags);
	nvme_json_add_blocks(jns, "npda", le16_to_cpu(ns->npda), bs, flags);
	nvme_json_add_blocks(jns, "nows", le16_to_cpu(ns->nows), bs, flags);
	nvme_json_add_le32(jns, "anagrpid", ns->anagrpid);
	nvme_json_add_id_ns_nsattr(jns, "nsattr", ns->nsattr, flags);
	nvme_json_add_le16(jns, "nvmsetid", ns->nvmsetid);
	nvme_json_add_le16(jns, "endgid", ns->endgid);
	nvme_json_add_uuid(jns, "nguid", ns->nguid, flags);
	nvme_json_add_oui(jns, "eui64", ns->eui64, 8, flags);

	jlbafs = nvme_json_new_array();
	for (i = 0; i <= ns->nlbaf; i++)
		nvme_json_add_id_ns_lbaf(jlbafs, &ns->lbaf[i], i == lbaf, flags);
	json_object_object_add(jns, "lbaf", jlbafs);

	return jns;
}

static struct json_object *nvme_id_ns_desc_to_json(
	struct nvme_ns_id_desc *desc, unsigned long flags)
{
	struct json_object *jdesc = nvme_json_new_object(flags);

	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_str(jdesc, "nidt", nvme_id_nsdesc_nidt_str(desc->nidt), flags);
	else
		nvme_json_add_int(jdesc, "nidt", desc->nidt);

	nvme_json_add_int(jdesc, "nidl", desc->nidl);
	nvme_json_add_hex_array(jdesc, "nid", desc->nid, desc->nidl);

	return jdesc;
}

struct json_object *nvme_id_ns_desc_list_to_json(void *list,
	unsigned long flags)
{
	struct json_object *jlist, *jdescs;
	struct nvme_ns_id_desc *cur;
	void *p = list;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(list, sizeof(*list), flags);

	jlist = nvme_json_new_object(flags);
	jdescs = nvme_json_new_array();

	cur = p;
	while (cur->nidl && p - list < 0x1000) {
		json_object_array_add(jdescs,
			nvme_id_ns_desc_to_json(cur, flags));
		p += cur->nidl + sizeof(*cur);
		cur = p;
	} 
	json_object_object_add(jlist, "ns-id-descriptors", jdescs);

	return jlist;
}

static struct json_object *nvme_id_ns_granularity_desc_to_json(
	struct nvme_id_ns_granularity_desc *gran, unsigned long flags)
{
	struct json_object *jgran = nvme_json_new_object(flags);

	nvme_json_add_le64(jgran, "nszeg", gran->namespace_size_granularity);
	nvme_json_add_le64(jgran, "ncapg", gran->namespace_capacity_granularity);

	return jgran;
}

struct json_object *nvme_id_ns_granularity_list_to_json(
	struct nvme_id_ns_granularity_list *glist, unsigned long flags)
{
	struct json_object *jglist, *jgrans;
	int i;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(glist, sizeof(*glist), flags);

	jglist = nvme_json_new_object(flags);

	nvme_json_add_le32(jglist, "attributes", glist->attributes);
	nvme_json_add_int(jglist, "ndesc", glist->num_descriptors);

	jgrans = nvme_json_new_array();
	for (i = 0; i <= MIN(glist->num_descriptors, 15); i++)
		json_object_array_add(jgrans,
			nvme_id_ns_granularity_desc_to_json(&glist->entry[i],
							    flags));
	json_object_object_add(jglist, "ng-descriptors", jgrans);

	return jglist;
}

static json_object *nvme_nvmset_attr_to_json(
	struct nvme_nvmset_attr *attr, unsigned long flags)
{
	struct json_object *jattr = nvme_json_new_object(flags);

	nvme_json_add_le16(jattr, "nvmsetid", attr->id);
	nvme_json_add_le16(jattr, "egi", attr->endurance_group_id);
	nvme_json_add_le32(jattr, "r4krt", attr->random_4k_read_typical);
	nvme_json_add_le32(jattr, "ows", attr->opt_write_size);
	nvme_json_add_int128(jattr, "tnvmsetcap", attr->total_nvmset_cap);
	nvme_json_add_int128(jattr, "unvmsetcap", attr->unalloc_nvmset_cap);

	return jattr;
}

struct json_object *nvme_id_nvm_set_list_to_json(
	struct nvme_id_nvmset_list *nvmset, unsigned long flags)
{
	struct json_object *jnvmset, *jattrs;
	int i;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(nvmset, sizeof(*nvmset), flags);

	jnvmset = nvme_json_new_object(flags);

	nvme_json_add_int(jnvmset, "nids", nvmset->nid);

	jattrs = nvme_json_new_array();
	for (i = 0; i < nvmset->nid; i++)
		json_object_array_add(jnvmset,
			nvme_nvmset_attr_to_json(&nvmset->ent[i], flags));
	json_object_object_add(jnvmset, "entry", jattrs);

	return jnvmset;
}

struct json_object *nvme_id_primary_ctrl_cap_to_json(
	struct nvme_primary_ctrl_cap *cap, unsigned long flags)
{
	struct json_object *jpri;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(cap, sizeof(*cap), flags);

	jpri = nvme_json_new_object(flags);

	nvme_json_add_le16(jpri, "cntlid", cap->cntlid);
	nvme_json_add_le16(jpri, "portid", cap->portid);
	nvme_json_add_int(jpri, "crt", cap->crt);
	nvme_json_add_le32(jpri, "vqfrt", cap->vqfrt);
	nvme_json_add_le32(jpri, "vqrfa", cap->vqrfa);
	nvme_json_add_le16(jpri, "vqrfap", cap->vqrfap);
	nvme_json_add_le16(jpri, "vqprt", cap->vqprt);
	nvme_json_add_le16(jpri, "vqfrsm", cap->vqfrsm);
	nvme_json_add_le16(jpri, "vqgran", cap->vqgran);
	nvme_json_add_le32(jpri, "vifrt", cap->vifrt);
	nvme_json_add_le32(jpri, "virfa", cap->virfa);
	nvme_json_add_le16(jpri, "virfap", cap->virfap);
	nvme_json_add_le16(jpri, "viprt", cap->viprt);
	nvme_json_add_le16(jpri, "vifrsm", cap->vifrsm);
	nvme_json_add_le16(jpri, "vigran", cap->vigran);

	return jpri;
}

static struct json_object *nvme_secondary_ctrl_entry_to_json(
	struct nvme_secondary_ctrl *ent, unsigned int flags)
{
	struct json_object *jsec = nvme_json_new_object(flags);

	nvme_json_add_le16(jsec, "scid", ent->scid);
	nvme_json_add_le16(jsec, "pcid", ent->pcid);
	nvme_json_add_int(jsec, "scs", ent->scs);
	nvme_json_add_le16(jsec, "vfn", ent->vfn);
	nvme_json_add_le16(jsec, "nvq", ent->nvq);
	nvme_json_add_le16(jsec, "nvi", ent->nvi);

	return jsec;
}

struct json_object *nvme_id_secondary_ctrl_list_to_json(
	struct nvme_secondary_ctrl_list *list, unsigned long flags)
{
	struct json_object *jlist, *jsecs;
	int i;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(list, sizeof(*list), flags);

	jlist = nvme_json_new_object(flags);
	jsecs = nvme_json_new_array();

	nvme_json_add_int(jlist, "nids", list->num);
	for (i = 0; i < MIN(list->num, 127); i++)
		json_object_array_add(jsecs,
			nvme_secondary_ctrl_entry_to_json(&list->sc_entry[i],
							  flags));
	json_object_object_add(jlist, "sc-entrys", jsecs);
	return jlist;
}

static struct json_object *nvme_id_uuid_to_json(
	struct nvme_id_uuid_list_entry *desc, unsigned long flags)
{
	struct json_object *juuid = nvme_json_new_object(flags);
	__u8 assoc = desc->header & NVME_ID_UUID_HDR_ASSOCIATION_MASK;

	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_str(juuid, "nidt", nvme_id_uuid_assoc_str(assoc), flags);
	else
		nvme_json_add_int(juuid, "association", assoc);
	nvme_json_add_hex_array(juuid, "uuid", desc->uuid, 16);

	return juuid;
}

struct json_object *nvme_id_uuid_list_to_json(
	struct nvme_id_uuid_list *list, unsigned long flags)
{
	struct json_object *jlist, *juuids;
	int i;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(list, sizeof(*list), flags);

	jlist = nvme_json_new_object(flags);
	juuids = nvme_json_new_array();

	for (i = 0; i < NVME_ID_UUID_LIST_MAX; i++)
		json_object_array_add(juuids,
			nvme_id_uuid_to_json(&list->entry[i], flags));
	json_object_object_add(jlist, "uuids", juuids);

	return jlist;
}

struct json_object *nvme_ns_list_to_json(
	struct nvme_ns_list *list, unsigned long flags)
{
	struct json_object *jlist, *jarray;
	int i;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(list, sizeof(*list), flags);

	jlist = nvme_json_new_object(flags);
	jarray = nvme_json_new_array();
	for (i = 0; i < 1024; i++) {
		struct json_object *jnsid;
		__u32 nsid;

		nsid = le32_to_cpu(list->ns[i]);
		if (!nsid)
			break;

		jnsid = nvme_json_new_int(nsid);
		json_object_array_add(jarray, jnsid);
	}
	json_object_object_add(jlist, "nsids", jarray);

	return jlist;
}

struct json_object *nvme_ctrl_list_to_json(
	struct nvme_ctrl_list *list, unsigned long flags)
{
	struct json_object *jlist, *jarray;
	__u16 num_ids;
	int i;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(list, sizeof(*list), flags);

	jlist = nvme_json_new_object(flags);
	jarray = nvme_json_new_array();

	num_ids = le16_to_cpu(list->num);
	nvme_json_add_int(jlist, "nids", num_ids);

	for (i = 0; i < MIN(num_ids, 2047); i++)
		json_object_array_add(jarray, nvme_json_new_int(
			le16_to_cpu(list->identifier[i])));

	json_object_object_add(jlist, "cntlids", jarray);

	return jlist;
}

static struct json_object *nvme_lbas_desc_to_json(struct nvme_lba_status_desc *lbasd)
{
	struct json_object *jlbasd;

	jlbasd = nvme_json_new_object(0);

	nvme_json_add_le64(jlbasd, "dslba", lbasd->dslba);
	nvme_json_add_le32(jlbasd, "nlb", lbasd->nlb);
	nvme_json_add_int(jlbasd, "status", lbasd->status);

	return jlbasd;
}

struct json_object *nvme_lba_status_desc_list_to_json(
	struct nvme_lba_status *lbas, unsigned long flags)
{
	struct json_object *jlbas, *jlbasds;
	__u64 i, nlsd = le64_to_cpu(lbas->nlsd);

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(lbas,
			sizeof(*lbas) + sizeof(lbas->descs[0]) * nlsd,
			flags);

	jlbas = nvme_json_new_object(flags);

	nvme_json_add_int64(jlbas, "nlds", nlsd);
	nvme_json_add_int(jlbas, "cmpc", lbas->cmpc);

	jlbasds = nvme_json_new_array();
	for (i = 0; i < nlsd; i++) {
		struct json_object *jlbasd;

		jlbasd = nvme_lbas_desc_to_json(&lbas->descs[i]);
		json_object_array_add(jlbasds, jlbasd);
	}
	json_object_object_add(jlbas, "entries", jlbasds);

	return jlbas;
}

static int nvme_ana_size(struct nvme_ana_log *ana)
{
	int i, offset = 0, ngroups = le16_to_cpu(ana->ngrps);
	int ret = sizeof(*ana) + sizeof(ana->descs[0]) * ngroups;
	void *base = ana;

	for (i = 0; i < ngroups; i++) {
		struct nvme_ana_group_desc *desc = base + offset;
		int nnsids = le32_to_cpu(desc->nnsids);

		ret += nnsids * sizeof(desc->nsids[0]);
	}
	return ret;
}

static struct json_object *nvme_ana_desc_to_json(
	struct nvme_ana_group_desc *desc, int *offset, unsigned long flags)
{
	struct json_object *jdesc, *jnsids;
	int j, nnsids;

	jdesc = nvme_json_new_object(flags);
	nnsids = le32_to_cpu(desc->nnsids);
	nvme_json_add_le32(jdesc, "anagid", desc->grpid);
	nvme_json_add_int(jdesc, "nnsids", nnsids);
	nvme_json_add_le64(jdesc, "cc", desc->chgcnt);
	nvme_json_add_int(jdesc, "state", desc->state);

	jnsids = nvme_json_new_array();
	for (j = 0; j < nnsids; j++) {
		__u32 nsid = le32_to_cpu(desc->nsids[j]);
		json_object_array_add(jnsids, nvme_json_new_int(nsid));
	}
	json_object_object_add(jdesc, "nsids", jnsids);
	*offset += nnsids * sizeof(__u32);

	return jdesc;
}

struct json_object *nvme_ana_log_to_json(
	struct nvme_ana_log *ana, unsigned long flags)
{
	struct json_object *jana, *jdescs;
	int i, offset = 0, ngroups = le16_to_cpu(ana->ngrps);
	void *base = &ana->descs;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(ana, nvme_ana_size(ana), flags);

	jana = nvme_json_new_object(flags);
	nvme_json_add_le64(jana, "cc", ana->chgcnt);
	nvme_json_add_int(jana, "nagd", ngroups);

	jdescs = nvme_json_new_array();
	for (i = 0; i < ngroups; i++) {
		struct nvme_ana_group_desc *desc = base + offset;

		json_object_array_add(jdescs,
			nvme_ana_desc_to_json(desc, &offset, flags));
	}
	json_object_object_add(jana, "anagds", jdescs);

	return jana;
}

static struct json_object *nvme_disc_entry_to_json(
	struct nvmf_disc_log_entry *e, unsigned long flags)
{
	struct json_object *jentry = nvme_json_new_object(flags);

	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_str(jentry, "trtype", nvmf_trtype_str(e->trtype), flags);
	else
		nvme_json_add_int(jentry, "trtype", e->trtype);

	nvme_json_add_int(jentry, "adrfam", e->adrfam);
	nvme_json_add_int(jentry, "subtype", e->subtype);
	nvme_json_add_int(jentry, "treq", e->treq);
	nvme_json_add_le16(jentry, "portid", e->portid);
	nvme_json_add_le16(jentry, "cntlid", e->cntlid);
	nvme_json_add_le16(jentry, "asqsz", e->asqsz);
	nvme_json_add_str_flags(jentry, "trsvcid", e->trsvcid,
		strnlen(e->trsvcid, sizeof(e->trsvcid)), flags);
	nvme_json_add_str_flags(jentry, "subnqn", e->subnqn,
		strnlen(e->subnqn, sizeof(e->subnqn)), flags);
	nvme_json_add_str_flags(jentry, "traddr", e->traddr,
		strnlen(e->traddr, sizeof(e->traddr)), flags);
	nvme_json_add_hex_array(jentry, "tsas", (void *)e->tsas.common, 16);

	return jentry;
}

struct json_object *nvme_discovery_log_to_json(
	struct nvmf_discovery_log *log, unsigned long flags)
{
	struct json_object *jlog, *jentries;
	int i, numrec = le64_to_cpu(log->numrec);

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(log,
			sizeof(*log) + sizeof(log->entries[0]) * numrec,
			flags);

	jlog = nvme_json_new_object(flags);
	nvme_json_add_le64(jlog, "genctr", log->genctr);
	nvme_json_add_int(jlog, "numrec", numrec);
	nvme_json_add_le16(jlog, "recfmt", log->recfmt);

	jentries = nvme_json_new_array();
	for (i = 0; i < numrec; i++) {
		struct nvmf_disc_log_entry *e = &log->entries[i];
		struct json_object *jentry;

		jentry = nvme_disc_entry_to_json(e, flags);
		if (!jentry)
			break;

		json_object_array_add(jentries, jentry);
	}
	json_object_object_add(jlog, "entries", jentries);

	return jlog;
}

struct json_object *nvme_cmd_effects_log_to_json(
	struct nvme_cmd_effects_log *effects, unsigned long flags)
{
	struct json_object *jeffects;
	__u32 effect;
	char key[8];
	int i;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(effects, sizeof(*effects), flags);

	jeffects = nvme_json_new_object(flags);
	for (i = 0; i < 255; i++) {
		effect = le32_to_cpu(effects->acs[i]);
		if (!(effect & NVME_CMD_EFFECTS_CSUPP))
			continue;
		sprintf(key, "acs%d", i);
		nvme_json_add_int(jeffects, key, effect);
	}

	for (i = 0; i < 255; i++) {
		effect = le32_to_cpu(effects->acs[i]);
		if (!(effect & NVME_CMD_EFFECTS_CSUPP))
			continue;
		sprintf(key, "iocs%d", i);
		nvme_json_add_le32(jeffects, key, effects->iocs[i]);
	}

	return jeffects;
}

struct json_object *nvme_ege_aggregate_log(
	struct nvme_eg_event_aggregate_log *eglog, unsigned long flags)
{
	struct json_object *jeglog, *jegs;
	int i, nents = le64_to_cpu(eglog->nr_entries);

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(eglog,
			sizeof(*eglog) + sizeof(eglog->egids[0]) * nents,
			flags);

	jeglog = nvme_json_new_object(flags);
	nvme_json_add_int(jeglog, "nents", nents);

	jegs = nvme_json_new_array();
	for (i = 0; i < nents; i++) {
		int egid = le16_to_cpu(eglog->egids[i]);

		if (!egid)
			break;
		json_object_array_add(jegs, nvme_json_new_int(egid));
	}
	json_object_object_add(jeglog, "cntlids", jegs);

	return jeglog;
}

struct json_object *nvme_endurance_group_log_to_json(
	struct nvme_endurance_group_log *eg, unsigned long flags)
{
	struct json_object *jeg;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(eg, sizeof(*eg), flags);

	jeg = nvme_json_new_object(flags);
	nvme_json_add_int(jeg, "cw", eg->critical_warning);
	nvme_json_add_int(jeg, "ap", eg->avl_spare);
	nvme_json_add_int(jeg, "apt", eg->avl_spare_threshold);
	nvme_json_add_int(jeg, "pu", eg->percent_used);
	nvme_json_add_int128(jeg, "ee", eg->endurance_estimate);
	nvme_json_add_int128(jeg, "dur", eg->data_units_read);
	nvme_json_add_int128(jeg, "duw", eg->data_units_written);
	nvme_json_add_int128(jeg, "mwc", eg->media_units_written);
	nvme_json_add_int128(jeg, "hrc", eg->host_read_cmds);
	nvme_json_add_int128(jeg, "hwc", eg->host_write_cmds);
	nvme_json_add_int128(jeg, "mdie", eg->media_data_integrity_err);
	nvme_json_add_int128(jeg, "nele", eg->num_err_info_log_entries);

	return jeg;
}

static struct json_object *nvme_error_to_json(
	struct nvme_error_log_page *log, unsigned long flags)
{
	struct json_object *jerror = nvme_json_new_object(flags);

	nvme_json_add_le64(jerror, "error-count", log->error_count);
	nvme_json_add_le16(jerror, "sqid", log->sqid);
	nvme_json_add_le16(jerror, "cmdid", log->cmdid);
	nvme_json_add_hex_le16_flags(jerror, "status-field", log->status_field, flags);
	nvme_json_add_hex_le16_flags(jerror, "err-loc", log->parm_error_location, flags);
	nvme_json_add_le64(jerror, "lba", log->lba);
	nvme_json_add_le32(jerror, "nsid", log->nsid);
	nvme_json_add_int(jerror, "vsia", log->vs);

	if (flags & NVME_JSON_HUMAN)
		nvme_json_add_str(jerror, "trtype", nvmf_trtype_str(log->trtype), flags);
	else
		nvme_json_add_int(jerror, "trtype", log->trtype);
	nvme_json_add_le64(jerror, "csi", log->cs);
	nvme_json_add_le16(jerror, "ttsi", log->trtype_spec_info);

	return jerror;
}

struct json_object *nvme_error_log_to_json(
	struct nvme_error_log_page *log, int entries, unsigned long flags)
{
	struct json_object *jlog, *jerrors;
	int i;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(log, sizeof(*log) * entries,
			flags);

	flags |= NVME_JSON_COMPACT;
	jlog = nvme_json_new_object(flags);
	jerrors = nvme_json_new_array();
	for (i = 0; i < entries; i++)
		json_object_array_add(jerrors,
			nvme_error_to_json(log + i, flags));
	json_object_object_add(jlog, "error", jerrors);

	return jlog;
}

struct json_object *nvme_fw_slot_log_to_json(
	struct nvme_firmware_slot *fw, unsigned long flags)
{
	struct json_object *jfw = nvme_json_new_object(flags);
	int i;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(fw, sizeof(*fw), flags);

	nvme_json_add_int(jfw, "afi", fw->afi);
	for (i = 0; i < 7; i++) {
		char key[5] = { 0 }; /* frsX\0 */

		if (!strcmp(fw->frs[i], "") ||
		    !fw->frs[i][0])
			continue;

		sprintf(key, "frs%d", i + 1);
		nvme_json_add_str_flags(jfw, key, fw->frs[i],
			sizeof(fw->frs[i]), 0);
	}
	return jfw;
}

static struct json_object *nvme_lba_status_lba_rd_to_json(
	struct nvme_lba_rd *rd, unsigned long flags)
{
	struct json_object *jrd = nvme_json_new_object(flags);

	nvme_json_add_le64(jrd, "rslba", rd->rslba);
	nvme_json_add_le32(jrd, "rnlb", rd->rnlb);

	return jrd;
}

static struct json_object *nvme_lba_status_log_ns_element_to_json(
	struct nvme_lbas_ns_element *element, int *offset,
	unsigned long flags)
{
	int i, neid = le32_to_cpu(element->neid);
	struct json_object *jelem, *jrds;

	jelem = nvme_json_new_object(flags);
	nvme_json_add_int(jelem, "neid", neid);
	nvme_json_add_le32(jelem, "nrld", element->nrld);
	nvme_json_add_int(jelem, "ratype", element->ratype);

	jrds = nvme_json_new_array();
	for (i = 0; i < neid; i++)
		json_object_array_add(jrds,
			nvme_lba_status_lba_rd_to_json(&element->lba_rd[i],
						       flags));
	json_object_object_add(jelem, "lbards", jrds);

	*offset += sizeof(*element) + neid * sizeof(element->lba_rd[0]);
	return jelem;
}

struct json_object *nvme_lba_status_log_to_json(
	struct nvme_lba_status_log *lbas, unsigned long flags)
{
	struct json_object *jlbas, *jelems;
	int offset = 0, lslplen = le32_to_cpu(lbas->lslplen);
	void *base = &lbas->elements;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(base, lslplen, flags);

	jlbas = nvme_json_new_object(flags);
	nvme_json_add_int(jlbas, "lslplen", lslplen);
	nvme_json_add_le32(jlbas, "nlslne", lbas->nlslne);
	nvme_json_add_le32(jlbas, "estulb", lbas->estulb);
	nvme_json_add_le16(jlbas, "lsgc", lbas->lsgc);

	jelems = nvme_json_new_array();
	while (offset < lslplen - sizeof(*lbas)) {
		struct nvme_lbas_ns_element *element = base + offset;

		json_object_array_add(jelems, 
			nvme_lba_status_log_ns_element_to_json(element,
							       &offset, flags));
	}
	json_object_object_add(jlbas, "jelems", jelems);

	return jlbas;
}


struct json_object *nvme_aggr_predictable_lat_log_to_json(
	struct nvme_aggregate_predictable_lat_event *pl, unsigned long flags)
{
	__u64 num_entries = le64_to_cpu(pl->num_entries);
	struct json_object *jpl, *jentries;
	int i;

	jpl = nvme_json_new_object(flags);
	nvme_json_add_int64(jpl, "nents", num_entries);

	jentries = nvme_json_new_array();
	for (i = 0; i < num_entries; i++)
		json_object_array_add(jentries,
			nvme_json_new_int(le16_to_cpu(pl->entries[i])));
	json_object_object_add(jpl, "entries", jentries);

	return jpl;
}

struct json_object *nvme_nvmset_predictable_lat_log_to_json(
	struct nvme_nvmset_predictable_lat_log *pl, unsigned long flags)
{
	struct json_object *jpl;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(pl, sizeof(*pl), flags);

	jpl = nvme_json_new_object(flags);
	nvme_json_add_int(jpl, "status", pl->status);
	nvme_json_add_le16(jpl, "event_type", pl->event_type);
	nvme_json_add_le64(jpl, "dtwin_rt", pl->dtwin_rt);
	nvme_json_add_le64(jpl, "dtwin_wt", pl->dtwin_wt);
	nvme_json_add_le64(jpl, "dtwin_tmax", pl->dtwin_tmax);
	nvme_json_add_le64(jpl, "dtwin_tmin_hi", pl->dtwin_tmin_hi);
	nvme_json_add_le64(jpl, "dtwin_tmin_lo", pl->dtwin_tmin_lo);
	nvme_json_add_le64(jpl, "dtwin_re", pl->dtwin_re);
	nvme_json_add_le64(jpl, "dtwin_we", pl->dtwin_we);
	nvme_json_add_le64(jpl, "dtwin_te", pl->dtwin_te);

	return jpl;
}


struct json_object *nvme_resv_notify_log_to_json(
	struct nvme_resv_notification_log *resv, unsigned long flags)
{
	struct json_object *jresv;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(resv, sizeof(*resv), flags);

	jresv = nvme_json_new_object(flags);
	nvme_json_add_le64(jresv, "lpc", resv->lpc);
	nvme_json_add_int(jresv, "rnlpt", resv->rnlpt);
	nvme_json_add_int(jresv, "nalp", resv->nalp);
	nvme_json_add_le32(jresv, "nsid", resv->nsid);

	return jresv;
}

struct json_object *nvme_sanitize_log_to_json(
	struct nvme_sanitize_log_page *san, unsigned long flags)
{
	struct json_object *jsan;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(san, sizeof(*san), flags);

	jsan = nvme_json_new_object(flags);
	nvme_json_add_le16(jsan, "sprog", san->sprog);
	nvme_json_add_le16(jsan, "sstat", san->sstat);
	nvme_json_add_le32(jsan, "scdw10", san->scdw10);
	nvme_json_add_le32(jsan, "eto", san->eto);
	nvme_json_add_le32(jsan, "etbe", san->etbe);
	nvme_json_add_le32(jsan, "etce", san->etce);
	nvme_json_add_le32(jsan, "etond", san->etond);
	nvme_json_add_le32(jsan, "etbend", san->etbend);
	nvme_json_add_le32(jsan, "etcend", san->etcend);

	return jsan;
}

static struct json_object *nvme_self_test_to_json(
	struct nvme_st_result *str, unsigned long flags)
{
	struct json_object *jstr;
	__u8 op = str->dsts & NVME_ST_RESULT_MASK;

	jstr = nvme_json_new_object(flags);
	nvme_json_add_int(jstr, "dstop", op);

	if (op == NVME_ST_RESULT_NOT_USED)
		return jstr;

	nvme_json_add_int(jstr, "stc", str->dsts >> NVME_ST_CODE_SHIFT);
	nvme_json_add_int(jstr, "seg", str->seg);
	nvme_json_add_int(jstr, "vid", str->vdi);
	nvme_json_add_le64(jstr, "poh", str->poh);
	if (str->vdi & NVME_ST_VALID_DIAG_INFO_NSID)
		nvme_json_add_le32(jstr, "nsid", str->nsid);
	if (str->vdi & NVME_ST_VALID_DIAG_INFO_FLBA)
		nvme_json_add_le64(jstr, "flba", str->flba);
	if (str->vdi & NVME_ST_VALID_DIAG_INFO_SCT)
		nvme_json_add_int(jstr, "sct", str->sct);
	if (str->vdi & NVME_ST_VALID_DIAG_INFO_SC)
		nvme_json_add_int(jstr, "sc", str->sc);
	nvme_json_add_int(jstr, "vs", (str->vs[1] << 8) | (str->vs[0]));

	return jstr;
}

struct json_object *nvme_dev_self_test_log_to_json(
	struct nvme_self_test_log *st, unsigned long flags)
{
	struct json_object *jst, *jstrs;
	int i;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(st, sizeof(*st), flags);

	jst = nvme_json_new_object(flags);
	jstrs = nvme_json_new_array();

	nvme_json_add_int(jst, "current-operation", st->current_operation);
	nvme_json_add_int(jst, "completion", st->completion);

	for (i = 0; i < NVME_LOG_ST_MAX_RESULTS; i++)
		json_object_array_add(jstrs,
			nvme_self_test_to_json(&st->result[i], flags));
	json_object_object_add(jst, "nsids", jstrs);

	return jst;
}

static void nvme_json_add_smart_cw(struct json_object *j, const char *n,
				   __u8 cw, unsigned long flags)
{
	struct json_object *jcw;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, "cw", cw, flags);
		return;
	}

	jcw = nvme_json_new_object(flags);

	nvme_json_add_0x(jcw, "value", cw, flags);
	nvme_json_add_flag_flags(jcw, "spare", cw, NVME_SMART_CRIT_SPARE, flags);
	nvme_json_add_flag_flags(jcw, "temperature", cw, NVME_SMART_CRIT_TEMPERATURE, flags);
	nvme_json_add_flag_flags(jcw, "degraded", cw, NVME_SMART_CRIT_DEGRADED, flags);
	nvme_json_add_flag_flags(jcw, "media", cw, NVME_SMART_CRIT_MEDIA, flags);
	nvme_json_add_flag_flags(jcw, "memory-backup", cw, NVME_SMART_CRIT_VOLATILE_MEMORY, flags);
	nvme_json_add_flag_flags(jcw, "pmr-ro", cw, NVME_SMART_CRIT_PMR_RO, flags);

	json_object_object_add(j, n, jcw);
}

static void nvme_json_add_smart_egcw(struct json_object *j, const char *n,
				   __u8 egcw, unsigned long flags)
{
	struct json_object *jegcw;

	if (!(flags & NVME_JSON_DECODE_COMPLEX)) {
		nvme_json_add_0x(j, "egcw", egcw, flags);
		return;
	}

	jegcw = nvme_json_new_object(flags);

	nvme_json_add_0x(jegcw, "value", egcw, flags);
	nvme_json_add_flag_flags(jegcw, "spare", egcw, NVME_SMART_EGCW_SPARE, flags);
	nvme_json_add_flag_flags(jegcw, "degraded", egcw, NVME_SMART_EGCW_DEGRADED, flags);
	nvme_json_add_flag_flags(jegcw, "read-only", egcw, NVME_SMART_EGCW_RO, flags);

	json_object_object_add(j, n, jegcw);
}

struct json_object *nvme_smart_log_to_json(
	struct nvme_smart_log *smart, unsigned long flags)
{
	__u32 temp = unalign_int(smart->temperature, sizeof(smart->temperature));
	struct json_object *jsmart = nvme_json_new_object(flags);
	int i;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(smart, sizeof(*smart), flags);

	nvme_json_add_smart_cw(jsmart, "critical-warning", smart->critical_warning, flags);
	nvme_json_add_temp(jsmart, "composite-temp", temp, flags);
	nvme_json_add_percent(jsmart, "available-spare", smart->avail_spare, flags);
	nvme_json_add_percent(jsmart, "spare-threshold", smart->spare_thresh, flags);
	nvme_json_add_percent(jsmart, "percent-used", smart->percent_used, flags);
	nvme_json_add_smart_egcw(jsmart, "endgrp-crit-warning", smart->endu_grp_crit_warn_sumry, flags);
	nvme_json_add_int128(jsmart, "data-units-read", smart->data_units_read);
	nvme_json_add_int128(jsmart, "data-units-written", smart->data_units_written);
	nvme_json_add_int128(jsmart, "host-reads", smart->host_reads);
	nvme_json_add_int128(jsmart, "host-writes", smart->host_writes);
	nvme_json_add_int128(jsmart, "ctrl-busy-time", smart->ctrl_busy_time);
	nvme_json_add_int128(jsmart, "power-cycles", smart->power_cycles);
	nvme_json_add_int128(jsmart, "power-on-hours", smart->power_on_hours);
	nvme_json_add_int128(jsmart, "unsafe-shutdowns", smart->unsafe_shutdowns);
	nvme_json_add_int128(jsmart, "media-errors", smart->media_errors);
	nvme_json_add_int128(jsmart, "error-log-entries", smart->num_err_log_entries);
	nvme_json_add_time_m_flags(jsmart, "warning-temp-time", smart->warning_temp_time, flags);
	nvme_json_add_time_m_flags(jsmart, "crit-comp-temp-time", smart->critical_comp_time, flags);

	for (i = 0; i < 8; i++) {
		__u32 t = le16_to_cpu(smart->temp_sensor[i]);
		char key[4] = {};

		if (t == 0)
			continue;
		sprintf(key, "ts%d", i + 1);
		nvme_json_add_temp(jsmart, key, t, flags);
	}

	nvme_json_add_le32(jsmart, "therm-mgmt-t1-trans-cnt", smart->thm_temp1_trans_count);
	nvme_json_add_le32(jsmart, "therm-mgmt-t2-trans-cnt", smart->thm_temp2_trans_count);
	nvme_json_add_le32(jsmart, "therm-mgmt-t1-total-time", smart->thm_temp1_total_time);
	nvme_json_add_le32(jsmart, "therm-mgmt-t2-total-time", smart->thm_temp2_total_time);

	return jsmart;
}

struct json_object *nvme_telemetry_log_to_json(
	struct nvme_telemetry_log *telem, unsigned long flags)
{
	struct json_object *jtelem;
	int size = sizeof(*telem) + NVME_LOG_TELEM_BLOCK_SIZE *
			le16_to_cpu(telem->dalb3);

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(telem, size, flags);

	jtelem = nvme_json_new_object(flags);
	nvme_json_add_int(jtelem, "lpi", telem->lpi);
	nvme_json_add_hex(jtelem, "ieee", nvme_ieee_to_int(telem->ieee), flags);
	nvme_json_add_le16(jtelem, "da1lb", telem->dalb1);
	nvme_json_add_le16(jtelem, "da2lb", telem->dalb2);
	nvme_json_add_le16(jtelem, "da3lb", telem->dalb3);
	nvme_json_add_int(jtelem, "tcida", telem->ctrlavail);
	nvme_json_add_int(jtelem, "tcidgn", telem->ctrldgn);
	nvme_json_add_hex_array(jtelem, "rid", telem->rsnident, sizeof(telem->rsnident));

	return jtelem;
}

struct json_object *nvme_persistent_event_log_to_json(
	struct nvme_persistent_event_log *pel, unsigned long flags)
{
	struct json_object *jpel;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(pel, sizeof(*pel), flags);

	jpel = nvme_json_new_object(flags);
	nvme_json_add_int(jpel, "lid", pel->lid);
	nvme_json_add_le32(jpel, "ttl", pel->ttl);
	nvme_json_add_int(jpel, "rv", pel->rv);
	nvme_json_add_le16(jpel, "lht", pel->lht);
	nvme_json_add_le64(jpel, "ts", pel->ts);
	nvme_json_add_int128(jpel, "poh", pel->poh);
	nvme_json_add_le64(jpel, "pcc", pel->pcc);
	nvme_json_add_hex(jpel, "vid", le16_to_cpu(pel->vid), flags);
	nvme_json_add_hex(jpel, "ssvid", le16_to_cpu(pel->ssvid), flags);
	nvme_json_add_str_flags(jpel, "sn", pel->sn, sizeof(pel->sn), 0);
	nvme_json_add_str_flags(jpel, "mn", pel->mn, sizeof(pel->mn), 0);
	nvme_json_add_str_flags(jpel, "subnqn", pel->subnqn, sizeof(pel->subnqn), 0);
	nvme_json_add_hex_array(jpel, "seb", pel->seb, sizeof(pel->seb));

	return jpel;
}

struct json_object *nvme_props_to_json(void *regs, unsigned long flags)
{
	struct json_object *jregs;

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(regs, 0x1000, flags);

	jregs = nvme_json_new_object(flags);
	nvme_json_add_le64_ptr(jregs, "cap", regs + NVME_REG_CAP);
	nvme_json_add_le32_ptr(jregs, "vs", regs + NVME_REG_VS);
	nvme_json_add_le32_ptr(jregs, "intms", regs + NVME_REG_INTMS);
	nvme_json_add_le32_ptr(jregs, "intmc", regs + NVME_REG_INTMC);
	nvme_json_add_le32_ptr(jregs, "cc", regs + NVME_REG_CC);
	nvme_json_add_le32_ptr(jregs, "csts", regs + NVME_REG_CSTS);
	nvme_json_add_le32_ptr(jregs, "nssr", regs + NVME_REG_NSSR);
	nvme_json_add_le32_ptr(jregs, "aqa", regs + NVME_REG_AQA);
	nvme_json_add_le64_ptr(jregs, "asq", regs + NVME_REG_ASQ);
	nvme_json_add_le64_ptr(jregs, "acq", regs + NVME_REG_ACQ);
	nvme_json_add_le32_ptr(jregs, "cmbloc", regs + NVME_REG_CMBLOC);
	nvme_json_add_le32_ptr(jregs, "cmbsz", regs + NVME_REG_CMBSZ);
	nvme_json_add_le32_ptr(jregs, "bpinfo", regs + NVME_REG_BPINFO);
	nvme_json_add_le32_ptr(jregs, "bprsel", regs + NVME_REG_BPRSEL);
	nvme_json_add_le64_ptr(jregs, "bpmbl", regs + NVME_REG_BPMBL);
	nvme_json_add_le64_ptr(jregs, "cmbmsc", regs + NVME_REG_CMBMSC);
	nvme_json_add_le32_ptr(jregs, "cmbsts", regs + NVME_REG_CMBSTS);
	nvme_json_add_le32_ptr(jregs, "pmrcap", regs + NVME_REG_PMRCAP);
	nvme_json_add_le32_ptr(jregs, "pmrctl", regs + NVME_REG_PMRCTL);
	nvme_json_add_le32_ptr(jregs, "pmrsts", regs + NVME_REG_PMRSTS);
	nvme_json_add_le32_ptr(jregs, "pmrebs", regs + NVME_REG_PMREBS);
	nvme_json_add_le32_ptr(jregs, "pmrswtp", regs + NVME_REG_PMRSWTP);
	nvme_json_add_le64_ptr(jregs, "pmrmsc", regs + NVME_REG_PMRMSC);

	return jregs;
}

static struct json_object *nvme_resv_ctrl_to_json(
	struct nvme_registered_ctrl *regctl,
	unsigned long flags)
{
	struct json_object *jrc;

	jrc = nvme_json_new_object(flags);

	nvme_json_add_le16(jrc, "cntlid", regctl->cntlid);
	nvme_json_add_int(jrc, "rcsts", regctl->rcsts);
	nvme_json_add_le64(jrc, "hostid", regctl->hostid);
	nvme_json_add_le64(jrc, "rkey", regctl->rkey);

	return jrc;
}

static struct json_object *nvme_resv_ctrl_ext_to_json(
	struct nvme_registered_ctrl_ext *regctl,
	unsigned long flags)
{
	struct json_object *jrc;

	jrc = nvme_json_new_object(flags);

	nvme_json_add_le16(jrc, "cntlid", regctl->cntlid);
	nvme_json_add_int(jrc, "rcsts", regctl->rcsts);
	nvme_json_add_le64(jrc, "rkey", regctl->rkey);
	nvme_json_add_int128(jrc, "hostid", regctl->hostid);

	return jrc;
}

struct json_object *nvme_resv_report_to_json(
	struct nvme_reservation_status *status, bool ext,
	unsigned long flags)
{
	int i, regctl = status->regctl[0] | (status->regctl[1] << 8);
	struct json_object *jrs, *jrcs;
	int size = sizeof(*status) - sizeof(status->rsvd24) +
		regctl * (ext ? sizeof(status->regctl_eds[0]) :
				sizeof(status->regctl_ds[0]));

	if (flags & NVME_JSON_BINARY)
		return nvme_json_new_str_len_flags(status, size, flags);

	jrs = nvme_json_new_object(flags);

	nvme_json_add_le32(jrs, "gen", status->gen);
	nvme_json_add_int(jrs, "rtype", status->rtype);
	nvme_json_add_int(jrs, "regctl", regctl);
	nvme_json_add_int(jrs, "ptpls", status->ptpls);

	jrcs = nvme_json_new_array();
	for (i = 0; i < regctl; i++) {
		struct json_object *jrc;

		if (ext)
			jrc = nvme_resv_ctrl_ext_to_json(
				&status->regctl_eds[i], flags);
		else
			jrc = nvme_resv_ctrl_to_json(
				&status->regctl_ds[i], flags);

		json_object_array_add(jrcs, jrc);
	}
	json_object_object_add(jrs, "nsids", jrcs);

	return NULL;
}
