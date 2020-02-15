#include <assert.h>
#include <stddef.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <stdbool.h>
#include <inttypes.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <dirent.h>
#include <libgen.h>

#ifdef LIBHUGETLBFS
#include <hugetlbfs.h>
#endif

#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <uuid.h>

#include "nvme.h"
#include "nvme-print.h"
#include "plugin.h"
#include "argconfig.h"

#define PATH_NVMF_DISC		"/etc/nvme/discovery.conf"
#define MAX_DISC_ARGS		32
#define MAX_DISC_RETRIES	10

#define CREATE_CMD
#include "nvme-builtin.h"

#define ARRAY_SIZE(x) sizeof(x) / sizeof(*x)

#if 0
void d(unsigned char *buf, int len, int width, int group)
{
	int i, offset = 0, line_done = 0;
	char ascii[32 + 1];

	assert(width < sizeof(ascii));
	printf("     ");
	for (i = 0; i <= 15; i++)
		printf("%3x", i);
	for (i = 0; i < len; i++) {
		line_done = 0;
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
			line_done = 1;
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
#endif

void nvme_show_status(const char *prefix, int status)
{
	if (status < 0)
		perror(prefix);
	else
		fprintf(stderr, "%s: nvme status: %s(%#x)\n", prefix,
			nvme_status_to_string(status), status);
}

#define min(x, y) (x < y) ? x : y
#define max(x, y) (x < y) ? y : x

static struct stat nvme_stat;
const char *devicename;

static const char nvme_version_string[] = NVME_VERSION;

static struct plugin builtin = {
	.commands = commands,
	.name = NULL,
	.desc = NULL,
	.next = NULL,
	.tail = &builtin,
};

static struct program nvme = {
	.name = "nvme",
	.version = nvme_version_string,
	.usage = "<command> [<device>] [<args>]",
	.desc = "The '<device>' may be either an NVMe character "\
		"device (ex: /dev/nvme0) or an nvme block device "\
		"(ex: /dev/nvme0n1).",
	.extensions = &builtin,
};

static const char *output_format = "Output format: normal|json|binary";
//static const char *output_format_no_binary = "Output format: normal|json";

/* Name of file to output log pages in their raw format */
static char *raw;
static bool persistent;
static bool quiet;

static const char *nvmf_tport		= "transport type";
static const char *nvmf_nqn		= "nqn name";
static const char *nvmf_traddr		= "transport address";
static const char *nvmf_trsvcid		= "transport service id (e.g. IP port)";
static const char *nvmf_htraddr		= "host traddr (e.g. FC WWN's)";
static const char *nvmf_hostnqn		= "user-defined hostnqn";
static const char *nvmf_hostid		= "user-defined hostid (if default not used)";
static const char *nvmf_nr_io_queues	= "number of io queues to use (default is core count)";
static const char *nvmf_nr_write_queues	= "number of write queues to use (default 0)";
static const char *nvmf_nr_poll_queues	= "number of poll queues to use (default 0)";
static const char *nvmf_queue_size	= "number of io queue elements to use (default 128)";
static const char *nvmf_keep_alive_tmo	= "keep alive timeout period in seconds";
static const char *nvmf_reconnect_delay	= "reconnect timeout period in seconds";
static const char *nvmf_ctrl_loss_tmo	= "controller loss timeout period in seconds";
static const char *nvmf_tos		= "type of service";
static const char *nvmf_dup_connect	= "allow duplicate connections between same transport host and subsystem port";
static const char *nvmf_disable_sqflow	= "disable controller sq flow control (default false)";
static const char *nvmf_hdr_digest	= "enable transport protocol header digest (TCP transport)";
static const char *nvmf_data_digest	= "enable transport protocol data digest (TCP transport)";

#define NVMF_OPTS(c)									\
	OPT_STRING("transport",       't', "STR", (char *)&c.transport,	nvmf_tport),	\
	OPT_STRING("traddr",          'a', "STR", (char *)&c.traddr,	nvmf_traddr),	\
	OPT_STRING("trsvcid",         's', "STR", (char *)&c.trsvcid,	nvmf_trsvcid),	\
	OPT_STRING("host-traddr",     'w', "STR", (char *)&c.host_traddr,	nvmf_htraddr),	\
	OPT_STRING("hostnqn",         'q', "STR", (char *)&c.hostnqn,	nvmf_hostnqn),	\
	OPT_STRING("hostid",          'I', "STR", (char *)&c.hostid,	nvmf_hostid),	\
	OPT_INT("nr-io-queues",       'i', &c.nr_io_queues,       nvmf_nr_io_queues),	\
	OPT_INT("nr-write-queues",    'W', &c.nr_write_queues,    nvmf_nr_write_queues),\
	OPT_INT("nr-poll-queues",     'P', &c.nr_poll_queues,     nvmf_nr_poll_queues),	\
	OPT_INT("queue-size",         'Q', &c.queue_size,         nvmf_queue_size),	\
	OPT_INT("keep-alive-tmo",     'k', &c.keep_alive_tmo,     nvmf_keep_alive_tmo),	\
	OPT_INT("reconnect-delay",    'c', &c.reconnect_delay,    nvmf_reconnect_delay),\
	OPT_INT("ctrl-loss-tmo",      'l', &c.ctrl_loss_tmo,      nvmf_ctrl_loss_tmo),	\
	OPT_INT("tos",                'T', &c.tos,                nvmf_tos),		\
	OPT_FLAG("duplicate-connect", 'D', &c.duplicate_connect,  nvmf_dup_connect),	\
	OPT_FLAG("disable-sqflow",    'd', &c.disable_sqflow,     nvmf_disable_sqflow),	\
	OPT_FLAG("hdr-digest",        'g', &c.hdr_digest,         nvmf_hdr_digest),	\
	OPT_FLAG("data-digest",       'G', &c.data_digest,        nvmf_data_digest)

static void *__nvme_alloc(size_t len, bool *huge)
{
	void *p;

	if (!posix_memalign(&p, getpagesize(), len)) {
		*huge = false;
		memset(p, 0, len);
		return p;
	}
	return NULL;
}

#ifdef LIBHUGETLBFS
#define HUGE_MIN 0x80000
static void nvme_free(void *p, bool huge)
{
	if (huge)
		free_hugepage_region(p);
	else
		free(p);
}

static void *nvme_alloc(size_t len, bool *huge)
{
	void *p;

	if (len < HUGE_MIN)
		return __nvme_alloc(len, huge);

	p = get_hugepage_region(len, GHR_DEFAULT);
	if (!p)
		return __nvme_alloc(len, huge);

	*huge = true;
	return p;
}
#else
static void nvme_free(void *p, bool huge)
{
	free(p);
}

static void *nvme_alloc(size_t len, bool *huge)
{
	return __nvme_alloc(len, huge);
}
#endif

static int open_dev(char *dev)
{
	int err, fd;

	devicename = basename(dev);
	err = open(dev, O_RDONLY);
	if (err < 0)
		goto perror;
	fd = err;

	err = fstat(fd, &nvme_stat);
	if (err < 0)
		goto perror;
	if (!S_ISCHR(nvme_stat.st_mode) && !S_ISBLK(nvme_stat.st_mode)) {
		fprintf(stderr, "%s is not a block or character device\n", dev);
		return -ENODEV;
	}
	return fd;
perror:
	perror(dev);
	return err;
}

int parse_and_open(int argc, char **argv, const char *desc,
	const struct argconfig_commandline_options *opts)
{
	int ret;

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (optind >= argc) {
		errno = EINVAL;
		perror(argv[0]);
		return -EINVAL;
	}

	ret = open_dev(argv[optind]);
	if (ret < 0)
		argconfig_print_help(desc, opts);
	return ret;
}

int validate_output_format(char *format)
{
	if (!format)
		return -EINVAL;
	if (!strcmp(format, "normal"))
		return NORMAL;
	if (!strcmp(format, "json"))
		return JSON;
	if (!strcmp(format, "binary"))
		return BINARY;
	if (!strcmp(format, "none"))
		return 0;
	return -EINVAL;
}

static int get_smart_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_smart_log log;
	const char *desc = "Retrieve SMART log for the given device "\
			"(or optionally a namespace) in either decoded format "\
			"(default) or binary.";
	const char *namespace = "(optional) desired namespace";
	const char *raw = "output in binary format";
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		__u32 namespace_id;
		int   raw_binary;
		char *output_format;
	};

	struct config cfg = {
		.namespace_id = NVME_NSID_ALL,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = 0;

	err = nvme_get_log_smart(fd, cfg.namespace_id, true, &log);
	if (!err)
		nvme_show_smart_log(&log, cfg.namespace_id, devicename, flags);
	else
		nvme_show_status("smart-log", err);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_ana_log(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Retrieve ANA log for the given device in " \
			    "decoded format (default), json or binary.";

	enum nvme_log_ana_lsp lsp = NVME_LOG_ANA_LSP_RGO_NAMESPACES;
	enum nvme_print_flags flags;
	int err, fd;
	size_t len;
	void *log;

	struct config {
		char *output_format;
		int groups;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("groups",       'g', &cfg.groups,        "use RGO"),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	err = nvme_get_ana_log_len(fd, &len);
	if (err)
		goto close_fd;

	log = malloc(len);
	if (!log) {
		perror("malloc");
		err = -1;
		goto close_fd;
	}

	if (cfg.groups)
		lsp = NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY;

	err = nvme_get_log_ana(fd, lsp, true, 0, len, log);
	if (!err)
		nvme_show_ana_log(log, devicename, flags, len);
	else
		nvme_show_status("ana-log", err);
	free(log);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_telemetry_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve telemetry log and write to binary file";
	const char *fname = "File name to save raw binary, includes header";
	const char *hgen = "Have the host tell the controller to generate the report";
	const char *cgen = "Gather report generated by the controller.";
	const char *dgen = "Pick which telemetry data area to report. Default is all. Valid options are 1, 2, 3.";

	struct nvme_telemetry_log *log = NULL;
	enum nvme_print_flags flags;
	int err = 0, fd, output;

	struct config {
		char *output_format;
		char *file_name;
		int host_gen;
		int ctrl_init;
		int data_area;
	};

	struct config cfg = {
		.output_format = "none",
		.data_area = 3,
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",    'f', &cfg.output_format, output_format),
		OPT_FILE("output-file",     'o', &cfg.file_name, fname),
		OPT_FLAG("host-generate",   'g', &cfg.host_gen,  hgen),
		OPT_FLAG("controller-init", 'c', &cfg.ctrl_init, cgen),
		OPT_UINT("data-area",       'd', &cfg.data_area, dgen),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	if (!cfg.file_name) {
		fprintf(stderr, "Please provide an output file!\n");
		err = -EINVAL;
		goto close_fd;
	}

	output = open(cfg.file_name, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (output < 0) {
		fprintf(stderr, "Failed to open output file %s: %s!\n",
				cfg.file_name, strerror(errno));
		err = output;
		goto close_fd;
	}

	if (cfg.host_gen)
		nvme_get_new_host_telemetry(fd, &log);
	else if (cfg.ctrl_init)
		nvme_get_ctrl_telemetry(fd, true, &log);
	else
		nvme_get_host_telemetry(fd, &log);

	if (!err)
		;
	else
		nvme_show_status("get-telemetry-log", err);

	free(log);
	close(output);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_endurance_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_endurance_group_log log;
	const char *desc = "Retrieves endurance groups log page and prints the log.";
	const char *group_id = "The endurance group identifier";
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		char *output_format;
		__u16 group_id;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_UINT("group-id",     'g', &cfg.group_id,      group_id),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	err = nvme_get_log_endurance_group(fd, cfg.group_id, &log);
	if (!err)
		nvme_show_endurance_log(&log, cfg.group_id, devicename, flags);
	else
		nvme_show_status("endurance log", err);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_effects_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve command effects log page and print the table.";
	const char *raw = "show log in binary format";
	const char *human_readable = "show log in readable format";
	struct nvme_cmd_effects_log log;

	int err, fd;
	enum nvme_print_flags flags;

	struct config {
		int   raw_binary;
		int   human_readable;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",  'o', &cfg.output_format,  output_format),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = BINARY;
	if (cfg.human_readable)
		flags |= VERBOSE;

	err = nvme_get_log_cmd_effects(fd, &log);
	if (!err)
		nvme_show_effects_log(&log, flags);
	else
		nvme_show_status("effects-log", err);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_error_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve specified number of "\
		"error log entries from a given device "\
		"in either decoded format (default) or binary.";
	const char *log_entries = "number of entries to retrieve";
	const char *raw = "dump in binary format";
	struct nvme_error_log_page *log;
	struct nvme_id_ctrl ctrl;
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		__u32 log_entries;
		int   raw_binary;
		char *output_format;
	};

	struct config cfg = {
		.log_entries  = 64,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_UINT("log-entries",  'e', &cfg.log_entries,   log_entries),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = 0;

	if (!cfg.log_entries) {
		fprintf(stderr, "non-zero log-entries is required param\n");
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_identify_ctrl(fd, &ctrl);
	if (err) {
		nvme_show_status("identify-controller", err);
		goto close_fd;
	}

	cfg.log_entries = min(cfg.log_entries, ctrl.elpe + 1);
	log = calloc(cfg.log_entries, sizeof(struct nvme_error_log_page));
	if (!log) {
		fprintf(stderr, "could not alloc buffer for error log\n");
		err = -1;
		goto close_fd;
	}

	err = nvme_get_log_error(fd, cfg.log_entries, true, log);
	if (!err)
		nvme_show_error_log(log, cfg.log_entries, devicename, flags);
	else
		nvme_show_status("error-log", err);
	free(log);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_fw_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve the firmware log for the "\
		"specified device in either decoded format (default) or binary.";
	const char *raw = "use binary output";
	struct nvme_firmware_slot log;
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		int raw_binary;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = 0;

	err = nvme_get_log_fw_slot(fd, true, &log);
	if (!err)
		nvme_show_fw_log(&log, devicename, flags);
	else
		nvme_show_status("fw-log", err);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_changed_ns_list_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_ns_list ns_list;
	const char *desc = "Retrieve Changed Namespaces log for the given device "\
			"in either decoded format "\
			"(default) or binary.";
	const char *raw = "output in binary format";
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		int   raw_binary;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = 0;

	err = nvme_get_log_changed_ns_list(fd, true, &ns_list);
	if (!err)
		nvme_show_changed_ns_list_log(&ns_list, devicename, flags);
	else
		nvme_show_status("changed-ns-list", err);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve desired number of bytes "\
		"from a given log on a specified device in either "\
		"hex-dump (default) or binary format";
	const char *namespace_id = "desired namespace";
	const char *log_id = "identifier of log to retrieve";
	const char *log_len = "how many bytes to retrieve";
	const char *aen = "result of the aen, use to override log id";
	const char *lsp = "log specific field";
	const char *lpo = "log page offset specifies the location within a log page from where to start returning data";
	const char *rae = "retain an asynchronous event";
	const char *raw = "output in raw format";
	const char *uuid_index = "UUID index";

	bool huge = false;
	int err, fd;
	void *log;

	struct config {
		__u32 namespace_id;
		__u32 log_id;
		__u32 log_len;
		__u32 aen;
		__u64 lpo;
		__u8  lsp;
		__u8  uuid_index;
		int   rae;
		int   raw_binary;
	};

	struct config cfg = {
		.namespace_id = NVME_NSID_ALL,
		.log_id       = 0xffffffff,
		.lpo          = 0,
		.lsp          = NVME_LOG_LSP_NONE,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_UINT("log-id",       'i', &cfg.log_id,       log_id),
		OPT_UINT("log-len",      'l', &cfg.log_len,      log_len),
		OPT_UINT("aen",          'a', &cfg.aen,          aen),
		OPT_LONG("lpo",          'o', &cfg.lpo,          lpo),
		OPT_BYTE("lsp",          's', &cfg.lsp,          lsp),
		OPT_FLAG("rae",          'r', &cfg.rae,          rae),
		OPT_BYTE("uuid-index",   'U', &cfg.uuid_index,   uuid_index),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (cfg.aen) {
		cfg.log_len = 4096;
		cfg.log_id = (cfg.aen >> 16) & 0xff;
	}

	if (cfg.log_id > 0xff) {
		fprintf(stderr, "Invalid log identifier: %d. Valid range: 0-255\n", cfg.log_id);
		err = -EINVAL;
		goto close_fd;
	}

	if (!cfg.log_len) {
		fprintf(stderr, "non-zero log-len is required param\n");
		err = -EINVAL;
		goto close_fd;
	}

	log = nvme_alloc(cfg.log_len, &huge);
	if (!log) {
		fprintf(stderr, "could not alloc buffer for log: %s\n",
				strerror(errno));
		err = -errno;
		goto close_fd;
	}

	err = nvme_get_log(fd, cfg.log_id, cfg.namespace_id, cfg.lpo, cfg.lsp, 
			     0, cfg.rae, cfg.uuid_index, cfg.log_len, log);
	if (!err) {
		if (!cfg.raw_binary) {
			printf("Device:%s log-id:%d namespace-id:%#x\n",
			       devicename, cfg.log_id, cfg.namespace_id);
			d(log, cfg.log_len, 16, 1);
		} else
			d_raw((unsigned char *)log, cfg.log_len);
	} else
		nvme_show_status("log-page", err);

	nvme_free(log, huge);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int sanitize_log(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Retrieve sanitize log and show it.";
	const char *raw = "show log in binary format";
	const char *human_readable = "show log in readable format";
	struct nvme_sanitize_log_page log;
	enum nvme_print_flags flags;
	int fd, err;

	struct config {
		int   raw_binary;
		int   human_readable;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",  'o', &cfg.output_format,  output_format),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	if (cfg.raw_binary)
		flags = BINARY;
	if (cfg.human_readable)
		flags |= VERBOSE;

	err = nvme_get_log_sanitize(fd, true, &log);
	if (!err)
		nvme_show_sanitize_log(&log, devicename, flags);
	else
		nvme_show_status("sanitize-status-log", err);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int list_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Show controller list information for the subsystem the "\
		"given device is part of, or optionally controllers attached to a specific namespace.";
	const char *controller = "controller to display";
	const char *namespace_id = "optional namespace attached to controller";

	struct nvme_ctrl_list cntlist;
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		__u16 cntid;
		__u32 namespace_id;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_SHRT("cntid",        'c', &cfg.cntid,         controller),
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;;

	if (cfg.namespace_id)
		err = nvme_identify_nsid_ctrl_list(fd, cfg.namespace_id, cfg.cntid, &cntlist);
	else
		err = nvme_identify_ctrl_list(fd, cfg.cntid, &cntlist);

	if (!err) {
	} else
		nvme_show_status("id-controller-list", err);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int list_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "For the specified controller handle, show the "\
		"namespace list in the associated NVMe subsystem, optionally starting with a given nsid.";
	const char *namespace_id = "first nsid returned list should start from";
	const char *all = "show all namespaces in the subsystem, whether attached or inactive";
	enum nvme_print_flags flags;
	int err, fd;

	struct nvme_ns_list ns_list;

	struct config {
		__u32 namespace_id;
		int  all;
		char *output_format;
	};

	struct config cfg = {
		.namespace_id = 1,
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",  'o', &cfg.output_format, output_format),
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,   namespace_id),
		OPT_FLAG("all",          'a', &cfg.all,            all),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	if (!cfg.namespace_id) {
		err = -EINVAL;
		fprintf(stderr, "invalid nsid parameter\n");
		goto close_fd;
	}

	if (cfg.all)
		err = nvme_identify_allocated_ns_list(fd, cfg.namespace_id - 1,
				    &ns_list);
	else
		err = nvme_identify_active_ns_list(fd, cfg.namespace_id - 1,
				    &ns_list);
	if (!err)
		nvme_show_changed_ns_list_log(&ns_list, devicename, flags);
	else
		nvme_show_status("id-namespace=list", err);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int delete_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Sends a namespace management command to delete the " \
		"provided namespace. All controllers should be detached from the " \
		"amespace prior to deletion.";
	const char *namespace_id = "namespace to delete";
	const char *timeout = "timeout value, in milliseconds";
	int err, fd;

	struct config {
		__u32	namespace_id;
		__u32	timeout;
	};

	struct config cfg = {
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_UINT("timeout",      't', &cfg.timeout,      timeout),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (S_ISBLK(nvme_stat.st_mode)) {
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id < 0) {
			err = cfg.namespace_id;
			goto close_fd;
		}
	} else if (!cfg.namespace_id) {
		fprintf(stderr, "%s: namespace-id parameter required\n",
						cmd->name);
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_ns_mgmt_delete(fd, cfg.namespace_id);
	if (!err)
		printf("%s: Success, deleted nsid:%d\n", cmd->name, cfg.namespace_id);
	else
		nvme_show_status("delete-namespace", err);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int nvme_attach_ns(int argc, char **argv, int attach, const char *desc, struct command *cmd)
{
	int err, num, i, fd, list[2048];
	__u16 ctrlist[2048];

	const char *namespace_id = "namespace to attach";
	const char *cont = "optional comma-sep controller id list";

	struct config {
		char  *cntlist;
		__u32 namespace_id;
	};

	struct config cfg = { 0 };

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_LIST("controllers",  'c', &cfg.cntlist,      cont),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (!cfg.namespace_id) {
		fprintf(stderr, "%s: namespace-id parameter required\n",
						cmd->name);
		err = -EINVAL;
		goto close_fd;
	}

	num = argconfig_parse_comma_sep_array(cfg.cntlist, list, 2047);
	if (num <= 0) {
		fprintf(stderr, "%s: controller id list is required\n",
						cmd->name);
		err = -EINVAL;
		goto close_fd;
	}

	for (i = 0; i < num; i++)
		ctrlist[i] = (uint16_t)list[i];

	if (attach)
		err = nvme_namespace_attach_ctrls(fd, cfg.namespace_id, num, ctrlist);
	else
		err = nvme_namespace_detach_ctrls(fd, cfg.namespace_id, num, ctrlist);

	if (!err)
		printf("%s: Success, nsid:%d\n", cmd->name, cfg.namespace_id);
	else
		nvme_show_status(attach ? "attach namespace" : "detach namespace", err);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int attach_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Attach the given namespace to the "\
		"given controller or comma-sep list of controllers. ID of the "\
		"given namespace becomes active upon attachment to a "\
		"controller. A namespace must be attached to a controller "\
		"before IO commands may be directed to that namespace.";
	return nvme_attach_ns(argc, argv, 1, desc, cmd);
}

static int detach_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Detach the given namespace from the "\
		"given controller; de-activates the given namespace's ID. A "\
		"namespace must be attached to a controller before IO "\
		"commands may be directed to that namespace.";
	return nvme_attach_ns(argc, argv, 0, desc, cmd);
}

static int create_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send a namespace management command "\
		"to the specified device to create a namespace with the given "\
		"parameters. The next available namespace ID is used for the "\
		"create operation. Note that create-ns does not attach the "\
		"namespace to a controller, the attach-ns command is needed.";
	const char *nsze = "size of ns";
	const char *ncap = "capacity of ns";
	const char *flbas = "FLBA size";
	const char *dps = "data protection capabilities";
	const char *nmic = "multipath and sharing capabilities";
	const char *anagrpid = "ANA Group Identifier";
	const char *nvmsetid = "NVM Set Identifier";
	const char *timeout = "timeout value, in milliseconds";
	const char *bs = "target block size";

	int err = 0, fd, i;
	struct nvme_id_ns ns;
	__u32 nsid;

	struct config {
		__u64	nsze;
		__u64	ncap;
		__u8	flbas;
		__u8	dps;
		__u8	nmic;
		__u32	anagrpid;
		__u16	nvmsetid;
		__u64	bs;
		__u32	timeout;
	};

	struct config cfg = {
		.flbas		= 0xff,
	};

	OPT_ARGS(opts) = {
		OPT_SUFFIX("nsze",       's', &cfg.nsze,     nsze),
		OPT_SUFFIX("ncap",       'c', &cfg.ncap,     ncap),
		OPT_BYTE("flbas",        'f', &cfg.flbas,    flbas),
		OPT_BYTE("dps",          'd', &cfg.dps,      dps),
		OPT_BYTE("nmic",         'm', &cfg.nmic,     nmic),
		OPT_UINT("anagrp-id",	 'a', &cfg.anagrpid, anagrpid),
		OPT_UINT("nvmset-id",	 'i', &cfg.nvmsetid, nvmsetid),
		OPT_SUFFIX("block-size", 'b', &cfg.bs,       bs),
		OPT_UINT("timeout",      't', &cfg.timeout,  timeout),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (cfg.flbas != 0xff && cfg.bs != 0x00) {
		fprintf(stderr,
			"Invalid specification of both FLBAS and Block Size, please specify only one\n");
		err = -EINVAL;
		goto close_fd;
	}

	if (cfg.bs) {
		if ((cfg.bs & (~cfg.bs + 1)) != cfg.bs) {
			fprintf(stderr,
				"Invalid value for block size (%"PRIu64"). "\
				"Block size must be a power of two\n",
				(uint64_t)cfg.bs);
			err = -EINVAL;
			goto close_fd;
		}

		err = nvme_identify_ns(fd, NVME_NSID_ALL, &ns);
		if (err) {
			nvme_show_status("identify-namespace", err);
			goto close_fd;
		}

		for (i = 0; i < 16; ++i) {
			if ((1 << ns.lbaf[i].ds) == cfg.bs && ns.lbaf[i].ms == 0) {
				cfg.flbas = i;
				break;
			}
		}

	}

	if (cfg.flbas == 0xff) {
		fprintf(stderr,
			"FLBAS corresponding to block size %"PRIu64" not found\n",
			(uint64_t)cfg.bs);
		fprintf(stderr,
			"Please correct block size, or specify FLBAS directly\n");
		err = -EINVAL;
		goto close_fd;
	}

	nvme_init_id_ns(&ns, cfg.nsze, cfg.ncap, cfg.flbas, cfg.dps, cfg.nmic,
			 cfg.anagrpid, cfg.nvmsetid);
	err = nvme_ns_mgmt_create(fd, &ns, &nsid, cfg.timeout);
	if (!err)
		printf("%s: Success, created nsid:%d\n", cmd->name, nsid);
	else
		nvme_show_status("create-namespace", err);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static bool nvme_match_device_filter(nvme_subsystem_t s)
{
	nvme_ctrl_t c;
	nvme_ns_t n;

	if (!devicename || !strlen(devicename))
		return true;

	nvme_subsystem_for_each_ctrl(s, c)
		if (!strcmp(devicename, nvme_ctrl_get_name(c)))
			return true;

	nvme_subsystem_for_each_ns(s, n)
		if (!strcmp(devicename, nvme_ns_get_name(n)))
			return true;

	return false;
}

static void nvme_show_subsystem_list(nvme_root_t r, unsigned long flags)
{
	nvme_subsystem_t s, _s;
	nvme_ctrl_t c, _c;
	nvme_path_t p, _p;
	nvme_ns_t n, _n;

	printf(".\n");
	nvme_for_each_subsystem_safe(r, s, _s) {
		printf("%c-- %s - NQN=%s\n",
			_s ? '|' : '`',
			nvme_subsystem_get_name(s),
			nvme_subsystem_get_nqn(s));

		nvme_subsystem_for_each_ns_safe(s, n, _n) {
			printf("%c   |-- %s lba size:%d lba max:%lu\n",
				_s ? '|' : ' ',
				nvme_ns_get_name(n), nvme_ns_get_lba_size(n),
				nvme_ns_get_lba_count(n));
		}

		nvme_subsystem_for_each_ctrl_safe(s, c, _c) {
			printf("%c   %c-- %s %s %s %s\n",
				_s ? '|' : ' ',
				_c ? '|' : '`',
				nvme_ctrl_get_name(c),
				nvme_ctrl_get_transport(c),
				nvme_ctrl_get_address(c),
				nvme_ctrl_get_state(c));

			nvme_ctrl_for_each_ns_safe(c, n, _n) 
				printf("%c   %c   %c-- %s lba size:%d lba max:%lu\n",
					_s ? '|' : ' ', 
					_c ? '|' : ' ', 
					_n ? '|' : '`',
					nvme_ns_get_name(n),
					nvme_ns_get_lba_size(n),
					nvme_ns_get_lba_count(n));

			nvme_ctrl_for_each_path_safe(c, p, _p) 
				printf("%c   %c   %c-- %s %s\n",
					_s ? '|' : ' ',
					_c ? '|' : ' ', 
					_p ? '|' : '`',
					nvme_path_get_name(p),
					nvme_path_get_ana_state(p));
		}
	}
	printf("\n");
}

static const char dash[101] = {[0 ... 99] = '-'};

static void nvme_show_list(nvme_root_t r, unsigned long flags)
{
	nvme_subsystem_t s;
	nvme_ctrl_t c;
	nvme_path_t p;
	nvme_ns_t n;

	printf("%-16s %-96s %-.16s\n", "Subsystem", "Subsystem-NQN", "Controllers");
	printf("%-.16s %-.96s %-.16s\n", dash, dash, dash);

	nvme_for_each_subsystem(r, s) {
		bool first = true;
		printf("%-16s %-96s ", nvme_subsystem_get_name(s), nvme_subsystem_get_nqn(s));

		nvme_subsystem_for_each_ctrl(s, c) {
			printf("%s%s", first ? "": ", ", nvme_ctrl_get_name(c));
			first = false;
		}
		printf("\n");
	}
	printf("\n");

	printf("%-8s %-20s %-40s %-8s %-6s %-14s %-12s %-16s\n", "Device",
		"SN", "MN", "FR", "TxPort", "Address", "Subsystem", "Namespaces");
	printf("%-.8s %-.20s %-.40s %-.8s %-.6s %-.14s %-.12s %-.16s\n", dash, dash,
		dash, dash, dash, dash, dash, dash);

	nvme_for_each_subsystem(r, s) {
		nvme_subsystem_for_each_ctrl(s, c) {
			bool first = true;

			printf("%-8s %-20s %-40s %-8s %-6s %-14s %-12s ",
				nvme_ctrl_get_name(c), nvme_ctrl_get_serial(c),
				nvme_ctrl_get_model(c), nvme_ctrl_get_firmware(c),
				nvme_ctrl_get_transport(c), nvme_ctrl_get_address(c),
				nvme_subsystem_get_name(s));

			nvme_ctrl_for_each_ns(c, n) {
				printf("%s%s", first ? "": ", ",
					nvme_ns_get_name(n));
				first = false;
			}

			nvme_ctrl_for_each_path(c, p) {
				printf("%s%s", first ? "": ", ",
					nvme_ns_get_name(nvme_path_get_ns(p)));
				first = false;
			}
			printf("\n");
		}
	}
	printf("\n");

 	printf("%-12s %-8s %-26s %-16s %-16s\n", "Device", "NSID", "Usage", "Format", "Controllers");
	printf("%-.12s %-.8s %-.26s %-.16s %-.16s\n", dash, dash, dash, dash, dash);

	nvme_for_each_subsystem(r, s) {
		nvme_subsystem_for_each_ctrl(s, c)
			nvme_ctrl_for_each_ns(c, n)
				printf("%-12s %8d %lu/%lu %16d %s\n",
					nvme_ns_get_name(n),
					nvme_ns_get_nsid(n),
					nvme_ns_get_lba_count(n),
					nvme_ns_get_lba_util(n),
					nvme_ns_get_lba_size(n),
					nvme_ctrl_get_name(c));

		nvme_subsystem_for_each_ns(s, n) {
			bool first = true;

			printf("%-12s %8d %lu/%lu %16d ",
				nvme_ns_get_name(n),
				nvme_ns_get_nsid(n),
				nvme_ns_get_lba_count(n),
				nvme_ns_get_lba_util(n),
				nvme_ns_get_lba_size(n));

			nvme_subsystem_for_each_ctrl(s, c) {
				printf("%s%s", first ? "" : ", ",
					nvme_ctrl_get_name(c));
				first = false;
			}
			printf("\n");
		}
	}

}

static int list_subsys(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Retrieve information for subsystems";
	const char *verbose = "Increase output verbosity";

	enum nvme_print_flags flags;
	nvme_root_t r;
	int err;

	struct config {
		char *output_format;
		int verbose;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("verbose",      'v', &cfg.verbose,       verbose),
		OPT_END()
	};

	err = argconfig_parse(argc, argv, desc, opts);
	if (err < 0)
		return err;

	devicename = NULL;
	if (optind < argc)
		devicename = basename(argv[optind++]);

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		return err;

	if (cfg.verbose)
		flags |= 0;

	if (devicename)
		r = nvme_scan_filter(nvme_match_device_filter);
	else
		r = nvme_scan();

	if (r) {
		nvme_show_subsystem_list(r, flags);
		nvme_free_tree(r);
	} else {
		if (devicename)
			fprintf(stderr, "Failed to scan nvme subsystem for %s\n", devicename);
		else
			fprintf(stderr, "Failed to scan nvme subssytems\n");
		err = -errno;
	}

	return err;
}

static int list(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve basic information for all NVMe namespaces";
	const char *verbose = "Increase output verbosity";

	enum nvme_print_flags flags;
	nvme_root_t r;
	int err;

	struct config {
		char *output_format;
		int verbose;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("verbose",      'v', &cfg.verbose,       verbose),
		OPT_END()
	};

	err = argconfig_parse(argc, argv, desc, opts);
	if (err < 0)
		return err;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		return err;
	if (cfg.verbose)
		flags |= 0;

	r = nvme_scan();

	if (r) {
		nvme_show_list(r, flags);
		nvme_free_tree(r);
	} else {
		fprintf(stderr, "Failed to scan nvme subssytems\n");
		err = -errno;
	}

	return 0;
}

int id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Controller command to "\
		"the given device and report information about the specified "\
		"controller in human-readable or "\
		"binary format. May also return vendor-specific "\
		"controller attributes in hex-dump if requested.";
	const char *vendor_specific = "dump binary vendor field";
	const char *raw = "show identify in binary format";
	const char *human_readable = "show identify in readable format";

	enum nvme_print_flags flags;
	struct nvme_id_ctrl ctrl;
	int err, fd;

	struct config {
		int vendor_specific;
		int raw_binary;
		int human_readable;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("vendor-specific", 'v', &cfg.vendor_specific, vendor_specific),
		OPT_FMT("output-format",    'o', &cfg.output_format,   output_format),
		OPT_FLAG("raw-binary",      'b', &cfg.raw_binary,      raw),
		OPT_FLAG("human-readable",  'H', &cfg.human_readable,  human_readable),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	if (cfg.raw_binary)
		flags = 0;
	if (cfg.vendor_specific)
		flags |= 0;
	if (cfg.human_readable)
		flags |= VERBOSE;

	err = nvme_identify_ctrl(fd, &ctrl);
	if (!err)
		nvme_show_id_ctrl(&ctrl, flags);
	else
		nvme_show_status("identify-controller", err);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

int __id_ctrl(int argc, char **argv, struct command *cmd,
	struct plugin *plugin, void (*vs)(__u8 *vs, struct json_object *root))
{
	return id_ctrl(argc, argv, cmd, plugin);
}

static int ns_descs(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send Namespace Identification Descriptors command to the "\
			    "given device, returns the namespace identification descriptors "\
			    "of the specific namespace in either human-readable or binary format.";
	const char *raw = "show descriptors in binary format";
	const char *namespace_id = "identifier of desired namespace";
	enum nvme_print_flags flags;
	void *nsdescs;
	int err, fd;

	struct config {
		__u32 namespace_id;
		int raw_binary;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id,  namespace_id),
		OPT_FMT("output-format",  'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = 0;

	if (!cfg.namespace_id) {
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id < 0) {
			err = cfg.namespace_id;
			goto close_fd;
		}
	}

	if (posix_memalign(&nsdescs, getpagesize(), 0x1000)) {
		fprintf(stderr, "can not allocate controller list payload\n");
		err = -1;
		goto close_fd;
	}

	err = nvme_identify_ns_descs(fd, cfg.namespace_id, nsdescs);
	if (!err) {
		nvme_show_id_ns_descs(nsdescs, cfg.namespace_id, flags);
	} else
		nvme_show_status("identify-namespace-descriptors", err);
	free(nsdescs);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int id_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace command to the "\
		"given device, returns properties of the specified namespace "\
		"in either human-readable or binary format. Can also return "\
		"binary vendor-specific namespace attributes.";
	const char *force = "Return this namespace, even if not attaced (1.2 devices only)";
	const char *vendor_specific = "dump binary vendor fields";
	const char *raw = "show identify in binary format";
	const char *human_readable = "show identify in readable format";
	const char *namespace_id = "identifier of desired namespace";

	enum nvme_print_flags flags;
	struct nvme_id_ns ns;
	int err, fd;

	struct config {
		__u32 namespace_id;
		int   vendor_specific;
		int   raw_binary;
		int   human_readable;
		int   force;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",    'n', &cfg.namespace_id,    namespace_id),
		OPT_FLAG("force",           'f', &cfg.force,           force),
		OPT_FLAG("vendor-specific", 'v', &cfg.vendor_specific, vendor_specific),
		OPT_FLAG("raw-binary",      'b', &cfg.raw_binary,      raw),
		OPT_FMT("output-format",    'o', &cfg.output_format,   output_format),
		OPT_FLAG("human-readable",  'H', &cfg.human_readable,  human_readable),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = BINARY;
	if (cfg.vendor_specific)
		flags |= 0;
	if (cfg.human_readable)
		flags |= VERBOSE;

	if (!cfg.namespace_id && S_ISBLK(nvme_stat.st_mode)) {
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id < 0) {
			err = cfg.namespace_id;
			goto close_fd;
		}
	} else if (!cfg.namespace_id) {
		fprintf(stderr,
			"Error: requesting namespace-id from non-block device\n");
		err = -ENOTBLK;
		goto close_fd;
	}

	if (cfg.force)
		err = nvme_identify_allocated_ns(fd, cfg.namespace_id, &ns);
	else
		err = nvme_identify_ns(fd, cfg.namespace_id, &ns);

	if (!err)
		nvme_show_id_ns(&ns, cfg.namespace_id, flags);
	else
		nvme_show_status("identify-namespace", err);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int id_ns_granularity(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace Granularity List command to the "\
		"given device, returns namespace granularity list "\
		"in either human-readable or binary format.";

	struct nvme_id_ns_granularity_list *glist;
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	if (posix_memalign((void *)&glist, getpagesize(),
			   NVME_IDENTIFY_DATA_SIZE)) {
		fprintf(stderr, "can not allocate granularity list payload\n");
		err = -1;
		goto close_fd;
	}

	err = nvme_identify_ns_granularity(fd, (void *)glist);
	if (!err)
		nvme_show_id_ns_granularity_list(glist, flags);
	else
		nvme_show_status("identify-namespace-granularity", err);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int id_nvmset(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify NVM Set List command to the "\
		"given device, returns entries for NVM Set identifiers greater "\
		"than or equal to the value specified CDW11.NVMSETID "\
		"in either binary format or json format";
	const char *nvmset_id = "NVM Set Identify value";

	struct nvme_id_nvmset_list nvmset;
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		__u16 nvmset_id;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_UINT("nvmset_id",    'i', &cfg.nvmset_id,     nvmset_id),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	err = nvme_identify_nvmset_list(fd, cfg.nvmset_id, &nvmset);
	if (!err)
		nvme_show_id_nvmset(&nvmset, cfg.nvmset_id, flags);
	else
		nvme_show_status("identify-nvmset-list", err);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int id_uuid(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify UUID List command to the "\
		"given device, returns list of supported Vendor Specific UUIDs "\
		"in either human-readable or binary format.";
	const char *raw = "show uuid in binary format";
	const char *human_readable = "show uuid in readable format";

	struct nvme_id_uuid_list uuid_list;
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		int   raw_binary;
		int   human_readable;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",   'o', &cfg.output_format,  output_format),
		OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw),
		OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return fd;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = BINARY;
	if (cfg.human_readable)
		flags |= VERBOSE;

	err = nvme_identify_uuid(fd, &uuid_list);
	if (!err)
		nvme_show_id_uuid_list(&uuid_list, flags);
	else
		nvme_show_status("identify-uuid-list", err);
close_fd:
	close(fd);
	return err;
}

static int get_ns_id(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err = 0, nsid, fd;
	const char *desc = "Get namespce ID of a the block device.";

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	nsid = nvme_get_nsid(fd);
	if (nsid <= 0) {
		perror(devicename);
		err = errno;
		goto close_fd;
	}
	err = 0;
	printf("%s: namespace-id:%d\n", devicename, nsid);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int virtual_mgmt(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc  = "The Virtualization Management command is supported by primary controllers "\
		"that support the Virtualization Enhancements capability. This command is used for:\n"\
		"  1. Modifying Flexible Resource allocation for the primary controller\n"\
		"  2. Assigning Flexible Resources for secondary controllers\n"\
		"  3. Setting the Online and Offline state for secondary controllers";
	const char *cntlid = "Controller Identifier(CNTLID)";
	const char *rt = "Resource Type(RT): [0,1]\n"\
		"0h: VQ Resources\n"\
		"1h: VI Resources";
	const char *act = "Action(ACT): [1,7,8,9]\n"\
		"1h: Primary Flexible\n"\
		"7h: Secondary Offline\n"\
		"8h: Secondary Assign\n"\
		"9h: Secondary Online";
	const char *nr = "Number of Controller Resources(NR)";
	int fd, err;
	__u32 result;

	struct config {
		__u16	cntlid;
		__u8	rt;
		__u8	act;
		__u16	nr;
	};

	struct config cfg = { 0 };

	OPT_ARGS(opts) = {
		OPT_SHRT("cntlid", 'c', &cfg.cntlid, cntlid),
		OPT_BYTE("rt",     'r', &cfg.rt,     rt),
		OPT_BYTE("act",    'a', &cfg.act,    act),
		OPT_SHRT("nr",     'n', &cfg.nr,     nr),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = nvme_virtual_mgmt(fd, cfg.act, cfg.rt, cfg.cntlid, cfg.nr,
				&result);
	if (!err)
		printf("success, Number of Resources allocated:%#x\n", result);
	else
		nvme_show_status("virt-mgmt", err);

	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int list_secondary_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Show secondary controller list associated with the primary controller "\
		"of the given device.";
	const char *controller = "lowest controller identifier to display";
	const char *namespace_id = "optional namespace attached to controller";
	const char *num_entries = "number of entries to retrieve";

	struct nvme_secondary_ctrl_list *sc_list;
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		__u16 cntid;
		__u32 num_entries;
		__u32 namespace_id;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
		.num_entries = ARRAY_SIZE(sc_list->sc_entry),
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_SHRT("cntid",        'c', &cfg.cntid,         controller),
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_UINT("num-entries",  'e', &cfg.num_entries,   num_entries),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	if (!cfg.num_entries) {
		fprintf(stderr, "non-zero num-entries is required param\n");
		err = -EINVAL;
		goto close_fd;
	}

	if (posix_memalign((void *)&sc_list, getpagesize(), sizeof(*sc_list))) {
		fprintf(stderr, "can not allocate controller list payload\n");
		err = -1;
		goto close_fd;
	}

	err = nvme_identify_secondary_ctrl_list(fd, cfg.cntid, sc_list);
	if (!err)
		nvme_show_list_secondary_ctrl(sc_list, 0, flags);
	else
		nvme_show_status("id-secondary-controller-list", err);

	free(sc_list);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int device_self_test(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc  = "Implementing the device self-test feature"\
		" which provides the necessary log to determine the state of the device";
	const char *namespace_id = "Indicate the namespace in which the device self-test"\
		" has to be carried out";
	const char * self_test_code = "This field specifies the action taken by the device self-test command : "\
		"\n1h Start a short device self-test operation\n"\
		"2h Start a extended device self-test operation\n"\
		"eh Start a vendor specific device self-test operation\n"\
		"fh abort the device self-test operation\n";
	int fd, err;

	struct config {
		__u32 namespace_id;
		__u32 stc;
	};

	struct config cfg = {
		.namespace_id  = NVME_NSID_ALL,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",   'n', &cfg.namespace_id, namespace_id),
		OPT_UINT("self-test-code", 's', &cfg.stc,          self_test_code),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = nvme_dev_self_test(fd, cfg.namespace_id, cfg.stc);
	if (!err) {
		if ((cfg.stc & 0xf) == 0xf)
			printf("Aborting device self-test operation\n");
		else
			printf("Device self-test started\n");
	} else
		nvme_show_status("device-self-test", err);

	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int self_test_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve the self-test log for the given device and given test "\
			"(or optionally a namespace) in either decoded format "\
			"(default) or binary.";
	const char *namespace_id = "Indicate the namespace from which the self-test "\
				    "log has to be obtained";
	const char *verbose = "Increase output verbosity";

	struct nvme_self_test_log log;
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		__u32 namespace_id;
		char *output_format;
		int verbose;
	};

	struct config cfg = {
		.namespace_id = NVME_NSID_ALL,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_FLAG("verbose",      'v', &cfg.verbose,       verbose),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.verbose)
		flags |= 0;

	err = nvme_get_log_device_self_test(fd, &log);
	if (!err)
		nvme_show_self_test_log(&log, devicename, flags);
	else
		nvme_show_status("self-test-log", err);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_feature(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Read operating parameters of the "\
		"specified controller. Operating parameters are grouped "\
		"and identified by Feature Identifiers; each Feature "\
		"Identifier contains one or more attributes that may affect "\
		"behaviour of the feature. Each Feature has three possible "\
		"settings: default, saveable, and current. If a Feature is "\
		"saveable, it may be modified by set-feature. Default values "\
		"are vendor-specific and not changeable. Use set-feature to "\
		"change saveable Features.";
	const char *raw = "show feature in binary format";
	const char *namespace_id = "identifier of desired namespace";
	const char *feature_id = "feature identifier";
	const char *sel = "[0-3]: current/default/saved/supported";
	const char *data_len = "buffer len if data is returned through host memory buffer";
	const char *cdw11 = "dword 11 for interrupt vector config";
	const char *human_readable = "show feature in readable format";

	enum nvme_print_flags flags;
	void *buf = NULL;
	__u32 result;
	int err, fd;

	struct config {
		__u32 namespace_id;
		__u32 feature_id;
		__u8  sel;
		__u32 cdw11;
		__u32 data_len;
		int  raw_binary;
		int  human_readable;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",  'o', &cfg.output_format,  output_format),
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id,   namespace_id),
		OPT_UINT("feature-id",    'f', &cfg.feature_id,     feature_id),
		OPT_BYTE("sel",           's', &cfg.sel,            sel),
		OPT_UINT("data-len",      'l', &cfg.data_len,       data_len),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw),
		OPT_UINT("cdw11",         'c', &cfg.cdw11,          cdw11),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	if (cfg.human_readable)
		flags |= VERBOSE;

	if (cfg.sel > 7) {
		fprintf(stderr, "invalid 'select' param:%d\n", cfg.sel);
		err = -EINVAL;
		goto close_fd;
	}

	if (!cfg.feature_id) {
		fprintf(stderr, "feature-id required param\n");
		err = -EINVAL;
		goto close_fd;
	}

	if (cfg.sel == 3)
		cfg.data_len = 0;
	else if (!cfg.data_len)
		nvme_get_feature_length(cfg.feature_id, cfg.cdw11, &cfg.data_len);

	if (cfg.data_len) {
		if (posix_memalign(&buf, getpagesize(), cfg.data_len)) {
			fprintf(stderr, "can not allocate feature payload\n");
			err = -1;
			goto close_fd;
		}
		memset(buf, 0, cfg.data_len);
	}

	err = nvme_get_features(fd, cfg.feature_id, cfg.namespace_id, cfg.sel, cfg.cdw11,
			0, cfg.data_len, buf, &result);
	if (!err)
		nvme_feature_show_fields(cfg.feature_id, result, buf);
	else
		nvme_show_status("get-feature", err);

	if (buf)
		free(buf);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int fw_download(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Copy all or part of a firmware image to "\
		"a controller for future update. Optionally, specify how "\
		"many KiB of the firmware to transfer at once. The offset will "\
		"start at 0 and automatically adjust based on xfer size "\
		"unless fw is split across multiple files. May be submitted "\
		"while outstanding commands exist on the Admin and IO "\
		"Submission Queues. Activate downloaded firmware with "\
		"fw-activate, and then reset the device to apply the downloaded firmware.";
	const char *fw = "firmware file (required)";
	const char *xfer = "transfer chunksize limit";
	const char *offset = "starting dword offset, default 0";
	int err, fd, fw_fd = -1;
	unsigned int fw_size;
	struct stat sb;
	void *fw_buf, *buf;
	bool huge;

	struct config {
		char  *fw;
		__u32 xfer;
		__u32 offset;
	};

	struct config cfg = {
		.fw     = "",
		.xfer   = 4096,
	};

	OPT_ARGS(opts) = {
		OPT_FILE("fw",     'f', &cfg.fw,     fw),
		OPT_UINT("xfer",   'x', &cfg.xfer,   xfer),
		OPT_UINT("offset", 'o', &cfg.offset, offset),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (!cfg.fw) {
		fprintf(stderr,
			"Required parameter [-fw | -f] not specified\n");
		err = -EINVAL;
		goto close_fd;
	}

	fw_fd = open(cfg.fw, O_RDONLY);
	cfg.offset <<= 2;
	if (fw_fd < 0) {
		fprintf(stderr, "Failed to open firmware file %s: %s\n",
				cfg.fw, strerror(errno));
		err = -EINVAL;
		goto close_fd;
	}

	err = fstat(fw_fd, &sb);
	if (err < 0) {
		perror("fstat");
		goto close_fw_fd;
	}

	fw_size = sb.st_size;
	if (fw_size & 0x3) {
		fprintf(stderr, "Invalid size:%d for f/w image\n", fw_size);
		err = -EINVAL;
		goto close_fw_fd;
	}

	fw_buf = nvme_alloc(fw_size, &huge);
	if (!fw_buf) {
		fprintf(stderr, "No memory for f/w size:%d\n", fw_size);
		err = -1;
		goto close_fw_fd;
	}

	buf = fw_buf;
	if (cfg.xfer == 0 || cfg.xfer % 4096)
		cfg.xfer = 4096;

	if (read(fw_fd, fw_buf, fw_size) != ((ssize_t)(fw_size))) {
		fprintf(stderr, "read :%s :%s\n", cfg.fw, strerror(errno));
		err = -errno;
		goto free;
	}

	err = nvme_fw_download_seq(fd, fw_size, cfg.xfer, cfg.offset, fw_buf);
	if (!err)
		printf("Firmware download success\n");
	else
		nvme_show_status("fw-download", err);

free:
	nvme_free(buf, huge);
close_fw_fd:
	close(fw_fd);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int fw_commit(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Verify downloaded firmware image and "\
		"commit to specific firmware slot. Device is not automatically "\
		"reset following firmware activation. A reset may be issued "\
		"with an 'echo 1 > /sys/class/nvme/nvmeX/reset_controller'. "\
		"Ensure nvmeX is the device you just activated before reset.";
	const char *slot = "[0-7]: firmware slot for commit action";
	const char *action = "[0-7]: commit action";
	const char *bpid = "[0,1]: boot partition identifier, if applicable (default: 0)";
	int err, fd;

	struct config {
		__u8 slot;
		__u8 action;
		__u8 bpid;
	};

	struct config cfg = { 0 };

	OPT_ARGS(opts) = {
		OPT_BYTE("slot",   's', &cfg.slot,   slot),
		OPT_BYTE("action", 'a', &cfg.action, action),
		OPT_BYTE("bpid",   'b', &cfg.bpid,   bpid),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (cfg.slot > 7) {
		fprintf(stderr, "invalid slot:%d\n", cfg.slot);
		err = -EINVAL;
		goto close_fd;
	}
	if (cfg.action > 7 || cfg.action == 4 || cfg.action == 5) {
		fprintf(stderr, "invalid action:%d\n", cfg.action);
		err = -EINVAL;
		goto close_fd;
	}
	if (cfg.bpid > 1) {
		fprintf(stderr, "invalid boot partition id:%d\n", cfg.bpid);
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_fw_commit(fd, cfg.slot, cfg.action, cfg.bpid);
	if (err >= 0) {
		switch (err & 0x3ff) {
		case NVME_SC_SUCCESS:
		case NVME_SC_FW_NEEDS_CONV_RESET:
		case NVME_SC_FW_NEEDS_SUBSYS_RESET:
		case NVME_SC_FW_NEEDS_RESET:
			printf("Success activating firmware action:%d slot:%d",
			       cfg.action, cfg.slot);
			if (cfg.action == 6 || cfg.action == 7)
				printf(" bpid:%d", cfg.bpid);
			printf("\n");
			break;
		default:
			break;
		}
	}
	if (err)
		nvme_show_status("fw-commit", err);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int subsystem_reset(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Resets the NVMe subsystem\n";
	int err, fd;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = nvme_subsystem_reset(fd);
	if (err < 0)
		perror("subsystem-reset");

	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int reset(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Resets the NVMe controller\n";
	int err, fd;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = nvme_ctrl_reset(fd);
	if (err < 0)
		perror("reset");

	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int ns_rescan(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Rescans the NVMe namespaces\n";
	int err, fd;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = nvme_ns_rescan(fd);
	if (err < 0)
		perror("namespace-rescan");

	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int sanitize(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send a sanitize command.";
	const char *no_dealloc_desc = "No deallocate after sanitize.";
	const char *oipbp_desc = "Overwrite invert pattern between passes.";
	const char *owpass_desc = "Overwrite pass count.";
	const char *ause_desc = "Allow unrestricted sanitize exit.";
	const char *sanact_desc = "Sanitize action.";
	const char *ovrpat_desc = "Overwrite pattern.";

	int fd, err;

	struct config {
		int    no_dealloc;
		int    oipbp;
		__u8   owpass;
		int    ause;
		__u8   sanact;
		__u32  ovrpat;
	};

	struct config cfg = { 0 };

	OPT_ARGS(opts) = {
		OPT_FLAG("no-dealloc", 'd', &cfg.no_dealloc, no_dealloc_desc),
		OPT_FLAG("oipbp",      'i', &cfg.oipbp,      oipbp_desc),
		OPT_BYTE("owpass",     'n', &cfg.owpass,     owpass_desc),
		OPT_FLAG("ause",       'u', &cfg.ause,       ause_desc),
		OPT_BYTE("sanact",     'a', &cfg.sanact,     sanact_desc),
		OPT_UINT("ovrpat",     'p', &cfg.ovrpat,     ovrpat_desc),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto err;

	switch (cfg.sanact) {
	case NVME_SANITIZE_SANACT_EXIT_FAILURE:
	case NVME_SANITIZE_SANACT_START_BLOCK_ERASE:
	case NVME_SANITIZE_SANACT_START_OVERWRITE:
	case NVME_SANITIZE_SANACT_START_CRYPTO_ERASE:
		break;
	default:
		fprintf(stderr, "Invalid Sanitize Action\n");
		err = -EINVAL;
		goto close_fd;
	}

	if (cfg.sanact == NVME_SANITIZE_SANACT_EXIT_FAILURE) {
	       if (cfg.ause || cfg.no_dealloc) {
			fprintf(stderr, "SANACT is Exit Failure Mode\n");
			err = -EINVAL;
			goto close_fd;
	       }
	}

	if (cfg.sanact == NVME_SANITIZE_SANACT_START_OVERWRITE) {
		if (cfg.owpass > 16) {
			fprintf(stderr, "OWPASS out of range [0-16]\n");
			err = -EINVAL;
			goto close_fd;
		}
	} else {
		if (cfg.owpass || cfg.oipbp || cfg.ovrpat) {
			fprintf(stderr, "SANACT is not Overwrite\n");
			err = -EINVAL;
			goto close_fd;
		}
	}

	err = nvme_sanitize_nvm(fd, cfg.sanact, cfg.ause, cfg.owpass, cfg.oipbp,
			    cfg.no_dealloc, cfg.ovrpat);
	nvme_show_status("sanitize", err);
close_fd:
	close(fd);
err:
	return nvme_status_to_errno(err, false);
}

static int nvme_get_properties(int fd, void **pbar)
{
	int offset;
	__u64 value;
	int err, size = getpagesize();

	*pbar = malloc(size);
	if (!*pbar) {
		fprintf(stderr, "malloc: %s\n", strerror(errno));
		return -1;
	}

	memset(*pbar, 0xff, size);
	for (offset = NVME_REG_CAP; offset <= NVME_REG_CMBSZ;) {
		err = nvme_get_property(fd, offset, &value);
		if (err > 0 && (err & 0xff) == NVME_SC_INVALID_FIELD) {
			err = 0;
			value = -1;
		} else if (err) {
			free(*pbar);
			break;
		}
		if (nvme_is_64bit_reg(offset)) {
			*(uint64_t *)(*pbar + offset) = value;
			offset += 8;
		} else {
			*(uint32_t *)(*pbar + offset) = value;
			offset += 4;
		}
	}

	return err;
}

static int show_registers(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Displays the NVMe controller registers";
	const char *human = "show info in readable format";

	enum nvme_print_flags flags;
	bool fabrics = true;
	int fd, err;
	void *bar;

	struct config {
		int human_readable;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",   'o', &cfg.output_format,  output_format),
		OPT_FLAG("human-readable", 'H', &cfg.human_readable, human),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.human_readable)
		flags |= VERBOSE;

	err = nvme_get_properties(fd, &bar);
	if (err) {
		bar = NULL;
		//mmap_registers(devicename);
		fabrics = false;
		if (bar)
			err = 0;
	}

	if (!bar)
		goto close_fd;

	nvme_show_ctrl_registers(bar, fabrics, flags);
	if (fabrics)
		free(bar);
	else
		munmap(bar, getpagesize());
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_property(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Reads and shows the defined NVMe controller property "\
			   "for NVMe over Fabric. Property offset must be one of:\n"
			   "CAP=0x0, VS=0x8, CC=0x14, CSTS=0x1c, NSSR=0x20";
	const char *offset = "offset of the requested property";
	const char *human_readable = "show property in readable format";

	int fd, err;
	__u64 value;

	struct config {
		int offset;
		int human_readable;
	};

	struct config cfg = {
		.offset = -1,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("offset",        'o', &cfg.offset,         offset),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (cfg.offset == -1) {
		fprintf(stderr, "offset required param");
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_get_property(fd, cfg.offset, &value);
	if (!err) {
	} else {
		nvme_show_status("get-property", err);
	}

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int set_property(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Writes and shows the defined NVMe controller property "\
			   "for NVMe ove Fabric";
	const char *offset = "the offset of the property";
	const char *value = "the value of the property to be set";
	int fd, err;

	struct config {
		int offset;
		int value;
	};

	struct config cfg = {
		.offset = -1,
		.value = -1,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("offset", 'o', &cfg.offset, offset),
		OPT_UINT("value",  'v', &cfg.value,  value),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (cfg.offset == -1) {
		fprintf(stderr, "offset required param");
		err = -EINVAL;
		goto close_fd;
	}
	if (cfg.value == -1) {
		fprintf(stderr, "value required param");
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_set_property(fd, cfg.offset, cfg.value);
	if (err) {
		nvme_show_status("set-property", err);
	} else {
		//printf("set-property: %02x (%s), value: %#08x\n", cfg.offset,
		//		nvme_register_to_string(cfg.offset), cfg.value);
	}

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int format(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Re-format a specified namespace on the "\
		"given device. Can erase all data in namespace (user "\
		"data erase) or delete data encryption key if specified. "\
		"Can also be used to change LBAF to change the namespaces reported physical block format.";
	const char *namespace_id = "identifier of desired namespace";
	const char *lbaf = "LBA format to apply (required)";
	const char *ses = "[0-2]: secure erase";
	const char *pil = "[0-1]: protection info location last/first 8 bytes of metadata";
	const char *pi = "[0-3]: protection info off/Type 1/Type 2/Type 3";
	const char *ms = "[0-1]: extended format off/on";
	const char *reset = "Automatically reset the controller after successful format";
	const char *timeout = "timeout value, in milliseconds";
	const char *bs = "target block size";
	const char *force = "The \"I know what I'm doing\" flag, skip confirmation before sending command";

	struct nvme_id_ctrl ctrl;
	struct nvme_id_ns ns;
	__u8 prev_lbaf = 0;
	__u8 lbads = 0;
	int err, fd, i;

	struct config {
		__u32 namespace_id;
		__u32 timeout;
		__u8  lbaf;
		__u8  ses;
		__u8  pi;
		__u8  pil;
		__u8  ms;
		__u64 bs;
		int reset;
		int force;
	};

	struct config cfg = {
		.timeout      = 600000,
		.lbaf         = 0xff,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_UINT("timeout",      't', &cfg.timeout,      timeout),
		OPT_BYTE("lbaf",         'l', &cfg.lbaf,         lbaf),
		OPT_BYTE("ses",          's', &cfg.ses,          ses),
		OPT_BYTE("pi",           'i', &cfg.pi,           pi),
		OPT_BYTE("pil",          'p', &cfg.pil,          pil),
		OPT_BYTE("ms",           'm', &cfg.ms,           ms),
		OPT_FLAG("reset",        'r', &cfg.reset,        reset),
		OPT_FLAG("force",        'f', &cfg.force,        force),
		OPT_SUFFIX("block-size", 'b', &cfg.bs,           bs),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (cfg.lbaf != 0xff && cfg.bs !=0) {
		fprintf(stderr,
			"Invalid specification of both LBAF and Block Size, please specify only one\n");
		err = -EINVAL;
		goto close_fd;
	}
	if (cfg.bs) {
		if ((cfg.bs & (~cfg.bs + 1)) != cfg.bs) {
			fprintf(stderr,
				"Invalid value for block size (%"PRIu64"), must be a power of two\n",
				       (uint64_t) cfg.bs);
			err = -EINVAL;
			goto close_fd;
		}
	}

	err = nvme_identify_ctrl(fd, &ctrl);
	if (err) {
		nvme_show_status("identify-ctrl", err);
		goto close_fd;
	}

	if ((ctrl.fna & 1) == 1) {
		/*
		 * FNA bit 0 set to 1: all namespaces ... shall be configured with the same
		 * attributes and a format (excluding secure erase) of any namespace results in a
		 * format of all namespaces.
		 */
		cfg.namespace_id = NVME_NSID_ALL;
	} else if (S_ISBLK(nvme_stat.st_mode)) {
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id < 0) {
			err = cfg.namespace_id;
			goto close_fd;
		}
	}

	if (cfg.namespace_id == 0) {
		fprintf(stderr,
			"Invalid namespace ID, "
			"specify a namespace to format or use '-n 0xffffffff' "
			"to format all namespaces on this controller.\n");
		err = -EINVAL;
		goto close_fd;
	}

	if (cfg.namespace_id != NVME_NSID_ALL) {
		err = nvme_identify_ns(fd, cfg.namespace_id, &ns);
		if (err) {
			nvme_show_status("identify-namespace", err);
			goto close_fd;
		}

		prev_lbaf = ns.flbas & 0xf;
		if (cfg.bs) {
			for (i = 0; i < 16; ++i) {
				if ((1ULL << ns.lbaf[i].ds) == cfg.bs &&
				    ns.lbaf[i].ms == 0) {
					cfg.lbaf = i;
					break;
				}
			}
			if (cfg.lbaf == 0xff) {
				fprintf(stderr,
					"LBAF corresponding to block size %"PRIu64"(LBAF %u) not found\n",
					(uint64_t)cfg.bs, lbads);
				fprintf(stderr,
					"Please correct block size, or specify LBAF directly\n");
				err = -EINVAL;
				goto close_fd;
			}
		} else  if (cfg.lbaf == 0xff)
			cfg.lbaf = prev_lbaf;
	}

	/* ses & pi checks set to 7 for forward-compatibility */
	if (cfg.ses > 7) {
		fprintf(stderr, "invalid secure erase settings:%d\n", cfg.ses);
		err = -EINVAL;
		goto close_fd;
	}
	if (cfg.lbaf > 15) {
		fprintf(stderr, "invalid lbaf:%d\n", cfg.lbaf);
		err = -EINVAL;
		goto close_fd;
	}
	if (cfg.pi > 7) {
		fprintf(stderr, "invalid pi:%d\n", cfg.pi);
		err = -EINVAL;
		goto close_fd;
	}
	if (cfg.pil > 1) {
		fprintf(stderr, "invalid pil:%d\n", cfg.pil);
		err = -EINVAL;
		goto close_fd;
	}
	if (cfg.ms > 1) {
		fprintf(stderr, "invalid ms:%d\n", cfg.ms);
		err = -EINVAL;
		goto close_fd;
	}

	if (!cfg.force) {
		fprintf(stderr, "You are about to format %s, namespace %#x%s.\n",
			devicename, cfg.namespace_id,
			cfg.namespace_id == NVME_NSID_ALL ? "(ALL namespaces)" : "");
		nvme_show_relatives(devicename);
		fprintf(stderr, "WARNING: Format may irrevocably delete this device's data.\n"
			"You have 10 seconds to press Ctrl-C to cancel this operation.\n\n"
			"Use the force [--force|-f] option to suppress this warning.\n");
		sleep(10);
		fprintf(stderr, "Sending format operation ... \n");
	}

	err = nvme_format_nvm(fd, cfg.namespace_id, cfg.lbaf, cfg.ms, cfg.pi,
				cfg.pil, cfg.ses, cfg.timeout);
	if (err)
		nvme_show_status("format", err);
	else {
		printf("Success formatting namespace:%x\n", cfg.namespace_id);

		if (S_ISBLK(nvme_stat.st_mode) && ioctl(fd, BLKRRPART) < 0) {
			fprintf(stderr, "failed to re-read partition table\n");
			err = -errno;
			goto close_fd;
		}

		if (cfg.reset && S_ISCHR(nvme_stat.st_mode))
			nvme_ctrl_reset(fd);
	}

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int set_feature(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Modify the saveable or changeable "\
		"current operating parameters of the controller. Operating "\
		"parameters are grouped and identified by Feature "\
		"Identifiers. Feature settings can be applied to the entire "\
		"controller and all associated namespaces, or to only a few "\
		"namespace(s) associated with the controller. Default values "\
		"for each Feature are vendor-specific and may not be modified."\
		"Use get-feature to determine which Features are supported by "\
		"the controller and are saveable/changeable.";
	const char *namespace_id = "desired namespace";
	const char *feature_id = "feature identifier (required)";
	const char *data_len = "buffer length if data required";
	const char *data = "optional file for feature data (default stdin)";
	const char *value = "new value of feature (required)";
	const char *cdw12 = "feature cdw12, if used";
	const char *save = "specifies that the controller shall save the attribute";

	int err, fd, ffd = STDIN_FILENO;
	enum nvme_print_flags flags;
	void *buf = NULL;
	__u32 result;

	struct config {
		char *file;
		__u32 namespace_id;
		__u32 feature_id;
		__u32 value;
		__u32 cdw12;
		__u32 data_len;
		int   save;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format,   output_format),
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_UINT("feature-id",   'f', &cfg.feature_id,   feature_id),
		OPT_UINT("value",        'v', &cfg.value,        value),
		OPT_UINT("cdw12",        'c', &cfg.cdw12,        cdw12),
		OPT_UINT("data-len",     'l', &cfg.data_len,     data_len),
		OPT_FILE("data",         'd', &cfg.file,         data),
		OPT_FLAG("save",         's', &cfg.save,         save),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	if (!cfg.feature_id) {
		fprintf(stderr, "feature-id required param\n");
		err = -EINVAL;
		goto close_fd;
	}

	if (!cfg.data_len)
		nvme_get_feature_length(cfg.feature_id, cfg.value,
					&cfg.data_len);

	if (cfg.data_len) {
		if (posix_memalign(&buf, getpagesize(), cfg.data_len)) {
			fprintf(stderr, "can not allocate feature payload\n");
			err = -1;
			goto close_fd;
		}
		memset(buf, 0, cfg.data_len);
	}

	if (buf) {
		if (cfg.file) {
			ffd = open(cfg.file, O_RDONLY);
			if (ffd <= 0) {
				perror(cfg.file);
				err = -errno;
				goto free;
			}
		}

		err = read(ffd, (void *)buf, cfg.data_len);
		if (err < 0) {
			perror("read");
			err = -errno;
			goto close_ffd;
		}
	}

	err = nvme_set_features(fd, cfg.feature_id, cfg.namespace_id, cfg.value,
			       cfg.cdw12, cfg.save, 0, 0, cfg.data_len, buf, &result);
	if (err)
		nvme_feature_show_fields(cfg.feature_id, result, buf);
	else
		nvme_show_status("set-feature", err);

close_ffd:
	close(ffd);
free:
	if (buf)
		free(buf);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int sec_send(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct stat sb;
	const char *desc = "Transfer security protocol data to "\
		"a controller. Security Receives for the same protocol should be "\
		"performed after Security Sends. The security protocol field "\
		"associates Security Sends (security-send) and Security Receives "\
		"(security-recv).";
	const char *file = "transfer payload";
	const char *secp = "security protocol (cf. SPC-4)";
	const char *spsp = "security-protocol-specific (cf. SPC-4)";
	const char *tl = "transfer length (cf. SPC-4)";
	const char *namespace_id = "desired namespace";
	const char *nssf = "NVMe Security Specific Field";
	int err, fd, sec_fd = -1;
	void *sec_buf;
	unsigned int sec_size;
	__u32 result;

	struct config {
		__u32 namespace_id;
		char  *file;
		__u8  nssf;
		__u8  secp;
		__u16 spsp;
		__u32 tl;
	};

	struct config cfg = { 0 };

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_FILE("file",         'f', &cfg.file,         file),
		OPT_BYTE("nssf",         'N', &cfg.nssf,         nssf),
		OPT_BYTE("secp",         'p', &cfg.secp,         secp),
		OPT_SHRT("spsp",         's', &cfg.spsp,         spsp),
		OPT_UINT("tl",           't', &cfg.tl,           tl),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (!cfg.file) {
		fprintf(stderr,
			"Required parameter [--file | -f] not specified\n");
		goto close_fd;
	}

	sec_fd = open(cfg.file, O_RDONLY);
	if (sec_fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n",
				cfg.file, strerror(errno));
		err = -EINVAL;
		goto close_fd;
	}

	err = fstat(sec_fd, &sb);
	if (err < 0) {
		perror("fstat");
		goto close_sec_fd;
	}

	sec_size = sb.st_size;
	if (posix_memalign(&sec_buf, getpagesize(), sec_size)) {
		fprintf(stderr, "No memory for security size:%d\n", sec_size);
		err = -1;
		goto close_sec_fd;
	}

	err = read(sec_fd, sec_buf, sec_size);
	if (err < 0) {
		err = -errno;
		fprintf(stderr, "Failed to read data from security file"
				" %s with %s\n", cfg.file, strerror(errno));
		goto free;
	}

	err = nvme_security_receive(fd, cfg.namespace_id, cfg.nssf, cfg.spsp, 0, cfg.secp,
			cfg.tl, sec_size, sec_buf, &result);
	if (err)
		nvme_show_status("security-send", err);
	else
		printf("NVME Security Send Command Success:%d\n", result);

free:
	free(sec_buf);
close_sec_fd:
	close(sec_fd);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int dir_send(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Set directive parameters of the "\
			    "specified directive type.";
	const char *raw = "show directive in binary format";
	const char *namespace_id = "identifier of desired namespace";
	const char *data_len = "buffer len (if) data is returned";
	const char *dtype = "directive type";
	const char *dspec = "directive specification associated with directive type";
	const char *doper = "directive operation";
	const char *endir = "directive enable";
	const char *ttype = "target directive type to be enabled/disabled";
	const char *human_readable = "show directive in readable format";
	int err, fd;
	__u32 result;
	__u32 dw12 = 0;
	void *buf = NULL;
	int ffd = STDIN_FILENO;

	struct config {
		char *file;
		__u32 namespace_id;
		__u32 data_len;
		__u16 dspec;
		__u8  dtype;
		__u8  doper;
		__u16 endir;
		__u8  ttype;
		int  raw_binary;
		int  human_readable;
	};

	struct config cfg = {
		.endir        = 1,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id,   namespace_id),
		OPT_UINT("data-len",      'l', &cfg.data_len,       data_len),
		OPT_BYTE("dir-type",      'D', &cfg.dtype,          dtype),
		OPT_BYTE("target-dir",    'T', &cfg.ttype,          ttype),
		OPT_SHRT("dir-spec",      'S', &cfg.dspec,          dspec),
		OPT_BYTE("dir-oper",      'O', &cfg.doper,          doper),
		OPT_SHRT("endir",         'e', &cfg.endir,          endir),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (!cfg.namespace_id) {
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id < 0) {
			err = cfg.namespace_id;
			goto close_fd;
		}
	}

	if (cfg.dtype == NVME_DIRECTIVE_DTYPE_IDENTIFY &&
	    cfg.doper == NVME_DIRECTIVE_SEND_IDENTIFY_DOPER_ENDIR)
		dw12 = cfg.ttype << 8 | cfg.endir;

	if (cfg.data_len) {
		if (posix_memalign(&buf, getpagesize(), cfg.data_len)) {
			err = -1;
			goto close_fd;
		}
		memset(buf, 0, cfg.data_len);
	}

	if (buf) {
		if (cfg.file) {
			ffd = open(cfg.file, O_RDONLY);
			if (ffd <= 0) {
				fprintf(stderr, "Failed to open file %s: %s\n",
						cfg.file, strerror(errno));
				err = -EINVAL;
				goto free;
			}
		}

		err = read(ffd, (void *)buf, cfg.data_len);
		if (err < 0) {
			err = -errno;
			fprintf(stderr, "failed to read data buffer from input"
					" file %s\n", strerror(errno));
			goto close_ffd;
		}
	}

	err = nvme_directive_send(fd, cfg.namespace_id, cfg.dspec, cfg.doper, cfg.dtype,
			dw12, cfg.data_len, buf, &result);
	if (err)
	 	nvme_show_status("dir-send", err);
	else {
		printf("dir-send: type %#x, operation %#x, spec_val %#x, nsid %#x, result %#x \n",
				cfg.dtype, cfg.doper, cfg.dspec, cfg.namespace_id, result);
		if (buf) {
			if (!cfg.raw_binary)
				d(buf, cfg.data_len, 16, 1);
			else
				d_raw(buf, cfg.data_len);
		}
	}

close_ffd:
	close(ffd);
free:
	if (buf)
		free(buf);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int write_uncor(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err, fd;
	const char *desc = "The Write Uncorrectable command is used to set a "\
			"range of logical blocks to invalid.";
	const char *namespace_id = "desired namespace";
	const char *start_block = "64-bit LBA of first block to access";
	const char *block_count = "number of blocks (zeroes based) on device to access";

	struct config {
		__u64 start_block;
		__u32 namespace_id;
		__u16 block_count;
	};

	struct config cfg = { 0 };

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id, namespace_id),
		OPT_SUFFIX("start-block", 's', &cfg.start_block,  start_block),
		OPT_SHRT("block-count",   'c', &cfg.block_count,  block_count),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (!cfg.namespace_id) {
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id < 0) {
			err = cfg.namespace_id;
			goto close_fd;
		}
	}

	err = nvme_write_uncorrectable(fd, cfg.namespace_id, cfg.start_block,
					cfg.block_count);
	nvme_show_status("write uncorrectable", err);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int write_zeroes(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err, fd;
	__u16 control = 0;
	const char *desc = "The Write Zeroes command is used to set a "\
			"range of logical blocks to zero.";
	const char *namespace_id = "desired namespace";
	const char *start_block = "64-bit LBA of first block to access";
	const char *block_count = "number of blocks (zeroes based) on device to access";
	const char *limited_retry = "limit media access attempts";
	const char *force = "force device to commit data before command completes";
	const char *prinfo = "PI and check field";
	const char *ref_tag = "reference tag (for end to end PI)";
	const char *app_tag_mask = "app tag mask (for end to end PI)";
	const char *app_tag = "app tag (for end to end PI)";
	const char *deac = "Set DEAC bit, requesting controller to deallocate specified logical blocks";

	struct config {
		__u64 start_block;
		__u32 namespace_id;
		__u32 ref_tag;
		__u16 app_tag;
		__u16 app_tag_mask;
		__u16 block_count;
		__u8  prinfo;
		int   deac;
		int   limited_retry;
		int   force_unit_access;
	};

	struct config cfg = { 0 };

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",      'n', &cfg.namespace_id,      namespace_id),
		OPT_SUFFIX("start-block",     's', &cfg.start_block,       start_block),
		OPT_SHRT("block-count",       'c', &cfg.block_count,       block_count),
		OPT_FLAG("deac",              'd', &cfg.deac,              deac),
		OPT_FLAG("limited-retry",     'l', &cfg.limited_retry,     limited_retry),
		OPT_FLAG("force-unit-access", 'f', &cfg.force_unit_access, force),
		OPT_BYTE("prinfo",            'p', &cfg.prinfo,            prinfo),
		OPT_UINT("ref-tag",           'r', &cfg.ref_tag,           ref_tag),
		OPT_SHRT("app-tag-mask",      'm', &cfg.app_tag_mask,      app_tag_mask),
		OPT_SHRT("app-tag",           'a', &cfg.app_tag,           app_tag),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (cfg.prinfo > 0xf) {
		err = -EINVAL;
		goto close_fd;
	}

	control |= (cfg.prinfo << 10);
	if (cfg.limited_retry)
		control |= NVME_IO_LR;
	if (cfg.force_unit_access)
		control |= NVME_IO_FUA;
	if (cfg.deac)
		control |= NVME_IO_DEAC;
	if (!cfg.namespace_id) {
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id < 0) {
			err = cfg.namespace_id;
			goto close_fd;
		}
	}

	err = nvme_write_zeros(fd, cfg.namespace_id, cfg.start_block, cfg.block_count,
			control, cfg.ref_tag, cfg.app_tag, cfg.app_tag_mask);
	nvme_show_status("write-zeroes", err);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int dsm(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "The Dataset Management command is used by the host to "\
		"indicate attributes for ranges of logical blocks. This includes attributes "\
		"for discarding unused blocks, data read and write frequency, access size, and other "\
		"information that may be used to optimize performance and reliability.";
	const char *namespace_id = "identifier of desired namespace";
	const char *blocks = "Comma separated list of the number of blocks in each range";
	const char *starting_blocks = "Comma separated list of the starting block in each range";
	const char *context_attrs = "Comma separated list of the context attributes in each range";
	const char *ad = "Attribute Deallocate";
	const char *idw = "Attribute Integral Dataset for Write";
	const char *idr = "Attribute Integral Dataset for Read";
	const char *cdw11 = "All the command DWORD 11 attributes. Use instead of specifying individual attributes";

	int err, fd;
	uint16_t nr, nc, nb, ns;
	int ctx_attrs[256] = {0,};
	int nlbs[256] = {0,};
	unsigned long long slbas[256] = {0,};
	struct nvme_dsm_range dsm[256];

	struct config {
		char  *ctx_attrs;
		char  *blocks;
		char  *slbas;
		int   ad;
		int   idw;
		int   idr;
		__u32 cdw11;
		__u32 namespace_id;
	};

	struct config cfg = { 0 };

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_LIST("ctx-attrs",    'a', &cfg.ctx_attrs,    context_attrs),
		OPT_LIST("blocks", 	 'b', &cfg.blocks,       blocks),
		OPT_LIST("slbs", 	 's', &cfg.slbas,        starting_blocks),
		OPT_FLAG("ad", 	         'd', &cfg.ad,           ad),
		OPT_FLAG("idw", 	 'w', &cfg.idw,          idw),
		OPT_FLAG("idr", 	 'r', &cfg.idr,          idr),
		OPT_UINT("cdw11",        'c', &cfg.cdw11,        cdw11),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	nc = argconfig_parse_comma_sep_array(cfg.ctx_attrs, ctx_attrs, ARRAY_SIZE(ctx_attrs));
	nb = argconfig_parse_comma_sep_array(cfg.blocks, nlbs, ARRAY_SIZE(nlbs));
	ns = argconfig_parse_comma_sep_array_long(cfg.slbas, slbas, ARRAY_SIZE(slbas));
	nr = max(nc, max(nb, ns));
	if (!nr || nr > 256) {
		fprintf(stderr, "No range definition provided\n");
		err = -EINVAL;
		goto close_fd;
	}

	if (!cfg.namespace_id) {
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id < 0) {
			err = cfg.namespace_id;
			goto close_fd;
		}
	}
	if (!cfg.cdw11)
		cfg.cdw11 = (cfg.ad << 2) | (cfg.idw << 1) | (cfg.idr << 0);

	nvme_init_dsm_range(dsm, (__u32 *)ctx_attrs, (__u32 *)nlbs, (__u64 *)slbas, nr);
	err = nvme_dsm(fd, cfg.namespace_id, cfg.cdw11, nr, dsm);
	nvme_show_status("data-set management", err);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int flush(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Commit data and metadata associated with "\
		"given namespaces to nonvolatile media. Applies to all commands "\
		"finished before the flush was submitted. Additional data may also be "\
		"flushed by the controller, from any namespace, depending on controller and "\
		"associated namespace status.";
	const char *namespace_id = "identifier of desired namespace";
	int err, fd;

	struct config {
		__u32 namespace_id;
	};

	struct config cfg = {
		.namespace_id = NVME_NSID_ALL,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (S_ISBLK(nvme_stat.st_mode)) {
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id < 0) {
			err = cfg.namespace_id;
			goto close_fd;
		}
	}

	err = nvme_flush(fd, cfg.namespace_id);
	nvme_show_status("flush", err);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int resv_acquire(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Obtain a reservation on a given "\
		"namespace. Only one reservation is allowed at a time on a "\
		"given namespace, though multiple controllers may register "\
		"with that namespace. Namespace reservation will abort with "\
		"status Reservation Conflict if the given namespace is "\
		"already reserved.";
	const char *namespace_id = "identifier of desired namespace";
	const char *crkey = "current reservation key";
	const char *prkey = "pre-empt reservation key";
	const char *rtype = "reservation type";
	const char *racqa = "reservation acquiry action";
	const char *iekey = "ignore existing res. key";
	int err, fd;

	struct config {
		__u32 namespace_id;
		__u64 crkey;
		__u64 prkey;
		__u8  rtype;
		__u8  racqa;
		int   iekey;
	};

	struct config cfg = { 0 };

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_LONG("crkey",        'c', &cfg.crkey,        crkey),
		OPT_LONG("prkey",        'p', &cfg.prkey,        prkey),
		OPT_BYTE("rtype",        't', &cfg.rtype,        rtype),
		OPT_BYTE("racqa",        'a', &cfg.racqa,        racqa),
		OPT_FLAG("iekey",        'i', &cfg.iekey,        iekey),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (!cfg.namespace_id) {
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id < 0) {
			err = cfg.namespace_id;
			goto close_fd;
		}
	}
	if (cfg.racqa > 7) {
		fprintf(stderr, "invalid racqa:%d\n", cfg.racqa);
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_resv_acquire(fd, cfg.namespace_id, cfg.rtype, cfg.racqa,
				!!cfg.iekey, cfg.crkey, cfg.prkey);
	nvme_show_status("reservation-acquire", err);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int resv_register(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Register, de-register, or "\
		"replace a controller's reservation on a given namespace. "\
		"Only one reservation at a time is allowed on any namespace.";
	const char *namespace_id = "identifier of desired namespace";
	const char *crkey = "current reservation key";
	const char *iekey = "ignore existing res. key";
	const char *nrkey = "new reservation key";
	const char *rrega = "reservation registration action";
	const char *cptpl = "change persistence through power loss setting";
	int err, fd;

	struct config {
		__u32 namespace_id;
		__u64 crkey;
		__u64 nrkey;
		__u8  rrega;
		__u8  cptpl;
		int   iekey;
	};

	struct config cfg = { 0 };

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_LONG("crkey",        'c', &cfg.crkey,        crkey),
		OPT_LONG("nrkey",        'k', &cfg.nrkey,        nrkey),
		OPT_BYTE("rrega",        'r', &cfg.rrega,        rrega),
		OPT_BYTE("cptpl",        'p', &cfg.cptpl,        cptpl),
		OPT_FLAG("iekey",        'i', &cfg.iekey,        iekey),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (!cfg.namespace_id) {
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id < 0) {
			err = cfg.namespace_id;
			goto close_fd;
		}
	}
	if (cfg.cptpl > 3) {
		fprintf(stderr, "invalid cptpl:%d\n", cfg.cptpl);
		err = -EINVAL;
		goto close_fd;
	}

	if (cfg.rrega > 7) {
		fprintf(stderr, "invalid rrega:%d\n", cfg.rrega);
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_resv_register(fd, cfg.namespace_id, cfg.rrega, cfg.cptpl,
				!!cfg.iekey, cfg.crkey, cfg.nrkey);
	nvme_show_status("reservation-register", err);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int resv_release(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Releases reservation held on a namespace by the "\
		"given controller. If rtype != current reservation"\
		"type, release will fails. If the given controller holds no "\
		"reservation on the namespace or is not the namespace's current "\
		"reservation holder, the release command completes with no "\
		"effect. If the reservation type is not Write Exclusive or "\
		"Exclusive Access, all registrants on the namespace except "\
		"the issuing controller are notified.";
	const char *namespace_id = "desired namespace";
	const char *crkey = "current reservation key";
	const char *iekey = "ignore existing res. key";
	const char *rtype = "reservation type";
	const char *rrela = "reservation release action";
	int err, fd;

	struct config {
		__u32 namespace_id;
		__u64 crkey;
		__u8  rtype;
		__u8  rrela;
		__u8  iekey;
	};

	struct config cfg = { 0 };

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_LONG("crkey",        'c', &cfg.crkey,        crkey),
		OPT_BYTE("rtype",        't', &cfg.rtype,        rtype),
		OPT_BYTE("rrela",        'a', &cfg.rrela,        rrela),
		OPT_FLAG("iekey",        'i', &cfg.iekey,        iekey),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (!cfg.namespace_id) {
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id < 0) {
			err = cfg.namespace_id;
			goto close_fd;
		}
	}
	if (cfg.rrela > 7) {
		fprintf(stderr, "invalid rrela:%d\n", cfg.rrela);
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_resv_release(fd, cfg.namespace_id, cfg.rtype, cfg.rrela,
				!!cfg.iekey, cfg.crkey);
	nvme_show_status("reservation-release", err);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int resv_report(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Returns Reservation Status data "\
		"structure describing any existing reservations on and the "\
		"status of a given namespace. Namespace Reservation Status "\
		"depends on the number of controllers registered for that "\
		"namespace.";
	const char *namespace_id = "identifier of desired namespace";
	const char *s = "number of bytes to transfer";
	const char *eds = "request extended data structure";
	const char *raw = "dump output in binary format";

	struct nvme_reservation_status *status;
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		__u32 namespace_id;
		__u32 len;
		__u32 eds;
		int   raw_binary;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_UINT("data-len",     'd', &cfg.len,           s),
		OPT_UINT("eds",          'e', &cfg.eds,           eds),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = 0;

	if (!cfg.namespace_id) {
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id < 0) {
			err = cfg.namespace_id;
			goto close_fd;
		}
	}

	if (cfg.len > 0x1000)
		cfg.len = 0x1000;
	if (cfg.len < 32)
		cfg.len = 32;

	if (posix_memalign((void **)&status, getpagesize(), cfg.len)) {
		fprintf(stderr, "No memory for resv report:%d\n", cfg.len);
		err = -1;
		goto close_fd;
	}
	memset(status, 0, cfg.len);

	err = nvme_resv_report(fd, cfg.namespace_id, cfg.len, cfg.eds, status);
	if (err)
		nvme_show_resv_report(status, cfg.len, cfg.eds, flags);
	else
		nvme_show_status("reservation-report", err);

	free(status);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static unsigned long long elapsed_utime(struct timeval start_time,
					struct timeval end_time)
{
	unsigned long long err = (end_time.tv_sec - start_time.tv_sec) * 1000000 +
		(end_time.tv_usec - start_time.tv_usec);
	return err;
}

static int submit_io(int opcode, char *command, const char *desc,
		     int argc, char **argv)
{
	int mode = S_IRUSR | S_IWUSR |S_IRGRP | S_IWGRP| S_IROTH;
	int flags = opcode & 1 ? O_RDONLY : O_WRONLY | O_CREAT;
	int dfd, mfd, fd, err, phys_sector_size;
	struct timeval start_time, end_time;
	void *buffer, *mbuffer = NULL;
	unsigned buffer_size = 0;
	__u16 control = 0;
	__u32 dsmgmt = 0;
	bool huge;

	const char *start_block = "64-bit addr of first block to access";
	const char *block_count = "number of blocks (zeroes based) on device to access";
	const char *data_size = "size of data in bytes";
	const char *metadata_size = "size of metadata in bytes";
	const char *ref_tag = "reference tag (for end to end PI)";
	const char *data = "data file";
	const char *metadata = "metadata file";
	const char *prinfo = "PI and check field";
	const char *app_tag_mask = "app tag mask (for end to end PI)";
	const char *app_tag = "app tag (for end to end PI)";
	const char *limited_retry = "limit num. media access attempts";
	const char *latency = "output latency statistics";
	const char *force = "force device to commit data before command completes";
	const char *show = "show command before sending";
	const char *dry = "show command instead of sending";
	const char *dtype = "directive type (for write-only)";
	const char *dspec = "directive specific (for write-only)";
	const char *dsm = "dataset management attributes (lower 16 bits)";

	struct config {
		__u64 start_block;
		__u16 block_count;
		__u64 data_size;
		__u64 metadata_size;
		__u32 ref_tag;
		char  *data;
		char  *metadata;
		__u8  prinfo;
		__u8 dtype;
		__u16 dspec;
		__u16 dsmgmt;
		__u16 app_tag_mask;
		__u16 app_tag;
		int   limited_retry;
		int   force_unit_access;
		int   show;
		int   dry_run;
		int   latency;
	};

	struct config cfg = { 0 };

	OPT_ARGS(opts) = {
		OPT_SUFFIX("start-block",     's', &cfg.start_block,       start_block),
		OPT_SHRT("block-count",       'c', &cfg.block_count,       block_count),
		OPT_SUFFIX("data-size",       'z', &cfg.data_size,         data_size),
		OPT_SUFFIX("metadata-size",   'y', &cfg.metadata_size,     metadata_size),
		OPT_UINT("ref-tag",           'r', &cfg.ref_tag,           ref_tag),
		OPT_FILE("data",              'd', &cfg.data,              data),
		OPT_FILE("metadata",          'M', &cfg.metadata,          metadata),
		OPT_BYTE("prinfo",            'p', &cfg.prinfo,            prinfo),
		OPT_SHRT("app-tag-mask",      'm', &cfg.app_tag_mask,      app_tag_mask),
		OPT_SHRT("app-tag",           'a', &cfg.app_tag,           app_tag),
		OPT_FLAG("limited-retry",     'l', &cfg.limited_retry,     limited_retry),
		OPT_FLAG("force-unit-access", 'f', &cfg.force_unit_access, force),
		OPT_BYTE("dir-type",          'T', &cfg.dtype,             dtype),
		OPT_SHRT("dir-spec",          'S', &cfg.dspec,             dspec),
		OPT_SHRT("dsm",               'D', &cfg.dsmgmt,            dsm),
		OPT_FLAG("show-command",      'v', &cfg.show,              show),
		OPT_FLAG("dry-run",           'w', &cfg.dry_run,           dry),
		OPT_FLAG("latency",           't', &cfg.latency,           latency),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	dfd = mfd = opcode & 1 ? STDIN_FILENO : STDOUT_FILENO;
	if (cfg.prinfo > 0xf) {
		err = -EINVAL;
		goto close_fd;
	}

	dsmgmt = cfg.dsmgmt;
	control |= (cfg.prinfo << 10);
	if (cfg.limited_retry)
		control |= NVME_IO_LR;
	if (cfg.force_unit_access)
		control |= NVME_IO_FUA;
	if (cfg.dtype) {
		if (cfg.dtype > 0xf) {
			fprintf(stderr, "Invalid directive type, %x\n",
				cfg.dtype);
			err = -EINVAL;
			goto close_fd;
		}
		control |= cfg.dtype << 4;
		dsmgmt |= ((__u32)cfg.dspec) << 16;
	}

	if (cfg.data && strlen(cfg.data)) {
		dfd = open(cfg.data, flags, mode);
		if (dfd < 0) {
			perror(cfg.data);
			err = -EINVAL;
			goto close_fd;
		}
		mfd = dfd;
	}
	if (cfg.metadata && strlen(cfg.metadata)) {
		mfd = open(cfg.metadata, flags, mode);
		if (mfd < 0) {
			perror(cfg.metadata);
			err = -EINVAL;
			goto close_dfd;
		}
	}

	if (!cfg.data_size)	{
		fprintf(stderr, "data size not provided\n");
		err = -EINVAL;
		goto close_mfd;
	}

	if (ioctl(fd, BLKPBSZGET, &phys_sector_size) < 0)
		goto close_mfd;

	buffer_size = (cfg.block_count + 1) * phys_sector_size;
	if (cfg.data_size < buffer_size)
		fprintf(stderr, "Rounding data size to fit block count (%u bytes)\n",
				buffer_size);
	else
		buffer_size = cfg.data_size;

	buffer = nvme_alloc(buffer_size, &huge);
	if (!buffer) {
		fprintf(stderr, "can not allocate io payload\n");
		err = -1;
		goto close_mfd;
	}

	if (cfg.metadata_size) {
		mbuffer = malloc(cfg.metadata_size);
		if (!mbuffer) {
			fprintf(stderr, "can not allocate io metadata "
					"payload: %s\n", strerror(errno));
			err = -1;
			goto free_buffer;
		}
		memset(mbuffer, 0, cfg.metadata_size);
	}

	if ((opcode & 1)) {
		err = read(dfd, (void *)buffer, cfg.data_size);
		if (err < 0) {
			err = -errno;
			fprintf(stderr, "failed to read data buffer from input"
					" file %s\n", strerror(errno));
			goto free_mbuffer;
		}
	}

	if ((opcode & 1) && cfg.metadata_size) {
		err = read(mfd, (void *)mbuffer, cfg.metadata_size);
		if (err < 0) {
			err = -errno;
			fprintf(stderr, "failed to read meta-data buffer from"
					" input file %s\n", strerror(errno));
			goto free_mbuffer;
		}
	}

	if (cfg.show) {
		printf("opcode       : %02x\n", opcode);
		printf("flags        : %02x\n", 0);
		printf("control      : %04x\n", control);
		printf("nblocks      : %04x\n", cfg.block_count);
		printf("rsvd         : %04x\n", 0);
		printf("metadata     : %"PRIx64"\n", (uint64_t)(uintptr_t)mbuffer);
		printf("addr         : %"PRIx64"\n", (uint64_t)(uintptr_t)buffer);
		printf("slba         : %"PRIx64"\n", (uint64_t)cfg.start_block);
		printf("dsmgmt       : %08x\n", dsmgmt);
		printf("reftag       : %08x\n", cfg.ref_tag);
		printf("apptag       : %04x\n", cfg.app_tag);
		printf("appmask      : %04x\n", cfg.app_tag_mask);
	}

	if (cfg.dry_run)
		goto free_mbuffer;

	gettimeofday(&start_time, NULL);
	if (opcode & 1)
		err = nvme_write(fd, 0, cfg.start_block, cfg.block_count,
			control, dsmgmt, 0, cfg.ref_tag, cfg.app_tag,
			cfg.app_tag_mask, buffer_size, buffer,
			cfg.metadata_size, mbuffer);
	else
		err = nvme_read(fd, 0, cfg.start_block, cfg.block_count,
			control, dsmgmt, cfg.ref_tag, cfg.app_tag,
			cfg.app_tag_mask, buffer_size, buffer,
			cfg.metadata_size, mbuffer);
	gettimeofday(&end_time, NULL);

	if (cfg.latency)
		printf(" latency: %s: %llu us\n", command,
			elapsed_utime(start_time, end_time));
	if (err)
		nvme_show_status("submit-io", err);
	else {
		if (!(opcode & 1) && write(dfd, (void *)buffer, cfg.data_size) < 0) {
			fprintf(stderr, "write: %s: failed to write buffer to output file\n",
					strerror(errno));
			err = -EINVAL;
		} else if (!(opcode & 1) && cfg.metadata_size &&
				write(mfd, (void *)mbuffer, cfg.metadata_size) < 0) {
			fprintf(stderr, "write: %s: failed to write meta-data buffer to output file\n",
					strerror(errno));
			err = -EINVAL;
		} else
			fprintf(stderr, "%s: Success\n", command);
	}

free_mbuffer:
	if (cfg.metadata_size)
		free(mbuffer);
free_buffer:
	nvme_free(buffer, huge);
close_mfd:
	if (strlen(cfg.metadata))
		close(mfd);
close_dfd:
	close(dfd);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int compare(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Compare specified logical blocks on "\
		"device with specified data buffer; return failure if buffer "\
		"and block(s) are dissimilar";
	return submit_io(nvme_cmd_compare, "compare", desc, argc, argv);
}

static int read_cmd(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Copy specified logical blocks on the given "\
		"device to specified data buffer (default buffer is stdout).";
	return submit_io(nvme_cmd_read, "read", desc, argc, argv);
}

static int write_cmd(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Copy from provided data buffer (default "\
		"buffer is stdin) to specified logical blocks on the given "\
		"device.";
	return submit_io(nvme_cmd_write, "write", desc, argc, argv);
}

static int verify_cmd(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err, fd;
	__u16 control = 0;
	const char *desc = "Verify specified logical blocks on the given device.";
	const char *namespace_id = "desired namespace";
	const char *start_block = "64-bit LBA of first block to access";
	const char *block_count = "number of blocks (zeroes based) on device to access";
	const char *limited_retry = "limit media access attempts";
	const char *force = "force device to commit cached data before performing the verify operation";
	const char *prinfo = "PI and check field";
	const char *ref_tag = "reference tag (for end to end PI)";
	const char *app_tag_mask = "app tag mask (for end to end PI)";
	const char *app_tag = "app tag (for end to end PI)";

	struct config {
		__u64 start_block;
		__u32 namespace_id;
		__u32 ref_tag;
		__u16 app_tag;
		__u16 app_tag_mask;
		__u16 block_count;
		__u8  prinfo;
		int   limited_retry;
		int   force_unit_access;
	};

	struct config cfg = { 0 };

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",      'n', &cfg.namespace_id,      namespace_id),
		OPT_SUFFIX("start-block",     's', &cfg.start_block,       start_block),
		OPT_SHRT("block-count",       'c', &cfg.block_count,       block_count),
		OPT_FLAG("limited-retry",     'l', &cfg.limited_retry,     limited_retry),
		OPT_FLAG("force-unit-access", 'f', &cfg.force_unit_access, force),
		OPT_BYTE("prinfo",            'p', &cfg.prinfo,            prinfo),
		OPT_UINT("ref-tag",           'r', &cfg.ref_tag,           ref_tag),
		OPT_SHRT("app-tag",           'a', &cfg.app_tag,           app_tag),
		OPT_SHRT("app-tag-mask",      'm', &cfg.app_tag_mask,      app_tag_mask),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto err;

	if (cfg.prinfo > 0xf) {
		err = EINVAL;
		goto close_fd;
	}

	control |= (cfg.prinfo << 10);
	if (cfg.limited_retry)
		control |= NVME_IO_LR;
	if (cfg.force_unit_access)
		control |= NVME_IO_FUA;

	if (!cfg.namespace_id) {
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id < 0) {
			err = cfg.namespace_id;
			goto close_fd;
		}
	}

	err = nvme_verify(fd, cfg.namespace_id, cfg.start_block, cfg.block_count,
				control, cfg.ref_tag, cfg.app_tag, cfg.app_tag_mask);
	nvme_show_status("verify", err);

close_fd:
	close(fd);
err:
	return err;
}

static int sec_recv(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Obtain results of one or more "\
		"previously submitted security-sends. Results, and association "\
		"between Security Send and Receive, depend on the security "\
		"protocol field as they are defined by the security protocol "\
		"used. A Security Receive must follow a Security Send made with "\
		"the same security protocol.";
	const char *size = "size of buffer (prints to stdout on success)";
	const char *secp = "security protocol (cf. SPC-4)";
	const char *spsp = "security-protocol-specific (cf. SPC-4)";
	const char *al = "allocation length (cf. SPC-4)";
	const char *raw = "dump output in binary format";
	const char *namespace_id = "desired namespace";
	const char *nssf = "NVMe Security Specific Field";
	int err, fd;
	void *sec_buf = NULL;
	__u32 result;

	struct config {
		__u32 namespace_id;
		__u32 size;
		__u8  secp;
		__u8  nssf;
		__u16 spsp;
		__u32 al;
		int   raw_binary;
	};

	struct config cfg = { 0 };

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_UINT("size",         'x', &cfg.size,         size),
		OPT_BYTE("nssf",         'N', &cfg.nssf,         nssf),
		OPT_BYTE("secp",         'p', &cfg.secp,         secp),
		OPT_SHRT("spsp",         's', &cfg.spsp,         spsp),
		OPT_UINT("al",           't', &cfg.al,           al),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (cfg.size) {
		if (posix_memalign(&sec_buf, getpagesize(), cfg.size)) {
			fprintf(stderr, "No memory for security size:%d\n",
								cfg.size);
			err = -1;
			goto close_fd;
		}
	}

	err = nvme_security_receive(fd, cfg.namespace_id, cfg.nssf, cfg.spsp, 0,
			cfg.secp, cfg.al, cfg.size, sec_buf, &result);
	if (err)
		nvme_show_status("security-receive", err);
	else {
		if (!cfg.raw_binary) {
			printf("NVME Security Receive Command Success:%d\n",
							result);
			d(sec_buf, cfg.size, 16, 1);
		} else if (cfg.size)
			d_raw((unsigned char *)sec_buf, cfg.size);
	}

	free(sec_buf);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_lba_status(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Information about potentially unrecoverable LBAs.";
	const char *slba = "Starting LBA(SLBA) in 64-bit address of the first"\
			    " logical block addressed by this command";
	const char *mndw = "Maximum Number of Dwords(MNDW) specifies maximum"\
			    " number of dwords to return";
	const char *atype = "Action Type(ATYPE) specifies the mechanism the"\
			     " the controller uses in determining the LBA"\
			     " Status Descriptors to return.";
	const char *rl = "Range Length(RL) specifies the length of the range"\
			  " of contiguous LBAs beginning at SLBA";

	enum nvme_print_flags flags;
	struct nvme_lba_status *lbas;
	unsigned long len;
	int err, fd;

	struct config {
		__u64 slba;
		__u32 mndw;
		__u8 atype;
		__u16 rl;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_SUFFIX("start-lba",  's', &cfg.slba,          slba),
		OPT_UINT("max-dw",       'm', &cfg.mndw,          mndw),
		OPT_BYTE("action",       'a', &cfg.atype,         atype),
		OPT_SHRT("range-len",    'l', &cfg.rl,            rl),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto err;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	if (!cfg.atype) {
		fprintf(stderr, "action type (--action) has to be given\n");
		err = -EINVAL;
		goto close_fd;
	}

	len = (cfg.mndw + 1) * 4;
	lbas = malloc(len);
	if (!lbas) {
		err = -1;
		goto close_fd;
	}
	memset(lbas, 0, len);

	err = nvme_get_lba_status(fd, 0xffffffff, cfg.slba, cfg.mndw, cfg.atype, cfg.rl, lbas);
	if (!err)
		nvme_show_lba_status(lbas, len, flags);
	else
		nvme_show_status("get-lba-status", err);

	free(lbas);
close_fd:
	close(fd);
err:
	return nvme_status_to_errno(err, false);
}

static int dir_receive(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Read directive parameters of the "\
			    "specified directive type.";
	const char *raw = "show directive in binary format";
	const char *namespace_id = "identifier of desired namespace";
	const char *data_len = "buffer len (if) data is returned";
	const char *dtype = "directive type";
	const char *dspec = "directive specification associated with directive type";
	const char *doper = "directive operation";
	const char *nsr = "namespace streams requested";
	const char *human_readable = "show directive in readable format";

	enum nvme_print_flags flags = 0;
	int err, fd;
	__u32 result;
	__u32 dw12 = 0;
	void *buf = NULL;

	struct config {
		__u32 namespace_id;
		__u32 data_len;
		__u16 dspec;
		__u8  dtype;
		__u8  doper;
		__u16 nsr;
		int  raw_binary;
		int  human_readable;
	};

	struct config cfg = {
		.namespace_id = 1,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id,   namespace_id),
		OPT_UINT("data-len",      'l', &cfg.data_len,       data_len),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw),
		OPT_BYTE("dir-type",      'D', &cfg.dtype,          dtype),
		OPT_SHRT("dir-spec",      'S', &cfg.dspec,          dspec),
		OPT_BYTE("dir-oper",      'O', &cfg.doper,          doper),
		OPT_SHRT("req-resource",  'r', &cfg.nsr,            nsr),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (cfg.raw_binary)
		flags = 0;
	if (cfg.human_readable)
		flags |= VERBOSE;

	if (cfg.dtype == NVME_DIRECTIVE_DTYPE_STREAMS &&
	    cfg.doper == NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE)
		dw12 = cfg.nsr;

	if (!cfg.data_len)
		nvme_get_directive_receive_length(cfg.dtype, cfg.doper,
						  &cfg.data_len);
	if (cfg.data_len) {
		if (posix_memalign(&buf, getpagesize(), cfg.data_len)) {
			err = -1;
			goto close_fd;
		}
		memset(buf, 0, cfg.data_len);
	}

	err = nvme_directive_recv(fd, cfg.namespace_id, cfg.dspec, cfg.doper, cfg.dtype,
			dw12, cfg.data_len, buf, &result);
	if (!err)
		nvme_directive_show(cfg.dtype, cfg.doper, cfg.dspec,
			cfg.namespace_id, result, buf, cfg.data_len, flags);
	else
		nvme_show_status("dir-receive", err);

	if (cfg.data_len)
		free(buf);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int passthru(int argc, char **argv, bool admin, const char *desc, struct command *cmd)
{
	void *data = NULL, *metadata = NULL;
	int err = 0, wfd = STDIN_FILENO, fd;
	__u32 result;
	bool huge;

	struct config {
		__u8  opcode;
		__u8  flags;
		__u16 rsvd;
		__u32 namespace_id;
		__u32 data_len;
		__u32 metadata_len;
		__u32 timeout;
		__u32 cdw2;
		__u32 cdw3;
		__u32 cdw10;
		__u32 cdw11;
		__u32 cdw12;
		__u32 cdw13;
		__u32 cdw14;
		__u32 cdw15;
		char  *input_file;
		int   raw_binary;
		int   show_command;
		int   dry_run;
		int   read;
		int   write;
		__u8  prefill;
	};

	struct config cfg = { 0 };

	const char *opcode = "opcode (required)";
	const char *flags = "command flags";
	const char *rsvd = "value for reserved field";
	const char *namespace_id = "desired namespace";
	const char *data_len = "data I/O length (bytes)";
	const char *metadata_len = "metadata seg. length (bytes)";
	const char *timeout = "timeout value, in milliseconds";
	const char *cdw2 = "command dword 2 value";
	const char *cdw3 = "command dword 3 value";
	const char *cdw10 = "command dword 10 value";
	const char *cdw11 = "command dword 11 value";
	const char *cdw12 = "command dword 12 value";
	const char *cdw13 = "command dword 13 value";
	const char *cdw14 = "command dword 14 value";
	const char *cdw15 = "command dword 15 value";
	const char *input = "write/send file (default stdin)";
	const char *raw_binary = "dump output in binary format";
	const char *show = "print command before sending";
	const char *dry = "show command instead of sending";
	const char *re = "set dataflow direction to receive";
	const char *wr = "set dataflow direction to send";
	const char *prefill = "prefill buffers with known byte-value, default 0";

	OPT_ARGS(opts) = {
		OPT_BYTE("opcode",       'o', &cfg.opcode,       opcode),
		OPT_BYTE("flags",        'f', &cfg.flags,        flags),
		OPT_BYTE("prefill",      'p', &cfg.prefill,      prefill),
		OPT_SHRT("rsvd",         'R', &cfg.rsvd,         rsvd),
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_UINT("data-len",     'l', &cfg.data_len,     data_len),
		OPT_UINT("metadata-len", 'm', &cfg.metadata_len, metadata_len),
		OPT_UINT("timeout",      't', &cfg.timeout,      timeout),
		OPT_UINT("cdw2",         '2', &cfg.cdw2,         cdw2),
		OPT_UINT("cdw3",         '3', &cfg.cdw3,         cdw3),
		OPT_UINT("cdw10",        '4', &cfg.cdw10,        cdw10),
		OPT_UINT("cdw11",        '5', &cfg.cdw11,        cdw11),
		OPT_UINT("cdw12",        '6', &cfg.cdw12,        cdw12),
		OPT_UINT("cdw13",        '7', &cfg.cdw13,        cdw13),
		OPT_UINT("cdw14",        '8', &cfg.cdw14,        cdw14),
		OPT_UINT("cdw15",        '9', &cfg.cdw15,        cdw15),
		OPT_FILE("input-file",   'i', &cfg.input_file,   input),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw_binary),
		OPT_FLAG("show-command", 's', &cfg.show_command, show),
		OPT_FLAG("dry-run",      'd', &cfg.dry_run,      dry),
		OPT_FLAG("read",         'r', &cfg.read,         re),
		OPT_FLAG("write",        'w', &cfg.write,        wr),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (cfg.input_file) {
		wfd = open(cfg.input_file, O_RDONLY,
			   S_IRUSR | S_IRGRP | S_IROTH);
		if (wfd < 0) {
			perror(cfg.input_file);
			err = -EINVAL;
			goto close_fd;
		}
	}

	if (cfg.metadata_len) {
		metadata = malloc(cfg.metadata_len);
		if (!metadata) {
			fprintf(stderr, "can not allocate metadata "
					"payload: %s\n", strerror(errno));
			err = -1;
			goto close_wfd;
		}
		memset(metadata, cfg.prefill, cfg.metadata_len);
	}

	if (cfg.data_len) {
		data = nvme_alloc(cfg.data_len, &huge);
		if (!data) {
			fprintf(stderr, "can not allocate data payload\n");
			err = -1;
			goto free_metadata;
		}

		if (cfg.write && !(cfg.opcode & 0x01))
			fprintf(stderr,
				"warning: write flag set but write direction bit is not set in the opcode\n");
		if (cfg.read && !(cfg.opcode & 0x02))
			fprintf(stderr,
				"warning: read flag set but read direction bit is not set in the opcode\n");

		memset(data, cfg.prefill, cfg.data_len);
		if (!cfg.read && !cfg.write) {
			fprintf(stderr, "data direction not given\n");
			err = -EINVAL;
			goto free_data;
		} else if (cfg.write) {
			if (read(wfd, data, cfg.data_len) < 0) {
				err = -errno;
				fprintf(stderr, "failed to read write buffer "
						"%s\n", strerror(errno));
				goto free_data;
			}
		}
	}

	if (cfg.show_command) {
		printf("opcode       : %02x\n", cfg.opcode);
		printf("flags        : %02x\n", cfg.flags);
		printf("rsvd1        : %04x\n", cfg.rsvd);
		printf("nsid         : %08x\n", cfg.namespace_id);
		printf("cdw2         : %08x\n", cfg.cdw2);
		printf("cdw3         : %08x\n", cfg.cdw3);
		printf("data_len     : %08x\n", cfg.data_len);
		printf("metadata_len : %08x\n", cfg.metadata_len);
		printf("addr         : %"PRIx64"\n", (uint64_t)(uintptr_t)data);
		printf("metadata     : %"PRIx64"\n", (uint64_t)(uintptr_t)metadata);
		printf("cdw10        : %08x\n", cfg.cdw10);
		printf("cdw11        : %08x\n", cfg.cdw11);
		printf("cdw12        : %08x\n", cfg.cdw12);
		printf("cdw13        : %08x\n", cfg.cdw13);
		printf("cdw14        : %08x\n", cfg.cdw14);
		printf("cdw15        : %08x\n", cfg.cdw15);
		printf("timeout_ms   : %08x\n", cfg.timeout);
	}

	if (cfg.dry_run)
		goto free_data;

	if (admin)
		err = nvme_admin_passthru(fd, cfg.opcode, cfg.flags, cfg.rsvd,
				cfg.namespace_id, cfg.cdw2, cfg.cdw3, cfg.cdw10,
				cfg.cdw11, cfg.cdw12, cfg.cdw13, cfg.cdw14,
				cfg.cdw15, cfg.data_len, data, cfg.metadata_len,
				metadata, cfg.timeout, &result);
	else
		err = nvme_io_passthru(fd, cfg.opcode, cfg.flags, cfg.rsvd,
				cfg.namespace_id, cfg.cdw2, cfg.cdw3, cfg.cdw10,
				cfg.cdw11, cfg.cdw12, cfg.cdw13, cfg.cdw14,
				cfg.cdw15, cfg.data_len, data, cfg.metadata_len,
				metadata, cfg.timeout, &result);

	if (err)
		nvme_show_status("passthru", err);
	else  {
		if (!cfg.raw_binary) {
			fprintf(stderr, "NVMe command result:%08x\n", result);
			if (data && cfg.read && !err)
				d((unsigned char *)data, cfg.data_len, 16, 1);
		} else if (data && cfg.read)
			d_raw((unsigned char *)data, cfg.data_len);
	}
free_data:
	if (cfg.data_len)
		nvme_free(data, huge);
free_metadata:
	if (cfg.metadata_len)
		free(metadata);
close_wfd:
	if (strlen(cfg.input_file))
		close(wfd);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int io_passthru(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send a user-defined IO command to the specified "\
		"device via IOCTL passthrough, return results.";
	return passthru(argc, argv, false, desc, cmd);
}

static int admin_passthru(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send a user-defined Admin command to the specified "\
		"device via IOCTL passthrough, return results.";
	return passthru(argc, argv, true, desc, cmd);
}

static int gen_hostnqn_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
#ifdef LIBUUIDX
	uuid_t uuid;
	char uuid_str[37]; /* e.g. 1b4e28ba-2fa1-11d2-883f-0016d3cca427 + \0 */

	uuid_generate_random(uuid);
	uuid_unparse_lower(uuid, uuid_str);
	printf("nqn.2014-08.org.nvmexpress:uuid:%s\n", uuid_str);
	return 0;
#else
	fprintf(stderr, "\"%s\" not supported. Install lib uuid and rebuild.\n",
		command->name);
	return ENOTSUP;
#endif
}

static int show_hostnqn_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	char *hostnqn;

	hostnqn = nvmf_hostnqn_from_file();
	if (!hostnqn)
		hostnqn =  nvmf_hostnqn_generate();

	if (!hostnqn) {
		fprintf(stderr, "hostnqn is not available -- use nvme gen-hostnqn\n");
		return ENOENT;
	}

	fprintf(stdout, hostnqn);
	free(hostnqn);

	return 0;
}

static bool nvme_ctrl_match_cfg(nvme_ctrl_t c, struct nvme_fabrics_config *cfg)
{
	const int size = 0x100;
	char addr[size];
	const char *a, *n, *t;
	int len = 0;

	if (!c)
		return false;

	a = nvme_ctrl_get_address(c);
	n = nvme_ctrl_get_subsysnqn(c);
	t = nvme_ctrl_get_transport(c);

	memset(addr, 0, size);
	if (cfg->traddr)
                len += snprintf(addr, size, "traddr=%s", cfg->traddr);
	if (cfg->trsvcid)
                len += snprintf(addr + len, size - len, "%strsvcid=%s",
                                len ? "," : "", cfg->trsvcid);
	if (cfg->host_traddr)
                len += snprintf(addr + len, size - len, "%shost_traddr=%s",
                                len ? "," : "", cfg->host_traddr);

	if (t && cfg->transport)
		if (strcmp(t, cfg->transport))
			return false;

	if (n && cfg->nqn)
		if (strcmp(n, cfg->nqn))
			return false;

	if (a && strlen(addr))
		if (strcmp(a, addr))
			return false;

	return true;
}

static void space_strip_len(int max, char *str)
{
	int i;

	for (i = max - 1; i >= 0; i--) {
		if (str[i] != '\0' && str[i] != ' ')
			return;
		else
			str[i] = '\0';
	}
}

static void save_discovery_log(struct nvmf_discovery_log *log)
{
	uint64_t numrec = le64_to_cpu(log->numrec);
	int fd, len, ret;

	fd = open(raw, O_CREAT|O_RDWR|O_TRUNC, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		fprintf(stderr, "failed to open %s: %s\n",
			raw, strerror(errno));
		return;
	}

	len = sizeof(struct nvmf_discovery_log) +
		numrec * sizeof(struct nvmf_disc_log_entry);
	ret = write(fd, log, len);
	if (ret < 0)
		fprintf(stderr, "failed to write to %s: %s\n",
			raw, strerror(errno));
	else
		printf("Discovery log is saved to %s\n", raw);

	close(fd);
}

static int nvmf_discover(nvme_ctrl_t c, const struct nvme_fabrics_config *defcfg,
	bool connect)
{
	struct nvmf_discovery_log *log = NULL;
	int ret;

	ret = nvmf_get_discovery_log(c, &log, MAX_DISC_RETRIES);
	if (ret) {
		nvme_show_status("nvmf-discover-log", ret);
		return nvme_status_to_errno(ret, false);
	}

	if (raw)
		save_discovery_log(log);
	else if (!connect)
		;/* FIXME: the display */
	else if (connect) {
		uint64_t numrec;
		int i;

		numrec = le64_to_cpu(log->numrec);
		for (i = 0; i < numrec; i++) {
			struct nvmf_disc_log_entry *e = &log->entries[i];
			bool discover = false;
			nvme_ctrl_t child;

			errno = 0;
			child = nvmf_connect_disc_entry(e, defcfg, &discover);
			if (child) {
				if (discover)
					nvmf_discover(child, defcfg, true);
				if (!persistent)
					nvme_ctrl_disconnect(c);
				nvme_free_ctrl(child);
			} else if (errno == EALREADY && !quiet) {
				char *traddr = log->entries[i].traddr;

				space_strip_len(NVMF_TRADDR_SIZE, traddr);
				fprintf(stderr, "traddr=%s is already connected\n",
					traddr);
			}
		}
	}

	free(log);
	return 0;
}

static int discover_from_conf_file(const char *desc, bool connect,
	const struct nvme_fabrics_config *defcfg)
{
	char *ptr, **argv, *p, line[4096];
	int argc, ret = 0;
	FILE *f;

	struct nvme_fabrics_config cfg = { 0 };

	OPT_ARGS(opts) = {
		NVMF_OPTS(cfg),
	};

	f = fopen(PATH_NVMF_DISC, "r");
	if (f == NULL) {
		errno = ENOENT;
		return -1;
	}

	argv = calloc(MAX_DISC_ARGS, sizeof(char *));
	if (!argv) {
		ret = -1;
		goto out;
	}

	argv[0] = "discover";
	memset(line, 0, sizeof(line));
	while (fgets(line, sizeof(line), f) != NULL) {
		nvme_ctrl_t c;

		if (line[0] == '#' || line[0] == '\n')
			continue;

		argc = 1;
		p = line;
		while ((ptr = strsep(&p, " =\n")) != NULL)
			argv[argc++] = ptr;
		argv[argc] = NULL;

		memcpy(&cfg, defcfg, sizeof(cfg));
		ret = argconfig_parse(argc, argv, desc, opts);
		if (ret)
			goto next;

		if (!cfg.transport && !cfg.traddr)
			goto next;

		errno = 0;
		c = nvmf_add_ctrl(&cfg);
		if (c) {
			nvmf_discover(c, defcfg, connect);
				return 0;
			if (!persistent)
				ret = nvme_ctrl_disconnect(c);
			nvme_free_ctrl(c);
		}
next:
		memset(&cfg, 0, sizeof(cfg));
	}
	free(argv);
out:
	fclose(f);
	return ret;
}

const static char *nqn_match;
static bool nvme_match_subsysnqn_filter(nvme_subsystem_t s)
{
	if (nqn_match && strlen(nqn_match))
		return strcmp(nvme_subsystem_get_nqn(s), nqn_match) == 0;
	return true;
}


static nvme_ctrl_t nvme_find_matching_ctrl(struct nvme_fabrics_config *cfg)
{
	nvme_subsystem_t s;
	nvme_root_t r;
	nvme_ctrl_t c;

	nqn_match = cfg->nqn;
	r = nvme_scan_filter(nvme_match_subsysnqn_filter);
	nvme_for_each_subsystem(r, s) {
		nvme_subsystem_for_each_ctrl(s, c) {
			if (nvme_ctrl_match_cfg(c, cfg)) {
				nvme_unlink_ctrl(c);
				goto found;
			}
		}
	}
found:
	nvme_free_tree(r);
	return c;
}

int discover(const char *desc, int argc, char **argv, bool connect)
{
	char *hnqn = NULL, *hid = NULL;
	int ret;

	struct nvme_fabrics_config cfg = {
		.nqn = NVME_DISC_SUBSYS_NAME,
		.tos = -1,
	};

	char *device = NULL;

	OPT_ARGS(opts) = {
		OPT_LIST("device",     'd', &device,     "use existing discovery controller device"),
		NVMF_OPTS(cfg),
		OPT_FILE("raw",        'r', &raw,        "save raw output to file"),
		OPT_FLAG("persistent", 'p', &persistent, "persistent discovery connection"),
		OPT_FLAG("quiet",      'S', &quiet,      "suppress already connected errors"),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (persistent && !cfg.keep_alive_tmo)
		cfg.keep_alive_tmo = 30;
	if (!cfg.hostnqn)
		cfg.hostnqn = hnqn = nvmf_hostnqn_from_file();
	if (device && !strcmp(device, "none"))
		device = NULL;

	if (!device && !cfg.transport && !cfg.traddr)
		ret = discover_from_conf_file(desc, connect, &cfg);
	else {
		nvme_ctrl_t c = NULL;

		if (device) {
			c = nvme_scan_ctrl(device);
			if (c && !nvme_ctrl_match_cfg(c, &cfg)) {
				nvme_free_ctrl(c);
				device = NULL;
				c = NULL;
			}
			if (!c)
				c = nvme_find_matching_ctrl(&cfg);
		}

		if (!c) {
			errno = 0;
			c = nvmf_add_ctrl(&cfg);
		}

		if (c) {
			ret = nvmf_discover(c, &cfg, connect);
			if (!device && !persistent)
				nvme_ctrl_disconnect(c);
			nvme_free_ctrl(c);
		} else {
			fprintf(stderr, "no controller found\n");
			ret = errno;
		}
	}

	if (hnqn)
		free(hnqn);
	if (hid)
		free(hid);

	return ret;
}

static int discover_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Send Get Log Page request to Discovery Controller.";
	return discover(desc, argc, argv, false);
}

static int connect_all_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Discover NVMeoF subsystems and connect to them";
	return discover(desc, argc, argv, true);
}

static int connect_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Connect to NVMeoF subsystem";
	int ret;

	struct nvme_fabrics_config cfg = {
		.tos = -1,
	};

	OPT_ARGS(opts) = {
		OPT_LIST("nqn", 'n', &cfg.nqn, nvmf_nqn),
		NVMF_OPTS(cfg),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (!cfg.nqn) {
		fprintf(stderr, "required argument [--nqn | -n] not specified\n");
		return EINVAL;
	}

	if (!cfg.transport) {
		fprintf(stderr,
			 "required argument [--transport | -t] not specified\n");
		return EINVAL;
	}

	if (strcmp(cfg.transport, "loop")) {
		if (!cfg.traddr) {
			fprintf(stderr,
				"required argument [--address | -a] not specified for transport %s\n",
				cfg.transport);
			return EINVAL;
		}
	}

	errno = 0;
	nvmf_add_ctrl_opts(&cfg);
	return errno;
}

static int disconnect_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Disconnect from NVMeoF subsystem";
	const char *nqn = "nvme qualified name";
	const char *device = "nvme device handle";
	nvme_subsystem_t s;
	nvme_root_t r;
	nvme_ctrl_t c;
	char *p;
	int ret;

	struct config {
		char *nqn;
		char *device;
	};

	struct config cfg = { 0 };

	OPT_ARGS(opts) = {
		OPT_LIST("nqn",    'n', &cfg.nqn,    nqn),
		OPT_LIST("device", 'd', &cfg.device, device),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (!cfg.nqn && !cfg.device) {
		fprintf(stderr,
			"Neither device name [--device | -d] nor NQN [--nqn | -n] provided\n");
		return EINVAL;
	}

	if (cfg.nqn) {
		int i = 0;
		char *n = cfg.nqn;

		while ((p = strsep(&n, ",")) != NULL) {
			nqn_match = p;
			r = nvme_scan_filter(nvme_match_subsysnqn_filter);
			if (!r)
				continue;

			nvme_for_each_subsystem(r, s) {
				nvme_subsystem_for_each_ctrl(s, c) {
					if (!nvme_ctrl_disconnect(c))
						i++;
				}
			}
			nvme_free_tree(r);
		}

		printf("NQN:%s disconnected %d controller(s)\n", cfg.nqn, i);
	}

	if (cfg.device) {
		char *d;

		d = cfg.device;
		while ((p = strsep(&d, ",")) != NULL) {
			c = nvme_scan_ctrl(p);
			if (!c) {
				fprintf(stderr, "Did not find device: %s\n", p);
				return errno;
			}
			ret = nvme_ctrl_disconnect(c);
			if (!ret)
				printf("Disconnected %s\n",
					nvme_ctrl_get_name(c));
			else
				perror("disconnect");
			nvme_free_ctrl(c);
		}
	}

	return 0;
}

static int disconnect_all_cmd(int argc, char **argv, struct command *command,
	struct plugin *plugin)
{
	const char *desc = "Disconnect from all connected NVMeoF subsystems";
	nvme_subsystem_t s;
	nvme_root_t r;
	nvme_ctrl_t c;
	int ret;

	struct nvme_fabrics_config cfg = { 0 };

	OPT_ARGS(opts) = {
		OPT_STRING("transport", 'r', "STR", (char *)&cfg.transport, nvmf_tport),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	r = nvme_scan();
	if (!r) {
		perror("nvme-scan");
		return errno;
	}

	nvme_for_each_subsystem(r, s) {
		nvme_subsystem_for_each_ctrl(s, c) {
			if (cfg.transport &&
			    strcmp(cfg.transport, nvme_ctrl_get_transport(c)))
				continue;
			else if (!strcmp(nvme_ctrl_get_transport(c), "pcie"))
				continue;

			if (nvme_ctrl_disconnect(c))
				fprintf(stderr, "failed to disconnect %s\n",
					nvme_ctrl_get_name(c));
		}
	}
	nvme_free_tree(r);

	return 0;
}

void register_extension(struct plugin *plugin)
{
	plugin->parent = &nvme;
	nvme.extensions->tail->next = plugin;
	nvme.extensions->tail = plugin;
}

int main(int argc, char **argv)
{
	int err;

	nvme.extensions->parent = &nvme;
	if (argc < 2) {
		general_help(&builtin);
		return 0;
	}
	setlocale(LC_ALL, "");

	err = handle_plugin(argc - 1, &argv[1], nvme.extensions);
	if (err == -ENOTTY)
		general_help(&builtin);

	return err;
}
