#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/ioctl.h>

#include <linux/lightnvm.h>

#include "nvme.h"
#include "plugin.h"

#include "argconfig.h"
#include "suffix.h"

#define CREATE_CMD
#include "lnvm-nvme.h"

enum nvme_nvm_admin_opcode {
	nvme_nvm_admin_identity		= 0xe2,
	nvme_nvm_admin_get_bb_tbl	= 0xf2,
	nvme_nvm_admin_set_bb_tbl	= 0xf1,
};

struct nvme_nvm_identity {
	__u8	opcode;
	__u8	flags;
	__le16	command_id;
	__le32	nsid;
	__le64	rsvd[2];
	__le64	prp1;
	__le64	prp2;
	__le32	chnl_off;
	__le32	rsvd11[5];
};

struct nvme_nvm_setbbtbl {
	__u8	opcode;
	__u8	flags;
	__le16	rsvd1;
	__le32	nsid;
	__le32	cdw2;
	__le32	cdw3;
	__le64	metadata;
	__u64	addr;
	__le32	metadata_len;
	__le32	data_len;
	__le64	ppa;
	__le16	nlb;
	__u8	value;
	__u8	rsvd2;
	__le32	cdw14;
	__le32	cdw15;
	__le32	timeout_ms;
	__le32	result;
};

struct nvme_nvm_getbbtbl {
	__u8	opcode;
	__u8	flags;
	__le16	rsvd1;
	__le32	nsid;
	__le32	cdw2;
	__le32	cdw3;
	__u64	metadata;
	__u64	addr;
	__u32	metadata_len;
	__u32	data_len;
	__le64	ppa;
	__le32	cdw12;
	__le32	cdw13;
	__le32	cdw14;
	__le32	cdw15;
	__le32	timeout_ms;
	__le32	result;
};

struct nvme_nvm_command {
	union {
		struct nvme_nvm_identity identity;
		struct nvme_nvm_getbbtbl get_bb;
	};
};

struct nvme_nvm_completion {
	__le64	result;		/* Used by LightNVM to return ppa completions */
	__le16	sq_head;	/* how much of this queue may be reclaimed */
	__le16	sq_id;		/* submission queue that generated this entry */
	__le16	command_id;	/* of the command which completed */
	__le16	status;		/* did the command fail, and if so, why? */
};

#define NVME_NVM_LP_MLC_PAIRS 886
struct nvme_nvm_lp_mlc {
	__le16			num_pairs;
	__u8			pairs[NVME_NVM_LP_MLC_PAIRS];
};

struct nvme_nvm_lp_tbl {
	__u8			id[8];
	struct nvme_nvm_lp_mlc	mlc;
};

struct nvme_nvm_id12_group {
	__u8			mtype;
	__u8			fmtype;
	__le16			res16;
	__u8			num_ch;
	__u8			num_lun;
	__u8			num_pln;
	__u8			rsvd1;
	__le16			num_blk;
	__le16			num_pg;
	__le16			fpg_sz;
	__le16			csecs;
	__le16			sos;
	__le16			rsvd2;
	__le32			trdt;
	__le32			trdm;
	__le32			tprt;
	__le32			tprm;
	__le32			tbet;
	__le32			tbem;
	__le32			mpos;
	__le32			mccap;
	__le16			cpar;
	__u8			reserved[10];
	struct nvme_nvm_lp_tbl lptbl;
} __attribute__((packed));

struct nvme_nvm_addr_format {
	__u8			ch_offset;
	__u8			ch_len;
	__u8			lun_offset;
	__u8			lun_len;
	__u8			pln_offset;
	__u8			pln_len;
	__u8			blk_offset;
	__u8			blk_len;
	__u8			pg_offset;
	__u8			pg_len;
	__u8			sect_offset;
	__u8			sect_len;
	__u8			res[4];
} __attribute__((packed));

enum {
	LNVM_IDFY_CAP_BAD_BLK_TBL_MGMT	= 0,
	LNVM_IDFY_CAP_HYBRID_CMD_SUPP	= 1,
	LNVM_IDFY_CAP_VCOPY		= 0,
	LNVM_IDFY_CAP_MRESETS		= 1,
	LNVM_IDFY_DOM_HYBRID_MODE	= 0,
	LNVM_IDFY_DOM_ECC_MODE		= 1,
	LNVM_IDFY_GRP_MTYPE_NAND	= 0,
	LNVM_IDFY_GRP_FMTYPE_SLC	= 0,
	LNVM_IDFY_GRP_FMTYPE_MLC	= 1,
	LNVM_IDFY_GRP_FMTYPE_TLC	= 2,
	LNVM_IDFY_GRP_MPOS_SNGL_PLN_RD	= 0,
	LNVM_IDFY_GRP_MPOS_DUAL_PLN_RD	= 1,
	LNVM_IDFY_GRP_MPOS_QUAD_PLN_RD	= 2,
	LNVM_IDFY_GRP_MPOS_SNGL_PLN_PRG	= 8,
	LNVM_IDFY_GRP_MPOS_DUAL_PLN_PRG	= 9,
	LNVM_IDFY_GRP_MPOS_QUAD_PLN_PRG	= 10,
	LNVM_IDFY_GRP_MPOS_SNGL_PLN_ERS	= 16,
	LNVM_IDFY_GRP_MPOS_DUAL_PLN_ERS	= 17,
	LNVM_IDFY_GRP_MPOS_QUAD_PLN_ERS	= 18,
	LNVM_IDFY_GRP_MCCAP_SLC		= 0,
	LNVM_IDFY_GRP_MCCAP_CMD_SUSP	= 1,
	LNVM_IDFY_GRP_MCCAP_SCRAMBLE	= 2,
	LNVM_IDFY_GRP_MCCAP_ENCRYPT	= 3,
};

struct nvme_nvm_id12 {
	__u8			ver_id;
	__u8			vmnt;
	__u8			cgrps;
	__u8			res;
	__le32			cap;
	__le32			dom;
	struct nvme_nvm_addr_format ppaf;
	__u8			resv[228];
	struct nvme_nvm_id12_group groups[4];
} __attribute__((packed));

struct nvme_nvm_id20_addrf {
	__u8			grp_len;
	__u8			pu_len;
	__u8			chk_len;
	__u8			lba_len;
	__u8			resv[4];
} __attribute__((packed));

struct nvme_nvm_id20 {
	__u8			mjr;
	__u8			mnr;
	__u8			resv[6];

	struct nvme_nvm_id20_addrf lbaf;

	__le32			mccap;
	__u8			resv2[12];

	__u8			wit;
	__u8			resv3[31];

	/* Geometry */
	__le16			num_grp;
	__le16			num_pu;
	__le32			num_chk;
	__le32			clba;
	__u8			resv4[52];

	/* Write data requirements */
	__le32			ws_min;
	__le32			ws_opt;
	__le32			mw_cunits;
	__le32			maxoc;
	__le32			maxocpu;
	__u8			resv5[44];

	/* Performance related metrics */
	__le32			trdt;
	__le32			trdm;
	__le32			twrt;
	__le32			twrm;
	__le32			tcrst;
	__le32			tcrsm;
	__u8			resv6[40];

	/* Reserved area */
	__u8			resv7[2816];

	/* Vendor specific */
	__u8			vs[1024];
} __attribute__((packed));

struct nvme_nvm_id {
	__u8			ver_id;
	__u8			resv[4095];
} __attribute__((packed));

enum {
	NVM_LID_CHUNK_INFO = 0xCA,
};

struct nvme_nvm_chunk_desc {
	__u8	cs;
	__u8	ct;
	__u8	wli;
	__u8	rsvd_7_3[5];
	__u64	slba;
	__u64	cnlb;
	__u64	wp;
};

struct nvme_nvm_bb_tbl {
	__u8	tblid[4];
	__le16	verid;
	__le16	revid;
	__le32	rvsd1;
	__le32	tblks;
	__le32	tfact;
	__le32	tgrown;
	__le32	tdresv;
	__le32	thresv;
	__le32	rsvd2[8];
	__u8	blk[0];
};

#define NVM_BLK_BITS (16)
#define NVM_PG_BITS  (16)
#define NVM_SEC_BITS (8)
#define NVM_PL_BITS  (8)
#define NVM_LUN_BITS (8)
#define NVM_CH_BITS  (7)

struct ppa_addr {
	/* Generic structure for all addresses */
	union {
		struct {
			__u64 blk	: NVM_BLK_BITS;
			__u64 pg	: NVM_PG_BITS;
			__u64 sec	: NVM_SEC_BITS;
			__u64 pl	: NVM_PL_BITS;
			__u64 lun	: NVM_LUN_BITS;
			__u64 ch	: NVM_CH_BITS;
			__u64 reserved	: 1;
		} g;

		__u64 ppa;
	};
};

static inline struct ppa_addr generic_to_dev_addr(
			struct nvme_nvm_addr_format *ppaf, struct ppa_addr r)
{
	struct ppa_addr l;

	l.ppa = ((__u64)r.g.blk) << ppaf->blk_offset;
	l.ppa |= ((__u64)r.g.pg) << ppaf->pg_offset;
	l.ppa |= ((__u64)r.g.sec) << ppaf->sect_offset;
	l.ppa |= ((__u64)r.g.pl) << ppaf->pln_offset;
	l.ppa |= ((__u64)r.g.lun) << ppaf->lun_offset;
	l.ppa |= ((__u64)r.g.ch) << ppaf->ch_offset;

	return l;
}
static int lnvm_open(void)
{
	char dev[FILENAME_MAX] = NVM_CTRL_FILE;
	int fd;

	fd = open(dev, O_WRONLY);
	if (fd < 0) {
		printf("Failed to open LightNVM mgmt interface\n");
		perror(dev);
		return fd;
	}

	return fd;
}

static void lnvm_close(int fd)
{
	close(fd);
}

int lnvm_do_init(char *dev, char *mmtype)
{
	struct nvm_ioctl_dev_init init;
	int fd, ret;

	fd = lnvm_open();
	if (fd < 0)
		return fd;

	memset(&init, 0, sizeof(struct nvm_ioctl_dev_init));
	strncpy(init.dev, dev, DISK_NAME_LEN - 1);
	strncpy(init.mmtype, mmtype, NVM_MMTYPE_LEN - 1);

	ret = ioctl(fd, NVM_DEV_INIT, &init);
	switch (errno) {
	case EINVAL:
		printf("Initialization failed.\n");
		break;
	case EEXIST:
		printf("Device has already been initialized.\n");
		break;
	case 0:
		break;
	default:
		printf("Unknown error occurred (%d)\n", errno);
		break;
	}

	lnvm_close(fd);

	return ret;
}

int lnvm_do_list_devices(void)
{
	struct nvm_ioctl_get_devices devs;
	int fd, ret, i;

	fd = lnvm_open();
	if (fd < 0)
		return fd;

	ret = ioctl(fd, NVM_GET_DEVICES, &devs);
	if (ret)
		return ret;

	printf("Number of devices: %u\n", devs.nr_devices);
	printf("%-12s\t%-12s\tVersion\n", "Device", "Block manager");

	for (i = 0; i < devs.nr_devices && i < 31; i++) {
		struct nvm_ioctl_device_info *info = &devs.info[i];

		printf("%-12s\t%-12s\t(%u,%u,%u)\n", info->devname, info->bmname,
				info->bmversion[0], info->bmversion[1],
				info->bmversion[2]);
	}

	lnvm_close(fd);

	return 0;
}

int lnvm_do_info(void)
{
	struct nvm_ioctl_info c;
	int fd, ret, i;

	fd = lnvm_open();
	if (fd < 0)
		return fd;

	memset(&c, 0, sizeof(struct nvm_ioctl_info));
	ret = ioctl(fd, NVM_INFO, &c);
	if (ret)
		return ret;

	printf("LightNVM (%u,%u,%u). %u target type(s) registered.\n",
			c.version[0], c.version[1], c.version[2], c.tgtsize);
	printf("Type\tVersion\n");

	for (i = 0; i < c.tgtsize; i++) {
		struct nvm_ioctl_info_tgt *tgt = &c.tgts[i];

		printf("%s\t(%u,%u,%u)\n",
				tgt->tgtname, tgt->version[0], tgt->version[1],
				tgt->version[2]);
	}

	lnvm_close(fd);
	return 0;
}

int lnvm_do_create_tgt(char *devname, char *tgtname, char *tgttype,
					int lun_begin, int lun_end,
					int over_prov, int flags)
{
	struct nvm_ioctl_create c;
	int fd, ret;

	fd = lnvm_open();
	if (fd < 0)
		return fd;

	strncpy(c.dev, devname, DISK_NAME_LEN - 1);
	strncpy(c.tgtname, tgtname, DISK_NAME_LEN - 1);
	strncpy(c.tgttype, tgttype, NVM_TTYPE_NAME_MAX - 1);
	c.flags = flags;

	/* Fall back into simple IOCTL version if no extended attributes used */
	if (over_prov != -1) {
		c.conf.type = NVM_CONFIG_TYPE_EXTENDED;
		c.conf.e.lun_begin = lun_begin;
		c.conf.e.lun_end = lun_end;
		c.conf.e.over_prov = over_prov;
	} else {
		c.conf.type = NVM_CONFIG_TYPE_SIMPLE;
		c.conf.s.lun_begin = lun_begin;
		c.conf.s.lun_end = lun_end;
	}

	ret = ioctl(fd, NVM_DEV_CREATE, &c);
	if (ret)
		fprintf(stderr, "Creation of target failed. Please see dmesg.\n");

	lnvm_close(fd);
	return ret;
}

int lnvm_do_remove_tgt(char *tgtname)
{
	struct nvm_ioctl_remove c;
	int fd, ret;

	fd = lnvm_open();
	if (fd < 0)
		return fd;

	strncpy(c.tgtname, tgtname, DISK_NAME_LEN - 1);
	c.flags = 0;

	ret = ioctl(fd, NVM_DEV_REMOVE, &c);
	if (ret)
		fprintf(stderr, "Remove of target failed. Please see dmesg.\n");

	lnvm_close(fd);
	return ret;
}

int lnvm_do_factory_init(char *devname, int erase_only_marked,
						int clear_host_marks,
						int clear_bb_marks)
{
	struct nvm_ioctl_dev_factory fact;
	int fd, ret;

	fd = lnvm_open();
	if (fd < 0)
		return fd;

	memset(&fact, 0, sizeof(struct nvm_ioctl_dev_factory));

	strncpy(fact.dev, devname, DISK_NAME_LEN - 1);
	if (erase_only_marked)
		fact.flags |= NVM_FACTORY_ERASE_ONLY_USER;
	if (clear_host_marks)
		fact.flags |= NVM_FACTORY_RESET_HOST_BLKS;
	if (clear_bb_marks)
		fact.flags |= NVM_FACTORY_RESET_GRWN_BBLKS;

	ret = ioctl(fd, NVM_DEV_FACTORY, &fact);
	switch (errno) {
	case EINVAL:
		fprintf(stderr, "Factory reset failed.\n");
		break;
	case 0:
		break;
	default:
		fprintf(stderr, "Unknown error occurred (%d)\n", errno);
		break;
	}

	lnvm_close(fd);
	return ret;
}

static void show_lnvm_id_grp(void *t, int human)
{
	struct nvme_nvm_id12_group *grp = t;
	uint32_t mpos = (uint32_t)le32_to_cpu(grp->mpos);
	uint32_t mccap = (uint32_t)le32_to_cpu(grp->mccap);

	printf(" mtype   : %d\n", grp->mtype);
	if (human) {
		if (grp->mtype == LNVM_IDFY_GRP_MTYPE_NAND)
			printf("           NAND Flash Memory\n");
		else
			printf("           Reserved\n");
	}
	printf(" fmtype  : %d\n", grp->fmtype);
	if (human) {
		if (grp->fmtype == LNVM_IDFY_GRP_FMTYPE_SLC)
			printf("           Single bit Level Cell flash (SLC)\n");
		else if (grp->fmtype == LNVM_IDFY_GRP_FMTYPE_MLC)
			printf("           Two bit Level Cell flash (MLC)\n");
		else if (grp->fmtype == LNVM_IDFY_GRP_FMTYPE_TLC)
			printf("           Three bit Level Cell flash (TLC)\n");
		else
			printf("           Reserved\n");
	}
	printf(" chnls   : %d\n", grp->num_ch);
	printf(" luns    : %d\n", grp->num_lun);
	printf(" plns    : %d\n", grp->num_pln);
	printf(" blks    : %d\n", (uint16_t)le16_to_cpu(grp->num_blk));
	printf(" pgs     : %d\n", (uint16_t)le16_to_cpu(grp->num_pg));
	printf(" fpg_sz  : %d\n", (uint16_t)le16_to_cpu(grp->fpg_sz));
	printf(" csecs   : %d\n", (uint16_t)le16_to_cpu(grp->csecs));
	printf(" sos     : %d\n", (uint16_t)le16_to_cpu(grp->sos));
	printf(" trdt    : %d\n", (uint32_t)le32_to_cpu(grp->trdt));
	printf(" trdm    : %d\n", (uint32_t)le32_to_cpu(grp->trdm));
	printf(" tprt    : %d\n", (uint32_t)le32_to_cpu(grp->tprt));
	printf(" tprm    : %d\n", (uint32_t)le32_to_cpu(grp->tprm));
	printf(" tbet    : %d\n", (uint32_t)le32_to_cpu(grp->tbet));
	printf(" tbem    : %d\n", (uint32_t)le32_to_cpu(grp->tbem));
	printf(" mpos    : %#x\n", mpos);
	if (human) {
		if (mpos & (1 << LNVM_IDFY_GRP_MPOS_SNGL_PLN_RD))
			printf("           [0]: Single plane read\n");
		if (mpos & (1 << LNVM_IDFY_GRP_MPOS_DUAL_PLN_RD))
			printf("           [1]: Dual plane read\n");
		if (mpos & (1 << LNVM_IDFY_GRP_MPOS_QUAD_PLN_RD))
			printf("           [2]: Quad plane read\n");
		if (mpos & (1 << LNVM_IDFY_GRP_MPOS_SNGL_PLN_PRG))
			printf("           [8]: Single plane program\n");
		if (mpos & (1 << LNVM_IDFY_GRP_MPOS_DUAL_PLN_PRG))
			printf("           [9]: Dual plane program\n");
		if (mpos & (1 << LNVM_IDFY_GRP_MPOS_QUAD_PLN_PRG))
			printf("           [10]: Quad plane program\n");
		if (mpos & (1 << LNVM_IDFY_GRP_MPOS_SNGL_PLN_ERS))
			printf("           [16]: Single plane erase\n");
		if (mpos & (1 << LNVM_IDFY_GRP_MPOS_DUAL_PLN_ERS))
			printf("           [17]: Dual plane erase\n");
		if (mpos & (1 << LNVM_IDFY_GRP_MPOS_QUAD_PLN_ERS))
			printf("           [18]: Quad plane erase\n");
	}
	printf(" mccap   : %#x\n", mccap);
	if (human) {
		if (mccap & (1 << LNVM_IDFY_GRP_MCCAP_SLC))
			printf("           [0]: SLC mode\n");
		if (mccap & (1 << LNVM_IDFY_GRP_MCCAP_CMD_SUSP))
			printf("           [1]: Command suspension\n");
		if (mccap & (1 << LNVM_IDFY_GRP_MCCAP_SCRAMBLE))
			printf("           [2]: Scramble\n");
		if (mccap & (1 << LNVM_IDFY_GRP_MCCAP_ENCRYPT))
			printf("           [3]: Encryption\n");
	}
	printf(" cpar    : %#x\n", (uint16_t)le16_to_cpu(grp->cpar));

}

static void show_lnvm_ppaf(struct nvme_nvm_addr_format *ppaf)
{
	printf("ppaf     :\n");
	printf(" ch offs : %d ch bits  : %d\n",
					ppaf->ch_offset, ppaf->ch_len);
	printf(" lun offs: %d lun bits : %d\n",
					ppaf->lun_offset, ppaf->lun_len);
	printf(" pl offs : %d pl bits  : %d\n",
					ppaf->pln_offset, ppaf->pln_len);
	printf(" blk offs: %d blk bits : %d\n",
					ppaf->blk_offset, ppaf->blk_len);
	printf(" pg offs : %d pg bits  : %d\n",
					ppaf->pg_offset, ppaf->pg_len);
	printf(" sec offs: %d sec bits : %d\n",
					ppaf->sect_offset, ppaf->sect_len);
}

static void show_lnvm_id12_ns(void *t, unsigned int flags)
{
	int i;
	int human = flags & VERBOSE;
	struct nvme_nvm_id12 *id = t;

	uint32_t cap = (uint32_t) le32_to_cpu(id->cap);
	uint32_t dom = (uint32_t) le32_to_cpu(id->dom);
	uint32_t cgrps = id->cgrps;

	if (id->cgrps > 4) {
		fprintf(stderr, "invalid identify geometry returned\n");
		return;
	}

	printf("verid    : %#x\n", id->ver_id);
	printf("vmnt     : %#x\n", id->vmnt);
	if (human) {
		if (!id->vmnt)
			printf("           Generic/Enable opcodes as found in this spec.");
		else
			printf("           Reserved/Reserved for future opcode configurations");
	}
	printf("\n");
	printf("cgrps    : %d\n", id->cgrps);
	printf("cap      : %#x\n", cap);
	if (human) {
		if (cap & (1 << LNVM_IDFY_CAP_BAD_BLK_TBL_MGMT))
			printf("           [0]: Bad block table management\n");
		if (cap & (1 << LNVM_IDFY_CAP_HYBRID_CMD_SUPP))
			printf("           [1]: Hybrid command support\n");
	}
	printf("dom      : %#x\n", dom);
	if (human) {
		if (dom & (1 << LNVM_IDFY_DOM_HYBRID_MODE))
			printf("           [0]: Hybrid mode (L2P MAP is in device)\n");
		if (dom & (1 << LNVM_IDFY_DOM_ECC_MODE))
			printf("           [1]: Error Code Correction(ECC) mode\n");
	}
	show_lnvm_ppaf(&id->ppaf);

	for (i = 0; i < cgrps; i++) {
		printf("grp      : %d\n", i);
		show_lnvm_id_grp((void *)&id->groups[i], human);
	}
}

static void show_lnvm_id20_ns(struct nvme_nvm_id20 *id, unsigned int flags)
{
	int human = flags & VERBOSE;
	uint32_t mccap = (uint32_t) le32_to_cpu(id->mccap);

	printf("ver_major     : %#x\n", id->mjr);
	printf("ver_minor     : %#x\n", id->mnr);

	printf("mccap         : %#x\n", mccap);
	if (human) {
		if (mccap & (1 << LNVM_IDFY_CAP_VCOPY))
			printf("           [0]: Vector copy support\n");
		if (mccap & (1 << LNVM_IDFY_CAP_MRESETS))
			printf("           [1]: Multiple resets support\n");
	}
	printf("wit           : %d\n", id->wit);

	printf("lba format\n");
	printf(" grp len      : %d\n", id->lbaf.grp_len);
	printf(" pu len       : %d\n", id->lbaf.pu_len);
	printf(" chk len      : %d\n", id->lbaf.chk_len);
	printf(" clba len     : %d\n", id->lbaf.lba_len);

	printf("geometry\n");
	printf(" num_grp      : %d\n", le16_to_cpu(id->num_grp));
	printf(" num_pu       : %d\n", le16_to_cpu(id->num_pu));
	printf(" num_chk      : %d\n", le32_to_cpu(id->num_chk));
	printf(" clba         : %d\n", le32_to_cpu(id->clba));
	printf("write req\n");
	printf(" ws_min       : %d\n", le32_to_cpu(id->ws_min));
	printf(" ws_opt       : %d\n", le32_to_cpu(id->ws_opt));
	printf(" mw_cunits    : %d\n", le32_to_cpu(id->mw_cunits));
	printf(" maxoc        : %d\n", le32_to_cpu(id->maxoc));
	printf(" maxocpu      : %d\n", le32_to_cpu(id->maxocpu));
	printf("perf metrics\n");
	printf(" trdt (ns)    : %d\n", le32_to_cpu(id->trdt));
	printf(" trdm (ns)    : %d\n", le32_to_cpu(id->trdm));
	printf(" twrt (ns)    : %d\n", le32_to_cpu(id->twrt));
	printf(" twrm (ns)    : %d\n", le32_to_cpu(id->twrm));
	printf(" tcrst (ns)   : %d\n", le32_to_cpu(id->tcrst));
	printf(" tcrsm (ns)   : %d\n", le32_to_cpu(id->tcrsm));
}

static void show_lnvm_id_ns(struct nvme_nvm_id *id, unsigned int flags)
{
	switch (id->ver_id) {
		case 1:
			show_lnvm_id12_ns((void *) id, flags);
		break;
		case 2:
			show_lnvm_id20_ns((void *) id, flags);
		break;
		default:
			fprintf(stderr, "Version %d not supported.\n",
					id->ver_id);
	}
}

int lnvm_get_identity(int fd, int nsid, struct nvme_nvm_id *nvm_id)
{
	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_nvm_admin_identity,
		.nsid		= nsid,
		.addr		= (__u64)(uintptr_t)nvm_id,
		.data_len	= sizeof(struct nvme_nvm_id),
	};

	return nvme_submit_admin_passthru(fd, &cmd, NULL);
}

int lnvm_do_id_ns(int fd, int nsid, unsigned int flags)
{
	struct nvme_nvm_id nvm_id;
	int err;

	err = lnvm_get_identity(fd, nsid, &nvm_id);
	if (!err) {
		if (flags & BINARY)
			d_raw((unsigned char *)&nvm_id, sizeof(nvm_id));
		else
			show_lnvm_id_ns(&nvm_id, flags);
	} else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x) NSID:%d\n",
			nvme_status_to_string(err, false), err, nsid);
	return err;
}

static inline const char *print_chunk_state(__u8 cs)
{
	switch (cs) {
	case 1 << 0:	return "FREE";
	case 1 << 1:	return "CLOSED";
	case 1 << 2:	return "OPEN";
	case 1 << 3:	return "OFFLINE";
	default:	return "UNKNOWN";
	}
}

static inline const char *print_chunk_type(__u8 ct)
{
	switch (ct & 0xF) {
	case 1 << 0:	return "SEQWRITE_REQ";
	case 1 << 1:	return "RANDWRITE_ALLOWED";
	default:	return "UNKNOWN";
	}
}

static inline const char *print_chunk_attr(__u8 ct)
{
	switch (ct & 0xF0) {
	case 1 << 4:	return "DEVIATED";
	default:	return "NONE";
	}
}

static void show_lnvm_chunk_log(struct nvme_nvm_chunk_desc *chunk_log,
				__u32 data_len)
{
	int nr_entry = data_len / sizeof(struct nvme_nvm_chunk_desc);
	int idx;

	printf("Total chunks in namespace: %d\n", nr_entry);
	for (idx = 0; idx < nr_entry; idx++) {
		struct nvme_nvm_chunk_desc *desc = &chunk_log[idx];

		printf(" [%5d] { ", idx);
		printf("SLBA: 0x%016"PRIx64, le64_to_cpu(desc->slba));
		printf(", WP: 0x%016"PRIx64, le64_to_cpu(desc->wp));
		printf(", CNLB: 0x%016"PRIx64, le64_to_cpu(desc->cnlb));
		printf(", State: %-8s", print_chunk_state(desc->cs));
		printf(", Type: %-20s", print_chunk_type(desc->ct));
		printf(", Attr: %-8s", print_chunk_attr(desc->ct));
		printf(", WLI: %4d }\n", desc->wli);
	}
}

int lnvm_do_chunk_log(int fd, __u32 nsid, __u32 data_len, void *data,
			unsigned int flags)
{
	int err;

	err = nvme_get_log(fd, NVM_LID_CHUNK_INFO, nsid, 0, 0, 0,
			false, 0, data_len, data);
	if (err > 0) {
		fprintf(stderr, "NVMe Status:%s(%x) NSID:%d\n",
			nvme_status_to_string(err, false), err, nsid);

		goto out;
	} else if (err < 0) {
		err = -errno;
		perror("nvme_get_log");

		goto out;
	}

	if (flags & BINARY)
		d_raw(data, data_len);
	else
		show_lnvm_chunk_log(data, data_len);

out:
	return err;
}

static void show_lnvm_bbtbl(struct nvme_nvm_bb_tbl *tbl)
{
	printf("verid    : %#x\n", (uint16_t)le16_to_cpu(tbl->verid));
	printf("tblks    : %d\n", (uint32_t)le32_to_cpu(tbl->tblks));
	printf("tfact    : %d\n", (uint32_t)le32_to_cpu(tbl->tfact));
	printf("tgrown   : %d\n", (uint32_t)le32_to_cpu(tbl->tgrown));
	printf("tdresv   : %d\n", (uint32_t)le32_to_cpu(tbl->tdresv));
	printf("thresv   : %d\n", (uint32_t)le32_to_cpu(tbl->thresv));
	printf("Use raw output to retrieve table.\n");
}

static int __lnvm_do_get_bbtbl(int fd, struct nvme_nvm_id12 *id,
						struct ppa_addr ppa,
						unsigned int flags)
{
	struct nvme_nvm_id12_group *grp = &id->groups[0];
	int bbtblsz = ((uint16_t)le16_to_cpu(grp->num_blk) * grp->num_pln);
	int bufsz = bbtblsz + sizeof(struct nvme_nvm_bb_tbl);
	struct nvme_nvm_bb_tbl *bbtbl;
	int err;

	bbtbl = calloc(1, bufsz);
	if (!bbtbl)
		return -ENOMEM;

	struct nvme_nvm_getbbtbl cmd = {
		.opcode		= nvme_nvm_admin_get_bb_tbl,
		.nsid		= cpu_to_le32(1),
		.addr		= (__u64)(uintptr_t)bbtbl,
		.data_len	= bufsz,
		.ppa		= cpu_to_le64(ppa.ppa),
	};
	void *tmp = &cmd;
	struct nvme_passthru_cmd *nvme_cmd = tmp;

	err = nvme_submit_admin_passthru(fd, nvme_cmd, NULL);
	if (err > 0) {
		fprintf(stderr, "NVMe Status:%s(%x)\n",
			nvme_status_to_string(err, false), err);
		free(bbtbl);
		return err;
	}

	if (flags & BINARY)
		d_raw((unsigned char *)&bbtbl->blk, bbtblsz);
	else {
		printf("LightNVM Bad Block Stats:\n");
		show_lnvm_bbtbl(bbtbl);
	}

	free(bbtbl);
	return 0;
}

int lnvm_do_get_bbtbl(int fd, int nsid, int lunid, int chid, unsigned int flags)
{
	struct nvme_nvm_id12 nvm_id;
	struct ppa_addr ppa;
	int err;
	void *tmp = &nvm_id;

	err = lnvm_get_identity(fd, nsid, (struct nvme_nvm_id *)tmp);
	if (err) {
		fprintf(stderr, "NVMe Status:%s(%x)\n",
			nvme_status_to_string(err, false), err);
		return err;
	}

	if (nvm_id.ver_id != 1) {
		fprintf(stderr, "Get bad block table not supported on version %d\n",
				nvm_id.ver_id);
		return -EINVAL;
	}

	if (chid >= nvm_id.groups[0].num_ch ||
					lunid >= nvm_id.groups[0].num_lun) {
		fprintf(stderr, "Out of bound channel id or LUN id\n");
		return -EINVAL;
	}

	ppa.ppa = 0;
	ppa.g.lun = lunid;
	ppa.g.ch = chid;

	ppa = generic_to_dev_addr(&nvm_id.ppaf, ppa);

	return __lnvm_do_get_bbtbl(fd, &nvm_id, ppa, flags);
}

static int __lnvm_do_set_bbtbl(int fd, struct ppa_addr ppa, __u8 value)
{
	int err;

	struct nvme_nvm_setbbtbl cmd = {
		.opcode		= nvme_nvm_admin_set_bb_tbl,
		.nsid		= cpu_to_le32(1),
		.ppa		= cpu_to_le64(ppa.ppa),
		.nlb		= cpu_to_le16(0),
		.value		= value,
	};
	void *tmp = &cmd;
	struct nvme_passthru_cmd *nvme_cmd = tmp;

	err = nvme_submit_admin_passthru(fd, nvme_cmd, NULL);
	if (err > 0) {
		fprintf(stderr, "NVMe Status:%s(%x)\n",
			nvme_status_to_string(err, false), err);
		return err;
	}
	return 0;
}

int lnvm_do_set_bbtbl(int fd, int nsid,
				int chid, int lunid, int plnid, int blkid,
				__u8 value)
{
	struct nvme_nvm_id12 nvm_id;
	struct ppa_addr ppa;
	int err;
	void *tmp = &nvm_id;

	err = lnvm_get_identity(fd, nsid, (struct nvme_nvm_id *)tmp);
	if (err) {
		fprintf(stderr, "NVMe Status:%s(%x)\n",
			nvme_status_to_string(err, false), err);
		return err;
	}

	if (nvm_id.ver_id != 1) {
		fprintf(stderr, "Set bad block table not supported on version %d\n",
				nvm_id.ver_id);
		return -EINVAL;
	}

	if (chid >= nvm_id.groups[0].num_ch ||
					lunid >= nvm_id.groups[0].num_lun ||
					plnid >= nvm_id.groups[0].num_pln ||
					blkid >= le16_to_cpu(nvm_id.groups[0].num_blk)) {
		fprintf(stderr, "Out of bound channel id, LUN id, plane id, or"\
				"block id\n");
		return -EINVAL;
	}

	ppa.ppa = 0;
	ppa.g.lun = lunid;
	ppa.g.ch = chid;
	ppa.g.pl = plnid;
	ppa.g.blk = blkid;

	ppa = generic_to_dev_addr(&nvm_id.ppaf, ppa);

	return __lnvm_do_set_bbtbl(fd, ppa, value);
}
static int lnvm_init(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Initialize LightNVM device. A LightNVM/Open-Channel SSD"\
			   " must have a media manager associated before it can"\
			   " be exposed to the user. The default is to initialize"
			   " the general media manager on top of the device.\n\n"
			   "Example:"
			   " lnvm-init -d nvme0n1";
	const char *devname = "identifier of desired device. e.g. nvme0n1.";
	const char *mmtype = "media manager to initialize on top of device. Default: gennvm.";
	int ret;

	struct config {
		char *devname;
		char *mmtype;
	};

	struct config cfg = {
		.devname = "",
		.mmtype = "gennvm",
	};

	OPT_ARGS(opts) = {
		OPT_STRING("device-name",   'd', "DEVICE", &cfg.devname, devname),
		OPT_STRING("mediamgr-name", 'm', "MM",     &cfg.mmtype,  mmtype),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret < 0)
		return ret;

	if (!strlen(cfg.devname)) {
		fprintf(stderr, "device name missing\n");
		return -EINVAL;
	}

	return lnvm_do_init(cfg.devname, cfg.mmtype);
}

static int lnvm_list(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "List all devices registered with LightNVM.";
	int ret;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret < 0)
		return ret;

	return lnvm_do_list_devices();
}

static int lnvm_info(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Show general information and registered target types with LightNVM";
	int ret;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret < 0)
		return ret;

	return lnvm_do_info();
}

static int lnvm_id_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Geometry command to the "\
		"given LightNVM device, returns properties of the specified "\
		"namespace in either human-readable or binary format.";
	const char *raw_binary = "show infos in binary format";
	const char *human_readable = "show infos in readable format";
	const char *namespace_id = "identifier of desired namespace. default: 1";
	unsigned int flags = 0;
	int fd;

	struct config {
		__u32 namespace_id;
		int   raw_binary;
		int   human_readable;
	};

	struct config cfg = {
		.namespace_id    = 1,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",   'n', &cfg.namespace_id,   namespace_id),
		OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw_binary),
		OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return fd;

	if (cfg.human_readable)
		flags |= VERBOSE;
	else if (cfg.raw_binary)
		flags |= BINARY;

	return lnvm_do_id_ns(fd, cfg.namespace_id, flags);
}

static int lnvm_chunk_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve the chunk information log for the "\
		"specified given LightNVM device, returns in either "\
		"human-readable or binary format.\n"\
		"This will request Geometry first to get the "\
		"num_grp,num_pu,num_chk first to figure out the total size "\
		"of the log pages."\
		;
	const char *output_format = "Output format: normal|binary";
	const char *human_readable = "Print normal in readable format";
	int err, fmt, fd;
	struct nvme_nvm_id20 geo;
	struct nvme_nvm_chunk_desc *chunk_log;
	__u32 nsid;
	__u32 data_len;
	unsigned int flags = 0;

	struct config {
		char *output_format;
		int human_readable;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",  'o', &cfg.output_format,  output_format),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return fd;

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0) {
		err = fmt;
		goto close;
	}

	if (fmt == BINARY)
		flags |= BINARY;
	else if (cfg.human_readable)
		flags |= VERBOSE;

	nsid = nvme_get_nsid(fd);

	/*
	 * It needs to figure out how many bytes will be requested by this
	 * subcommand by the (num_grp * num_pu * num_chk) from the Geometry.
	 */
	err = lnvm_get_identity(fd, nsid, (struct nvme_nvm_id *) &geo);
	if (err)
		goto close;

	data_len = (geo.num_grp * geo.num_pu * geo.num_chk) *
			sizeof(struct nvme_nvm_chunk_desc);
	chunk_log = malloc(data_len);
	if (!chunk_log) {
		fprintf(stderr, "cound not alloc for chunk log %dbytes\n",
				data_len);
		err = -ENOMEM;
		goto close;
	}

	err = lnvm_do_chunk_log(fd, nsid, data_len, chunk_log, flags);
	if (err)
		fprintf(stderr, "get log page for chunk information failed\n");

	free(chunk_log);
close:
	close(fd);
	return err;
}

static int lnvm_create_tgt(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Instantiate a target on top of a LightNVM enabled device.";
	const char *devname = "identifier of desired device. e.g. nvme0n1.";
	const char *tgtname = "target name of the device to initialize. e.g. target0.";
	const char *tgttype = "identifier of target type. e.g. pblk.";
	const char *lun_begin = "Define begin of luns to use for target.";
	const char *lun_end = "Define set of luns to use for target.";
	const char *over_prov = "Define over-provision percentage for target.";
	const char *flag_factory = "Create target in factory mode";
	int flags;
	int ret;

	struct config {
		char *devname;
		char *tgtname;
		char *tgttype;
		__u32 lun_begin;
		__u32 lun_end;
		__u32 over_prov;

		/* flags */
		__u32 factory;
	};

	struct config cfg = {
		.devname = "",
		.tgtname = "",
		.tgttype = "",
		.lun_begin = -1,
		.lun_end = -1,
		.over_prov = -1,
		.factory = 0,
	};

	OPT_ARGS(opts) = {
		OPT_STRING("device-name", 'd', "DEVICE",      &cfg.devname, devname),
		OPT_STRING("target-name", 'n', "TARGET",      &cfg.tgtname, tgtname),
		OPT_STRING("target-type", 't', "TARGETTYPE",  &cfg.tgttype, tgttype),
		OPT_UINT("lun-begin",     'b', &cfg.lun_begin, lun_begin),
		OPT_UINT("lun-end",       'e', &cfg.lun_end,   lun_end),
		OPT_UINT("over-prov",     'o', &cfg.over_prov, over_prov),
		OPT_FLAG("factory",       'f', &cfg.factory,   flag_factory),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret < 0)
		return ret;

	if (!strlen(cfg.devname)) {
		fprintf(stderr, "device name missing\n");
		return -EINVAL;
	}
	if (!strlen(cfg.tgtname)) {
		fprintf(stderr, "target name missing\n");
		return -EINVAL;
	}
	if (!strlen(cfg.tgttype)) {
		fprintf(stderr, "target type missing\n");
		return -EINVAL;
	}

	flags = 0;
	if (cfg.factory)
		flags |= NVM_TARGET_FACTORY;

	return lnvm_do_create_tgt(cfg.devname, cfg.tgtname, cfg.tgttype, cfg.lun_begin, cfg.lun_end, cfg.over_prov, flags);
}

static int lnvm_remove_tgt(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Remove an initialized LightNVM target.";
	const char *tgtname = "target name of the device to remove. e.g. target0.";
	int ret;

	struct config {
		char *tgtname;
	};

	struct config cfg = {
		.tgtname = "",
	};

	OPT_ARGS(opts) = {
		OPT_STRING("target-name", 'n', "TARGET", &cfg.tgtname, tgtname),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret < 0)
		return ret;

	if (!strlen(cfg.tgtname)) {
		fprintf(stderr, "target name missing\n");
		return -EINVAL;
	}

	return lnvm_do_remove_tgt(cfg.tgtname);
}

static int lnvm_factory_init(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Factory initialize a LightNVM enabled device.";
	const char *devname = "identifier of desired device. e.g. nvme0n1.";
	const char *erase_only_marked = "only erase marked blocks. default: all blocks.";
	const char *host_marks = "remove host side blocks list. default: keep.";
	const char *bb_marks = "remove grown bad blocks list. default: keep";
	int ret;

	struct config {
		char *devname;
		int  erase_only_marked;
		int  clear_host_marks;
		int  clear_bb_marks;
	};

	struct config cfg = {
		.devname = "",
	};

	OPT_ARGS(opts) = {
		OPT_STRING("device-name",        'd', "DEVICE", &cfg.devname, devname),
		OPT_FLAG("erase-only-marked",    'e', &cfg.erase_only_marked, erase_only_marked),
		OPT_FLAG("clear-host-side-blks", 's', &cfg.clear_host_marks,  host_marks),
		OPT_FLAG("clear-bb-blks",        'b', &cfg.clear_bb_marks,    bb_marks),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret < 0)
		return ret;

	if (!strlen(cfg.devname)) {
		fprintf(stderr, "device name missing\n");
		return -EINVAL;
	}

	return lnvm_do_factory_init(cfg.devname, cfg.erase_only_marked,
				cfg.clear_host_marks, cfg.clear_bb_marks);
}

static int lnvm_get_bbtbl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Receive bad block table from a LightNVM compatible"\
			   " device.";
	const char *namespace = "(optional) desired namespace";
	const char *ch = "channel identifier";
	const char *lun = "lun identifier (within a channel)";
	const char *raw_binary = "show infos in binary format";
	unsigned int fd, flags = 0;

	struct config {
		__u32 namespace_id;
		__u16 lunid;
		__u16 chid;
		int   raw_binary;
	};

	struct config cfg = {
		.namespace_id = 1,
		.lunid = 0,
		.chid = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace),
		OPT_SHRT("channel-id",   'c', &cfg.chid,         ch),
		OPT_SHRT("lun-id",       'l', &cfg.lunid,        lun),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw_binary),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);

	if (cfg.raw_binary)
		flags |= BINARY;

	return lnvm_do_get_bbtbl(fd, cfg.namespace_id, cfg.lunid, cfg.chid, flags);
}

static int lnvm_set_bbtbl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Update bad block table on a LightNVM compatible"\
			   " device.";
	const char *namespace = "(optional) desired namespace";
	const char *ch = "channel identifier";
	const char *lun = "lun identifier (within a channel)";
	const char *pln = "plane identifier (within a lun)";
	const char *blk = "block identifier (within a plane)";
	const char *value = "value to update the specific block to.";
	int fd;

	struct config {
		__u32 namespace_id;
		__u16 lunid;
		__u16 chid;
		__u16 plnid;
		__u16 blkid;
		__u16 value;
	};

	struct config cfg = {
		.namespace_id = 1,
		.lunid = 0,
		.chid = 0,
		.plnid = 0,
		.blkid = 0,
		.value = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace),
		OPT_SHRT("channel-id",   'c', &cfg.chid,         ch),
		OPT_SHRT("lun-id",       'l', &cfg.lunid,        lun),
		OPT_SHRT("plane-id",     'p', &cfg.plnid,        pln),
		OPT_SHRT("block-id",     'b', &cfg.blkid,        blk),
		OPT_SHRT("value",        'v', &cfg.value,        value),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);

	printf("Updating: Ch.: %u LUN: %u Plane: %u Block: %u -> %u\n",
			cfg.chid, cfg.lunid, cfg.plnid, cfg.blkid, cfg.value);
	return lnvm_do_set_bbtbl(fd, cfg.namespace_id, cfg.chid, cfg.lunid,
				 cfg.plnid, cfg.blkid, cfg.value);
}
