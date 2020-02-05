/*
 * Copyright (c) 2006-2007 The Regents of the University of California.
 * Copyright (c) 2004-2009 Voltaire, Inc. All rights reserved.
 * Copyright (c) 2002-2010 Mellanox Technologies LTD. All rights reserved.
 * Copyright (c) 1996-2003 Intel Corporation. All rights reserved.
 * Copyright (c) 2009 HNR Consulting. All rights reserved.
 * Copyright (c) 2011 Lawrence Livermore National Security. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

/**
 * Define common functions which can be included in the various C based diags.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#include <limits.h>
#include <sys/stat.h>
#include <stdarg.h>

#include <infiniband/umad.h>
#include <infiniband/mad.h>
#include <ibdiag_common.h>
#include <ibdiag_version.h>

typedef struct guid_2_m_key {
	uint64_t guid;
	uint64_t m_key;
} guid_2_m_key_t;

typedef struct guid_2_lid {
	uint64_t guid;
	uint16_t start_lid;
	uint16_t end_lid;
} guid_2_lid_t;

typedef struct neighbors_nodes {
	uint64_t src_guid;
	uint8_t src_port;
	uint64_t dest_guid;
	uint8_t dest_port;
} neighbors_nodes_t;

int ibverbose;
enum MAD_DEST ibd_dest_type = IB_DEST_LID;
ib_portid_t *ibd_sm_id;
static ib_portid_t sm_portid = { 0 };

/* general config options */
#if defined(WIN32) || defined(_WIN32)
#define PATH_SEPARATOR "\\"
#else
#define PATH_SEPARATOR "/"
#endif

char *ibd_ca = NULL;
int ibd_ca_port = 0;
int ibd_timeout = 0;
uint32_t ibd_ibnetdisc_flags = IBND_CONFIG_MLX_EPI;
char ibd_mkey_file_dir_path[LENGTH_OF_PATH] = {0};
char ibd_cfg_file_mkey_file_dir_path[LENGTH_OF_PATH] = {0};
uint64_t ibd_mkey = 0;
uint64_t ibd_cfg_file_mkey = 0;
uint64_t ibd_sakey = 0;
int show_keys = 0;
char *ibd_nd_format = NULL;
uint8_t ibd_mkey_flag = 0;
uint8_t ibd_mkey_file_flag = 0;
uint8_t ibd_cfg_file_mkey_flag = 0;
uint8_t ibd_cfg_file_mkey_file_flag = 0;
mkey_manager_t ibd_mkey_mgr = {.neighbors_nodes_table = {NULL},
			       .guid_2_lid_table = NULL,
			       .default_mkey = 0,
			       .state = DEFAULT_MKEY,
			       .dest_type = IB_DEST_LID,
			       .is_guid_2_lid_loaded = 0,
			       .is_guid_2_mkey_loaded = 0,
			       .is_neighbors_loaded = 0};

static const char *prog_name;
static const char *prog_args;
static const char **prog_examples;
static struct option *long_opts = NULL;
static const struct ibdiag_opt *opts_map[256];

static int add_guid_2_mkey_obj_to_table(guid_2_m_key_t *guid_2_mkey_obj,
					neighbor_node_t *guid_2_mkey_table[])
{
	int hash_idx = HASH_BY_GUID(guid_2_mkey_obj->guid) % HTSZ;
	neighbor_node_t *tblnode;

	for (tblnode = guid_2_mkey_table[hash_idx]; tblnode;
	     tblnode = tblnode->next)
		if (tblnode->guid == guid_2_mkey_obj->guid)
			break;

	if (!tblnode) {
		tblnode = calloc(1, sizeof(neighbor_node_t));

		if (!tblnode)
			IBEXIT("Error: Could not find memory for guid2mkey"
			       "object\n");

		tblnode->guid = guid_2_mkey_obj->guid;
		tblnode->next = guid_2_mkey_table[hash_idx];
		guid_2_mkey_table[hash_idx] = tblnode;
	}

	tblnode->mkey = guid_2_mkey_obj->m_key;
	tblnode->is_mkey_exist = 1;

	return 0;
}

static int get_mkey_by_guid(const mkey_manager_t *mkey_mgr, uint64_t guid,
		     uint64_t *p_mkey)
{
	int hash_idx = HASH_BY_GUID(guid) % HTSZ;
	const neighbor_node_t *tblnode;
	neighbor_node_t * const *hash = mkey_mgr->neighbors_nodes_table;

	if (mkey_mgr->state == DEFAULT_MKEY) {
		*p_mkey = mkey_mgr->default_mkey;
		return 0;
	}

	if (!(mkey_mgr->is_guid_2_mkey_loaded)) {
		*p_mkey = mkey_mgr->default_mkey;
		return 0;
	}

	for (tblnode = hash[hash_idx]; tblnode; tblnode = tblnode->next)
		if (tblnode->guid == guid)
			break;

	if (tblnode) {
		if (!(tblnode->is_mkey_exist)) {
			fprintf(stderr, "Mkey was not found for GUID 0x%" PRIx64
				" in mkey table\n", guid);
			*p_mkey = mkey_mgr->default_mkey;
			return -1;
		}

		*p_mkey = tblnode->mkey;
	} else {
		fprintf(stderr, "Mkey was not found for GUID 0x%" PRIx64
			" in mkey table\n", guid);
		*p_mkey = mkey_mgr->default_mkey;
		return -1;
	}

	return 0;
}

static int add_guid_2_lid_obj_to_table(guid_2_lid_t *guid_2_lid_obj,
				       uint64_t *guid_2_lid_table)
{
	uint16_t i;

	for (i = guid_2_lid_obj->start_lid; i <= guid_2_lid_obj->end_lid; i++) {
		if (guid_2_lid_table[i - 1])
			fprintf(stderr, "LID %" PRIu16
				" is already exists in guid2lid table\n"
				"with GUID 0x%" PRIx64 "\n", i,
				guid_2_lid_table[i - 1]);
		else
			guid_2_lid_table[i - 1] = guid_2_lid_obj->guid;
	}

	return 0;
}

static int get_guid_by_lid(uint16_t lid, const uint64_t *guid_2_lid_table,
			   uint64_t *p_guid)
{
	if (!guid_2_lid_table)
		IBEXIT("Error: guid2lid table was not loaded\n");

	if ((lid == 0) || (lid >= IB_MAX_UCAST_LID + 1))
		IBEXIT("LID %" PRIu16 " is invalid\n", lid);

	if (guid_2_lid_table[lid - 1]) {
		*p_guid = guid_2_lid_table[lid - 1];
	} else {
		fprintf(stderr, "GUID  was not found for LID %" PRIu16
			" in guid2lid table\n", lid);
		*p_guid = 0;
		return -1;
	}

	return 0;
}

static int get_mkey_by_lid(const mkey_manager_t *mkey_mgr, uint16_t lid,
		    uint64_t *p_mkey)
{
	int result;
	uint64_t guid;

	if (mkey_mgr->state == DEFAULT_MKEY) {
		*p_mkey = mkey_mgr->default_mkey;
		return 0;
	}

	if (!(mkey_mgr->is_guid_2_lid_loaded)) {
		*p_mkey = mkey_mgr->default_mkey;
		return 0;
	}

	result = get_guid_by_lid(lid, mkey_mgr->guid_2_lid_table, &guid);

	if (result < 0) {
		*p_mkey = mkey_mgr->default_mkey;
		return result;
	}

	result = get_mkey_by_guid(mkey_mgr, guid, p_mkey);

	if (result < 0)
		*p_mkey = mkey_mgr->default_mkey;

	return result;
}

static void destroy_guid_2_lid_table(mkey_manager_t *mkey_mgr)
{
	if (mkey_mgr->is_guid_2_lid_loaded) {
		free(mkey_mgr->guid_2_lid_table);
		mkey_mgr->guid_2_lid_table = NULL;
		mkey_mgr->is_guid_2_lid_loaded = 0;
	}
}

static uint64_t get_local_guid(char *ca_name, uint8_t ca_port)
{
	ibmad_gid_t selfgid;
	uint64_t *gid;
	uint64_t guid = 0;

	if (resolve_self(ca_name, ca_port, NULL, NULL, &selfgid) < 0)
		IBEXIT("Error: Failed to get local GUID\n");

	gid = (uint64_t *)selfgid;
	guid = cl_ntoh64(gid[1]);

	return guid;
}

static int get_mkey_by_dr(const mkey_manager_t *mkey_mgr, const ib_dr_path_t *drpath,
		   uint64_t src_guid, uint64_t *p_mkey)
{
	uint64_t guid = src_guid;
	uint8_t port;
	int length_of_drpath = drpath->cnt;
	int i;
	int hash_idx;
	const neighbor_node_t *tblnode;
	neighbor_node_t * const *hash = mkey_mgr->neighbors_nodes_table;

	if (mkey_mgr->state == DEFAULT_MKEY) {
		*p_mkey = mkey_mgr->default_mkey;
		return 0;
	}

	if (!(mkey_mgr->is_neighbors_loaded)) {
		*p_mkey = mkey_mgr->default_mkey;
		return 0;
	}

	if (drpath->p[0])
		IBEXIT("Error: Direct Route path must start from zero\n");

	hash_idx = HASH_BY_GUID(guid) % HTSZ;

	for (tblnode = hash[hash_idx]; tblnode; tblnode = tblnode->next)
		if (tblnode->guid == guid)
			break;

	if (!tblnode) {
		fprintf(stderr, "Node source GUID: 0x%" PRIx64
			" doesn't exist\n", guid);
		*p_mkey = mkey_mgr->default_mkey;
		return -1;
	}

	for (i = 1; i <= length_of_drpath; i++) {
		port = drpath->p[i];

		if ((!port) || (port > IB_NODE_NUM_PORTS_MAX))
			IBEXIT("Error: Invalid port of Direct Route path: %"
				PRIu8 "\n", port);

		if (tblnode->neighbors_nodes_ports[port - 1]) {
			tblnode = tblnode->neighbors_nodes_ports[port - 1];
		} else {
			fprintf(stderr, "Node Neighbor GUID of GUID: 0x%" PRIx64
				" Port: %" PRIu8 " doesn't exist\n",
				tblnode->guid, port);
			*p_mkey = mkey_mgr->default_mkey;
			return -1;
		}
	}

	if (!(tblnode->is_mkey_exist)) {
		fprintf(stderr, "Mkey was not found for GUID 0x%" PRIx64
			" in mkey table\n", guid);
		*p_mkey = mkey_mgr->default_mkey;
		return -1;
	}

	*p_mkey = tblnode->mkey;

	return 0;
}

static int get_mkey_by_drslid(const mkey_manager_t *mkey_mgr,
		       const ib_dr_path_t *drpath, uint16_t src_lid,
		       uint64_t *p_mkey)
{
	uint64_t guid;
	int result;

	if (mkey_mgr->state == DEFAULT_MKEY) {
		*p_mkey = mkey_mgr->default_mkey;
		return 0;
	}

	if (!(mkey_mgr->is_guid_2_lid_loaded)) {
		*p_mkey = mkey_mgr->default_mkey;
		return 0;
	}

	result = get_guid_by_lid(src_lid, mkey_mgr->guid_2_lid_table, &guid);

	if (result < 0) {
		*p_mkey = mkey_mgr->default_mkey;
		return result;
	}

	result = get_mkey_by_dr(mkey_mgr, drpath, guid, p_mkey);

	if (result < 0)
		*p_mkey = mkey_mgr->default_mkey;

	return result;
}

int get_mkey_by_portid(const mkey_manager_t *mkey_mgr,
		       const ib_portid_t *portid, uint64_t *p_mkey)
{
	uint64_t local_guid;
	int result;

	if (mkey_mgr->state == DEFAULT_MKEY) {
		*p_mkey = mkey_mgr->default_mkey;
		return 0;
	}

	if (portid->lid <= 0)
	{
		local_guid = get_local_guid(ibd_ca, ibd_ca_port);
		result = get_mkey_by_dr(mkey_mgr, &(portid->drpath), local_guid,
					p_mkey);
	} else {
		if ((portid->drpath.drslid) &&
		    (portid->drpath.drdlid == 0xffff))
			result = get_mkey_by_drslid(mkey_mgr, &(portid->drpath),
						    (uint16_t)(portid->lid),
						    p_mkey);
		else
			result = get_mkey_by_lid(mkey_mgr,
						 (uint16_t)(portid->lid), p_mkey);
	}

	return result;
}

static int add_node_to_neighbors_nodes_table(neighbors_nodes_t *node,
					     neighbor_node_t *hash[])
{
	int hash_idx_src = HASH_BY_GUID(node->src_guid) % HTSZ;
	int hash_idx_dest = HASH_BY_GUID(node->dest_guid) % HTSZ;
	neighbor_node_t *tblnode_src;
	neighbor_node_t *tblnode_dest;

	for (tblnode_src = hash[hash_idx_src]; tblnode_src;
	     tblnode_src = tblnode_src->next)
		if (tblnode_src->guid == node->src_guid)
			break;

	if (!tblnode_src) {
		tblnode_src = calloc(1, sizeof(neighbor_node_t));

		if (!tblnode_src)
			IBEXIT("Error: Could not find memory for source"
			       "neighbor object\n");

		tblnode_src->guid = node->src_guid;
		tblnode_src->next = hash[hash_idx_src];
		hash[hash_idx_src] = tblnode_src;
	}

	for (tblnode_dest = hash[hash_idx_dest]; tblnode_dest;
	     tblnode_dest = tblnode_dest->next)
		if (tblnode_dest->guid == node->dest_guid)
			break;

	if (!tblnode_dest) {
		tblnode_dest = calloc(1, sizeof(neighbor_node_t));

		if (!tblnode_dest)
			IBEXIT("Error: Could not find memory for dest neighbor"
			       "object\n");

		tblnode_dest->guid = node->dest_guid;
		tblnode_dest->next = hash[hash_idx_dest];
		hash[hash_idx_dest] = tblnode_dest;
	}

	/* Bind between neighbors */
	if (!tblnode_src->neighbors_nodes_ports[node->src_port - 1])
		tblnode_src->neighbors_nodes_ports[node->src_port - 1] = tblnode_dest;

	if (!tblnode_dest->neighbors_nodes_ports[node->dest_port - 1])
		tblnode_dest->neighbors_nodes_ports[node->dest_port - 1] = tblnode_src;

	return 0;
}

static void destroy_neighbors_nodes_table(mkey_manager_t *mkey_mgr)
{
	int i,j;
	neighbor_node_t *tblnode;
	neighbor_node_t *tblnode_next;

	if (!(mkey_mgr->is_guid_2_mkey_loaded) &&
	    !(mkey_mgr->is_neighbors_loaded))
		return;

	for (i = 0; i < HTSZ; i++)
		if (mkey_mgr->neighbors_nodes_table[i]) {
			tblnode = mkey_mgr->neighbors_nodes_table[i];

			while (tblnode) {
				for (j = 0; j < IB_NODE_NUM_PORTS_MAX; j++)
					tblnode->neighbors_nodes_ports[j] = NULL;

				tblnode_next = tblnode->next;
				free(tblnode);
				tblnode = tblnode_next;
			}

			mkey_mgr->neighbors_nodes_table[i] = NULL;
		}

	mkey_mgr->is_guid_2_mkey_loaded = 0;
	mkey_mgr->is_neighbors_loaded = 0;
}


static void resolve_mkey_flags()
{
	if (ibd_mkey_flag || !ibd_mkey_file_flag)
		ibd_mkey_file_dir_path[0] = 0;

	if (!ibd_mkey_flag && !ibd_mkey_file_flag) {
		if (ibd_cfg_file_mkey_flag) {
			ibd_mkey = ibd_cfg_file_mkey;
			ibd_mkey_file_dir_path[0] = 0;
		} else {
			if (ibd_cfg_file_mkey_file_flag) {
				strncpy(ibd_mkey_file_dir_path,
					ibd_cfg_file_mkey_file_dir_path,
					sizeof(ibd_mkey_file_dir_path) - 1);
			} else {
				ibd_mkey_file_dir_path[0] = 0;
			}
		}
	}
}

static const char *get_build_version(void)
{
	return "BUILD VERSION: " IBDIAG_VERSION " Build date: " __DATE__ " "
	    __TIME__;
}

static void pretty_print(int start, int width, const char *str)
{
	int len = width - start;
	const char *p, *e;

	while (1) {
		while (isspace(*str))
			str++;
		p = str;
		do {
			e = p + 1;
			p = strchr(e, ' ');
		} while (p && p - str < len);
		if (!p) {
			fprintf(stderr, "%s", str);
			break;
		}
		if (e - str == 1)
			e = p;
		fprintf(stderr, "%.*s\n%*s", (int)(e - str), str, start, "");
		str = e;
	}
}

static inline int val_str_true(const char *val_str)
{
	return ((strncmp(val_str, "TRUE", strlen("TRUE")) == 0) ||
		(strncmp(val_str, "true", strlen("true")) == 0));
}


uint8_t *ext_speeds_reset_via(void *rcvbuf, ib_portid_t *dest,
			      int port, uint64_t mask, unsigned timeout,
			      const struct ibmad_port *srcport)
{
	ib_rpc_t rpc = { 0 };
	int lid = dest->lid;

	DEBUG("lid %u port %d mask 0x%" PRIx64, lid, port, mask);

	if (lid == -1) {
		IBWARN("only lid routed is supported");
		return NULL;
	}

	if (!mask)
		mask = ~0;

	rpc.mgtclass = IB_PERFORMANCE_CLASS;
	rpc.method = IB_MAD_METHOD_SET;
	rpc.attr.id = IB_GSI_PORT_EXT_SPEEDS_COUNTERS;

	memset(rcvbuf, 0, IB_MAD_SIZE);

	mad_set_field(rcvbuf, 0, IB_PESC_PORT_SELECT_F, port);
	mad_set_field64(rcvbuf, 0, IB_PESC_COUNTER_SELECT_F, mask);
	rpc.attr.mod = 0;
	rpc.timeout = timeout;
	rpc.datasz = IB_PC_DATA_SZ;
	rpc.dataoffs = IB_PC_DATA_OFFS;
	if (!dest->qp)
		dest->qp = 1;
	if (!dest->qkey)
		dest->qkey = IB_DEFAULT_QP1_QKEY;

	return mad_rpc(srcport, &rpc, dest, rcvbuf, rcvbuf);
}

uint8_t is_rsfec_mode_active(ib_portid_t * portid, int port,
			     uint16_t cap_mask, struct ibmad_port *srcport)
{
	int res = 0;
	uint8_t data[IB_SMP_DATA_SIZE] = { 0 };
	uint32_t fec_mode_active = 0;
	uint32_t pie_capmask = 0;

	if (cap_mask & IS_PM_RSFEC_COUNTERS_SUP) {
		if (!is_port_info_extended_supported(portid, port, srcport)) {
			IBWARN("Port Info Extended not supported");
			goto EXIT;
		}

		if (!smp_query_via(data, portid, IB_ATTR_PORT_INFO_EXT, port, 0,
				   srcport))
			IBEXIT("smp query portinfo extended failed");

		mad_decode_field(data, IB_PORT_EXT_CAPMASK_F, &pie_capmask);
		mad_decode_field(data, IB_PORT_EXT_FEC_MODE_ACTIVE_F,
				 &fec_mode_active);
		if((pie_capmask &
		   CL_NTOH32(IB_PORT_EXT_CAP_IS_FEC_MODE_SUPPORTED)) &&
		   ((CL_NTOH16(IB_PORT_EXT_RS_FEC_MODE_ACTIVE) == (fec_mode_active & 0xffff)) ||
		   (CL_NTOH16(IB_PORT_EXT_RS_FEC2_MODE_ACTIVE) == (fec_mode_active & 0xffff)))) {
			res = 1;
			goto EXIT;
		}
        }

EXIT:
        return res;
}

void read_ibdiag_config(const char *file)
{
	char buf[1024];
	FILE *config_fd = NULL;
	char *p_prefix, *p_last;
	char *name;
	char *val_str;
	struct stat statbuf;

	/* silently ignore missing config file */
	if (stat(file, &statbuf))
		return;

	config_fd = fopen(file, "r");
	if (!config_fd)
		return;

	ibd_cfg_file_mkey_flag = 0;
	ibd_cfg_file_mkey_file_flag = 0;

	while (fgets(buf, sizeof buf, config_fd) != NULL) {
		p_prefix = strtok_r(buf, "\n", &p_last);
		if (!p_prefix)
			continue; /* ignore blank lines */

		if (*p_prefix == '#')
			continue; /* ignore comment lines */

		name = strtok_r(p_prefix, "=", &p_last);
		val_str = strtok_r(NULL, "\n", &p_last);

		if (strncmp(name, "CA", strlen("CA")) == 0) {
			free(ibd_ca);
			ibd_ca = strdup(val_str);
		} else if (strncmp(name, "Port", strlen("Port")) == 0) {
			ibd_ca_port = strtoul(val_str, NULL, 0);
		} else if (strncmp(name, "timeout", strlen("timeout")) == 0) {
			ibd_timeout = strtoul(val_str, NULL, 0);
		} else if (strncmp(name, "MLX_EPI", strlen("MLX_EPI")) == 0) {
			if (val_str_true(val_str)) {
				ibd_ibnetdisc_flags |= IBND_CONFIG_MLX_EPI;
			} else {
				ibd_ibnetdisc_flags &= ~IBND_CONFIG_MLX_EPI;
			}
		} else if (strncmp(name, "m_key_files", strlen("m_key_files")) == 0) {
			strncpy(ibd_cfg_file_mkey_file_dir_path, val_str,
				sizeof(ibd_cfg_file_mkey_file_dir_path) - 1);
			ibd_cfg_file_mkey_file_flag = 1;
		} else if (strncmp(name, "m_key", strlen("m_key")) == 0) {
			ibd_cfg_file_mkey = strtoull(val_str, 0, 0);
			ibd_cfg_file_mkey_flag = 1;
		} else if (strncmp(name, "sa_key",
				   strlen("sa_key")) == 0) {
			ibd_sakey = strtoull(val_str, 0, 0);
		} else if (strncmp(name, "nd_format",
				   strlen("nd_format")) == 0) {
			ibd_nd_format = strdup(val_str);
		}
	}

	fclose(config_fd);
}


void ibdiag_show_usage()
{
	struct option *o = long_opts;
	int n;

	fprintf(stderr, "\nUsage: %s [options] %s\n\n", prog_name,
		prog_args ? prog_args : "");

	if (long_opts[0].name)
		fprintf(stderr, "Options:\n");
	for (o = long_opts; o->name; o++) {
		const struct ibdiag_opt *io = opts_map[o->val];
		n = fprintf(stderr, "  --%s", io->name);
		if (isprint(io->letter))
			n += fprintf(stderr, ", -%c", io->letter);
		if (io->has_arg)
			n += fprintf(stderr, " %s",
				     io->arg_tmpl ? io->arg_tmpl : "<val>");
		if (io->description && *io->description) {
			n += fprintf(stderr, "%*s  ", 24 - n > 0 ? 24 - n : 0,
				     "");
			pretty_print(n, 74, io->description);
		}
		fprintf(stderr, "\n");
	}

	if (prog_examples) {
		const char **p;
		fprintf(stderr, "\nExamples:\n");
		for (p = prog_examples; *p && **p; p++)
			fprintf(stderr, "  %s %s\n", prog_name, *p);
	}

	fprintf(stderr, "\n");

	exit(2);
}

static int process_opt(int ch, char *optarg)
{
	char *endp;
	long val;

	switch (ch) {
	case 'z':
		read_ibdiag_config(optarg);
		break;
	case 'h':
		ibdiag_show_usage();
		break;
	case 'V':
		fprintf(stderr, "%s %s\n", prog_name, get_build_version());
		exit(0);
	case 'e':
		madrpc_show_errors(1);
		break;
	case 'v':
		ibverbose++;
		break;
	case 'd':
		ibdebug++;
		madrpc_show_errors(1);
		umad_debug(ibdebug - 1);
		break;
	case 'C':
		ibd_ca = optarg;
		break;
	case 'P':
		ibd_ca_port = strtoul(optarg, 0, 0);
		if (ibd_ca_port < 0)
			IBEXIT("cannot resolve CA port %d", ibd_ca_port);
		break;
	case 'D':
		ibd_dest_type = IB_DEST_DRPATH;
		break;
	case 'L':
		ibd_dest_type = IB_DEST_LID;
		break;
	case 'G':
		ibd_dest_type = IB_DEST_GUID;
		break;
	case 't':
		errno = 0;
		val = strtol(optarg, &endp, 0);
		if (errno || (endp && *endp != '\0') || val <= 0 ||
		    val > INT_MAX)
			IBEXIT("Invalid timeout \"%s\".  Timeout requires a "
				"positive integer value < %d.", optarg, INT_MAX);
		else {
			madrpc_set_timeout((int)val);
			ibd_timeout = (int)val;
		}
		break;
	case 's':
		/* srcport is not required when resolving via IB_DEST_LID */
		if (resolve_portid_str(ibd_ca, ibd_ca_port, &sm_portid, optarg,
				IB_DEST_LID, 0, NULL) < 0)
			IBEXIT("cannot resolve SM destination port %s",
				optarg);
		ibd_sm_id = &sm_portid;
		break;
	case 'K':
		show_keys = 1;
		break;
	case 'y':
		errno = 0;
		ibd_mkey_flag = 1;
		ibd_mkey = strtoull(optarg, &endp, 0);
		if (errno || *endp != '\0') {
			errno = 0;
			ibd_mkey = strtoull(getpass("M_Key: "), &endp, 0);
			if (errno || *endp != '\0') {
				IBEXIT("Bad M_Key");
			}
                }
                break;
	case 'w':
		ibd_mkey_file_flag = 1;
		strncpy(ibd_mkey_file_dir_path, optarg,
			sizeof(ibd_mkey_file_dir_path) - 1);
		break;
	default:
		return -1;
	}

	return 0;
}

static void make_opt(struct option *l, const struct ibdiag_opt *o,
		     const struct ibdiag_opt *map[])
{
	l->name = o->name;
	l->has_arg = o->has_arg;
	l->flag = NULL;
	l->val = o->letter;
	if (!map[l->val])
		map[l->val] = o;
}


static void make_str_opts(const struct option *o, char *p, unsigned size)
{
	unsigned i, n = 0;

	for (n = 0; o->name && n + 2 + o->has_arg < size; o++) {
		p[n++] = (char)o->val;
		for (i = 0; i < (unsigned)o->has_arg; i++)
			p[n++] = ':';
	}
	p[n] = '\0';
}


void ibexit(const char *fn, char *msg, ...)
{
	char buf[512];
	va_list va;
	int n;

	va_start(va, msg);
	n = vsprintf(buf, msg, va);
	va_end(va);
	buf[n] = 0;

	if (ibdebug)
		printf("%s: iberror: [pid %d] %s: failed: %s\n",
		       prog_name ? prog_name : "", getpid(), fn, buf);
	else
		printf("%s: iberror: failed: %s\n",
		       prog_name ? prog_name : "", buf);

	exit(-1);
}

char *
conv_cnt_human_readable(uint64_t val64, float *val, int data)
{
	uint64_t tmp = val64;
	int ui = 0;
	uint64_t div = 1;

	tmp /= 1024;
	while (tmp) {
		ui++;
		tmp /= 1024;
		div *= 1024;
	}

	*val = (float)(val64);
	if (data) {
		*val *= 4;
		if (*val/div > 1024) {
			ui++;
			div *= 1024;
		}
	}
	*val /= div;

	if (data) {
		switch (ui) {
			case 0:
				return ("B");
			case 1:
				return ("KB");
			case 2:
				return ("MB");
			case 3:
				return ("GB");
			case 4:
				return ("TB");
			case 5:
				return ("PB");
			case 6:
				return ("EB");
			default:
				return ("");
		}
	} else {
		switch (ui) {
			case 0:
				return ("");
			case 1:
				return ("K");
			case 2:
				return ("M");
			case 3:
				return ("G");
			case 4:
				return ("T");
			case 5:
				return ("P");
			case 6:
				return ("E");
			default:
				return ("");
		}
	}
	return ("");
}

int is_port_info_extended_supported(ib_portid_t * dest, int port,
				    struct ibmad_port *srcport)
{
	uint8_t data[IB_SMP_DATA_SIZE] = { 0 };
	uint32_t cap_mask;
	uint16_t cap_mask2;
	int type, portnum;

	if (!smp_query_via(data, dest, IB_ATTR_NODE_INFO, 0, 0, srcport))
		IBEXIT("node info query failed");

	mad_decode_field(data, IB_NODE_TYPE_F, &type);
	if (type == IB_NODE_SWITCH)
		portnum = 0;
	else
		portnum = port;

	if (!smp_query_via(data, dest, IB_ATTR_PORT_INFO, portnum, 0, srcport))
		IBEXIT("port info query failed");

	mad_decode_field(data, IB_PORT_CAPMASK_F, &cap_mask);
	if (cap_mask & CL_NTOH32(IB_PORT_CAP_HAS_CAP_MASK2)) {
		mad_decode_field(data, IB_PORT_CAPMASK2_F, &cap_mask2);
		if (!(cap_mask2 &
		      CL_NTOH16(IB_PORT_CAP2_IS_PORT_INFO_EXT_SUPPORTED))) {
			IBWARN("port info capability mask2 = 0x%x doesn't"
			       " indicate PortInfoExtended support", cap_mask2);
			return 0;
		}
	} else {
		IBWARN("port info capability mask2 not supported");
		return 0;
	}

	return 1;
}

int is_mlnx_ext_port_info_supported(uint32_t vendorid,
				    uint16_t devid)
{
	if (ibd_ibnetdisc_flags & IBND_CONFIG_MLX_EPI) {

		if ((devid >= 0xc738 && devid <= 0xc73b) ||
		    devid == 0xc839 || devid == 0xcb20 || devid == 0xcf08 ||
		    devid == 0xcf09 || devid == 0xd2f0 ||
		    ((vendorid == 0x119f) &&
		     /* Bull SwitchX */
		     (devid == 0x1b02 || devid == 0x1b50 ||
		      /* Bull SwitchIB and SwitchIB2 */
		      devid == 0x1ba0 ||
		      (devid >= 0x1bd0 && devid <= 0x1bd5) ||
		      /* Bull Quantum */
		      devid == 0x1bf0)))
			return 1;
		if ((devid >= 0x1003 && devid <= 0x101b) ||
		    (devid == 0xa2d2) ||
		    ((vendorid == 0x119f) &&
		     /* Bull ConnectX3 */
		     (devid == 0x1b33 || devid == 0x1b73 ||
		      devid == 0x1b40 || devid == 0x1b41 ||
		      devid == 0x1b60 || devid == 0x1b61 ||
		      /* Bull ConnectIB */
		      devid == 0x1b83 ||
		      devid == 0x1b93 || devid == 0x1b94 ||
		      /* Bull ConnectX4, Sequana HDR and HDR100 */
		      devid == 0x1bb4 || devid == 0x1bb5 ||
		      (devid >= 0x1bc4 && devid <= 0x1bc6))))
			return 1;
	}

	return 0;
}

/** =========================================================================
 * Resolve the SM portid using the umad layer rather than using
 * ib_resolve_smlid_via which requires a PortInfo query on the local port.
 */
int resolve_sm_portid(char *ca_name, uint8_t portnum, ib_portid_t *sm_id)
{
	umad_port_t port;
	int rc;

	if (!sm_id)
		return (-1);

	if ((rc = umad_get_port(ca_name, portnum, &port)) < 0)
		return rc;

	memset(sm_id, 0, sizeof(*sm_id));
	sm_id->lid = port.sm_lid;
	sm_id->sl = port.sm_sl;

	umad_release_port(&port);

	return 0;
}

/** =========================================================================
 * Resolve local CA characteristics using the umad layer rather than using
 * ib_resolve_self_via which requires SMP queries on the local port.
 */
int resolve_self(char *ca_name, uint8_t ca_port, ib_portid_t *portid,
		 int *portnum, ibmad_gid_t *gid)
{
	umad_port_t port;
	uint64_t prefix, guid;
	int rc;

	if (!(portid || portnum || gid))
		return (-1);

	if ((rc = umad_get_port(ca_name, ca_port, &port)) < 0)
		return rc;

	if (portid) {
		memset(portid, 0, sizeof(*portid));
		portid->lid = port.base_lid;
		portid->sl = port.sm_sl;
	}
	if (portnum)
		*portnum = port.portnum;
	if (gid) {
		memset(gid, 0, sizeof(*gid));
		prefix = cl_ntoh64(port.gid_prefix);
		guid = cl_ntoh64(port.port_guid);
		mad_encode_field(*gid, IB_GID_PREFIX_F, &prefix);
		mad_encode_field(*gid, IB_GID_GUID_F, &guid);
	}

	umad_release_port(&port);

	return 0;
}

int resolve_gid(char *ca_name, uint8_t ca_port, ib_portid_t * portid,
		ibmad_gid_t gid, ib_portid_t * sm_id,
		const struct ibmad_port *srcport)
{
	ib_portid_t sm_portid;
	char buf[IB_SA_DATA_SIZE] = { 0 };

	if (!sm_id) {
		sm_id = &sm_portid;
		if (resolve_sm_portid(ca_name, ca_port, sm_id) < 0)
			return -1;
	}

	if ((portid->lid =
	     ib_path_query_via(srcport, gid, gid, sm_id, buf)) < 0)
		return -1;

	return 0;
}

int resolve_guid(char *ca_name, uint8_t ca_port, ib_portid_t *portid,
		 uint64_t *guid, ib_portid_t *sm_id,
		 const struct ibmad_port *srcport)
{
	ib_portid_t sm_portid;
	uint8_t buf[IB_SA_DATA_SIZE] = { 0 };
	uint64_t prefix;
	ibmad_gid_t selfgid;

	if (!sm_id) {
		sm_id = &sm_portid;
		if (resolve_sm_portid(ca_name, ca_port, sm_id) < 0)
			return -1;
	}

	if (resolve_self(ca_name, ca_port, NULL, NULL, &selfgid) < 0)
		return -1;

	memcpy(&prefix, selfgid, sizeof(prefix));
	prefix = cl_hton64(prefix);

	mad_set_field64(portid->gid, 0, IB_GID_PREFIX_F,
			prefix ? prefix : IB_DEFAULT_SUBN_PREFIX);
	if (guid)
		mad_set_field64(portid->gid, 0, IB_GID_GUID_F, *guid);

	if ((portid->lid =
	     ib_path_query_via(srcport, selfgid, portid->gid, sm_id, buf)) < 0)
		return -1;

	mad_decode_field(buf, IB_SA_PR_SL_F, &portid->sl);
	return 0;
}


static unsigned int get_max_width(unsigned int num)
{
	unsigned r = 0;			/* 1x */

	if (num & 8)
		r = 3;			/* 12x */
	else {
		if (num & 4)
			r = 2;		/* 8x */
		else if (num & 2)
			r = 1;		/* 4x */
		else if (num & 0x10)
			r = 4;		/* 2x */
	}

        return (1 << r);
}

static unsigned int get_max(unsigned int num)
{
	unsigned r = 0;		// r will be lg(num)

	while (num >>= 1)	// unroll for more speed...
		r++;

	return (1 << r);
}

void get_max_msg(char *width_msg, char *speed_msg, int msg_size, ibnd_port_t * port)
{
	char buf[64];
	uint32_t max_speed = 0;
	uint32_t cap_mask, rem_cap_mask, fdr10;
	uint8_t *info = NULL;

	uint32_t max_width = get_max_width(mad_get_field(port->info, 0,
						   IB_PORT_LINK_WIDTH_SUPPORTED_F)
				     & mad_get_field(port->remoteport->info, 0,
						     IB_PORT_LINK_WIDTH_SUPPORTED_F));
	if ((max_width & mad_get_field(port->info, 0,
				       IB_PORT_LINK_WIDTH_ACTIVE_F)) == 0)
		// we are not at the max supported width
		// print what we could be at.
		snprintf(width_msg, msg_size, "Could be %s",
			 mad_dump_val(IB_PORT_LINK_WIDTH_ACTIVE_F,
				      buf, 64, &max_width));

	if (port->node->type == IB_NODE_SWITCH) {
		if (port->node->ports[0])
			info = (uint8_t *)&port->node->ports[0]->info;
	}
	else
		info = (uint8_t *)&port->info;

	if (info)
		cap_mask = mad_get_field(info, 0, IB_PORT_CAPMASK_F);
	else
		cap_mask = 0;

	info = NULL;
	if (port->remoteport->node->type == IB_NODE_SWITCH) {
		if (port->remoteport->node->ports[0])
			info = (uint8_t *)&port->remoteport->node->ports[0]->info;
	} else
		info = (uint8_t *)&port->remoteport->info;

	if (info)
		rem_cap_mask = mad_get_field(info, 0, IB_PORT_CAPMASK_F);
	else
		rem_cap_mask = 0;
	if (cap_mask & CL_NTOH32(IB_PORT_CAP_HAS_EXT_SPEEDS) &&
	    rem_cap_mask & CL_NTOH32(IB_PORT_CAP_HAS_EXT_SPEEDS))
		goto check_ext_speed;
check_fdr10_supp:
	fdr10 = (mad_get_field(port->ext_info, 0,
			       IB_MLNX_EXT_PORT_LINK_SPEED_SUPPORTED_F) & FDR10)
		&& (mad_get_field(port->remoteport->ext_info, 0,
				  IB_MLNX_EXT_PORT_LINK_SPEED_SUPPORTED_F) & FDR10);
	if (fdr10)
		goto check_fdr10_active;

	max_speed = get_max(mad_get_field(port->info, 0,
					  IB_PORT_LINK_SPEED_SUPPORTED_F)
			    & mad_get_field(port->remoteport->info, 0,
					    IB_PORT_LINK_SPEED_SUPPORTED_F));
	if ((max_speed & mad_get_field(port->info, 0,
				       IB_PORT_LINK_SPEED_ACTIVE_F)) == 0)
		// we are not at the max supported speed
		// print what we could be at.
		snprintf(speed_msg, msg_size, "Could be %s",
			 mad_dump_val(IB_PORT_LINK_SPEED_ACTIVE_F,
				      buf, 64, &max_speed));
	return;

check_ext_speed:
	if (mad_get_field(port->info, 0,
			  IB_PORT_LINK_SPEED_EXT_SUPPORTED_F) == 0 ||
	    mad_get_field(port->remoteport->info, 0,
			  IB_PORT_LINK_SPEED_EXT_SUPPORTED_F) == 0)
		goto check_fdr10_supp;
	max_speed = get_max(mad_get_field(port->info, 0,
					  IB_PORT_LINK_SPEED_EXT_SUPPORTED_F)
			    & mad_get_field(port->remoteport->info, 0,
					    IB_PORT_LINK_SPEED_EXT_SUPPORTED_F));
	if ((max_speed & mad_get_field(port->info, 0,
				       IB_PORT_LINK_SPEED_EXT_ACTIVE_F)) == 0)
		// we are not at the max supported extended speed
		// print what we could be at.
		snprintf(speed_msg, msg_size, "Could be %s",
			 mad_dump_val(IB_PORT_LINK_SPEED_EXT_ACTIVE_F,
				      buf, 64, &max_speed));
	return;

check_fdr10_active:
	if ((mad_get_field(port->ext_info, 0,
			   IB_MLNX_EXT_PORT_LINK_SPEED_ACTIVE_F) & FDR10) == 0) {
		/* Special case QDR to try to avoid confusion with FDR10 */
		if (mad_get_field(port->info, 0, IB_PORT_LINK_SPEED_ACTIVE_F) == 4)	/* QDR (10.0 Gbps) */
			snprintf(speed_msg, msg_size,
				 "Could be FDR10 (Found link at QDR but expected speed is FDR10)");
		else
			snprintf(speed_msg, msg_size, "Could be FDR10");
	}
}

int vsnprint_field(char *buf, size_t n, enum MAD_FIELDS f, int spacing,
		   const char *format, va_list va_args)
{
	int len, i, ret;

	len = strlen(mad_field_name(f));
	if (len + 2 > n || spacing + 1 > n)
		return 0;

	strncpy(buf, mad_field_name(f), n);
	buf[len] = ':';
	for (i = len+1; i < spacing+1; i++) {
		buf[i] = '.';
	}

	ret = vsnprintf(&buf[spacing+1], n - spacing, format, va_args);
	if (ret >= n - spacing)
		buf[n] = '\0';

	return ret + spacing;
}

int snprint_field(char *buf, size_t n, enum MAD_FIELDS f, int spacing,
		  const char *format, ...)
{
	va_list val;
	int ret;

	va_start(val, format);
	ret = vsnprint_field(buf, n, f, spacing, format, val);
	va_end(val);

	return ret;
}

void dump_portinfo(void *pi, int tabs)
{
	int field, i;
	char val[64];
	char buf[1024];

	for (field = IB_PORT_FIRST_F; field < IB_PORT_LAST_F; field++) {
		for (i=0;i<tabs;i++)
			printf("\t");
		if (field == IB_PORT_MKEY_F && show_keys == 0) {
			snprint_field(buf, 1024, field, 32, NOT_DISPLAYED_STR);
		} else {
			mad_decode_field(pi, field, val);
			if (!mad_dump_field(field, buf, 1024, val))
				return;
		}
		printf("%s\n", buf);
	}

	for (field = IB_PORT_CAPMASK2_F;
	     field < IB_PORT_LINK_SPEED_EXT_LAST_F; field++) {
		for (i=0;i<tabs;i++)
			printf("\t");
		mad_decode_field(pi, field, val);
		if (!mad_dump_field(field, buf, 1024, val))
			return;
		printf("%s\n", buf);
	}
}

op_fn_t *match_op(const match_rec_t match_tbl[], char *name)
{
	const match_rec_t *r;
	for (r = match_tbl; r->name; r++)
		if (!strcasecmp(r->name, name) ||
		    (r->alias && !strcasecmp(r->alias, name)))
			return r->fn;
	return NULL;
}

boolean_t is_gi_supported(uint16_t device_id, uint32_t vendor_id)
{
	if(vendor_id == 0x119f){
		if(device_id == 0x1b83 || device_id == 0x1b93  || device_id == 0x1b94
		   || device_id == 0x1bb4 || device_id == 0x1bb5
		   || device_id == 0x1bc4 || device_id == 0x1bc5 || device_id == 0x1bc6
		   || device_id == 0x1bf0 || device_id == 0x1ba0
		   || (device_id >= 0x1bd0 && device_id <= 0x1bd5))
			return TRUE;
	} else if(device_id == 0x1011 || (device_id >= 0x1013 && device_id <= 0x101b)
		  || device_id == 0xcb20 || device_id == 0xcf08
		  || device_id == 0xcf09 || device_id == 0x2df0
		  || device_id == 0xa2d2)
		return TRUE;
	return FALSE;
}
