/*-
 * Copyright (c) 2010 Alexey Illarionov <littlesavage@rambler.ru>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdint.h>
#include <time.h>

struct record_t {
  uint32_t fw_id;       /* UTM firewall ID */
  /* Netflow v5 */
  uint32_t src_addr;    /* Source IP address */
  uint32_t dst_addr;    /* Destination IP address */
  uint32_t next_hop;    /* Next hop IP address */
  uint16_t i_ifx;       /* Source interface index */
  uint16_t o_ifx;       /* Destination interface index */
  uint32_t packets;     /* Number of packets in a flow */
  uint32_t octets;      /* Number of octets in a flow */
  uint32_t first;       /* System uptime at start of a flow */
  uint32_t last;        /* System uptime at end of a flow */
  uint16_t s_port;      /* Source port */
  uint16_t d_port;      /* Destination port */
  uint8_t pad1;         /* Pad to word boundary */
  uint8_t flags;        /* Cumulative OR of tcp flags */
  uint8_t prot;         /* IP protocol */
  uint8_t tos;          /* IP type of service */
  uint16_t src_as;      /* Src peer/origin Autonomous System */
  uint16_t dst_as;      /* Dst peer/origin Autonomous System */
  uint8_t src_mask;     /* Source route's mask bits */
  uint8_t dst_mask;     /* Destination route's mask bits */
  uint16_t pad2;        /* Pad to word boundary */
  /* */
  uint32_t slink_id;    /* UTM service link ID */
  uint32_t account_id;  /* UTM Account ID */
  uint32_t account_ip;  /* UTM User IP */
  uint32_t tclass;      /* UTM traffic class */
  uint32_t timestamp;   /* UTM timestamp */
  uint32_t router_ip;   /* UTM netflow router IP */
} __attribute__((__packed__));

struct record_netaddrs_t {
   char src_addr[INET_ADDRSTRLEN+1];
   char dst_addr[INET_ADDRSTRLEN+1];
   char next_hop[INET_ADDRSTRLEN+1];
   char router_ip[INET_ADDRSTRLEN+1];
   char account_ip[INET_ADDRSTRLEN+1];
};

struct filter_t *new_filter(const char *str, char *err, size_t err_size);
unsigned filter(struct filter_t *f, const struct record_t *rec);
void free_filter(struct filter_t *filter);


struct sqlite_nf_ctx *new_sqlite_nf(const char *fname, char *err_msg, size_t err_msg_size);
int insert_sqlite_nf(struct sqlite_nf_ctx *ctx, const struct record_t *rec, struct record_netaddrs_t *addrs);
void close_sqlite_nf(struct sqlite_nf_ctx *ctx);

time_t get_timestamp(const char *time_str);

