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

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <assert.h>
#include <archive.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ya_get_nf_direct.h"

#define DEFAULT_DB_DIR	"/netup/utm5/db/"
#define DEFAULT_DB_FILE	"/netup/utm5/db/iptraffic_raw.dbs"
#define READ_BUF_SIZE	(2*1024*1024/sizeof(struct record_t))
#define OPEN_ARCHIVE_BLOCK_SIZE  (16*1024*1024)

const char *progname = "ya_get_nf_direct";
const char *revision = "$Revision: 0.2, 05-nov-2012 $";

static volatile sig_atomic_t info;

struct opts_t {
   const char *directory;

   unsigned use_database;
   const char *database;

   unsigned use_account_id;
   unsigned account_id;

   unsigned use_src_ip;
   uint32_t src_ip;
   uint32_t src_ip_mask;

   unsigned use_dst_ip;
   uint32_t dst_ip;
   uint32_t dst_ip_mask;

   unsigned use_src_port;
   unsigned src_port;

   unsigned use_dst_port;
   unsigned dst_port;

   unsigned use_tclass;
   unsigned tclass;

   struct filter_t *extended_filter;

   struct sqlite_nf_ctx *sqlite_ctx;
   char *sqlite_db;

   unsigned long from;
   unsigned long to;

   unsigned long long limit;
   unsigned extended;

};

struct ctx_t {
   struct opts_t opts;

   unsigned done;
   unsigned long long rows_printed;
   unsigned long long rows_traversed;
   unsigned long last_traversed_timestamp;
   const char *current_file;
   struct timespec start_time;
   struct record_t buf[READ_BUF_SIZE*sizeof(struct record_t)];
};


inline static void print_rec(struct ctx_t *ctx, const struct record_t *rec);
inline static void print_stats(const struct ctx_t *ctx);
static int process_file(struct ctx_t *ctx, const char *fname);
static int process_dir(struct ctx_t *ctx, const char *dirname);
static int seek_to_timestamp(int fd, unsigned long ts);
time_t get_timestamp(const char *time_str);


void siginfo_f(int sig __attribute__((unused)))
{
   info=1;
}

static void usage(void)
{
 fprintf(stdout, "Usage: %s [-h] [options]\n"
       ,progname);
 return;
}

static void version(void)
{
 fprintf(stdout,"%s %s\n",progname,revision);
}

static void help(void)
{

 printf("%s - UTM ya_get_nf_direct module.\n%s\n",
       progname, revision);
 usage();
 printf(
   "Options:\n"
   "    -D, --directory             Directory, default: %s\n"
   "    -b, --database              Database name, (- - stdin), default: %s\n"
   "    -a, --account_id            Account ID, default: none\n"
   "    -s, --src_ip=<addr>[/mask]  Source Address, default: none\n"
   "    -d, --dst_ip=<addr>[/mask]  Destination Address, default: none\n"
   "    -p, --src_port              Source port, default: none\n"
   "    -P, --dst_port              Destination port, default: none\n"
   "    -c, --tclass                Traffic class, default: none\n"
   "    -f, --from=timestamp        From timestamp/datetime, default: 0. Format: %%Y-%%m-%%dT%%H:%%M:%%S\n"
   "    -t, --to=timestamp          To timestamp/datetime, default: current timestamp. Format: %%Y-%%m-%%dT%%H:%%M:%%S\n"
   "    -l, --limit                 Max count of rows, default: unlim\n"
   "    -e, --extended              Print stats in extended format\n"
   "    -F, --filter=<filter>       Apply extended filter\n"
   "    -S, --sqlite=<db>           Dump to Sqlite database db\n"
   "    -h, --help                  Help\n"
   "    -v, --version               Show version\n"
   "\n"
   "Extended filters:\n"
   "    Logical operators:                  ||, &&, !, ()\n"
   "    Comprarsion operators:              ==, !=, >, >=, <, <=\n"
   "    Supported expressions: \n"
   "        fw_id      [==]    addr[/mask]  Netup Firewall ID\n"
   "        src_addr   [==]    addr[/mask]  Source IP/Network\n"
   "        dst_addr   [==]    addr[/mask]  Destination IP/Network\n"
   "        next_hop   [==]    addr[/mask]  Next Hop IP/Network\n"
   "        i_ifx      [compr] num          Source interface index\n"
   "        o_ifx      [compr] num          Destination interface index\n"
   "        packets    [compr] num          Number of packets in a flow\n"
   "        octets     [compr] num          Number of octets in a flow\n"
   "        s_port     [compr] num          Source port\n"
   "        d_port     [compr] num          Destination port\n"
   "        flags      [==]    num          TCP flags\n"
   "        prot       [compr] num          IP Protocol\n"
   "        tos        [compr] num          IP TOS\n"
   "        src_as     [compr] num          Source AS\n"
   "        dst_as     [compr] num          Destination AS\n"
   "        slink_id   [compr] num          UTM service link ID\n"
   "        account_id [compr] num          UTM account ID\n"
   "        account_ip [==]    addr[/mask]  UTM accounted IP\n"
   "        tclass     [compr] num          UTM traffic class\n"
   "        timestamp  [compr] num|datetime UTM timestamp\n"
   "        router_ip  [==]    addr[/mask]  Netflow Router IP\n\n"
   "Example: '(timestamp >= 2010-01-01T12:00 && src_addr 192.168.1.0/24) || (dst_addr 192.168.2.0/24 && ! account_id 5)'\n"
   "\n",
   DEFAULT_DB_DIR,
   DEFAULT_DB_FILE
 );
 return;
}

static int dir_filter(const struct dirent *d)
{
   int cnt;
   unsigned long  timestamp;
   char iptraffic[10];
   char raw[10];
   char utm[4];

   /* iptraffic_raw_\d.utm*  */
   cnt = sscanf(d->d_name, "%[^_]_%[^_]_%lu.%[^_.]", iptraffic, raw, &timestamp, utm);

   if (cnt < 3)
      return 0;

   if (strcasecmp(iptraffic, "iptraffic") != 0)
      return 0;

   if (strcasecmp(raw, "raw") != 0)
      return 0;

   if (strcasecmp(utm, "utm") != 0)
      return 0;

   return 1;
}

static int dir_comparer(const struct dirent **d1, const struct dirent **d2)
{
   unsigned long t1, t2;

   if (!d1 || !*d1)
      return -1;

   if (!d2 || !*d2)
      return 1;

   t1 = t2 = 0;

   sscanf((*d1)->d_name, "%*[^_]_%*[^_]_%lu.%*[^_.]", &t1);
   sscanf((*d2)->d_name, "%*[^_]_%*[^_]_%lu.%*[^_.]", &t2);

   return t1 - t2;
}

static int process_dir(struct ctx_t *ctx, const char *dirname)
{
   int res;
   int i, cnt;
   struct dirent **namelist;

   res = -1;

   cnt = scandir(dirname, &namelist, dir_filter, dir_comparer);

   if (cnt < 0) {
      fprintf(stderr, "Can not open directory `%s`\n", dirname);
      return -1;
   }
   if (cnt == 0) {
      free(namelist);
      fprintf(stderr, "No database files found in `%s`\n", dirname);
      return -1;
   }

   for(i=0; i<cnt ; i++) {
      char *fname;
      unsigned long ts_from, ts_to;

      fname = NULL;

      sscanf(namelist[i]->d_name, "%*[^_]_%*[^_]_%lu.%*[^_.]", &ts_from);

      if (i + 1 >= cnt) {
	 ts_to = ULONG_MAX;
      }else {
	 sscanf(namelist[i+1]->d_name, "%*[^_]_%*[^_]_%lu.%*[^_.]", &ts_to);
      }

      if (!((ctx->opts.to >= ts_from) && (ctx->opts.from < ts_to)))
	 continue;

      fprintf(stderr, "file %s\n", namelist[i]->d_name);
      if (asprintf(&fname, "%s/%s", dirname, namelist[i]->d_name) < 0) {
	 fprintf(stderr, "asprintf() error on `%s` file\n", namelist[i]->d_name);
	 continue;
      }
      process_file(ctx, fname);
      free(fname);
      if (ctx->done) {
	 break;
      }
   }

   while(cnt--) {
      free(namelist[cnt]);
   }

   free(namelist);

   return res;
}

static int process_file(struct ctx_t *ctx, const char *fname)
{
   int res, res0;
   int error;
   int truncated;
   int limit;
   unsigned is_archive;
   ssize_t read_bytes;
   int fd;
   struct archive *archive;
   struct archive_entry *entry;
   struct record_t *buf;

   res = -1;
   buf = ctx->buf;

   {
      int len;
      len = fname ? strlen(fname) : 0;

      if ( fname
	    && (len > 5)
	    && (fname[len-4] == '.')
	    && ((fname[len-3] == 'u') || (fname[len-3] == 'U'))
	    && ((fname[len-2] == 't') || (fname[len-2] == 'T'))
	    && ((fname[len-1] == 'm') || (fname[len-1] == 'M'))) {
	 is_archive=0;
	 if (!fname) {
	    fd = fileno(stdin);
	 }else {
	    fd = open(fname, O_RDONLY);
	    if (fd < 0) {
	       fprintf(stderr, "Can not open database file `%s`: %s\n",
		     fname, strerror(errno));
	       goto read_error;
	    }
	    if (fname)
	       seek_to_timestamp(fd, ctx->opts.from);
	 }
      }else {
	 is_archive=1;
	 archive = archive_read_new();
	 if (!archive) {
	    fprintf(stderr, "archive_read_new() error");
	    goto read_error;
	 }

	 archive_read_support_format_all(archive);
	 archive_read_support_filter_all(archive);

	 archive_read_support_format_raw(archive);

	 if (!fname) {
	    res0 = archive_read_open_filename(archive, NULL, OPEN_ARCHIVE_BLOCK_SIZE);
	 }else {
	    res0 = archive_read_open_filename(archive, fname, OPEN_ARCHIVE_BLOCK_SIZE);
	 }
	 if (res0 != ARCHIVE_OK) {
	    fprintf(stderr, "Can not open database file `%s`\n", fname);
	    goto read_error;
	 }

	 res = archive_read_next_header(archive, &entry);
	 if (res != ARCHIVE_OK) {
	    fprintf(stderr, "archive_read_next_header() error: %s\n",
		  archive_error_string(archive));
	    goto read_error;
	 }
      }
   }

   ctx->current_file = fname ? fname : "stdin";

   error = truncated = limit = 0;
   read_bytes=0;
   for(;;) {
      unsigned i;
      unsigned max_i;
      ssize_t tail_bytes;

      tail_bytes = read_bytes % sizeof(struct record_t);
      if (tail_bytes) {
	 memmove(buf, buf+read_bytes-tail_bytes, tail_bytes);
      }

      if (is_archive) {
	 read_bytes = archive_read_data(archive, buf+tail_bytes,
	       READ_BUF_SIZE*sizeof(struct record_t)-tail_bytes);
      }else {
	 read_bytes = read(fd, buf+tail_bytes,
	       READ_BUF_SIZE*sizeof(struct record_t)-tail_bytes);
      }

      if (read_bytes < 0) {
	 error = 1;
	 break;
      }else if (read_bytes == 0) {
	 if (tail_bytes) {
	    truncated = 1;
	    fprintf(stderr, "read %lli bytes\n", (long long)read_bytes);
	 }
	 break;
      }

      if (info) {
	 info = 0;
	 print_stats(ctx);
      }

      max_i = (read_bytes+tail_bytes) / sizeof(struct record_t);
      for (i=0; i < max_i; i++) {
	 const struct record_t *rec;
	 rec = &buf[i];
	 /* Grep  */
	 if (ctx->opts.use_account_id) {
	    if (rec->account_id != ctx->opts.account_id)
	       continue;
	 }
	 if (ctx->opts.use_src_ip) {
	    if (ctx->opts.src_ip != (rec->src_addr & ctx->opts.src_ip_mask))
	       continue;
	 }
	 if (ctx->opts.use_dst_ip) {
	    if (ctx->opts.dst_ip != (rec->dst_addr & ctx->opts.dst_ip_mask))
	       continue;
	 }
	 if (ctx->opts.use_src_port) {
	    if (rec->s_port != ctx->opts.src_port)
	       continue;
	 }
	 if (ctx->opts.use_dst_port) {
	    if (rec->d_port != ctx->opts.dst_port)
	       continue;
	 }
	 if (ctx->opts.use_tclass) {
	    if (rec->tclass != ctx->opts.tclass)
	       continue;
	 }
	 if (rec->timestamp < ctx->opts.from)
	    continue;
	 if (rec->timestamp > ctx->opts.to) {
	    ctx->done=1;
	    limit=1;
	    ctx->rows_traversed += i;
	    ctx->last_traversed_timestamp = rec->timestamp;
	    break;
	 }

	 if (ctx->opts.extended_filter) {
	    if (!filter(ctx->opts.extended_filter, rec))
	       continue;
	 }

	 print_rec(ctx, rec);

	 if (ctx->opts.limit) {
	    if (ctx->rows_printed >= ctx->opts.limit) {
	       limit=1;
	       ctx->done=1;
	       ctx->rows_traversed += i;
	       ctx->last_traversed_timestamp = rec->timestamp;
	       break;
	    }
	 }
      }
      if (ctx->done)
	 break;
      ctx->rows_traversed += max_i;
      if (max_i > 0) {
	 ctx->last_traversed_timestamp = buf[max_i-1].timestamp;
      }
   } /* for(;;)  */

   if (error) {
      fprintf(stderr, "Read error: %s\n",
	    is_archive ? archive_error_string(archive) : strerror(errno));
      goto read_error;
   }
   if (truncated) {
      fprintf(stderr, "Truncated database file\n");
      goto read_error;
   }

   res = 0;

read_error:
   if (is_archive) {
      archive_read_free(archive);
   }else {
      if (fname && (fd > 0))
	 close(fd);
   }

   return res;
}

static int seek_to_timestamp(int fd, unsigned long timestamp)
{
   ssize_t read_bytes;
   off_t last;
   unsigned long t1, t2;
   unsigned long t1_timestamp, t2_timestamp;
   struct record_t rec;

   last = lseek(fd, 0, SEEK_SET);

   if (last < 0)
      return -1;

   /* First timestamp */
   read_bytes = read(fd, &rec, sizeof(struct record_t));
   if (read_bytes < (ssize_t)sizeof(struct record_t)) {
      lseek(fd, 0, SEEK_SET);
      return -1;
   }

   t1_timestamp = rec.timestamp;
   t1 = 0;

   if (t1_timestamp >= timestamp)
      return -1;

   /* Last timestamp */
   last = lseek(fd, 0, SEEK_END);
   if (last < 0) {
      lseek(fd, 0, SEEK_SET);
      return -1;
   }
   last = lseek(fd, last-sizeof(struct record_t), SEEK_SET);
   if (last < 0) {
      lseek(fd, 0, SEEK_SET);
      return -1;
   }

   read_bytes = read(fd, &rec, sizeof(struct record_t));
   if (read_bytes < (ssize_t)sizeof(struct record_t)) {
      lseek(fd, 0, SEEK_SET);
      return -1;
   }

   t2_timestamp = rec.timestamp;
   t2 = 1+(last / sizeof(struct record_t));

   if (t2_timestamp < t1_timestamp) {
      /* Something wrong with this database */
      lseek(fd, 0, SEEK_SET);
      return -1;
   }

   if (t2_timestamp < timestamp) {
      /* no data in this database */
      lseek(fd, 0, SEEK_END);
      return 1;
   }

   /*
   fprintf(stderr, "start: t1: %lu, t2: %lu, first ts: %lu, last ts: %lu searchfor: %lu.\n",
	 t1, t2, t1_timestamp, t2_timestamp, timestamp);
	 */
   for(;abs(t1-t2) > 1;) {
      unsigned long tmp;

      tmp = t1 + ((t2-t1)/2 + ((t2-t1)%2));
      last = lseek(fd, tmp*sizeof(struct record_t), SEEK_SET);
      if (last < 0) {
	 lseek(fd, 0, SEEK_SET);
	 return -1;
      }
      read_bytes = read(fd, &rec, sizeof(struct record_t));
      if (read_bytes < (ssize_t)sizeof(struct record_t)) {
	 lseek(fd, 0, SEEK_SET);
	 return -1;
      }
      if (rec.timestamp >= timestamp) {
	 t2 = tmp;
	 t2_timestamp = rec.timestamp;
      }else {
	 t1 = tmp;
	 t1_timestamp = rec.timestamp;
      }
      /*
      fprintf(stderr, "t1: %lu, t2: %lu seekto: %lu, first ts: %lu, "
	 "last ts: %lu.\n", t1, t2, tmp, t1_timestamp, t2_timestamp);
      */
      if ((t2 < t1)
	    || (t2_timestamp < t1_timestamp)) {
	 fprintf(stderr, "Wrong timestamp in DB. t1: %lu, t2: %lu, "
	       "t1_timestamp: %lu, t2_timestamp: %lu.\n",
	       t1, t2, t1_timestamp, t2_timestamp);
	 lseek(fd, 0, SEEK_SET);
	 return -1;
      }
   }

   return 1;
}

time_t get_timestamp(const char *time_str)
{
   struct tm *tm;
   unsigned long long_tmp;
   char *endptr;
   time_t tt;

   if (!time_str || (time_str[0] == '\0'))
      return (time_t)-1;

   long_tmp = strtoul(optarg,&endptr, 10);

   if (endptr == time_str) {
      return (time_t)-1;
   }

   if (endptr[0] == '\0') {
      return (time_t)long_tmp;
   }

   time(&tt);
   tm = localtime(&tt);
   tm->tm_sec = 0;
   tm->tm_min = 0;
   tm->tm_hour = 0;
   endptr= strptime(time_str, "%F", tm);
   if (endptr == NULL)
      return (time_t)-1;

   if (endptr[0] == 'T') {
      const char *hhmmss = endptr;
      endptr = strptime(hhmmss, "T%T", tm);
      if (!endptr || (endptr[0] != '\0')) {
	 endptr = strptime(hhmmss, "T%R", tm);
	 if (!endptr || (endptr[0] != '\0')) {
	    return (time_t)-1;
	 }
      }
   }

   return mktime(tm);
}

inline static void print_rec(struct ctx_t *ctx, const struct record_t *rec)
{
   struct in_addr tmp_addr;
   FILE *stream = stdout;
   static struct record_netaddrs_t addrs;
   static uint32_t src_addr1;
   static uint32_t dst_addr1;
   static uint32_t next_hop1;
   static uint32_t router_ip1;
   static uint32_t account_ip1;

   static char timestamp[26+1];
   static time_t timestamp_int;

   /* src_addr  */
   if (src_addr1 == 0 || (rec->src_addr != src_addr1)) {
      src_addr1 = rec->src_addr;
      tmp_addr.s_addr = htonl(src_addr1);
      inet_ntop(AF_INET, &tmp_addr, addrs.src_addr, sizeof(addrs.src_addr));
   }

   /* dst_addr  */
   if (dst_addr1 == 0 || (rec->dst_addr != dst_addr1)) {
      dst_addr1 = rec->dst_addr;
      tmp_addr.s_addr = htonl(dst_addr1);
      inet_ntop(AF_INET, &tmp_addr, addrs.dst_addr, sizeof(addrs.dst_addr));
   }

   /* timestamp  */
   if (timestamp_int == 0 || (timestamp_int != (time_t)rec->timestamp)) {
      timestamp_int = rec->timestamp;
      ctime_r(&timestamp_int, timestamp);
   }

   if (ctx->opts.extended || ctx->opts.sqlite_db) {
      /* next_hop  */
      if (next_hop1 == 0 || (rec->next_hop != next_hop1)) {
	 next_hop1 = rec->next_hop;
	 tmp_addr.s_addr = htonl(next_hop1);
	 inet_ntop(AF_INET, &tmp_addr, addrs.next_hop, sizeof(addrs.next_hop));
      }

      /* router-ip  */
      if (router_ip1 == 0 || (rec->router_ip != router_ip1)) {
	 router_ip1 = rec->router_ip;
	 tmp_addr.s_addr = htonl(router_ip1);
	 inet_ntop(AF_INET, &tmp_addr, addrs.router_ip, sizeof(addrs.router_ip));
      }

      if (ctx->opts.sqlite_db) {
	 /* account-ip  */
	 if (account_ip1 ==0 || (rec->account_ip != account_ip1)) {
	    account_ip1 = rec->account_ip;
	    tmp_addr.s_addr = htonl(account_ip1);
	    inet_ntop(AF_INET, &tmp_addr, addrs.account_ip, sizeof(addrs.account_ip));
	 }
	 insert_sqlite_nf(ctx->opts.sqlite_ctx, rec, &addrs);
      }
   }

   if (ctx->rows_printed == 0) {
      /* Print header */
      if (ctx->opts.extended)
	 fprintf(stream, "timestamp account_id source destination t_class packets bytes sport "
	       "dport nexthop iface oface tcp_flags proto tos src_as dst_as src_mask"
	       "dst_mask router_ip_from date\n"
	       );
      else
	 fprintf(stream, "timestamp account_id source destination t_class packets bytes sport dport date\n");
   }

   if (ctx->opts.extended) {
      /*  timestamp account_id source destination t_class packets bytes sport
       *  dport nexthop iface oface tcp_flags proto tos src_as dst_as src_mask
       *  dst_mask router_ip_from date */
      fprintf(stream,
	    "%u %u %s %s %u %u %u %hu %hu %s %hu %hu %hhu %hhu %hhu %hu %hu %hhu %hhu %s %s",
	    rec->timestamp,
	    rec->account_id,
	    addrs.src_addr,
	    addrs.dst_addr,
	    rec->tclass,
	    rec->packets,
	    rec->octets,
	    rec->s_port,
	    rec->d_port,
	    addrs.next_hop,
	    rec->i_ifx,
	    rec->o_ifx,
	    rec->flags,
	    rec->prot,
	    rec->tos,
	    rec->src_as,
	    rec->dst_as,
	    rec->src_mask,
	    rec->dst_mask,
	    addrs.router_ip,
	    timestamp);
   }else {
      /* timestamp account_id source destination t_class packets bytes sport
       * dport date  */
      fprintf(stream, "%u %u %s %s %u %u %u %hu %hu %s",
	    rec->timestamp,
	    rec->account_id,
	    addrs.src_addr,
	    addrs.dst_addr,
	    rec->tclass,
	    rec->packets,
	    rec->octets,
	    rec->s_port,
	    rec->d_port,
	    timestamp);
   }
   ctx->rows_printed++;
}

inline static void print_stats(const struct ctx_t *ctx)
{
   struct timespec tp;
   double speed_kbps;
   double tdiff;

   clock_gettime(CLOCK_MONOTONIC, &tp);

   tdiff = (tp.tv_sec + 0.000000001*tp.tv_nsec)-
      (ctx->start_time.tv_sec + 0.000000001*ctx->start_time.tv_nsec);

   if (tdiff <= 0) {
      speed_kbps=0;
   }else {
      speed_kbps = ctx->rows_traversed*sizeof(struct record_t)/(1024.0*1024.0*tdiff);
   }

   fprintf(stderr,
	 "records:%llu printed:%llu last_ts:%lu speed:%.3fMiB/s file:%s\n",
	 ctx->rows_traversed,
	 ctx->rows_printed,
	 ctx->last_traversed_timestamp,
	 speed_kbps,
	 ctx->current_file
	 );
}

int main(int argc, char *argv[])
{
   signed char c;
   struct ctx_t *ctx;
   time_t tmp_timestamp;
   char err_str[200];

   static struct option longopts[] = {
      {"version",     no_argument,        0, 'v'},
      {"help",        no_argument,       0, 'h'},
      {"directory",   required_argument, 0, 'D'},
      {"database",    required_argument, 0, 'b'},
      {"account_id",  required_argument, 0, 'a'},
      {"src_ip",      required_argument, 0, 's'},
      {"dst_ip",      required_argument, 0, 'd'},
      {"src_port",    required_argument, 0, 'p'},
      {"dst_port",    required_argument, 0, 'P'},
      {"tclass",      required_argument, 0, 'c'},
      {"from",        required_argument, 0, 'f'},
      {"to",          required_argument, 0, 't'},
      {"limit",       required_argument, 0, 'l'},
      {"extended",    required_argument, 0, 'e'},
      {"filter",      required_argument, 0, 'F'},
      {"sqlite",      required_argument, 0, 'S'},
      {0, 0, 0, 0}
   };

   ctx = malloc(sizeof(*ctx));

   if (ctx == NULL) {
      perror(NULL);
      return 1;
   }

   ctx->opts.use_database
      = ctx->opts.use_account_id
      = ctx->opts.use_src_ip
      = ctx->opts.use_dst_ip
      = ctx->opts.use_src_port
      = ctx->opts.use_dst_port
      = ctx->opts.use_tclass
      = ctx->opts.extended
      = 0;

   ctx->opts.limit = 0;
   ctx->opts.from = 0;
   time(&tmp_timestamp);
   ctx->opts.to = (unsigned long)tmp_timestamp;
   ctx->opts.directory = NULL;
   ctx->opts.extended_filter = NULL;
   ctx->opts.sqlite_ctx = NULL;
   ctx->opts.sqlite_db = NULL;

   while ((c = getopt_long(argc, argv, "vh?D:b:a:s:d:p:P:c:f:F:t:l:S:e",longopts,NULL)) != -1) {
      int tmp;
      struct in_addr tmp_ip;

      switch (c) {
	 case 'D':
	    ctx->opts.directory = strdup(optarg);
	    if (ctx->opts.directory == NULL) {
	       perror(NULL);
	       goto main_error;
	    }
	    break;
	 case 'F':
	    ctx->opts.extended_filter = new_filter(optarg, err_str, sizeof(err_str));
	    if (ctx->opts.extended_filter == NULL) {
	       fprintf(stderr, "%s\n", err_str);
	       goto main_error;
	    }
	    break;
	 case 'S':
	    ctx->opts.sqlite_db = strdup(optarg);
	    if (ctx->opts.sqlite_db == NULL) {
	       perror(NULL);
	       goto main_error;
	    }
	    ctx->opts.sqlite_ctx = new_sqlite_nf(ctx->opts.sqlite_db, err_str, sizeof(err_str));
	    if (ctx->opts.sqlite_ctx == NULL) {
	       fprintf(stderr, "%s\n", err_str);
	       goto main_error;
	    }
	    break;
	 case 'b':
	    ctx->opts.use_database = 1;
	    ctx->opts.database = strdup(optarg);
	    if (ctx->opts.database == NULL) {
	       perror(NULL);
	       goto main_error;
	    }
	    break;
	 case 'a':
	    ctx->opts.use_account_id = 1;
	    ctx->opts.account_id = strtoul(optarg,(char **)NULL, 10);
	    break;
	 case 's':
	    ctx->opts.use_src_ip = 1;
	    tmp = inet_net_pton(AF_INET, optarg, &tmp_ip,
		  sizeof(tmp_ip));
	    if (tmp < 0) {
	       fprintf(stderr, "Wrong source IP\n");
	       goto main_error;
	    }else {
	       if (tmp) {
		  ctx->opts.src_ip_mask = (uint32_t)(0 - (1 << (32-tmp)));
	       }else {
		  ctx->opts.src_ip_mask = 0;
	       }
	       ctx->opts.src_ip = ntohl(tmp_ip.s_addr) & ctx->opts.src_ip_mask;
	    }
	    break;
	 case 'd':
	    ctx->opts.use_dst_ip = 1;
	    tmp = inet_net_pton(AF_INET, optarg, &tmp_ip,
		  sizeof(tmp_ip));
	    if (tmp < 0) {
	       fprintf(stderr, "Wrong destination IP\n");
	       goto main_error;
	    }else {
	       if (tmp) {
		  ctx->opts.dst_ip_mask = (uint32_t)(0 - (1 << (32-tmp)));
	       }else {
		  ctx->opts.dst_ip_mask = 0;
	       }
	       ctx->opts.dst_ip = ntohl(tmp_ip.s_addr) & ctx->opts.dst_ip_mask;
	    }
	    break;
	 case 'p':
	    ctx->opts.use_src_port = 1;
	    ctx->opts.src_port = strtoul(optarg,(char **)NULL, 10);
	    if (ctx->opts.src_port > 0xffff) {
	       fprintf(stderr, "Wrong source port `%s`\n", optarg);
	       goto main_error;
	    }
	    break;
	 case 'P':
	    ctx->opts.use_dst_port = 1;
	    ctx->opts.dst_port = strtoul(optarg,(char **)NULL, 10);
	    if (ctx->opts.dst_port > 0xffff) {
	       fprintf(stderr, "Wrong destination port `%s`\n", optarg);
	       goto main_error;
	    }
	    break;
	 case 'c':
	    ctx->opts.use_tclass = 1;
	    ctx->opts.tclass = strtoul(optarg,(char **)NULL, 10);
	    break;
	 case 'f':
	    tmp_timestamp = get_timestamp(optarg);
	    if (tmp_timestamp < 0) {
	       fprintf(stderr, "Wrong %s timestamp/datetime `%s`. Required format: %%Y-%%m-%%dT%%H:%%M:%%S. \n", "start", optarg);
	       goto main_error;
	    }

	    ctx->opts.from = (unsigned long)tmp_timestamp;
	    break;
	 case 't':
	    tmp_timestamp = get_timestamp(optarg);
	    if (tmp_timestamp < 0) {
	       fprintf(stderr, "Wrong %s timestamp/datetime `%s`\n. Required format: %%Y-%%m-%%dT%%H:%%M:%%S.", "end", optarg);
	       goto main_error;
	    }

	    ctx->opts.to = (unsigned long)tmp_timestamp;
	    break;
	 case 'l':
	    ctx->opts.limit = strtoull(optarg,(char **)NULL, 10);
	    break;
	 case 'e':
	    ctx->opts.extended=1;
	    break;
	 case 'v':
	    version();
	    free(ctx);
	    exit(0);
	    break;
	 default:
	    help();
	    free(ctx);
	    exit(0);
	    break;
      }
   }
   argc -= optind;
   argv += optind;

   if (ctx->opts.from > ctx->opts.to) {
      fprintf(stderr, "Start timestamp greater then end timestamp.");
      goto main_error;
   }else {
      fprintf(stderr, "Time period (timestamps): %lu - %lu\n",
	    (unsigned long)ctx->opts.from,
	    (unsigned long)ctx->opts.to
	    );
   }

   ctx->done=0;
   ctx->rows_printed=0;
   ctx->rows_traversed=0;
   ctx->current_file = "no";
   ctx->last_traversed_timestamp=0;
   clock_gettime(CLOCK_MONOTONIC, &ctx->start_time);

#ifdef SIGINFO
   signal(SIGINFO, siginfo_f);
#endif
   signal(SIGUSR1, siginfo_f);

   if (ctx->opts.use_database) {
      assert(ctx->opts.database != NULL);
      process_file(ctx,
	    (ctx->opts.database[0]=='-') && (ctx->opts.database[1]=='\0') ? NULL : ctx->opts.database);
   }else {
      process_dir(ctx,
	    ctx->opts.directory ? ctx->opts.directory : DEFAULT_DB_DIR
	    );
   }

   free_filter(ctx->opts.extended_filter);
   if (ctx->opts.sqlite_ctx)
      close_sqlite_nf(ctx->opts.sqlite_ctx);
   free(ctx->opts.sqlite_db);
   free(ctx);
   return 0;

main_error:
   free_filter(ctx->opts.extended_filter);
   if (ctx->opts.sqlite_ctx)
      close_sqlite_nf(ctx->opts.sqlite_ctx);
   free(ctx->opts.sqlite_db);
   free(ctx);
   return 1;

}


