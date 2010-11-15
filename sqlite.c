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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>

#include "ya_get_nf_direct.h"

struct  sqlite_nf_ctx {
   struct sqlite3 *db;
   sqlite3_stmt *insert_stmt;
   unsigned rows_cnt;
};

#define MAX_RECORDS_IN_TRANSACTION 50000

static const char create_db_sql[] =
   "PRAGMA count_changes=OFF;"
   "PRAGMA default_synchronous=OFF;"
   "PRAGMA synchronous=OFF;"
   "PRAGMA journal_mode = OFF;"
   "CREATE TABLE traffic("
      "fw_id   INTEGER,"
      "src_addr   STRING,"
      "dst_addr   STRING,"
      "next_hop   STRING,"
      "i_ifx   INTEGER,"
      "o_ifx   INTEGER,"
      "packets   INTEGER,"
      "octets   INTEGER,"
      "first   INTEGER,"
      "last   INTEGER,"
      "s_port   INTEGER,"
      "d_port   INTEGER,"
      "flags   INTEGER,"
      "prot   INTEGER,"
      "tos   INTEGER,"
      "src_as   INTEGER,"
      "dst_as   INTEGER,"
      "src_mask   INTEGER,"
      "dst_mask   INTEGER,"
      "slink_id   INTEGER,"
      "account_id   INTEGER,"
      "account_ip   STRING,"
      "tclass   INTEGER,"
      "timestamp   INTEGER,"
      "router_ip   STRING"
      ");";

static const char insert_sql[] =
   "INSERT INTO traffic VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";

struct sqlite_nf_ctx *new_sqlite_nf(const char *fname, char *err, size_t err_msg_size)
{
   int r;
   struct sqlite_nf_ctx *res;
   char *errmsg;

   assert(fname);

   res = malloc(sizeof(*res));
   if (res == NULL) {
      if (err) snprintf(err, err_msg_size, "malloc error");
      return NULL;
   }

   res->rows_cnt = 0;

   r = sqlite3_open(fname, &res->db);
   if (r != SQLITE_OK) {
      if (err)
	    snprintf(err, err_msg_size,
		  res->db ? sqlite3_errmsg(res->db) : "malloc error");
      goto sqlite_nf_new_error;
   }

   r = sqlite3_exec(res->db, create_db_sql, NULL, NULL, &errmsg);
   if (r != SQLITE_OK) {
      if (err) snprintf(err, err_msg_size, "%s", errmsg);
      sqlite3_free(errmsg);
      goto sqlite_nf_new_error;
   }

   r = sqlite3_prepare_v2(res->db, insert_sql, -1, &res->insert_stmt, NULL);
   if (r != SQLITE_OK) {
      if (err) snprintf(err, err_msg_size, "prepare statement error: %s", sqlite3_errmsg(res->db));
      goto sqlite_nf_new_error;
   }

   r = sqlite3_exec(res->db, "BEGIN", NULL, NULL, &errmsg);
   if (r != SQLITE_OK) {
      if (err) snprintf(err, err_msg_size, "%s", errmsg);
      sqlite3_free(errmsg);
      goto sqlite_nf_new_error;
   }

   return res;

sqlite_nf_new_error:
   if (res->db)
      sqlite3_close(res->db);
   free(res);
   return NULL;
}

int insert_sqlite_nf(struct sqlite_nf_ctx *ctx, const struct record_t *rec, struct record_netaddrs_t *addrs)
{
   int rc;
   int i;
   char *errmsg;

   assert(ctx);
   assert(rec);

   if ((ctx->rows_cnt % MAX_RECORDS_IN_TRANSACTION) == 0) {
      rc = sqlite3_exec(ctx->db, "COMMIT; BEGIN;", NULL, NULL, &errmsg);
      if (rc != SQLITE_OK) {
	 fprintf(stderr, "Sqlite COMMIT failed: %s\n", errmsg);
	 sqlite3_free(errmsg);
	 return -1;
      }
   }

   i=1;
   sqlite3_bind_int64(ctx->insert_stmt, i++, (sqlite3_int64)rec->fw_id);
   sqlite3_bind_text(ctx->insert_stmt, i++, addrs->src_addr, -1, SQLITE_STATIC);
   sqlite3_bind_text(ctx->insert_stmt, i++, addrs->dst_addr, -1, SQLITE_STATIC);
   sqlite3_bind_text(ctx->insert_stmt, i++, addrs->next_hop, -1, SQLITE_STATIC);
   sqlite3_bind_int(ctx->insert_stmt, i++, (int)rec->i_ifx);
   sqlite3_bind_int(ctx->insert_stmt, i++, (int)rec->o_ifx);
   sqlite3_bind_int64(ctx->insert_stmt, i++, (sqlite3_int64)rec->packets);
   sqlite3_bind_int64(ctx->insert_stmt, i++, (sqlite3_int64)rec->octets);
   sqlite3_bind_int64(ctx->insert_stmt, i++, (sqlite3_int64)rec->first);
   sqlite3_bind_int64(ctx->insert_stmt, i++, (sqlite3_int64)rec->last);
   sqlite3_bind_int(ctx->insert_stmt, i++, (int)rec->s_port);
   sqlite3_bind_int(ctx->insert_stmt, i++, (int)rec->d_port);
   sqlite3_bind_int(ctx->insert_stmt, i++, (int)rec->flags);
   sqlite3_bind_int(ctx->insert_stmt, i++, (int)rec->prot);
   sqlite3_bind_int(ctx->insert_stmt, i++, (int)rec->tos);
   sqlite3_bind_int(ctx->insert_stmt, i++, (int)rec->src_as);
   sqlite3_bind_int(ctx->insert_stmt, i++, (int)rec->dst_as);
   sqlite3_bind_int(ctx->insert_stmt, i++, (int)rec->src_mask);
   sqlite3_bind_int(ctx->insert_stmt, i++, (int)rec->dst_mask);

   sqlite3_bind_int64(ctx->insert_stmt, i++, (sqlite3_int64)rec->slink_id);
   sqlite3_bind_int64(ctx->insert_stmt, i++, (sqlite3_int64)rec->account_id);

   sqlite3_bind_text(ctx->insert_stmt, i++, addrs->account_ip, -1, SQLITE_STATIC);

   sqlite3_bind_int64(ctx->insert_stmt, i++, (sqlite3_int64)rec->tclass);
   sqlite3_bind_int64(ctx->insert_stmt, i++, (sqlite3_int64)rec->timestamp);
   sqlite3_bind_text(ctx->insert_stmt, i++, addrs->router_ip, -1, SQLITE_STATIC);

   rc = sqlite3_step(ctx->insert_stmt);
   rc = sqlite3_reset(ctx->insert_stmt);
   if (rc != SQLITE_OK) {
      fprintf(stderr, "Sqlite INSERT failed: %s\n", sqlite3_errmsg(ctx->db));
   }
   ctx->rows_cnt++;

   return 0;
}

void close_sqlite_nf(struct sqlite_nf_ctx *ctx)
{

   assert(ctx);
   sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);

   sqlite3_finalize(ctx->insert_stmt);
   sqlite3_close(ctx->db);
   free(ctx);
}



