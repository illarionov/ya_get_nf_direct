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

%{
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>
#include <netinet/in.h>

#include "ya_get_nf_direct.h"

enum token_t {
   TOKEN_END=0,

   OP_EQ,
   OP_NE,
   OP_GT,
   OP_GE,
   OP_LT,
   OP_LE,
   LEFT_BRACE,
   RIGHT_BRACE,
   OP_AND,
   OP_OR,
   OP_NOT,

   FW_ID,
   SRC_ADDR,
   DST_ADDR,
   NEXT_HOP,
   I_IFX,
   O_IFX,
   PACKETS,
   OCTETS,
   S_PORT,
   D_PORT,
   FLAGS,
   PROTO,
   TOS,
   SRC_AS,
   DST_AS,
   SLINK_ID,
   ACCOUNT_ID,
   ACCOUNT_IP,
   TCLASS,
   TIMESTAMP,
   ROUTER_IP,

   NUMBER,
   NETADDR,
   DATETIME,
   UNKNOWN
};

struct filter_elm_t {
   enum token_t operator;
   struct filter_elm_t *next;
   struct {
      enum token_t field;
      union {
	 uint32_t u32;
	 uint16_t u16;
	 uint8_t  u8;
	 struct {
	    uint32_t ip;
	    uint32_t mask;
	 }addr;
      } arg;
   } expr;
};

struct filter_t {
   struct filter_elm_t *head;
   struct filter_elm_t *tail;
   unsigned max_stack_size;
   unsigned *stack;
};

%}

%option noyywrap
%option nounput

%%

fw_id	   return FW_ID;
src_addr   return SRC_ADDR;
dst_addr   return DST_ADDR;
next_hop   return NEXT_HOP;
i_ifx      return I_IFX;
o_ifx      return O_IFX;
packets    return PACKETS;
octets     return OCTETS;
s_port     return S_PORT;
d_port     return D_PORT;
flags      return FLAGS;
proto      return PROTO;
tos        return TOS;
src_as     return SRC_AS;
dst_as     return DST_AS;
slink_id   return SLINK_ID;
account_id return ACCOUNT_ID;
account_ip return ACCOUNT_IP;
tclass     return TCLASS;
timestamp  return TIMESTAMP;
router_ip  return ROUTER_IP;

"=="          return OP_EQ;
"!="         return OP_NE;
">"          return OP_GT;
">="         return OP_GE;
"<"          return OP_LT;
"<="         return OP_LE;
"("          return LEFT_BRACE;
")"          return RIGHT_BRACE;
"&&"          return OP_AND;
"||"           return OP_OR;
"!"          return OP_NOT;

[0-9]+       return NUMBER;

[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(\/[0-9]{1,2})?  return NETADDR;

[ \t\n]+      ;
[^ \t\n()=!<>]+     return UNKNOWN;

.		  return UNKNOWN;

%%

static struct filter_elm_t *add_elm_to_filter(struct filter_t *f, enum token_t operator);
static struct filter_elm_t *push_elm(struct filter_elm_t **s, enum token_t operator);
static void print_filter(struct filter_t *f);

struct filter_t *new_filter(const char *str, char *err, size_t err_size)
{
   enum token_t t;
   unsigned state;
   struct filter_t *filter;
   struct filter_elm_t *elm;
   struct filter_elm_t *s;

   assert(str);
   yy_scan_string(str);

   filter = malloc(sizeof(*filter));
   filter->head = filter->tail = NULL;
   filter->max_stack_size = 0;
   filter->stack = NULL;
   s = NULL;
   elm = NULL;

   state=0;
   for(;(t=yylex()) != 0;) {
      /* /printf("token: %u, text: %s\n", t, yytext); */
      switch (state) {
	    case 0: /* wait for field */
	       switch (t) {
		  case OP_EQ:
		  case OP_NE:
		  case OP_GT:
		  case OP_GE:
		  case OP_LT:
		  case OP_LE:
		  case NUMBER:
		  case NETADDR:
		  case DATETIME:
		  case UNKNOWN:
		     if (err)
			snprintf(err, err_size, "Unknown token `%s`", yytext);
		     goto new_filter_error;
		     break;
		  case RIGHT_BRACE:
		     elm = NULL;
		     while (s) {
			elm = s;
			s = s->next;
			if (elm->operator == LEFT_BRACE)
			   break;
			elm->next = NULL;
			if (filter->tail) {
			   filter->tail = filter->tail->next = elm;
			}else
			   filter->tail = filter->head = elm;
		     }
		     if (elm == NULL) {
			if (err) snprintf(err, err_size, "Unexpected `)`");
			goto new_filter_error;
		     }else
			free(elm);
		     break;
		  case LEFT_BRACE:
		  case OP_OR:
		  case OP_AND:
		  case OP_NOT:
		     while(s) {
			if (t == LEFT_BRACE)
			   break;
			if (s->operator == LEFT_BRACE)
			   break;
			if ((t == OP_AND) && (s->operator == OP_OR))
			   break;
			if ((t == OP_NOT) && (
				 (s->operator == OP_OR)
				 || (s->operator == OP_NOT)
				 || (s->operator == OP_AND))
			   )
			   break;

			elm = s;
			s = s->next;
			elm->next = NULL;
			if (filter->tail)
			   filter->tail = filter->tail->next = elm;
			else
			   filter->tail = filter->head = elm;
		     }
		     if (push_elm(&s, t) == NULL) {
			if (err) snprintf(err, err_size, "Can not create filter element");
			goto new_filter_error;
		     }
		     break;
		  default:
		     /* field  */
		     elm = add_elm_to_filter(filter, UNKNOWN);
		     if (!elm) {
			if (err)
			   snprintf(err, err_size, "Can not create filter element");
			goto new_filter_error;
		     }
		     elm->expr.field = t;
		     state = 1;
		  break;
	       }
	       break;
	    case 1:
	       assert(filter->tail);
	       assert(filter->tail->expr.field != OP_AND);
	       assert(filter->tail->expr.field != OP_OR);
	       assert(filter->tail->expr.field != OP_NOT);
	       assert(filter->tail->expr.field != LEFT_BRACE);
	       assert(filter->tail->expr.field != RIGHT_BRACE);

	       switch (t) {
		  case OP_EQ:
		  case OP_NE:
		  case OP_GT:
		  case OP_GE:
		  case OP_LT:
		  case OP_LE:
		     if (filter->tail->operator != UNKNOWN) {
			if (err)
			   snprintf(err, err_size, "Wrong token `%s`", yytext);
			goto new_filter_error;
		     }
		     filter->tail->operator = t;
		     break;
		  case NUMBER:
		  case NETADDR:
		  case DATETIME:
		  case UNKNOWN:
		     if (filter->tail->operator == UNKNOWN)
			filter->tail->operator = OP_EQ;
		     state = 0;
		     switch (filter->tail->expr.field) {
			case SRC_ADDR:
			case ACCOUNT_IP:
			case DST_ADDR:
			case NEXT_HOP:
			case ROUTER_IP:
			   if (t != NETADDR) {
			      if (err)
				 snprintf(err, err_size, "Not IP: `%s`", yytext);
			      goto new_filter_error;
			   }
			   if (filter->tail->operator != OP_EQ) {
			      if (err)
				 snprintf(err, err_size, "Wrong operator for `%s`", yytext);
			      goto new_filter_error;
			   }else {
			      int tmp;
			      struct in_addr tmp_ip;

			      tmp = inet_net_pton(AF_INET, yytext, &tmp_ip,
				    sizeof(tmp_ip));
			      if (tmp < 0) {
				 if (err) snprintf(err, err_size, "Not IP: `%s`", yytext);
				 goto new_filter_error;
			      }else {
				 if (tmp)
				    filter->tail->expr.arg.addr.mask = (uint32_t)(0 - (1 << (32-tmp)));
				 else
				    filter->tail->expr.arg.addr.mask = 0;
				 filter->tail->expr.arg.addr.ip = ntohl(tmp_ip.s_addr) & filter->tail->expr.arg.addr.mask;
			      }
			   }
			   break;
			case I_IFX:
			case O_IFX:
			case S_PORT:
			case D_PORT:
			case SRC_AS:
			case DST_AS:
			   if (t != NUMBER) {
			      if (err) snprintf(err, err_size, "Not a number: `%s`", yytext);
			      goto new_filter_error;
			   }else{
			      unsigned long tmp;
			      tmp = strtoul(yytext,(char **)NULL, 10);
			      if (tmp > 0xffff) {
				 if (err) snprintf(err, err_size, "Wrong value: `%s`", yytext);
				 goto new_filter_error;
			      }
			      filter->tail->expr.arg.u16 = (uint16_t) tmp;
			   }
			   break;

			case FLAGS:
			case TOS:
			case PROTO:
			   if (t != NUMBER) {
			      if (err)
				 snprintf(err, err_size, "Not a number: `%s`", yytext);
			      goto new_filter_error;
			   }else {
			      unsigned long tmp;
			      tmp = strtoul(yytext,(char **)NULL, 10);
			      if (tmp > 0xff) {
				 if (err) snprintf(err, err_size, "Wrong number: `%s`", yytext);
				 goto new_filter_error;
			      }
			      filter->tail->expr.arg.u8 = (uint8_t) tmp;
			   }
			   break;

			case FW_ID:
			case PACKETS:
			case OCTETS:
			case SLINK_ID:
			case ACCOUNT_ID:
			case TCLASS:
			   if (t != NUMBER) {
			      if (err)
				 snprintf(err, err_size, "Not a number: `%s`", yytext);
			      goto new_filter_error;
			   }else {
			      unsigned long tmp;
			      tmp = strtoul(yytext,(char **)NULL, 10);
			      if (tmp > 0xffffffff) {
				 if (err) snprintf(err, err_size, "Wrong number: `%s`", yytext);
				 goto new_filter_error;
			      }
			      filter->tail->expr.arg.u32 = (uint32_t) tmp;
			   }
			   break;

			case TIMESTAMP:
			   {
			      time_t tmp;

			      tmp = get_timestamp(yytext);
			      if (tmp < 0) {
				 if (err)
				    snprintf(err, err_size, "Wrong timestamp: `%s`", yytext);
				 goto new_filter_error;
			      }
			      filter->tail->expr.arg.u32 = (uint32_t)tmp;
			   }
			   break;
			default:
			   if (err)
			      snprintf(err, err_size, "Wrong argument `%s`", yytext);
			   goto new_filter_error;
			   break;
		     } /* switch (filter->tail->expr.field) */
		     break;
		  default:
		     if (err)
			snprintf(err, err_size, "Wrong token `%s`", yytext);
		     goto new_filter_error;
		     break;
	       } /* switch(t)  */
	       break;
	    default:
	       /* UNREACHABALE  */
	       assert(0);
	       break;
      }
   }


   while (s) {
      if (s->operator == LEFT_BRACE) {
	 if (err) snprintf(err, err_size, "Unexpected `(`");
	 goto new_filter_error;
      }
      elm = s;
      s = s->next;
      elm->next = NULL;
      if (filter->tail)
	 filter->tail = filter->tail->next = elm;
      else
	 filter->tail = filter->head = elm;
   }

   {
      /*  Check filter */
      unsigned s_size, max_s_size;

      s_size = max_s_size=0;
      for (elm=filter->head; elm; elm=elm->next) {
	 switch (elm->operator){
	    case OP_AND:
	    case OP_OR:
	       if (s_size < 2) {
		  if (err) snprintf(err, err_size, "wrong expression");
		  goto new_filter_error;
	       }else {
		  struct filter_elm_t *tmp;
		  s_size--;
		  tmp = s;
		  s = s->next;
		  free(tmp);
	       }
	       break;
	    case OP_NOT:
	       if (s_size < 1) {
		  if (err) snprintf(err, err_size, "wrong expression");
		  goto new_filter_error;
	       }
	       break;
	    default:
	       if (push_elm(&s, elm->operator) == NULL) {
		  if (err) snprintf(err, err_size, "Can not create filter element");
		  goto new_filter_error;
	       }
	       s_size += 1;
	       max_s_size = max_s_size >= s_size ? max_s_size : s_size;
	       break;
	 }
      }
      if (s_size != 1) {
	 if (err) snprintf(err, err_size,
	       "Wrong expression: too many arguments: %u", s_size);
	 goto new_filter_error;
      }
      free(s);
      s = NULL;

      filter->max_stack_size = max_s_size+1;
      filter->stack = malloc(sizeof(filter->stack[0])*filter->max_stack_size);
      if (filter->stack == NULL) {
	 if (err) snprintf(err, err_size,
	       "Wrong expression: too many arguments: %u", s_size);
	 goto new_filter_error;
      }
   }

   yy_delete_buffer(YY_CURRENT_BUFFER);
   print_filter(filter);
   return filter;

new_filter_error:
   while(s) {
      elm = s;
      s = s->next;
      free(s);
   }

   print_filter(filter);
   free_filter(filter);
   yy_delete_buffer(YY_CURRENT_BUFFER);
   return NULL;
}


static struct filter_elm_t *add_elm_to_filter(struct filter_t *f, enum token_t operator)
{
   struct filter_elm_t *elm;

   assert(f);

   elm = malloc(sizeof(*elm));
   if (elm == NULL)
      return NULL;

   elm->operator = operator;
   elm->next = NULL;

   elm->expr.field = 0;

   if (f->head == NULL) {
      assert(f->tail == NULL);
      f->head = f->tail = elm;
   }else {
      assert(f->tail);
      f->tail->next = elm;
      f->tail = elm;
   }

   return elm;
}

static struct filter_elm_t *push_elm(struct filter_elm_t **s, enum token_t operator)
{
   struct filter_elm_t *elm;
   elm = malloc(sizeof(*elm));
   if (elm == NULL)
      return NULL;
   elm->operator = operator;
   elm->next = *s;
   *s = elm;
   return elm;
}

void free_filter(struct filter_t *f)
{
   struct filter_elm_t *t;

   if (f == NULL)
      return;
   for(;f->head != NULL;) {
      t = f->head;
      f->head = t->next;
      free(t);
   }
   free(f->stack);
   free(f);
}

static inline unsigned eval_u32_expr(const struct filter_elm_t *elm, uint32_t val)
{
   switch(elm->operator) {
      case OP_EQ: return (val == elm->expr.arg.u32); break;
      case OP_NE: return (val != elm->expr.arg.u32); break;
      case OP_GT: return (val > elm->expr.arg.u32); break;
      case OP_GE: return (val >= elm->expr.arg.u32); break;
      case OP_LT: return (val < elm->expr.arg.u32); break;
      case OP_LE: return (val <= elm->expr.arg.u32); break;
      default: assert(0); break;
   }
   return 0;
}

static inline unsigned eval_u16_expr(const struct filter_elm_t *elm, uint16_t val)
{
   switch(elm->operator) {
      case OP_EQ: return (val == elm->expr.arg.u16); break;
      case OP_NE: return (val != elm->expr.arg.u16); break;
      case OP_GT: return (val > elm->expr.arg.u16); break;
      case OP_GE: return (val >= elm->expr.arg.u16); break;
      case OP_LT: return (val < elm->expr.arg.u16); break;
      case OP_LE: return (val <= elm->expr.arg.u16); break;
      default: assert(0); break;
   }
   return 0;
}

static inline unsigned eval_u8_expr(const struct filter_elm_t *elm, uint8_t val)
{
   switch(elm->operator) {
      case OP_EQ: return (val == elm->expr.arg.u8); break;
      case OP_NE: return (val != elm->expr.arg.u8); break;
      case OP_GT: return (val > elm->expr.arg.u8); break;
      case OP_GE: return (val >= elm->expr.arg.u8); break;
      case OP_LT: return (val < elm->expr.arg.u8); break;
      case OP_LE: return (val <= elm->expr.arg.u8); break;
      default: assert(0); break;
   }
   return 0;
}

static inline unsigned eval_expr(const struct filter_elm_t *elm, const struct record_t *rec)
{

   switch(elm->expr.field) {
      case SRC_ADDR:
	 assert(elm->operator == OP_EQ);
	 return (elm->expr.arg.addr.ip == (rec->src_addr & elm->expr.arg.addr.mask));
	 break;
      case DST_ADDR:
	 assert(elm->operator == OP_EQ);
	 return (elm->expr.arg.addr.ip == (rec->dst_addr & elm->expr.arg.addr.mask));
	 break;
      case NEXT_HOP:
	 assert(elm->operator == OP_EQ);
	 return (elm->expr.arg.addr.ip == (rec->next_hop & elm->expr.arg.addr.mask));
	 break;
      case ACCOUNT_IP:
	 assert(elm->operator == OP_EQ);
	 return (elm->expr.arg.addr.ip == (rec->account_ip & elm->expr.arg.addr.mask));
	 break;

      case ROUTER_IP:
	 assert(elm->operator == OP_EQ);
	 return (elm->expr.arg.addr.ip == (rec->router_ip & elm->expr.arg.addr.mask));
	 break;

      case I_IFX:  return eval_u16_expr(elm, rec->i_ifx); break;
      case O_IFX:  return eval_u16_expr(elm, rec->o_ifx); break;
      case S_PORT: return eval_u16_expr(elm, rec->s_port); break;
      case D_PORT: return eval_u16_expr(elm, rec->d_port); break;
      case SRC_AS: return eval_u16_expr(elm, rec->src_as); break;
      case DST_AS: return eval_u16_expr(elm, rec->dst_as); break;

      case FLAGS: return eval_u8_expr(elm, rec->flags); break;
      case PROTO: return eval_u8_expr(elm, rec->prot); break;
      case TOS:   return eval_u8_expr(elm, rec->tos); break;

      case FW_ID:      return eval_u32_expr(elm, rec->fw_id); break;
      case PACKETS:    return eval_u32_expr(elm, rec->packets); break;
      case OCTETS:     return eval_u32_expr(elm, rec->octets); break;
      case SLINK_ID:   return eval_u32_expr(elm, rec->slink_id); break;
      case ACCOUNT_ID: return eval_u32_expr(elm, rec->account_id); break;
      case TCLASS:     return eval_u32_expr(elm, rec->tclass); break;
      case TIMESTAMP:  return eval_u32_expr(elm, rec->timestamp); break;
      default:
	 /* UNREACHABLE */
	 assert(0);
	 break;
   }

   return 0;
}

unsigned filter(struct filter_t *f, const struct record_t *rec)
{
   unsigned s_p;
   struct filter_elm_t *elm;
   unsigned *s;

   assert(f);
   assert(rec);

   s_p=0;
   s = f->stack;
   s[s_p]=0;

   for (elm=f->head; elm; elm=elm->next) {
      switch(elm->operator) {
	 case OP_AND:
	    assert(s_p>=2);
	    s[s_p-2]=s[s_p-1] && s[s_p-2];
	    s_p--;
	    break;
	 case OP_OR:
	    assert(s_p>=2);
	    s[s_p-2]=s[s_p-1] || s[s_p-2];
	    s_p--;
	    break;
	 case OP_NOT:
	    assert(s_p>=1);
	    s[s_p-1]=!s[s_p-1];
	    break;
	 default:
	    s[s_p++] = eval_expr(elm,rec);
	    break;
      }
   }

   assert(s_p==1);
   return f->stack[0];
}

static const char *token2text(enum token_t t)
{
   switch (t) {
      case OP_EQ: return "="; break;
      case OP_NE: return "!="; break;
      case OP_GT: return ">"; break;
      case OP_GE: return ">="; break;
      case OP_LT: return "<"; break;
      case OP_LE: return "<="; break;
      case LEFT_BRACE: return "("; break;
      case RIGHT_BRACE: return ")"; break;
      case OP_AND: return "&&"; break;
      case OP_OR: return "||"; break;
      case OP_NOT: return "!"; break;
      case FW_ID: return "fw_id"; break;
      case SRC_ADDR: return "src_addr"; break;
      case ACCOUNT_IP: return "account_ip"; break;
      case DST_ADDR: return "dst_addr"; break;
      case NEXT_HOP: return "next_hop"; break;
      case I_IFX: return "i_ifx"; break;
      case O_IFX: return "o_ifx"; break;
      case PACKETS: return "packets"; break;
      case OCTETS: return "octets"; break;
      case S_PORT: return "s_port"; break;
      case D_PORT: return "d_port"; break;
      case FLAGS: return "flags"; break;
      case PROTO: return "proto"; break;
      case TOS: return "tos"; break;
      case SRC_AS: return "src_as"; break;
      case DST_AS: return "dst_as"; break;
      case SLINK_ID: return "slink_id"; break;
      case ACCOUNT_ID: return "account_id"; break;
      case TCLASS: return "tclass"; break;
      case TIMESTAMP: return "timestamp"; break;
      case ROUTER_IP: return "router_ip"; break;
      case NUMBER: return "_number"; break;
      case NETADDR: return "_netaddr"; break;
      case DATETIME: return "_datetime"; break;
      case UNKNOWN: return "_unknown"; break;
      default: break;
   }

   return "__unknown";
}

static void print_filter(struct filter_t *f)
{
   struct filter_elm_t *fe;

   assert(f);

   fprintf(stderr, "FILTER: ");
   if (f->head == NULL) {
      fprintf(stderr, "empty\n");
   }

   for(fe=f->head;fe;fe=fe->next) {
      switch(fe->operator) {
	 case LEFT_BRACE:
	 case RIGHT_BRACE:
	 case OP_AND:
	 case OP_OR:
	 case OP_NOT:
	    fprintf(stderr, " %s ", token2text(fe->operator));
	    break;
	 default:
	    fprintf(stderr, " (%s%s", token2text(fe->expr.field),
		  token2text(fe->operator));
	    switch (fe->expr.field) {
	       case SRC_ADDR:
	       case ACCOUNT_IP:
	       case DST_ADDR:
	       case NEXT_HOP:
	       case ROUTER_IP:
		  fprintf(stderr, "0x%x/%x)", fe->expr.arg.addr.ip,
			fe->expr.arg.addr.mask);
		  break;
	       case I_IFX:
	       case O_IFX:
	       case S_PORT:
	       case D_PORT:
	       case SRC_AS:
	       case DST_AS:
		  fprintf(stderr, "%d)", fe->expr.arg.u16);
		  break;
	       case FLAGS:
	       case TOS:
	       case PROTO:
		  fprintf(stderr, "%d)", fe->expr.arg.u8);
		  break;
	       default:
		  fprintf(stderr, "%d)", fe->expr.arg.u32);
		  break;
	    }
	    break;
      }
   }
   fprintf(stderr, "\n");
}
