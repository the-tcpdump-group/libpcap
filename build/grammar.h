/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

#ifndef YY_PCAP_HOME_REDVIKING_PROJECTS_LIBPCAP_BUILD_GRAMMAR_H_INCLUDED
# define YY_PCAP_HOME_REDVIKING_PROJECTS_LIBPCAP_BUILD_GRAMMAR_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int pcap_debug;
#endif

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    DST = 258,                     /* DST  */
    SRC = 259,                     /* SRC  */
    HOST = 260,                    /* HOST  */
    GATEWAY = 261,                 /* GATEWAY  */
    NET = 262,                     /* NET  */
    NETMASK = 263,                 /* NETMASK  */
    PORT = 264,                    /* PORT  */
    PORTRANGE = 265,               /* PORTRANGE  */
    LESS = 266,                    /* LESS  */
    GREATER = 267,                 /* GREATER  */
    PROTO = 268,                   /* PROTO  */
    PROTOCHAIN = 269,              /* PROTOCHAIN  */
    CBYTE = 270,                   /* CBYTE  */
    ARP = 271,                     /* ARP  */
    RARP = 272,                    /* RARP  */
    IP = 273,                      /* IP  */
    SCTP = 274,                    /* SCTP  */
    TCP = 275,                     /* TCP  */
    UDP = 276,                     /* UDP  */
    ICMP = 277,                    /* ICMP  */
    IGMP = 278,                    /* IGMP  */
    IGRP = 279,                    /* IGRP  */
    PIM = 280,                     /* PIM  */
    VRRP = 281,                    /* VRRP  */
    CARP = 282,                    /* CARP  */
    ATALK = 283,                   /* ATALK  */
    AARP = 284,                    /* AARP  */
    DECNET = 285,                  /* DECNET  */
    LAT = 286,                     /* LAT  */
    SCA = 287,                     /* SCA  */
    MOPRC = 288,                   /* MOPRC  */
    MOPDL = 289,                   /* MOPDL  */
    TK_BROADCAST = 290,            /* TK_BROADCAST  */
    TK_MULTICAST = 291,            /* TK_MULTICAST  */
    NUM = 292,                     /* NUM  */
    INBOUND = 293,                 /* INBOUND  */
    OUTBOUND = 294,                /* OUTBOUND  */
    IFINDEX = 295,                 /* IFINDEX  */
    PF_IFNAME = 296,               /* PF_IFNAME  */
    PF_RSET = 297,                 /* PF_RSET  */
    PF_RNR = 298,                  /* PF_RNR  */
    PF_SRNR = 299,                 /* PF_SRNR  */
    PF_REASON = 300,               /* PF_REASON  */
    PF_ACTION = 301,               /* PF_ACTION  */
    TYPE = 302,                    /* TYPE  */
    SUBTYPE = 303,                 /* SUBTYPE  */
    DIR = 304,                     /* DIR  */
    ADDR1 = 305,                   /* ADDR1  */
    ADDR2 = 306,                   /* ADDR2  */
    ADDR3 = 307,                   /* ADDR3  */
    ADDR4 = 308,                   /* ADDR4  */
    RA = 309,                      /* RA  */
    TA = 310,                      /* TA  */
    LINK = 311,                    /* LINK  */
    GEQ = 312,                     /* GEQ  */
    LEQ = 313,                     /* LEQ  */
    NEQ = 314,                     /* NEQ  */
    ID = 315,                      /* ID  */
    EID = 316,                     /* EID  */
    HID = 317,                     /* HID  */
    HID6 = 318,                    /* HID6  */
    AID = 319,                     /* AID  */
    LSH = 320,                     /* LSH  */
    RSH = 321,                     /* RSH  */
    LEN = 322,                     /* LEN  */
    IPV6 = 323,                    /* IPV6  */
    ICMPV6 = 324,                  /* ICMPV6  */
    AH = 325,                      /* AH  */
    ESP = 326,                     /* ESP  */
    VLAN = 327,                    /* VLAN  */
    MPLS = 328,                    /* MPLS  */
    PPPOED = 329,                  /* PPPOED  */
    PPPOES = 330,                  /* PPPOES  */
    GENEVE = 331,                  /* GENEVE  */
    VXLAN = 332,                   /* VXLAN  */
    ISO = 333,                     /* ISO  */
    ESIS = 334,                    /* ESIS  */
    CLNP = 335,                    /* CLNP  */
    ISIS = 336,                    /* ISIS  */
    L1 = 337,                      /* L1  */
    L2 = 338,                      /* L2  */
    IIH = 339,                     /* IIH  */
    LSP = 340,                     /* LSP  */
    SNP = 341,                     /* SNP  */
    CSNP = 342,                    /* CSNP  */
    PSNP = 343,                    /* PSNP  */
    STP = 344,                     /* STP  */
    IPX = 345,                     /* IPX  */
    NETBEUI = 346,                 /* NETBEUI  */
    LANE = 347,                    /* LANE  */
    LLC = 348,                     /* LLC  */
    METAC = 349,                   /* METAC  */
    BCC = 350,                     /* BCC  */
    SC = 351,                      /* SC  */
    ILMIC = 352,                   /* ILMIC  */
    OAMF4EC = 353,                 /* OAMF4EC  */
    OAMF4SC = 354,                 /* OAMF4SC  */
    OAM = 355,                     /* OAM  */
    OAMF4 = 356,                   /* OAMF4  */
    CONNECTMSG = 357,              /* CONNECTMSG  */
    METACONNECT = 358,             /* METACONNECT  */
    VPI = 359,                     /* VPI  */
    VCI = 360,                     /* VCI  */
    RADIO = 361,                   /* RADIO  */
    FISU = 362,                    /* FISU  */
    LSSU = 363,                    /* LSSU  */
    MSU = 364,                     /* MSU  */
    HFISU = 365,                   /* HFISU  */
    HLSSU = 366,                   /* HLSSU  */
    HMSU = 367,                    /* HMSU  */
    SIO = 368,                     /* SIO  */
    OPC = 369,                     /* OPC  */
    DPC = 370,                     /* DPC  */
    SLS = 371,                     /* SLS  */
    HSIO = 372,                    /* HSIO  */
    HOPC = 373,                    /* HOPC  */
    HDPC = 374,                    /* HDPC  */
    HSLS = 375,                    /* HSLS  */
    LEX_ERROR = 376,               /* LEX_ERROR  */
    OR = 377,                      /* OR  */
    AND = 378,                     /* AND  */
    UMINUS = 379                   /* UMINUS  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 346 "/home/redviking/projects/libpcap/build/grammar.y"

	int i;
	bpf_u_int32 h;
	char *s;
	struct stmt *stmt;
	struct arth *a;
	struct {
		struct qual q;
		int atmfieldtype;
		int mtp3fieldtype;
		struct block *b;
	} blk;
	struct block *rblk;

#line 203 "/home/redviking/projects/libpcap/build/grammar.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif




int pcap_parse (void *yyscanner, compiler_state_t *cstate);


#endif /* !YY_PCAP_HOME_REDVIKING_PROJECTS_LIBPCAP_BUILD_GRAMMAR_H_INCLUDED  */
