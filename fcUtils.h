/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 * Copyright (C) 2003 Dinesh G. Dutt <ddutt@cisco.com>
 * Copyright (C) 2003-04 Luca Deri <deri@ntop.org>
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef __FC_UTILS_H__
#define __FC_UTILS_H__

#define FC_ID_SYSTEM_DOMAIN    0xFF
#define FC_ID_DOMCTLR_AREA     0xFC
#define FC_BROADCAST_ADDR      "ff.ff.ff"
#define FC_FAB_CTLR_ADDR       "ff.ff.fd"

#define MDSHDR_HEADER_SIZE               16
#define MDSHDR_TRAILER_SIZE              6

/* SOF Encodings */
#define MDSHDR_SOFc1                     0x1
#define MDSHDR_SOFi1                     0x2
#define MDSHDR_SOFn1                     0x3
#define MDSHDR_SOFi2                     0x4
#define MDSHDR_SOFn2                     0x5
#define MDSHDR_SOFi3                     0x6
#define MDSHDR_SOFn3                     0x7
#define MDSHDR_SOFf                      0x8
#define MDSHDR_SOFc4                     0x9
#define MDSHDR_SOFi4                     0xa
#define MDSHDR_SOFn4                     0xb

/* EOF Encodings */
#define MDSHDR_EOFt                      0x1
#define MDSHDR_EOFdt                     0x2
#define MDSHDR_EOFa                      0x4
#define MDSHDR_EOFn                      0x3
#define MDSHDR_EOFdti                    0x6
#define MDSHDR_EOFni                     0x7
#define MDSHDR_EOFrt                     0xa
#define MDSHDR_EOFrti                    0xe
#define MDSHDR_EOF_UNKNOWN               0xb

/* R_CTL upper bits creates a classification tree */
#define FC_RCTL_DEV_DATA       0x00
#define FC_RCTL_ELS            0x20
#define FC_RCTL_LINK_DATA      0x30
#define FC_RCTL_VIDEO          0x40
#define FC_RCTL_BLS            0x80
#define FC_RCTL_LINK_CTL       0xC0
/* XXX - is 0xF0 Extended Routing?  It is in the FC-FS draft on the T11
   Web site. */

#define FC_TYPE_CMNSVC         0x0  /* Used in PRLI Svc Param Page */

/* TYPE definitions for Basic or Extended Link_Data */
#define FC_TYPE_ELS            0x1

/* TYPE definitions for FC-4 */
#define FC_TYPE_LLCSNAP        0x4
#define FC_TYPE_IP             0x5
#define FC_TYPE_SCSI           0x8
#define FC_TYPE_SB_TO_CU       0x1B /* SB3 Control Unit -> Channel */
#define FC_TYPE_SB_FROM_CU     0x1C /* SB3 Channel -> Control Unit */ 
#define FC_TYPE_FCCT           0x20
#define FC_TYPE_SWILS          0x22
#define FC_TYPE_AL             0x23
#define FC_TYPE_SNMP           0x24

/* Derived Frame types (used for ULP demux) */
#define FC_FTYPE_SWILS         0x1
#define FC_FTYPE_IP            0x2
#define FC_FTYPE_SCSI          0x3
#define FC_FTYPE_BLS           0x4
#define FC_FTYPE_ELS           0x5
#define FC_FTYPE_FCCT          0x7
#define FC_FTYPE_LINKDATA      0x8
#define FC_FTYPE_VDO           0x9
#define FC_FTYPE_LINKCTL       0xA
#define FC_FTYPE_SWILS_RSP     0xB
#define FC_FTYPE_SBCCS         0xC
#define FC_FTYPE_UNDEF         0xD

/* Well-known Address Definitions (in Network order) */
#define FC_WKA_MULTICAST       0xFFFFF5
#define FC_WKA_CLKSYNC         0xFFFFF6
#define FC_WKA_KEYDIST         0xFFFFF7
#define FC_WKA_ALIAS           0xFFFFF8
#define FC_WKA_QOSF            0xFFFFF9
#define FC_WKA_MGMT            0xFFFFFA
#define FC_WKA_TIME            0xFFFFFB
#define FC_WKA_DNS             0xFFFFFC
#define FC_WKA_FABRIC_CTRLR    0xFFFFFD
#define FC_WKA_FPORT           0xFFFFFE
#define FC_WKA_BCAST           0xFFFFFF

#define FC_ELS_CMD_ACC         0x02
#define FC_ELS_CMD_PLOGI       0x03
#define FC_ELS_CMD_LOGO        0x05
#define FC_ELS_CMD_RSCN          0x61
#define FC_ELS_CMD_SCR           0x62

/* Well-known GSTYPEs */
#define FCCT_GSTYPE_KEYSVC   0xF7
#define FCCT_GSTYPE_ALIASSVC 0xF8
#define FCCT_GSTYPE_MGMTSVC  0xFA
#define FCCT_GSTYPE_TIMESVC  0xFB
#define FCCT_GSTYPE_DIRSVC   0xFC

/* Well-known GSSUBTYPES */
/* Actual servers serving the directory service type identified by subtype */ 
#define FCCT_GSSUBTYPE_DNS  0x02
#define FCCT_GSSUBTYPE_IP   0x03
#define FCCT_GSSUBTYPE_FCS  0x01
#define FCCT_GSSUBTYPE_UNS  0x02
#define FCCT_GSSUBTYPE_FZS  0x03
#define FCCT_GSSUBTYPE_AS   0x01
#define FCCT_GSSUBTYPE_TS   0x01

#define FCDNS_RPN_ID   0x0212
#define FCDNS_RNN_ID   0x0213
#define FCDNS_RCS_ID   0x0214
#define FCDNS_RFT_ID   0x0217
#define FCDNS_RSPN_ID  0x0218
#define FCDNS_RPT_ID   0x021A
#define FCDNS_RIPP_ID  0x021B
#define FCDNS_RHA_ID   0x021D
#define FCDNS_RFD_ID   0x021E
#define FCDNS_RFF_ID   0x021F
#define FCDNS_RIP_NN   0x0235
#define FCDNS_RIPA_NN  0x0236
#define FCDNS_RSNN_NN  0x0239

/* Information Categories based on lower 4 bits of R_CTL */
#define FCP_IU_DATA              0x1
#define FCP_IU_CONFIRM           0x3
#define FCP_IU_XFER_RDY          0x5
#define FCP_IU_CMD               0x6
#define FCP_IU_RSP               0x7

/* SWILS Commands */
#define FC_SWILS_SWRJT          0x01
#define FC_SWILS_SWACC          0x02
#define FC_SWILS_ELP            0x10
#define FC_SWILS_EFP            0x11
#define FC_SWILS_DIA            0x12
#define FC_SWILS_RDI            0x13
#define FC_SWILS_HLO            0x14
#define FC_SWILS_LSU            0x15
#define FC_SWILS_LSA            0x16
#define FC_SWILS_BF             0x17
#define FC_SWILS_RCF            0x18
#define FC_SWILS_RSCN           0x1B
#define FC_SWILS_DRLIR          0x1E
#define FC_SWILS_DSCN           0x20
#define FC_SWILS_LOOPD          0x21
#define FC_SWILS_MR             0x22
#define FC_SWILS_ACA            0x23
#define FC_SWILS_RCA            0x24
#define FC_SWILS_SFC            0x25
#define FC_SWILS_UFC            0x26
#define FC_SWILS_ESC            0x30

#define MAX_FC_DOMAINS          240

#define DEFAULT_VSAN            1
#define MAX_USER_VSAN           1001
#define MAX_VSANS_GRAPHED       10
#define MAX_VSANS               4095

#define MAX_FC_PROTOCOL_NAME    12
#define MAX_FC_PROTOCOLS        6

#define FC_HDR_SIZE             24

/* SW_RSCN fields */
#define FC_SW_RSCN_FABRIC_DETECT 0x01
#define FC_SW_RSCN_NPORT_DETECT  0x02

#define FC_SW_RSCN_PORT_ONLINE   0x10
#define FC_SW_RSCN_PORT_OFFLINE  0x20

/* FC Alias Size */
#define FC_ALIAS_SIZE            64

#define CMP_FC_PORT(a,b) \
        if ((a->hostFcAddress.domain == 0xFF) ||                                        \
            (b->hostFcAddress.domain == 0xFF)) {                                        \
            /* Always compare FC_IDs for reserved FC_IDs */                             \
            rc = memcmp (&a->hostFcAddress, &b->hostFcAddress, LEN_FC_ADDRESS);         \
        }                                                                               \
        else {                                                                          \
            /* Sort such that entries with alias names show up together, then           \
             * entries with pWWN and finally entries with FC_ID. Within each            \
             * set, the entries must be correctly sorted.                               \
             */                                                                         \
            if ((a->hostSymFcAddress[0] != '\0') &&                                     \
                (b->hostSymFcAddress[0] != '\0')) {                                     \
                rc = strcmp(a->hostSymFcAddress, b->hostSymFcAddress);                  \
            }                                                                           \
            else if ((a->hostSymFcAddress[0] == 0) &&                                   \
                     (b->hostSymFcAddress[0] != '\0')) {                                \
                rc = 1;        /* Named entries float to top */                         \
            }                                                                           \
            else if ((a->hostSymFcAddress[0] != 0) &&                                   \
                     (b->hostSymFcAddress[0] == '\0')) {                                \
                rc = -1;        /* Named entries float to top */                        \
            }                                                                           \
            else if ((a->pWWN.str[0] != '\0') &&                                        \
                     (b->pWWN.str[0] != '\0')) {                                        \
                rc = memcmp (a->pWWN.str, b->pWWN.str, LEN_WWN_ADDRESS);                \
            }                                                                           \
            else if ((a->pWWN.str[0] == '\0') &&                                        \
                     (b->pWWN.str[0] != '\0')) {                                        \
                rc = 1;  /* pWWN entries float above FC_ID only entries */              \
            }                                                                           \
            else if ((a->pWWN.str[0] != '\0') &&                                        \
                     (b->pWWN.str[0] == '\0')) {                                        \
                rc = -1;                                                                \
            }                                                                           \
            else {                                                                      \
                rc = memcmp (&a->hostFcAddress, &b->hostFcAddress, LEN_FC_ADDRESS);     \
            }                                                                           \
        }



#endif
