/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 *           Copyright (C) 1998-2009 Luca Deri <deri@ntop.org>
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

#ifndef __SCSI_UTILS_H__
#define __SCSI_UTILS_H__

#define SCSI_DEV_BLOCK                   0x0
#define SCSI_DEV_SSC                     0x1
#define SCSI_DEV_PRINTER                 0x2
#define SCSI_DEV_WORM                    0x4
#define SCSI_DEV_CDROM                   0x5
#define SCSI_DEV_SMC                     0x8
#define SCSI_DEV_INITIATOR               0x12 /* Our own convention */
#define SCSI_DEV_UNKNOWN                 0x13 /* Our own convention */
#define SCSI_DEV_NODEV                   0x1F
#define SCSI_DEV_UNINIT                  0xFF

#define SCSI_READ_CMD                    0x1
#define SCSI_WR_CMD                      0x2
#define SCSI_NONRDWR_CMD                 0x3

#define SCSI_SPC2_INQUIRY                0x12
#define SCSI_SPC2_INQUIRY_EVPD           0xFF
#define SCSI_SPC2_REPORTLUNS             0xA0
#define SCSI_SBC2_READCAPACITY           0x25
#define SCSI_SBC2_READ6                  0x08
#define SCSI_SBC2_READ10                 0x28
#define SCSI_SBC2_READ12                 0xA8
#define SCSI_SBC2_READ16                 0x88
#define SCSI_SBC2_WRITE6                 0x0A
#define SCSI_SBC2_WRITE10                0x2A
#define SCSI_SBC2_WRITE12                0xAA
#define SCSI_SBC2_WRITE16                0x8A
#define SCSI_SSC2_READ6                  0x08
#define SCSI_SSC2_READ_16                0x88
#define SCSI_SSC2_READ_REVERSE_6         0x0F
#define SCSI_SSC2_READ_REVERSE_16        0x81
#define SCSI_SSC2_WRITE6                 0x0A
#define SCSI_SSC2_WRITE_16               0x8A

#define MAX_LUNS_SUPPORTED               256
#define MAX_LUNS_GRAPHED                 10
#define SCSI_VENDOR_ID_LEN               16

#define SCSI_STATUS_GOOD                 0
#define SCSI_STATUS_CHK_CONDITION        0x02
#define SCSI_STATUS_BUSY                 0x08
#define SCSI_STATUS_RESV_CONFLICT        0x18
#define SCSI_STATUS_TASK_SET_FULL        0x28
#define SCSI_STATUS_TASK_ABORTED         0x40 

#define SCSI_TM_ABORT_TASK_SET           0x2
#define SCSI_TM_CLEAR_TASK_SET           0x4
#define SCSI_TM_LUN_RESET                0x10
#define SCSI_TM_TARGET_RESET             0x20
#define SCSI_TM_CLEAR_ACA                0x40

#endif
