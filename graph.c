/*
 *  Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
 *
 *  			    http://www.ntop.org/
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
 * Do not use local defs for pnggraph
 * (included by ntop.h)
 */

#include "ntop.h"

#define _GRAPH_C_
#include "globals-report.h"

static unsigned long clr[] = { 0xf08080L, 0x4682b4L, 0x66cdaaL,
                               0xf4a460L, 0xb0c4deL, 0x90ee90L,
                               0xffd700L, 0x87ceebL, 0xdda0ddL,
                               0x7fffd4L, 0xffb6c1L, 0x708090L,
                               0x6495edL, 0xdeb887L, 0x6b8e23L};

/* ******************************************************************* */

#include "gd.h"
#include "gdfontl.h"
#include "gdfonts.h"
#include "gdfontmb.h"
#define M_PI	3.14159265358979323846

#include <stdio.h>

/* ******************************************************************* */

#define MIN_SLICE_PERCENTAGE 0.1 /* % */
#define BOX_SIZE               7



static void drawLegend(gdImagePtr im,
		       short width,
		       short height,
		       int   num_points,
		       char  *labels[],              /* slice labels */
		       float data[],
		       int colors[], int labelColor) {

  int edge_x, edge_y, i;
#ifdef SHOW_PERCENTAGE
  float total;
  char str[32];
#endif

  edge_x = (width*.75)+10;
  edge_y = (height/10);

#ifdef SHOW_PERCENTAGE
  for(i=0, total=0; i<num_points; i++)
    total += data[i];
#endif

  for(i=0; i<num_points; i++) {
    gdImageFilledRectangle(im, edge_x, edge_y, edge_x+BOX_SIZE, edge_y+BOX_SIZE, colors[i]);
    gdImageRectangle(im, edge_x-1, edge_y-1, edge_x+BOX_SIZE+1, edge_y+BOX_SIZE+1, labelColor);
#ifdef SHOW_PERCENTAGE
    snprintf(str, sizeof(str), "%s(%.1f%%)", labels[i], (data[i]*100)/total);
    gdImageString(im, gdFontSmall, edge_x+BOX_SIZE+5, edge_y-5, str, labelColor);
#else
    gdImageString(im, gdFontSmall, edge_x+BOX_SIZE+5, edge_y-3, labels[i], labelColor);
#endif
    edge_y += gdFontSmall->h*1.5;
  }
}

/* ************************ */

void drawPie(short width,
	     short height,
	     FILE* filepointer,            /* open file pointer, can be stdout */
	     int   num_points,
	     char  *labels[],              /* slice labels */
	     float data[] ) {
  gdImagePtr im;
  int black, white, colors[64], numColors, i;
  int center_x, center_y, radius, begDeg, endDeg, x, y;
  float total;
  int displ;
  float radiant;

  im = gdImageCreate(width, height);

  white = gdImageColorAllocate(im, 255, 255, 255); /* bg color */
  black = gdImageColorAllocate(im, 0, 0, 0);
  numColors = sizeof(clr)/sizeof(unsigned long);
  for(i=0; i<numColors; i++) {
    colors[i] = gdImageColorAllocate(im, clr[i]>>16, clr[i]>>8, clr[i]&0x0000FF);
  }

  /* ******************************* */
  for(i=0, total=0; i<num_points; i++)
    total += data[i];

  center_x = width/3, center_y = height/2;
  radius = height/3;
  begDeg = 0;

  gdImageArc(im, center_x, center_y, 2*radius, 2*radius, 0, 360, black);
  radiant = begDeg-90; radiant /= 360; radiant *= 2*M_PI;
  x = center_x+(radius)*cos(radiant);
  y = center_y+(radius)*sin(radiant);
  gdImageLine(im, center_x, center_y, x,y, black);

  for(i=0; i<num_points; i++) {
    displ = (360*data[i])/total;

    if(i < (num_points-1))
      endDeg = begDeg+displ;
    else
      endDeg = 360;

#if GD2_VERS == 2 /* GD 2.x detected */
    gdImageFilledArc(im, center_x, center_y, 2*radius, 2*radius,
		     begDeg+270, endDeg+270, colors[i], gdArc);
#else
    radiant = begDeg-90; radiant /= 360; radiant *= 2*M_PI;
    x = center_x+(radius)*cos(radiant);
    y = center_y+(radius)*sin(radiant);
    gdImageArc(im, center_x, center_y, 2*radius, 2*radius,
	       begDeg+270, endDeg+270, black);
    gdImageLine(im, center_x, center_y, x,y, black);

    begDeg = (begDeg+endDeg)/2;
    radiant = begDeg-90; radiant /= 360; radiant *= 2*M_PI;
    x = center_x+(radius/2)*cos(radiant);
    y = center_y+(radius/2)*sin(radiant);
    gdImageFillToBorder(im, x, y, black, colors[i]);
#endif

    begDeg = endDeg;
  }

#if GD2_VERS == 2 /* GD 2.x detected */
  gdImageArc(im, center_x, center_y, 2*radius, 2*radius, 0, 360, black);
#endif

  drawLegend(im, width, height, num_points, labels, data, colors, black);
  gdImagePng(im, filepointer);
  gdImageDestroy(im);
}

/* ************************ */

/* Fix for large numbers (over 4Gb) courtesy of
   Kouprie Robbert <r.kouprie@dto.tudelft.nl>
*/
void drawBar(short width,
	     short height,
	     FILE* filepointer,  /* open file pointer, can be stdout */
	     int   num_points,
	     char  *labels[],    /* slice labels */
	     float data[]) {
  gdImagePtr im;
  int black, white, gray, colors[64], numColors, i, ngrid, base, padding;
  int center_x, center_y, vmargin, hmargin, xsize, ysize, xpos, ypos, dypix;
  float maxval, total, yscale, txtsz, txtht;
  float dydat, xmax, ymax, xmin, ymin;

  im = gdImageCreate(width, height);

  white = gdImageColorAllocate(im, 255, 255, 255); /* bg color */
  black = gdImageColorAllocate(im, 0, 0, 0);
  gray = gdImageColorAllocate(im, 200, 200, 200);
  numColors = sizeof(clr)/sizeof(unsigned long);
  for(i=0; i<numColors; i++) {
    colors[i] = gdImageColorAllocate(im, clr[i]>>16, clr[i]>>8, clr[i]&0x0000FF);
  }

  /* ******************************* */

  maxval = 0;

  for(i=0, total=0; i<num_points; i++) {
    total += data[i];
    if(data[i] > maxval) maxval =  data[i];
  }

  center_x = width/3, center_y = height/2;

  /* ************************* */

  vmargin = 20; // top (bottom) vertical margin for title (x-labels)
  hmargin = 60; // left horizontal margin for y-labels

  base = floor((((width*.75)) - hmargin) / num_points); // distance between columns

  ysize = height - 2 * vmargin; // y-size of plot
  xsize = num_points * base; // x-size of plot

  // y labels and grid lines
  ngrid = 4; // number of grid lines

  dydat = maxval / ngrid; // data units between grid lines
  dypix = ysize / (ngrid + 1); // pixels between grid lines

  // make y-axis text label from height of grid line (in data units)
  for (i = 0; i <= (ngrid + 1); i++) {
    char *theStr = formatBytes(i * dydat, 0); // make label text

    txtsz = gdFontSmall->w*strlen(theStr); // pixel-width of label
    txtht = gdFontSmall->h; // pixel-height of label

    // height of grid line in pixels
    ypos = vmargin + ysize - (i*dypix);
    xpos = hmargin - 10 - txtsz;
    if(xpos < 1) xpos = 1;

    gdImageString(im, gdFontSmall, xpos, ypos - (int)(txtht/2), theStr, black);

    if (!(i == 0) && !(i > ngrid)) {
      gdImageLine(im, hmargin, ypos, hmargin + xsize, ypos, gray);
    }
  }

  // columns and x labels
  padding = 3; // half of spacing between columns
  yscale = (float)ysize/((ngrid+1) * dydat); // pixels per data unit

  for (i = 0; i<num_points; i++) {
    // vertical columns
    ymax = vmargin + ysize;

    if(ymax > (int)(data[i]*yscale)) {
      ymin = ymax - (int)(data[i]*yscale);
      if(ymin < vmargin) ymin = vmargin;
    }
    else
      ymin = vmargin;

    xmax = hmargin + (i+1)*base - padding;
    xmin = hmargin + i*base + padding;

    if((xmax-xmin) > 100) {
      xmax = xmin+100;
    }

    gdImageFilledRectangle(im, xmin, ymin, xmax, ymax, colors[i]);
    gdImageRectangle(im, xmin, ymin, xmax, ymax, black);

    // x labels
    txtsz = gdFontSmall->w * strlen(labels[i]);

    xpos = xmin + (int)((base - txtsz) / 2);
    if(xmin > xpos) xpos = xmin; else xmin = xpos;
    ypos = ymax + 3; // distance from x axis
  }

  // plot frame
  gdImageRectangle(im, hmargin, vmargin, hmargin + xsize, vmargin + ysize, black);

  /* ************************* */

  drawLegend(im, width, height, num_points, labels, data, colors, black);
  gdImagePng(im, filepointer);
  gdImageDestroy(im);
}

/* ************************** */

void drawArea(short width,
	      short height,
	      FILE* filepointer,            /* open file pointer, can be stdout */
	      int   num_points,
	      char  *labels[],              /* slice labels */
	      float data[],
	      char *xtitle,
	      char *ytitle,
	      u_short formatYlabels) {
  gdImagePtr im;
  int black, white, colors[64], numColors, i;
  float maxval=0;
  int center_x, center_y, base;
  float total, yscale, txtsz, txtht;
  float vmargin, hmargin, xsize, ysize, ngrid, dydat, dypix, ydat, xpos, ypos;
  float padding, ymax, ymin, xmax, xmin, gray;
  char str[16];

  im = gdImageCreate(width, height);

  white = gdImageColorAllocate(im, 255, 255, 255); /* bg color */
  black = gdImageColorAllocate(im, 0, 0, 0);
  gray = gdImageColorAllocate(im, 200, 200, 200);
  numColors = sizeof(clr)/sizeof(unsigned long);
  for(i=0; i<numColors; i++) {
    colors[i] = gdImageColorAllocate(im, clr[i]>>16, clr[i]>>8, clr[i]&0x0000FF);
  }

  /* ******************************* */
  for(i=0, total=0; i<num_points; i++) {
    total += data[i];
    if(data[i] > maxval) maxval =  data[i];
  }

  center_x = width/2, center_y = height/2;

  /* ************************* */

  vmargin = 40; // top (bottom) vertical margin for title (x-labels)
  hmargin = 60; // left horizontal margin for y-labels

  base = (int)((width - hmargin) / (1+num_points)); // distance between columns

  xsize = num_points * base; // x-size of plot
  ysize = height - (1.5 * vmargin); // y-size of plot

  /* printf("x-size=%.1f/y-size=%.1f\n", xsize, ysize); */
  // y labels and grid lines
  ngrid = 4; // number of grid lines

  dydat = maxval / ngrid; // data units between grid lines
  dypix = ysize / (ngrid + 1); // pixels between grid lines

  for (i = 0; i <= (ngrid + 1); i++) {
    // height of grid line in units of data
    ydat = i * dydat;
    snprintf(str, sizeof(str), "%.1f", ydat);

    // height of grid line in pixels
    ypos = vmargin/2 + ysize - (int)(i*dypix);
    txtht = gdFontSmall->h;

    if(maxval > 0) {
      if(!formatYlabels) {
	txtsz = gdFontSmall->w*strlen(str); 
	xpos = hmargin - txtsz; if(xpos < 1) xpos = 1;
	gdImageString(im, gdFontSmall, xpos-5, ypos - (int)(txtht/2), str, black);
      } else {
	char *theStr = formatThroughput(i * dydat, 0);

	/* traceEvent(CONST_TRACE_INFO, "%u/%s", i * dydat, theStr); */

	txtsz = gdFontSmall->w*strlen(theStr);
	xpos = hmargin - txtsz; if(xpos < 1) xpos = 1;
	gdImageString(im, gdFontSmall, xpos-5, ypos - (int)(txtht/2), theStr, black);	
      }
    }

    if (!(i == 0) && !(i > ngrid)) {
      gdImageLine(im, hmargin, ypos, hmargin + xsize, ypos, gray);
    }
  }

  // columns and x labels
  padding = 0; // half of spacing between columns
  yscale = (float)ysize / ((ngrid+1) * dydat); // pixels per data unit

  if(maxval > 0) {
    gdPoint points[5];

    memset(points, 0, sizeof(points));

    for (i = 0; i<num_points; i++) {
      // vertical columns
      ymax = vmargin/2 + ysize;
      ymin = ymax - (int)(data[i]*yscale);
      xmax = hmargin + (i+1)*base - padding;
      xmin = hmargin + i*base + padding;

      if(i == 0) {
	points[0].x = xmin; points[0].y = ymin;
	points[1].x = xmin; points[1].y = ymax;
	points[2].x = xmax; points[2].y = ymax;
	points[3].x = xmax; points[3].y = ymin;
      } else {
	points[0].x = points[3].x; points[0].y = points[3].y;
	points[1].x = points[2].x; points[1].y = points[2].y;
	points[2].x = xmax; points[2].y = ymax;
	points[3].x = xmax; points[3].y = ymin;
      }

      points[4].x = points[0].x; points[4].y = points[0].y;

      gdImageFilledPolygon(im, points, 5, colors[0]);
      gdImageFilledRectangle(im, points[0].x-1, points[0].y-1, points[0].x+1, points[0].y+1, black);
      gdImageFilledRectangle(im, points[3].x-1, points[3].y-1, points[3].x+1, points[3].y+1, black);
      gdImageLine(im, points[0].x, points[0].y, points[3].x, points[3].y, black);

      if((i % 2) == 0) {
	snprintf(str, sizeof(str), "%5s",labels[i]);
	gdImageStringUp(im, gdFontSmall, points[0].x-gdFontSmall->w, height-2, str, black);
      }

      // x labels
      txtsz = gdFontSmall->w * strlen(labels[i]);

      xpos = xmin + (int)((base - txtsz) / 2);
      if(xmin > xpos) xpos = xmin; else xmin = xpos;
      ypos = ymax + 3; // distance from x axis
    }
  }

  // plot frame
  gdImageRectangle(im, hmargin, vmargin/2, hmargin + xsize, vmargin/2 + ysize, black);

  if(xtitle)
    gdImageString(im, gdFontSmall, (width/2)-(strlen(xtitle)*gdFontSmall->w)/2,
		  height-gdFontSmall->h-2, xtitle, black);

  if(ytitle)
    gdImageString(im, gdFontSmall, 5, 2, ytitle, black);

  gdImagePng(im, filepointer);
  gdImageDestroy(im);
}

/* ************************ */

void sendGraphFile(char* fileName, int doNotUnlink) {
  FILE *fd;
  int len;
  char tmpStr[256];
  int bufSize=sizeof(tmpStr)-1;


  if((fd = fopen(fileName, "rb")) != NULL) {

    for(;;) {
      len = fread(tmpStr, sizeof(char), bufSize, fd);
      if(len > 0) {
	sendStringLen(tmpStr, len);
      }
      if(len <= 0) break;
    }
    fclose(fd);
  } else
    traceEvent(CONST_TRACE_WARNING, "Unable to open file %s - graphic not sent", fileName);

  if (doNotUnlink == 0) {
    unlink(fileName);
  }
}

/* ************************ */

void hostTrafficDistrib(HostTraffic *theHost, short dataSent) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[20];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int num=0;
  FILE *fd;
  TrafficCounter totTraffic;
  int useFdOpen = 0, idx = 0;
  ProtocolsList *protoList = myGlobals.ipProtosList;

  if(dataSent) {
    totTraffic.value = theHost->tcpSentLoc.value+theHost->tcpSentRem.value+
      theHost->udpSentLoc.value+theHost->udpSentRem.value+
      theHost->icmpSent.value+theHost->stpSent.value
      +theHost->ipxSent.value+theHost->osiSent.value+theHost->dlcSent.value+
      theHost->arp_rarpSent.value+theHost->decnetSent.value+theHost->appletalkSent.value+
      theHost->netbiosSent.value+theHost->ipv6Sent.value+theHost->otherSent.value;

    idx = 0;
    while(protoList != NULL) {
      totTraffic.value += theHost->ipProtosList[idx].sent.value;
      idx++, protoList = protoList->next;
    }
  } else {
    totTraffic.value = theHost->tcpRcvdLoc.value+theHost->tcpRcvdFromRem.value+
      theHost->udpRcvdLoc.value+theHost->udpRcvdFromRem.value+
      theHost->icmpRcvd.value+theHost->stpRcvd.value
      +theHost->ipxRcvd.value+theHost->osiRcvd.value+theHost->dlcRcvd.value+
      theHost->arp_rarpRcvd.value+theHost->decnetRcvd.value+theHost->appletalkRcvd.value+
      theHost->netbiosRcvd.value+theHost->ipv6Rcvd.value+theHost->otherRcvd.value;

    idx = 0;
    while(protoList != NULL) {
      totTraffic.value += theHost->ipProtosList[idx].rcvd.value;
      idx++, protoList = protoList->next;
    }
  }

  if(totTraffic.value > 0) {
    if(dataSent) {
      if(theHost->tcpSentLoc.value+theHost->tcpSentRem.value > 0) {
	p[num] = (float)((100*(theHost->tcpSentLoc.value+
			       theHost->tcpSentRem.value))/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "TCP";
      }

      if(theHost->udpSentLoc.value+theHost->udpSentRem.value > 0) {
	p[num] = (float)((100*(theHost->udpSentLoc.value+
			       theHost->udpSentRem.value))/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "UDP";
      }

      if(theHost->icmpSent.value > 0) {
	p[num] = (float)((100*theHost->icmpSent.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "ICMP";
      }

      if(theHost->stpSent.value > 0) {
	p[num] = (float)((100*theHost->stpSent.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "STP";
      }

      if(theHost->ipxSent.value > 0) {
	p[num] = (float)((100*theHost->ipxSent.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "IPX";
      }

      if(theHost->dlcSent.value > 0) {
	p[num] = (float)((100*theHost->dlcSent.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "DLC";
      }

      if(theHost->osiSent.value > 0) {
	p[num] = (float)((100*theHost->osiSent.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "OSI";
      }

      if(theHost->arp_rarpSent.value > 0) {
	p[num] = (float)((100*theHost->arp_rarpSent.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "(R)ARP";
      }

      if(theHost->decnetSent.value > 0) {
	p[num] = (float)((100*theHost->decnetSent.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "DECNET";
      }

      if(theHost->appletalkSent.value > 0) {
	p[num] = (float)((100*theHost->appletalkSent.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "AppleTalk";
      }

      if(theHost->netbiosSent.value > 0) {
	p[num] = (float)((100*theHost->netbiosSent.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "NetBios";
      }

      if(theHost->ipv6Sent.value > 0) {
	p[num] = (float)((100*theHost->ipv6Sent.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "IPv6";
      }

      if(theHost->otherSent.value > 0) {
	p[num] = (float)((100*theHost->otherSent.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "Other";
      }
    } else {
      if(theHost->tcpRcvdLoc.value+theHost->tcpRcvdFromRem.value > 0) {
	p[num] = (float)((100*(theHost->tcpRcvdLoc.value+
			       theHost->tcpRcvdFromRem.value))/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "TCP";
      }

      if(theHost->udpRcvdLoc.value+theHost->udpRcvdFromRem.value > 0) {
	p[num] = (float)((100*(theHost->udpRcvdLoc.value+
			       theHost->udpRcvdFromRem.value))/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "UDP";
      }

      if(theHost->icmpRcvd.value > 0) {
	p[num] = (float)((100*theHost->icmpRcvd.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "ICMP";
      }

      if(theHost->stpRcvd.value > 0) {
	p[num] = (float)((100*theHost->stpRcvd.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "STP";
      }

      if(theHost->ipxRcvd.value > 0) {
	p[num] = (float)((100*theHost->ipxRcvd.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "IPX";
      }

      if(theHost->dlcRcvd.value > 0) {
	p[num] = (float)((100*theHost->dlcRcvd.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "DLC";
      }

      if(theHost->osiRcvd.value > 0) {
	p[num] = (float)((100*theHost->osiRcvd.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "OSI";
      }

      if(theHost->arp_rarpRcvd.value > 0) {
	p[num] = (float)((100*theHost->arp_rarpRcvd.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "(R)ARP";
      }

      if(theHost->decnetRcvd.value > 0) {
	p[num] = (float)((100*theHost->decnetRcvd.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "DECNET";
      }

      if(theHost->appletalkRcvd.value > 0) {
	p[num] = (float)((100*theHost->appletalkRcvd.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "AppleTalk";
      }

      if(theHost->netbiosRcvd.value > 0) {
	p[num] = (float)((100*theHost->netbiosRcvd.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "NetBios";
      }

      if(theHost->ipv6Rcvd.value > 0) {
	p[num] = (float)((100*theHost->ipv6Rcvd.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "IPv6";
      }

      if(theHost->otherRcvd.value > 0) {
	p[num] = (float)((100*theHost->otherRcvd.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "Other";
      }
    }

    idx = 0; protoList = myGlobals.ipProtosList;
    while(protoList != NULL) {
      if(dataSent) {
	if(theHost->ipProtosList[idx].sent.value > 0) {
	  p[num] = (float)((100*theHost->ipProtosList[idx].sent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = protoList->protocolName;
	}
      } else {
	if(theHost->ipProtosList[idx].rcvd.value > 0) {
	  p[num] = (float)((100*theHost->ipProtosList[idx].rcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = protoList->protocolName;
	}
      }

      idx++, protoList = protoList->next;
    }

    if(num == 0) {
      traceEvent(CONST_TRACE_WARNING, "Graph failure (1)");
      return; /* TODO: this has to be handled better */
    }

#ifndef WIN32
    /* Unices */

    if(myGlobals.newSock < 0)
      useFdOpen = 0;
    else
      useFdOpen = 1;

    if(useFdOpen)
      fd = fdopen(abs(myGlobals.newSock), "ab");
    else
      fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

    if(num == 1) p[0] = 100; /* just to be safe */

    drawPie(300, 250,
	    fd,			/* open file pointer */
	    num,		/* number of slices */
	    lbl,		/* slice labels */
	    p);			/* data array */
    fclose(fd);

    if(!useFdOpen)
      sendGraphFile(fileName, 0);
  }
}

/* ************************ */

void hostFragmentDistrib(HostTraffic *theHost, short dataSent) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[20];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int num=0;
  FILE *fd;
  TrafficCounter totTraffic;
  int useFdOpen = 0;

  if(dataSent)
    totTraffic.value = theHost->tcpFragmentsSent.value+theHost->udpFragmentsSent.value+theHost->icmpFragmentsSent.value;
  else
    totTraffic.value = theHost->tcpFragmentsRcvd.value+theHost->udpFragmentsRcvd.value+theHost->icmpFragmentsRcvd.value;

  if(totTraffic.value > 0) {
    if(dataSent) {
      if(theHost->tcpFragmentsSent.value > 0) {
	p[num] = (float)((100*(theHost->tcpFragmentsSent.value))/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "TCP";
      }

      if(theHost->udpFragmentsSent.value > 0) {
	p[num] = (float)((100*(theHost->udpFragmentsSent.value))/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "UDP";
      }

      if(theHost->icmpFragmentsSent.value > 0) {
	p[num] = (float)((100*(theHost->icmpFragmentsSent.value))/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "ICMP";
      }
    } else {
      if(theHost->tcpFragmentsRcvd.value > 0) {
	p[num] = (float)((100*(theHost->tcpFragmentsRcvd.value))/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "TCP";
      }

      if(theHost->udpFragmentsRcvd.value > 0) {
	p[num] = (float)((100*(theHost->udpFragmentsRcvd.value))/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "UDP";
      }

      if(theHost->icmpFragmentsRcvd.value > 0) {
	p[num] = (float)((100*(theHost->icmpFragmentsRcvd.value))/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "ICMP";
      }
    }

    if(num == 0) {
      traceEvent(CONST_TRACE_WARNING, "Graph failure (2)");
      return; /* TODO: this has to be handled better */
    }

#ifndef WIN32
    /* Unices */

    if(myGlobals.newSock < 0)
      useFdOpen = 0;
    else
      useFdOpen = 1;

    if(useFdOpen)
      fd = fdopen(abs(myGlobals.newSock), "ab");
    else
      fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

    if(num == 1) p[0] = 100; /* just to be safe */
    drawPie(400, 250,
	    fd,			/* open file pointer */
	    num,		/* number of slices */
	    lbl,		/* slice labels */
	    p);			/* data array */

    fclose(fd);

    if(!useFdOpen)
      sendGraphFile(fileName, 0);
  }
}

/* ************************ */

void hostTotalFragmentDistrib(HostTraffic *theHost, short dataSent) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[20];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int num=0;
  FILE *fd;
  TrafficCounter totFragmentedTraffic, totTraffic;
  int useFdOpen = 0;

  if(dataSent) {
    totTraffic.value = theHost->ipBytesSent.value;
    totFragmentedTraffic.value = theHost->tcpFragmentsSent.value+theHost->udpFragmentsSent.value
      +theHost->icmpFragmentsSent.value;
  } else {
    totTraffic.value = theHost->ipBytesRcvd.value;
    totFragmentedTraffic.value = theHost->tcpFragmentsRcvd.value+theHost->udpFragmentsRcvd.value
      +theHost->icmpFragmentsRcvd.value;
  }

  if(totTraffic.value > 0) {
    p[num] = (float)((100*totFragmentedTraffic.value)/totTraffic.value);
    lbl[num++] = "Frag";

    p[num] = 100-((float)(100*totFragmentedTraffic.value)/totTraffic.value);
    if(p[num] > 0) { lbl[num++] = "Non Frag"; }

    if(num == 0) {
      traceEvent(CONST_TRACE_WARNING, "Graph failure (3)");
      return; /* TODO: this has to be handled better */
    }

#ifndef WIN32
    /* Unices */

    if(myGlobals.newSock < 0)
      useFdOpen = 0;
    else
      useFdOpen = 1;

    if(useFdOpen)
      fd = fdopen(abs(myGlobals.newSock), "ab");
    else
      fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

    if(num == 1) p[0] = 100; /* just to be safe */
    drawPie(400, 250,
	    fd,			/* open file pointer */
	    num,		/* number of slices */
	    lbl,		/* slice labels */
	    p);			/* data array */

    fclose(fd);

    if(!useFdOpen)
      sendGraphFile(fileName, 0);
  }
}

/* ************************ */

void hostIPTrafficDistrib(HostTraffic *theHost, short dataSent) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[MAX_NUM_PROTOS];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int i, num=0;
  FILE *fd;
  TrafficCounter traffic, totalIPTraffic, diffTraffic;
  int useFdOpen = 0;

  if(theHost->protoIPTrafficInfos == NULL) {
    traceEvent(CONST_TRACE_WARNING, "Graph failure (5)");
    return;
  }

  totalIPTraffic.value = 0;
  diffTraffic.value = 0;

  if(dataSent)
    totalIPTraffic.value = theHost->ipBytesSent.value;
  else
    totalIPTraffic.value = theHost->ipBytesRcvd.value;

  if(totalIPTraffic.value > 0) {
    for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
      if(dataSent)
	traffic.value = theHost->protoIPTrafficInfos[i].sentLoc.value+theHost->protoIPTrafficInfos[i].sentRem.value;
      else
	traffic.value = theHost->protoIPTrafficInfos[i].rcvdLoc.value+theHost->protoIPTrafficInfos[i].rcvdFromRem.value;

      if(traffic.value > 0) {
	p[num] = (float)((100*traffic.value)/totalIPTraffic.value);
	diffTraffic.value += traffic.value;
	lbl[num++] = myGlobals.protoIPTrafficInfos[i];
      }

      if(num >= MAX_NUM_PROTOS) break; /* Too much stuff */
    }
  }

  if(num == 0) {
    p[num] = 1;
    lbl[num++] = "Other";
  } else {
    if(diffTraffic.value < totalIPTraffic.value) {
      diffTraffic.value = totalIPTraffic.value - diffTraffic.value;
      p[num] = (float)((100*diffTraffic.value)/totalIPTraffic.value);
      lbl[num++] = "Other";
    }
  }

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;

  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  if(num == 1) p[0] = 100;

  if(num == 1) p[0] = 100; /* just to be safe */
  drawPie(300, 250,
	  fd,			/* open file pointer */
	  num,			/* number of slices */
	  lbl,			/* slice labels */
	  p);			/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* ********************************** */

void pktSizeDistribPie(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[7];
  char	*lbl[] = { "", "", "", "", "", "", "" };
  int num=0;
  FILE *fd;
  int useFdOpen = 0;

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo64.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo64.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "< 64";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo128.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo128.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "< 128";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo256.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo256.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "< 256";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo512.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo512.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "< 512";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1024.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1024.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "< 1024";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1518.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1518.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "< 1518";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above1518.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above1518.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "> 1518";
  };


#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;

  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  if(num == 1) p[0] = 100; /* just to be safe */
  drawPie(400, 250,
	  fd,			/* open file pointer */
	  num,			/* number of slices */
	  lbl,			/* slice labels */
	  p);			/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* ********************************** */

void pktTTLDistribPie(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[8];
  char	*lbl[] = { "", "", "", "", "", "", "" };
  int num=0;
  FILE *fd;
  int useFdOpen = 0;

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo32.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo32.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "< 32";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo64.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo64.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "< 64";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo96.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo96.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "< 96";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo128.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo128.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "< 128";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo160.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo160.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "< 160";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo192.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo192.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "< 192";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo224.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo224.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "< 224";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo255.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo255.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "<= 255";
  };

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;

  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  if(num == 1) p[0] = 100; /* just to be safe */
  drawPie(400, 250,
	  fd,			/* open file pointer */
	  num,			/* number of slices */
	  lbl,			/* slice labels */
	  p);			/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* ************************ */

void ipProtoDistribPie(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[3];
  char	*lbl[] = { "Loc", "Rem->Loc", "Loc->Rem" };
  int num=0;
  FILE *fd;
  int useFdOpen = 0;

  p[num] = (float)(myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.local.value+
		   myGlobals.device[myGlobals.actualReportDeviceId].udpGlobalTrafficStats.local.value)/1024;
  if(p[num] > 0) {
    lbl[num++] = "Loc";
  }

  p[num] = (float)(myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.remote2local.value+
		   myGlobals.device[myGlobals.actualReportDeviceId].udpGlobalTrafficStats.remote2local.value)/1024;
  if(p[num] > 0) {
    lbl[num++] = "Rem->Loc";
  }

  p[num] = (float)(myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.local2remote.value+
		   myGlobals.device[myGlobals.actualReportDeviceId].udpGlobalTrafficStats.local2remote.value)/1024;
  if(p[num] > 0) {
    lbl[num++] = "Loc->Rem";
  }

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;

  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  if(num == 1) p[0] = 100; /* just to be safe */
  drawPie(400, 250,
	  fd,			/* open file pointer */
	  num,			/* number of slices */
	  lbl,			/* slice labels */
	  p);			/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* ************************ */

void interfaceTrafficPie(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[MAX_NUM_DEVICES];
  int i;
  FILE *fd;
  TrafficCounter totPkts;
  struct pcap_stat pcapStat;
  char	*lbl[MAX_NUM_DEVICES];
  int myDevices=0;
  int useFdOpen = 0;

  totPkts.value = 0;

  for(i=0; i<myGlobals.numDevices; i++)
    if(myGlobals.device[i].pcapPtr && (!myGlobals.device[i].virtualDevice)) {
      if (pcap_stats(myGlobals.device[i].pcapPtr, &pcapStat) >= 0) {
	p[i] = (float)pcapStat.ps_recv;
	totPkts.value += pcapStat.ps_recv;
      }
    }

  if(totPkts.value == 0)
    totPkts.value++;

  for(i=0; i<myGlobals.numDevices; i++) {
    if((!myGlobals.device[i].virtualDevice) && (p[i] > 0))  {
      p[myDevices]   = 100*(((float)p[i])/totPkts.value);
      lbl[myDevices] = myGlobals.device[i].name;
      myDevices++;
    }
  }

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;

  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  if(myDevices == 1) p[0] = 100; /* just to be safe */
  drawPie(400, 250,
	  fd,		/* open file pointer */
	  myDevices,	/* number of slices */
	  lbl,		/* slice labels */
	  p);		/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* ************************ */

void pktCastDistribPie(void) {
  char fileName[64] = "/tmp/graph-XXXXXX";
  float p[3];
  char	*lbl[] = { "", "", "" };
  int num=0, useFdOpen = 0;
  FILE *fd;
  TrafficCounter unicastPkts;

  unicastPkts.value = myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value
    - myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts.value
    - myGlobals.device[myGlobals.actualReportDeviceId].multicastPkts.value;

  if(unicastPkts.value > 0) {
    p[num] = (float)(100*unicastPkts.value)/(float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "Unicast";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "Broadcast";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].multicastPkts.value > 0) {
    int i;

    p[num] = 100;
    for(i=0; i<num; i++)
      p[num] -= p[i];

    if(p[num] < 0) p[num] = 0;
    lbl[num++] = "Multicast";
  };

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;

  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  if(num == 1) p[0] = 100;  /* just to be safe */
  drawPie(400, 250,
	  fd,			/* open file pointer */
	  num,			/* number of slices */
	  lbl,			/* slice labels */
	  p);			/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* ************************ */

void drawTrafficPie(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  TrafficCounter ip;
  float p[2];
  char	*lbl[] = { "IP", "Non IP" };
  int num=0;
  FILE *fd;
  int useFdOpen = 0;

  if(myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value == 0) return;

  ip.value = myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value;

  p[0] = ip.value*100/myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value; num++;
  p[1] = 100-p[0];

  if(p[1] > 0)
    num++;

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;

  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  if(num == 1) p[0] = 100; /* just to be safe */
  drawPie(400, 250,
	  fd,			/* open file pointer */
	  num,			/* number of slices */
	  lbl,			/* slice labels */
	  p);			/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* ************************ */

void drawThptGraph(int sortedColumn) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  int i, len;
  char  labels[60][32];
  char  *lbls[60];
  FILE *fd;
  time_t tmpTime;
  float graphData[60], maxBytesPerSecond;
  struct tm t;
  int useFdOpen = 0;

  memset(graphData, 0, sizeof(graphData));

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;

  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  switch(sortedColumn) {
  case 1: /* 60 Minutes */
    for(i=0; i<60; i++) {
      lbls[59-i] = labels[i];
      labels[i][0] = '\0';
    }

    len = myGlobals.device[myGlobals.actualReportDeviceId].numThptSamples;
    if(len > 60) len = 60;
    for(i=0; i<len; i++) {
      tmpTime = myGlobals.actTime-i*60;
      strftime(labels[i], 32, "%H:%M", localtime_r(&tmpTime, &t));
    }

    for(maxBytesPerSecond=0, i=0; i<len; i++) {
      graphData[59-i] = myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].trafficValue;
      if(graphData[59-i] > maxBytesPerSecond) maxBytesPerSecond = graphData[59-i];
    }

    if(maxBytesPerSecond > 1048576 /* 1024*1024 */) {
      for(i=0; i<len; i++)
	graphData[59-i] /= 1048576;
    } else if(maxBytesPerSecond > 1024) {
      for(i=0; i<len; i++)
	graphData[59-i] /= 1024;
    }

    drawArea(600, 300,            /* width, height           */
	     fd,                  /* open FILE pointer       */
	     60,                  /* num points per data set */
	     (char**)lbls,        /* X labels array of char* */
	     graphData, NULL,     /* dataset 1   */
	     "Throughput", 1);
    break;
  case 2: /* 24 Hours */
    for(i=0; i<24; i++) {
      lbls[23-i] = labels[i];
      labels[i][0] = '\0';
    }

    len = myGlobals.device[myGlobals.actualReportDeviceId].numThptSamples/60;
    if(len > 24) len = 24;
    for(i=0; i<len; i++) {
      tmpTime = myGlobals.actTime-((i+1)*60*60);
      strftime(labels[i], 32, "%b %d %H:%M", localtime_r(&tmpTime, &t));
    }

    for(maxBytesPerSecond=0, i=0; i<len; i++) {
      graphData[23-i] = myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].trafficValue;
      if(graphData[23-i] > maxBytesPerSecond) maxBytesPerSecond = graphData[23-i];
    }

    if(maxBytesPerSecond > 1048576 /* 1024*1024 */) {
      for(i=0; i<len; i++)
	graphData[23-i] /= 1048576;
    } else if(maxBytesPerSecond > 1024) {
      for(i=0; i<len; i++)
	graphData[23-i] /= 1024;
    }

    drawArea(600, 300,      /* width, height           */
	     fd,            /* open FILE pointer       */
	     24,            /* num points per data set */
	     lbls,          /* X labels array of char* */
	     graphData, NULL,    /* dataset 1   */
	     "Throughput", 1);
    break;
  case 3: /* 30 Days */
    for(i=0; i<30; i++) {
      lbls[29-i] = labels[i];
      labels[i][0] = '\0';
    }

    len = myGlobals.device[myGlobals.actualReportDeviceId].numThptSamples/(24*60);
    if(len > 30) len = 30;
    for(i=0; i<len; i++) {
      tmpTime = myGlobals.actTime-((i+1)*(60*60*24));
      strftime(labels[i], 32, "%b %d %H:%M", localtime_r(&tmpTime, &t));
    }

    for(maxBytesPerSecond=0, i=0; i<len; i++) {
      graphData[29-i] = myGlobals.device[myGlobals.actualReportDeviceId].last30daysThpt[i];
      if(graphData[29-i] > maxBytesPerSecond) maxBytesPerSecond = graphData[29-i];
    }

    if(maxBytesPerSecond > 1048576 /* 1024*1024 */) {
      for(i=0; i<len; i++)
	graphData[29-i] /= 1048576;
    } else if(maxBytesPerSecond > 1024) {
      for(i=0; i<len; i++)
	graphData[29-i] /= 1024;
    }

    drawArea(600, 300,          /* width, height           */
	     fd,                /* open FILE pointer       */
	     30,                /* num points per data set */
	     lbls,              /* X labels array of char* */
	     graphData, NULL,
	     "Throughput", 1);
    break;
  }

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* ************************ */

void drawGlobalProtoDistribution(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  TrafficCounter ip;
  float p[256]; /* Fix courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
  char	*lbl[16];
  FILE *fd;
  int idx = 0;
  int useFdOpen = 0;

  ip.value = myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value;

  if(myGlobals.device[myGlobals.actualReportDeviceId].tcpBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].tcpBytes.value; lbl[idx] = "TCP";  idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].udpBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].udpBytes.value; lbl[idx] = "UDP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].icmpBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].icmpBytes.value; lbl[idx] = "ICMP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].otherIpBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].otherIpBytes.value; lbl[idx] = "Other IP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].arpRarpBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].arpRarpBytes.value; lbl[idx] = "(R)ARP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].dlcBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].dlcBytes.value; lbl[idx] = "DLC"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].ipxBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].ipxBytes.value; lbl[idx] = "IPX"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].decnetBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].decnetBytes.value;lbl[idx] = "Decnet";  idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].atalkBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].atalkBytes.value; lbl[idx] = "AppleTalk"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].netbiosBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].netbiosBytes.value; lbl[idx] = "NetBios"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].osiBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].osiBytes.value; lbl[idx] = "OSI"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].ipv6Bytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].ipv6Bytes.value; lbl[idx] = "IPv6"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].stpBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].stpBytes.value; lbl[idx] = "STP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].otherBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].otherBytes.value; lbl[idx] = "Other"; idx++; }


  {
    ProtocolsList *protoList = myGlobals.ipProtosList;
    int idx1 = 0;

    while(protoList != NULL) {

      if(myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList[idx1].value > 0) {
	p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList[idx1].value;
	lbl[idx] = protoList->protocolName; idx++;
      }

      idx1++, protoList = protoList->next;
    }
  }


#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;

  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  drawBar(600, 250,	/* width/height */
	  fd,	        /* open file pointer */
	  idx,	        /* number of slices */
	  lbl,	        /* slice labels */
	  p);	        /* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* ************************ */

void drawGlobalIpProtoDistribution(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  int i, idx=0, idx1 = 0;
  float p[256];
  char *lbl[256];
  FILE *fd;
  int useFdOpen = 0;
  ProtocolsList *protoList = myGlobals.ipProtosList;
  float total, partialTotal = 0;

  total = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value;

  while(protoList != NULL) {
    if(total > (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList[idx1].value)
      total -= (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList[idx1].value;
    else
      total = 0;

    idx1++, protoList = protoList->next;
  }

  for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
    p[idx]  = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].local.value
      +myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].remote.value;
    p[idx] += (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].remote2local.value
      +myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].local2remote.value;
    if(p[idx] > 0) {
      partialTotal += p[idx];
      lbl[idx] = myGlobals.protoIPTrafficInfos[i];
      idx++;
    }
  }

  /*  Add a bar for the Other TCP/UDP based protocols
      Courtesy of Robbert Kouprie <r.kouprie@dto.tudelft.nl>
  */
  if (total > partialTotal) {
    lbl[idx] = "Other";
    p[idx] = total - partialTotal;
    idx++;
  }

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;

  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  drawBar(600, 300,	/* width/height */
	  fd,		/* open file pointer */
	  idx,		/* number of slices */
	  lbl,		/* slice labels */
	  p);		/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* ******************************** */

int drawHostsDistanceGraph(int checkOnly) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  int i, j, numPoints=0;
  char  *lbls[32], labels[32][8];
  FILE *fd;
  float graphData[60];
  int useFdOpen = 0;
  HostTraffic *el;

  memset(graphData, 0, sizeof(graphData));

  for(i=0; i<=30; i++) {
    sprintf(labels[i], "%d", i);
    lbls[i] = labels[i];
    graphData[i] = 0;
  }

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    if(!subnetPseudoLocalHost(el)) {
      j = guessHops(el);
      if((j > 0) && (j <= 30)) {
	graphData[j]++;
	numPoints++;
      }
    }
  } /* for */

  if(checkOnly)
    return(numPoints);

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;

  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  drawArea(400, 250,    /* width, height           */
	   fd,          /* open FILE pointer       */
	   30,          /* num points per data set */
	   lbls,        /* X labels array of char* */
	   graphData, "Hops (TTL)",
	   "Number of Hosts", 0);

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);

  return(numPoints);
}

/* ************************ */


