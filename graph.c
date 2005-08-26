/*
 *  Copyright (C) 1998-2004 Luca Deri <deri@ntop.org>
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

#ifndef EMBEDDED

#define _GRAPH_C_
#include "globals-report.h"

static unsigned long clr[] = { 0xf08080L, 0x4682b4L, 0x66cdaaL,
                               0xf4a460L, 0xb0c4deL, 0x90ee90L,
                               0xffd700L, 0x87ceebL, 0xdda0ddL,
                               0x7fffd4L, 0xffb6c1L, 0x708090L,
                               0x6495edL, 0xdeb887L, 0x6b8e23L,
			       0xf08080L, 0x4682b4L, 0x66cdaaL,
                               0xf4a460L, 0xb0c4deL, 0x90ee90L,
                               0xffd700L, 0x87ceebL, 0xdda0ddL };

/* ************************ */

struct bar_elements {
  char *label;
  float data;
};

/* ******************************************************************* */

#include "gd.h"
#include "gdfontl.h"
#include "gdfonts.h"
#include "gdfontmb.h"

#ifndef M_PI
#define M_PI	3.14159265358979323846
#endif

#include <stdio.h>

/* ******************************************************************* */

/**********************************************************/
/* Guess at the version of gd from various breadcrumbs in */
/* the library (only things checkable at run-time, since  */
/* just because it was compiled against a version doesn't */
/* mean that's what it's running on...)                   */
/**********************************************************/

char* gdVersionGuess(void) {
#ifdef WIN32
#if GD2_VERS == 2 /* GD 2.x detected */    
    return("2.x");
#else
    return("1.8.x");
#endif
#else
#if (defined(HAVE_DIRENT_H) && defined(HAVE_DLFCN_H)) || defined(DARWIN)
  void *gdPtr = NULL;

  gdPtr = (void*)dlopen(CONST_LIBGD_SO, RTLD_NOW); /* Load the library */

  if(gdPtr == NULL) {
    traceEvent(CONST_TRACE_WARNING, "GDVERCHK: Unable to load gd, message is '%s'", dlerror());
#if GD2_VERS == 2 /* GD 2.x detected */    
    return("2.x");
#else
    return("1.8.x");
#endif
  }

#define test_gd_function(a, b)   if((void*)dlsym(gdPtr, a) != NULL) { dlclose(gdPtr); return(b); }

  test_gd_function("gdImageCreateFromPngPtr", "2.0.21+");
  test_gd_function("gdFontCacheSetup", "2.0.16-2.0.20");
  test_gd_function("gdImageSetClip", "2.0.12-2.0.15");
  test_gd_function("gdImageCopyRotated", "2.0.8-2.0.11");
  test_gd_function("gdImageStringFTEx", "2.0.5-2.0.7");
  test_gd_function("gdFreeFontCache", "2.0.4");
  test_gd_function("gdImageCreateTrueColor", "2.0.0-2.0.3");
  test_gd_function("gdImageCreateFromJpeg", "1.8.4");

#undef test_gd_function

  dlclose(gdPtr);

  return("1.8.3 or below");

#else

  return(NULL);
#endif
#endif
}

/* ************************************************** */

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
    gdImageFilledRectangle(im, edge_x, edge_y, edge_x+CONST_LEGEND_BOX_SIZE, 
                           edge_y+CONST_LEGEND_BOX_SIZE, colors[i]);
    gdImageRectangle(im, edge_x-1, edge_y-1, edge_x+CONST_LEGEND_BOX_SIZE+1,
                     edge_y+CONST_LEGEND_BOX_SIZE+1, labelColor);
#ifdef SHOW_PERCENTAGE
    safe_snprintf(__FILE__, __LINE__, str, sizeof(str), "%s(%.1f%%)", labels[i], (data[i]*100)/total);
    gdImageString(im, gdFontSmall, edge_x+CONST_LEGEND_BOX_SIZE+5, edge_y-5, (unsigned char*)str, labelColor);
#else
    gdImageString(im, gdFontSmall, edge_x+CONST_LEGEND_BOX_SIZE+5, edge_y-3, (unsigned char*)labels[i], labelColor);
#endif
    edge_y += gdFontSmall->h*1.5;
  }
}

/* ************************************************ */

static int cmpElementsFctn(const void *_a, const void *_b) {
  struct bar_elements *a = (struct bar_elements *)_a;
  struct bar_elements *b = (struct bar_elements *)_b;

  if((a == NULL) && (b != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "cmpFctn() error (1)");
    return(1);
  } else if((a != NULL) && (b == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "cmpFctn() error (2)");
    return(-1);
  } else if((a == NULL) && (b == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "cmpFctn() error (3)");
    return(0);
  }

  return((a)->data < (b)->data ? 1 : -1);
}

/* ************************ */

void drawPie(short width,
	     short height,
	     FILE* filepointer,            /* open file pointer, can be stdout */
	     int   num_points,
	     char  *labels[],              /* slice labels */
	     float data[],
	     int sorted) {
  gdImagePtr im;
  int black, white, colors[64], numColors, i;
  int center_x, center_y, radius, begDeg, endDeg, x, y;
  float total;
  int displ;
  float radiant;
  struct bar_elements *elems = NULL;

  if(sorted) {
    elems = (struct bar_elements*)malloc(sizeof(struct bar_elements)*num_points);

    if(elems == NULL) return; /* Not enough memory */

    for(i=0; i<num_points; i++) {
      elems[i].label = labels[i];
      elems[i].data = data[i];
    }

    qsort(elems, num_points, sizeof(struct bar_elements), cmpElementsFctn);

    for(i=0; i<num_points; i++) {
      labels[i] = elems[i].label;
      data[i] = elems[i].data;
    }
  }

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

  /* Safety check */
  if(num_points == 0) {
    num_points = 1;
    data[0] = 1;
  }

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

  drawLegend(im, width-25, height, num_points, labels, data, colors, black);
  gdImagePng(im, filepointer);
  gdImageDestroy(im);

  if(sorted && elems)
    free(elems);
}

/* ************************************************ */

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
  struct bar_elements *elems;

  if(num_points <= 0) return;
  
  elems = (struct bar_elements*)malloc(sizeof(struct bar_elements)*num_points);
  if(elems == NULL) return; /* Not enough memory */

  for(i=0; i<num_points; i++) {
    elems[i].label = labels[i];
    elems[i].data = data[i];
  }

  qsort(elems, num_points, sizeof(struct bar_elements), cmpElementsFctn);

  for(i=0; i<num_points; i++) {
    labels[i] = elems[i].label;
    data[i] = elems[i].data;
  }

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
    char buf[32];
    char *theStr = formatBytes(i * dydat, 0, buf, sizeof(buf)); // make label text

    txtsz = gdFontSmall->w*strlen(theStr); // pixel-width of label
    txtht = gdFontSmall->h; // pixel-height of label

    // height of grid line in pixels
    ypos = vmargin + ysize - (i*dypix);
    xpos = hmargin - 10 - txtsz;
    if(xpos < 1) xpos = 1;

    gdImageString(im, gdFontSmall, xpos, ypos - (int)(txtht/2), (unsigned char*)theStr, black);

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
  free(elems);
}

/* ************************** */

void drawArea(short width, short height,
	      FILE* filepointer, int num_points,
	      char* labels[], float data[],
	      char* xtitle, char* ytitle,
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
  hmargin = 70; // left horizontal margin for y-labels

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
    safe_snprintf(__FILE__, __LINE__, str, sizeof(str), "%.1f", ydat);

    // height of grid line in pixels
    ypos = vmargin/2 + ysize - (int)(i*dypix);
    txtht = gdFontSmall->h;

    if(maxval > 0) {
      if(!formatYlabels) {
	txtsz = gdFontSmall->w*strlen(str); 
	xpos = hmargin - txtsz; if(xpos < 1) xpos = 1;
	gdImageString(im, gdFontSmall, xpos-5, ypos - (int)(txtht/2), (unsigned char*)str, black);
      } else {
	char buf[32];
	char *theStr = formatThroughput(i * dydat, 0, buf, sizeof(buf));

	/* traceEvent(CONST_TRACE_INFO, "%u/%s", i * dydat, theStr); */

	txtsz = gdFontSmall->w*strlen(theStr);
	xpos = hmargin - txtsz; if(xpos < 1) xpos = 1;
	gdImageString(im, gdFontSmall, xpos-5, ypos - (int)(txtht/2), (unsigned char*)theStr, black);	
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
	safe_snprintf(__FILE__, __LINE__, str, sizeof(str), "%5s", labels[i]);
	gdImageStringUp(im, gdFontSmall, points[0].x-gdFontSmall->w, height-2, (unsigned char*)str, black);
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
		  height-gdFontSmall->h-2, (unsigned char*)xtitle, black);

  if(ytitle)
    gdImageString(im, gdFontSmall, 5, 2, (unsigned char*)ytitle, black);

  gdImagePng(im, filepointer);
  gdImageDestroy(im);
}

/* ************************ */

void sendGraphFile(char* fileName, int doNotUnlink) {
  FILE *fd;
  int len;
  char tmpStr[256];
  int bufSize=sizeof(tmpStr)-1, totLen = 0;

  memset(&tmpStr, 0, sizeof(tmpStr);

  if((fd = fopen(fileName, "rb")) != NULL) {

    for(;;) {
      len = fread(tmpStr, sizeof(char), bufSize, fd);
      if(len > 0) {
		sendStringLen(tmpStr, len);
		totLen += len;
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
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
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
      theHost->icmpSent.value+theHost->ipv6Sent.value;
    
    if(theHost->nonIPTraffic != NULL)
      totTraffic.value += theHost->nonIPTraffic->stpSent.value+
	theHost->nonIPTraffic->ipxSent.value+theHost->nonIPTraffic->osiSent.value+theHost->nonIPTraffic->dlcSent.value+
	theHost->nonIPTraffic->arp_rarpSent.value+theHost->nonIPTraffic->decnetSent.value+theHost->nonIPTraffic->appletalkSent.value+
	theHost->nonIPTraffic->netbiosSent.value+theHost->nonIPTraffic->otherSent.value;

    idx = 0;
    while(protoList != NULL) {
      if(theHost->ipProtosList[idx] != NULL) 
	totTraffic.value += theHost->ipProtosList[idx]->sent.value;
      idx++, protoList = protoList->next;
    }
  } else {
    totTraffic.value = theHost->tcpRcvdLoc.value+theHost->tcpRcvdFromRem.value+
      theHost->udpRcvdLoc.value+theHost->udpRcvdFromRem.value+
      theHost->icmpRcvd.value+theHost->ipv6Rcvd.value;

    if(theHost->nonIPTraffic != NULL)
      totTraffic.value += theHost->nonIPTraffic->stpRcvd.value
	+theHost->nonIPTraffic->ipxRcvd.value+theHost->nonIPTraffic->osiRcvd.value+theHost->nonIPTraffic->dlcRcvd.value+
	theHost->nonIPTraffic->arp_rarpRcvd.value+theHost->nonIPTraffic->decnetRcvd.value+theHost->nonIPTraffic->appletalkRcvd.value+
	theHost->nonIPTraffic->netbiosRcvd.value+theHost->nonIPTraffic->otherRcvd.value;
    
    idx = 0;
    while(protoList != NULL) {
      if(theHost->ipProtosList[idx] != NULL) 
	totTraffic.value += theHost->ipProtosList[idx]->rcvd.value;
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

      if(theHost->ipv6Sent.value > 0) {
	p[num] = (float)((100*theHost->ipv6Sent.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "IPv6";
      }

      if(theHost->nonIPTraffic != NULL) {
	if(theHost->nonIPTraffic->stpSent.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->stpSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "STP";
	}

	if(theHost->nonIPTraffic->ipxSent.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->ipxSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "IPX";
	}

	if(theHost->nonIPTraffic->dlcSent.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->dlcSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "DLC";
	}

	if(theHost->nonIPTraffic->osiSent.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->osiSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "OSI";
	}

	if(theHost->nonIPTraffic->arp_rarpSent.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->arp_rarpSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "(R)ARP";
	}

	if(theHost->nonIPTraffic->decnetSent.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->decnetSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "DECNET";
	}

	if(theHost->nonIPTraffic->appletalkSent.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->appletalkSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "AppleTalk";
	}

	if(theHost->nonIPTraffic->netbiosSent.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->netbiosSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "NetBios";
	}

	if(theHost->nonIPTraffic->otherSent.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->otherSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "Other";
	}
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

      if(theHost->ipv6Rcvd.value > 0) {
	p[num] = (float)((100*theHost->ipv6Rcvd.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "IPv6";
      }

      if(theHost->nonIPTraffic != NULL) {
	if(theHost->nonIPTraffic->stpRcvd.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->stpRcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "STP";
	}

	if(theHost->nonIPTraffic->ipxRcvd.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->ipxRcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "IPX";
	}

	if(theHost->nonIPTraffic->dlcRcvd.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->dlcRcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "DLC";
	}

	if(theHost->nonIPTraffic->osiRcvd.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->osiRcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "OSI";
	}

	if(theHost->nonIPTraffic->arp_rarpRcvd.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->arp_rarpRcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "(R)ARP";
	}

	if(theHost->nonIPTraffic->decnetRcvd.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->decnetRcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "DECNET";
	}

	if(theHost->nonIPTraffic->appletalkRcvd.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->appletalkRcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "AppleTalk";
	}

	if(theHost->nonIPTraffic->netbiosRcvd.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->netbiosRcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "NetBios";
	}

	if(theHost->nonIPTraffic->otherRcvd.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->otherRcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "Other";
	}
      }
  }

    idx = 0; protoList = myGlobals.ipProtosList;
    while(protoList != NULL) {
      if(theHost->ipProtosList[idx] != NULL) {
	if(dataSent) {
	  if(theHost->ipProtosList[idx]->sent.value > 0) {
	    p[num] = (float)((100*theHost->ipProtosList[idx]->sent.value)/totTraffic.value);
	    if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = protoList->protocolName;
	  }
	} else {
	  if(theHost->ipProtosList[idx]->rcvd.value > 0) {
	    p[num] = (float)((100*theHost->ipProtosList[idx]->rcvd.value)/totTraffic.value);
	    if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = protoList->protocolName;
	  }
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
	    p, 0);			/* data array */
    fclose(fd);

    if(!useFdOpen)
      sendGraphFile(fileName, 0);
  }
}

/* ************************ */

void hostFragmentDistrib(HostTraffic *theHost, short dataSent) {
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
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
	    p, 1);			/* data array */

    fclose(fd);

    if(!useFdOpen)
      sendGraphFile(fileName, 0);
  }
}

/* ************************ */

void hostTimeTrafficDistribution(HostTraffic *theHost, short dataSent) {
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
  float p[24];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int num=0, i;
  FILE *fd;
  int useFdOpen = 0;

  for(i=0; i<24; i++) {
    TrafficCounter traf;

    if(dataSent)
      traf.value = theHost->trafficDistribution->last24HoursBytesSent[i].value;
    else
      traf.value = theHost->trafficDistribution->last24HoursBytesRcvd[i].value;

    if(traf.value > 0) {
      p[num] = traf.value;
      switch(i) {
      case 0:
	lbl[num++] = "12PM-1AM";
	break;
      case 1:
	lbl[num++] = "1-2AM";
	break;
      case 2:
	lbl[num++] = "2-3AM";
	break;
      case 3:
	lbl[num++] = "3-4AM";
	break;
      case 4:
	lbl[num++] = "4-5AM";
	break;
      case 5:
	lbl[num++] = "5-6AM";
	break;
      case 6:
	lbl[num++] = "6-7AM";
	break;
      case 7:
	lbl[num++] = "7-8AM";
	break;
      case 8:
	lbl[num++] = "8-9AM";
	break;
      case 9:
	lbl[num++] = "9-10AM";
	break;
      case 10:
	lbl[num++] = "10-11AM";
	break;
      case 11:
	lbl[num++] = "11-12AM";
	break;
      case 12:
	lbl[num++] = "12AM-1PM";
	break;
      case 13:
	lbl[num++] = "1-2PM";
	break;
      case 14:
	lbl[num++] = "2-3PM";
	break;
      case 15:
	lbl[num++] = "3-4PM";
	break;
      case 16:
	lbl[num++] = "4-5PM";
	break;
      case 17:
	lbl[num++] = "5-6PM";
	break;
      case 18:
	lbl[num++] = "6-7PM";
	break;
      case 19:
	lbl[num++] = "7-8PM";
	break;
      case 20:
	lbl[num++] = "8-9PM";
	break;
      case 21:
	lbl[num++] = "9-10PM";
	break;
      case 22:
	lbl[num++] = "10-11PM";
	break;
      case 23:
	lbl[num++] = "11-12PM";
	break;
      }
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
  drawPie(300, 250,
	  fd,		/* open file pointer */
	  num,		/* number of slices */
	  lbl,		/* slice labels */
	  p, 0);	        /* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* ************************ */

void hostTotalFragmentDistrib(HostTraffic *theHost, short dataSent) {
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
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
	    p, 1);			/* data array */

    fclose(fd);

    if(!useFdOpen)
      sendGraphFile(fileName, 0);
  }
}

/* ************************ */

void hostIPTrafficDistrib(HostTraffic *theHost, short dataSent) {
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
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
      if(theHost->protoIPTrafficInfos[i]) {
	if(dataSent)
	  traffic.value = theHost->protoIPTrafficInfos[i]->sentLoc.value+theHost->protoIPTrafficInfos[i]->sentRem.value;
	else
	  traffic.value = theHost->protoIPTrafficInfos[i]->rcvdLoc.value+theHost->protoIPTrafficInfos[i]->rcvdFromRem.value;
      } else
	traffic.value = 0;
      
      if(traffic.value > 0) {
	p[num] = (float)((100*traffic.value)/totalIPTraffic.value);
	diffTraffic.value += traffic.value;
	lbl[num++] = myGlobals.ipTrafficProtosNames[i];
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
	  p, 1);			/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* ********************************** */

void pktSizeDistribPie(void) {
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
  float p[10];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "", "" };
  int num=0;
  FILE *fd;
  int useFdOpen = 0;

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo64.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo64.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 64";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo128.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo128.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 128";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo256.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo256.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 256";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo512.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo512.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 512";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1024.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1024.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 1024";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1518.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1518.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 1518";
  };

#ifdef MAKE_WITH_JUMBO_FRAMES
  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo2500.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo2500.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 2500";
  };
  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo6500.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo6500.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 6500";
  };
  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo9000.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo9000.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 9000";
  };
  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above9000.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above9000.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "> 9000";
  };
#else
  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above1518.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above1518.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "> 1518";
  };
#endif


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
	  p, 0);			/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* ********************************** */

void pktTTLDistribPie(void) {
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
  float p[10];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "" };
  int num=0;
  FILE *fd;
  int useFdOpen = 0;

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo32.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo32.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "<= 32";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo64.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo64.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "<= 64";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo96.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo96.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "<= 96";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo128.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo128.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "<= 128";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo160.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo160.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "<= 160";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo192.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo192.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "<= 192";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo224.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo224.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "<= 224";
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
	  p, 0);			/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* ************************ */

void ipProtoDistribPie(void) {
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
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
	  p, 1);			/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* ************************ */

void interfaceTrafficPie(void) {
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
  float p[MAX_NUM_DEVICES];
  int i;
  FILE *fd;
  TrafficCounter totPkts;
  char	*lbl[MAX_NUM_DEVICES];
  int myDevices=0;
  int useFdOpen = 0;

  totPkts.value = 0;

  for(i=0; i<myGlobals.numDevices; i++) {
    p[i] = (float)myGlobals.device[i].ethernetPkts.value;
    totPkts.value += myGlobals.device[i].ethernetPkts.value;
  }

  if(totPkts.value == 0) {
    traceEvent(CONST_TRACE_WARNING, "interfaceTrafficPie: no interfaces to draw");
    return;
  }

  for(i=0; i<myGlobals.numDevices; i++) {
    if(myGlobals.device[i].activeDevice) {
      p[myDevices]   = 100*(((float)p[i])/totPkts.value);
      lbl[myDevices] = myGlobals.device[i].humanFriendlyName;
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

  if(myDevices == 1) 
    p[0] = 100; /* just to be safe */
  else if(myDevices == 0) {
    traceEvent(CONST_TRACE_WARNING, "interfaceTrafficPie: no interfaces to draw");
    return;
  }

  drawPie(500, 250,
	  fd,		/* open file pointer */
	  myDevices,	/* number of slices */
	  lbl,		/* slice labels */
	  p, 1);		/* data array */
  
  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* ************************ */

void pktCastDistribPie(void) {
  char fileName[64] = "/tmp/ntop-graph-XXXXXX";
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
	  p, 1);			/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* ************************ */

void drawTrafficPie(void) {
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
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

  if(fd == NULL) return;

  if(num == 1) p[0] = 100; /* just to be safe */
  drawPie(400, 250,
	  fd,			/* open file pointer */
	  num,			/* number of slices */
	  lbl,			/* slice labels */
	  p, 1);			/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* ************************ */

void drawThptGraph(int sortedColumn) {
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
  int i, len;
  char  labels[60][32];
  char  *lbls[60];
  FILE *fd;
  time_t tmpTime;
  float graphData[60];
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
      strftime(labels[i], 32, CONST_TOD_NOSEC_TIMESPEC, localtime_r(&tmpTime, &t));
    }

    for(i=0; i<len; i++)
      graphData[59-i] = myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].trafficValue;

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
      strftime(labels[i], 32, CONST_TOD_NOSEC_TIMESPEC, localtime_r(&tmpTime, &t));
    }

    for(i=0; i<len; i++)
      graphData[23-i] = myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].trafficValue;

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
      strftime(labels[i], 32, "%d/%m", localtime_r(&tmpTime, &t));
    }

    for(i=0; i<len; i++)
      graphData[29-i] = myGlobals.device[myGlobals.actualReportDeviceId].last30daysThpt[i];

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
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
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
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
  int i, idx=0, idx1 = 0, maxNumDisplayProto = 13;
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
    if((p[idx] > 0) && ((p[idx]*100/total) > 1 /* the proto is at least 1% */)) {
      partialTotal += p[idx];
      lbl[idx] = myGlobals.ipTrafficProtosNames[i];
      idx++;
    }

    if(idx >= maxNumDisplayProto) break;
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
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
  int i, j, numPoints=0;
  char  *lbls[32], labels[32][8];
  FILE *fd;
  float graphData[60];
  int useFdOpen = 0;
  HostTraffic *el;

  memset(graphData, 0, sizeof(graphData));

  for(i=0; i<=30; i++) {
    safe_snprintf(__FILE__, __LINE__, labels[i], sizeof(labels[i]), "%d", i);
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

void hostFcTrafficDistrib(HostTraffic *theHost, short dataSent) {
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
  float p[MAX_NUM_PROTOS];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int i, num=0, explodePieces[MAX_NUM_PROTOS];
  FILE *fd;
  TrafficCounter traffic, totalFcTraffic, diffTraffic;
  char *lblstouse[] = { "SCSI", "FICON", "ELS", "NS", "IP/FC", "Others"};
  Counter protoTrafficSent[] = {
      theHost->fcCounters->fcFcpBytesSent.value,
      theHost->fcCounters->fcFiconBytesSent.value,
      theHost->fcCounters->fcElsBytesSent.value,
      theHost->fcCounters->fcDnsBytesSent.value,
      theHost->fcCounters->fcIpfcBytesSent.value,
      theHost->fcCounters->otherFcBytesSent.value,
  };

  Counter protoTrafficRcvd[] = {
      theHost->fcCounters->fcFcpBytesRcvd.value,
      theHost->fcCounters->fcFiconBytesRcvd.value,
      theHost->fcCounters->fcElsBytesRcvd.value,
      theHost->fcCounters->fcDnsBytesRcvd.value,
      theHost->fcCounters->fcIpfcBytesRcvd.value,
      theHost->fcCounters->otherFcBytesRcvd.value,
  };
  int useFdOpen = 0;

  totalFcTraffic.value = 0;
  diffTraffic.value = 0;

  if(dataSent)
      totalFcTraffic.value = theHost->fcCounters->fcBytesSent.value;
  else
      totalFcTraffic.value = theHost->fcCounters->fcBytesRcvd.value;
  
  if(totalFcTraffic.value > 0) {
      for (i = 0; i < 6; i++) {
          if(dataSent) 
              traffic.value = protoTrafficSent[i];
          else 
              traffic.value = protoTrafficRcvd[i];

          if(traffic.value > 0) {
              p[num] = (float)((100*traffic.value)/totalFcTraffic.value);
              diffTraffic.value += traffic.value;

              if(num == 0)
                  explodePieces[num]=10;
              else
                  explodePieces[num]=explodePieces[num-1];
              if (p[num]<5.0)
                  explodePieces[num]+=9;
              else if (p[num]>10.0)
                  explodePieces[num]=10;
              
              lbl[num++] = lblstouse[i];
          }
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
	  p, 1);			/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* ********************************** */

void fcPktSizeDistribPie(void) {
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
  float p[10];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "", ""};
  int num=0;
  FILE *fd;
  int useFdOpen = 0;

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo36.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo36.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 36";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo48.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo48.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 48";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo52.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo52.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 52";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo68.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo68.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 68";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo104.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo104.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 104";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo548.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo548.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 548";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo1060.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo1060.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 1060";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo2136.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo2136.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 2136";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.above2136.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.above2136.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "> 2136";
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
	  p, 0);			/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* ******************************** */

void drawGlobalFcProtoDistribution(void) {
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
  int idx=0;
  float p[256];
  char *lbl[256];
  FILE *fd;
  int useFdOpen = 0;

  p[myGlobals.numIpProtosToMonitor] = 0;

  if(myGlobals.device[myGlobals.actualReportDeviceId].fcFcpBytes.value) {
      p[idx]  = (float)myGlobals.device[myGlobals.actualReportDeviceId].fcFcpBytes.value;
      lbl[idx++] = "SCSI";
  }

  if (myGlobals.device[myGlobals.actualReportDeviceId].fcFiconBytes.value) {
      p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].fcFiconBytes.value;
      lbl[idx++] = "FICON";
  }

  if (myGlobals.device[myGlobals.actualReportDeviceId].fcElsBytes.value) {
      p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].fcElsBytes.value;
      lbl[idx++] = "ELS";
  }

  if (myGlobals.device[myGlobals.actualReportDeviceId].fcIpfcBytes.value) {
      p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].fcIpfcBytes.value;
      lbl[idx++] = "IP/FC";
  }

  if (myGlobals.device[myGlobals.actualReportDeviceId].fcDnsBytes.value) {
      p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].fcDnsBytes.value;
      lbl[idx++] = "NS";
  }

  if (myGlobals.device[myGlobals.actualReportDeviceId].fcSwilsBytes.value) {
      p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].fcSwilsBytes.value;
      lbl[idx++] = "SWILS";
  }

  if (myGlobals.device[myGlobals.actualReportDeviceId].otherFcBytes.value) {
      p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].otherFcBytes.value;
      lbl[idx++] = "Others";
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
	  fd,		/* open file pointer */
	  idx,		/* number of slices */
	  lbl,		/* slice labels */
	  p);		/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* *******************************************************/

void drawLunStatsBytesDistribution (HostTraffic *el) {
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
  int lun, numEntries, idx=0;
  float p[MAX_LUNS_GRAPHED+1];
  char *lbl[MAX_LUNS_GRAPHED+1];
  char label[MAX_LUNS_GRAPHED+1][10];
  LunStatsSortedEntry sortedLunTbl[MAX_LUNS_SUPPORTED];
  LunStatsSortedEntry *entry;
  FILE *fd;
  int useFdOpen = 0;
  ScsiLunTrafficInfo *lunStats;

  p[MAX_LUNS_GRAPHED] = 0;
  numEntries = 0;

  memset(sortedLunTbl, 0, sizeof (sortedLunTbl));

  for (lun=0, numEntries=0; lun < MAX_LUNS_SUPPORTED; lun++) {
    if ((lunStats = el->fcCounters->activeLuns[lun]) != NULL) {
          sortedLunTbl[numEntries].lun = lun;
          sortedLunTbl[numEntries++].stats = el->fcCounters->activeLuns[lun];
      }
  }

  myGlobals.columnSort = 4;     /* This is based on total I/O */
  qsort (sortedLunTbl, numEntries, sizeof (LunStatsSortedEntry), cmpLunFctn);

  idx = 0;
  for (lun = numEntries-1; ((idx < MAX_LUNS_GRAPHED) && (lun >= 0));
       lun--) {
      entry = &sortedLunTbl[lun];
      p[idx] = (float) (entry->stats->bytesSent.value +
                        entry->stats->bytesRcvd.value);
      if (p[idx] > 0) {
          safe_snprintf(__FILE__, __LINE__, label[idx], sizeof(label[idx]), "%hd", entry->lun);
          lbl[idx] = label[idx];
          idx++;
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

  drawBar (600, 250,	/* width/height */
           fd,		/* open file pointer */
           idx,     /* number of slices */
           lbl,		/* slice labels */
           p);		/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* *******************************************************/

void drawLunStatsPktsDistribution (HostTraffic *el) {
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
  int lun, numEntries, idx=0;
  float p[MAX_LUNS_GRAPHED+1];
  char *lbl[MAX_LUNS_GRAPHED+1];
  char label[MAX_LUNS_GRAPHED+1][10];
  FILE *fd;
  int useFdOpen = 0;
  ScsiLunTrafficInfo *lunStats;
  LunStatsSortedEntry sortedLunTbl[MAX_LUNS_SUPPORTED];
  LunStatsSortedEntry *entry;

  p[MAX_LUNS_GRAPHED] = 0;
  numEntries = 0;

  memset(sortedLunTbl, 0, sizeof (sortedLunTbl));

  for (lun=0, numEntries=0; lun < MAX_LUNS_SUPPORTED; lun++) {
      if ((lunStats = el->fcCounters->activeLuns[lun]) != NULL) {
          sortedLunTbl[numEntries].lun = lun;
          sortedLunTbl[numEntries++].stats = el->fcCounters->activeLuns[lun];
      }
  }

  myGlobals.columnSort = 5;     /* This is based on total frames */
  qsort (sortedLunTbl, numEntries, sizeof (LunStatsSortedEntry), cmpLunFctn);
  
  for (lun = numEntries-1; ((idx < MAX_LUNS_GRAPHED) && (lun >= 0));
       lun--) {
      entry = &sortedLunTbl[lun];
      p[idx] = (float) (entry->stats->pktRcvd +
                        entry->stats->pktSent);
      if (p[idx] > 0) {
          sprintf (label[idx],"%hd", entry->lun);
          lbl[idx] = label[idx];
          idx++;
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

  drawBar (600, 250,	/* width/height */
           fd,		/* open file pointer */
           idx,     /* number of slices */
           lbl,		/* slice labels */
           p);		/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* *******************************************************/

void drawVsanStatsBytesDistribution (int deviceId) {
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
  int numVsans, idx=0, i, j;
  float p[MAX_VSANS_GRAPHED+1];
  char *lbl[MAX_VSANS_GRAPHED+1];
  char label[MAX_VSANS_GRAPHED+1][10];
  FILE *fd;
  int useFdOpen = 0;
  FcFabricElementHash **theHash;
  FcFabricElementHash *tmpTable[MAX_ELEMENT_HASH];
  
  if ((theHash = myGlobals.device[deviceId].vsanHash) == NULL) {
      return;
  }

  p[MAX_VSANS_GRAPHED] = 0;
  numVsans = 0;

  memset (tmpTable, sizeof (FcFabricElementHash *)*MAX_ELEMENT_HASH, 0);
  for (i=0; i<MAX_ELEMENT_HASH; i++) {
      if((theHash[i] != NULL) && (theHash[i]->vsanId < MAX_HASHDUMP_ENTRY) &&
         (theHash[i]->vsanId < MAX_USER_VSAN)) {
          if (theHash[i]->totBytes.value)
              tmpTable[numVsans++] = theHash[i];
      }
  }

  if (!numVsans) {
      printNoDataYet ();
      return;
  }
  
  myGlobals.columnSort = 3;
  qsort (tmpTable, numVsans, sizeof (FcFabricElementHash **), cmpVsanFctn);
  
  idx = 0;
  for (i = numVsans-1, j = 0; i >= 0; i--, j++) {
      if (tmpTable[i] != NULL) {
          p[idx] = tmpTable[i]->totBytes.value;
          if (tmpTable[i]->vsanId) {
              sprintf (label[idx], "%hd", tmpTable[i]->vsanId);
          }
          else {
              sprintf (label[idx], "N/A");
          }
          lbl[idx] = label[idx];
	  idx++;
      }

      if (j >= MAX_VSANS_GRAPHED)
          break;
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

  drawBar (600, 250,	/* width/height */
           fd,		/* open file pointer */
           idx,     /* number of slices */
           lbl,		/* slice labels */
           p);		/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* *******************************************************/

void drawVsanStatsPktsDistribution (int deviceId) {
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
  int numVsans, idx=0, i, j;
  float p[MAX_VSANS_GRAPHED+1];
  char *lbl[MAX_VSANS_GRAPHED+1];
  char label[MAX_VSANS_GRAPHED+1][10];
  FILE *fd;
  int useFdOpen = 0;
  FcFabricElementHash **theHash;
  FcFabricElementHash *tmpTable[MAX_ELEMENT_HASH];
  
  if ((theHash = myGlobals.device[deviceId].vsanHash) == NULL) {
      return;
  }

  p[MAX_VSANS_GRAPHED] = 0;
  numVsans = 0;

  memset (tmpTable, sizeof (FcFabricElementHash *)*MAX_ELEMENT_HASH, 0);
  for (i=0; i<MAX_ELEMENT_HASH; i++) {
      if((theHash[i] != NULL) && (theHash[i]->vsanId < MAX_HASHDUMP_ENTRY) &&
         (theHash[i]->vsanId < MAX_USER_VSAN)) {
          if (theHash[i]->totPkts.value)
              tmpTable[numVsans++] = theHash[i];
      }
  }

  if (!numVsans) {
      printNoDataYet ();
      return;
  }
  
  myGlobals.columnSort = 4;
  qsort (tmpTable, numVsans, sizeof (FcFabricElementHash **), cmpVsanFctn);
  
  idx = 0;
  for (i = numVsans-1, j = 0; i >= 0; i--, j++) {
      if (tmpTable[i] != NULL) {
          p[idx] = tmpTable[i]->totPkts.value;
          if (tmpTable[i]->vsanId) {
              sprintf (label[idx], "%d", tmpTable[i]->vsanId);
          }
          else {
              sprintf (label[idx], "N/A");
          }
	  
          lbl[idx] = label[idx];
	  idx++;
      }

      if (j >= MAX_VSANS_GRAPHED)
          break;
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

  drawBar (600, 250,	/* width/height */
           fd,		/* open file pointer */
           idx,     /* number of slices */
           lbl,		/* slice labels */
           p);		/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* *******************************************************/

void drawVsanSwilsProtoDistribution(u_short vsanId) {
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
  int idx=0;
  FcFabricElementHash *hash;
  float p[256];
  char *lbl[256];
  FILE *fd;
  int useFdOpen = 0;

  p[myGlobals.numIpProtosToMonitor] = 0;

  hash = getFcFabricElementHash (vsanId, myGlobals.actualReportDeviceId);
  
  p[0] = (float)hash->dmBytes.value;
  if (p[0] > 0) {
      p[myGlobals.numIpProtosToMonitor] += p[0];
      lbl[idx++] = "DM";
  }

  p[1] = (float)hash->fspfBytes.value;
  if (p[1] > 0) {
      p[myGlobals.numIpProtosToMonitor] += p[1];
      lbl[idx++] = "FSPF";
  }

  p[2] = (float)hash->nsBytes.value;
  if (p[2] > 0) {
      p[myGlobals.numIpProtosToMonitor] += p[2];
      lbl[idx++] = "NS";
  }

  p[3] = (float)hash->zsBytes.value;
  if (p[3] > 0) {
      p[myGlobals.numIpProtosToMonitor] += p[3];
      lbl[idx++] = "ZS";
  }

  p[4] = (float)hash->rscnBytes.value;
  if (p[4] > 0) {
      p[myGlobals.numIpProtosToMonitor] += p[4];
      lbl[idx++] = "SW_RSCN";
  }

  p[5] = (float)hash->fcsBytes.value;
  if (p[5] > 0) {
      p[myGlobals.numIpProtosToMonitor] += p[5];
      lbl[idx++] = "FCS";
  }

  p[6] = (float)hash->otherCtlBytes.value;
  if (p[6] > 0) {
      p[myGlobals.numIpProtosToMonitor] += p[6];
      lbl[idx++] = "Others";
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

  drawPie (600, 250,	/* width/height */
           fd,		/* open file pointer */
           idx,		/* number of slices */
           lbl,		/* slice labels */
           p, 1);		/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}

/* *******************************************************/

void drawVsanDomainTrafficDistribution(u_short vsanId, u_char dataSent) {
  char fileName[NAME_MAX] = "/tmp/ntop-graph-XXXXXX";
  int i, idx=0, numEntries = 0;
  FcFabricElementHash *hash;
  float p[MAX_VSANS_GRAPHED+1];
  char *lbl[MAX_VSANS_GRAPHED+1], labels[MAX_VSANS_GRAPHED+1][8];
  FILE *fd;
  int useFdOpen = 0;
  Counter total;
  SortedFcDomainStatsEntry *fcDomainStats;

  p[MAX_FC_DOMAINS+1] = 0;

  hash = getFcFabricElementHash (vsanId, myGlobals.actualReportDeviceId);

  if (hash == NULL) {
      printNoDataYet();
      return;
  }

  fcDomainStats = (SortedFcDomainStatsEntry *)malloc (MAX_FC_DOMAINS*sizeof (SortedFcDomainStatsEntry));
  if (fcDomainStats == NULL) {
      traceEvent (CONST_TRACE_WARNING, "Unable to allocate memory for SortedFcDomainStatsEntry\n");
      printNoDataYet();
      return;
  }
  memset (fcDomainStats, 0, MAX_FC_DOMAINS*sizeof (SortedFcDomainStatsEntry));
  
  for (i = 1; i < MAX_FC_DOMAINS; i++) {
      if (dataSent) {
          if (hash->domainStats[i].sentBytes.value) {
              fcDomainStats[numEntries].domainId = i;
              fcDomainStats[numEntries++].stats = &hash->domainStats[i];
          }
      }
      else {
          if (hash->domainStats[i].rcvdBytes.value) {
              fcDomainStats[numEntries].domainId = i;
              fcDomainStats[numEntries++].stats = &hash->domainStats[i];
          }
      }
  }

  if (numEntries == 0) {
      printNoDataYet();
      return;
  }

  myGlobals.columnSort = dataSent;
  qsort (fcDomainStats, numEntries, sizeof (SortedFcDomainStatsEntry), cmpFcDomainFctn);
  
  for (i = numEntries-1; (idx < MAX_VSANS_GRAPHED) && (i >= 0); i--) {
      if (dataSent) {
          total = fcDomainStats[i].stats->sentBytes.value;
      }
      else {
          total = fcDomainStats[i].stats->rcvdBytes.value;
      }
      if (total > 0) {
          p[idx] = (float)total;
          sprintf (labels[idx], "%x", fcDomainStats[i].domainId);
          lbl[idx] = labels[idx];
          idx++;
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
	  fd,		/* open file pointer */
	  idx,		/* number of slices */
	  lbl,		/* slice labels */
	  p);		/* data array */

  fclose(fd);

  if(!useFdOpen)
    sendGraphFile(fileName, 0);
}


#endif /* EMBEDDED */
