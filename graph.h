/*
 *  Copyright (C) 1998-2000 Luca Deri <deri@ntop.org>
 *                      
 *  			  Centro SERRA, University of Pisa
 *  			  http://www.ntop.org/
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

#ifndef GRAPH_H
#define GRAPH_H


/* Simplified interface to gdchart */

typedef enum {
  GDC_LINE,
  GDC_AREA,
  GDC_BAR,
  GDC_HILOCLOSE,
  GDC_COMBO_LINE_BAR,
  GDC_COMBO_HLC_BAR,
  GDC_COMBO_LINE_AREA,
  GDC_COMBO_HLC_AREA,
  GDC_3DHILOCLOSE,
  GDC_3DCOMBO_LINE_BAR,
  GDC_3DCOMBO_LINE_AREA,
  GDC_3DCOMBO_HLC_BAR,
  GDC_3DCOMBO_HLC_AREA,
  GDC_3DBAR,
  GDC_3DAREA,
  GDC_3DLINE
} GDC_CHART_T;


typedef enum {
  GDC_3DPIE,
  GDC_2DPIE
} GDCPIE_TYPE;

extern unsigned long  GDCPIE_LineColor;
extern int* GDCPIE_explode;
extern unsigned long* GDCPIE_Color;
extern unsigned long  GDCPIE_BGColor;
extern unsigned long  GDCPIE_EdgeColor;
extern unsigned long  GDC_BGColor;
extern unsigned long  GDC_LineColor;
extern unsigned long  *GDC_SetColor;
extern char* GDC_title;
extern char* GDC_ytitle;
extern char* GDC_xtitle;
extern char* GDC_ytitle2;
extern char* GDC_title;


extern int GDC_out_graph(short	gifwidth,
			 short	gifheight,  
			 FILE	*gif_fptr,
			 GDC_CHART_T type,
			 int  num_points,
			 char *xlbl[],
			 int  num_sets,
			 ... );

extern void pie_gif(short width,
		    short height,
		    FILE*,
		    GDCPIE_TYPE,
		    int  num_points,
		    char *labels[],
		    float data[]);

#endif /* GRAPH_H */
