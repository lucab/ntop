/*
 *  RRD-alarm  --  Round-Robin Database alarm.
 *  Copyright (C) 2003 Daniele Sgandurra <sgandurr@cli.di.unipi.it>
 *
 *  ----------------------------------------------------------------
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#define _GNU_SOURCE


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <signal.h>
#include "rrd.h"


#define MAX 260
#define IFERROR(s, m) if((s) == -1) {perror(m); exit(errno);}
#define ERR_MALLOC(v) if((v) == NULL) {perror("Malloc"), exit(errno);}
#define PARAMS(v, m) v = strtok(m, "\t"); if(v == NULL){ return (-1);}


typedef struct interval {
  time_t start;
  time_t end;
  int times;
  struct interval *next;
} Interval;


void usage();
void usage_file();
void usage_help();
void about();
int prepare_params(char *command_line, unsigned int *line_id,
                   char **rrd_filename, char **thresholdType,
                   double *threshold, int *rep, char **my_start,
                   char **myEnd, char **action,  unsigned int *rearm);


int main(int argc, char *argv[])
{
  char          *rrd_argv[32];
  int           my_argc = 0, rc, i;
  time_t        start, end, j, i_time;
  unsigned long step, ds_cnt;
  rrd_value_t   *data,*datai, *dataj, val, val2;
  char          **ds_namv;
  char          *filename, *my_start, *my_end;


  double        threshold;
  int           ind ,rep, fd, times, alarm;
  Interval      *Intervals, *p_Intervals;
  int           total = 0;
  FILE          *file;
  char          *rrd_filename;
  size_t        length, zero = 0;
  unsigned int  line_id;
  char          **command_line, *params = NULL;
  int           n_commands = 0;
  char          *action;
  unsigned int  rearm;
  char          *thresholdType;
  int           c_command;
  char          sdir[MAX] = ".rrd_alarm-saved";
  int           ch;
  int           o_help = 0;
  int           o_verbose = 0;
  int           o_vverbose = 0;


  if(argc < 2)
    {
      about();
      usage();
      exit(1);
    }
  while((ch = getopt(argc, argv, "hvVd:")) != -1)
    {
      switch (ch)
	{
	case 'h':
	  o_help = 1;
	  break;
	case 'v':
	  o_verbose = 1;
	  break;
	case 'V':
	  o_verbose = 1;
	  o_vverbose = 1;
	  break;
	case 'd':
	  strncpy(sdir, optarg, MAX - 1);
	  break;
	}
    }
  if(o_help)
    {
      usage_help();
      exit(0);
    }
  if(optind >= argc)
    {
      usage();
      exit(1);
    }


  filename = argv[argc - 1];
  IFERROR((fd = open(filename, O_RDONLY)), filename);
  close(fd);
  file = fopen(filename, "r");
  command_line = (char **) malloc(sizeof(char *));
  ERR_MALLOC(command_line);
  while((length = getline(&params, &zero, file)) != -1)
    {
      if(strchr(params, '#') != params) /* skip commented lines */
	{
	  command_line[n_commands++] = params;
	  params = NULL;
	  command_line = (char **) realloc(command_line, (n_commands + 1) * sizeof(char *));
	  ERR_MALLOC(command_line);
	}
    }
  fclose(file);


  for(c_command = 0; c_command < n_commands; c_command++)
    {
      int err = 0;
      alarm = 0;
      times = 0;
      optind = 1;
      Intervals = NULL;
      p_Intervals = NULL;
      err = prepare_params(command_line[c_command], &line_id, &rrd_filename, &thresholdType, &threshold, &rep, &my_start, &my_end, &action, &rearm);
      if(err != 0)
	{
	  printf("\nSintax error in line %d of the configuration file\n", c_command + 1);
	  fflush(stdin);
	  free(command_line[c_command]);
	  continue;
	}
      my_argc = 0;
      rrd_argv[my_argc++] = "rrd_fetch";
      rrd_argv[my_argc++] = rrd_filename;
      rrd_argv[my_argc++] = "AVERAGE";
      rrd_argv[my_argc++] = "--start";
      rrd_argv[my_argc++] = my_start;
      rrd_argv[my_argc++] = "--end";
      rrd_argv[my_argc++] = my_end;


      ind = !strcmp(thresholdType, "below") ? 0: 1; /* 0 = below; 1 = above */
      rc = rrd_fetch(my_argc , rrd_argv, &start, &end, &step, &ds_cnt, &ds_namv, &data);
      if(rc == -1)
	{
	  printf("\nError while calling rrd_fetch(): %s\n", rrd_get_error());
	  free(command_line[c_command]);
	  continue;
	}
      if(o_verbose)
	{
	  time_t c_time = time(0);
	  char c_date[25];
	  strncpy(c_date, ctime(&c_time), 24);
	  c_date[24] = '\0';
	  printf("\n%s [%s:%d]\n", c_date, filename, line_id);
	  printf("Reading file: %s...\n", rrd_filename); 
	}
      datai = data;
      total = 0;
      for(j = start; j <= end; j += step)
	{
	  val = *(datai++);
	  if(val > 0)
	    {
	      if(!ind) /* below */
		{
		  if(val < threshold)
		    {
		      times++;
		      if(times == rep)
			{
			  alarm = 1;
			  i_time = j - rep*step;
			  dataj = datai - rep;
			  val2 = *dataj;
			  if(Intervals == NULL)
			    {
			      Intervals = malloc(sizeof(Interval));
			      ERR_MALLOC(Intervals);
			      p_Intervals = Intervals;
			    }
			  else
			    {
			      Intervals->next = malloc(sizeof(Interval));
			      ERR_MALLOC(Intervals);
			      Intervals = Intervals->next;
			    }
			  Intervals->start = i_time;
			  total = 0;
			  if(o_vverbose)
			    {
			      printf("------------------------------------------\n");
			    }
			  while(i_time < end && val2 < threshold)
			    {
			      if(o_vverbose)
				{
				  printf("%15f - %s", val2, ctime(&i_time));
				}
			      i_time += step;
			      val2 = *(++dataj);
			      total++;
			    }
			  Intervals->end = i_time - step;
			  Intervals->times = total;
			  Intervals->next = NULL;
			}
		    }
		  else
		    {
		      times = 0;
		    }
		}
	      else  /* above */
		{
		  if(val > threshold)
		    {
		      times++;
		      if(times == rep)
			{
			  alarm = 1;
			  i_time = j - rep*step;
			  dataj = datai - rep;
			  val2 = *dataj;
			  if(Intervals == NULL)
			    {
			      Intervals = malloc(sizeof(Interval));
			      ERR_MALLOC(Intervals);
			      p_Intervals = Intervals;
			    }
			  else
			    {
			      Intervals->next = malloc(sizeof(Interval));
			      ERR_MALLOC(Intervals);
			      Intervals = Intervals->next;
			    }
			  Intervals->start = i_time;
			  total = 0;
			  if(o_vverbose)
			    {
			      printf("------------------------------------------\n");
			    }
			  while(i_time < end && val2 > threshold)
			    {
			      if(o_vverbose)
				{
				  printf("%15f - %s", val2, ctime(&i_time));
				}
			      i_time += step;
			      val2 = *(++dataj);
			      total++;
			    }
			  Intervals->end = i_time - step;
			  Intervals->times = total;
			  Intervals->next = NULL;
			}
		    }
		  else
		    {
		      times = 0;
		    }
		}
	    }
	  else
	    {
	      times = 0;
	    }
	}


      if(alarm)
	{
	  char   save_filename[MAX];
	  time_t last_time;
	  time_t c_time = time(0);
	  int    n_bytes;
	  int    send_alarm = 0;
	  int    n_intervals = 0;
	  DIR    *dir;
	  char   *filename2 = strrchr(filename, '/') == NULL ? filename : strrchr(filename, '/') + 1;

	  if((dir = opendir(sdir)) == NULL)
	    {
	      IFERROR(mkdir(sdir, 0744), "Creating the directory");
	    }
	  else
	    {
	      IFERROR(closedir(dir), "Closing the directory");
	    }
	  sprintf(save_filename, "%s/%s-%d-last_alarm", sdir, filename2, line_id);
	  IFERROR(fd = open(save_filename, O_RDWR | O_CREAT, 0644), "Error while opening file");
	  IFERROR(n_bytes = read(fd, &last_time, sizeof(time_t)), "Error while reading file");
	  if(n_bytes == 0)
	    {
	      IFERROR(write(fd, &c_time, sizeof(time_t)), "Error while updating data file");
	      send_alarm = 1;
	    }
	  else
	    {
	      if(last_time + rearm < c_time)
		{
		  lseek(fd, 0, SEEK_SET);
		  IFERROR(write(fd, &c_time, sizeof(time_t)), "Error while updating data file");
		  send_alarm = 1;
		}
	    }
	  close(fd);


	  if(o_vverbose)
	    {
	      printf("------------------------------------------\n");
	    }
	  while(p_Intervals != NULL)
	    {
	      if(o_verbose)
		{
		  printf("Interval:\n");
		  printf("\tStart = %s", ctime(&p_Intervals->start));
		  printf("\tEnd =  %s", ctime(&p_Intervals->end));
		  printf("\t%d time/s %s %.2f \n", p_Intervals->times, thresholdType, threshold);
		}
	      n_intervals++;
	      free(p_Intervals);
	      p_Intervals = p_Intervals->next;
	    }
	  if(o_verbose)
	    {
	      printf("%d interval/s found\n", n_intervals);
	    }
	  if(send_alarm)
	    {
	      system(action);
	    }
	}
      else
	{
	  if( o_verbose)
	    {
	      printf("No intervals matching the criteria were found\n");
	    }
	}


      for(i = 0;i < ds_cnt; i++)
	{
	  free(ds_namv[i]);
	}
      free(ds_namv);
      free(data);
      free(command_line[c_command]);
    }
  free(command_line);
  return (0);
}


int prepare_params(char *command_line, unsigned int *line_id, char **rrd_filename, 
                   char **thresholdType, double *threshold, int *rep, char **my_start,
                   char **my_end, char **action, unsigned int *rearm)
{
  char *param;


  PARAMS(param, command_line);
  *line_id = atoi(param);


  PARAMS(param, NULL);
  *rrd_filename = param;


  PARAMS(param, NULL);
  *thresholdType = param;


  PARAMS(param, NULL);
  *threshold = atof(param);


  PARAMS(param, NULL);
  *rep = atoi(param);


  PARAMS(param, NULL);
  *my_start = param;


  PARAMS(param, NULL);
  *my_end = param;


  PARAMS(param, NULL);
  *action = param;


  PARAMS(param, NULL);
  *rearm = atoi(param);


  return (0);
}


void usage()
{
  printf("\nUsage: rrd_alarm filename [option:parameter]\n"
	 "Filename is the name of the configuration file\n");
  printf("Valid options are:\n"
	 "\t\t-d directory \tChange default directory (./.rrd_alarm-saved)\n"
	 "\t\t\t\tcontaining files used for determining last alarms\n"
	 "\t\t-h\t\tPrint a small usage guide\n"
	 "\t\t-v\t\tVerbose\n"
	 "\t\t-V\t\tVery verbose (implies -v)\n");
}


void usage_file()
{
  printf("\nConfiguration file must have the following syntax:\n"
	 "id\tfile\tbelow|above\tthreshold\tminRepetitions\tstart\tend\taction\trearm\n");
  printf("Where:\n"
	 "#id:\t\tunique identifier of the command line\n"
	 "#file:\t\tpath of the RRD file\n"
	 "#below|above:\tthreshold type\n"
	 "#threshold:\tthreshold value\n"
	 "#minRepetitions:min number of threshold boundaries\n"
	 "#start:\t\tbegin (time)\n"
	 "#end:\t\tend (time)\n"
	 "#action:\taction to perform if threshold is verified\n"
	 "#rearm:\t\tmin time (sec) between two consecutive alarms\n");
  printf("Every params separated by a TAB.\n"
	 "Lines beginning with # are ignored. You can put as many lines as you like.\n");
}


void usage_help()
{
  usage();
  usage_file();
}


void about()
{
  printf("RRD-alarm 1.0.1 Copyright (C) 2003 by Daniele Sgandurra <sgandurr@cli.di.unipi.it>\n\n");
  printf("Distributed under the Terms of the GNU General Public License Version 2.\n");
  printf("Visit www.gnu.org/copyleft/gpl.html for more information.\n");
}
