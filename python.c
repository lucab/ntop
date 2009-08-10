/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 *                          http://www.ntop.org
 *
 *             Copyright (C) 2009 Luca Deri <deri@ntop.org>
 *                                Daniele Sgandurra <sgandurra@ntop.org>
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


#include "ntop.h"
#include "globals-report.h"

#ifdef HAVE_PYTHON

#include "Python.h" 

static HostTraffic *ntop_host = NULL;
static char query_string[2048];

/* **************************************** */

static PyObject* python_sendHTTPHeader(PyObject *self,
				       PyObject *args) {
  int mime_type;
  
  if(!PyArg_Parse(args, "d", &mime_type)) return NULL;
    
  sendHTTPHeader(mime_type /* FLAG_HTTP_TYPE_HTML */, 0, 0);
  return PyString_FromString("");
}

/* **************************************** */

static PyObject* python_printHTMLHeader(PyObject *self,
				       PyObject *args) {
  char *title;
  
  if(!PyArg_Parse(args, "s", &title)) return NULL;
    
  printHTMLheader(title, NULL, 0);
  return PyString_FromString("");
}

/* **************************************** */

static PyObject* python_printHTMLFooter(PyObject *self,
				       PyObject *args) {
  printHTMLtrailer();
  return PyString_FromString("");
}

/* **************************************** */

static PyObject* python_sendString(PyObject *self,
				   PyObject *args) {
  char *msg;
  
  /* parse the incoming arguments */
  if (!PyArg_Parse(args, "s", &msg)) {
      return NULL;
    }

  sendString(msg);
  return PyString_FromString("");
}

/* **************************************** */

static PyObject* python_getFirstHost(PyObject *self,
				     PyObject *args) {
  int actualDeviceId;
  
  /* parse the incoming arguments */
  if(!PyArg_Parse(args, "d", &actualDeviceId))
    return NULL;
    
  ntop_host = getFirstHost(actualDeviceId);
  
  //return PyString_FromString(ntop_host ? "1" : "0");
  return Py_BuildValue("i", ntop_host ? 1 : 0);
}

/* **************************************** */

static PyObject* python_getNextHost(PyObject *self,
				    PyObject *args) {
  int actualDeviceId;
  
  /* parse the incoming arguments */
  if(!PyArg_Parse(args, "d", &actualDeviceId))
    return NULL;

  if(ntop_host == NULL)
    ntop_host = getFirstHost(actualDeviceId);
  else 
    ntop_host = getNextHost(actualDeviceId, ntop_host);  

  //return PyString_FromString(ntop_host ? "1" : "0");
  return Py_BuildValue("i", ntop_host ? 1 : 0);

}

/* **************************************** */

static PyObject* python_ethAddress(PyObject *self,
				   PyObject *args) {
  return PyString_FromString(ntop_host ? ntop_host->ethAddressString : "");
}

/* **************************************** */

static PyObject* python_ipAddress(PyObject *self,
				   PyObject *args) {
  return PyString_FromString(ntop_host ? ntop_host->hostNumIpAddress : "");
}

/* **************************************** */

static PyMethodDef ntop_methods[] = {
  { "sendHTTPHeader", python_sendHTTPHeader },

  { "printHTMLHeader", python_printHTMLHeader },
  { "printHTMLFooter", python_printHTMLFooter },
  { "sendString", python_sendString },

  { "getFirstHost", python_getFirstHost },
  { "getNextHost",  python_getNextHost },

  { NULL, NULL}
};

/* **************************************** */

static PyMethodDef host_methods[] = {
  { "ethAddress", python_ethAddress },
  { "ipAddress",  python_ipAddress },

  { NULL, NULL}
};

/* **************************************** */

static void init_python_ntop(void) {
  Py_InitModule("ntop", ntop_methods);
  Py_InitModule("host", host_methods);
}

/* **************************************** */

int handlePythonHTTPRequest(char *url) {
  int idx, found = 0;
  char python_path[256];
  struct stat statbuf;
  FILE *fd;
  char *question_mark = strchr(url, '?');

  traceEvent(CONST_TRACE_INFO, "Calling python... [%s]", url);

  if(question_mark) question_mark[0] = '\0';
  safe_snprintf(__FILE__, __LINE__, query_string, sizeof(query_string)-1, "%s", question_mark ? &question_mark[1] : "");

  for(idx=0; (!found) && (myGlobals.dataFileDirs[idx] != NULL); idx++) {
    safe_snprintf(__FILE__, __LINE__, python_path, sizeof(python_path),
		  "%s/python/%s", myGlobals.dataFileDirs[idx], url);
    revertSlashIfWIN32(python_path, 0);

    if(!stat(python_path, &statbuf)) {
      /* Found */
      /* traceEvent(CONST_TRACE_INFO, "[python] [%d] Found %s", idx, python_path); */
      found = 1;
      break;
    } else {
      /* traceEvent(CONST_TRACE_INFO, "[python] [%d] Not found %s", idx, python_path); */
    }
  }

  if(!found) {
    returnHTTPpageNotFound(NULL);
    return(1);
  }

  /* ********************************* */

  traceEvent(CONST_TRACE_INFO, "[PYTHON] Executing %s", 
	     python_path);

  /* Pass argv[0] to the Python interpreter */
  Py_SetProgramName(python_path);

  /* Initialize the Python interpreter.  Required. */
  Py_Initialize();

  /* Initialize ntop module */
  init_python_ntop();

  if((fd = fopen(python_path, "r")) != NULL)
    PyRun_SimpleFile(fd, python_path);

  /* Cleaning up the interpreter */
  Py_Finalize();

  return(1);
}


#endif /* HAVE_PYTHON */
