/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 *                          http://www.ntop.org
 *
 *             Copyright (C) 2009 Luca Deri <deri@ntop.org>
 *                                Daniele Sgandurra <sgandurra@ntop.org>
 *                                Jaime Blasco <jaime.blasco@alienvault.com>
 *                                Gianluca Medici <gianluca_medici@tin.it>
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
static pthread_mutex_t python_mutex;

/* **************************************** */

static PyObject* python_sendHTTPHeader(PyObject *self, PyObject *args) {
  int mime_type;

  // traceEvent(CONST_TRACE_WARNING, "-%s-", "python_sendHTTPHeader");
  
  if(!PyArg_ParseTuple(args, "i", &mime_type)) return NULL;
    
  sendHTTPHeader(mime_type /* FLAG_HTTP_TYPE_HTML */, 0, 0);
  return PyString_FromString("");
}

/* **************************************** */

static PyObject* python_printHTMLHeader(PyObject *self,
				       PyObject *args) {
  char *title;
  
  // traceEvent(CONST_TRACE_WARNING, "-%s-", "python_printHTMLHeader");

  if(!PyArg_ParseTuple(args, "s", &title)) return NULL;
    
  printHTMLheader(title, NULL, 0);
  return PyString_FromString("");
}

/* **************************************** */

static PyObject* python_printHTMLFooter(PyObject *self,
				       PyObject *args) {

  // traceEvent(CONST_TRACE_WARNING, "-%s-", "python_printHTMLFooter");

  printHTMLtrailer();
  return PyString_FromString("");
}

/* **************************************** */

static PyObject* python_sendString(PyObject *self,
				   PyObject *args) {
  char *msg;
  
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_sendString");
  
  /* parse the incoming arguments */
  if (!PyArg_ParseTuple(args, "s", &msg)) {
      return NULL;
    }

  sendString(msg);
  return PyString_FromString("");
}

/* **************************************** */

static PyObject* python_getFirstHost(PyObject *self,
				     PyObject *args) {
  int actualDeviceId;

  // traceEvent(CONST_TRACE_WARNING, "-%s- [%p]", "python_getFirstHost", ntop_host);
  
  /* parse the incoming arguments */
  if(!PyArg_ParseTuple(args, "i", &actualDeviceId))
    return NULL;
    
  ntop_host = getFirstHost(actualDeviceId);
  
  //Return PyString_FromString(ntop_host ? "1" : "0");
  return Py_BuildValue("i", ntop_host ? 1 : 0);
}

/* **************************************** */

static PyObject* python_findHostByNumIP(PyObject *self,
					PyObject *args) {
  char *hostIpAddress;
  int vlanId;
  int actualDeviceId;
  HostAddr addr;

  // traceEvent(CONST_TRACE_WARNING, "-%s- [%p]", "python_findHostByNumIP", ntop_host);

  /* parse the incoming arguments */
  if(!PyArg_ParseTuple(args, "sii", &hostIpAddress, &vlanId, &actualDeviceId))
    return NULL;

  addr.Ip4Address.s_addr = inet_addr(hostIpAddress); /* FIX: add IPv6 support */    
  ntop_host = findHostByNumIP(addr, vlanId, actualDeviceId);
  
  return Py_BuildValue("i", ntop_host ? 1 : 0);
}

/* **************************************** */

static PyObject* python_getPreference(PyObject *self,
				      PyObject *args) {
  char *key, value[512] = { '\0' };
  int rc;
  
  if(!PyArg_ParseTuple(args, "s", &key)) return NULL;
    
  rc = fetchPrefsValue(key, value, sizeof(value));
  return PyString_FromString(rc == 0 ? value : "");
}

/* **************************************** */

static PyObject* python_getNextHost(PyObject *self,
				    PyObject *args) {
  int actualDeviceId;

  //traceEvent(CONST_TRACE_WARNING, "-%s- [%p]", "python_getNextHost", ntop_host);
  
  /* parse the incoming arguments */
  if(!PyArg_ParseTuple(args, "i", &actualDeviceId))
    return NULL;

  if(ntop_host != NULL)
    ntop_host = getNextHost(actualDeviceId, ntop_host);  
  else
    ntop_host = getFirstHost(actualDeviceId);

  //return PyString_FromString(ntop_host ? "1" : "0");
  return Py_BuildValue("i", ntop_host ? 1 : 0);

}

/* **************************************** */

static PyObject* python_hostSerial(PyObject *self,
				   PyObject *args) {
  char buf[64];

  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_hostSerial");
  return PyString_FromString(ntop_host ? serial2str(ntop_host->hostSerial, buf, sizeof(buf)) : "");
}

/* **************************************** */

static PyObject* python_ethAddress(PyObject *self,
				   PyObject *args) {

  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ethAddress");
  return PyString_FromString(ntop_host ? ntop_host->ethAddressString : "");
}

/* **************************************** */

static PyObject* python_ipAddress(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyString_FromString((ntop_host && ntop_host->hostNumIpAddress) ? ntop_host->hostNumIpAddress : "");
}


/* **************************************** */

static PyObject* python_hostResolvedName(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyString_FromString((ntop_host && ntop_host->hostResolvedName) ? ntop_host->hostResolvedName : "");
}

/* **************************************** */

static PyObject* python_hostTrafficBucket(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  //return PyString_FromFormat((ntop_host && ntop_host->hostResolvedName) ? ntop_host->hostResolvedName : "");
  return PyString_FromFormat("%u", ntop_host->hostTrafficBucket);
}

/* **************************************** */

static PyObject* python_numHostSessions(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyString_FromFormat("%u", ntop_host->numHostSessions);
}

/* **************************************** */

static PyObject* python_vlanId(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyString_FromFormat("%u", ntop_host->vlanId);
}

/* **************************************** */

static PyObject* python_networkMask(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyString_FromFormat("%u", ntop_host->network_mask);
}

/* **************************************** */

static PyObject* python_hwModel(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyString_FromString((ntop_host && ntop_host->hwModel) ? ntop_host->hwModel : "");
}

/* **************************************** */

static PyObject* python_isFTPhost(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isFTPhost(ntop_host));
}

/* **************************************** */

static PyObject* python_isServer(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isServer(ntop_host));
}

/* **************************************** */

static PyObject* python_isWorkstation(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isWorkstation(ntop_host));
}

/* **************************************** */

static PyObject* python_isMasterBrowser(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isMasterBrowser(ntop_host));
}

/* **************************************** */

static PyObject* python_isMultihomed(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isMultihomed(ntop_host));
}

/* **************************************** */

static PyObject* python_isMultivlaned(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isMultivlaned(ntop_host));
}

/* **************************************** */

static PyObject* python_isPrinter(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isPrinter(ntop_host));
}

/* **************************************** */

static PyObject* python_isSMTPhost(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isSMTPhost(ntop_host));
}

/* **************************************** */

static PyObject* python_isPOPhost(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isPOPhost(ntop_host));
}

/* **************************************** */

static PyObject* python_isIMAPhost(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isIMAPhost(ntop_host));
}

/* **************************************** */

static PyObject* python_isDirectoryHost(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isDirectoryHost(ntop_host));
}

/* **************************************** */

static PyObject* python_isHTTPhost(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isHTTPhost(ntop_host));
}

/* **************************************** */

static PyObject* python_isWINShost(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isWINShost(ntop_host));
}

/* **************************************** */

static PyObject* python_isBridgeHost(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isBridgeHost(ntop_host));
}

/* **************************************** */

static PyObject* python_isVoIPClient(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isVoIPClient(ntop_host));
}

/* **************************************** */

static PyObject* python_isVoIPGateway(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isVoIPGateway(ntop_host));
}

/* **************************************** */

static PyObject* python_isVoIPHost(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isVoIPHost(ntop_host));
}

/* **************************************** */

static PyObject* python_isDHCPClient(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isDHCPClient(ntop_host));
}

/* **************************************** */

static PyObject* python_isDHCPServer(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isDHCPServer(ntop_host));
}

/* **************************************** */

static PyObject* python_isP2P(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isP2P(ntop_host));
}

/* **************************************** */

static PyObject* python_isNtpServer(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyBool_FromLong(isNtpServer(ntop_host));
}

/* **************************************** */

static PyObject* python_totContactedSentPeers(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyString_FromFormat("%lu", (unsigned long)(ntop_host->totContactedSentPeers));
}

/* **************************************** */

static PyObject* python_totContactedRcvdPeers(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyString_FromFormat("%lu", (unsigned long)(ntop_host->totContactedRcvdPeers));
}

/* **************************************** */

static PyObject* python_fingerprint(PyObject *self, PyObject *args) {
  return PyString_FromString((ntop_host && ntop_host->fingerprint) ? ntop_host->fingerprint : "");
}

/* **************************************** */

static PyObject* python_pktsSent(PyObject *self, PyObject *args) {
  return PyString_FromFormat("%lu", (unsigned long)(ntop_host->pktSent.value));
}

static PyObject* python_pktsRcvd(PyObject *self, PyObject *args) {
  return PyString_FromFormat("%lu", (unsigned long)(ntop_host->pktRcvd.value));
}

/* **************************************** */

static PyObject* python_bytesSent(PyObject *self, PyObject *args) {
  return PyString_FromFormat("%lu", (unsigned long)(ntop_host->bytesSent.value));
}

static PyObject* python_bytesRcvd(PyObject *self, PyObject *args) {
  return PyString_FromFormat("%lu", (unsigned long)(ntop_host->bytesRcvd.value));
}

/* **************************************** */

#ifdef HAVE_GEOIP

#define VAL(a) ((a != NULL) ? a : "")

static PyObject* python_getGeoIP(PyObject *self, PyObject *args) {
  PyObject *obj = PyDict_New();
  GeoIPRecord *geo = (ntop_host && ntop_host->geo_ip) ? ntop_host->geo_ip : NULL;

  if(geo != NULL) {
    PyDict_SetItem(obj, PyString_FromString("country_code"), PyString_FromString(VAL(geo->country_code)));
    PyDict_SetItem(obj, PyString_FromString("country_name"), PyString_FromString(VAL(geo->country_name)));
    PyDict_SetItem(obj, PyString_FromString("region"), PyString_FromString(VAL(geo->region)));
    PyDict_SetItem(obj, PyString_FromString("city"), PyString_FromString(VAL(geo->city)));
    PyDict_SetItem(obj, PyString_FromString("latitude"), PyFloat_FromDouble((double)geo->latitude));
    PyDict_SetItem(obj, PyString_FromString("longitude"), PyFloat_FromDouble((double)geo->longitude));
  }

  return obj;
}
#endif

/* **************************************** */

static PyObject* python_synPktsSent(PyObject *self,
				   PyObject *args) {
  //traceEvent(CONST_TRACE_WARNING, "-%s-", "python_ipAddress");

  return PyString_FromFormat("%lu",
			     (ntop_host && ntop_host->secHostPkts) ? 
			     (unsigned long)(ntop_host->secHostPkts->synPktsSent.value.value) : 0);
}

/* **************************************** */

static PyMethodDef ntop_methods[] = {
  { "sendHTTPHeader", python_sendHTTPHeader, METH_VARARGS| METH_KEYWORDS, "" },
  { "printHTMLHeader", python_printHTMLHeader, METH_VARARGS, "" },

  { "printHTMLFooter", python_printHTMLFooter, METH_VARARGS, "" },
  { "sendString",      python_sendString,      METH_VARARGS, "" },

  { "getFirstHost",    python_getFirstHost,    METH_VARARGS, "" },
  { "getNextHost",     python_getNextHost,     METH_VARARGS, "" },
  { "findHostByNumIP", python_findHostByNumIP, METH_VARARGS, "" },

  { "getPreference",      python_getPreference,      METH_VARARGS, "" },
  { NULL, NULL, 0, NULL }
};

/* **************************************** */

static PyMethodDef host_methods[] = {
  { "serial", python_hostSerial, METH_NOARGS, "Get host unique serial identifier" },
  { "ethAddress", python_ethAddress, METH_NOARGS, "Get host MAC address" },
  { "ipAddress",  python_ipAddress, METH_NOARGS, "Get host IP address" },
  { "hostResolvedName",  python_hostResolvedName, METH_NOARGS, "Get host Resolved Name" },
  { "hostTrafficBucket",  python_hostTrafficBucket, METH_NOARGS, "Get Traffic Bucket" },
  { "numHostSessions",  python_numHostSessions, METH_NOARGS, "Get numHostSessions" },
  { "vlanId",  python_vlanId, METH_NOARGS, "Get vlanId" },
  { "network_mask",  python_networkMask, METH_NOARGS, "Get network_mask" },
  { "hwModel",  python_hwModel, METH_NOARGS, "Get hwModel" },
  { "isFTPhost",  python_isFTPhost, METH_NOARGS, "Check FTP Host" },
  { "isServer",  python_isServer, METH_NOARGS, "Check isServer" },
  { "isWorkstation",  python_isWorkstation, METH_NOARGS, "Check isWorkstation Host" },
  { "isMasterBrowser",  python_isMasterBrowser, METH_NOARGS, "Check isMasterBrowser Host" },
  { "isMultihomed",  python_isMultihomed, METH_NOARGS, "Check isMultihomed Host" },
  { "isMultivlaned",  python_isMultivlaned, METH_NOARGS, "Check isMultivlaned Host" },
  { "isPrinter",  python_isPrinter, METH_NOARGS, "Check isPrinter Host" },
  { "isSMTPhost",  python_isSMTPhost, METH_NOARGS, "Check isSMTPhost Host" },
  { "isPOPhost",  python_isPOPhost, METH_NOARGS, "Check isPOPhost Host" },
  { "isIMAPhost",  python_isIMAPhost, METH_NOARGS, "Check isIMAPhost Host" },
  { "isDirectoryHost",  python_isDirectoryHost, METH_NOARGS, "Check isDirectoryHost Host" },
  { "isHTTPhost",  python_isHTTPhost, METH_NOARGS, "Check isHTTPhost Host" },
  { "isWINShost",  python_isWINShost, METH_NOARGS, "Check isWINShost Host" },
  { "isBridgeHost",  python_isBridgeHost, METH_NOARGS, "Check isBridgeHost Host" },
  { "isVoIPClient",  python_isVoIPClient, METH_NOARGS, "Check isVoIPClient Host" },
  { "isVoIPGateway",  python_isVoIPGateway, METH_NOARGS, "Check isVoIPGateway Host" },
  { "isVoIPHost",  python_isVoIPHost, METH_NOARGS, "Check isVoIPHost Host" },
  { "isDHCPClient",  python_isDHCPClient, METH_NOARGS, "Check isDHCPClient Host" },
  { "isDHCPServer",  python_isDHCPServer, METH_NOARGS, "Check isDHCPServer Host" },
  { "isP2P",  python_isP2P, METH_NOARGS, "Check isP2P Host" },
  { "isNtpServer",  python_isNtpServer, METH_NOARGS, "Check isNtpServer Host" },
  { "totContactedSentPeers",  python_totContactedSentPeers, METH_NOARGS, "Check totContactedSentPeers Host" },
  { "totContactedRcvdPeers",  python_totContactedRcvdPeers, METH_NOARGS, "Check totContactedRcvdPeers Host" },
  { "fingerprint",  python_fingerprint, METH_NOARGS, "Check fingerprint Host" },
  { "synPktsSent",  python_synPktsSent, METH_NOARGS, "Check synPktsSent Host" },
  { "pktSent",  python_pktsSent, METH_NOARGS, "Return the number of packets sent by this host" },
  { "pktRcvd",  python_pktsRcvd, METH_NOARGS, "Return the number of packets rcvd by this host" },
  { "bytesSent",  python_bytesSent, METH_NOARGS, "Return the number of bytes sent by this host" },
  { "bytesRcvd",  python_bytesRcvd, METH_NOARGS, "Return the number of bytes rcvd by this host" },
#ifdef HAVE_GEOIP
  { "geoIP",  python_getGeoIP, METH_NOARGS, "Read geoLocalization info" },
#endif
  { NULL, NULL, 0, NULL }
};

/* **************************************** */

static void init_python_ntop(void) {
  pthread_mutex_init(&python_mutex, 0);
  Py_InitModule("ntop", ntop_methods);
  Py_InitModule("host", host_methods);
}

/* **************************************** */

void init_python(int argc, char *argv[]) {
  if(argv) Py_SetProgramName(argv[0]);

  /* Initialize the Python interpreter.  Required. */
  Py_Initialize();
  
  if(argv) PySys_SetArgv(argc, argv);

  /* Initialize thread support */
  PyEval_InitThreads();

  init_python_ntop();
}

/* **************************************** */

void term_python(void) {
  Py_Finalize();   /* Cleaning up the interpreter */
}

/* **************************************** */

int handlePythonHTTPRequest(char *url) {
  int idx, found = 0;
  char python_path[256];
  struct stat statbuf;
  FILE *fd;
  char *question_mark = strchr(url, '?'), *key;

  traceEvent(CONST_TRACE_INFO, "Calling python... [%s]", url);

  if(question_mark) question_mark[0] = '\0';
  safe_snprintf(__FILE__, __LINE__, query_string, sizeof(query_string)-1, 
		"%s", question_mark ? &question_mark[1] : "");

  for(idx=0; myGlobals.dataFileDirs[idx] != NULL; idx++) {
    char tmpStr[256];
    
    safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr),
		  "%s/html", myGlobals.dataFileDirs[idx]);
    revertSlashIfWIN32(tmpStr, 0);
    if(stat(tmpStr, &statbuf) == 0) {
      setenv("DOCUMENT_ROOT", tmpStr, 1);
      break;
    }
  }
 
  setenv("QUERY_STRING", query_string, 1);

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

  if((fd = fopen(python_path, "r")) != NULL) {
    /* TODO: remove this mutex */
    pthread_mutex_lock(&python_mutex);
    PyRun_SimpleFile(fd, python_path);
    pthread_mutex_unlock(&python_mutex);
  }

  fclose(fd);

  return(1);
}


#endif /* HAVE_PYTHON */
