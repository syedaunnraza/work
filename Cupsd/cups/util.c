/*
 * "$Id: util.c 7721 2008-07-11 22:48:49Z mike $"
 *
 *   Printing utilities for the Common UNIX Printing System (CUPS).
 *
 *   Copyright 2007 by Apple Inc.
 *   Copyright 1997-2006 by Easy Software Products.
 *
 *   These coded instructions, statements, and computer programs are the
 *   property of Apple Inc. and are protected by Federal copyright
 *   law.  Distribution and use rights are outlined in the file "LICENSE.txt"
 *   which should have been included with this file.  If this file is
 *   file is missing or damaged, see the license at "http://www.cups.org/".
 *
 *   This file is subject to the Apple OS-Developed Software exception.
 *
 * Contents:
 *
 *   cupsCancelJob()        - Cancel a print job on the default server.
 *   cupsFreeJobs()         - Free memory used by job data.
 *   cupsGetClasses()       - Get a list of printer classes from the default
 *                            server.
 *   cupsGetDefault()       - Get the default printer or class from the default
 *                            server.
 *   cupsGetDefault2()      - Get the default printer or class from the
 *                            specified server.
 *   cupsGetJobs()          - Get the jobs from the default server.
 *   cupsGetJobs2()         - Get the jobs from the specified server.
 *   cupsGetPPD()           - Get the PPD file for a printer on the default
 *                            server.
 *   cupsGetPPD2()          - Get the PPD file for a printer on the specified
 *                            server.
 *   cupsGetPrinters()      - Get a list of printers from the default server.
 *   cupsGetServerPPD()     - Get an available PPD file from the server.
 *   cupsLastError()        - Return the last IPP status code.
 *   cupsLastErrorString()  - Return the last IPP status-message.
 *   cupsPrintFile()        - Print a file to a printer or class on the default
 *                            server.
 *   cupsPrintFile2()       - Print a file to a printer or class on the
 *                            specified server.
 *   cupsPrintFiles()       - Print one or more files to a printer or class on
 *                            the default server.
 *   cupsPrintFiles2()      - Print one or more files to a printer or class on
 *                            the specified server.
 *   cups_connect()         - Connect to the specified host...
 *   cups_get_printer_uri() - Get the printer-uri-supported attribute for the
 *                            first printer in a class.
 */

/*
 * Include necessary headers...
 */

#include "globals.h"
#include "debug.h"
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#if defined(WIN32) || defined(__EMX__)
#  include <io.h>
#else
#  include <unistd.h>
#endif /* WIN32 || __EMX__ */


/*
 * Local functions...
 */

static char	*cups_connect(const char *name, char *printer, char *hostname);
static int	cups_get_printer_uri(http_t *http, const char *name,
		                     char *host, int hostsize, int *port,
				     char *resource, int resourcesize,
				     int depth);


/*
 * 'cupsCancelJob()' - Cancel a print job on the default server.
 *
 * Use the cupsLastError() and cupsLastErrorString() functions to get
 * the cause of any failure.
 */

int					/* O - 1 on success, 0 on failure */
cupsCancelJob(const char *name,		/* I - Name of printer or class */
              int        job)		/* I - Job ID */
{
  char		printer[HTTP_MAX_URI],	/* Printer name */
		hostname[HTTP_MAX_URI],	/* Hostname */
		uri[HTTP_MAX_URI];	/* Printer URI */
  ipp_t		*request,		/* IPP request */
		*response;		/* IPP response */
  _cups_globals_t *cg = _cupsGlobals();	/* Pointer to library globals */


 /*
  * See if we can connect to the server...
  */

  if (!cups_connect(name, printer, hostname))
  {
    DEBUG_puts("Unable to connect to server!");

    return (0);
  }

 /*
  * Create a printer URI...
  */

  if (httpAssembleURIf(HTTP_URI_CODING_ALL, uri, sizeof(uri), "ipp", NULL,
                       "localhost", 0, "/printers/%s", printer) != HTTP_URI_OK)
  {
    _cupsSetError(IPP_INTERNAL_ERROR, NULL);

    return (0);
  }

 /*
  * Build an IPP_CANCEL_JOB request, which requires the following
  * attributes:
  *
  *    attributes-charset
  *    attributes-natural-language
  *    printer-uri
  *    job-id
  *    [requesting-user-name]
  */

  request = ippNewRequest(IPP_CANCEL_JOB);

  ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "printer-uri",
               NULL, uri);

  ippAddInteger(request, IPP_TAG_OPERATION, IPP_TAG_INTEGER, "job-id", job);

  ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name",
               NULL, cupsUser());

 /*
  * Do the request...
  */

  if ((response = cupsDoRequest(cg->http, request, "/jobs/")) != NULL)
    ippDelete(response);

  return (cg->last_error < IPP_REDIRECTION_OTHER_SITE);
}


/*
 * 'cupsFreeJobs()' - Free memory used by job data.
 */

void
cupsFreeJobs(int        num_jobs,	/* I - Number of jobs */
             cups_job_t *jobs)		/* I - Jobs */
{
  int	i;				/* Looping var */


  if (num_jobs <= 0 || jobs == NULL)
    return;

  for (i = 0; i < num_jobs; i ++)
  {
    free(jobs[i].dest);
    free(jobs[i].user);
    free(jobs[i].format);
    free(jobs[i].title);
  }

  free(jobs);
}


/*
 * 'cupsGetClasses()' - Get a list of printer classes from the default server.
 *
 * This function is deprecated - use cupsGetDests() instead.
 *
 * @deprecated@
 */

int					/* O - Number of classes */
cupsGetClasses(char ***classes)		/* O - Classes */
{
  int		n;			/* Number of classes */
  ipp_t		*request,		/* IPP Request */
		*response;		/* IPP Response */
  ipp_attribute_t *attr;		/* Current attribute */
  char		**temp;			/* Temporary pointer */
  _cups_globals_t *cg = _cupsGlobals();	/* Pointer to library globals */


  if (classes == NULL)
  {
    _cupsSetError(IPP_INTERNAL_ERROR, NULL);

    return (0);
  }

 /*
  * Try to connect to the server...
  */

  if (!cups_connect("default", NULL, NULL))
  {
    DEBUG_puts("Unable to connect to server!");

    return (0);
  }

 /*
  * Build a CUPS_GET_CLASSES request, which requires the following
  * attributes:
  *
  *    attributes-charset
  *    attributes-natural-language
  *    requested-attributes
  */

  request = ippNewRequest(CUPS_GET_CLASSES);

  ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_KEYWORD,
               "requested-attributes", NULL, "printer-name");

 /*
  * Do the request and get back a response...
  */

  n        = 0;
  *classes = NULL;

  if ((response = cupsDoRequest(cg->http, request, "/")) != NULL)
  {
    for (attr = response->attrs; attr != NULL; attr = attr->next)
      if (attr->name != NULL &&
          strcasecmp(attr->name, "printer-name") == 0 &&
          attr->value_tag == IPP_TAG_NAME)
      {
        if (n == 0)
	  temp = malloc(sizeof(char *));
	else
	  temp = realloc(*classes, sizeof(char *) * (n + 1));

	if (temp == NULL)
	{
	 /*
	  * Ran out of memory!
	  */

          while (n > 0)
	  {
	    n --;
	    free((*classes)[n]);
	  }

	  free(*classes);
	  ippDelete(response);
	  return (0);
	}

        *classes = temp;
        temp[n]  = strdup(attr->values[0].string.text);
	n ++;
      }

    ippDelete(response);
  }

  return (n);
}


/*
 * 'cupsGetDefault()' - Get the default printer or class for the default server.
 *
 * This function returns the default printer or class as defined by
 * the LPDEST or PRINTER environment variables. If these environment
 * variables are not set, the server default destination is returned.
 * Applications should use the cupsGetDests() and cupsGetDest() functions
 * to get the user-defined default printer, as this function does not
 * support the lpoptions-defined default printer.
 */

const char *				/* O - Default printer or NULL */
cupsGetDefault(void)
{
  const char	*var;			/* Environment variable */
  _cups_globals_t *cg = _cupsGlobals();	/* Pointer to library globals */


 /*
  * First see if the LPDEST or PRINTER environment variables are
  * set...  However, if PRINTER is set to "lp", ignore it to work
  * around a "feature" in most Linux distributions - the default
  * user login scripts set PRINTER to "lp"...
  */

  if ((var = getenv("LPDEST")) != NULL)
    return (var);
  else if ((var = getenv("PRINTER")) != NULL && strcmp(var, "lp") != 0)
    return (var);

 /*
  * Try to connect to the server...
  */

  if (!cups_connect("default", NULL, NULL))
  {
    DEBUG_puts("Unable to connect to server!");

    return (NULL);
  }

 /*
  * Return the default printer...
  */

  return (cupsGetDefault2(cg->http));
}


/*
 * 'cupsGetDefault2()' - Get the default printer or class for the specified server.
 *
 * This function returns the default printer or class as defined by
 * the LPDEST or PRINTER environment variables. If these environment
 * variables are not set, the server default destination is returned.
 * Applications should use the cupsGetDests() and cupsGetDest() functions
 * to get the user-defined default printer, as this function does not
 * support the lpoptions-defined default printer.
 *
 * @since CUPS 1.1.21@
 */

const char *				/* O - Default printer or NULL */
cupsGetDefault2(http_t *http)		/* I - HTTP connection */
{
  ipp_t		*request,		/* IPP Request */
		*response;		/* IPP Response */
  ipp_attribute_t *attr;		/* Current attribute */
  const char	*var;			/* Environment variable */
  _cups_globals_t *cg = _cupsGlobals();	/* Pointer to library globals */


 /*
  * First see if the LPDEST or PRINTER environment variables are
  * set...  However, if PRINTER is set to "lp", ignore it to work
  * around a "feature" in most Linux distributions - the default
  * user login scripts set PRINTER to "lp"...
  */

  if ((var = getenv("LPDEST")) != NULL)
    return (var);
  else if ((var = getenv("PRINTER")) != NULL && strcmp(var, "lp") != 0)
    return (var);

 /*
  * Range check input...
  */

  if (!http)
    return (NULL);

 /*
  * Build a CUPS_GET_DEFAULT request, which requires the following
  * attributes:
  *
  *    attributes-charset
  *    attributes-natural-language
  */

  request = ippNewRequest(CUPS_GET_DEFAULT);

 /*
  * Do the request and get back a response...
  */

  if ((response = cupsDoRequest(http, request, "/")) != NULL)
  {
    if ((attr = ippFindAttribute(response, "printer-name", IPP_TAG_NAME)) != NULL)
    {
      strlcpy(cg->def_printer, attr->values[0].string.text, sizeof(cg->def_printer));
      ippDelete(response);
      return (cg->def_printer);
    }

    ippDelete(response);
  }

  return (NULL);
}


/*
 * 'cupsGetJobs()' - Get the jobs from the default server.
 */

int					/* O - Number of jobs */
cupsGetJobs(cups_job_t **jobs,		/* O - Job data */
            const char *mydest,		/* I - NULL = all destinations,       *
	                                 *     otherwise show jobs for mydest */
            int        myjobs,		/* I - 0 = all users, 1 = mine */
	    int        completed)	/* I - -1 = show all, 0 = active, *
	                                 *     1 = completed jobs         */
{
  _cups_globals_t *cg = _cupsGlobals();	/* Pointer to library globals */

 /*
  * Try to connect to the server...
  */

  if (!cups_connect("default", NULL, NULL))
  {
    DEBUG_puts("Unable to connect to server!");

    return (-1);
  }

 /*
  * Return the jobs...
  */

  return (cupsGetJobs2(cg->http, jobs, mydest, myjobs, completed));
}



/*
 * 'cupsGetJobs2()' - Get the jobs from the specified server.
 *
 * @since CUPS 1.1.21@
 */

int					/* O - Number of jobs */
cupsGetJobs2(http_t     *http,		/* I - HTTP connection */
             cups_job_t **jobs,		/* O - Job data */
             const char *mydest,	/* I - NULL = all destinations,       *
	                                 *     otherwise show jobs for mydest */
             int        myjobs,		/* I - 0 = all users, 1 = mine */
	     int        completed)	/* I - -1 = show all, 0 = active, *
	                                 *     1 = completed jobs         */
{
  int		n;			/* Number of jobs */
  ipp_t		*request,		/* IPP Request */
		*response;		/* IPP Response */
  ipp_attribute_t *attr;		/* Current attribute */
  cups_job_t	*temp;			/* Temporary pointer */
  int		id,			/* job-id */
		priority,		/* job-priority */
		size;			/* job-k-octets */
  ipp_jstate_t	state;			/* job-state */
  time_t	completed_time,		/* time-at-completed */
		creation_time,		/* time-at-creation */
		processing_time;	/* time-at-processing */
  const char	*dest,			/* job-printer-uri */
		*format,		/* document-format */
		*title,			/* job-name */
		*user;			/* job-originating-user-name */
  char		uri[HTTP_MAX_URI];	/* URI for jobs */
  _cups_globals_t *cg = _cupsGlobals();	/* Pointer to library globals */
  static const char * const attrs[] =	/* Requested attributes */
		{
		  "job-id",
		  "job-priority",
		  "job-k-octets",
		  "job-state",
		  "time-at-completed",
		  "time-at-creation",
		  "time-at-processing",
		  "job-printer-uri",
		  "document-format",
		  "job-name",
		  "job-originating-user-name"
		};


 /*
  * Range check input...
  */

  if (!http || !jobs)
  {
    _cupsSetError(IPP_INTERNAL_ERROR, NULL);

    return (-1);
  }

 /*
  * Get the right URI...
  */

  if (mydest)
  {
    if (httpAssembleURIf(HTTP_URI_CODING_ALL, uri, sizeof(uri), "ipp", NULL,
                         "localhost", 0, "/printers/%s", mydest) != HTTP_URI_OK)
    {
      _cupsSetError(IPP_INTERNAL_ERROR, NULL);

      return (-1);
    }
  }
  else
    strcpy(uri, "ipp://localhost/jobs");


 /*
  * Build an IPP_GET_JOBS request, which requires the following
  * attributes:
  *
  *    attributes-charset
  *    attributes-natural-language
  *    printer-uri
  *    requesting-user-name
  *    which-jobs
  *    my-jobs
  *    requested-attributes
  */

  request = ippNewRequest(IPP_GET_JOBS);

  ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI,
               "printer-uri", NULL, uri);

  ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME,
               "requesting-user-name", NULL, cupsUser());

  if (myjobs)
    ippAddBoolean(request, IPP_TAG_OPERATION, "my-jobs", 1);

  if (completed > 0)
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_KEYWORD,
                 "which-jobs", NULL, "completed");
  else if (completed < 0)
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_KEYWORD,
                 "which-jobs", NULL, "all");

  ippAddStrings(request, IPP_TAG_OPERATION, IPP_TAG_KEYWORD,
                "requested-attributes", sizeof(attrs) / sizeof(attrs[0]),
		NULL, attrs);

 /*
  * Do the request and get back a response...
  */

  n     = 0;
  *jobs = NULL;

  if ((response = cupsDoRequest(http, request, "/")) != NULL)
  {
    for (attr = response->attrs; attr != NULL; attr = attr->next)
    {
     /*
      * Skip leading attributes until we hit a job...
      */

      while (attr != NULL && attr->group_tag != IPP_TAG_JOB)
        attr = attr->next;

      if (attr == NULL)
        break;

     /*
      * Pull the needed attributes from this job...
      */

      id              = 0;
      size            = 0;
      priority        = 50;
      state           = IPP_JOB_PENDING;
      user            = "unknown";
      dest            = NULL;
      format          = "application/octet-stream";
      title           = "untitled";
      creation_time   = 0;
      completed_time  = 0;
      processing_time = 0;

      while (attr != NULL && attr->group_tag == IPP_TAG_JOB)
      {
        if (strcmp(attr->name, "job-id") == 0 &&
	    attr->value_tag == IPP_TAG_INTEGER)
	  id = attr->values[0].integer;
        else if (strcmp(attr->name, "job-state") == 0 &&
	         attr->value_tag == IPP_TAG_ENUM)
	  state = (ipp_jstate_t)attr->values[0].integer;
        else if (strcmp(attr->name, "job-priority") == 0 &&
	         attr->value_tag == IPP_TAG_INTEGER)
	  priority = attr->values[0].integer;
        else if (strcmp(attr->name, "job-k-octets") == 0 &&
	         attr->value_tag == IPP_TAG_INTEGER)
	  size = attr->values[0].integer;
        else if (strcmp(attr->name, "time-at-completed") == 0 &&
	         attr->value_tag == IPP_TAG_INTEGER)
	  completed_time = attr->values[0].integer;
        else if (strcmp(attr->name, "time-at-creation") == 0 &&
	         attr->value_tag == IPP_TAG_INTEGER)
	  creation_time = attr->values[0].integer;
        else if (strcmp(attr->name, "time-at-processing") == 0 &&
	         attr->value_tag == IPP_TAG_INTEGER)
	  processing_time = attr->values[0].integer;
        else if (strcmp(attr->name, "job-printer-uri") == 0 &&
	         attr->value_tag == IPP_TAG_URI)
	{
	  if ((dest = strrchr(attr->values[0].string.text, '/')) != NULL)
	    dest ++;
        }
        else if (strcmp(attr->name, "job-originating-user-name") == 0 &&
	         attr->value_tag == IPP_TAG_NAME)
	  user = attr->values[0].string.text;
        else if (strcmp(attr->name, "document-format") == 0 &&
	         attr->value_tag == IPP_TAG_MIMETYPE)
	  format = attr->values[0].string.text;
        else if (strcmp(attr->name, "job-name") == 0 &&
	         (attr->value_tag == IPP_TAG_TEXT ||
		  attr->value_tag == IPP_TAG_NAME))
	  title = attr->values[0].string.text;

        attr = attr->next;
      }

     /*
      * See if we have everything needed...
      */

      if (dest == NULL || id == 0)
      {
        if (attr == NULL)
	  break;
	else
          continue;
      }

     /*
      * Allocate memory for the job...
      */

      if (n == 0)
        temp = malloc(sizeof(cups_job_t));
      else
	temp = realloc(*jobs, sizeof(cups_job_t) * (n + 1));

      if (temp == NULL)
      {
       /*
        * Ran out of memory!
        */

	cupsFreeJobs(n, *jobs);
	*jobs = NULL;

        ippDelete(response);
	return (0);
      }

      *jobs = temp;
      temp  += n;
      n ++;

     /*
      * Copy the data over...
      */

      temp->dest            = strdup(dest);
      temp->user            = strdup(user);
      temp->format          = strdup(format);
      temp->title           = strdup(title);
      temp->id              = id;
      temp->priority        = priority;
      temp->state           = state;
      temp->size            = size;
      temp->completed_time  = completed_time;
      temp->creation_time   = creation_time;
      temp->processing_time = processing_time;

      if (attr == NULL)
        break;
    }

    ippDelete(response);
  }

  if (n == 0 && cg->last_error >= IPP_BAD_REQUEST)
    return (-1);
  else
    return (n);
}


/*
 * 'cupsGetPPD()' - Get the PPD file for a printer on the default server.
 *
 * For classes, cupsGetPPD() returns the PPD file for the first printer
 * in the class.
 */

const char *				/* O - Filename for PPD file */
cupsGetPPD(const char *name)		/* I - Printer name */
{
  _cups_globals_t *cg = _cupsGlobals();	/* Pointer to library globals */

 /*
  * See if we can connect to the server...
  */

  if (!cups_connect(name, NULL, NULL))
  {
    DEBUG_puts("Unable to connect to server!");

    return (NULL);
  }

 /*
  * Return the PPD file...
  */

  return (cupsGetPPD2(cg->http, name));
}


/*
 * 'cupsGetPPD2()' - Get the PPD file for a printer from the specified server.
 *
 * For classes, cupsGetPPD2() returns the PPD file for the first printer
 * in the class.
 *
 * @since CUPS 1.1.21@
 */

const char *				/* O - Filename for PPD file */
cupsGetPPD2(http_t     *http,		/* I - HTTP connection */
            const char *name)		/* I - Printer name */
{
  int		http_port;		/* Port number */
  char		http_hostname[HTTP_MAX_HOST];
					/* Hostname associated with connection */
  http_t	*http2;			/* Alternate HTTP connection */
  int		fd;			/* PPD file */
  char		localhost[HTTP_MAX_URI],/* Local hostname */
		hostname[HTTP_MAX_URI],	/* Hostname */
		resource[HTTP_MAX_URI];	/* Resource name */
  int		port;			/* Port number */
  http_status_t	status;			/* HTTP status from server */
  _cups_globals_t *cg = _cupsGlobals();	/* Pointer to library globals */


 /*
  * Range check input...
  */

  DEBUG_printf(("cupsGetPPD2(http=%p, name=\"%s\")\n", http,
                name ? name : "(null)"));

  if (!http || !name)
  {
    if (!http)
      _cupsSetError(IPP_INTERNAL_ERROR, "No HTTP connection!");
    else
      _cupsSetError(IPP_INTERNAL_ERROR, "No printer name!");

    return (NULL);
  }

 /*
  * Try finding a printer URI for this printer...
  */

  if (!cups_get_printer_uri(http, name, hostname, sizeof(hostname), &port,
                            resource, sizeof(resource), 0))
    return (NULL);

  DEBUG_printf(("cupsGetPPD3: Printer hostname=\"%s\", port=%d\n", hostname, port));

 /*
  * Remap local hostname to localhost...
  */

  httpGetHostname(NULL, localhost, sizeof(localhost));

  DEBUG_printf(("Local hostname=\"%s\"\n", localhost));

  if (!strcasecmp(localhost, hostname))
    strcpy(hostname, "localhost");

 /*
  * Get the hostname and port number we are connected to...
  */

  httpGetHostname(http, http_hostname, sizeof(http_hostname));

#ifdef AF_INET6
  if (http->hostaddr->addr.sa_family == AF_INET6)
    http_port = ntohs(http->hostaddr->ipv6.sin6_port);
  else
#endif /* AF_INET6 */
  if (http->hostaddr->addr.sa_family == AF_INET)
    http_port = ntohs(http->hostaddr->ipv4.sin_port);
  else
    http_port = ippPort(); 

  DEBUG_printf(("Connection hostname=\"%s\", port=%d\n", http_hostname,
                http_port));

 /*
  * Reconnect to the correct server as needed...
  */

  if (!strcasecmp(http_hostname, hostname) && port == http_port)
    http2 = http;
  else if ((http2 = httpConnectEncrypt(hostname, port,
                                       cupsEncryption())) == NULL)
  {
    DEBUG_puts("Unable to connect to server!");

    return (NULL);
  }

 /*
  * Get a temp file...
  */

  if ((fd = cupsTempFd(cg->ppd_filename, sizeof(cg->ppd_filename))) < 0)
  {
   /*
    * Can't open file; close the server connection and return NULL...
    */

    _cupsSetError(IPP_INTERNAL_ERROR, strerror(errno));

    if (http2 != http)
      httpClose(http2);

    return (NULL);
  }

 /*
  * And send a request to the HTTP server...
  */

  strlcat(resource, ".ppd", sizeof(resource));

  status = cupsGetFd(http2, resource, fd);

  close(fd);

 /*
  * See if we actually got the file or an error...
  */

  if (status != HTTP_OK)
  {
    switch (status)
    {
      case HTTP_NOT_FOUND :
          _cupsSetError(IPP_NOT_FOUND, httpStatus(status));
	  break;

      case HTTP_UNAUTHORIZED :
          _cupsSetError(IPP_NOT_AUTHORIZED, httpStatus(status));
	  break;

      default :
	  DEBUG_printf(("HTTP error %d mapped to IPP_SERVICE_UNAVAILABLE!\n",
                	status));
	  _cupsSetError(IPP_SERVICE_UNAVAILABLE, httpStatus(status));
	  break;
    }

    unlink(cg->ppd_filename);

    return (NULL);
  }

  if (http2 != http)
    httpClose(http2);

 /*
  * Return the PPD file...
  */

  return (cg->ppd_filename);
}


/*
 * 'cupsGetPrinters()' - Get a list of printers from the default server.
 *
 * This function is deprecated - use cupsGetDests() instead.
 *
 * @deprecated@
 */

int					/* O - Number of printers */
cupsGetPrinters(char ***printers)	/* O - Printers */
{
  int		n;			/* Number of printers */
  ipp_t		*request,		/* IPP Request */
		*response;		/* IPP Response */
  ipp_attribute_t *attr;		/* Current attribute */
  char		**temp;			/* Temporary pointer */
  _cups_globals_t *cg = _cupsGlobals();	/* Pointer to library globals */


  if (printers == NULL)
  {
    _cupsSetError(IPP_INTERNAL_ERROR, NULL);

    return (0);
  }

 /*
  * Try to connect to the server...
  */

  if (!cups_connect("default", NULL, NULL))
  {
    DEBUG_puts("Unable to connect to server!");

    return (0);
  }

 /*
  * Build a CUPS_GET_PRINTERS request, which requires the following
  * attributes:
  *
  *    attributes-charset
  *    attributes-natural-language
  *    requested-attributes
  */

  request = ippNewRequest(CUPS_GET_PRINTERS);

  ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_KEYWORD,
               "requested-attributes", NULL, "printer-name");

  ippAddInteger(request, IPP_TAG_OPERATION, IPP_TAG_ENUM,
                "printer-type", 0);

  ippAddInteger(request, IPP_TAG_OPERATION, IPP_TAG_ENUM,
                "printer-type-mask", CUPS_PRINTER_CLASS);

 /*
  * Do the request and get back a response...
  */

  n         = 0;
  *printers = NULL;

  if ((response = cupsDoRequest(cg->http, request, "/")) != NULL)
  {
    for (attr = response->attrs; attr != NULL; attr = attr->next)
      if (attr->name != NULL &&
          strcasecmp(attr->name, "printer-name") == 0 &&
          attr->value_tag == IPP_TAG_NAME)
      {
        if (n == 0)
	  temp = malloc(sizeof(char *));
	else
	  temp = realloc(*printers, sizeof(char *) * (n + 1));

	if (temp == NULL)
	{
	 /*
	  * Ran out of memory!
	  */

	  while (n > 0)
	  {
	    n --;
	    free((*printers)[n]);
	  }

	  free(*printers);
	  ippDelete(response);
	  return (0);
	}

        *printers = temp;
        temp[n]   = strdup(attr->values[0].string.text);
	n ++;
      }

    ippDelete(response);
  }

  return (n);
}


/*
 * 'cupsGetServerPPD()' - Get an available PPD file from the server.
 *
 * This function returns the named PPD file from the server.  The
 * list of available PPDs is provided by the IPP CUPS_GET_PPDS
 * operation.
 *
 * You must remove (unlink) the PPD file when you are finished with
 * it. The PPD filename is stored in a static location that will be
 * overwritten on the next call to cupsGetPPD(), cupsGetPPD2(), or
 * cupsGetServerPPD().
 *
 * @since CUPS 1.3@
 */

char *					/* O - Name of PPD file or NULL on error */
cupsGetServerPPD(http_t     *http,	/* I - HTTP connection */
                 const char *name)	/* I - Name of PPD file ("ppd-name") */
{
  int			fd;		/* PPD file descriptor */
  ipp_t			*request;	/* IPP request */
  _cups_globals_t	*cg = _cupsGlobals();
					/* Pointer to library globals */


 /*
  * Range check input...
  */

  if (!http || !name)
  {
    if (!http)
      _cupsSetError(IPP_INTERNAL_ERROR, "No HTTP connection!");
    else
      _cupsSetError(IPP_INTERNAL_ERROR, "No PPD name!");

    return (NULL);
  }

 /*
  * Get a temp file...
  */

  if ((fd = cupsTempFd(cg->ppd_filename, sizeof(cg->ppd_filename))) < 0)
  {
   /*
    * Can't open file; close the server connection and return NULL...
    */

    _cupsSetError(IPP_INTERNAL_ERROR, strerror(errno));

    return (NULL);
  }

 /*
  * Get the PPD file...
  */

  request = ippNewRequest(CUPS_GET_PPD);
  ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "ppd-name", NULL,
               name);

  ippDelete(cupsDoIORequest(http, request, "/", -1, fd));

  close(fd);

  if (cupsLastError() != IPP_OK)
  {
    unlink(cg->ppd_filename);
    return (NULL);
  }
  else
    return (cg->ppd_filename);
}


/*
 * 'cupsLastError()' - Return the last IPP status code.
 */

ipp_status_t				/* O - IPP status code from last request */
cupsLastError(void)
{
  return (_cupsGlobals()->last_error);
}


/*
 * 'cupsLastErrorString()' - Return the last IPP status-message.
 *
 * @since CUPS 1.2@
 */

const char *				/* O - status-message text from last request */
cupsLastErrorString(void)
{
  return (_cupsGlobals()->last_status_message);
}


/*
 * 'cupsPrintFile()' - Print a file to a printer or class on the default server.
 */

int					/* O - Job ID */
cupsPrintFile(const char    *name,	/* I - Printer or class name */
              const char    *filename,	/* I - File to print */
	      const char    *title,	/* I - Title of job */
              int           num_options,/* I - Number of options */
	      cups_option_t *options)	/* I - Options */
{
  DEBUG_printf(("cupsPrintFile(name=\"%s\", filename=\"%s\", "
                "title=\"%s\", num_options=%d, options=%p)\n",
                name, filename, title, num_options, options));

  return (cupsPrintFiles(name, 1, &filename, title, num_options, options));
}


/*
 * 'cupsPrintFile2()' - Print a file to a printer or class on the specified server.
 *
 * @since CUPS 1.1.21@
 */

int					/* O - Job ID */
cupsPrintFile2(http_t        *http,	/* I - HTTP connection */
               const char    *name,	/* I - Printer or class name */
               const char    *filename,	/* I - File to print */
	       const char    *title,	/* I - Title of job */
               int           num_options,
					/* I - Number of options */
	       cups_option_t *options)	/* I - Options */
{
  DEBUG_printf(("cupsPrintFile2(http=%p, name=\"%s\", filename=\"%s\", "
                "title=\"%s\", num_options=%d, options=%p)\n",
                http, name, filename, title, num_options, options));

  return (cupsPrintFiles2(http, name, 1, &filename, title, num_options, options));
}


/*
 * 'cupsPrintFiles()' - Print one or more files to a printer or class on the
 *                      default server.
 */

int					/* O - Job ID */
cupsPrintFiles(const char    *name,	/* I - Printer or class name */
               int           num_files,	/* I - Number of files */
               const char    **files,	/* I - File(s) to print */
	       const char    *title,	/* I - Title of job */
               int           num_options,
					/* I - Number of options */
	       cups_option_t *options)	/* I - Options */
{
  _cups_globals_t *cg = _cupsGlobals();	/* Pointer to library globals */

  DEBUG_printf(("cupsPrintFiles(name=\"%s\", num_files=%d, "
                "files=%p, title=\"%s\", num_options=%d, options=%p)\n",
                name, num_files, files, title, num_options, options));


 /*
  * Setup a connection and request data...
  */

  if (!cups_connect(name, NULL, NULL))
  {
    DEBUG_printf(("cupsPrintFiles: Unable to open connection - %s.\n",
                  strerror(errno)));
    DEBUG_puts("Unable to connect to server!");

    return (0);
  }

 /*
  * Print the file(s)...
  */

  return (cupsPrintFiles2(cg->http, name, num_files, files, title,
                          num_options, options));
}



/*
 * 'cupsPrintFiles2()' - Print one or more files to a printer or class on the
 *                       specified server.
 *
 * @since CUPS 1.1.21@
 */

int					/* O - Job ID */
cupsPrintFiles2(http_t        *http,	/* I - HTTP connection */
                const char    *name,	/* I - Printer or class name */
                int           num_files,/* I - Number of files */
                const char    **files,	/* I - File(s) to print */
	        const char    *title,	/* I - Title of job */
                int           num_options,
					/* I - Number of options */
	        cups_option_t *options)	/* I - Options */
{
  int		i;			/* Looping var */
  const char	*val;			/* Pointer to option value */
  ipp_t		*request;		/* IPP request */
  ipp_t		*response;		/* IPP response */
  ipp_attribute_t *attr;		/* IPP job-id attribute */
  char		uri[HTTP_MAX_URI];	/* Printer URI */
  int		jobid;			/* New job ID */
  const char	*base;			/* Basename of current filename */


  DEBUG_printf(("cupsPrintFiles(http=%p, name=\"%s\", num_files=%d, "
                "files=%p, title=\"%s\", num_options=%d, options=%p)\n",
                http, name, num_files, files, title, num_options, options));

 /*
  * Range check input...
  */

  if (!http || !name || num_files < 1 || files == NULL)
  {
    _cupsSetError(IPP_INTERNAL_ERROR, NULL);

    return (0);
  }

 /*
  * Setup the printer URI...
  */

  if (httpAssembleURIf(HTTP_URI_CODING_ALL, uri, sizeof(uri), "ipp", NULL,
                       "localhost", 0, "/printers/%s", name) != HTTP_URI_OK)
  {
    _cupsSetError(IPP_INTERNAL_ERROR, NULL);

    return (0);
  }

 /*
  * Build a standard CUPS URI for the printer and fill the standard IPP
  * attributes...
  */

  if ((request = ippNewRequest(num_files == 1 ? IPP_PRINT_JOB :
                                                IPP_CREATE_JOB)) == NULL)
  {
    _cupsSetError(IPP_INTERNAL_ERROR, NULL);

    return (0);
  }

  ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "printer-uri",
               NULL, uri);

  ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name",
               NULL, cupsUser());

  if (title)
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "job-name", NULL,
                 title);

 /*
  * Then add all options...
  */

  cupsEncodeOptions(request, num_options, options);

 /*
  * Do the request...
  */

  snprintf(uri, sizeof(uri), "/printers/%s", name);

  if (num_files == 1)
    response = cupsDoFileRequest(http, request, uri, *files);
  else
    response = cupsDoRequest(http, request, uri);

  if (response == NULL)
    jobid = 0;
  else if (response->request.status.status_code > IPP_OK_CONFLICT)
  {
    DEBUG_printf(("IPP response code was 0x%x!\n",
                  response->request.status.status_code));
    jobid = 0;
  }
  else if ((attr = ippFindAttribute(response, "job-id", IPP_TAG_INTEGER)) == NULL)
  {
    DEBUG_puts("No job ID!");

    _cupsSetError(IPP_INTERNAL_ERROR, NULL);

    jobid = 0;
  }
  else
    jobid = attr->values[0].integer;

  if (response != NULL)
    ippDelete(response);

 /*
  * Handle multiple file jobs if the create-job operation worked...
  */

  if (jobid > 0 && num_files > 1)
    for (i = 0; i < num_files; i ++)
    {
     /*
      * Build a standard CUPS URI for the job and fill the standard IPP
      * attributes...
      */

      if ((request = ippNewRequest(IPP_SEND_DOCUMENT)) == NULL)
	return (0);

      snprintf(uri, sizeof(uri), "ipp://localhost/jobs/%d", jobid);

      ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "job-uri",
        	   NULL, uri);

     /*
      * Handle raw print files...
      */

      if (cupsGetOption("raw", num_options, options))
	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_MIMETYPE,
	             "document-format", NULL, "application/vnd.cups-raw");
      else if ((val = cupsGetOption("document-format", num_options,
                                    options)) != NULL)
	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_MIMETYPE,
	             "document-format", NULL, val);
      else
	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_MIMETYPE,
	             "document-format", NULL, "application/octet-stream");

      ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME,
                   "requesting-user-name", NULL, cupsUser());

     /*
      * Add the original document filename...
      */

      if ((base = strrchr(files[i], '/')) != NULL)
        base ++;
      else
        base = files[i];

      ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "document-name",
                   NULL, base);

     /*
      * Is this the last document?
      */

      if (i == (num_files - 1))
        ippAddBoolean(request, IPP_TAG_OPERATION, "last-document", 1);

     /*
      * Send the file...
      */

      snprintf(uri, sizeof(uri), "/printers/%s", name);

      if ((response = cupsDoFileRequest(http, request, uri,
                                        files[i])) != NULL)
	ippDelete(response);
    }

  return (jobid);
}


/*
 * 'cups_connect()' - Connect to the specified host...
 */

static char *				/* I - Printer name or NULL */
cups_connect(const char *name,		/* I - Destination (printer[@host]) */
	     char       *printer,	/* O - Printer name [HTTP_MAX_URI] */
             char       *hostname)	/* O - Hostname [HTTP_MAX_URI] */
{
  char	hostbuf[HTTP_MAX_URI],		/* Name of host */
	http_hostname[HTTP_MAX_HOST];	/* Hostname associated with connection */
  _cups_globals_t  *cg = _cupsGlobals();/* Pointer to library globals */


  DEBUG_printf(("cups_connect(\"%s\", %p, %p)\n", name, printer, hostname));

  if (name == NULL)
  {
    _cupsSetError(IPP_BAD_REQUEST, NULL);

    return (NULL);
  }

 /*
  * All jobs are now queued to cupsServer() to avoid hostname
  * resolution problems and to ensure that the user sees all
  * locally queued jobs locally.
  */

  strlcpy(hostbuf, cupsServer(), sizeof(hostbuf));

  httpGetHostname(cg->http, http_hostname, sizeof(http_hostname));

  if (hostname != NULL)
    strlcpy(hostname, hostbuf, HTTP_MAX_URI);
  else
    hostname = hostbuf;

  if (printer != NULL)
    strlcpy(printer, name, HTTP_MAX_URI);
  else
    printer = (char *)name;

  if (cg->http != NULL)
  {
    if (!strcasecmp(http_hostname, hostname))
      return (printer);

    httpClose(cg->http);
  }

  DEBUG_printf(("connecting to %s on port %d...\n", hostname, ippPort()));

  if ((cg->http = httpConnectEncrypt(hostname, ippPort(),
                                     cupsEncryption())) == NULL)
  {
    DEBUG_puts("Unable to connect to server!");

    _cupsSetError(IPP_SERVICE_UNAVAILABLE, strerror(errno));

    return (NULL);
  }
  else
    return (printer);
}


/*
 * 'cups_get_printer_uri()' - Get the printer-uri-supported attribute for the first printer in a class.
 */

static int				/* O - 1 on success, 0 on failure */
cups_get_printer_uri(
    http_t     *http,			/* I - HTTP connection */
    const char *name,			/* I - Name of printer or class */
    char       *host,			/* I - Hostname buffer */
    int        hostsize,		/* I - Size of hostname buffer */
    int        *port,			/* O - Port number */
    char       *resource,		/* I - Resource buffer */
    int        resourcesize,		/* I - Size of resource buffer */
    int        depth)			/* I - Depth of query */
{
  int		i;			/* Looping var */
  int		http_port;		/* Port number */
  http_t	*http2;			/* Alternate HTTP connection */
  ipp_t		*request,		/* IPP request */
		*response;		/* IPP response */
  ipp_attribute_t *attr;		/* Current attribute */
  char		uri[HTTP_MAX_URI],	/* printer-uri attribute */
		scheme[HTTP_MAX_URI],	/* Scheme name */
		username[HTTP_MAX_URI],	/* Username:password */
		classname[255],		/* Temporary class name */
		http_hostname[HTTP_MAX_HOST];
					/* Hostname associated with connection */
  static const char * const requested_attrs[] =
		{			/* Requested attributes */
		  "printer-uri-supported",
		  "printer-type",
		  "member-uris"
		};


  DEBUG_printf(("cups_get_printer_uri(http=%p, name=\"%s\", host=%p, "
                "hostsize=%d, resource=%p, resourcesize=%d, depth=%d)\n",
		http, name ? name : "(null)", host, hostsize,
		resource, resourcesize, depth));

 /*
  * Setup the printer URI...
  */

  if (httpAssembleURIf(HTTP_URI_CODING_ALL, uri, sizeof(uri), "ipp", NULL,
                       "localhost", 0, "/printers/%s", name) != HTTP_URI_OK)
  {
    _cupsSetError(IPP_INTERNAL_ERROR, "Unable to create printer-uri!");

    *host     = '\0';
    *resource = '\0';

    return (0);
  }

  DEBUG_printf(("cups_get_printer_uri: printer-uri=\"%s\"\n", uri));

 /*
  * Get the hostname and port number we are connected to...
  */

  httpGetHostname(http, http_hostname, sizeof(http_hostname));

#ifdef AF_INET6
  if (http->hostaddr->addr.sa_family == AF_INET6)
    http_port = ntohs(http->hostaddr->ipv6.sin6_port);
  else
#endif /* AF_INET6 */
  if (http->hostaddr->addr.sa_family == AF_INET)
    http_port = ntohs(http->hostaddr->ipv4.sin_port);
  else
    http_port = ippPort(); 

 /*
  * Build an IPP_GET_PRINTER_ATTRIBUTES request, which requires the following
  * attributes:
  *
  *    attributes-charset
  *    attributes-natural-language
  *    printer-uri
  *    requested-attributes
  */

  request = ippNewRequest(IPP_GET_PRINTER_ATTRIBUTES);

  ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "printer-uri",
               NULL, uri);

  ippAddStrings(request, IPP_TAG_OPERATION, IPP_TAG_NAME,
                "requested-attributes",
		sizeof(requested_attrs) / sizeof(requested_attrs[0]),
		NULL, requested_attrs);

 /*
  * Do the request and get back a response...
  */

  if ((response = cupsDoRequest(http, request, "/")) != NULL)
  {
    if ((attr = ippFindAttribute(response, "member-uris", IPP_TAG_URI)) != NULL)
    {
     /*
      * Get the first actual printer name in the class...
      */

      for (i = 0; i < attr->num_values; i ++)
      {
	httpSeparateURI(HTTP_URI_CODING_ALL, attr->values[i].string.text,
	                scheme, sizeof(scheme), username, sizeof(username),
			host, hostsize, port, resource, resourcesize);
	if (!strncmp(resource, "/printers/", 10))
	{
	 /*
	  * Found a printer!
	  */

          ippDelete(response);

	  return (1);
	}
      }

     /*
      * No printers in this class - try recursively looking for a printer,
      * but not more than 3 levels deep...
      */

      if (depth < 3)
      {
	for (i = 0; i < attr->num_values; i ++)
	{
	  httpSeparateURI(HTTP_URI_CODING_ALL, attr->values[i].string.text,
	                  scheme, sizeof(scheme), username, sizeof(username),
			  host, hostsize, port, resource, resourcesize);
	  if (!strncmp(resource, "/classes/", 9))
	  {
	   /*
	    * Found a class!  Connect to the right server...
	    */

	    if (!strcasecmp(http_hostname, host) && *port == http_port)
	      http2 = http;
	    else if ((http2 = httpConnectEncrypt(host, *port,
						 cupsEncryption())) == NULL)
	    {
	      DEBUG_puts("Unable to connect to server!");

	      continue;
	    }

           /*
	    * Look up printers on that server...
	    */

            strlcpy(classname, resource + 9, sizeof(classname));

            cups_get_printer_uri(http2, classname, host, hostsize, port,
	                         resource, resourcesize, depth + 1);

           /*
	    * Close the connection as needed...
	    */

	    if (http2 != http)
	      httpClose(http2);

            if (*host)
	      return (1);
	  }
	}
      }
    }
    else if ((attr = ippFindAttribute(response, "printer-uri-supported",
                                      IPP_TAG_URI)) != NULL)
    {
      httpSeparateURI(HTTP_URI_CODING_ALL, attr->values[0].string.text,
                      scheme, sizeof(scheme), username, sizeof(username),
		      host, hostsize, port, resource, resourcesize);
      ippDelete(response);

      if (!strncmp(resource, "/classes/", 9))
      {
        _cupsSetError(IPP_INTERNAL_ERROR, _("No printer-uri found for class!"));

	*host     = '\0';
	*resource = '\0';

	return (0);
      }

      return (1);
    }

    ippDelete(response);
  }

  if (cupsLastError() != IPP_NOT_FOUND)
    _cupsSetError(IPP_INTERNAL_ERROR, _("No printer-uri found!"));

  *host     = '\0';
  *resource = '\0';

  return (0);
}


/*
 * End of "$Id: util.c 7721 2008-07-11 22:48:49Z mike $".
 */
