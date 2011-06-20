/*
 * "$Id: server.c 6649 2007-07-11 21:46:42Z mike $"
 *
 *   Server start/stop routines for the Common UNIX Printing System (CUPS).
 *
 *   Copyright 2007 by Apple Inc.
 *   Copyright 1997-2006 by Easy Software Products, all rights reserved.
 *
 *   These coded instructions, statements, and computer programs are the
 *   property of Apple Inc. and are protected by Federal copyright
 *   law.  Distribution and use rights are outlined in the file "LICENSE.txt"
 *   which should have been included with this file.  If this file is
 *   file is missing or damaged, see the license at "http://www.cups.org/".
 *
 * Contents:
 *
 *   cupsdStartServer() - Start the server.
 *   cupsdStopServer()  - Stop the server.
 */

/*
 * Include necessary headers...
 */

#include <cups/http-private.h>
#include "cupsd.h"
#include <grp.h>
#ifdef HAVE_NOTIFY_H
#  include <notify.h>
#endif /* HAVE_NOTIFY_H */


/*
 * Local globals...
 */

static int	started = 0;


/*
 * 'cupsdStartServer()' - Start the server.
 */

void
cupsdStartServer(void)
{
#ifdef HAVE_LIBSSL
  int			i;		/* Looping var */
  struct timeval	curtime;	/* Current time in microseconds */
  unsigned char		data[1024];	/* Seed data */
#endif /* HAVE_LIBSSL */


#ifdef HAVE_LIBSSL
 /*
  * Initialize the encryption libraries...
  */

  printf("[server.c::cupsdStartServer()] initializing the SSL encryption libraries\n");
  SSL_library_init();
  SSL_load_error_strings();

 /*
  * Using the current time is a dubious random seed, but on some systems
  * it is the best we can do (on others, this seed isn't even used...)
  */

  gettimeofday(&curtime, NULL);
  srand(curtime.tv_sec + curtime.tv_usec);

  for (i = 0; i < sizeof(data); i ++)
    data[i] = rand(); /* Yes, this is a poor source of random data... */

  RAND_seed(&data, sizeof(data));
  printf("[server.c::cupsdStartServer()] seeding a lot of crap \n");

#elif defined(HAVE_GNUTLS)
 /*
  * Initialize the encryption libraries...
  */
  printf("[server.c::cupsdStartServer()] initializing the gnutils libraries \n");
  gnutls_global_init();
#endif /* HAVE_LIBSSL */

 /*
  * Startup all the networking stuff...
  */

  cupsdStartListening();
  cupsdStartBrowsing();
  cupsdStartPolling();

 /*
  * Create a pipe for CGI processes...
  */

  if (cupsdOpenPipe(CGIPipes))
    cupsdLogMessage(CUPSD_LOG_ERROR,
                    "cupsdStartServer: Unable to create pipes for CGI status!");
  else
  {
    CGIStatusBuffer = cupsdStatBufNew(CGIPipes[0], "[CGI]");

    printf("[server.c::cupsdStartServer()] created a pipe for cgi processes, adding to polling engine \n");
    cupsdAddSelect(CGIPipes[0], (cupsd_selfunc_t)cupsdUpdateCGI, NULL, NULL);
  }

 /*
  * Mark that the server has started and printers and jobs may be changed...
  */

  LastEvent     = CUPSD_EVENT_PRINTER_CHANGED | CUPSD_EVENT_JOB_STATE_CHANGED |
                  CUPSD_EVENT_SERVER_STARTED;

  started = 1;

  printf("[server.c::cupsdStartServer()] done \n");
}


/*
 * 'cupsdStopServer()' - Stop the server.
 */

void
cupsdStopServer(void)
{
  if (!started)
    return;

 /*
  * Close all network clients and stop all jobs...
  */

  cupsdCloseAllClients();
  cupsdStopListening();
  cupsdStopPolling();
  cupsdStopBrowsing();
  cupsdStopAllNotifiers();
  cupsdSaveRemoteCache();
  cupsdDeleteAllCerts();

  if (Clients)
  {
    cupsArrayDelete(Clients);
    Clients = NULL;
  }

 /*
  * Close the pipe for CGI processes...
  */

  if (CGIPipes[0] >= 0)
  {
    cupsdRemoveSelect(CGIPipes[0]);

    cupsdStatBufDelete(CGIStatusBuffer);
    close(CGIPipes[1]);

    CGIPipes[0] = -1;
    CGIPipes[1] = -1;
  }

 /*
  * Close all log files...
  */

  if (AccessFile != NULL)
  {
    cupsFileClose(AccessFile);

    AccessFile = NULL;
  }

  if (ErrorFile != NULL)
  {
    cupsFileClose(ErrorFile);

    ErrorFile = NULL;
  }

  if (PageFile != NULL)
  {
    cupsFileClose(PageFile);

    PageFile = NULL;
  }

#ifdef HAVE_NOTIFY_POST
 /*
  * Send one last notification as the server shuts down.
  */

  cupsdLogMessage(CUPSD_LOG_DEBUG,
                  "notify_post(\"com.apple.printerListChange\") last");
  notify_post("com.apple.printerListChange");
#endif /* HAVE_NOTIFY_POST */

  started = 0;
}


/*
 * End of "$Id: server.c 6649 2007-07-11 21:46:42Z mike $".
 */
