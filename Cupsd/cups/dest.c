/*
 * "$Id: dest.c 7721 2008-07-11 22:48:49Z mike $"
 *
 *   User-defined destination (and option) support for the Common UNIX
 *   Printing System (CUPS).
 *
 *   Copyright 2007-2008 by Apple Inc.
 *   Copyright 1997-2007 by Easy Software Products.
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
 *   cupsAddDest()            - Add a destination to the list of destinations.
 *   cupsFreeDests()          - Free the memory used by the list of
 *                              destinations.
 *   cupsGetDest()            - Get the named destination from the list.
 *   cupsGetDests()           - Get the list of destinations from the default
 *                              server.
 *   cupsGetDests2()          - Get the list of destinations from the
 *                              specified server.
 *   cupsRemoveDest()         - Remove a destination from the destination list.
 *   cupsDestSetDefaultDest() - Set the default destination.
 *   cupsSetDests()           - Set the list of destinations for the default
 *                              server.
 *   cupsSetDests2()          - Set the list of destinations for the specified
 *                              server.
 *   cups_get_dests()         - Get destinations from a file.
 *   cups_get_sdests()        - Get destinations from a server.
 */

/*
 * Include necessary headers...
 */

#include "globals.h"
#include <stdlib.h>
#include <ctype.h>
#include <sys/stat.h>

#ifdef HAVE_NOTIFY_H
#  include <notify.h>
#endif /* HAVE_NOTIFY_H */


/*
 * Local functions...
 */

static int	cups_get_dests(const char *filename, int num_dests,
		               cups_dest_t **dests);
static int	cups_get_sdests(http_t *http, ipp_op_t op, int num_dests,
		                cups_dest_t **dests);


/*
 * 'cupsAddDest()' - Add a destination to the list of destinations.
 *
 * This function cannot be used to add a new class or printer queue,
 * it only adds a new container of saved options for the named
 * destination or instance.
 *
 * If the named destination already exists, the destination list is
 * returned unchanged.  Adding a new instance of a destination creates
 * a copy of that destination's options.
 *
 * Use the cupsSaveDests() function to save the updated list of
 * destinations to the user's lpoptions file.
 */

int					/* O  - New number of destinations */
cupsAddDest(const char  *name,		/* I  - Destination name */
            const char	*instance,	/* I  - Instance name or NULL for none/primary */
            int         num_dests,	/* I  - Number of destinations */
            cups_dest_t **dests)	/* IO - Destinations */
{
  int		i;			/* Looping var */
  cups_dest_t	*dest;			/* Destination pointer */
  cups_dest_t	*parent;		/* Parent destination */
  cups_option_t	*option;		/* Current option */


  if (!name || !dests)
    return (0);

  if (cupsGetDest(name, instance, num_dests, *dests))
    return (num_dests);

 /*
  * Add new destination...
  */

  if (num_dests == 0)
    dest = malloc(sizeof(cups_dest_t));
  else
    dest = realloc(*dests, sizeof(cups_dest_t) * (num_dests + 1));

  if (dest == NULL)
    return (num_dests);

  *dests = dest;

 /*
  * Find where to insert the destination...
  */

  for (i = num_dests; i > 0; i --, dest ++)
    if (strcasecmp(name, dest->name) < 0)
      break;
    else if (!instance && dest->instance)
      break;
    else if (!strcasecmp(name, dest->name) &&
             instance  && dest->instance &&
             strcasecmp(instance, dest->instance) < 0)
      break;

  if (i > 0)
    memmove(dest + 1, dest, i * sizeof(cups_dest_t));

 /*
  * Initialize the destination...
  */

  dest->name        = strdup(name);
  dest->is_default  = 0;
  dest->num_options = 0;
  dest->options     = (cups_option_t *)0;

  if (!instance)
    dest->instance = NULL;
  else
  {
   /*
    * Copy options from the primary instance...
    */

    dest->instance = strdup(instance);

    if ((parent = cupsGetDest(name, NULL, num_dests + 1, *dests)) != NULL)
    {
      for (i = parent->num_options, option = parent->options;
           i > 0;
	   i --, option ++)
	dest->num_options = cupsAddOption(option->name, option->value,
	                                  dest->num_options,
					  &(dest->options));
    }
  }

  return (num_dests + 1);
}


/*
 * 'cupsFreeDests()' - Free the memory used by the list of destinations.
 */

void
cupsFreeDests(int         num_dests,	/* I - Number of destinations */
              cups_dest_t *dests)	/* I - Destinations */
{
  int		i;			/* Looping var */
  cups_dest_t	*dest;			/* Current destination */


  if (num_dests == 0 || dests == NULL)
    return;

  for (i = num_dests, dest = dests; i > 0; i --, dest ++)
  {
    free(dest->name);

    if (dest->instance)
      free(dest->instance);

    cupsFreeOptions(dest->num_options, dest->options);
  }

  free(dests);
}


/*
 * 'cupsGetDest()' - Get the named destination from the list.
 *
 * Use the cupsGetDests() or cupsGetDests2() functions to get a
 * list of supported destinations for the current user.
 */

cups_dest_t *				/* O - Destination pointer or NULL */
cupsGetDest(const char  *name,		/* I - Destination name or NULL for the default destination */
            const char	*instance,	/* I - Instance name or NULL */
            int         num_dests,	/* I - Number of destinations */
            cups_dest_t *dests)		/* I - Destinations */
{
  int	comp;				/* Result of comparison */


  if (num_dests <= 0 || !dests)
    return (NULL);

  if (!name)
  {
   /*
    * NULL name for default printer.
    */

    while (num_dests > 0)
    {
      if (dests->is_default)
        return (dests);

      num_dests --;
      dests ++;
    }
  }
  else
  {
   /*
    * Lookup name and optionally the instance...
    */

    while (num_dests > 0)
    {
      if ((comp = strcasecmp(name, dests->name)) < 0)
	return (NULL);
      else if (comp == 0)
      {
	if ((!instance && !dests->instance) ||
            (instance != NULL && dests->instance != NULL &&
	     !strcasecmp(instance, dests->instance)))
	  return (dests);
      }

      num_dests --;
      dests ++;
    }
  }

  return (NULL);
}


/*
 * 'cupsGetDests()' - Get the list of destinations from the default server.
 *
 * Starting with CUPS 1.2, the returned list of destinations include the
 * printer-info, printer-is-accepting-jobs, printer-is-shared,
 * printer-make-and-model, printer-state, printer-state-change-time,
 * printer-state-reasons, and printer-type attributes as options.
 *
 * Use the cupsFreeDests() function to free the destination list and
 * the cupsGetDest() function to find a particular destination.
 */

int					/* O - Number of destinations */
cupsGetDests(cups_dest_t **dests)	/* O - Destinations */
{
  int		num_dests;		/* Number of destinations */
  http_t	*http;			/* HTTP connection */


 /*
  * Connect to the CUPS server and get the destination list and options...
  */

  http = httpConnectEncrypt(cupsServer(), ippPort(), cupsEncryption());

  num_dests = cupsGetDests2(http, dests);

  if (http)
    httpClose(http);

  return (num_dests);
}


/*
 * 'cupsGetDests2()' - Get the list of destinations from the specified server.
 *
 * Starting with CUPS 1.2, the returned list of destinations include the
 * printer-info, printer-is-accepting-jobs, printer-is-shared,
 * printer-make-and-model, printer-state, printer-state-change-time,
 * printer-state-reasons, and printer-type attributes as options.
 *
 * Use the cupsFreeDests() function to free the destination list and
 * the cupsGetDest() function to find a particular destination.
 *
 * @since CUPS 1.1.21@
 */

int					/* O - Number of destinations */
cupsGetDests2(http_t      *http,	/* I - HTTP connection */
              cups_dest_t **dests)	/* O - Destinations */
{
  int		i;			/* Looping var */
  int		num_dests;		/* Number of destinations */
  cups_dest_t	*dest;			/* Destination pointer */
  const char	*home;			/* HOME environment variable */
  char		filename[1024];		/* Local ~/.cups/lpoptions file */
  const char	*defprinter;		/* Default printer */
  char		name[1024],		/* Copy of printer name */
		*instance;		/* Pointer to instance name */
  int		num_reals;		/* Number of real queues */
  cups_dest_t	*reals;			/* Real queues */
  _cups_globals_t *cg = _cupsGlobals();	/* Global data */


 /*
  * Range check the input...
  */

  if (!http || !dests)
    return (0);

 /*
  * Initialize destination array...
  */

  num_dests = 0;
  *dests    = (cups_dest_t *)0;

 /*
  * Grab the printers and classes...
  */

  num_dests = cups_get_sdests(http, CUPS_GET_PRINTERS, num_dests, dests);
  num_dests = cups_get_sdests(http, CUPS_GET_CLASSES, num_dests, dests);

 /*
  * Make a copy of the "real" queues for a later sanity check...
  */

  if (num_dests > 0)
  {
    num_reals = num_dests;
    reals     = calloc(num_reals, sizeof(cups_dest_t));

    if (reals)
      memcpy(reals, *dests, num_reals * sizeof(cups_dest_t));
    else
      num_reals = 0;
  }
  else
  {
    num_reals = 0;
    reals     = NULL;
  }

 /*
  * Grab the default destination...
  */

  if ((defprinter = cupsGetDefault2(http)) != NULL)
  {
   /*
    * Grab printer and instance name...
    */

    strlcpy(name, defprinter, sizeof(name));

    if ((instance = strchr(name, '/')) != NULL)
      *instance++ = '\0';

   /*
    * Lookup the printer and instance and make it the default...
    */

    if ((dest = cupsGetDest(name, instance, num_dests, *dests)) != NULL)
      dest->is_default = 1;
  }
  else
  {
   /*
    * This initialization of "instance" is unnecessary, but avoids a
    * compiler warning...
    */

    instance = NULL;
  }

 /*
  * Load the /etc/cups/lpoptions and ~/.cups/lpoptions files...
  */

  snprintf(filename, sizeof(filename), "%s/lpoptions", cg->cups_serverroot);
  num_dests = cups_get_dests(filename, num_dests, dests);

  if ((home = getenv("HOME")) != NULL)
  {
    snprintf(filename, sizeof(filename), "%s/.cups/lpoptions", home);
    if (access(filename, 0))
      snprintf(filename, sizeof(filename), "%s/.lpoptions", home);

    num_dests = cups_get_dests(filename, num_dests, dests);
  }

 /*
  * Validate the current default destination - this prevents old
  * Default lines in /etc/cups/lpoptions and ~/.cups/lpoptions from
  * pointing to a non-existent printer or class...
  */

  if (num_reals)
  {
   /*
    * See if we have a default printer...
    */

    if ((dest = cupsGetDest(NULL, NULL, num_dests, *dests)) != NULL)
    {
     /*
      * Have a default; see if it is real...
      */

      dest = cupsGetDest(dest->name, NULL, num_reals, reals);
    }

   /*
    * If dest is NULL, then no default (that exists) is set, so we
    * need to set a default if one exists...
    */

    if (dest == NULL && defprinter != NULL)
    {
      for (i = 0; i < num_dests; i ++)
        (*dests)[i].is_default = 0;

      if ((dest = cupsGetDest(name, instance, num_dests, *dests)) != NULL)
	dest->is_default = 1;
    }

   /*
    * Free memory...
    */

    free(reals);
  }

 /*
  * Return the number of destinations...
  */

  return (num_dests);
}


/*
 * 'cupsRemoveDest()' - Remove a destination from the destination list.
 *
 * Removing a destination/instance does not delete the class or printer
 * queue, merely the lpoptions for that destination/instance.  Use the
 * cupsSetDests() or cupsSetDests2() functions to save the new options
 * for the user.
 *
 * @since CUPS 1.3@
 */

int					/* O  - New number of destinations */
cupsRemoveDest(const char  *name,	/* I  - Destination name */
               const char  *instance,	/* I  - Instance name or NULL */
	       int         num_dests,	/* I  - Number of destinations */
	       cups_dest_t **dests)	/* IO - Destinations */
{
  int		i;			/* Index into destinations */
  cups_dest_t	*dest;			/* Pointer to destination */


 /*
  * Find the destination...
  */

  if ((dest = cupsGetDest(name, instance, num_dests, *dests)) == NULL)
    return (num_dests);

 /*
  * Free memory...
  */

  cupsFreeOptions(dest->num_options, dest->options);

 /*
  * Remove the destination from the array...
  */

  num_dests --;

  i = dest - *dests;

  if (i < num_dests)
    memmove(dest, dest + 1, (num_dests - i) * sizeof(cups_dest_t));

  return (num_dests);
}


/*
 * 'cupsDestSetDefaultDest()' - Set the default destination.
 *
 * @since CUPS 1.3@
 */

void
cupsSetDefaultDest(
    const char  *name,			/* I - Destination name */
    const char  *instance,		/* I - Instance name or NULL */
    int         num_dests,		/* I - Number of destinations */
    cups_dest_t *dests)			/* I - Destinations */
{
  int		i;			/* Looping var */
  cups_dest_t	*dest;			/* Current destination */


 /*
  * Range check input...
  */

  if (!name || num_dests <= 0 || !dests)
    return;

 /*
  * Loop through the array and set the "is_default" flag for the matching
  * destination...
  */

  for (i = num_dests, dest = dests; i > 0; i --, dest ++)
    dest->is_default = !strcasecmp(name, dest->name) &&
                       ((!instance && !dest->instance) ||
		        (instance && dest->instance &&
			 !strcasecmp(instance, dest->instance)));
}


/*
 * 'cupsSetDests()' - Save the list of destinations for the default server.
 *
 * This function saves the destinations to /etc/cups/lpoptions when run
 * as root and ~/.cups/lpoptions when run as a normal user.
 */

void
cupsSetDests(int         num_dests,	/* I - Number of destinations */
             cups_dest_t *dests)	/* I - Destinations */
{
  http_t	*http;			/* HTTP connection */


 /*
  * Connect to the CUPS server and save the destination list and options...
  */

  http = httpConnectEncrypt(cupsServer(), ippPort(), cupsEncryption());

  cupsSetDests2(http, num_dests, dests);

  if (http)
    httpClose(http);
}


/*
 * 'cupsSetDests2()' - Save the list of destinations for the specified server.
 *
 * This function saves the destinations to /etc/cups/lpoptions when run
 * as root and ~/.cups/lpoptions when run as a normal user.
 *
 * @since CUPS 1.1.21@
 */

int					/* O - 0 on success, -1 on error */
cupsSetDests2(http_t      *http,	/* I - HTTP connection */
              int         num_dests,	/* I - Number of destinations */
              cups_dest_t *dests)	/* I - Destinations */
{
  int		i, j;			/* Looping vars */
  int		wrote;			/* Wrote definition? */
  cups_dest_t	*dest;			/* Current destination */
  cups_option_t	*option;		/* Current option */
  _ipp_option_t	*match;			/* Matching attribute for option */
  FILE		*fp;			/* File pointer */
#ifndef WIN32
  const char	*home;			/* HOME environment variable */
#endif /* WIN32 */
  char		filename[1024];		/* lpoptions file */
  int		num_temps;		/* Number of temporary destinations */
  cups_dest_t	*temps,			/* Temporary destinations */
		*temp;			/* Current temporary dest */
  const char	*val;			/* Value of temporary option */
  _cups_globals_t *cg = _cupsGlobals();	/* Global data */


 /*
  * Range check the input...
  */

  if (!http || !num_dests || !dests)
    return (-1);

 /*
  * Get the server destinations...
  */

  num_temps = cups_get_sdests(http, CUPS_GET_PRINTERS, 0, &temps);
  num_temps = cups_get_sdests(http, CUPS_GET_CLASSES, num_temps, &temps);

 /*
  * Figure out which file to write to...
  */

  snprintf(filename, sizeof(filename), "%s/lpoptions", cg->cups_serverroot);

#ifndef WIN32
  if (getuid())
  {
   /*
    * Merge in server defaults...
    */

    num_temps = cups_get_dests(filename, num_temps, &temps);

   /*
    * Point to user defaults...
    */

    if ((home = getenv("HOME")) != NULL)
    {
     /*
      * Remove the old ~/.lpoptions file...
      */

      snprintf(filename, sizeof(filename), "%s/.lpoptions", home);
      unlink(filename);

     /*
      * Create ~/.cups subdirectory...
      */

      snprintf(filename, sizeof(filename), "%s/.cups", home);
      if (access(filename, 0))
        mkdir(filename, 0700);

      snprintf(filename, sizeof(filename), "%s/.cups/lpoptions", home);
    }
  }
#endif /* !WIN32 */

 /*
  * Try to open the file...
  */

  if ((fp = fopen(filename, "w")) == NULL)
  {
    cupsFreeDests(num_temps, temps);
    return (-1);
  }

#ifndef WIN32
 /*
  * Set the permissions to 0644 when saving to the /etc/cups/lpoptions
  * file...
  */

  if (!getuid())
    fchmod(fileno(fp), 0644);
#endif /* !WIN32 */

 /*
  * Write each printer; each line looks like:
  *
  *    Dest name[/instance] options
  *    Default name[/instance] options
  */

  for (i = num_dests, dest = dests; i > 0; i --, dest ++)
    if (dest->instance != NULL || dest->num_options != 0 || dest->is_default)
    {
      if (dest->is_default)
      {
	fprintf(fp, "Default %s", dest->name);
	if (dest->instance)
	  fprintf(fp, "/%s", dest->instance);

        wrote = 1;
      }
      else
        wrote = 0;

      if ((temp = cupsGetDest(dest->name, dest->instance, num_temps, temps)) == NULL)
        temp = cupsGetDest(dest->name, NULL, num_temps, temps);

      for (j = dest->num_options, option = dest->options; j > 0; j --, option ++)
      {
       /*
        * See if this option is a printer attribute; if so, skip it...
	*/

        if ((match = _ippFindOption(option->name)) != NULL &&
	    match->group_tag == IPP_TAG_PRINTER)
	  continue;

       /*
	* See if the server/global options match these; if so, don't
	* write 'em.
	*/

        if (temp &&
	    (val = cupsGetOption(option->name, temp->num_options,
	                         temp->options)) != NULL &&
            !strcasecmp(val, option->value))
	  continue;

       /*
        * Options don't match, write to the file...
	*/

        if (!wrote)
	{
	  fprintf(fp, "Dest %s", dest->name);
	  if (dest->instance)
	    fprintf(fp, "/%s", dest->instance);
          wrote = 1;
	}
        
        if (option->value[0])
	{
	  if (strchr(option->value, ' ') ||
	      strchr(option->value, '\\') ||
	      strchr(option->value, '\"') ||
	      strchr(option->value, '\''))
	  {
	   /*
	    * Quote the value...
	    */

	    fprintf(fp, " %s=\"", option->name);

	    for (val = option->value; *val; val ++)
	    {
	      if (strchr("\"\'\\", *val))
	        putc('\\', fp);

              putc(*val, fp);
	    }

	    putc('\"', fp);
          }
	  else
	  {
	   /*
	    * Store the literal value...
	    */

	    fprintf(fp, " %s=%s", option->name, option->value);
          }
	}
	else
	  fprintf(fp, " %s", option->name);
      }

      if (wrote)
        fputs("\n", fp);
    }

 /*
  * Free the temporary destinations and close the file...
  */

  cupsFreeDests(num_temps, temps);

  fclose(fp);

#ifdef HAVE_NOTIFY_POST
 /*
  * Send a notification so that MacOS X applications can know about the
  * change, too.
  */

  notify_post("com.apple.printerListChange");
#endif /* HAVE_NOTIFY_POST */

  return (0);
}


/*
 * 'cups_get_dests()' - Get destinations from a file.
 */

static int				/* O - Number of destinations */
cups_get_dests(const char  *filename,	/* I - File to read from */
               int         num_dests,	/* I - Number of destinations */
               cups_dest_t **dests)	/* IO - Destinations */
{
  int		i;			/* Looping var */
  cups_dest_t	*dest;			/* Current destination */
  FILE		*fp;			/* File pointer */
  char		line[8192],		/* Line from file */
		*lineptr,		/* Pointer into line */
		*name,			/* Name of destination/option */
		*instance;		/* Instance of destination */
  const char	*printer;		/* PRINTER or LPDEST */


 /*
  * Check environment variables...
  */

  if ((printer = getenv("LPDEST")) == NULL)
    if ((printer = getenv("PRINTER")) != NULL)
      if (strcmp(printer, "lp") == 0)
        printer = NULL;

 /*
  * Try to open the file...
  */

  if ((fp = fopen(filename, "r")) == NULL)
    return (num_dests);

 /*
  * Read each printer; each line looks like:
  *
  *    Dest name[/instance] options
  *    Default name[/instance] options
  */

  while (fgets(line, sizeof(line), fp) != NULL)
  {
   /*
    * See what type of line it is...
    */

    if (strncasecmp(line, "dest", 4) == 0 && isspace(line[4] & 255))
      lineptr = line + 4;
    else if (strncasecmp(line, "default", 7) == 0 && isspace(line[7] & 255))
      lineptr = line + 7;
    else
      continue;

   /*
    * Skip leading whitespace...
    */

    while (isspace(*lineptr & 255))
      lineptr ++;

    if (!*lineptr)
      continue;

    name = lineptr;

   /*
    * Search for an instance...
    */

    while (!isspace(*lineptr & 255) && *lineptr && *lineptr != '/')
      lineptr ++;

    if (!*lineptr)
      continue;

    if (*lineptr == '/')
    {
     /*
      * Found an instance...
      */

      *lineptr++ = '\0';
      instance = lineptr;

     /*
      * Search for an instance...
      */

      while (!isspace(*lineptr & 255) && *lineptr)
	lineptr ++;
    }
    else
      instance = NULL;

    *lineptr++ = '\0';

   /*
    * See if the primary instance of the destination exists; if not,
    * ignore this entry and move on...
    */

    if (cupsGetDest(name, NULL, num_dests, *dests) == NULL)
      continue;

   /*
    * Add the destination...
    */

    num_dests = cupsAddDest(name, instance, num_dests, dests);

    if ((dest = cupsGetDest(name, instance, num_dests, *dests)) == NULL)
    {
     /*
      * Out of memory!
      */

      fclose(fp);
      return (num_dests);
    }

   /*
    * Add options until we hit the end of the line...
    */

    dest->num_options = cupsParseOptions(lineptr, dest->num_options,
                                         &(dest->options));

   /*
    * Set this as default if needed...
    */

    if (strncasecmp(line, "default", 7) == 0 && printer == NULL)
    {
      for (i = 0; i < num_dests; i ++)
        (*dests)[i].is_default = 0;

      dest->is_default = 1;
    }
  }

 /*
  * Close the file and return...
  */

  fclose(fp);      

  return (num_dests);
}


/*
 * 'cups_get_sdests()' - Get destinations from a server.
 */

static int				/* O - Number of destinations */
cups_get_sdests(http_t      *http,	/* I - HTTP connection */
                ipp_op_t    op,		/* I - get-printers or get-classes */
                int         num_dests,	/* I - Number of destinations */
                cups_dest_t **dests)	/* IO - Destinations */
{
  int		i;			/* Looping var */
  cups_dest_t	*dest;			/* Current destination */
  ipp_t		*request,		/* IPP Request */
		*response;		/* IPP Response */
  ipp_attribute_t *attr;		/* Current attribute */
  int		accepting,		/* printer-is-accepting-jobs attribute */
		shared,			/* printer-is-shared attribute */
		state,			/* printer-state attribute */
		change_time,		/* printer-state-change-time attribute */
		type;			/* printer-type attribute */
  const char	*info,			/* printer-info attribute */
		*location,		/* printer-location attribute */
		*make_model,		/* printer-make-and-model attribute */
		*name;			/* printer-name attribute */
  char		job_sheets[1024],	/* job-sheets-default attribute */
		auth_info_req[1024],	/* auth-info-required attribute */
		reasons[1024];		/* printer-state-reasons attribute */
  int		num_options;		/* Number of options */
  cups_option_t	*options;		/* Options */
  char		optname[1024],		/* Option name */
		value[2048],		/* Option value */
		*ptr;			/* Pointer into name/value */
  static const char * const pattrs[] =	/* Attributes we're interested in */
		{
		  "auth-info-required",
		  "job-sheets-default",
		  "printer-info",
		  "printer-is-accepting-jobs",
		  "printer-is-shared",
		  "printer-location",
		  "printer-make-and-model",
		  "printer-name",
		  "printer-state",
		  "printer-state-change-time",
		  "printer-state-reasons",
		  "printer-type",
		  "printer-defaults"
		};


 /*
  * Build a CUPS_GET_PRINTERS or CUPS_GET_CLASSES request, which require
  * the following attributes:
  *
  *    attributes-charset
  *    attributes-natural-language
  *    requesting-user-name
  */

  request = ippNewRequest(op);

  ippAddStrings(request, IPP_TAG_OPERATION, IPP_TAG_KEYWORD,
                "requested-attributes", sizeof(pattrs) / sizeof(pattrs[0]),
		NULL, pattrs);

  ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME,
               "requesting-user-name", NULL, cupsUser());

 /*
  * Do the request and get back a response...
  */

  if ((response = cupsDoRequest(http, request, "/")) != NULL)
  {
    for (attr = response->attrs; attr != NULL; attr = attr->next)
    {
     /*
      * Skip leading attributes until we hit a printer...
      */

      while (attr != NULL && attr->group_tag != IPP_TAG_PRINTER)
        attr = attr->next;

      if (attr == NULL)
        break;

     /*
      * Pull the needed attributes from this printer...
      */

      accepting   = 0;
      change_time = 0;
      info        = NULL;
      location    = NULL;
      make_model  = NULL;
      name        = NULL;
      num_options = 0;
      options     = NULL;
      shared      = 1;
      state       = IPP_PRINTER_IDLE;
      type        = CUPS_PRINTER_LOCAL;

      auth_info_req[0] = '\0';
      job_sheets[0]    = '\0';
      reasons[0]       = '\0';

      while (attr != NULL && attr->group_tag == IPP_TAG_PRINTER)
      {
        if (!strcmp(attr->name, "auth-info-required") &&
	    attr->value_tag == IPP_TAG_KEYWORD)
        {
	  strlcpy(auth_info_req, attr->values[0].string.text,
		  sizeof(auth_info_req));

	  for (i = 1, ptr = auth_info_req + strlen(auth_info_req);
	       i < attr->num_values;
	       i ++)
	  {
	    snprintf(ptr, sizeof(auth_info_req) - (ptr - auth_info_req), ",%s",
	             attr->values[i].string.text);
	    ptr += strlen(ptr);
	  }
        }
        else if (!strcmp(attr->name, "job-sheets-default") &&
	         (attr->value_tag == IPP_TAG_KEYWORD ||
	          attr->value_tag == IPP_TAG_NAME))
        {
	  if (attr->num_values == 2)
	    snprintf(job_sheets, sizeof(job_sheets), "%s,%s",
	             attr->values[0].string.text, attr->values[1].string.text);
	  else
	    strlcpy(job_sheets, attr->values[0].string.text,
	            sizeof(job_sheets));
        }
        else if (!strcmp(attr->name, "printer-info") &&
	         attr->value_tag == IPP_TAG_TEXT)
	  info = attr->values[0].string.text;
	else if (!strcmp(attr->name, "printer-is-accepting-jobs") &&
	         attr->value_tag == IPP_TAG_BOOLEAN)
          accepting = attr->values[0].boolean;
	else if (!strcmp(attr->name, "printer-is-shared") &&
	         attr->value_tag == IPP_TAG_BOOLEAN)
          shared = attr->values[0].boolean;
        else if (!strcmp(attr->name, "printer-location") &&
	         attr->value_tag == IPP_TAG_TEXT)
	  location = attr->values[0].string.text;
        else if (!strcmp(attr->name, "printer-make-and-model") &&
	         attr->value_tag == IPP_TAG_TEXT)
	  make_model = attr->values[0].string.text;
        else if (!strcmp(attr->name, "printer-name") &&
	         attr->value_tag == IPP_TAG_NAME)
	  name = attr->values[0].string.text;
	else if (!strcmp(attr->name, "printer-state") &&
	         attr->value_tag == IPP_TAG_ENUM)
          state = attr->values[0].integer;
	else if (!strcmp(attr->name, "printer-state-change-time") &&
	         attr->value_tag == IPP_TAG_INTEGER)
          change_time = attr->values[0].integer;
        else if (!strcmp(attr->name, "printer-state-reasons") &&
	         attr->value_tag == IPP_TAG_KEYWORD)
	{
	  strlcpy(reasons, attr->values[0].string.text, sizeof(reasons));
	  for (i = 1, ptr = reasons + strlen(reasons);
	       i < attr->num_values;
	       i ++)
	  {
	    snprintf(ptr, sizeof(reasons) - (ptr - reasons), ",%s",
	             attr->values[i].string.text);
	    ptr += strlen(ptr);
	  }
	}
	else if (!strcmp(attr->name, "printer-type") &&
	         attr->value_tag == IPP_TAG_ENUM)
          type = attr->values[0].integer;
        else if (strncmp(attr->name, "notify-", 7) &&
	         (attr->value_tag == IPP_TAG_BOOLEAN ||
		  attr->value_tag == IPP_TAG_ENUM ||
		  attr->value_tag == IPP_TAG_INTEGER ||
		  attr->value_tag == IPP_TAG_KEYWORD ||
		  attr->value_tag == IPP_TAG_NAME ||
		  attr->value_tag == IPP_TAG_RANGE) &&
		 strstr(attr->name, "-default"))
	{
	  char	*valptr;		/* Pointer into attribute value */


	 /*
	  * Add a default option...
	  */

          strlcpy(optname, attr->name, sizeof(optname));
	  if ((ptr = strstr(optname, "-default")) != NULL)
	    *ptr = '\0';

          value[0] = '\0';
	  for (i = 0, ptr = value; i < attr->num_values; i ++)
	  {
	    if (ptr >= (value + sizeof(value) - 1))
	      break;

            if (i)
	      *ptr++ = ',';

            switch (attr->value_tag)
	    {
	      case IPP_TAG_INTEGER :
	      case IPP_TAG_ENUM :
	          snprintf(ptr, sizeof(value) - (ptr - value), "%d",
		           attr->values[i].integer);
	          break;

	      case IPP_TAG_BOOLEAN :
	          if (attr->values[i].boolean)
		    strlcpy(ptr, "true", sizeof(value) - (ptr - value));
		  else
		    strlcpy(ptr, "false", sizeof(value) - (ptr - value));
	          break;

	      case IPP_TAG_RANGE :
	          if (attr->values[i].range.lower ==
		          attr->values[i].range.upper)
	            snprintf(ptr, sizeof(value) - (ptr - value), "%d",
		             attr->values[i].range.lower);
		  else
	            snprintf(ptr, sizeof(value) - (ptr - value), "%d-%d",
		             attr->values[i].range.lower,
			     attr->values[i].range.upper);
	          break;

	      default :
		  for (valptr = attr->values[i].string.text;
		       *valptr && ptr < (value + sizeof(value) - 2);)
		  {
	            if (strchr(" \t\n\\\'\"", *valptr))
		      *ptr++ = '\\';

		    *ptr++ = *valptr++;
		  }

		  *ptr = '\0';
	          break;
	    }

	    ptr += strlen(ptr);
          }

	  num_options = cupsAddOption(optname, value, num_options, &options);
	}

        attr = attr->next;
      }

     /*
      * See if we have everything needed...
      */

      if (!name)
      {
        cupsFreeOptions(num_options, options);

        if (attr == NULL)
	  break;
	else
          continue;
      }

      num_dests = cupsAddDest(name, NULL, num_dests, dests);

      if ((dest = cupsGetDest(name, NULL, num_dests, *dests)) != NULL)
      {
        dest->num_options = num_options;
	dest->options     = options;

        num_options = 0;
	options     = NULL;

        if (auth_info_req[0])
          dest->num_options = cupsAddOption("auth-info-required", auth_info_req,
	                                    dest->num_options,
	                                    &(dest->options));

        if (job_sheets[0])
          dest->num_options = cupsAddOption("job-sheets", job_sheets,
	                                    dest->num_options,
	                                    &(dest->options));

        if (info)
          dest->num_options = cupsAddOption("printer-info", info,
	                                    dest->num_options,
	                                    &(dest->options));

        sprintf(value, "%d", accepting);
	dest->num_options = cupsAddOption("printer-is-accepting-jobs", value,
					  dest->num_options,
					  &(dest->options));

        sprintf(value, "%d", shared);
	dest->num_options = cupsAddOption("printer-is-shared", value,
					  dest->num_options,
					  &(dest->options));

        if (location)
          dest->num_options = cupsAddOption("printer-location",
	                                    location, dest->num_options,
	                                    &(dest->options));

        if (make_model)
          dest->num_options = cupsAddOption("printer-make-and-model",
	                                    make_model, dest->num_options,
	                                    &(dest->options));

        sprintf(value, "%d", state);
	dest->num_options = cupsAddOption("printer-state", value,
					  dest->num_options,
					  &(dest->options));

        if (change_time)
	{
	  sprintf(value, "%d", change_time);
	  dest->num_options = cupsAddOption("printer-state-change-time", value,
					    dest->num_options,
					    &(dest->options));
        }

        if (reasons[0])
          dest->num_options = cupsAddOption("printer-state-reasons", reasons,
					    dest->num_options,
	                                    &(dest->options));

        sprintf(value, "%d", type);
	dest->num_options = cupsAddOption("printer-type", value,
					  dest->num_options,
					  &(dest->options));
      }

      cupsFreeOptions(num_options, options);

      if (attr == NULL)
	break;
    }

    ippDelete(response);
  }

 /*
  * Return the count...
  */

  return (num_dests);
}


/*
 * End of "$Id: dest.c 7721 2008-07-11 22:48:49Z mike $".
 */
