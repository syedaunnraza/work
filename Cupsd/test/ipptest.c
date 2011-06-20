/*
 * "$Id: ipptest.c 7721 2008-07-11 22:48:49Z mike $"
 *
 *   IPP test command for the Common UNIX Printing System (CUPS).
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
 * Contents:
 *
 *   main()       - Parse options and do tests.
 *   do_tests()   - Do tests as specified in the test file.
 *   get_tag()    - Get an IPP value or group tag from a name...
 *   get_token()  - Get a token from a file.
 *   print_attr() - Print an attribute on the screen.
 *   usage()      - Show program usage.
 */

/*
 * Include necessary headers...
 */

#include <stdio.h>
#include <stdlib.h>
#include <cups/string.h>
#include <errno.h>
#include <ctype.h>

#include <cups/cups.h>
#include <cups/language.h>


/*
 * Globals...
 */

int		Verbosity = 0;		/* Show all attributes? */
const char	* const TagNames[] =
		{			/* Value/group tag names */
		  "zero",		/* 0x00 */
		  "operation",		/* 0x01 */
		  "job",		/* 0x02 */
		  "end",		/* 0x03 */
		  "printer",		/* 0x04 */
		  "unsupported-group",	/* 0x05 */
		  "subscription",	/* 0x06 */
		  "event-notification",	/* 0x07 */
		  "", "", "", "", "", "", "", "",
		  "unsupported-value",	/* 0x10 */
		  "default",		/* 0x11 */
		  "unknown",		/* 0x12 */
		  "novalue",		/* 0x13 */
		  "",
		  "notsettable",	/* 0x15 */
		  "deleteattr",		/* 0x16 */
		  "anyvalue",		/* 0x17 */
		  "", "", "", "", "", "", "", "", "",
		  "integer",		/* 0x21 */
		  "boolean",		/* 0x22 */
		  "enum",		/* 0x23 */
		  "", "", "", "", "", "", "", "", "", "", "", "",
		  "string",		/* 0x30 */
		  "date",		/* 0x31 */
		  "resolution",		/* 0x32 */
		  "range",		/* 0x33 */
		  "collection",		/* 0x34 */
		  "textlang",		/* 0x35 */
		  "namelang",		/* 0x36 */
		  "", "", "", "", "", "", "", "", "", "",
		  "text",		/* 0x41 */
		  "name",		/* 0x42 */
		  "",
		  "keyword",		/* 0x44 */
		  "uri",		/* 0x45 */
		  "urischeme",		/* 0x46 */
		  "charset",		/* 0x47 */
		  "language",		/* 0x48 */
		  "mimetype"		/* 0x49 */
		};




/*
 * Local functions...
 */

int		do_tests(const char *, const char *);
ipp_op_t	ippOpValue(const char *);
ipp_status_t	ippErrorValue(const char *);
ipp_tag_t	get_tag(const char *);
const char	*get_tag_string(ipp_tag_t tag);
char		*get_token(FILE *, char *, int, int *linenum);
void		print_attr(ipp_attribute_t *);
void		usage(const char *option);


/*
 * 'main()' - Parse options and do tests.
 */

int					/* O - Exit status */
main(int  argc,				/* I - Number of command-line arguments */
     char *argv[])			/* I - Command-line arguments */
{
  int		i;			/* Looping var */
  int		status;			/* Status of tests... */
  const char	*uri;			/* URI to use */
  const char	*testfile;		/* Test file to use */
  int		interval;		/* Test interval */


 /*
  * We need at least:
  *
  *     testipp URL testfile
  */

  uri      = NULL;
  testfile = NULL;
  status   = 0;
  interval = 0;

  for (i = 1; i < argc; i ++)
  {
    if (argv[i][0] == '-')
    {
      if (!strcmp(argv[i], "-v"))
        Verbosity ++;
      else if (!strcmp(argv[i], "-d"))
      {
        i ++;

	if (i >= argc)
	  usage(NULL);
	else
	  putenv(argv[i]);
      }
      else if (!strcmp(argv[i], "-i"))
      {
        i++;

	if (i >= argc)
	  usage(NULL);
	else
	  interval = atoi(argv[i]);
      }
      else
        usage(argv[i]);
    }
    else if (!strncmp(argv[i], "ipp://", 6) ||
             !strncmp(argv[i], "http://", 7) ||
             !strncmp(argv[i], "https://", 8))
    {
     /*
      * Set URI...
      */

      if (!testfile && uri)
        usage(NULL);

      uri      = argv[i];
      testfile = NULL;
    }
    else
    {
     /*
      * Run test...
      */

      testfile = argv[i];

      if (!do_tests(uri, testfile))
        status ++;
    }
  }

  if (!uri || !testfile)
    usage(NULL);

 /*
  * Loop if the interval is set...
  */

  if (interval)
  {
    for (;;)
    {
      sleep(interval);
      do_tests(uri, testfile);
    }
  }

 /*
  * Exit...
  */

  return (status);
}


/*
 * 'do_tests()' - Do tests as specified in the test file.
 */

int					/* 1 = success, 0 = failure */
do_tests(const char *uri,		/* I - URI to connect on */
         const char *testfile)		/* I - Test file to use */
{
  int		i;			/* Looping var */
  int		linenum;		/* Current line number */
  int		version;		/* IPP version number to use */
  http_t	*http;			/* HTTP connection to server */
  char		method[HTTP_MAX_URI],	/* URI method */
		userpass[HTTP_MAX_URI],	/* username:password */
		server[HTTP_MAX_URI],	/* Server */
		resource[HTTP_MAX_URI];	/* Resource path */
  int		port;			/* Port number */
  FILE		*fp;			/* Test file */
  char		token[1024],		/* Token from file */
		*tokenptr,		/* Pointer into token */
		temp[1024],		/* Temporary string */
		*tempptr;		/* Pointer into temp string */
  ipp_t		*request;		/* IPP request */
  ipp_t		*response;		/* IPP response */
  ipp_op_t	op;			/* Operation */
  ipp_tag_t	group;			/* Current group */
  ipp_tag_t	value;			/* Current value type */
  ipp_attribute_t *attrptr;		/* Attribute pointer */
  char		attr[128];		/* Attribute name */
  int		num_statuses;		/* Number of valid status codes */
  ipp_status_t	statuses[100];		/* Valid status codes */
  int		num_expects;		/* Number of expected attributes */
  char		*expects[100];		/* Expected attributes */
  int		num_displayed;		/* Number of displayed attributes */
  char		*displayed[100];	/* Displayed attributes */
  char		name[1024];		/* Name of test */
  char		filename[1024];		/* Filename */
  int		pass;			/* Did we pass the test? */
  int		job_id;			/* Job ID from last operation */
  int		subscription_id;	/* Subscription ID from last operation */


 /*
  * Open the test file...
  */

  if ((fp = fopen(testfile, "r")) == NULL)
  {
    printf("Unable to open test file %s - %s\n", testfile, strerror(errno));
    return (0);
  }

 /*
  * Connect to the server...
  */

  httpSeparateURI(HTTP_URI_CODING_ALL, uri, method, sizeof(method), userpass,
                  sizeof(userpass), server, sizeof(server), &port, resource,
		  sizeof(resource));
  if ((http = httpConnect(server, port)) == NULL)
  {
    printf("Unable to connect to %s on port %d - %s\n", server, port,
           strerror(errno));
    fclose(fp);
    return (0);
  }

 /*
  * Loop on tests...
  */

  printf("\"%s\":\n", testfile);
  pass            = 1;
  job_id          = 0;
  subscription_id = 0;
  version         = 1;
  linenum         = 1;

  while (get_token(fp, token, sizeof(token), &linenum) != NULL)
  {
   /*
    * Expect an open brace...
    */

    if (strcmp(token, "{"))
    {
      printf("Unexpected token %s seen on line %d - aborting test!\n", token,
             linenum);
      httpClose(http);
      return (0);
    }

   /*
    * Initialize things...
    */

    httpSeparateURI(HTTP_URI_CODING_ALL, uri, method, sizeof(method), userpass,
                    sizeof(userpass), server, sizeof(server), &port, resource,
		    sizeof(resource));

    request       = ippNew();
    op            = (ipp_op_t)0;
    group         = IPP_TAG_ZERO;
    num_statuses  = 0;
    num_expects   = 0;
    num_displayed = 0;
    filename[0]   = '\0';

    strcpy(name, testfile);
    if (strrchr(name, '.') != NULL)
      *strrchr(name, '.') = '\0';

   /*
    * Parse until we see a close brace...
    */

    while (get_token(fp, token, sizeof(token), &linenum) != NULL)
    {
      if (!strcmp(token, "}"))
        break;
      else if (!strcasecmp(token, "NAME"))
      {
       /*
        * Name of test...
	*/

	get_token(fp, name, sizeof(name), &linenum);
      }
      else if (!strcasecmp(token, "VERSION"))
      {
       /*
        * IPP version number for test...
	*/

	get_token(fp, temp, sizeof(temp), &linenum);
	sscanf(temp, "%*d.%d", &version);
      }
      else if (!strcasecmp(token, "RESOURCE"))
      {
       /*
        * Resource name...
	*/

	get_token(fp, resource, sizeof(resource), &linenum);
      }
      else if (!strcasecmp(token, "OPERATION"))
      {
       /*
        * Operation...
	*/

	get_token(fp, token, sizeof(token), &linenum);
	op = ippOpValue(token);
      }
      else if (!strcasecmp(token, "GROUP"))
      {
       /*
        * Attribute group...
	*/

	get_token(fp, token, sizeof(token), &linenum);
	value = get_tag(token);

	if (value == group)
	  ippAddSeparator(request);

        group = value;
      }
      else if (!strcasecmp(token, "DELAY"))
      {
       /*
        * Delay before operation...
	*/

        int delay;

	get_token(fp, token, sizeof(token), &linenum);
	if ((delay = atoi(token)) > 0)
	  sleep(delay);
      }
      else if (!strcasecmp(token, "ATTR"))
      {
       /*
        * Attribute...
	*/

	get_token(fp, token, sizeof(token), &linenum);
	value = get_tag(token);
	get_token(fp, attr, sizeof(attr), &linenum);
	get_token(fp, temp, sizeof(temp), &linenum);

        token[sizeof(token) - 1] = '\0';

        for (tempptr = temp, tokenptr = token;
	     *tempptr && tokenptr < (token + sizeof(token) - 1);)
	  if (*tempptr == '$')
	  {
	   /*
	    * Substitute a string/number...
	    */

            if (!strncasecmp(tempptr + 1, "uri", 3))
	    {
	      strlcpy(tokenptr, uri, sizeof(token) - (tokenptr - token));
	      tempptr += 4;
	    }
	    else if (!strncasecmp(tempptr + 1, "method", 6))
	    {
	      strlcpy(tokenptr, method, sizeof(token) - (tokenptr - token));
	      tempptr += 7;
	    }
	    else if (!strncasecmp(tempptr + 1, "username", 8))
	    {
	      strlcpy(tokenptr, userpass, sizeof(token) - (tokenptr - token));
	      tempptr += 9;
	    }
	    else if (!strncasecmp(tempptr + 1, "hostname", 8))
	    {
	      strlcpy(tokenptr, server, sizeof(token) - (tokenptr - token));
	      tempptr += 9;
	    }
	    else if (!strncasecmp(tempptr + 1, "port", 4))
	    {
	      snprintf(tokenptr, sizeof(token) - (tokenptr - token),
	               "%d", port);
	      tempptr += 5;
	    }
	    else if (!strncasecmp(tempptr + 1, "resource", 8))
	    {
	      strlcpy(tokenptr, resource, sizeof(token) - (tokenptr - token));
	      tempptr += 9;
	    }
	    else if (!strncasecmp(tempptr + 1, "job-id", 6))
	    {
	      snprintf(tokenptr, sizeof(token) - (tokenptr - token),
	               "%d", job_id);
	      tempptr += 7;
	    }
	    else if (!strncasecmp(tempptr + 1, "notify-subscription-id", 22))
	    {
	      snprintf(tokenptr, sizeof(token) - (tokenptr - token),
	               "%d", subscription_id);
	      tempptr += 23;
	    }
	    else if (!strncasecmp(tempptr + 1, "user", 4))
	    {
	      strlcpy(tokenptr, cupsUser(), sizeof(token) - (tokenptr - token));
	      tempptr += 5;
	    }
	    else if (!strncasecmp(tempptr + 1, "ENV[", 4))
	    {
	      char *end;		/* End of $ENV[name] */


	      if ((end = strchr(tempptr + 5, ']')) != NULL)
	      {
	        *end++ = '\0';
		strlcpy(tokenptr,
		        getenv(tempptr + 5) ? getenv(tempptr + 5) : tempptr + 5,
		        sizeof(token) - (tokenptr - token));
		tempptr = end;
	      }
	      else
	      {
		*tokenptr++ = *tempptr++;
		*tokenptr   = '\0';
	      }
	    }
            else
	    {
	      *tokenptr++ = *tempptr++;
	      *tokenptr   = '\0';
	    }

            tokenptr += strlen(tokenptr);
	  }
	  else
	  {
	    *tokenptr++ = *tempptr++;
	    *tokenptr   = '\0';
	  }

        switch (value)
	{
	  case IPP_TAG_BOOLEAN :
	      if (!strcasecmp(token, "true"))
		ippAddBoolean(request, group, attr, 1);
              else
		ippAddBoolean(request, group, attr, atoi(token));
	      break;

	  case IPP_TAG_INTEGER :
	  case IPP_TAG_ENUM :
	      ippAddInteger(request, group, value, attr, atoi(token));
	      break;

	  case IPP_TAG_RESOLUTION :
	      puts("    ERROR: resolution tag not yet supported!");
	      break;

	  case IPP_TAG_RANGE :
	      puts("    ERROR: range tag not yet supported!");
	      break;

	  default :
	      if (!strchr(token, ','))
	        ippAddString(request, group, value, attr, NULL, token);
	      else
	      {
	       /*
	        * Multiple string values...
		*/

                int	num_values;	/* Number of values */
                char	*values[100],	/* Values */
			*ptr;		/* Pointer to next value */


                values[0]  = token;
		num_values = 1;

                for (ptr = strchr(token, ','); ptr; ptr = strchr(ptr, ','))
		{
		  *ptr++ = '\0';
		  values[num_values] = ptr;
		  num_values ++;
		}

	        ippAddStrings(request, group, value, attr, num_values,
		              NULL, (const char **)values);
	      }
	      break;
	}
      }
      else if (!strcasecmp(token, "FILE"))
      {
       /*
        * File...
	*/

	get_token(fp, filename, sizeof(filename), &linenum);
      }
      else if (!strcasecmp(token, "STATUS") &&
               num_statuses < (int)(sizeof(statuses) / sizeof(statuses[0])))
      {
       /*
        * Status...
	*/

	get_token(fp, token, sizeof(token), &linenum);
	statuses[num_statuses] = ippErrorValue(token);
	num_statuses ++;
      }
      else if (!strcasecmp(token, "EXPECT") &&
               num_expects < (int)(sizeof(expects) / sizeof(expects[0])))
      {
       /*
        * Expected attributes...
	*/

	get_token(fp, token, sizeof(token), &linenum);
	expects[num_expects] = strdup(token);
	num_expects ++;
      }
      else if (!strcasecmp(token, "DISPLAY") &&
               num_displayed < (int)(sizeof(displayed) / sizeof(displayed[0])))
      {
       /*
        * Display attributes...
	*/

	get_token(fp, token, sizeof(token), &linenum);
	displayed[num_displayed] = strdup(token);
	num_displayed ++;
      }
      else
      {
	printf("Unexpected token %s seen on line %d - aborting test!\n", token,
	       linenum);
	httpClose(http);
	ippDelete(request);
	return (0);
      }
    }

   /*
    * Submit the IPP request...
    */

    request->request.op.version[1]   = version;
    request->request.op.operation_id = op;
    request->request.op.request_id   = 1;

    if (Verbosity)
    {
      printf("%s:\n", ippOpString(op));

      for (attrptr = request->attrs; attrptr; attrptr = attrptr->next)
	print_attr(attrptr);
    }

    printf("    %-60.60s [", name);
    fflush(stdout);

    if (filename[0])
      response = cupsDoFileRequest(http, request, resource, filename);
    else
      response = cupsDoIORequest(http, request, resource, -1,
                                 Verbosity ? 1 : -1);

    if (response == NULL)
    {
      time_t curtime;

      curtime = time(NULL);

      puts("FAIL]");
      printf("        ERROR %04x (%s) @ %s\n", cupsLastError(),
	     cupsLastErrorString(), ctime(&curtime));
      pass = 0;
    }
    else
    {
      if ((attrptr = ippFindAttribute(response, "job-id",
                                      IPP_TAG_INTEGER)) != NULL)
        job_id = attrptr->values[0].integer;

      if ((attrptr = ippFindAttribute(response, "notify-subscription-id",
                                      IPP_TAG_INTEGER)) != NULL)
        subscription_id = attrptr->values[0].integer;

      for (i = 0; i < num_statuses; i ++)
        if (response->request.status.status_code == statuses[i])
	  break;

      if (i == num_statuses && num_statuses > 0)
	pass = 0;
      else
      {
        for (i = 0; i < num_expects; i ++)
	  if (ippFindAttribute(response, expects[i], IPP_TAG_ZERO) == NULL)
	  {
	    pass = 0;
	    break;
	  }
      }

      if (pass)
      {
	puts("PASS]");
	printf("        RECEIVED: %lu bytes in response\n",
	       (unsigned long)ippLength(response));

        if (Verbosity)
	{
	  for (attrptr = response->attrs; attrptr != NULL; attrptr = attrptr->next)
	    print_attr(attrptr);
        }
        else if (num_displayed > 0)
	{
	  for (attrptr = response->attrs; attrptr != NULL; attrptr = attrptr->next)
	    if (attrptr->name)
	    {
	      for (i = 0; i < num_displayed; i ++)
		if (!strcmp(displayed[i], attrptr->name))
		{
		  print_attr(attrptr);
		  break;
		}
	    }
        }
      }
      else
      {
	puts("FAIL]");
	printf("        RECEIVED: %lu bytes in response\n",
	       (unsigned long)ippLength(response));

	for (i = 0; i < num_statuses; i ++)
          if (response->request.status.status_code == statuses[i])
	    break;

	if (i == num_statuses && num_statuses > 0)
	  puts("        BAD STATUS");

	printf("        status-code = %04x (%s)\n",
	       cupsLastError(), ippErrorString(cupsLastError()));

        for (i = 0; i < num_expects; i ++)
	  if (ippFindAttribute(response, expects[i], IPP_TAG_ZERO) == NULL)
	    printf("        EXPECTED: %s\n", expects[i]);

	for (attrptr = response->attrs; attrptr != NULL; attrptr = attrptr->next)
	  print_attr(attrptr);
      }

      ippDelete(response);
    }

    for (i = 0; i < num_expects; i ++)
      free(expects[i]);

    if (!pass)
      break;
  }

  fclose(fp);
  httpClose(http);

  return (pass);
}


/*
 * 'get_tag()' - Get an IPP value or group tag from a name...
 */

ipp_tag_t				/* O - Value/group tag */
get_tag(const char *name)		/* I - Name of value/group tag */
{
  int			i;		/* Looping var */


  for (i = 0; i < (sizeof(TagNames) / sizeof(TagNames[0])); i ++)
    if (!strcasecmp(name, TagNames[i]))
      return ((ipp_tag_t)i);

  return (IPP_TAG_ZERO);
}


/*
 * 'get_tag_string()' - Get the string associated with a tag.
 */

const char *				/* O - Tag name string */
get_tag_string(ipp_tag_t tag)		/* I - IPP tag */
{
  if (tag < (ipp_tag_t)(sizeof(TagNames) / sizeof(TagNames[0])))
    return (TagNames[tag]);
  else
    return ("UNKNOWN");
}


/*
 * 'get_token()' - Get a token from a file.
 */

char *					/* O  - Token from file or NULL on EOF */
get_token(FILE *fp,			/* I  - File to read from */
          char *buf,			/* I  - Buffer to read into */
	  int  buflen,			/* I  - Length of buffer */
	  int  *linenum)		/* IO - Current line number */
{
  int	ch,				/* Character from file */
	quote;				/* Quoting character */
  char	*bufptr,			/* Pointer into buffer */
	*bufend;			/* End of buffer */


  for (;;)
  {
   /*
    * Skip whitespace...
    */

    while (isspace(ch = getc(fp)))
    {
      if (ch == '\n')
        (*linenum) ++;
    }

   /*
    * Read a token...
    */

    if (ch == EOF)
      return (NULL);
    else if (ch == '\'' || ch == '\"')
    {
     /*
      * Quoted text...
      */

      quote  = ch;
      bufptr = buf;
      bufend = buf + buflen - 1;

      while ((ch = getc(fp)) != EOF)
	if (ch == quote)
          break;
	else if (bufptr < bufend)
          *bufptr++ = ch;

      *bufptr = '\0';
      return (buf);
    }
    else if (ch == '#')
    {
     /*
      * Comment...
      */

      while ((ch = getc(fp)) != EOF)
	if (ch == '\n')
          break;

      (*linenum) ++;
    }
    else
    {
     /*
      * Whitespace delimited text...
      */

      ungetc(ch, fp);

      bufptr = buf;
      bufend = buf + buflen - 1;

      while ((ch = getc(fp)) != EOF)
	if (isspace(ch) || ch == '#')
          break;
	else if (bufptr < bufend)
          *bufptr++ = ch;

      if (ch == '#')
        ungetc(ch, fp);

      *bufptr = '\0';
      return (buf);
    }
  }
}


/*
 * 'print_attr()' - Print an attribute on the screen.
 */

void
print_attr(ipp_attribute_t *attr)	/* I - Attribute to print */
{
  int		i;			/* Looping var */


  if (attr->name == NULL)
  {
    puts("        -- separator --");
    return;
  }

  printf("        %s (%s%s) = ", attr->name,
         attr->num_values > 1 ? "1setOf " : "",
	 get_tag_string(attr->value_tag));

  switch (attr->value_tag)
  {
    case IPP_TAG_INTEGER :
    case IPP_TAG_ENUM :
	for (i = 0; i < attr->num_values; i ++)
	  printf("%d ", attr->values[i].integer);
	break;

    case IPP_TAG_BOOLEAN :
	for (i = 0; i < attr->num_values; i ++)
	  if (attr->values[i].boolean)
	    printf("true ");
	  else
	    printf("false ");
	break;

    case IPP_TAG_NOVALUE :
	printf("novalue");
	break;

    case IPP_TAG_RANGE :
	for (i = 0; i < attr->num_values; i ++)
	  printf("%d-%d ", attr->values[i].range.lower,
		 attr->values[i].range.upper);
	break;

    case IPP_TAG_RESOLUTION :
	for (i = 0; i < attr->num_values; i ++)
	  printf("%dx%d%s ", attr->values[i].resolution.xres,
		 attr->values[i].resolution.yres,
		 attr->values[i].resolution.units == IPP_RES_PER_INCH ?
		     "dpi" : "dpc");
	break;

    case IPP_TAG_STRING :
    case IPP_TAG_TEXT :
    case IPP_TAG_NAME :
    case IPP_TAG_KEYWORD :
    case IPP_TAG_CHARSET :
    case IPP_TAG_URI :
    case IPP_TAG_MIMETYPE :
    case IPP_TAG_LANGUAGE :
	for (i = 0; i < attr->num_values; i ++)
	  printf("\"%s\" ", attr->values[i].string.text);
	break;

    case IPP_TAG_TEXTLANG :
    case IPP_TAG_NAMELANG :
	for (i = 0; i < attr->num_values; i ++)
	  printf("\"%s\",%s ", attr->values[i].string.text,
		 attr->values[i].string.charset);
	break;

    default :
	break; /* anti-compiler-warning-code */
  }

  putchar('\n');
}


/*
 * 'usage()' - Show program usage.
 */

void
usage(const char *option)		/* I - Option string or NULL */
{
  if (option)
    fprintf(stderr, "ipptest: Unknown option \"%s\"!\n", option);

  fputs("Usage: ipptest [options] URL testfile [ ... testfileN ]\n", stderr);
  fputs("Options:\n", stderr);
  fputs("\n", stderr);
  fputs("-i N    Repeat the last test file once every N seconds.\n", stderr);
  fputs("-v      Show all attributes in response, even on success.\n", stderr);

  exit(1);
}


/*
 * End of "$Id: ipptest.c 7721 2008-07-11 22:48:49Z mike $".
 */
