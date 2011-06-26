/*
 * "$Id: cupstestppd.c 7729 2008-07-14 18:06:16Z mike $"
 *
 *   PPD test program for the Common UNIX Printing System (CUPS).
 *
 *   Copyright 2007-2008 by Apple Inc.
 *   Copyright 1997-2007 by Easy Software Products, all rights reserved.
 *
 *   These coded instructions, statements, and computer programs are the
 *   property of Apple Inc. and are protected by Federal copyright
 *   law.  Distribution and use rights are outlined in the file "LICENSE.txt"
 *   which should have been included with this file.  If this file is
 *   file is missing or damaged, see the license at "http://www.cups.org/".
 *
 *   PostScript is a trademark of Adobe Systems, Inc.
 *
 *   This file is subject to the Apple OS-Developed Software exception.
 *
 * Contents:
 *
 *   main()               - Main entry for test program.
 *   check_basics()       - Check for CR LF, mixed line endings, and blank lines.
 *   check_constraints()  - Check UIConstraints in the PPD file.
 *   check_defaults()     - Check default option keywords in the PPD file.
 *   check_filters()      - Check filters in the PPD file.
 *   check_translations() - Check translations in the PPD file.
 *   show_conflicts()     - Show option conflicts in a PPD file.
 *   test_raster()        - Test PostScript commands for raster printers.
 *   usage()              - Show program usage...
 *   valid_utf8()         - Check whether a string contains valid UTF-8 text.
 */

/*
 * Include necessary headers...
 */

#include <cups/string.h>
#include <cups/cups.h>
#include <cups/i18n.h>
#include <filter/raster.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>


/*
 * Error warning overrides...
 */

enum
{
  WARN_NONE = 0,
  WARN_CONSTRAINTS = 1,
  WARN_DEFAULTS = 2,
  WARN_FILTERS = 4,
  WARN_TRANSLATIONS = 8,
  WARN_ALL = 15
};


/*
 * Error codes...
 */

enum
{
  ERROR_NONE = 0,
  ERROR_USAGE,
  ERROR_FILE_OPEN,
  ERROR_PPD_FORMAT,
  ERROR_CONFORMANCE
};


/*
 * Line endings...
 */

enum
{
  EOL_NONE = 0,
  EOL_CR,
  EOL_LF,
  EOL_CRLF
};


/*
 * Local functions...
 */

static void	check_basics(const char *filename);
static int	check_constraints(ppd_file_t *ppd, int errors, int verbose,
		                  int warn);
static int	check_defaults(ppd_file_t *ppd, int errors, int verbose,
		               int warn);
static int	check_filters(ppd_file_t *ppd, const char *root, int errors,
		              int verbose, int warn);
static int	check_translations(ppd_file_t *ppd, int errors, int verbose,\
		                   int warn);
static void	show_conflicts(ppd_file_t *ppd);
static int	test_raster(ppd_file_t *ppd, int verbose);
static void	usage(void);
static int	valid_utf8(const char *s);


/*
 * 'main()' - Main entry for test program.
 */

int					/* O - Exit status */
main(int  argc,				/* I - Number of command-line args */
     char *argv[])			/* I - Command-line arguments */
{
  int		i, j, k, m, n;		/* Looping vars */
  int		len;			/* Length of option name */
  char		*opt;			/* Option character */
  const char	*ptr;			/* Pointer into string */
  int		files;			/* Number of files */
  int		verbose;		/* Want verbose output? */
  int		warn;			/* Which errors to just warn about */
  int		status;			/* Exit status */
  int		errors;			/* Number of conformance errors */
  int		ppdversion;		/* PPD spec version in PPD file */
  ppd_status_t	error;			/* Status of ppdOpen*() */
  int		line;			/* Line number for error */
  struct stat	statbuf;		/* File information */
  char		pathprog[1024],		/* Complete path to program/filter */
		*root;			/* Root directory */
  int		xdpi,			/* X resolution */
		ydpi;			/* Y resolution */
  ppd_file_t	*ppd;			/* PPD file record */
  ppd_attr_t	*attr;			/* PPD attribute */
  ppd_size_t	*size;			/* Size record */
  ppd_group_t	*group;			/* UI group */
  ppd_option_t	*option;		/* Standard UI option */
  ppd_group_t	*group2;		/* UI group */
  ppd_option_t	*option2;		/* Standard UI option */
  ppd_choice_t	*choice;		/* Standard UI option choice */
  struct lconv	*loc;			/* Locale data */
  static char	*uis[] = { "BOOLEAN", "PICKONE", "PICKMANY" };
  static char	*sections[] = { "ANY", "DOCUMENT", "EXIT",
                                "JCL", "PAGE", "PROLOG" };


  _cupsSetLocale(argv);
  loc = localeconv();

 /*
  * Display PPD files for each file listed on the command-line...
  */

  ppdSetConformance(PPD_CONFORM_STRICT);

  verbose = 0;
  ppd     = NULL;
  files   = 0;
  status  = ERROR_NONE;
  root    = "";
  warn    = WARN_NONE;

  for (i = 1; i < argc; i ++)
    if (argv[i][0] == '-' && argv[i][1])
    {
      for (opt = argv[i] + 1; *opt; opt ++)
        switch (*opt)
	{
	  case 'R' :			/* Alternate root directory */
	      i ++;

	      if (i >= argc)
	        usage();

              root = argv[i];
	      break;

	  case 'W' :			/* Turn errors into warnings  */
	      i ++;

	      if (i >= argc)
	        usage();

              if (!strcmp(argv[i], "none"))
	        warn = WARN_NONE;
	      else if (!strcmp(argv[i], "constraints"))
	        warn |= WARN_CONSTRAINTS;
	      else if (!strcmp(argv[i], "defaults"))
	        warn |= WARN_DEFAULTS;
	      else if (!strcmp(argv[i], "filters"))
	        warn |= WARN_FILTERS;
	      else if (!strcmp(argv[i], "translations"))
	        warn |= WARN_TRANSLATIONS;
	      else if (!strcmp(argv[i], "all"))
	        warn = WARN_ALL;
	      else
	        usage();
	      break;

	  case 'q' :			/* Quiet mode */
	      if (verbose > 0)
	      {
        	_cupsLangPuts(stderr,
		              _("cupstestppd: The -q option is incompatible "
			        "with the -v option.\n"));
		return (1);
	      }

	      verbose --;
	      break;

	  case 'r' :			/* Relaxed mode */
              ppdSetConformance(PPD_CONFORM_RELAXED);
	      break;

	  case 'v' :			/* Verbose mode */
	      if (verbose < 0)
	      {
        	_cupsLangPuts(stderr,
		              _("cupstestppd: The -v option is incompatible "
			        "with the -q option.\n"));
		return (1);
	      }

	      verbose ++;
	      break;

	  default :
	      usage();
	      break;
	}
    }
    else
    {
     /*
      * Open the PPD file...
      */

      if (files && verbose >= 0)
        _cupsLangPuts(stdout, "\n");

      files ++;

      if (argv[i][0] == '-')
      {
       /*
        * Read from stdin...
	*/

        if (verbose >= 0)
          printf("(stdin):");

        ppd = ppdOpen(stdin);
      }
      else
      {
       /*
        * Read from a file...
	*/

        if (verbose >= 0)
          printf("%s:", argv[i]);

        ppd = ppdOpenFile(argv[i]);
      }

      if (ppd == NULL)
      {
        error = ppdLastError(&line);

	if (error <= PPD_ALLOC_ERROR)
	{
	  status = ERROR_FILE_OPEN;

	  if (verbose >= 0)
            _cupsLangPrintf(stdout,
	                    _(" FAIL\n"
			      "      **FAIL**  Unable to open PPD file - %s\n"),
			    strerror(errno));
	}
	else
	{
	  status = ERROR_PPD_FORMAT;

          if (verbose >= 0)
	  {
            _cupsLangPrintf(stdout,
	                    _(" FAIL\n"
			      "      **FAIL**  Unable to open PPD file - "
			      "%s on line %d.\n"),
			    ppdErrorString(error), line);

            switch (error)
	    {
	      case PPD_MISSING_PPDADOBE4 :
	          _cupsLangPuts(stdout,
		                _("                REF: Page 42, section 5.2.\n"));
	          break;
	      case PPD_MISSING_VALUE :
	          _cupsLangPuts(stdout,
		                _("                REF: Page 20, section 3.4.\n"));
	          break;
	      case PPD_BAD_OPEN_GROUP :
	      case PPD_NESTED_OPEN_GROUP :
	          _cupsLangPuts(stdout,
		                _("                REF: Pages 45-46, section 5.2.\n"));
	          break;
	      case PPD_BAD_OPEN_UI :
	      case PPD_NESTED_OPEN_UI :
	          _cupsLangPuts(stdout,
		                _("                REF: Pages 42-45, section 5.2.\n"));
	          break;
	      case PPD_BAD_ORDER_DEPENDENCY :
	          _cupsLangPuts(stdout,
		                _("                REF: Pages 48-49, section 5.2.\n"));
	          break;
	      case PPD_BAD_UI_CONSTRAINTS :
	          _cupsLangPuts(stdout,
		                _("                REF: Pages 52-54, section 5.2.\n"));
	          break;
	      case PPD_MISSING_ASTERISK :
	          _cupsLangPuts(stdout,
		                _("                REF: Page 15, section 3.2.\n"));
	          break;
	      case PPD_LINE_TOO_LONG :
	          _cupsLangPuts(stdout,
		                _("                REF: Page 15, section 3.1.\n"));
	          break;
	      case PPD_ILLEGAL_CHARACTER :
	          _cupsLangPuts(stdout,
		                _("                REF: Page 15, section 3.1.\n"));
	          break;
	      case PPD_ILLEGAL_MAIN_KEYWORD :
	          _cupsLangPuts(stdout,
		                _("                REF: Pages 16-17, section 3.2.\n"));
	          break;
	      case PPD_ILLEGAL_OPTION_KEYWORD :
	          _cupsLangPuts(stdout,
		                _("                REF: Page 19, section 3.3.\n"));
	          break;
	      case PPD_ILLEGAL_TRANSLATION :
	          _cupsLangPuts(stdout,
		                _("                REF: Page 27, section 3.5.\n"));
	          break;
              default :
	          break;
	    }

	    check_basics(argv[i]);
	  }
        }

	continue;
      }

     /*
      * Show the header and then perform basic conformance tests (limited
      * only by what the CUPS PPD functions actually load...)
      */

      errors     = 0;
      ppdversion = 43;

      if (verbose > 0)
        _cupsLangPuts(stdout,
	              _("\n    DETAILED CONFORMANCE TEST RESULTS\n"));

      if ((attr = ppdFindAttr(ppd, "FormatVersion", NULL)) != NULL &&
          attr->value)
        ppdversion = (int)(10 * _cupsStrScand(attr->value, NULL, loc) + 0.5);

      for (j = 0; j < ppd->num_filters; j ++)
        if (strstr(ppd->filters[j], "application/vnd.cups-raster"))
	{
	  if (!test_raster(ppd, verbose))
	    errors ++;
	  break;
	}

     /*
      * Look for default keywords with no matching option...
      */

      if (!(warn & WARN_DEFAULTS))
        errors = check_defaults(ppd, errors, verbose, 0);

      if ((attr = ppdFindAttr(ppd, "DefaultImageableArea", NULL)) == NULL)
      {
	if (verbose >= 0)
	{
	  if (!errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  _cupsLangPuts(stdout,
			_("      **FAIL**  REQUIRED DefaultImageableArea\n"
			  "                REF: Page 102, section 5.15.\n"));
	}

	errors ++;
      }
      else if (ppdPageSize(ppd, attr->value) == NULL &&
	       strcmp(attr->value, "Unknown"))
      {
	if (verbose >= 0)
	{
	  if (!errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  _cupsLangPrintf(stdout,
			  _("      **FAIL**  BAD DefaultImageableArea %s!\n"
			    "                REF: Page 102, section 5.15.\n"),
			  attr->value);
	}

	errors ++;
      }
      else
      {
	if (verbose > 0)
	  _cupsLangPuts(stdout, _("        PASS    DefaultImageableArea\n"));
      }

      if ((attr = ppdFindAttr(ppd, "DefaultPaperDimension", NULL)) == NULL)
      {
	if (verbose >= 0)
	{
	  if (!errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  _cupsLangPuts(stdout,
			_("      **FAIL**  REQUIRED DefaultPaperDimension\n"
			  "                REF: Page 103, section 5.15.\n"));
	}

	errors ++;
      }
      else if (ppdPageSize(ppd, attr->value) == NULL &&
	       strcmp(attr->value, "Unknown"))
      {
	if (verbose >= 0)
	{
	  if (!errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  _cupsLangPrintf(stdout,
			  _("      **FAIL**  BAD DefaultPaperDimension %s!\n"
			    "                REF: Page 103, section 5.15.\n"),
			  attr->value);
	}

	errors ++;
      }
      else if (verbose > 0)
	_cupsLangPuts(stdout, _("        PASS    DefaultPaperDimension\n"));

      for (j = 0, group = ppd->groups; j < ppd->num_groups; j ++, group ++)
	for (k = 0, option = group->options; k < group->num_options; k ++, option ++)
	{
	 /*
	  * Verify that we have a default choice...
	  */

	  if (option->defchoice[0])
	  {
	    if (ppdFindChoice(option, option->defchoice) == NULL &&
		strcmp(option->defchoice, "Unknown"))
	    {
	      if (verbose >= 0)
	      {
		if (!errors && !verbose)
		  _cupsLangPuts(stdout, _(" FAIL\n"));

		_cupsLangPrintf(stdout,
				_("      **FAIL**  BAD Default%s %s\n"
				  "                REF: Page 40, section 4.5.\n"),
				option->keyword, option->defchoice);
	      }

	      errors ++;
	    }
	    else if (verbose > 0)
	      _cupsLangPrintf(stdout,
			      _("        PASS    Default%s\n"),
			      option->keyword);
	  }
	  else
	  {
	    if (verbose >= 0)
	    {
	      if (!errors && !verbose)
		_cupsLangPuts(stdout, _(" FAIL\n"));

	      _cupsLangPrintf(stdout,
			      _("      **FAIL**  REQUIRED Default%s\n"
				"                REF: Page 40, section 4.5.\n"),
			      option->keyword);
	    }

	    errors ++;
	  }
	}

      if (ppdFindAttr(ppd, "FileVersion", NULL) != NULL)
      {
	if (verbose > 0)
	  _cupsLangPuts(stdout, _("        PASS    FileVersion\n"));
      }
      else
      {
	if (verbose >= 0)
	{
	  if (!errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  _cupsLangPuts(stdout,
	                _("      **FAIL**  REQUIRED FileVersion\n"
			  "                REF: Page 56, section 5.3.\n"));
        }

	errors ++;
      }

      if (ppdFindAttr(ppd, "FormatVersion", NULL) != NULL)
      {
	if (verbose > 0)
	  _cupsLangPuts(stdout, _("        PASS    FormatVersion\n"));
      }
      else
      {
	if (verbose >= 0)
	{
	  if (!errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  _cupsLangPuts(stdout,
	                _("      **FAIL**  REQUIRED FormatVersion\n"
			  "                REF: Page 56, section 5.3.\n"));
        }

	errors ++;
      }

      if (ppd->lang_encoding != NULL)
      {
	if (verbose > 0)
	  _cupsLangPuts(stdout, _("        PASS    LanguageEncoding\n"));
      }
      else if (ppdversion > 40)
      {
	if (verbose >= 0)
	{
	  if (!errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  _cupsLangPuts(stdout,
	                _("      **FAIL**  REQUIRED LanguageEncoding\n"
			  "                REF: Pages 56-57, section 5.3.\n"));
        }

	errors ++;
      }

      if (ppd->lang_version != NULL)
      {
	if (verbose > 0)
	  _cupsLangPuts(stdout, _("        PASS    LanguageVersion\n"));
      }
      else
      {
	if (verbose >= 0)
	{
	  if (!errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  _cupsLangPuts(stdout,
	                _("      **FAIL**  REQUIRED LanguageVersion\n"
			  "                REF: Pages 57-58, section 5.3.\n"));
        }

	errors ++;
      }

      if (ppd->manufacturer != NULL)
      {
        if (!strncasecmp(ppd->manufacturer, "Hewlett-Packard", 15) ||
	    !strncasecmp(ppd->manufacturer, "Hewlett Packard", 15))
	{
	  if (verbose >= 0)
	  {
	    if (!errors && !verbose)
	      _cupsLangPuts(stdout, _(" FAIL\n"));

	    _cupsLangPuts(stdout,
	                  _("      **FAIL**  BAD Manufacturer (should be "
			    "\"HP\")\n"
			    "                REF: Page 211, table D.1.\n"));
          }

	  errors ++;
	}
        else if (!strncasecmp(ppd->manufacturer, "OkiData", 7) ||
	         !strncasecmp(ppd->manufacturer, "Oki Data", 8))
	{
	  if (verbose >= 0)
	  {
	    if (!errors && !verbose)
	      _cupsLangPuts(stdout, _(" FAIL\n"));

	    _cupsLangPuts(stdout,
	                  _("      **FAIL**  BAD Manufacturer (should be "
			    "\"Oki\")\n"
			    "                REF: Page 211, table D.1.\n"));
          }

	  errors ++;
	}
	else if (verbose > 0)
	  _cupsLangPuts(stdout, _("        PASS    Manufacturer\n"));
      }
      else if (ppdversion >= 43)
      {
	if (verbose >= 0)
	{
	  if (!errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  _cupsLangPuts(stdout,
	                _("      **FAIL**  REQUIRED Manufacturer\n"
			  "                REF: Pages 58-59, section 5.3.\n"));
        }

	errors ++;
      }

      if (ppd->modelname != NULL)
      {
        for (ptr = ppd->modelname; *ptr; ptr ++)
	  if (!isalnum(*ptr & 255) && !strchr(" ./-+", *ptr))
	    break;

	if (*ptr)
	{
	  if (verbose >= 0)
	  {
	    if (!errors && !verbose)
	      _cupsLangPuts(stdout, _(" FAIL\n"));

	    _cupsLangPrintf(stdout,
	                    _("      **FAIL**  BAD ModelName - \"%c\" not "
			      "allowed in string.\n"
			      "                REF: Pages 59-60, section 5.3.\n"),
	                    *ptr);
          }

	  errors ++;
	}
	else if (verbose > 0)
	  _cupsLangPuts(stdout, _("        PASS    ModelName\n"));
      }
      else
      {
	if (verbose >= 0)
	{
	  if (!errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  _cupsLangPuts(stdout,
	                _("      **FAIL**  REQUIRED ModelName\n"
			  "                REF: Pages 59-60, section 5.3.\n"));
        }

	errors ++;
      }

      if (ppd->nickname != NULL)
      {
	if (verbose > 0)
	  _cupsLangPuts(stdout, _("        PASS    NickName\n"));
      }
      else
      {
	if (verbose >= 0)
	{
	  if (!errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  _cupsLangPuts(stdout,
	                _("      **FAIL**  REQUIRED NickName\n"
	                  "                REF: Page 60, section 5.3.\n"));
        }

	errors ++;
      }

      if (ppdFindOption(ppd, "PageSize") != NULL)
      {
	if (verbose > 0)
	  _cupsLangPuts(stdout, _("        PASS    PageSize\n"));
      }
      else
      {
	if (verbose >= 0)
	{
	  if (!errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  _cupsLangPuts(stdout,
	                _("      **FAIL**  REQUIRED PageSize\n"
			  "                REF: Pages 99-100, section 5.14.\n"));
        }

	errors ++;
      }

      if (ppdFindOption(ppd, "PageRegion") != NULL)
      {
	if (verbose > 0)
	  _cupsLangPuts(stdout, _("        PASS    PageRegion\n"));
      }
      else
      {
	if (verbose >= 0)
	{
	  if (!errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  _cupsLangPuts(stdout,
	                _("      **FAIL**  REQUIRED PageRegion\n"
			  "                REF: Page 100, section 5.14.\n"));
        }

	errors ++;
      }

      if (ppd->pcfilename != NULL)
      {
	if (verbose > 0)
          _cupsLangPuts(stdout, _("        PASS    PCFileName\n"));
      }
      else
      {
	if (verbose >= 0)
	{
	  if (!errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  _cupsLangPuts(stdout,
	                _("      **FAIL**  REQUIRED PCFileName\n"
			  "                REF: Pages 61-62, section 5.3.\n"));
        }

	errors ++;
      }

      if (ppd->product != NULL)
      {
        if (ppd->product[0] != '(' ||
	    ppd->product[strlen(ppd->product) - 1] != ')')
	{
	  if (verbose >= 0)
	  {
	    if (!errors && !verbose)
	      _cupsLangPuts(stdout, _(" FAIL\n"));

	    _cupsLangPuts(stdout,
	                  _("      **FAIL**  BAD Product - not \"(string)\".\n"
			    "                REF: Page 62, section 5.3.\n"));
          }

	  errors ++;
	}
	else if (verbose > 0)
	  _cupsLangPuts(stdout, _("        PASS    Product\n"));
      }
      else
      {
	if (verbose >= 0)
	{
	  if (!errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  _cupsLangPuts(stdout,
	                _("      **FAIL**  REQUIRED Product\n"
			  "                REF: Page 62, section 5.3.\n"));
        }

	errors ++;
      }

      if ((attr = ppdFindAttr(ppd, "PSVersion", NULL)) != NULL &&
          attr->value != NULL)
      {
        char	junkstr[255];			/* Temp string */
	int	junkint;			/* Temp integer */


        if (sscanf(attr->value, "(%[^)])%d", junkstr, &junkint) != 2)
	{
	  if (verbose >= 0)
	  {
	    if (!errors && !verbose)
	      _cupsLangPuts(stdout, _(" FAIL\n"));

	    _cupsLangPuts(stdout,
	                  _("      **FAIL**  BAD PSVersion - not \"(string) "
			    "int\".\n"
			    "                REF: Pages 62-64, section 5.3.\n"));
          }

	  errors ++;
	}
	else if (verbose > 0)
	  _cupsLangPuts(stdout, _("        PASS    PSVersion\n"));
      }
      else
      {
	if (verbose >= 0)
	{
	  if (!errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  _cupsLangPuts(stdout,
	                _("      **FAIL**  REQUIRED PSVersion\n"
			  "                REF: Pages 62-64, section 5.3.\n"));
        }

	errors ++;
      }

      if (ppd->shortnickname != NULL)
      {
        if (strlen(ppd->shortnickname) > 31)
	{
	  if (verbose >= 0)
	  {
	    if (!errors && !verbose)
	      _cupsLangPuts(stdout, _(" FAIL\n"));

	    _cupsLangPuts(stdout,
	                  _("      **FAIL**  BAD ShortNickName - longer "
			    "than 31 chars.\n"
			    "                REF: Pages 64-65, section 5.3.\n"));
          }

	  errors ++;
	}
	else if (verbose > 0)
	  _cupsLangPuts(stdout, _("        PASS    ShortNickName\n"));
      }
      else if (ppdversion >= 43)
      {
	if (verbose >= 0)
	{
	  if (!errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  _cupsLangPuts(stdout,
	                _("      **FAIL**  REQUIRED ShortNickName\n"
			  "                REF: Page 64-65, section 5.3.\n"));
        }

	errors ++;
      }

      if (ppd->patches != NULL && strchr(ppd->patches, '\"') &&
          strstr(ppd->patches, "*End"))
      {
	if (verbose >= 0)
	{
	  if (!errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  _cupsLangPuts(stdout,
	                _("      **FAIL**  BAD JobPatchFile attribute in file\n"
	                  "                REF: Page 24, section 3.4.\n"));
        }

	errors ++;
      }

     /*
      * Check for page sizes without the corresponding ImageableArea or
      * PaperDimension values...
      */

      if (ppd->num_sizes == 0)
      {
	if (verbose >= 0)
	{
	  if (!errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  _cupsLangPuts(stdout,
	                _("      **FAIL**  REQUIRED PageSize\n"
			  "                REF: Page 41, section 5.\n"
			  "                REF: Page 99, section 5.14.\n"));
        }

	errors ++;
      }
      else
      {
	for (j = 0, size = ppd->sizes; j < ppd->num_sizes; j ++, size ++)
	{
	 /*
	  * Don't check custom size...
	  */

	  if (!strcmp(size->name, "Custom"))
	    continue;

	 /*
	  * Check for ImageableArea...
	  */

          if (size->left == 0.0 && size->bottom == 0.0 &&
	      size->right == 0.0 && size->top == 0.0)
	  {
	    if (verbose >= 0)
	    {
	      if (!errors && !verbose)
		_cupsLangPuts(stdout, _(" FAIL\n"));

	      _cupsLangPrintf(stdout,
	                      _("      **FAIL**  REQUIRED ImageableArea for "
			        "PageSize %s\n"
				"                REF: Page 41, section 5.\n"
				"                REF: Page 102, section 5.15.\n"),
	        	      size->name);
            }

	    errors ++;
	  }

	 /*
	  * Check for PaperDimension...
	  */

          if (size->width == 0.0 && size->length == 0.0)
	  {
	    if (verbose >= 0)
	    {
	      if (!errors && !verbose)
		_cupsLangPuts(stdout, _(" FAIL\n"));

	      _cupsLangPrintf(stdout,
	                      _("      **FAIL**  REQUIRED PaperDimension "
			        "for PageSize %s\n"
				"                REF: Page 41, section 5.\n"
				"                REF: Page 103, section 5.15.\n"),
	                      size->name);
            }

	    errors ++;
	  }
	}
      }

     /*
      * Check for valid Resolution, JCLResolution, or SetResolution values...
      */

      if ((option = ppdFindOption(ppd, "Resolution")) == NULL)
	if ((option = ppdFindOption(ppd, "JCLResolution")) == NULL)
          option = ppdFindOption(ppd, "SetResolution");

      if (option != NULL)
      {
        for (j = option->num_choices, choice = option->choices; j > 0; j --, choice ++)
        {
	 /*
	  * Verify that all resolution options are of the form NNNdpi
	  * or NNNxNNNdpi...
	  */

          xdpi = strtol(choice->choice, (char **)&ptr, 10);
	  if (ptr > choice->choice && xdpi > 0)
	  {
	    if (*ptr == 'x')
	      ydpi = strtol(ptr + 1, (char **)&ptr, 10);
	    else
	      ydpi = xdpi;
	  }
	  else
	    ydpi = xdpi;

	  if (xdpi <= 0 || xdpi > 99999 || ydpi <= 0 || ydpi > 99999 ||
	      strcmp(ptr, "dpi"))
	  {
	    if (verbose >= 0)
	    {
	      if (!errors && !verbose)
		_cupsLangPuts(stdout, _(" FAIL\n"));

	      _cupsLangPrintf(stdout,
	                      _("      **FAIL**  Bad %s choice %s!\n"
			        "                REF: Page 84, section 5.9\n"),
	                      option->keyword, choice->choice);
            }

	    errors ++;
	  }
	}
      }

     /*
      * Check for a duplex option, and for standard values...
      */

      if ((option = ppdFindOption(ppd, "Duplex")) == NULL)
	if ((option = ppdFindOption(ppd, "JCLDuplex")) == NULL)
	  if ((option = ppdFindOption(ppd, "EFDuplex")) == NULL)
            option = ppdFindOption(ppd, "KD03Duplex");

      if (option != NULL)
      {
        if (ppdFindChoice(option, "None") == NULL)
	{
	  if (verbose >= 0)
	  {
	    if (!errors && !verbose)
	      _cupsLangPuts(stdout, _(" FAIL\n"));

	    _cupsLangPrintf(stdout,
	                    _("      **FAIL**  REQUIRED %s does not define "
			      "choice None!\n"
			      "                REF: Page 122, section 5.17\n"),
	                    option->keyword);
          }

	  errors ++;
	}

        for (j = option->num_choices, choice = option->choices; j > 0; j --, choice ++)
          if (strcmp(choice->choice, "None") &&
	      strcmp(choice->choice, "DuplexNoTumble") &&
	      strcmp(choice->choice, "DuplexTumble") &&
	      strcmp(choice->choice, "SimplexTumble"))
	  {
	    if (verbose >= 0)
	    {
	      if (!errors && !verbose)
		_cupsLangPuts(stdout, _(" FAIL\n"));

	      _cupsLangPrintf(stdout,
	                      _("      **FAIL**  Bad %s choice %s!\n"
			        "                REF: Page 122, section 5.17\n"),
	        	      option->keyword, choice->choice);
            }

	    errors ++;
	  }
      }

      if ((attr = ppdFindAttr(ppd, "1284DeviceID", NULL)) &&
          strcmp(attr->name, "1284DeviceID"))
      {
	if (verbose >= 0)
	{
	  if (!errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  _cupsLangPrintf(stdout,
	                  _("      **FAIL**  %s must be 1284DeviceID!\n"
			    "                REF: Page 72, section 5.5\n"),
			  attr->name);
        }

	errors ++;
      }

      if (!(warn & WARN_CONSTRAINTS))
        errors = check_constraints(ppd, errors, verbose, 0);

      if (!(warn & WARN_FILTERS))
        errors = check_filters(ppd, root, errors, verbose, 0);

      if (!(warn & WARN_TRANSLATIONS))
        errors = check_translations(ppd, errors, verbose, 0);

      if ((attr = ppdFindAttr(ppd, "cupsLanguages", NULL)) != NULL &&
	  attr->value)
      {
       /*
	* This file contains localizations, check for conformance of the
	* base translation...
	*/

        if ((attr = ppdFindAttr(ppd, "LanguageEncoding", NULL)) != NULL)
	{
	  if (!attr->value || strcmp(attr->value, "ISOLatin1"))
	  {
	    if (!errors && !verbose)
	      _cupsLangPuts(stdout, _(" FAIL\n"));

            if (verbose >= 0)
	      _cupsLangPrintf(stdout,
	                      _("      **FAIL**  Bad LanguageEncoding %s - "
			        "must be ISOLatin1!\n"),
	                      attr->value ? attr->value : "(null)");

            errors ++;
	  }

          if (!ppd->lang_version || strcmp(ppd->lang_version, "English"))
	  {
	    if (!errors && !verbose)
	      _cupsLangPuts(stdout, _(" FAIL\n"));

            if (verbose >= 0)
	      _cupsLangPrintf(stdout,
	                      _("      **FAIL**  Bad LanguageVersion %s - "
			        "must be English!\n"),
	                      ppd->lang_version ? ppd->lang_version : "(null)");

            errors ++;
	  }
	  
	 /*
	  * Loop through all options and choices...
	  */

	  for (option = ppdFirstOption(ppd);
	       option;
	       option = ppdNextOption(ppd))
	  {
	   /*
	    * Check for special characters outside A0 to BF, F7, or F8
	    * that are used for languages other than English.
	    */

	    for (ptr = option->text; *ptr; ptr ++)
	      if ((*ptr & 0x80) && (*ptr & 0xe0) != 0xa0 &&
		  (*ptr & 0xff) != 0xf7 && (*ptr & 0xff) != 0xf8)
		break;

	    if (*ptr)
	    {
	      if (!errors && !verbose)
		_cupsLangPuts(stdout, _(" FAIL\n"));

	      if (verbose >= 0)
		_cupsLangPrintf(stdout,
				_("      **FAIL**  Default translation "
				  "string for option %s contains 8-bit "
				  "characters!\n"),
				option->keyword);

	      errors ++;
	    }

	    for (j = 0; j < option->num_choices; j ++)
	    {
	     /*
	      * Check for special characters outside A0 to BF, F7, or F8
	      * that are used for languages other than English.
	      */

	      for (ptr = option->choices[j].text; *ptr; ptr ++)
		if ((*ptr & 0x80) && (*ptr & 0xe0) != 0xa0 &&
		    (*ptr & 0xff) != 0xf7 && (*ptr & 0xff) != 0xf8)
		  break;

	      if (*ptr)
	      {
		if (!errors && !verbose)
		  _cupsLangPuts(stdout, _(" FAIL\n"));

		if (verbose >= 0)
		  _cupsLangPrintf(stdout,
				  _("      **FAIL**  Default translation "
				    "string for option %s choice %s contains "
				    "8-bit characters!\n"),
				  option->keyword,
				  option->choices[j].choice);

		errors ++;
	      }
	    }
	  }
	}
      }

     /*
      * Final pass/fail notification...
      */

      if (errors)
	status = ERROR_CONFORMANCE;
      else if (!verbose)
	_cupsLangPuts(stdout, _(" PASS\n"));

      if (verbose >= 0)
      {
        check_basics(argv[i]);

	if (warn & WARN_CONSTRAINTS)
	  errors = check_constraints(ppd, errors, verbose, 1);

	if (warn & WARN_DEFAULTS)
	  errors = check_defaults(ppd, errors, verbose, 1);

	if (warn & WARN_FILTERS)
	  errors = check_filters(ppd, root, errors, verbose, 1);

	if (warn & WARN_TRANSLATIONS)
	  errors = check_translations(ppd, errors, verbose, 1);

       /*
	* Look for default keywords with no corresponding option...
	*/

	for (j = 0; j < ppd->num_attrs; j ++)
	{
	  attr = ppd->attrs[j];

          if (!strcmp(attr->name, "DefaultColorSpace") ||
	      !strcmp(attr->name, "DefaultColorSep") ||
	      !strcmp(attr->name, "DefaultFont") ||
	      !strcmp(attr->name, "DefaultHalftoneType") ||
	      !strcmp(attr->name, "DefaultImageableArea") ||
	      !strcmp(attr->name, "DefaultLeadingEdge") ||
	      !strcmp(attr->name, "DefaultOutputOrder") ||
	      !strcmp(attr->name, "DefaultPaperDimension") ||
	      !strcmp(attr->name, "DefaultResolution") ||
	      !strcmp(attr->name, "DefaultScreenProc") ||
	      !strcmp(attr->name, "DefaultTransfer"))
	    continue;

	  if (!strncmp(attr->name, "Default", 7) && 
	      !ppdFindOption(ppd, attr->name + 7))
            _cupsLangPrintf(stdout,
	                    _("        WARN    %s has no corresponding "
			      "options!\n"),
	                    attr->name);
	}

       /*
        * Check for old Duplex option names...
	*/

	if ((option = ppdFindOption(ppd, "EFDuplex")) == NULL)
          option = ppdFindOption(ppd, "KD03Duplex");

        if (option)
	{
	  _cupsLangPrintf(stdout,
	                  _("        WARN    Duplex option keyword %s "
			    "should be named Duplex or JCLDuplex!\n"
			    "                REF: Page 122, section 5.17\n"),
	        	  option->keyword);
	}

        ppdMarkDefaults(ppd);
	if (ppdConflicts(ppd))
	{
	  _cupsLangPuts(stdout,
	                _("        WARN    Default choices conflicting!\n"));

          show_conflicts(ppd);
        }

        if (ppdversion < 43)
	{
          _cupsLangPrintf(stdout,
	                  _("        WARN    Obsolete PPD version %.1f!\n"
			    "                REF: Page 42, section 5.2.\n"),
	        	  0.1f * ppdversion);
	}

        if (!ppd->lang_encoding && ppdversion < 41)
	{
	  _cupsLangPuts(stdout,
	                _("        WARN    LanguageEncoding required by PPD "
			  "4.3 spec.\n"
			  "                REF: Pages 56-57, section 5.3.\n"));
	}

        if (!ppd->manufacturer && ppdversion < 43)
	{
	  _cupsLangPuts(stdout,
	                _("        WARN    Manufacturer required by PPD "
			  "4.3 spec.\n"
			  "                REF: Pages 58-59, section 5.3.\n"));
	}

       /*
	* Treat a PCFileName attribute longer than 12 characters as
	* a warning and not a hard error...
	*/

	if (ppd->pcfilename && strlen(ppd->pcfilename) > 12)
	{
	  _cupsLangPuts(stdout,
	                _("        WARN    PCFileName longer than 8.3 in "
			  "violation of PPD spec.\n"
			  "                REF: Pages 61-62, section 5.3.\n"));
        }

        if (!ppd->shortnickname && ppdversion < 43)
	{
	  _cupsLangPuts(stdout,
	                _("        WARN    ShortNickName required by PPD "
			  "4.3 spec.\n"
			  "                REF: Pages 64-65, section 5.3.\n"));
	}

       /*
        * Check the Protocols line and flag PJL + BCP since TBCP is
	* usually used with PJL...
	*/

        if (ppd->protocols)
	{
	  if (strstr(ppd->protocols, "PJL") &&
	      strstr(ppd->protocols, "BCP") &&
	      !strstr(ppd->protocols, "TBCP"))
	  {
	    _cupsLangPuts(stdout,
	                  _("        WARN    Protocols contains both PJL "
			    "and BCP; expected TBCP.\n"
			    "                REF: Pages 78-79, section 5.7.\n"));
	  }

	  if (strstr(ppd->protocols, "PJL") &&
	      (!ppd->jcl_begin || !ppd->jcl_end || !ppd->jcl_ps))
	  {
	    _cupsLangPuts(stdout,
	                  _("        WARN    Protocols contains PJL but JCL "
			    "attributes are not set.\n"
			    "                REF: Pages 78-79, section 5.7.\n"));
	  }
	}

       /*
        * Check for options with a common prefix, e.g. Duplex and Duplexer,
	* which are errors according to the spec but won't cause problems
	* with CUPS specifically...
	*/

	for (j = 0, group = ppd->groups; j < ppd->num_groups; j ++, group ++)
	  for (k = 0, option = group->options; k < group->num_options; k ++, option ++)
	  {
	    len = strlen(option->keyword);

	    for (m = 0, group2 = ppd->groups;
		 m < ppd->num_groups;
		 m ++, group2 ++)
	      for (n = 0, option2 = group2->options;
	           n < group2->num_options;
		   n ++, option2 ++)
		if (option != option2 &&
	            len < strlen(option2->keyword) &&
	            !strncmp(option->keyword, option2->keyword, len))
		{
		  _cupsLangPrintf(stdout,
		                  _("        WARN    %s shares a common "
				    "prefix with %s\n"
				    "                REF: Page 15, section "
				    "3.2.\n"),
		                  option->keyword, option2->keyword);
        	}
	  }
      }

     /*
      * cupsICCProfile
      */

      for (attr = ppdFindAttr(ppd, "cupsICCProfile", NULL); 
	   attr != NULL; 
	   attr = ppdFindNextAttr(ppd, "cupsICCProfile", NULL))
      {
	if (attr->value)
	{
	  if (attr->value[0] == '/')
	    snprintf(pathprog, sizeof(pathprog), "%s%s", root, attr->value);
	  else
	  {
	    if ((ptr = getenv("CUPS_DATADIR")) == NULL)
	      ptr = CUPS_DATADIR;

            if (*ptr == '/' || !*root)
	      snprintf(pathprog, sizeof(pathprog), "%s%s/profiles/%s", root,
	               ptr, attr->value);
            else
	      snprintf(pathprog, sizeof(pathprog), "%s/%s/profiles/%s", root,
	               ptr, attr->value);
          }
	}

	if (!attr->value || !attr->value[0] || stat(pathprog, &statbuf))
	{
	  if (verbose >= 0)
	    _cupsLangPrintf(stdout,
			    _("        WARN    Missing cupsICCProfile "
			      "file \"%s\"\n"),
			    !attr->value || !attr->value[0] ? "<NULL>" :
							      attr->value);
	}
      }

#ifdef __APPLE__
     /*
      * APDialogExtension
      */

      for (attr = ppdFindAttr(ppd, "APDialogExtension", NULL); 
	   attr != NULL; 
	   attr = ppdFindNextAttr(ppd, "APDialogExtension", NULL))
      {
	if ((!attr->value || stat(attr->value, &statbuf)) && verbose >= 0)
	  _cupsLangPrintf(stdout, _("        WARN    Missing "
				    "APDialogExtension file \"%s\"\n"),
			  attr->value ? attr->value : "<NULL>");
      }

     /*
      * APPrinterIconPath
      */

      for (attr = ppdFindAttr(ppd, "APPrinterIconPath", NULL); 
	   attr != NULL; 
	   attr = ppdFindNextAttr(ppd, "APPrinterIconPath", NULL))
      {
	if ((!attr->value || stat(attr->value, &statbuf)) && verbose >= 0)
	  _cupsLangPrintf(stdout, _("        WARN    Missing "
				    "APPrinterIconPath file \"%s\"\n"),
			  attr->value ? attr->value : "<NULL>");
      }
#endif	/* __APPLE__ */

      if (verbose > 0)
      {
        if (errors)
          _cupsLangPrintf(stdout, _("    %d ERRORS FOUND\n"), errors);
	else
	  _cupsLangPuts(stdout, _("    NO ERRORS FOUND\n"));
      }

     /*
      * Then list the options, if "-v" was provided...
      */ 

      if (verbose > 1)
      {
	_cupsLangPrintf(stdout,
                        "\n"
		        "    language_level = %d\n"
			"    color_device = %s\n"
			"    variable_sizes = %s\n"
			"    landscape = %d\n",
			ppd->language_level,
			ppd->color_device ? "TRUE" : "FALSE",
			ppd->variable_sizes ? "TRUE" : "FALSE",
			ppd->landscape);

	switch (ppd->colorspace)
	{
	  case PPD_CS_CMYK :
              _cupsLangPuts(stdout, "    colorspace = PPD_CS_CMYK\n");
	      break;
	  case PPD_CS_CMY :
              _cupsLangPuts(stdout, "    colorspace = PPD_CS_CMY\n");
	      break;
	  case PPD_CS_GRAY :
              _cupsLangPuts(stdout, "    colorspace = PPD_CS_GRAY\n");
	      break;
	  case PPD_CS_RGB :
              _cupsLangPuts(stdout, "    colorspace = PPD_CS_RGB\n");
	      break;
	  default :
              _cupsLangPuts(stdout, "    colorspace = <unknown>\n");
	      break;
	}

	_cupsLangPrintf(stdout, "    num_emulations = %d\n",
			ppd->num_emulations);
	for (j = 0; j < ppd->num_emulations; j ++)
	  _cupsLangPrintf(stdout, "        emulations[%d] = %s\n",
	                  j, ppd->emulations[j].name);

	_cupsLangPrintf(stdout, "    lang_encoding = %s\n",
	                ppd->lang_encoding);
	_cupsLangPrintf(stdout, "    lang_version = %s\n",
	                ppd->lang_version);
	_cupsLangPrintf(stdout, "    modelname = %s\n", ppd->modelname);
	_cupsLangPrintf(stdout, "    ttrasterizer = %s\n",
        		ppd->ttrasterizer == NULL ? "None" : ppd->ttrasterizer);
	_cupsLangPrintf(stdout, "    manufacturer = %s\n",
	                ppd->manufacturer);
	_cupsLangPrintf(stdout, "    product = %s\n", ppd->product);
	_cupsLangPrintf(stdout, "    nickname = %s\n", ppd->nickname);
	_cupsLangPrintf(stdout, "    shortnickname = %s\n",
	                ppd->shortnickname);
	_cupsLangPrintf(stdout, "    patches = %d bytes\n",
        		ppd->patches == NULL ? 0 : (int)strlen(ppd->patches));

	_cupsLangPrintf(stdout, "    num_groups = %d\n", ppd->num_groups);
	for (j = 0, group = ppd->groups; j < ppd->num_groups; j ++, group ++)
	{
	  _cupsLangPrintf(stdout, "        group[%d] = %s\n",
	                  j, group->text);

	  for (k = 0, option = group->options; k < group->num_options; k ++, option ++)
	  {
	    _cupsLangPrintf(stdout,
	                    "            options[%d] = %s (%s) %s %s %.0f "
			    "(%d choices)\n",
	        	    k, option->keyword, option->text, uis[option->ui],
			    sections[option->section], option->order,
			    option->num_choices);

            if (!strcmp(option->keyword, "PageSize") ||
        	!strcmp(option->keyword, "PageRegion"))
            {
              for (m = option->num_choices, choice = option->choices;
		   m > 0;
		   m --, choice ++)
	      {
		size = ppdPageSize(ppd, choice->choice);

		if (size == NULL)
		  _cupsLangPrintf(stdout,
                                  "                %s (%s) = ERROR",
				  choice->choice, choice->text);
        	else
		  _cupsLangPrintf(stdout,
                                  "                %s (%s) = %.2fx%.2fin "
				  "(%.1f,%.1f,%.1f,%.1f)",
		        	  choice->choice, choice->text,
				  size->width / 72.0, size->length / 72.0,
				  size->left / 72.0, size->bottom / 72.0,
				  size->right / 72.0, size->top / 72.0);

        	if (!strcmp(option->defchoice, choice->choice))
		  _cupsLangPuts(stdout, " *\n");
		else
		  _cupsLangPuts(stdout, "\n");
              }
	    }
	    else
	    {
	      for (m = option->num_choices, choice = option->choices;
		   m > 0;
		   m --, choice ++)
	      {
		_cupsLangPrintf(stdout, "                %s (%s)",
		                choice->choice, choice->text);

        	if (!strcmp(option->defchoice, choice->choice))
		  _cupsLangPuts(stdout, " *\n");
		else
		  _cupsLangPuts(stdout, "\n");
	      }
            }
	  }
	}

	_cupsLangPrintf(stdout, "    num_consts = %d\n",
	                ppd->num_consts);
	for (j = 0; j < ppd->num_consts; j ++)
	  _cupsLangPrintf(stdout,
                	  "        consts[%d] = *%s %s *%s %s\n",
        		  j, ppd->consts[j].option1, ppd->consts[j].choice1,
			  ppd->consts[j].option2, ppd->consts[j].choice2);

	_cupsLangPrintf(stdout, "    num_profiles = %d\n",
	                ppd->num_profiles);
	for (j = 0; j < ppd->num_profiles; j ++)
	  _cupsLangPrintf(stdout,
                	  "        profiles[%d] = %s/%s %.3f %.3f "
			  "[ %.3f %.3f %.3f %.3f %.3f %.3f %.3f %.3f %.3f ]\n",
        		  j, ppd->profiles[j].resolution,
			  ppd->profiles[j].media_type,
			  ppd->profiles[j].gamma, ppd->profiles[j].density,
			  ppd->profiles[j].matrix[0][0],
			  ppd->profiles[j].matrix[0][1],
			  ppd->profiles[j].matrix[0][2],
			  ppd->profiles[j].matrix[1][0],
			  ppd->profiles[j].matrix[1][1],
			  ppd->profiles[j].matrix[1][2],
			  ppd->profiles[j].matrix[2][0],
			  ppd->profiles[j].matrix[2][1],
			  ppd->profiles[j].matrix[2][2]);

	_cupsLangPrintf(stdout, "    num_fonts = %d\n", ppd->num_fonts);
	for (j = 0; j < ppd->num_fonts; j ++)
	  _cupsLangPrintf(stdout, "        fonts[%d] = %s\n",
	                  j, ppd->fonts[j]);

	_cupsLangPrintf(stdout, "    num_attrs = %d\n", ppd->num_attrs);
	for (j = 0; j < ppd->num_attrs; j ++)
	  _cupsLangPrintf(stdout,
	                  "        attrs[%d] = %s %s%s%s: \"%s\"\n", j,
	        	  ppd->attrs[j]->name, ppd->attrs[j]->spec,
			  ppd->attrs[j]->text[0] ? "/" : "",
			  ppd->attrs[j]->text,
			  ppd->attrs[j]->value ?
			      ppd->attrs[j]->value : "(null)");
      }

      ppdClose(ppd);
    }

  if (!files)
    usage();

  return (status);
}


/*
 * 'check_basics()' - Check for CR LF, mixed line endings, and blank lines.
 */

static void
check_basics(const char *filename)	/* I - PPD file to check */
{
  cups_file_t	*fp;			/* File pointer */
  int		ch;			/* Current character */
  int		col,			/* Current column */
		whitespace;		/* Only seen whitespace? */
  int		eol;			/* Line endings */
  int		linenum;		/* Line number */
  int		mixed;			/* Mixed line endings? */


  if ((fp = cupsFileOpen(filename, "r")) == NULL)
    return;

  linenum    = 1;
  col        = 0;
  eol        = EOL_NONE;
  mixed      = 0;
  whitespace = 1;

  while ((ch = cupsFileGetChar(fp)) != EOF)
  {
    if (ch == '\r' || ch == '\n')
    {
      if (ch == '\n')
      {
	if (eol == EOL_NONE)
	  eol = EOL_LF;
	else if (eol != EOL_LF)
	  mixed = 1;
      }
      else if (ch == '\r')
      {
	if (cupsFilePeekChar(fp) == '\n')
	{
	  cupsFileGetChar(fp);

          if (eol == EOL_NONE)
	    eol = EOL_CRLF;
	  else if (eol != EOL_CRLF)
	    mixed = 1;
	}
	else if (eol == EOL_NONE)
	  eol = EOL_CR;
        else if (eol != EOL_CR)
	  mixed = 1;
      }
      
      if (col > 0 && whitespace)
	_cupsLangPrintf(stdout,
		        _("        WARN    Line %d only contains whitespace!\n"),
			linenum);

      linenum ++;
      col        = 0;
      whitespace = 1;
    }
    else
    {
      if (ch != ' ' && ch != '\t')
        whitespace = 0;

      col ++;
    }
  }

  if (mixed)
    _cupsLangPuts(stdout,
		  _("        WARN    File contains a mix of CR, LF, and "
		    "CR LF line endings!\n"));

  if (eol == EOL_CRLF)
    _cupsLangPuts(stdout,
		  _("        WARN    Non-Windows PPD files should use lines "
		    "ending with only LF, not CR LF!\n"));

  cupsFileClose(fp);
}


/*
 * 'check_constraints()' - Check UIConstraints in the PPD file.
 */

static int				/* O - Errors found */
check_constraints(ppd_file_t *ppd,	/* I - PPD file */
                  int        errors,	/* I - Errors found */
                  int        verbose,	/* I - Verbosity level */
                  int        warn)	/* I - Warnings only? */
{
  int		j;			/* Looping var */
  ppd_const_t	*c;			/* Current constraint */
  ppd_option_t	*option;		/* Standard UI option */
  ppd_option_t	*option2;		/* Standard UI option */
  const char	*prefix;		/* WARN/FAIL prefix */


  prefix = warn ? "  WARN  " : "**FAIL**";

  for (j = ppd->num_consts, c = ppd->consts; j > 0; j --, c ++)
  {
    option  = ppdFindOption(ppd, c->option1);
    option2 = ppdFindOption(ppd, c->option2);

    if (!option || !option2)
    {
      if (!warn && !errors && !verbose)
	_cupsLangPuts(stdout, _(" FAIL\n"));

      if (!option)
	_cupsLangPrintf(stdout,
			_("      %s  Missing option %s in "
			  "UIConstraint \"*%s %s *%s %s\"!\n"),
			prefix, c->option1,
			c->option1, c->choice1, c->option2, c->choice2);
      
      if (!option2)
	_cupsLangPrintf(stdout,
			_("      %s  Missing option %s in "
			  "UIConstraint \"*%s %s *%s %s\"!\n"),
			prefix, c->option2,
			c->option1, c->choice1, c->option2, c->choice2);

      if (!warn)
        errors ++;

      continue;
    }

    if (c->choice1[0] && !ppdFindChoice(option, c->choice1))
    {
      if (!warn && !errors && !verbose)
	_cupsLangPuts(stdout, _(" FAIL\n"));

      _cupsLangPrintf(stdout,
		      _("      %s  Missing choice *%s %s in "
			"UIConstraint \"*%s %s *%s %s\"!\n"),
		      prefix, c->option1, c->choice1,
		      c->option1, c->choice1, c->option2, c->choice2);

      if (!warn)
        errors ++;
    }

    if (c->choice2[0] && !ppdFindChoice(option2, c->choice2))
    {
      if (!warn && !errors && !verbose)
	_cupsLangPuts(stdout, _(" FAIL\n"));

      _cupsLangPrintf(stdout,
		      _("      %s  Missing choice *%s %s in "
			"UIConstraint \"*%s %s *%s %s\"!\n"),
		      prefix, c->option2, c->choice2,
		      c->option1, c->choice1, c->option2, c->choice2);

      if (!warn)
        errors ++;
    }
  }

  return (errors);
}


/*
 * 'check_defaults()' - Check default option keywords in the PPD file.
 */

static int				/* O - Errors found */
check_defaults(ppd_file_t *ppd,		/* I - PPD file */
	       int        errors,	/* I - Errors found */
	       int        verbose,	/* I - Verbosity level */
	       int        warn)		/* I - Warnings only? */
{
  int		j, k;			/* Looping vars */
  ppd_attr_t	*attr;			/* PPD attribute */
  ppd_option_t	*option;		/* Standard UI option */
  const char	*prefix;		/* WARN/FAIL prefix */


  prefix = warn ? "  WARN  " : "**FAIL**";

  for (j = 0; j < ppd->num_attrs; j ++)
  {
    attr = ppd->attrs[j];

    if (!strcmp(attr->name, "DefaultColorSpace") ||
	!strcmp(attr->name, "DefaultFont") ||
	!strcmp(attr->name, "DefaultHalftoneType") ||
	!strcmp(attr->name, "DefaultImageableArea") ||
	!strcmp(attr->name, "DefaultLeadingEdge") ||
	!strcmp(attr->name, "DefaultOutputOrder") ||
	!strcmp(attr->name, "DefaultPaperDimension") ||
	!strcmp(attr->name, "DefaultResolution") ||
	!strcmp(attr->name, "DefaultTransfer"))
      continue;

    if (!strncmp(attr->name, "Default", 7))
    {
      if ((option = ppdFindOption(ppd, attr->name + 7)) != NULL &&
	  strcmp(attr->value, "Unknown"))
      {
       /*
	* Check that the default option value matches a choice...
	*/

	for (k = 0; k < option->num_choices; k ++)
	  if (!strcmp(option->choices[k].choice, attr->value))
	    break;

	if (k >= option->num_choices)
	{
	  if (!warn && !errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  if (verbose >= 0)
	    _cupsLangPrintf(stdout,
			    _("      %s  %s %s does not exist!\n"),
			    prefix, attr->name, attr->value);

          if (!warn)
	    errors ++;
	}
      }
    }
  }

  return (errors);
}


/*
 * 'check_filters()' - Check filters in the PPD file.
 */

static int				/* O - Errors found */
check_filters(ppd_file_t *ppd,		/* I - PPD file */
              const char *root,		/* I - Root directory */
	      int        errors,	/* I - Errors found */
	      int        verbose,	/* I - Verbosity level */
	      int        warn)		/* I - Warnings only? */
{
  int		i;			/* Looping var */
  ppd_attr_t	*attr;			/* PPD attribute */
  const char	*ptr;			/* Pointer into string */
  struct stat	statbuf;		/* File information */
  char		super[16],		/* Super-type for filter */
		type[256],		/* Type for filter */
		program[1024],		/* Program/filter name */
		pathprog[1024];		/* Complete path to program/filter */
  int		cost;			/* Cost of filter */
  const char	*prefix;		/* WARN/FAIL prefix */


  prefix = warn ? "  WARN  " : "**FAIL**";

  for (i = 0; i < ppd->num_filters; i ++)
  {
    if (sscanf(ppd->filters[i], "%15[^/]/%255s%d%*[ \t]%1023[^\n]", super, type,
               &cost, program) != 4)
    {
      if (!warn && !errors && !verbose)
	_cupsLangPuts(stdout, _(" FAIL\n"));

      if (verbose >= 0)
	_cupsLangPrintf(stdout,
			_("      %s  Bad cupsFilter value \"%s\"!\n"),
			prefix, ppd->filters[i]);

      if (!warn)
        errors ++;
    }
    else
    {
      if (program[0] == '/')
	snprintf(pathprog, sizeof(pathprog), "%s%s", root, program);
      else
      {
	if ((ptr = getenv("CUPS_SERVERBIN")) == NULL)
	  ptr = CUPS_SERVERBIN;

	if (*ptr == '/' || !*root)
	  snprintf(pathprog, sizeof(pathprog), "%s%s/filter/%s", root, ptr,
		   program);
	else
	  snprintf(pathprog, sizeof(pathprog), "%s/%s/filter/%s", root, ptr,
		   program);
      }

      if (stat(pathprog, &statbuf))
      {
	if (!warn && !errors && !verbose)
	  _cupsLangPuts(stdout, _(" FAIL\n"));

	if (verbose >= 0)
	  _cupsLangPrintf(stdout, _("      %s  Missing cupsFilter "
				    "file \"%s\"\n"), prefix, program);

	if (!warn)
	  errors ++;
      }
    }
  }

  for (attr = ppdFindAttr(ppd, "cupsPreFilter", NULL);
       attr;
       attr = ppdFindNextAttr(ppd, "cupsPreFilter", NULL))
  {
    if (!attr->value ||
	sscanf(attr->value, "%15[^/]/%255s%d%*[ \t]%1023[^\n]", super, type,
	       &cost, program) != 4)
    {
      if (!warn && !errors && !verbose)
	_cupsLangPuts(stdout, _(" FAIL\n"));

      if (verbose >= 0)
	_cupsLangPrintf(stdout,
			_("      %s  Bad cupsPreFilter value \"%s\"!\n"),
			prefix, attr->value ? attr->value : "");

      if (!warn)
        errors ++;
    }
    else
    {
      if (program[0] == '/')
	snprintf(pathprog, sizeof(pathprog), "%s%s", root, program);
      else
      {
	if ((ptr = getenv("CUPS_SERVERBIN")) == NULL)
	  ptr = CUPS_SERVERBIN;

	if (*ptr == '/' || !*root)
	  snprintf(pathprog, sizeof(pathprog), "%s%s/filter/%s", root, ptr,
		   program);
	else
	  snprintf(pathprog, sizeof(pathprog), "%s/%s/filter/%s", root, ptr,
		   program);
      }

      if (stat(pathprog, &statbuf))
      {
	if (!warn && !errors && !verbose)
	  _cupsLangPuts(stdout, _(" FAIL\n"));

	if (verbose >= 0)
	  _cupsLangPrintf(stdout, _("      %s  Missing cupsPreFilter "
				    "file \"%s\"\n"), prefix, program);

        if (!warn)
	  errors ++;
      }
    }
  }

  return (errors);
}


/*
 * 'check_translations()' - Check translations in the PPD file.
 */

static int				/* O - Errors found */
check_translations(ppd_file_t *ppd,	/* I - PPD file */
                   int        errors,	/* I - Errors found */
                   int        verbose,	/* I - Verbosity level */
                   int        warn)	/* I - Warnings only? */
{
  int		j;			/* Looping var */
  ppd_attr_t	*attr;			/* PPD attribute */
  char		*languages,		/* Copy of attribute value */
		*langstart,		/* Start of current language */
		*langptr,		/* Pointer into languages */
		keyword[PPD_MAX_NAME],	/* Localization keyword (full) */
		llkeyword[PPD_MAX_NAME],/* Localization keyword (base) */
		ckeyword[PPD_MAX_NAME],	/* Custom option keyword (full) */
		cllkeyword[PPD_MAX_NAME];
					/* Custom option keyword (base) */
  ppd_option_t	*option;		/* Standard UI option */
  ppd_coption_t	*coption;		/* Custom option */
  ppd_cparam_t	*cparam;		/* Custom parameter */
  cups_array_t	*langlist;		/* List of languages so far */
  char		ll[3];			/* Base language */
  const char	*prefix;		/* WARN/FAIL prefix */


  prefix = warn ? "  WARN  " : "**FAIL**";

  if ((attr = ppdFindAttr(ppd, "cupsLanguages", NULL)) != NULL &&
      attr->value)
  {
   /*
    * This file contains localizations, check them...
    */

    if ((languages = strdup(attr->value)) == NULL)
      return (1);

    langlist = cupsArrayNew((cups_array_func_t)strcmp, NULL);

    for (langptr = languages; *langptr;)
    {
     /*
      * Skip leading whitespace...
      */

      while (isspace(*langptr & 255))
	langptr ++;

      if (!*langptr)
	break;

     /*
      * Find the end of this language name...
      */

      for (langstart = langptr;
	   *langptr && !isspace(*langptr & 255);
	   langptr ++);

      if (*langptr)
	*langptr++ = '\0';

      j = strlen(langstart);
      if (j != 2 && j != 5)
      {
	if (!warn && !errors && !verbose)
	  _cupsLangPuts(stdout, _(" FAIL\n"));

	if (verbose >= 0)
	  _cupsLangPrintf(stdout,
			  _("      %s  Bad language \"%s\"!\n"),
			  prefix, langstart);

	if (!warn)
	  errors ++;

	continue;
      }

      if (!strcmp(langstart, "en"))
        continue;

      cupsArrayAdd(langlist, langstart);

      strlcpy(ll, langstart, sizeof(ll));

     /*
      * Loop through all options and choices...
      */

      for (option = ppdFirstOption(ppd);
	   option;
	   option = ppdNextOption(ppd))
      {
        if (!strcmp(option->keyword, "PageRegion"))
	  continue;

	snprintf(keyword, sizeof(keyword), "%s.Translation", langstart);
	snprintf(llkeyword, sizeof(llkeyword), "%s.Translation", ll);

	if ((attr = ppdFindAttr(ppd, keyword, option->keyword)) == NULL &&
	    (attr = ppdFindAttr(ppd, llkeyword, option->keyword)) == NULL)
	{
	  if (!warn && !errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  if (verbose >= 0)
	    _cupsLangPrintf(stdout,
			    _("      %s  Missing \"%s\" translation "
			      "string for option %s!\n"),
			    prefix, langstart, option->keyword);

          if (!warn)
	    errors ++;
	}
	else if (!valid_utf8(attr->text))
	{
	  if (!warn && !errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  if (verbose >= 0)
	    _cupsLangPrintf(stdout,
			    _("      %s  Bad UTF-8 \"%s\" translation "
			      "string for option %s!\n"),
			    prefix, langstart, option->keyword);

	  if (!warn)
	    errors ++;
	}

	snprintf(keyword, sizeof(keyword), "%s.%s", langstart,
		 option->keyword);
	snprintf(llkeyword, sizeof(llkeyword), "%s.%s", ll,
		 option->keyword);

	for (j = 0; j < option->num_choices; j ++)
	{
	  if (!strcasecmp(option->choices[j].choice, "Custom") &&
	      (coption = ppdFindCustomOption(ppd,
					     option->keyword)) != NULL)
	  {
	    snprintf(ckeyword, sizeof(ckeyword), "%s.Custom%s",
		     langstart, option->keyword);

	    if ((attr = ppdFindAttr(ppd, ckeyword, "True")) != NULL &&
		!valid_utf8(attr->text))
	    {
	      if (!warn && !errors && !verbose)
		_cupsLangPuts(stdout, _(" FAIL\n"));

	      if (verbose >= 0)
		_cupsLangPrintf(stdout,
				_("      %s  Bad UTF-8 \"%s\" "
				  "translation string for option %s, "
				  "choice %s!\n"),
				prefix, langstart,
				ckeyword + 1 + strlen(langstart),
				"True");

              if (!warn)
		errors ++;
	    }

	    if (strcasecmp(option->keyword, "PageSize"))
	    {
	      for (cparam = (ppd_cparam_t *)cupsArrayFirst(coption->params);
		   cparam;
		   cparam = (ppd_cparam_t *)cupsArrayNext(coption->params))
	      {
		snprintf(ckeyword, sizeof(ckeyword), "%s.ParamCustom%s",
			 langstart, option->keyword);
		snprintf(cllkeyword, sizeof(cllkeyword), "%s.ParamCustom%s",
			 ll, option->keyword);

		if ((attr = ppdFindAttr(ppd, ckeyword,
					cparam->name)) == NULL &&
		    (attr = ppdFindAttr(ppd, cllkeyword,
					cparam->name)) == NULL)
		{
		  if (!warn && !errors && !verbose)
		    _cupsLangPuts(stdout, _(" FAIL\n"));

		  if (verbose >= 0)
		    _cupsLangPrintf(stdout,
				    _("      %s  Missing \"%s\" "
				      "translation string for option %s, "
				      "choice %s!\n"),
				    prefix, langstart,
				    ckeyword + 1 + strlen(langstart),
				    cparam->name);

                  if (!warn)
		    errors ++;
		}
		else if (!valid_utf8(attr->text))
		{
		  if (!warn && !errors && !verbose)
		    _cupsLangPuts(stdout, _(" FAIL\n"));

		  if (verbose >= 0)
		    _cupsLangPrintf(stdout,
				    _("      %s  Bad UTF-8 \"%s\" "
				      "translation string for option %s, "
				      "choice %s!\n"),
				    prefix, langstart,
				    ckeyword + 1 + strlen(langstart),
				    cparam->name);

		  if (!warn)
		    errors ++;
		}
	      }
	    }
	  }
	  else if ((attr = ppdFindAttr(ppd, keyword,
				       option->choices[j].choice)) == NULL &&
		   (attr = ppdFindAttr(ppd, llkeyword,
				       option->choices[j].choice)) == NULL)
	  {
	    if (!warn && !errors && !verbose)
	      _cupsLangPuts(stdout, _(" FAIL\n"));

	    if (verbose >= 0)
	      _cupsLangPrintf(stdout,
			      _("      %s  Missing \"%s\" "
				"translation string for option %s, "
				"choice %s!\n"),
			      prefix, langstart, option->keyword,
			      option->choices[j].choice);

	    if (!warn)
	      errors ++;
	  }
	  else if (!valid_utf8(attr->text))
	  {
	    if (!warn && !errors && !verbose)
	      _cupsLangPuts(stdout, _(" FAIL\n"));

	    if (verbose >= 0)
	      _cupsLangPrintf(stdout,
			      _("      %s  Bad UTF-8 \"%s\" "
				"translation string for option %s, "
				"choice %s!\n"),
			      prefix, langstart, option->keyword,
			      option->choices[j].choice);

	    if (!warn)
	      errors ++;
	  }
	}
      }
    }

   /*
    * Verify that we have the base language for each localized one...
    */

    for (langptr = (char *)cupsArrayFirst(langlist);
	 langptr;
	 langptr = (char *)cupsArrayNext(langlist))
      if (langptr[2])
      {
       /*
	* Lookup the base language...
	*/

	cupsArraySave(langlist);

	strlcpy(ll, langptr, sizeof(ll));

	if (!cupsArrayFind(langlist, ll) && strcmp(ll, "zh"))
	{
	  if (!warn && !errors && !verbose)
	    _cupsLangPuts(stdout, _(" FAIL\n"));

	  if (verbose >= 0)
	    _cupsLangPrintf(stdout,
			    _("      %s  No base translation \"%s\" "
			      "is included in file!\n"), prefix, ll);

	  if (!warn)
	    errors ++;
	}

	cupsArrayRestore(langlist);
      }

   /*
    * Free memory used for the languages...
    */

    cupsArrayDelete(langlist);
    free(languages);
  }

  return (errors);
}


/*
 * 'show_conflicts()' - Show option conflicts in a PPD file.
 */

static void
show_conflicts(ppd_file_t *ppd)		/* I - PPD to check */
{
  int		i, j;			/* Looping variables */
  ppd_const_t	*c;			/* Current constraint */
  ppd_option_t	*o1, *o2;		/* Options */
  ppd_choice_t	*c1, *c2;		/* Choices */


 /*
  * Loop through all of the UI constraints and report any options
  * that conflict...
  */

  for (i = ppd->num_consts, c = ppd->consts; i > 0; i --, c ++)
  {
   /*
    * Grab pointers to the first option...
    */

    o1 = ppdFindOption(ppd, c->option1);

    if (o1 == NULL)
      continue;
    else if (c->choice1[0] != '\0')
    {
     /*
      * This constraint maps to a specific choice.
      */

      c1 = ppdFindChoice(o1, c->choice1);
    }
    else
    {
     /*
      * This constraint applies to any choice for this option.
      */

      for (j = o1->num_choices, c1 = o1->choices; j > 0; j --, c1 ++)
        if (c1->marked)
	  break;

      if (j == 0 ||
          !strcasecmp(c1->choice, "None") ||
          !strcasecmp(c1->choice, "Off") ||
          !strcasecmp(c1->choice, "False"))
        c1 = NULL;
    }

   /*
    * Grab pointers to the second option...
    */

    o2 = ppdFindOption(ppd, c->option2);

    if (o2 == NULL)
      continue;
    else if (c->choice2[0] != '\0')
    {
     /*
      * This constraint maps to a specific choice.
      */

      c2 = ppdFindChoice(o2, c->choice2);
    }
    else
    {
     /*
      * This constraint applies to any choice for this option.
      */

      for (j = o2->num_choices, c2 = o2->choices; j > 0; j --, c2 ++)
        if (c2->marked)
	  break;

      if (j == 0 ||
          !strcasecmp(c2->choice, "None") ||
          !strcasecmp(c2->choice, "Off") ||
          !strcasecmp(c2->choice, "False"))
        c2 = NULL;
    }

   /*
    * If both options are marked then there is a conflict...
    */

    if (c1 != NULL && c1->marked && c2 != NULL && c2->marked)
      _cupsLangPrintf(stdout,
                      _("        WARN    \"%s %s\" conflicts with \"%s %s\"\n"
                        "                (constraint=\"%s %s %s %s\")\n"),
        	      o1->keyword, c1->choice, o2->keyword, c2->choice,
		      c->option1, c->choice1, c->option2, c->choice2);
  }
}


/*
 * 'test_raster()' - Test PostScript commands for raster printers.
 */

static int				/* O - 1 on success, 0 on failure */
test_raster(ppd_file_t *ppd,		/* I - PPD file */
            int        verbose)		/* I - Verbosity */
{
  cups_page_header2_t	header;		/* Page header */


  ppdMarkDefaults(ppd);
  if (cupsRasterInterpretPPD(&header, ppd, 0, NULL, 0))
  {
    if (!verbose)
      _cupsLangPuts(stdout, _(" FAIL\n"));

    if (verbose >= 0)
      _cupsLangPrintf(stdout,
		      _("      **FAIL**  Default option code cannot be "
			"interpreted: %s\n"), cupsRasterErrorString());

    return (0);
  }

 /*
  * Try a test of custom page size code, if available...
  */

  if (!ppdPageSize(ppd, "Custom.612x792"))
    return (1);

  ppdMarkOption(ppd, "PageSize", "Custom.612x792");

  if (cupsRasterInterpretPPD(&header, ppd, 0, NULL, 0))
  {
    if (!verbose)
      _cupsLangPuts(stdout, _(" FAIL\n"));

    if (verbose >= 0)
      _cupsLangPrintf(stdout,
		      _("      **FAIL**  Default option code cannot be "
			"interpreted: %s\n"), cupsRasterErrorString());

    return (0);
  }

  return (1);
}


/*
 * 'usage()' - Show program usage...
 */

static void
usage(void)
{
  _cupsLangPuts(stdout,
                _("Usage: cupstestppd [options] filename1.ppd[.gz] "
		  "[... filenameN.ppd[.gz]]\n"
		  "       program | cupstestppd [options] -\n"
		  "\n"
		  "Options:\n"
		  "\n"
		  "    -R root-directory    Set alternate root\n"
		  "    -W {all,none,constraints,defaults,filters,translations}\n"
		  "                         Issue warnings instead of errors\n"
		  "    -q                   Run silently\n"
		  "    -r                   Use 'relaxed' open mode\n"
		  "    -v                   Be slightly verbose\n"
		  "    -vv                  Be very verbose\n"));

  exit(ERROR_USAGE);
}


/*
 * 'valid_utf8()' - Check whether a string contains valid UTF-8 text.
 */

static int				/* O - 1 if valid, 0 if not */
valid_utf8(const char *s)		/* I - String to check */
{
  while (*s)
  {
    if (*s & 0x80)
    {
     /*
      * Check for valid UTF-8 sequence...
      */

      if ((*s & 0xc0) == 0x80)
        return (0);			/* Illegal suffix byte */
      else if ((*s & 0xe0) == 0xc0)
      {
       /*
        * 2-byte sequence...
        */

        s ++;

        if ((*s & 0xc0) != 0x80)
          return (0);			/* Missing suffix byte */
      }
      else if ((*s & 0xf0) == 0xe0)
      {
       /*
        * 3-byte sequence...
        */

        s ++;

        if ((*s & 0xc0) != 0x80)
          return (0);			/* Missing suffix byte */

        s ++;

        if ((*s & 0xc0) != 0x80)
          return (0);			/* Missing suffix byte */
      }
      else if ((*s & 0xf8) == 0xf0)
      {
       /*
        * 4-byte sequence...
        */

        s ++;

        if ((*s & 0xc0) != 0x80)
          return (0);			/* Missing suffix byte */

        s ++;

        if ((*s & 0xc0) != 0x80)
          return (0);			/* Missing suffix byte */

        s ++;

        if ((*s & 0xc0) != 0x80)
          return (0);			/* Missing suffix byte */
      }
      else
        return (0);			/* Bad sequence */
    }

    s ++;
  }

  return (1);
}


/*
 * End of "$Id: cupstestppd.c 7729 2008-07-14 18:06:16Z mike $".
 */
