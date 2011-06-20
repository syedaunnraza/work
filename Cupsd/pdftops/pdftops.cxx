//
// "$Id: pdftops.cxx 7726 2008-07-14 17:53:24Z mike $"
//
//   PDF to PostScript filter front-end for the Common UNIX Printing
//   System (CUPS).
//
//   Copyright 2007-2008 by Apple Inc.
//   Copyright 1997-2006 by Easy Software Products.
//
//   These coded instructions, statements, and computer programs are the
//   property of Apple Inc. and are protected by Federal copyright
//   law.  Distribution and use rights are outlined in the file "LICENSE.txt"
//   which should have been included with this file.  If this file is
//   file is missing or damaged, see the license at "http://www.cups.org/".
//
// Contents:
//
//   main() - Main entry for filter...
//

//
// Include necessary headers...
//

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <cups/string.h>
#include <cups/i18n.h>
#include "parseargs.h"
#include "GString.h"
#include "gmem.h"
#include "Object.h"
#include "Stream.h"
#include "Array.h"
#include "Dict.h"
#include "XRef.h"
#include "Catalog.h"
#include "Page.h"
#include "PDFDoc.h"
#include "PSOutputDev.h"
#include "GlobalParams.h"
#include "Error.h"
#include "config.h"

#include <cups/cups.h>


//
// 'main()' - Main entry for filter...
//

int					// O - Exit status
main(int  argc,				// I - Number of command-line args
     char *argv[])			// I - Command-line arguments
{
  PDFDoc	*doc;			// Input file
  GString	*fileName;		// Input filename
  GString	*psFileName;		// Output filename
  PSLevel	level;			// PostScript level
  PSOutputDev	*psOut;			// Output device
  int		num_options;		// Number of options
  cups_option_t	*options;		// Options
  const char	*val;			// Option value
  ppd_file_t	*ppd;			// Current PPD
  ppd_size_t	*size;			// Current media size
  int		fd;			// Copy file descriptor
  const char	*server_root;		// Location of config files
  char		tempfile[1024];		// Temporary file
  char		buffer[8192];		// Copy buffer
  int		bytes;			// Bytes copied
  int		width, length;		// Size in points
  int		orientation;		// Orientation
  int		temp;			// Temporary var
  int		duplex;			// Duplex the output?
  int		fit;			// Fit the pages to the output
  int		printCommands;		// Output debug info for commands?


  // Make sure status messages are not buffered...
  setbuf(stderr, NULL);

  // Make sure we have the right number of arguments for CUPS!
  if (argc < 6 || argc > 7) {
    fprintf(stderr, _("Usage: %s job user title copies options [filename]\n"),
            argv[0]);
    return (1);
  }

  // Copy stdin if needed...
  if (argc == 6) {
    if ((fd = cupsTempFd(tempfile, sizeof(tempfile))) < 0) {
      perror(_("ERROR: Unable to copy PDF file"));
      return (1);
    }

    fprintf(stderr, "DEBUG: pdftops - copying to temp print file \"%s\"\n",
            tempfile);

    while ((bytes = fread(buffer, 1, sizeof(buffer), stdin)) > 0)
      write(fd, buffer, bytes);
    close(fd);

    fileName = new GString(tempfile);
  } else {
    fileName = new GString(argv[6]);
    tempfile[0] = '\0';
  }

  // Default to "Universal" size - min of A4 and Letter...
  width  = 595;
  length = 792;
  level  = psLevel2;
  duplex = 0;
  fit    = 0;

  // Get PPD and initialize options as needed...
  num_options = cupsParseOptions(argv[5], 0, &options);

  if ((ppd = ppdOpenFile(getenv("PPD"))) != NULL)
  {
    fprintf(stderr, "DEBUG: pdftops - opened PPD file \"%s\"...\n", getenv("PPD"));

    ppdMarkDefaults(ppd);
    cupsMarkOptions(ppd, num_options, options);

    if ((size = ppdPageSize(ppd, NULL)) != NULL)
    {
      width  = (int)size->width;
      length = (int)size->length;
    }

    level = ppd->language_level == 1 ? psLevel1 : psLevel2;
  }

  // Track the orientation of the print job and update the page
  // dimensions and margins as needed...
  orientation = 0;

  if ((val = cupsGetOption("landscape", num_options, options)) != NULL)
  {
    if (strcasecmp(val, "no") != 0 && strcasecmp(val, "off") != 0 &&
        strcasecmp(val, "false") != 0)
      orientation = 1;
  }
  else if ((val = cupsGetOption("orientation-requested", num_options, options)) != NULL)
  {
   /*
    * Map IPP orientation values to 0 to 3:
    *
    *   3 = 0 degrees   = 0
    *   4 = 90 degrees  = 1
    *   5 = -90 degrees = 3
    *   6 = 180 degrees = 2
    */

    orientation = atoi(val) - 3;
    if (orientation >= 2)
      orientation ^= 1;
  }

  switch (orientation & 3)
  {
    case 0 : /* Portait */
    case 2 : /* Reverse Portrait */
        break;

    case 1 : /* Landscape */
    case 3 : /* Reverse Landscape */
	temp   = width;
	width  = length;
	length = temp;
	break;
  }

  if ((val = cupsGetOption("debug", num_options, options)) != NULL &&
      strcasecmp(val, "no") && strcasecmp(val, "off") &&
      strcasecmp(val, "false"))
    printCommands = 1;
  else
    printCommands = 0;

  if ((val = cupsGetOption("fitplot", num_options, options)) != NULL &&
      strcasecmp(val, "no") && strcasecmp(val, "off") &&
      strcasecmp(val, "false"))
    fit = 1;

  if ((val = cupsGetOption("sides", num_options, options)) != NULL &&
      strncasecmp(val, "two-", 4) == 0)
    duplex = 1;
  else if ((val = cupsGetOption("Duplex", num_options, options)) != NULL &&
           strncasecmp(val, "Duplex", 6) == 0)
    duplex = 1;
  else if ((val = cupsGetOption("JCLDuplex", num_options, options)) != NULL &&
           strncasecmp(val, "Duplex", 6) == 0)
    duplex = 1;
  else if ((val = cupsGetOption("EFDuplex", num_options, options)) != NULL &&
           strncasecmp(val, "Duplex", 6) == 0)
    duplex = 1;
  else if ((val = cupsGetOption("KD03Duplex", num_options, options)) != NULL &&
           strncasecmp(val, "Duplex", 6) == 0)
    duplex = 1;
  else if (ppdIsMarked(ppd, "Duplex", "DuplexNoTumble") ||
           ppdIsMarked(ppd, "Duplex", "DuplexTumble") ||
	   ppdIsMarked(ppd, "JCLDuplex", "DuplexNoTumble") ||
           ppdIsMarked(ppd, "JCLDuplex", "DuplexTumble") ||
	   ppdIsMarked(ppd, "EFDuplex", "DuplexNoTumble") ||
           ppdIsMarked(ppd, "EFDuplex", "DuplexTumble") ||
	   ppdIsMarked(ppd, "KD03Duplex", "DuplexNoTumble") ||
           ppdIsMarked(ppd, "KD03Duplex", "DuplexTumble"))
    duplex = 1;

  if (ppd != NULL)
    ppdClose(ppd);

  fprintf(stderr, "DEBUG: pdftops - level = %d, width = %d, length = %d\n",
          level, width, length);

  // read config file
  if ((server_root = getenv("CUPS_SERVERROOT")) == NULL)
    server_root = CUPS_SERVERROOT;

  snprintf(buffer, sizeof(buffer), "%s/pdftops.conf", server_root);

  globalParams = new GlobalParams(buffer);

  if (fit || globalParams->getPSPaperWidth() > 0)
  {
    // Only set paper size and area if we are fitting to the job's
    // page size or the pdftops.conf file does not contain
    // "psPaperSize match"...

    fprintf(stderr, "DEBUG: Setting paper dimensions to %dx%d!\n", width,
            length);

    globalParams->setPSPaperWidth(width);
    globalParams->setPSPaperHeight(length);
    globalParams->setPSImageableArea(0, 0, width, length);
  }

  globalParams->setPSDuplex(duplex);
  globalParams->setPSExpandSmaller(fit);
  globalParams->setPSShrinkLarger(fit);
  globalParams->setPSLevel(level);
  globalParams->setPSASCIIHex(level == psLevel1);
  globalParams->setPSEmbedType1(1);
  globalParams->setPSEmbedTrueType(1);
  globalParams->setPSEmbedCIDPostScript(1);
  globalParams->setErrQuiet(0);
  globalParams->setPrintCommands(printCommands);

  if (printCommands)
    setbuf(stdout, NULL);

  // open PDF file
  doc = new PDFDoc(fileName, NULL, NULL);

  // check for print permission
  if (doc->isOk() && doc->okToPrint())
  {
    // CUPS always writes to stdout...
    psFileName = new GString("-");

    // write PostScript file
    psOut = new PSOutputDev(psFileName->getCString(), doc->getXRef(),
                            doc->getCatalog(), 1, doc->getNumPages(),
			    psModePS, 0, 0, 0, 0, gFalse, NULL);
    if (psOut->isOk())
      doc->displayPages(psOut, 1, doc->getNumPages(), 72.0, 72.0, 0,
                        gTrue, gFalse, gFalse);
    delete psOut;

    // clean up
    delete psFileName;
  }
  else
  {
    error(-1, "Unable to print this document.");
  }

  cupsFreeOptions(num_options, options);

  delete doc;
  delete globalParams;

  // check for memory leaks
  Object::memCheck(stderr);
  gMemReport(stderr);

  // Remove temp file if needed...
  if (tempfile[0])
    unlink(tempfile);

  return 0;
}


//
// End of "$Id: pdftops.cxx 7726 2008-07-14 17:53:24Z mike $".
//
