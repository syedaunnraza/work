/*
 * "$Id: ieee1284.c 7386 2008-03-21 00:31:31Z mike $"
 *
 *   IEEE-1284 support functions for the Common UNIX Printing System (CUPS).
 *
 *   Copyright 2007 by Apple Inc.
 *   Copyright 1997-2007 by Easy Software Products, all rights reserved.
 *
 *   These coded instructions, statements, and computer programs are the
 *   property of Apple Inc. and are protected by Federal copyright
 *   law.  Distribution and use rights are outlined in the file "LICENSE.txt"
 *   "LICENSE" which should have been included with this file.  If this
 *   file is missing or damaged, see the license at "http://www.cups.org/".
 *
 *   This file is subject to the Apple OS-Developed Software exception.
 *
 * Contents:
 *
 *   backendGetDeviceID()  - Get the IEEE-1284 device ID string and
 *                           corresponding URI.
 *   backendGetMakeModel() - Get the make and model string from the device ID.
 */

/*
 * Include necessary headers.
 */

#include "backend-private.h"

#ifdef __linux
#  include <sys/ioctl.h>
#  include <linux/lp.h>
#  define IOCNR_GET_DEVICE_ID		1
#  define LPIOC_GET_DEVICE_ID(len)	_IOC(_IOC_READ, 'P', IOCNR_GET_DEVICE_ID, len)
#  include <linux/parport.h>
#  include <linux/ppdev.h>
#  include <unistd.h>
#  include <fcntl.h>
#endif /* __linux */

#ifdef __sun
#  ifdef __sparc
#    include <sys/ecppio.h>
#  else
#    include <sys/ioccom.h>
#    include <sys/ecppsys.h>
#  endif /* __sparc */
#endif /* __sun */


/*
 * 'backendGetDeviceID()' - Get the IEEE-1284 device ID string and
 *                          corresponding URI.
 */

int					/* O - 0 on success, -1 on failure */
backendGetDeviceID(
    int        fd,			/* I - File descriptor */
    char       *device_id,		/* O - 1284 device ID */
    int        device_id_size,		/* I - Size of buffer */
    char       *make_model,		/* O - Make/model */
    int        make_model_size,		/* I - Size of buffer */
    const char *scheme,			/* I - URI scheme */
    char       *uri,			/* O - Device URI */
    int        uri_size)		/* I - Size of buffer */
{
#ifdef __APPLE__ /* This function is a no-op */
  return (-1);

#else /* Get the device ID from the specified file descriptor... */
  char	*attr,				/* 1284 attribute */
  	*delim,				/* 1284 delimiter */
	*uriptr,			/* Pointer into URI */
	manufacturer[256],		/* Manufacturer string */
	serial_number[1024];		/* Serial number string */
  int	manulen;			/* Length of manufacturer string */
#  ifdef __linux
  int	length;				/* Length of device ID info */
  int   got_id = 0;
#  endif /* __linux */
#  if defined(__sun) && defined(ECPPIOC_GETDEVID)
  struct ecpp_device_id did;		/* Device ID buffer */
#  endif /* __sun && ECPPIOC_GETDEVID */


  DEBUG_printf(("backendGetDeviceID(fd=%d, device_id=%p, device_id_size=%d, "
                "make_model=%p, make_model_size=%d, scheme=\"%s\", "
		"uri=%p, uri_size=%d)\n", fd, device_id, device_id_size,
		make_model, make_model_size, scheme ? scheme : "(null)",
		uri, uri_size));

 /*
  * Range check input...
  */

  if (!device_id || device_id_size < 32)
  {
    DEBUG_puts("backendGetDeviceID: Bad args!");
    return (-1);
  }

  if (make_model)
    *make_model = '\0';

  if (fd >= 0)
  {
   /*
    * Get the device ID string...
    */

    *device_id = '\0';

#  ifdef __linux
  if (ioctl(fd, LPIOC_GET_DEVICE_ID(device_id_size), device_id))
  {
   /*
    * Linux has to implement things differently for every device it seems.
    * Since the standard parallel port driver does not provide a simple
    * ioctl() to get the 1284 device ID, we have to open the "raw" parallel
    * device corresponding to this port and do some negotiation trickery
    * to get the current device ID.
    */

    if (uri && !strncmp(uri, "parallel:/dev/", 14))
    {
      char	devparport[16];		/* /dev/parportN */
      int	devparportfd,		/* File descriptor for raw device */
		mode;			/* Port mode */


     /*
      * Since the Linux parallel backend only supports 4 parallel port
      * devices, just grab the trailing digit and use it to construct a
      * /dev/parportN filename...
      */

      snprintf(devparport, sizeof(devparport), "/dev/parport%s",
               uri + strlen(uri) - 1);

      if ((devparportfd = open(devparport, O_RDWR | O_NOCTTY)) != -1)
      {
       /*
        * Claim the device...
        */

	if (!ioctl(devparportfd, PPCLAIM))
	{
          fcntl(devparportfd, F_SETFL, fcntl(devparportfd, F_GETFL) | O_NONBLOCK);

	  mode = IEEE1284_MODE_COMPAT;

	  if (!ioctl(devparportfd, PPNEGOT, &mode))
	  {
	   /*
	    * Put the device into Device ID mode...
	    */

	    mode = IEEE1284_MODE_NIBBLE | IEEE1284_DEVICEID;

	    if (!ioctl(devparportfd, PPNEGOT, &mode))
	    {
	     /*
	      * Read the 1284 device ID...
	      */

	      if ((length = read(devparportfd, device_id,
	                         device_id_size - 1)) >= 2)
              {
	        device_id[length] = '\0';
	        got_id = 1;
	      }
	    }
	  }

         /*
	  * Release the device...
	  */

	  ioctl(devparportfd, PPRELEASE);
	}

        close(devparportfd);
      }
    }
  }
  else
    got_id = 1;

  if (got_id)
    {
     /*
      * Extract the length of the device ID string from the first two
      * bytes.  The 1284 spec says the length is stored MSB first...
      */

      length = (((unsigned)device_id[0] & 255) << 8) +
	       ((unsigned)device_id[1] & 255);

     /*
      * Check to see if the length is larger than our buffer; first
      * assume that the vendor incorrectly implemented the 1284 spec,
      * and then limit the length to the size of our buffer...
      */

      if (length > (device_id_size - 2))
	length = (((unsigned)device_id[1] & 255) << 8) +
		 ((unsigned)device_id[0] & 255);

      if (length > (device_id_size - 2))
	length = device_id_size - 2;

     /*
      * Copy the device ID text to the beginning of the buffer and
      * nul-terminate.
      */

      memmove(device_id, device_id + 2, length);
      device_id[length] = '\0';
    }
#    ifdef DEBUG
    else
      printf("backendGetDeviceID: ioctl failed - %s\n", strerror(errno));
#    endif /* DEBUG */
#  endif /* __linux */

#   if defined(__sun) && defined(ECPPIOC_GETDEVID)
    did.mode = ECPP_CENTRONICS;
    did.len  = device_id_size - 1;
    did.rlen = 0;
    did.addr = device_id;

    if (!ioctl(fd, ECPPIOC_GETDEVID, &did))
    {
     /*
      * Nul-terminate the device ID text.
      */

      if (did.rlen < (device_id_size - 1))
	device_id[did.rlen] = '\0';
      else
	device_id[device_id_size - 1] = '\0';
    }
#    ifdef DEBUG
    else
      printf("backendGetDeviceID: ioctl failed - %s\n", strerror(errno));
#    endif /* DEBUG */
#  endif /* __sun && ECPPIOC_GETDEVID */
  }

  DEBUG_printf(("backendGetDeviceID: device_id=\"%s\"\n", device_id));

  if (scheme && uri)
    *uri = '\0';

  if (!*device_id)
    return (-1);

 /*
  * Get the make and model...
  */

  if (make_model)
    backendGetMakeModel(device_id, make_model, make_model_size);

 /*
  * Then generate a device URI...
  */

  if (scheme && uri && uri_size > 32)
  {
   /*
    * Look for the serial number field...
    */

    if ((attr = strstr(device_id, "SERN:")) != NULL)
      attr += 5;
    else if ((attr = strstr(device_id, "SERIALNUMBER:")) != NULL)
      attr += 13;
    else if ((attr = strstr(device_id, ";SN:")) != NULL)
      attr += 4;

    if (attr)
    {
      strlcpy(serial_number, attr, sizeof(serial_number));

      if ((delim = strchr(serial_number, ';')) != NULL)
	*delim = '\0';
    }
    else
      serial_number[0] = '\0';

   /*
    * Generate the device URI from the manufacturer, make_model, and
    * serial number strings.
    */

    snprintf(uri, uri_size, "%s://", scheme);

    if ((attr = strstr(device_id, "MANUFACTURER:")) != NULL)
      attr += 13;
    else if ((attr = strstr(device_id, "Manufacturer:")) != NULL)
      attr += 13;
    else if ((attr = strstr(device_id, "MFG:")) != NULL)
      attr += 4;

    if (attr)
    {
      strlcpy(manufacturer, attr, sizeof(manufacturer));

      if ((delim = strchr(manufacturer, ';')) != NULL)
        *delim = '\0';

      if (!strcasecmp(manufacturer, "Hewlett-Packard"))
        strcpy(manufacturer, "HP");
      else if (!strcasecmp(manufacturer, "Lexmark International"))
        strcpy(manufacturer, "Lexmark");
    }
    else
    {
      strlcpy(manufacturer, make_model, sizeof(manufacturer));

      if ((delim = strchr(manufacturer, ' ')) != NULL)
        *delim = '\0';
    }

    manulen = strlen(manufacturer);

    for (uriptr = uri + strlen(uri), delim = manufacturer;
	 *delim && uriptr < (uri + uri_size - 3);
	 delim ++)
      if (*delim == ' ')
      {
	*uriptr++ = '%';
	*uriptr++ = '2';
	*uriptr++ = '0';
      }
      else
	*uriptr++ = *delim;

    *uriptr++ = '/';

    if (!strncasecmp(make_model, manufacturer, manulen))
    {
      delim = make_model + manulen;

      while (isspace(*delim & 255))
        delim ++;
    }
    else
      delim = make_model;

    for (; *delim && uriptr < (uri + uri_size - 3); delim ++)
      if (*delim == ' ')
      {
	*uriptr++ = '%';
	*uriptr++ = '2';
	*uriptr++ = '0';
      }
      else
	*uriptr++ = *delim;

    if (serial_number[0])
    {
     /*
      * Add the serial number to the URI...
      */

      strlcpy(uriptr, "?serial=", uri_size - (uriptr - uri));
      strlcat(uriptr, serial_number, uri_size - (uriptr - uri));
    }
    else
      *uriptr = '\0';
  }

  return (0);
#endif /* __APPLE__ */
}


/*
 * 'backendGetMakeModel()' - Get the make and model string from the device ID.
 */

int					/* O - 0 on success, -1 on failure */
backendGetMakeModel(
    const char *device_id,		/* O - 1284 device ID */
    char       *make_model,		/* O - Make/model */
    int        make_model_size)		/* I - Size of buffer */
{
  char	*attr,				/* 1284 attribute */
  	*delim,				/* 1284 delimiter */
	*mfg,				/* Manufacturer string */
	*mdl;				/* Model string */


  DEBUG_printf(("backendGetMakeModel(device_id=\"%s\", "
                "make_model=%p, make_model_size=%d)\n", device_id,
		make_model, make_model_size));

 /*
  * Range check input...
  */

  if (!device_id || !*device_id || !make_model || make_model_size < 32)
  {
    DEBUG_puts("backendGetMakeModel: Bad args!");
    return (-1);
  }

  *make_model = '\0';

 /*
  * Look for the description field...
  */

  if ((attr = strstr(device_id, "DES:")) != NULL)
    attr += 4;
  else if ((attr = strstr(device_id, "DESCRIPTION:")) != NULL)
    attr += 12;

  if (attr)
  {
   /*
    * Make sure the description contains something useful, since some
    * printer manufacturers (HP) apparently don't follow the standards
    * they helped to define...
    *
    * Here we require the description to be 8 or more characters in length,
    * containing at least one space and one letter.
    */

    if ((delim = strchr(attr, ';')) == NULL)
      delim = attr + strlen(attr);

    if ((delim - attr) < 8)
      attr = NULL;
    else
    {
      char	*ptr;			/* Pointer into description */
      int	letters,		/* Number of letters seen */
		spaces;			/* Number of spaces seen */


      for (ptr = attr, letters = 0, spaces = 0; ptr < delim; ptr ++)
      {
        if (isspace(*ptr & 255))
	  spaces ++;
	else if (isalpha(*ptr & 255))
	  letters ++;

        if (spaces && letters)
	  break;
      }

      if (!spaces || !letters)
        attr = NULL;
    }
  }

  if ((mfg = strstr(device_id, "MANUFACTURER:")) != NULL)
    mfg += 13;
  else if ((mfg = strstr(device_id, "Manufacturer:")) != NULL)
    mfg += 13;
  else if ((mfg = strstr(device_id, "MFG:")) != NULL)
    mfg += 4;

  if ((mdl = strstr(device_id, "MODEL:")) != NULL)
    mdl += 6;
  else if ((mdl = strstr(device_id, "Model:")) != NULL)
    mdl += 6;
  else if ((mdl = strstr(device_id, "MDL:")) != NULL)
    mdl += 4;

  if (mdl)
  {
   /*
    * Build a make-model string from the manufacturer and model attributes...
    */

    if (mfg)
    {
     /*
      * Skip leading whitespace...
      */

      while (isspace(*mfg & 255))
        mfg ++;

     /*
      * Map common bad names to the ones we use for driver selection...
      */

      if (!strncasecmp(mfg, "Hewlett-Packard", 15))
	strlcpy(make_model, "HP", make_model_size);
      else if (!strncasecmp(mfg, "Lexmark International", 21))
	strlcpy(make_model, "Lexmark", make_model_size);
      else
      {
       /*
        * Use the manufacturer that is supplied...
	*/

	strlcpy(make_model, mfg, make_model_size);

	if ((delim = strchr(make_model, ';')) != NULL)
	  *delim = '\0';

       /*
        * But strip trailing whitespace...
	*/

	for (delim = make_model + strlen(make_model) - 1;
	     delim > make_model && *delim == ' ';
	     delim --)
	  *delim = '\0';
      }

      if (!strncasecmp(make_model, mdl, strlen(make_model)))
      {
       /*
	* Just copy model string, since it has the manufacturer...
	*/

	strlcpy(make_model, mdl, make_model_size);
      }
      else
      {
       /*
	* Concatenate the make and model...
	*/

        while (isspace(*mdl & 255))
	  mdl ++;

	strlcat(make_model, " ", make_model_size);
	strlcat(make_model, mdl, make_model_size);
      }
    }
    else
    {
     /*
      * Just copy model string, since it has the manufacturer...
      */

      while (isspace(*mdl & 255))
	mdl ++;

      strlcpy(make_model, mdl, make_model_size);
    }
  }
  else if (attr)
  {
   /*
    * Use description...
    */

    while (isspace(*attr & 255))
      attr ++;

    if (!strncasecmp(attr, "Hewlett-Packard hp ", 19))
    {
     /*
      * Check for a common HP bug...
      */

      strlcpy(make_model, "HP ", make_model_size);
      strlcpy(make_model + 3, attr + 19, make_model_size - 3);
    }
    else if (!strncasecmp(attr, "Hewlett-Packard ", 16))
    {
      strlcpy(make_model, "HP ", make_model_size);
      strlcpy(make_model + 3, attr + 16, make_model_size - 3);
    }
    else
    {
      strlcpy(make_model, attr, make_model_size);
    }
  }
  else
  {
   /*
    * Use "Unknown" as the printer make and model...
    */

    strlcpy(make_model, "Unknown", make_model_size);
  }

 /*
  * Strip trailing data...
  */

  if ((delim = strchr(make_model, ';')) != NULL)
    *delim = '\0';

  for (delim = make_model + strlen(make_model) - 1;
       delim > make_model && *delim == ' ';
       delim --)
    *delim = '\0';

 /*
  * Strip trailing whitespace...
  */

  for (delim = make_model + strlen(make_model) - 1; delim >= make_model; delim --)
    if (isspace(*delim & 255))
      *delim = '\0';
    else
      break;

 /*
  * Return...
  */

  if (make_model[0])
    return (0);
  else
    return (-1);
}


/*
 * End of "$Id: ieee1284.c 7386 2008-03-21 00:31:31Z mike $".
 */
