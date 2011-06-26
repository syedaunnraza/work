/*
 * "$Id: sysman.h 6649 2007-07-11 21:46:42Z mike $"
 *
 *   System management definitions for the Common UNIX Printing System (CUPS).
 *
 *   Copyright 2007 by Apple Inc.
 *   Copyright 2006 by Easy Software Products.
 *
 *   These coded instructions, statements, and computer programs are the
 *   property of Apple Inc. and are protected by Federal copyright
 *   law.  Distribution and use rights are outlined in the file "LICENSE.txt"
 *   which should have been included with this file.  If this file is
 *   file is missing or damaged, see the license at "http://www.cups.org/".
 */

/*
 * Globals...
 */

VAR int			Sleeping	VALUE(0);
					/* Non-zero if machine is entering or *
					 * in a sleep state...                */
#ifdef __APPLE__
VAR int			SysEventPipes[2] VALUE2(-1,-1);
					/* System event notification pipes */
#endif	/* __APPLE__ */


/*
 * Prototypes...
 */

extern void	cupsdStartSystemMonitor(void);
extern void	cupsdStopSystemMonitor(void);
extern void	cupsdUpdateSystemMonitor(void);


/*
 * End of "$Id: sysman.h 6649 2007-07-11 21:46:42Z mike $".
 */
