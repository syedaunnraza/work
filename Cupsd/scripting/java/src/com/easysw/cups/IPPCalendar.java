package com.easysw.cups;
/**
 * @version 1.00 06-NOV-2002
 * @author  Apple Inc.
 *
 *   Internet Printing Protocol definitions for the Common UNIX Printing
 *   System (CUPS).
 *
 *   Copyright 2007 by Apple Inc.
 *   Copyright 1997-2002 by Easy Software Products.
 *
 *   These coded instructions, statements, and computer programs are the
 *   property of Apple Inc. and are protected by Federal copyright
 *   law.  Distribution and use rights are outlined in the file "LICENSE.txt"
 *   which should have been included with this file.  If this file is
 *   file is missing or damaged, see the license at "http://www.cups.org/".
 */

/**
 * An <code>IPPCalendar</code> object is used for date/time conversion.
 *
 * @author	TDB
 * @version	1.0
 * @since	JDK1.3
 */

import java.util.*;

class IPPCalendar extends GregorianCalendar
{
  /**
   * Get the time in milliseconds from the <code>GregorianCalendar</code>
   * class.
   *
   * @return	<code>long</code>	Time in milliseconds of a date.
   */
  public long getTimeInMillis()
  {
    return(super.getTimeInMillis());
  }

  /**
   * Get the unix time in seconds from the <code>GregorianCalendar</code>
   * class.
   *
   * @return	<code>int</code>	Unix Time in seconds of a date.
   */
  public int getUnixTime()
  {
    return( (int)(getTimeInMillis() / 1000) );
  }

} // end of class
