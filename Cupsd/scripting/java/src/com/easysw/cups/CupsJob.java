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
 * A <code>CupsJob</code> object holds job data, and has methods to 
 * process cups job list responses into a usable form.
 *
 * @author	TDB
 * @version	1.0
 * @since	JDK1.3
 */

//
import java.io.*;
import java.net.*;

public class CupsJob
{
    public int		job_id;
    public String       job_more_info;
    public String       job_uri;
    public String       job_printer_uri;
    public long         job_printer_up_time;
    public String       job_name;
    public String       job_originating_user_name;
    public String       document_format;
    public String       job_originating_host_name;
    public int          job_priority;
    public int          job_state;
    public int          job_media_sheets_completed;
    public int          job_k_octets;
    public long         time_at_creation;
    public long         time_at_processing;
    public long         time_at_completed;
    public String       job_hold_until;
    public String       job_sheets;
    public String       job_state_reasons;


    /**
     * Constructor - set some default values.
     */
    public CupsJob()
    {
      job_id = -1;
      job_more_info = "";
      job_uri = "";
      job_printer_uri = "";
      job_printer_up_time = 0;
      job_name = "";
      job_originating_user_name = "";
      document_format = "";
      job_originating_host_name = "";
      job_priority = -1;
      job_state = 0;
      job_media_sheets_completed = 0;
      job_k_octets = 0;
      time_at_creation = 0;
      time_at_processing = 0;
      time_at_completed = 0;
      job_hold_until = "";
      job_sheets = "";
      job_state_reasons = "";
    }




    /**
     * Process an attribute from a cups.doRequest() call
     * and move the value into a local member.
     *
     * @see	<code>IPPDefs</code>
     * @see	<code>IPPValues</code>
     * @see	<code>IPPAttributes</code>
     */
    public void updateAttribute( IPPAttribute a )
    {
      IPPValue val;
     
      //
      //  Kick out if no values are present.
      //
      if (a.values.size() < 1)
        return;

      val = (IPPValue)a.values.get(0);
      if (a.name.compareTo("job-more-info") == 0)
      {
        job_more_info = val.text;
      }
      else if (a.name.compareTo("job-uri") == 0)
      {
        job_uri = val.text;
      }
      else if (a.name.compareTo("job-printer-up-time") == 0)
      {
        job_printer_up_time = val.integer_value;
      }
      else if (a.name.compareTo("job-originating-user-name") == 0)
      {
        job_originating_user_name = val.text;
      }
      else if (a.name.compareTo("document-format") == 0)
      {
        document_format = val.text;
      }
      else if (a.name.compareTo("job-priority") == 0)
      {
        job_priority = val.integer_value;
      }
      else if (a.name.compareTo("job-originating-host-name") == 0)
      {
        job_originating_host_name = val.text;
      }
      else if (a.name.compareTo("job-id") == 0)
      {
        job_id = val.integer_value;
      }
      else if (a.name.compareTo("job-state") == 0)
      {
        job_state = val.integer_value;
      }
      else if (a.name.compareTo("job-media-sheets-completed") == 0)
      {
        job_media_sheets_completed = val.integer_value;
      }
      else if (a.name.compareTo("job-printer-uri") == 0)
      {
        job_printer_uri = val.text;
      }
      else if (a.name.compareTo("job-name") == 0)
      {
        job_name = val.text;
      }
      else if (a.name.compareTo("job-k-octets") == 0)
      {
        job_k_octets = val.integer_value;
      }
      else if (a.name.compareTo("time-at-creation") == 0)
      {
        time_at_creation = val.integer_value;
      }
      else if (a.name.compareTo("time-at-processing") == 0)
      {
        time_at_processing = val.integer_value;
      }
      else if (a.name.compareTo("time-at-completed") == 0)
      {
        time_at_completed = val.integer_value;
      }
      else if (a.name.compareTo("job-hold-until") == 0)
      {
        job_hold_until = val.text;
      }
      else if (a.name.compareTo("job-sheets") == 0)
      {
        job_sheets = val.text;
      }
      else if (a.name.compareTo("job-state-reasons") == 0)
      {
        job_state_reasons = val.text;
      }
    }


    /**
     * Convert a job status to a string.
     *
     * @see	<code>IPPDefs</code>
     */
    public String jobStatusText()
    {
      switch( job_state )
      {
        case 3:  return("Pending");
        case 4:  return("Held");
        case 5:  return("Processing");
        case 6:  return("Stopped");
        case 7:  return("Cancelled");
        case 8:  return("Aborted");
        case 9:  return("Completed");
      }
      return("Unknown");
    }


}

//  eof ....
