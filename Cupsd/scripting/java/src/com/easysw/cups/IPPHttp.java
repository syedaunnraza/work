package com.easysw.cups;

/**
 * @version 1.1 23-JAN-2007
 * @author  Apple Inc.
 *
 *   Internet Printing Protocol definitions for the Common UNIX Printing
 *   System (CUPS).
 *
 *   Copyright 2007 by Apple Inc.
 *   Copyright 1997-2007 by Easy Software Products.
 *
 *   These coded instructions, statements, and computer programs are the
 *   property of Apple Inc. and are protected by Federal copyright
 *   law.  Distribution and use rights are outlined in the file "LICENSE.txt"
 *   which should have been included with this file.  If this file is
 *   file is missing or damaged, see the license at "http://www.cups.org/".
 */

/**
 * An <code>IPPHttp</code> object is used for reading/writing to the cups
 * server, and processing responses.
 *
 * @author	TDB
 * @version	1.1
 * @since	JDK1.3
 */

import java.io.*;
import java.util.*;
import java.net.*;
import java.security.*;

public class IPPHttp
{

  /**
   *  Class constants - most not in use yet.
   */
  public static final int HTTP_WAITING = 0x00;
  public static final int HTTP_OPTIONS = 0x01;
  public static final int HTTP_GET = 0x02;
  public static final int HTTP_GET_SEND = 0x03;
  public static final int HTTP_HEAD = 0x04;
  public static final int HTTP_POST = 0x05;
  public static final int HTTP_POST_RECV = 0x06;
  public static final int HTTP_POST_SEND = 0x07;
  public static final int HTTP_PUT = 0x08;
  public static final int HTTP_PUT_RECV = 0x09;
  public static final int HTTP_DELETE = 0x0A;
  public static final int HTTP_TRACE = 0x0B;
  public static final int HTTP_CLOSE = 0x0C;
  public static final int HTTP_STATUS = 0x0D;

  public static final int HTTP_0_9 = 0x09;
  public static final int HTTP_1_0 = 0x64;
  public static final int HTTP_1_1 = 0x65;

  public static final int HTTP_KEEPALIVE_OFF = 0x00;
  public static final int HTTP_KEEPALIVE_ON = 0x01;

  public static final int HTTP_ENCODE_LENGTH = 0x00;
  public static final int HTTP_ENCODE_CHUNKED = 0x01;

  public static final int HTTP_ENCRYPT_IF_REQUESTED = 0x00;
  public static final int HTTP_ENCRYPT_NEVER = 0x01;
  public static final int HTTP_ENCRYPT_REQUIRED = 0x02;
  public static final int HTTP_ENCRYPT_ALWAYS = 0x03;

  public static final int HTTP_AUTH_NONE = 0x00;
  public static final int HTTP_AUTH_BASIC = 0x01;
  public static final int HTTP_AUTH_MD5 = 0x02;
  public static final int HTTP_AUTH_MD5_SESS = 0x03;
  public static final int HTTP_AUTH_MD5_INT = 0x04;
  public static final int HTTP_AUTH_MD5_SESS_INT = 0x05;

  public static final int HTTP_ERROR = 0xFFFFFFFF;
  public static final int HTTP_CONTINUE = 0x64;
  public static final int HTTP_SWITCHING_PROTOCOLS = 0x65;
  public static final int HTTP_OK = 0xC8;
  public static final int HTTP_CREATED = 0xC9;
  public static final int HTTP_ACCEPTED = 0xCA;
  public static final int HTTP_NOT_AUTHORITATIVE = 0xCB;
  public static final int HTTP_NO_CONTENT = 0xCC;
  public static final int HTTP_RESET_CONTENT = 0xCD;
  public static final int HTTP_PARTIAL_CONTENT = 0xCE;
  public static final int HTTP_MULTIPLE_CHOICES = 0x12C;
  public static final int HTTP_MOVED_PERMANENTLY = 0x12D;
  public static final int HTTP_MOVED_TEMPORARILY = 0x12E;
  public static final int HTTP_SEE_OTHER = 0x12F;
  public static final int HTTP_NOT_MODIFIED = 0x130;
  public static final int HTTP_USE_PROXY = 0x131;
  public static final int HTTP_BAD_REQUEST = 0x190;
  public static final int HTTP_UNAUTHORIZED = 0x191;
  public static final int HTTP_PAYMENT_REQUIRED = 0x192;
  public static final int HTTP_FORBIDDEN = 0x193;
  public static final int HTTP_NOT_FOUND = 0x194;
  public static final int HTTP_METHOD_NOT_ALLOWED = 0x195;
  public static final int HTTP_NOT_ACCEPTABLE = 0x196;
  public static final int HTTP_PROXY_AUTHENTICATION = 0x197;
  public static final int HTTP_REQUEST_TIMEOUT = 0x198;
  public static final int HTTP_CONFLICT = 0x199;
  public static final int HTTP_GONE = 0x19A;
  public static final int HTTP_LENGTH_REQUIRED = 0x19B;
  public static final int HTTP_PRECONDITION = 0x19C;
  public static final int HTTP_REQUEST_TOO_LARGE = 0x19D;
  public static final int HTTP_URI_TOO_LONG = 0x19E;
  public static final int HTTP_UNSUPPORTED_MEDIATYPE = 0x19F;
  public static final int HTTP_UPGRADE_REQUIRED = 0x1AA;
  public static final int HTTP_SERVER_ERROR = 0x1F4;
  public static final int HTTP_NOT_IMPLEMENTED = 0x1F5;
  public static final int HTTP_BAD_GATEWAY = 0x1F6;
  public static final int HTTP_SERVICE_UNAVAILABLE = 0x1F7;
  public static final int HTTP_GATEWAY_TIMEOUT = 0x1F8;

  public static final int HTTP_NOT_SUPPORTED = 0x1F9;

  public static final int HTTP_FIELD_UNKNOWN = 0xFFFFFFFF;
  public static final int HTTP_FIELD_ACCEPT_LANGUAGE = 0x00;
  public static final int HTTP_FIELD_ACCEPT_RANGES = 0x01;
  public static final int HTTP_FIELD_AUTHORIZATION = 0x02;
  public static final int HTTP_FIELD_CONNECTION = 0x03;
  public static final int HTTP_FIELD_CONTENT_ENCODING = 0x04;
  public static final int HTTP_FIELD_CONTENT_LANGUAGE = 0x05;
  public static final int HTTP_FIELD_CONTENT_LENGTH = 0x06;
  public static final int HTTP_FIELD_CONTENT_LOCATION = 0x07;
  public static final int HTTP_FIELD_CONTENT_MD5 = 0x08;
  public static final int HTTP_FIELD_CONTENT_RANGE = 0x09;
  public static final int HTTP_FIELD_CONTENT_TYPE = 0x0A;
  public static final int HTTP_FIELD_CONTENT_VERSION = 0x0B;
  public static final int HTTP_FIELD_DATE = 0x0C;
  public static final int HTTP_FIELD_HOST = 0x0D;
  public static final int HTTP_FIELD_IF_MODIFIED_SINCE = 0x0E;
  public static final int HTTP_FIELD_IF_UNMODIFIED_SINCE = 0x0F;
  public static final int HTTP_FIELD_KEEP_ALIVE = 0x10;
  public static final int HTTP_FIELD_LAST_MODIFIED = 0x11;
  public static final int HTTP_FIELD_LINK = 0x12;
  public static final int HTTP_FIELD_LOCATION = 0x13;
  public static final int HTTP_FIELD_RANGE = 0x14;
  public static final int HTTP_FIELD_REFERER = 0x15;
  public static final int HTTP_FIELD_RETRY_AFTER = 0x16;
  public static final int HTTP_FIELD_TRANSFER_ENCODING = 0x17;
  public static final int HTTP_FIELD_UPGRADE = 0x18;
  public static final int HTTP_FIELD_USER_AGENT = 0x19;
  public static final int HTTP_FIELD_WWW_AUTHENTICATE = 0x1A;
  public static final int HTTP_FIELD_MAX = 0x1B;

  public static final String http_fields[] =
                      {
			  "Accept-Language",
			  "Accept-Ranges",
			  "Authorization",
			  "Connection",
			  "Content-Encoding",
			  "Content-Language",
			  "Content-Length",
			  "Content-Location",
			  "Content-MD5",
			  "Content-Range",
			  "Content-Type",
			  "Content-Version",
			  "Date",
			  "Host",
			  "If-Modified-Since",
			  "If-Unmodified-since",
			  "Keep-Alive",
			  "Last-Modified",
			  "Link",
			  "Location",
			  "Range",
			  "Referer",
			  "Retry-After",
			  "Transfer-Encoding",
			  "Upgrade",
			  "User-Agent",
			  "WWW-Authenticate"
			};
  public static final String days[] =
                      {
			  "Sun",
			  "Mon",
			  "Tue",
			  "Wed",
			  "Thu",
			  "Fri",
			  "Sat"
			};
  public static final String months[] =
			{
			  "Jan",
			  "Feb",
			  "Mar",
			  "Apr",
			  "May",
			  "Jun",
		          "Jul",
			  "Aug",
			  "Sep",
			  "Oct",
			  "Nov",
			  "Dec"
			};



  //
  //  Private class members.
  //
  private URL                  url;   // URL of connection.

  public  Socket               conn;       // Connection socket.
  public  boolean              connected;  // True when connected.

  public  BufferedInputStream  is;    //  Input stream.
  public  BufferedReader       br;
  public  BufferedOutputStream os;    //  Output stream.

  private boolean             encrypted;

  public  int                 write_content_length;
  private char                write_buffer[];
  private int                 write_buffer_head;
  private int                 write_buffer_tail;

  public String               read_header_date;
  public String               read_header_server;
  public String               read_header_charset;
  public String               read_header_content_language;
  public String               read_header_content_type;
  public int                  read_header_content_length;

  public char                 read_buffer[];
  private int                 read_buffer_head;
  private int                 read_buffer_tail;

  public int                  status;
  public String               status_text;
  public String               version;
  public int                  error;
  public int                  activity;

  public String               hostname;       // Hostname from URL
  public int                  port;           // Port from URL.
  public String               path;           // Path from URL.
  public String               user;           // User name
  public String               passwd;         // Password

  public String               auth_type;      // none, basic, digest
  public String               realm;          // For digest auth
  public String               opaque;         // For digest auth
  public String               nonce;          // For digest auth
  public String               resource;       // For digest auth
  public String               method;         // For digest auth

  public String               http_request;  
  public int                  http_content_length;



  /**
   *  Constructor using <code>URL</code>.
   *
   *  @param	request_url	<code>URL</code> of server to connect to.
   *  @throw	IOException
   *  @throw	UnknownHostException
   */
  public IPPHttp( String request_url )
        throws IOException, UnknownHostException
  {

    encrypted   = false;
    status      = 0;
    status_text = "";
    version     = "1.0";
    connected   = false;
    user        = "";
    passwd      = "";

    auth_type   = "";
    realm       = "";
    nonce       = "";
    resource    = "";
    method      = "";

    try
    {
      //
      //  Create the URL and split it up.
      //
      url      = new URL(request_url);
      hostname = url.getHost();
      port     = url.getPort();
      path     = url.getPath();


      //
      //  Open the socket and set the options.
      //
      conn     = new Socket(hostname, port);
      conn.setSoTimeout(200);

      //
      //  Create the input and output streams.
      //
      is       = new BufferedInputStream(new DataInputStream(conn.getInputStream()));
      os       = new BufferedOutputStream(new DataOutputStream(conn.getOutputStream()));
      connected = true;
    }
    catch(UnknownHostException unknownhostexception)
    {
            throw unknownhostexception;
    }
    catch(IOException ioexception)
    {
            throw ioexception;
    }
  }



  /**
   *  Constructor using <code>URL, user and pass</code>.
   *
   *  @param	request_url	<code>URL</code> of server to connect to.
   *  @param	p_auth_type     <code>String</code> basic or digest.
   *  @param	p_user		<code>String</code> User name.
   *  @param	p_passwd	<code>String</code> password.
   *  @throw	IOException
   *  @throw	UnknownHostException
   */
  public IPPHttp( String request_url, String p_auth_type,
                  String p_user,      String p_passwd )
        throws IOException, UnknownHostException
  {
    encrypted   = false;
    status      = 0;
    status_text = "";
    version     = "1.0";
    connected   = false;

    user        = p_user;
    passwd      = p_passwd;
    auth_type   = p_auth_type;

    realm       = "";
    nonce       = "";
    resource    = "";
    method      = "";

    try
    {
      //
      //  Create the URL and split it up.
      //
      url      = new URL(request_url);
      hostname = url.getHost();
      port     = url.getPort();
      path     = url.getPath();

      //
      //  Open the socket and set the options.
      //
      conn     = new Socket(hostname, port);
      conn.setSoTimeout(200);

      //
      //  Create the input and output streams.
      //
      is       = new BufferedInputStream(new DataInputStream(conn.getInputStream()));
      os       = new BufferedOutputStream(new DataOutputStream(conn.getOutputStream()));
      connected = true;
    }
    catch(UnknownHostException unknownhostexception)
    {
            throw unknownhostexception;
    }
    catch(IOException ioexception)
    {
            throw ioexception;
    }
  }




  /**
   *  Re-establish a dropped connection.
   *
   *  @return	<code>boolean</code>		True if connected.
   *
   *  @throw	IOException
   */
  public boolean reConnect() throws IOException
  {
    connected   = false;
    status      = 0;
    status_text = "";
    try
    {
      //
      //  Open the socket and set the options.
      //
      conn     = new Socket(hostname, port);
      conn.setSoTimeout(200);

      //
      //  Create the input and output streams.
      //
      is       = new BufferedInputStream(new DataInputStream(conn.getInputStream()));
      os       = new BufferedOutputStream(new DataOutputStream(conn.getOutputStream()));
      connected = true;
      return(connected);

    }
    catch (IOException ioexception)
    {
      connected = false;
      throw(ioexception);
    }
  }



  /**
   * Set the user name.
   *
   * @param	p_user		<code>String</code> - user name.
   */
  public void setUser(String p_user )
  {
    user = p_user;
  }


  /**
   * Set the password.
   *
   * @param	p_passwd	<code>String</code> - password.
   */
  public void setPassword(String p_passwd )
  {
    passwd = p_passwd;
  }




  /**
   * Write the request header bytes to the server.
   *
   * @param	request		<code>String</code> - the request.
   * @param	content_length	<code>int</code> - size of the total request.
   * @throw	IOException
   */
  public int writeHeader(String request, int content_length )
        throws IOException
  {

    http_request        = request;
    http_content_length = content_length;

    try
    {
      String s1 = "POST " + request + " HTTP/1.0\r\n";
      os.write(s1.getBytes(), 0, s1.length());

      s1 = "Content-type: application/ipp\r\n";
      os.write(s1.getBytes(), 0, s1.length());


      //
      //  Do basic style authorization if needed.
      //
      if (auth_type.compareTo("basic") == 0)
      {
        s1 = user + ":" + passwd;
        String auth_string = Base64Coder.encodeString(s1);
        s1 = "Authorization: Basic " + auth_string + "\r\n";
        os.write(s1.getBytes(), 0, s1.length());
      }
      else if (auth_type.compareTo("digest") == 0)
      {
        try
        {
            IPPMD5 md5 = IPPMD5.getInstance();
            String auth_string = md5.MD5Digest(user, passwd, realm,
                                             "POST", path, nonce );
            s1 = "Authorization: Digest " + "username=\"" + user + "\", " +
                 "realm=\"" + realm + "\", " +
                 "nonce=\"" + nonce + "\", " +
                 "response=\"" + auth_string + "\"\r\n";

            os.write(s1.getBytes(), 0, s1.length());
        }
        catch(NoSuchAlgorithmException e)
        {
            System.out.println("No such algorithm: MD5.");
        }
      }

      s1 = "Content-length: " + content_length + "\r\n\r\n";
      os.write(s1.getBytes(), 0, s1.length());
      os.flush();
    }
    catch(IOException ioexception)
    {
      error = HTTP_ERROR;
      throw ioexception;
    }


    try
    {
      int          local_status = 0;

      //
      //  Check for any response.
      //
      if (is.available() > 0)
      {
        StringBuffer http_version = new StringBuffer(32);
        StringBuffer http_status  = new StringBuffer(32);
        StringBuffer http_text    = new StringBuffer(256);

        String read_buffer;
        status = 0;
        is.mark(8192);
        while (is.available() > 0)
        {
          read_buffer = read_line();

          if (read_buffer.startsWith("HTTP/"))
          {
            int i,n;
            String s2 = read_buffer.substring(5);


            for (i=0;(i < s2.length() && s2.charAt(i) != ' '); i++)
            {
              http_version.append(s2.charAt(i));
            }
            while (i < s2.length() && s2.charAt(i) == ' ')
              i++;
            for (;(i < s2.length() && s2.charAt(i) != '\n' && 
                 s2.charAt(i) != '\r' && s2.charAt(i) != ' '); i++)
            {
              http_status.append(s2.charAt(i));
            }

            while (i < s2.length() && s2.charAt(i) == ' ')
              i++;
            for (n=0;(n < 256 && i < s2.length() && s2.charAt(i) != '\n' && 
                 s2.charAt(i) != '\r' && s2.charAt(i) != ' '); i++)
            {
              http_text.append(s2.charAt(i));
            }
            local_status      = Integer.parseInt(http_status.toString(), 10);
          }
        }
        is.reset();
      }

      //
      //  See if we need to reconnect and send authorization.
      //
      switch( local_status )
      {
        //
        //  Not authorized.
        //
        case HTTP_UNAUTHORIZED: read_header();
                  return( local_status );
      }
    }
    catch(IOException ioexception)
    {
      error = HTTP_ERROR;
      throw ioexception;
    }
    return(0);
  }






  public int checkForResponse()
  {
    //
    //  Check for any response.
    //
    try
    {
      if (is.available() > 0)
      {
        StringBuffer http_version = new StringBuffer(32);
        StringBuffer http_status  = new StringBuffer(32);
        StringBuffer http_text    = new StringBuffer(256);
        int          local_status = 0;
        String       read_buffer;

        status = 0;
        is.mark(8192);
        while (is.available() > 0)
        {
          read_buffer = read_line();
          if (read_buffer.startsWith("HTTP/"))
          {
            int i,n;
            String s2 = read_buffer.substring(5);
            for (i=0;(i < s2.length() && s2.charAt(i) != ' '); i++)
            {
              http_version.append(s2.charAt(i));
            }
            while (i < s2.length() && s2.charAt(i) == ' ')
              i++;
            for (;(i < s2.length() && s2.charAt(i) != '\n' && 
                 s2.charAt(i) != '\r' && s2.charAt(i) != ' '); i++)
            {
              http_status.append(s2.charAt(i));
            }

            while (i < s2.length() && s2.charAt(i) == ' ')
              i++;
            for (n=0;(n < 256 && i < s2.length() && s2.charAt(i) != '\n' && 
                 s2.charAt(i) != '\r' && s2.charAt(i) != ' '); i++)
            {
              http_text.append(s2.charAt(i));
            }
            local_status      = Integer.parseInt(http_status.toString(), 10);
            status = local_status;
          }
        }
        is.reset();

        //
        //  See if we need to reconnect and send authorization.
        //
        switch( local_status )
        {
          //
          //  Not authorized.
          //
          case HTTP_UNAUTHORIZED: read_header();
                    return( local_status );
        }
      } 
    }
    catch (IOException e)
    {
      return(HTTP_ERROR);
    }
    return(0);
  }


  /**
   *  Write bytes to the output stream.
   *
   *  @param	bytes		Array of bytes to write to the stream.
   *  @throw	IOException
   */
  public void write(byte bytes[])
        throws IOException
  {
    try
    {
      os.write(bytes, 0, bytes.length);
      os.flush();
    }
    catch(IOException ioexception)
    {
      error = HTTP_ERROR;
      throw ioexception;
    }
  }


  /**
   *  Write bytes to the output stream.
   *
   *  @param	bytes		Array of bytes to write to the stream.
   *  @param	length		Number of bytes to write to the stream.
   *  @throw	IOException
   */
  public void write(byte bytes[], int length )
        throws IOException
  {
    try
    {
      os.write(bytes, 0, length);
      os.flush();
    }
    catch(IOException ioexception)
    {
      error = HTTP_ERROR;
      throw ioexception;
    }
  }










  /**
   *  Read the HTTP header from the input stream.
   *
   *  @return	<code>int</code>	Content length of response.
   *  @return	0			Return zero on error.
   *  @throw	IOException
   */	
  public int read_header()
        throws IOException
  {
    boolean done = false;
    read_header_content_length = 0;

    String read_buffer; 
    while (!done)
    {
        read_buffer = read_line();
        if (read_buffer.startsWith("HTTP/"))
        {
          int i,n;
          String s2 = read_buffer.substring(5);

          StringBuffer http_version = new StringBuffer(32);
          StringBuffer http_status  = new StringBuffer(32);
          StringBuffer http_text    = new StringBuffer(256);

          for (i=0;(i < s2.length() && s2.charAt(i) != ' '); i++)
          {
            http_version.append(s2.charAt(i));
          }
          while (i < s2.length() && s2.charAt(i) == ' ')
            i++;
          for (;(i < s2.length() && s2.charAt(i) != '\n' && 
                 s2.charAt(i) != '\r' && s2.charAt(i) != ' '); i++)
          {
            http_status.append(s2.charAt(i));
          }

          while (i < s2.length() && s2.charAt(i) == ' ')
            i++;
          for (n=0;(n < 256 && i < s2.length() && s2.charAt(i) != '\n' && 
                 s2.charAt(i) != '\r' && s2.charAt(i) != ' '); i++)
          {
            http_text.append(s2.charAt(i));
          }
          version     = http_version.toString();
          status      = Integer.parseInt(http_status.toString(), 10);
          status_text = http_text.toString();
        }
        else if (read_buffer.startsWith("WWW-Authenticate: Basic"))
        {
          String s2=read_buffer.substring("WWW-Authenticate: Basic".length());
          auth_type = "basic";
        }
        else if (read_buffer.startsWith("WWW-Authenticate: Digest"))
        {
          String s2=read_buffer.substring("WWW-Authenticate: Digest".length());
          auth_type = "digest";
          parseAuthenticate(s2);
        }
        else if (read_buffer.startsWith("Content-Length:"))
        {
          String s2 = read_buffer.substring(15);
          read_header_content_length = Integer.parseInt(s2.trim(), 10);
        }
        else if (read_buffer.startsWith("Content-Language:"))
        {
          String s3 = read_buffer.substring(17);
          read_header_content_language = s3.trim();
        } 
        else if (read_buffer.startsWith("Server:"))
        {
          String s4 = read_buffer.substring(7);
          read_header_server = s4.trim();
        }
        else if (read_buffer.startsWith("Date:"))
        {
          String s5 = read_buffer.substring(5);
          read_header_date = s5.trim();
        } 
        else if (read_buffer.length() == 0)
        {
          done = true;
          return( read_header_content_length );
        }
    }
    return( 0 );
  }



  /**
   *  Read a line from the input stream.
   *
   * @return	<code>String</code>	Line read.
   * @throw	<code>IOException</code>
   */
  public String read_line()
        throws IOException
  {
    StringBuffer sb = new StringBuffer();
    int          c = 0;

    try
    {
      while ((c != -1) && (c != 10))
      {
        c = is.read();
        switch( c )
        {
          case -1:
          case 10:
          case 13:
                   break;

          default: sb.append((char)c);
        }
      }
    }
    catch (IOException e)
    {
      throw(e);
    }
    return(sb.toString());
  }





  /**
   *  Read up to <code>count</code> bytes from the input stream.
   *
   * @param	<code>count</code>	Number of bytes to read.
   * @return	<code>char[]</code>	Character array of data read.
   * @throw	<code>IOException</code>
   */
  public char[] read(int count)
        throws IOException
  {
    char ac[] = new char[count];
    int j = 0;
    try
    {
      for (int k = is.read(); k != -1 && j < count; k = is.read())
      {
        ac[j++] = (char)k;
      }
    }
    catch(IOException ioexception)
    {
      throw ioexception;
    }
    return(ac);
  }


  /**
   *  Process the HTTP response from the server.
   *
   * @return	<code>IPP</code>	IPP object containing response data.
   * @see	<code>IPP</code>
   * @see	<code>IPPRequest</code>
   * @see	<code>IPPAttribute</code>
   * @see	<code>IPPValue</code>
   * @see	<code>IPPDefs</code>
   */
  public IPP processResponse()
  {
    IPP              ipp;
    IPPAttribute     attr;       // temp attribute 
    IPPValue         val;        // temp value

    short            vtag;       //  Current value tag 
    short            gtag;       //  Current group tag

    char[]           buffer;

    ipp = new IPP();
    ipp.request = new IPPRequest();

    int read_buffer_bytes     = read_buffer.length;
    int read_buffer_remaining = read_buffer_bytes;
    int bufferidx             = 0;
    int n;


    ipp.current = -1;   // current attritue??
    ipp.last    = -1;   //  last attr?
    attr        = null;
    buffer      = read_buffer;
    gtag        = -1;
    vtag        = -1;


    //  ---------------------------------------------------------------
    //  State machine to process response.
    //
    ipp.state  = IPPDefs.IDLE;
    while ((ipp.state != IPPDefs.TAG_END) &&
           (read_buffer_remaining > 0))
    {
      switch (ipp.state)
      {
        case IPPDefs.IDLE :
            ipp.state++;         /* Avoid common problem... */

        //
        // Get the request header...
        //
        case IPPDefs.HEADER :
          if (read_buffer_remaining < 8)
	  {
	    return (null);
	  }

          //
          //  Verify the major version number...
	  //
	  if (buffer[0] != (char)1)
	  {
	    return (null);
	  }

          //
          //  Then copy the request header over...
  	  //
          ipp.request.version[0]  = buffer[bufferidx++];
          ipp.request.version[1]  = buffer[bufferidx++];
          ipp.request.op_status   = (short)((short)buffer[bufferidx] << 8) | 
                                             (short)buffer[bufferidx+1];
          bufferidx += 2;
      
          //
          //  Get the text version of the request status ....
          //
          ipp.status = new IPPStatus(ipp.request.op_status);

          ipp.request.request_id  = (int)((int)buffer[bufferidx] << 24) | 
                                         ((int)buffer[bufferidx+1] << 16) |
	                                 ((int)buffer[bufferidx+2] << 8) | 
                                         ((int)buffer[bufferidx+3]);
          bufferidx += 4;
          read_buffer_remaining -= 8;

          ipp.state   = IPPDefs.ATTRIBUTE;
	  ipp.current = -1;
	  ipp.current_tag  = IPPDefs.TAG_ZERO;
          break;

      case IPPDefs.ATTRIBUTE :
          while (read_buffer_remaining > 0)
          {
	    //
	    //  Read the value tag first.
	    //
            vtag = (short)buffer[bufferidx++];
            read_buffer_remaining--;
	    if (vtag == IPPDefs.TAG_END)
	    {
	      //
	      //  No more attributes left...
	      //
	      ipp.state = IPPDefs.DATA;
              if (attr != null)
              {
                ipp.addAttribute(attr);
                attr = null;
              }
	      break;
	    }
            else if (vtag < IPPDefs.TAG_UNSUPPORTED_VALUE)
	    {
              if (attr != null)
              {
                ipp.addAttribute(attr);
              }

	      //
	      //  Group tag...  Set the current group and continue...
	      //
              gtag = vtag;

              // If still the same group ....
              if (ipp.current_tag == gtag)
              {
                //
                //  Add a separator
                //
                attr = new IPPAttribute(IPPDefs.TAG_ZERO,IPPDefs.TAG_ZERO,"");
                ipp.addAttribute(attr);
                attr = null;
              }


	      ipp.current_tag  = gtag;
	      ipp.current = -1;
	      continue;
	    }

            //
	    // Get the name...
	    //
            n = ((int)buffer[bufferidx] << 8) | (int)buffer[bufferidx+1];
            bufferidx += 2;
            read_buffer_remaining -= 2;

            if (n == 0)
	    {
              //
              //  Parse Error, can't add additional values to null attr
              //
              if (attr == null)
	        return (null);

	      //
	      //  More values for current attribute...
	      //

	      //
	      // Make sure we aren't adding a new value of a different
	      // type...
	      //

	      if (attr.value_tag == IPPDefs.TAG_STRING ||
                  (attr.value_tag >= IPPDefs.TAG_TEXTLANG &&
		   attr.value_tag <= IPPDefs.TAG_MIMETYPE))
              {
	        //
	        // String values can sometimes come across in different
	        // forms; accept sets of differing values...
	        //
	        if (vtag != IPPDefs.TAG_STRING &&
    	           (vtag < IPPDefs.TAG_TEXTLANG || vtag > IPPDefs.TAG_MIMETYPE))
	          return (null);
              }
	      else if (attr.value_tag != vtag)
	        return (null);
	    }
	    else
	    {
              if (attr != null)
              {
                ipp.addAttribute(attr);
                attr = null;
              }

              //
              // New Attribute
              //
              StringBuffer s = new StringBuffer();
              for (int i=0; i < n; i++)
              {
                s.append((char)buffer[bufferidx++]);
                read_buffer_remaining--;
              }
              attr     = new IPPAttribute( gtag, vtag, s.toString() );
	    }
	    n = ((short)buffer[bufferidx] << 8) | (short)buffer[bufferidx+1];
            bufferidx += 2;
            read_buffer_remaining -= 2;

	    switch (vtag)
	    {
	      case IPPDefs.TAG_INTEGER :
	      case IPPDefs.TAG_ENUM :
	  	n = (int)(((int)buffer[bufferidx] << 24) |
                          ((int)buffer[bufferidx+1] << 16) |
                          ((int)buffer[bufferidx+2] << 8) |
                          ((int)buffer[bufferidx+3]));
                bufferidx += 4;
                read_buffer_remaining -= 4;
                attr.addInteger( n );
	        break;

	      case IPPDefs.TAG_BOOLEAN :
                if ((byte)buffer[bufferidx++] > 0)
                  attr.addBoolean(true);
                else
                  attr.addBoolean(false);
                read_buffer_remaining --;
	        break;

	      case IPPDefs.TAG_TEXT :
	      case IPPDefs.TAG_NAME :
	      case IPPDefs.TAG_KEYWORD :
	      case IPPDefs.TAG_STRING :
	      case IPPDefs.TAG_URI :
	      case IPPDefs.TAG_URISCHEME :
	      case IPPDefs.TAG_CHARSET :
	      case IPPDefs.TAG_LANGUAGE :
	      case IPPDefs.TAG_MIMETYPE :
                StringBuffer s = new StringBuffer();
                for (int i=0; i < n; i++ )
                {
                  s.append( (char)buffer[bufferidx++] );
                  read_buffer_remaining --;
                }
                attr.addString( "", s.toString() );
	        break;


	      case IPPDefs.TAG_DATE :
                char db[] = new char[11];
                for (int i=0; i < 11; i++ )
                {
                  db[i] = (char)buffer[bufferidx++];
                  read_buffer_remaining --;
                }
                attr.addDate( db );
	        break;


	      case IPPDefs.TAG_RESOLUTION :
                if (read_buffer_remaining < 9)
                  return( null );

                int  x, y;
                byte u;
                x = (int)(((int)buffer[bufferidx] & 0xff000000) << 24) |
                         (((int)buffer[bufferidx+1] & 0x00ff0000) << 16) |
                         (((int)buffer[bufferidx+2] & 0x0000ff00) << 8) |
                         (((int)buffer[bufferidx+3] & 0x000000ff));
                bufferidx += 4;
                read_buffer_remaining -= 4;

                y = (int)(((int)buffer[bufferidx] & 0xff000000) << 24) |
                         (((int)buffer[bufferidx+1] & 0x00ff0000) << 16) |
                         (((int)buffer[bufferidx+2] & 0x0000ff00) << 8) |
                         (((int)buffer[bufferidx+3] & 0x000000ff));
                bufferidx += 4;
                read_buffer_remaining -= 4;

                u = (byte)buffer[bufferidx++];
                read_buffer_remaining--;
                attr.addResolution( u, x, y );         
	        break;

	      case IPPDefs.TAG_RANGE :
	        if (read_buffer_remaining < 8)
		  return (null);

                int lower, upper; 
                lower = (int)(((int)buffer[bufferidx] & 0xff000000) << 24) |
                         (((int)buffer[bufferidx+1] & 0x00ff0000) << 16) |
                         (((int)buffer[bufferidx+2] & 0x0000ff00) << 8) |
                         (((int)buffer[bufferidx+3] & 0x000000ff));
                bufferidx += 4;
                read_buffer_remaining -= 4;

                upper = (int)(((int)buffer[bufferidx] & 0xff000000) << 24) |
                         (((int)buffer[bufferidx+1] & 0x00ff0000) << 16) |
                         (((int)buffer[bufferidx+2] & 0x0000ff00) << 8) |
                         (((int)buffer[bufferidx+3] & 0x000000ff));
                bufferidx += 4;
                read_buffer_remaining -= 4;

                attr.addRange( (short)lower, (short)upper );         
	        break;

	      case IPPDefs.TAG_TEXTLANG :
	      case IPPDefs.TAG_NAMELANG :
	       //
	       // text-with-language and name-with-language are composite
	       // values:
	       //
	       // charset-length
	       // charset
	       // text-length
	       // text
	       //

		n = ((int)buffer[bufferidx] << 8) | (int)buffer[bufferidx+1];
                bufferidx += 2;

                StringBuffer cs = new StringBuffer();
                for (int i=0; i < n; i++ )
                {
                  cs.append( (char)buffer[bufferidx++] );
                  read_buffer_remaining --;
                }

		n = ((int)buffer[bufferidx] << 8) | (int)buffer[bufferidx+1];
                bufferidx += 2;

                StringBuffer tx = new StringBuffer();
                for (int i=0; i < n; i++ )
                {
                  tx.append( (char)buffer[bufferidx++] );
                  read_buffer_remaining --;
                }

                attr.addString( cs.toString(), tx.toString() );
	        break;


              default : /* Other unsupported values */
	        if (n > 0)
		{
                  bufferidx += n;
                  read_buffer_remaining -= n;
		}
	        break;
	    }
	  }  // End of while

          if (attr != null)
          {
            ipp.addAttribute(attr);
            attr = null;
          }
          break;

      case IPPDefs.DATA :
        break;

      default :
        break; /* anti-compiler-warning-code */
    }
  }
  return (ipp);
}



//
//  Parse a WWW-Authenticate: Digest request
//
public void parseAuthenticate( String p_auth )
{
  String        tmp;
  StringBuffer	val;
  int           i,n;

  tmp = p_auth;
  while (tmp.length() > 0)
  {
    i = 0;
    while (tmp.length() > 0 && (tmp.charAt(i) == ' ' || tmp.charAt(i) == '"'))
      tmp = tmp.substring(1); 
    i = 0;

    if (tmp.startsWith("realm="))
    {
      i = "realm=".length();
      tmp = tmp.substring(i);
      i = 0;
      while ((i < tmp.length()) && 
             (tmp.charAt(i) == ' ' || 
              tmp.charAt(i) == '"' || 
              tmp.charAt(i) == '='))
      {
        i++;
      }
      val = new StringBuffer(1024);
      while (i < tmp.length() && tmp.charAt(i) != '"')
        val.append(tmp.charAt(i++));
      realm = val.toString();
      tmp = tmp.substring(i);
    }
    else if (tmp.startsWith("nonce="))
    {
      i = "nonce=".length();
      tmp = tmp.substring(i);
      i = 0;
      while ((i < tmp.length()) && 
             (tmp.charAt(i) == ' ' || 
              tmp.charAt(i) == '"' || 
              tmp.charAt(i) == '='))
      {
        i++;
      }
      val = new StringBuffer(1024);
      while (i < tmp.length() && tmp.charAt(i) != '"')
        val.append(tmp.charAt(i++));
      nonce = val.toString();
      tmp = tmp.substring(i);
    }
    else if (tmp.startsWith("opaque="))
    {
      i = "opaque=".length();
      tmp = tmp.substring(i);
      i = 0;
      while ((i < tmp.length()) && 
             (tmp.charAt(i) == ' ' || 
              tmp.charAt(i) == '"' || 
              tmp.charAt(i) == '='))
      {
        i++;
      }
      val = new StringBuffer(1024);
      while (i < tmp.length() && tmp.charAt(i) != '"')
        val.append(tmp.charAt(i++));
      opaque = val.toString();
      tmp = tmp.substring(i);
    }
    else 
    {
      StringBuffer name = new StringBuffer(256);
      while ((i < tmp.length()) && 
             (tmp.charAt(i) != ' ' || 
              tmp.charAt(i) != '"' || 
              tmp.charAt(i) != '='))
      {
        name.append(tmp.charAt(i++));
      }
     
      i = name.toString().length();
      tmp = tmp.substring(i);
      i = 0;
      while ((i < tmp.length()) && 
             (tmp.charAt(i) == ' ' || 
              tmp.charAt(i) == '"' || 
              tmp.charAt(i) == '='))
      {
        i++;
      }
      val = new StringBuffer(1024);
      while (i < tmp.length() && tmp.charAt(i) != '"')
        val.append(tmp.charAt(i++));
      //junk = val.toString();
      tmp = tmp.substring(i);
    }
  }
}





}  // End of IPPHttp class


