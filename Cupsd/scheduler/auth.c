/*
 * "$Id: auth.c 7485 2008-04-21 23:13:22Z mike $"
 *
 *   Authorization routines for the Common UNIX Printing System (CUPS).
 *
 *   Copyright 2007-2008 by Apple Inc.
 *   Copyright 1997-2007 by Easy Software Products, all rights reserved.
 *
 *   This file contains Kerberos support code, copyright 2006 by
 *   Jelmer Vernooij.
 *
 *   These coded instructions, statements, and computer programs are the
 *   property of Apple Inc. and are protected by Federal copyright
 *   law.  Distribution and use rights are outlined in the file "LICENSE.txt"
 *   which should have been included with this file.  If this file is
 *   file is missing or damaged, see the license at "http://www.cups.org/".
 *
 * Contents:
 *
 *   cupsdAddLocation()        - Add a location for authorization.
 *   cupsdAddName()            - Add a name to a location...
 *   cupsdAllowHost()          - Add a host name that is allowed to access the
 *                               location.
 *   cupsdAllowIP()            - Add an IP address or network that is allowed
 *                               to access the location.
 *   cupsdAuthorize()          - Validate any authorization credentials.
 *   cupsdCheckAuth()          - Check authorization masks.
 *   cupsdCheckGroup()         - Check for a user's group membership.
 *   cupsdCopyLocation()       - Make a copy of a location...
 *   cupsdDeleteAllLocations() - Free all memory used for location
 *                               authorization.
 *   cupsdDeleteLocation()     - Free all memory used by a location.
 *   cupsdDenyHost()           - Add a host name that is not allowed to access
 *                               the location.
 *   cupsdDenyIP()             - Add an IP address or network that is not
 *                               allowed to access the location.
 *   cupsdFindBest()           - Find the location entry that best matches the
 *                               resource.
 *   cupsdFindLocation()       - Find the named location.
 *   cupsdIsAuthorized()       - Check to see if the user is authorized...
 *   add_allow()               - Add an allow mask to the location.
 *   add_deny()                - Add a deny mask to the location.
 *   compare_locations()       - Compare two locations.
 *   cups_crypt()              - Encrypt the password using the DES or MD5
 *                               algorithms, as needed.
 *   get_gss_creds()           - Obtain GSS credentials.
 *   get_md5_password()        - Get an MD5 password.
 *   pam_func()                - PAM conversation function.
 *   to64()                    - Base64-encode an integer value...
 *   check_authref()           - Check an authorization services reference.
 */

/*
 * Include necessary headers...
 */

#include "cupsd.h"
#include <grp.h>
#ifdef HAVE_SHADOW_H
#  include <shadow.h>
#endif /* HAVE_SHADOW_H */
#ifdef HAVE_CRYPT_H
#  include <crypt.h>
#endif /* HAVE_CRYPT_H */
#if HAVE_LIBPAM
#  ifdef HAVE_PAM_PAM_APPL_H
#    include <pam/pam_appl.h>
#  else
#    include <security/pam_appl.h>
#  endif /* HAVE_PAM_PAM_APPL_H */
#endif /* HAVE_LIBPAM */
#ifdef HAVE_USERSEC_H
#  include <usersec.h>
#endif /* HAVE_USERSEC_H */
#ifdef HAVE_MEMBERSHIP_H
#  include <membership.h>
#endif /* HAVE_MEMBERSHIP_H */
#ifdef HAVE_AUTHORIZATION_H
#  include <Security/AuthorizationTags.h>
#  ifdef HAVE_SECBASEPRIV_H
#    include <Security/SecBasePriv.h>
#  else
extern const char *cssmErrorString(int error);
#  endif /* HAVE_SECBASEPRIV_H */
#endif /* HAVE_AUTHORIZATION_H */
#ifdef HAVE_SYS_PARAM_H
#  include <sys/param.h>
#endif /* HAVE_SYS_PARAM_H */
#ifdef HAVE_SYS_UCRED_H
#  include <sys/ucred.h>
typedef struct xucred cupsd_ucred_t;
#  define CUPSD_UCRED_UID(c) (c).cr_uid
#else
typedef struct ucred cupsd_ucred_t;
#  define CUPSD_UCRED_UID(c) (c).uid
#endif /* HAVE_SYS_UCRED_H */


/*
 * Local functions...
 */

static cupsd_authmask_t	*add_allow(cupsd_location_t *loc);
static cupsd_authmask_t	*add_deny(cupsd_location_t *loc);
#ifdef HAVE_AUTHORIZATION_H
static int		check_authref(cupsd_client_t *con, const char *right);
#endif /* HAVE_AUTHORIZATION_H */
static int		compare_locations(cupsd_location_t *a,
			                  cupsd_location_t *b);
#if !HAVE_LIBPAM && !defined(HAVE_USERSEC_H)
static char		*cups_crypt(const char *pw, const char *salt);
#endif /* !HAVE_LIBPAM && !HAVE_USERSEC_H */
#ifdef HAVE_GSSAPI
static gss_cred_id_t	get_gss_creds(const char *service_name,
			              const char *con_server_name);
#endif /* HAVE_GSSAPI */
static char		*get_md5_password(const char *username,
			                  const char *group, char passwd[33]);
#if HAVE_LIBPAM
static int		pam_func(int, const struct pam_message **,
			         struct pam_response **, void *);
#elif !defined(HAVE_USERSEC_H)
static void		to64(char *s, unsigned long v, int n);
#endif /* HAVE_LIBPAM */


/*
 * Local structures...
 */

#if HAVE_LIBPAM
typedef struct cupsd_authdata_s		/**** Authentication data ****/
{
  char	username[33],			/* Username string */
	password[33];			/* Password string */
} cupsd_authdata_t;
#endif /* HAVE_LIBPAM */


/*
 * Local globals...
 */

#if defined(__hpux) && HAVE_LIBPAM
static cupsd_authdata_t	*auth_data;	/* Current client being authenticated */
#endif /* __hpux && HAVE_LIBPAM */


/*
 * 'cupsdAddLocation()' - Add a location for authorization.
 */

cupsd_location_t *			/* O - Pointer to new location record */
cupsdAddLocation(const char *location)	/* I - Location path */
{
  cupsd_location_t	*temp;		/* New location */


 /*
  * Make sure the locations array is created...
  */

  if (!Locations)
    Locations = cupsArrayNew((cups_array_func_t)compare_locations, NULL);

  if (!Locations)
    return (NULL);

 /*
  * Try to allocate memory for the new location.
  */

  if ((temp = calloc(1, sizeof(cupsd_location_t))) == NULL)
    return (NULL);

 /*
  * Initialize the record and copy the name over...
  */

  if ((temp->location = strdup(location)) == NULL)
  {
    free(temp);
    return (NULL);
  }

  temp->length = strlen(temp->location);

  cupsArrayAdd(Locations, temp);

  cupsdLogMessage(CUPSD_LOG_DEBUG2, "cupsdAddLocation: added location \'%s\'",
                  location);

 /*
  * Return the new record...
  */

  return (temp);
}


/*
 * 'cupsdAddName()' - Add a name to a location...
 */

void
cupsdAddName(cupsd_location_t *loc,	/* I - Location to add to */
             char             *name)	/* I - Name to add */
{
  char	**temp;				/* Pointer to names array */


  cupsdLogMessage(CUPSD_LOG_DEBUG2, "cupsdAddName(loc=%p, name=\"%s\")",
                  loc, name);

  if (loc->num_names == 0)
    temp = malloc(sizeof(char *));
  else
    temp = realloc(loc->names, (loc->num_names + 1) * sizeof(char *));

  if (temp == NULL)
  {
    cupsdLogMessage(CUPSD_LOG_ERROR, "Unable to add name to location %s: %s",
                    loc->location ? loc->location : "nil", strerror(errno));
    return;
  }

  loc->names = temp;

  if ((temp[loc->num_names] = strdup(name)) == NULL)
  {
    cupsdLogMessage(CUPSD_LOG_ERROR,
                    "Unable to duplicate name for location %s: %s",
                    loc->location ? loc->location : "nil", strerror(errno));
    return;
  }

  loc->num_names ++;
}


/*
 * 'cupsdAllowHost()' - Add a host name that is allowed to access the location.
 */

void
cupsdAllowHost(cupsd_location_t *loc,	/* I - Location to add to */
               char             *name)	/* I - Name of host or domain to add */
{
  cupsd_authmask_t	*temp;		/* New host/domain mask */
  char			ifname[32],	/* Interface name */
			*ifptr;		/* Pointer to end of name */


  cupsdLogMessage(CUPSD_LOG_DEBUG2, "cupsdAllowHost(loc=%p(%s), name=\"%s\")",
                  loc, loc->location ? loc->location : "nil", name);

  if ((temp = add_allow(loc)) == NULL)
    return;

  if (!strcasecmp(name, "@LOCAL"))
  {
   /*
    * Allow *interface*...
    */

    temp->type             = CUPSD_AUTH_INTERFACE;
    temp->mask.name.name   = strdup("*");
    temp->mask.name.length = 1;
  }
  else if (!strncasecmp(name, "@IF(", 4))
  {
   /*
    * Allow *interface*...
    */

    strlcpy(ifname, name + 4, sizeof(ifname));

    ifptr = ifname + strlen(ifname);

    if (ifptr[-1] == ')')
    {
      ifptr --;
      *ifptr = '\0';
    }

    temp->type             = CUPSD_AUTH_INTERFACE;
    temp->mask.name.name   = strdup(ifname);
    temp->mask.name.length = ifptr - ifname;
  }
  else
  {
   /*
    * Allow name...
    */

    temp->type             = CUPSD_AUTH_NAME;
    temp->mask.name.name   = strdup(name);
    temp->mask.name.length = strlen(name);
  }
}


/*
 * 'cupsdAllowIP()' - Add an IP address or network that is allowed to access
 *                    the location.
 */

void
cupsdAllowIP(
    cupsd_location_t *loc,		/* I - Location to add to */
    const unsigned   address[4],	/* I - IP address to add */
    const unsigned   netmask[4])	/* I - Netmask of address */
{
  cupsd_authmask_t	*temp;		/* New host/domain mask */


  cupsdLogMessage(CUPSD_LOG_DEBUG2,
                  "cupsdAllowIP(loc=%p(%s), address=%x:%x:%x:%x, netmask=%x:%x:%x:%x)",
		  loc, loc->location ? loc->location : "nil",
		  address[0], address[1], address[2], address[3],
		  netmask[0], netmask[1], netmask[2], netmask[3]);

  if ((temp = add_allow(loc)) == NULL)
    return;

  temp->type = CUPSD_AUTH_IP;
  memcpy(temp->mask.ip.address, address, sizeof(temp->mask.ip.address));
  memcpy(temp->mask.ip.netmask, netmask, sizeof(temp->mask.ip.netmask));
}


/*
 * 'cupsdAuthorize()' - Validate any authorization credentials.
 */

void
cupsdAuthorize(cupsd_client_t *con)	/* I - Client connection */
{
  int		type;			/* Authentication type */
  const char	*authorization;		/* Pointer into Authorization string */
  char		*ptr,			/* Pointer into string */
		username[256],		/* Username string */
		password[33];		/* Password string */
  cupsd_cert_t	*localuser;		/* Certificate username */
  char		nonce[HTTP_MAX_VALUE],	/* Nonce value from client */
		md5[33],		/* MD5 password */
		basicmd5[33];		/* MD5 of Basic password */
  static const char * const states[] =	/* HTTP client states... */
		{
		  "WAITING",
		  "OPTIONS",
		  "GET",
		  "GET",
		  "HEAD",
		  "POST",
		  "POST",
		  "POST",
		  "PUT",
		  "PUT",
		  "DELETE",
		  "TRACE",
		  "CLOSE",
		  "STATUS"
		};


 /*
  * Locate the best matching location so we know what kind of
  * authentication to expect...
  */

  con->best = cupsdFindBest(con->uri, con->http.state);
  con->type = CUPSD_AUTH_NONE;

  cupsdLogMessage(CUPSD_LOG_DEBUG2,
                  "cupsdAuthorize: con->uri=\"%s\", con->best=%p(%s)",
                  con->uri, con->best, con->best ? con->best->location : "");

  if (con->best && con->best->type != CUPSD_AUTH_NONE)
  {
    if (con->best->type == CUPSD_AUTH_DEFAULT)
      type = DefaultAuthType;
    else
      type = con->best->type;
  }
  else
    type = DefaultAuthType;

 /*
  * Decode the Authorization string...
  */

  authorization = httpGetField(&con->http, HTTP_FIELD_AUTHORIZATION);

  cupsdLogMessage(CUPSD_LOG_DEBUG2, "cupsdAuthorize: Authorization=\"%s\"",
                  authorization);

  username[0] = '\0';
  password[0] = '\0';

#ifdef HAVE_AUTHORIZATION_H
  if (con->authref)
  {
    AuthorizationFree(con->authref, kAuthorizationFlagDefaults);
    con->authref = NULL;
  }
#endif /* HAVE_AUTHORIZATION_H */

  if (!*authorization)
  {
   /*
    * No authorization data provided, return early...
    */

    cupsdLogMessage(CUPSD_LOG_DEBUG,
                    "cupsdAuthorize: No authentication data provided.");
    return;
  }
#ifdef HAVE_AUTHORIZATION_H
  else if (!strncmp(authorization, "AuthRef", 6) && 
           !strcasecmp(con->http.hostname, "localhost"))
  {
    OSStatus		status;		/* Status */
    int			authlen;	/* Auth string length */
    AuthorizationItemSet *authinfo;	/* Authorization item set */

   /*
    * Get the Authorization Services data...
    */

    authorization += 7;
    while (isspace(*authorization & 255))
      authorization ++;

    authlen = sizeof(nonce);
    httpDecode64_2(nonce, &authlen, authorization);

    if (authlen != kAuthorizationExternalFormLength)
    {
      cupsdLogMessage(CUPSD_LOG_ERROR,
	              "External Authorization reference size is incorrect!");
      return;
    }

    if ((status = AuthorizationCreateFromExternalForm(
		      (AuthorizationExternalForm *)nonce, &con->authref)) != 0)
    {
      cupsdLogMessage(CUPSD_LOG_ERROR,
		      "AuthorizationCreateFromExternalForm returned %d (%s)",
		      (int)status, cssmErrorString(status));
      return;
    }

    if ((status = AuthorizationCopyInfo(con->authref, 
					kAuthorizationEnvironmentUsername, 
					&authinfo)) != 0)
    {
      cupsdLogMessage(CUPSD_LOG_ERROR,
		      "AuthorizationCopyInfo returned %d (%s)",
		      (int)status, cssmErrorString(status));
      return;
    }
  
    if (authinfo->count == 1)
      strlcpy(username, authinfo->items[0].value, sizeof(username));

    cupsdLogMessage(CUPSD_LOG_DEBUG,
                    "cupsdAuthorize: Authorized as %s using AuthRef",
		    username);

    AuthorizationFreeItemSet(authinfo);

    con->type = CUPSD_AUTH_BASIC;
  }
#endif /* HAVE_AUTHORIZATION_H */
#if defined(SO_PEERCRED) && defined(AF_LOCAL)
  else if (!strncmp(authorization, "PeerCred ", 9) &&
           con->http.hostaddr->addr.sa_family == AF_LOCAL)
  {
   /*
    * Use peer credentials from domain socket connection...
    */

    struct passwd	*pwd;		/* Password entry for this user */
    cupsd_ucred_t	peercred;	/* Peer credentials */
    socklen_t		peersize;	/* Size of peer credentials */


    if ((pwd = getpwnam(authorization + 9)) == NULL)
    {
      cupsdLogMessage(CUPSD_LOG_ERROR, "User \"%s\" does not exist!",
                      authorization + 9);
      return;
    }

    peersize = sizeof(peercred);

    if (getsockopt(con->http.fd, SOL_SOCKET, SO_PEERCRED, &peercred, &peersize))
    {
      cupsdLogMessage(CUPSD_LOG_ERROR, "Unable to get peer credentials - %s",
                      strerror(errno));
      return;
    }

    if (pwd->pw_uid != CUPSD_UCRED_UID(peercred))
    {
      cupsdLogMessage(CUPSD_LOG_ERROR,
                      "Invalid peer credentials for \"%s\" - got %d, "
		      "expected %d!", authorization + 9,
		      CUPSD_UCRED_UID(peercred), pwd->pw_uid);
#  ifdef HAVE_SYS_UCRED_H
      cupsdLogMessage(CUPSD_LOG_DEBUG, "cupsdAuthorize: cr_version=%d",
                      peercred.cr_version);
      cupsdLogMessage(CUPSD_LOG_DEBUG, "cupsdAuthorize: cr_uid=%d",
                      peercred.cr_uid);
      cupsdLogMessage(CUPSD_LOG_DEBUG, "cupsdAuthorize: cr_ngroups=%d",
                      peercred.cr_ngroups);
      cupsdLogMessage(CUPSD_LOG_DEBUG, "cupsdAuthorize: cr_groups[0]=%d",
                      peercred.cr_groups[0]);
#  endif /* HAVE_SYS_UCRED_H */
      return;
    }

    strlcpy(username, authorization + 9, sizeof(username));

    cupsdLogMessage(CUPSD_LOG_DEBUG,
                    "cupsdAuthorize: Authorized as %s using PeerCred",
		    username);

    con->type = CUPSD_AUTH_BASIC;
  }
#endif /* SO_PEERCRED && AF_LOCAL */
  else if (!strncmp(authorization, "Local", 5) &&
           !strcasecmp(con->http.hostname, "localhost"))
  {
   /*
    * Get Local certificate authentication data...
    */

    authorization += 5;
    while (isspace(*authorization & 255))
      authorization ++;

    if ((localuser = cupsdFindCert(authorization)) != NULL)
    {
      strlcpy(username, localuser->username, sizeof(username));

      cupsdLogMessage(CUPSD_LOG_DEBUG,
		      "cupsdAuthorize: Authorized as %s using Local",
		      username);
    }
    else
    {
      cupsdLogMessage(CUPSD_LOG_ERROR,
                      "cupsdAuthorize: Local authentication certificate not "
		      "found!");
      return;
    }

#ifdef HAVE_GSSAPI
    if (localuser->ccache)
      con->type = CUPSD_AUTH_NEGOTIATE;
    else
#endif /* HAVE_GSSAPI */
      con->type = CUPSD_AUTH_BASIC;
  }
  else if (!strncmp(authorization, "Basic", 5))
  {
   /*
    * Get the Basic authentication data...
    */

    int	userlen;			/* Username:password length */


    authorization += 5;
    while (isspace(*authorization & 255))
      authorization ++;

    userlen = sizeof(username);
    httpDecode64_2(username, &userlen, authorization);

   /*
    * Pull the username and password out...
    */

    if ((ptr = strchr(username, ':')) == NULL)
    {
      cupsdLogMessage(CUPSD_LOG_ERROR,
                      "cupsdAuthorize: Missing Basic password!");
      return;
    }

    *ptr++ = '\0';

    if (!username[0])
    {
     /*
      * Username must not be empty...
      */

      cupsdLogMessage(CUPSD_LOG_ERROR,
                      "cupsdAuthorize: Empty Basic username!");
      return;
    }

    if (!*ptr)
    {
     /*
      * Password must not be empty...
      */

      cupsdLogMessage(CUPSD_LOG_ERROR,
                      "cupsdAuthorize: Empty Basic password!");
      return;
    }

    strlcpy(password, ptr, sizeof(password));

   /*
    * Validate the username and password...
    */

    switch (type)
    {
      default :
      case CUPSD_AUTH_BASIC :
          {
#if HAVE_LIBPAM
	   /*
	    * Only use PAM to do authentication.  This supports MD5
	    * passwords, among other things...
	    */

	    pam_handle_t	*pamh;	/* PAM authentication handle */
	    int			pamerr;	/* PAM error code */
	    struct pam_conv	pamdata;/* PAM conversation data */
	    cupsd_authdata_t	data;	/* Authentication data */


            strlcpy(data.username, username, sizeof(data.username));
	    strlcpy(data.password, password, sizeof(data.password));

#  if defined(__sun) || defined(__hpux)
	    pamdata.conv        = (int (*)(int, struct pam_message **,
	                                   struct pam_response **,
					   void *))pam_func;
#  else
	    pamdata.conv        = pam_func;
#  endif /* __sun || __hpux */
	    pamdata.appdata_ptr = &data;

#  ifdef __hpux
	   /*
	    * Workaround for HP-UX bug in pam_unix; see pam_func() below for
	    * more info...
	    */

	    auth_data = &data;
#  endif /* __hpux */

	    pamerr = pam_start("cups", username, &pamdata, &pamh);
	    if (pamerr != PAM_SUCCESS)
	    {
	      cupsdLogMessage(CUPSD_LOG_ERROR,
	                      "cupsdAuthorize: pam_start() returned %d (%s)!\n",
        	              pamerr, pam_strerror(pamh, pamerr));
	      return;
	    }

	    pamerr = pam_authenticate(pamh, PAM_SILENT);
	    if (pamerr != PAM_SUCCESS)
	    {
	      cupsdLogMessage(CUPSD_LOG_ERROR,
	                      "cupsdAuthorize: pam_authenticate() returned %d "
			      "(%s)!\n",
        	              pamerr, pam_strerror(pamh, pamerr));
	      pam_end(pamh, 0);
	      return;
	    }

	    pamerr = pam_acct_mgmt(pamh, PAM_SILENT);
	    if (pamerr != PAM_SUCCESS)
	    {
	      cupsdLogMessage(CUPSD_LOG_ERROR,
	                      "cupsdAuthorize: pam_acct_mgmt() returned %d "
			      "(%s)!\n",
        	              pamerr, pam_strerror(pamh, pamerr));
	      pam_end(pamh, 0);
	      return;
	    }

	    pam_end(pamh, PAM_SUCCESS);

#elif defined(HAVE_USERSEC_H)
	   /*
	    * Use AIX authentication interface...
	    */

	    char	*authmsg;	/* Authentication message */
	    int		reenter;	/* ??? */


	    cupsdLogMessage(CUPSD_LOG_DEBUG,
	                    "cupsdAuthorize: AIX authenticate of username \"%s\"",
                            username);

	    reenter = 1;
	    if (authenticate(username, password, &reenter, &authmsg) != 0)
	    {
	      cupsdLogMessage(CUPSD_LOG_DEBUG,
	                      "cupsdAuthorize: Unable to authenticate username "
			      "\"%s\": %s",
	                      username, strerror(errno));
	      return;
	    }

#else
           /*
	    * Use normal UNIX password file-based authentication...
	    */

            char		*pass;	/* Encrypted password */
            struct passwd	*pw;	/* User password data */
#  ifdef HAVE_SHADOW_H
            struct spwd		*spw;	/* Shadow password data */
#  endif /* HAVE_SHADOW_H */


	    pw = getpwnam(username);	/* Get the current password */
	    endpwent();			/* Close the password file */

	    if (!pw)
	    {
	     /*
	      * No such user...
	      */

	      cupsdLogMessage(CUPSD_LOG_ERROR,
	                      "cupsdAuthorize: Unknown username \"%s\"!",
        	              username);
	      return;
	    }

#  ifdef HAVE_SHADOW_H
	    spw = getspnam(username);
	    endspent();

	    if (!spw && !strcmp(pw->pw_passwd, "x"))
	    {
	     /*
	      * Don't allow blank passwords!
	      */

	      cupsdLogMessage(CUPSD_LOG_ERROR,
	                      "cupsdAuthorize: Username \"%s\" has no shadow "
			      "password!", username);
	      return;
	    }

	    if (spw && !spw->sp_pwdp[0] && !pw->pw_passwd[0])
#  else
	    if (!pw->pw_passwd[0])
#  endif /* HAVE_SHADOW_H */
	    {
	     /*
	      * Don't allow blank passwords!
	      */

	      cupsdLogMessage(CUPSD_LOG_ERROR,
	                      "cupsdAuthorize: Username \"%s\" has no password!",
        	              username);
	      return;
	    }

	   /*
	    * OK, the password isn't blank, so compare with what came from the
	    * client...
	    */

	    pass = cups_crypt(password, pw->pw_passwd);

	    cupsdLogMessage(CUPSD_LOG_DEBUG2,
	                    "cupsdAuthorize: pw_passwd=\"%s\", crypt=\"%s\"",
		            pw->pw_passwd, pass);

	    if (!pass || strcmp(pw->pw_passwd, pass))
	    {
#  ifdef HAVE_SHADOW_H
	      if (spw)
	      {
		pass = cups_crypt(password, spw->sp_pwdp);

		cupsdLogMessage(CUPSD_LOG_DEBUG2,
	                	"cupsdAuthorize: sp_pwdp=\"%s\", crypt=\"%s\"",
				spw->sp_pwdp, pass);

		if (pass == NULL || strcmp(spw->sp_pwdp, pass))
		{
	          cupsdLogMessage(CUPSD_LOG_ERROR,
		                  "cupsdAuthorize: Authentication failed for "
				  "user \"%s\"!",
				  username);
		  return;
        	}
	      }
	      else
#  endif /* HAVE_SHADOW_H */
	      {
		cupsdLogMessage(CUPSD_LOG_ERROR,
		        	"cupsdAuthorize: Authentication failed for "
				"user \"%s\"!",
				username);
		return;
              }
	    }
#endif /* HAVE_LIBPAM */
          }

	  cupsdLogMessage(CUPSD_LOG_DEBUG,
			  "cupsdAuthorize: Authorized as %s using Basic",
			  username);
          break;

      case CUPSD_AUTH_BASICDIGEST :
         /*
	  * Do Basic authentication with the Digest password file...
	  */

	  if (!get_md5_password(username, NULL, md5))
	  {
            cupsdLogMessage(CUPSD_LOG_ERROR,
	                    "cupsdAuthorize: Unknown MD5 username \"%s\"!",
	                    username);
            return;
	  }

	  httpMD5(username, "CUPS", password, basicmd5);

	  if (strcmp(md5, basicmd5))
	  {
            cupsdLogMessage(CUPSD_LOG_ERROR,
	                    "cupsdAuthorize: Authentication failed for \"%s\"!",
	                    username);
            return;
	  }

	  cupsdLogMessage(CUPSD_LOG_DEBUG,
			  "cupsdAuthorize: Authorized as %s using BasicDigest",
			  username);
	  break;
    }

    con->type = type;
  }
  else if (!strncmp(authorization, "Digest", 6))
  {
   /*
    * Get the username, password, and nonce from the Digest attributes...
    */

    if (!httpGetSubField2(&(con->http), HTTP_FIELD_AUTHORIZATION, "username",
                          username, sizeof(username)) || !username[0])
    {
     /*
      * Username must not be empty...
      */

      cupsdLogMessage(CUPSD_LOG_ERROR,
                      "cupsdAuthorize: Empty or missing Digest username!");
      return;
    }

    if (!httpGetSubField2(&(con->http), HTTP_FIELD_AUTHORIZATION, "response",
                          password, sizeof(password)) || !password[0])
    {
     /*
      * Password must not be empty...
      */

      cupsdLogMessage(CUPSD_LOG_ERROR,
                      "cupsdAuthorize: Empty or missing Digest password!");
      return;
    }

    if (!httpGetSubField(&(con->http), HTTP_FIELD_AUTHORIZATION, "nonce",
                         nonce))
    {
      cupsdLogMessage(CUPSD_LOG_ERROR,
	              "cupsdAuthorize: No nonce value for Digest "
		      "authentication!");
      return;
    }

    if (strcmp(con->http.hostname, nonce))
    {
      cupsdLogMessage(CUPSD_LOG_ERROR,
	              "cupsdAuthorize: Bad nonce value, expected \"%s\", "
		      "got \"%s\"!", con->http.hostname, nonce);
      return;
    }

   /*
    * Validate the username and password...
    */

    if (!get_md5_password(username, NULL, md5))
    {
      cupsdLogMessage(CUPSD_LOG_ERROR,
	              "cupsdAuthorize: Unknown MD5 username \"%s\"!",
	              username);
      return;
    }

    httpMD5Final(nonce, states[con->http.state], con->uri, md5);

    if (strcmp(md5, password))
    {
      cupsdLogMessage(CUPSD_LOG_ERROR,
	              "cupsdAuthorize: Authentication failed for \"%s\"!",
	              username);
      return;
    }

    cupsdLogMessage(CUPSD_LOG_DEBUG,
                    "cupsdAuthorize: Authorized as %s using Digest",
		    username);

    con->type = CUPSD_AUTH_DIGEST;
  }
#ifdef HAVE_GSSAPI
  else if (!strncmp(authorization, "Negotiate", 9)) 
  {
    int			len;		/* Length of authorization string */
    gss_cred_id_t	server_creds;	/* Server credentials */
    gss_ctx_id_t	context;	/* Authorization context */
    OM_uint32		major_status,	/* Major status code */
			minor_status;	/* Minor status code */
    gss_buffer_desc	input_token = GSS_C_EMPTY_BUFFER,
					/* Input token from string */
			output_token = GSS_C_EMPTY_BUFFER;
					/* Output token for username */
    gss_name_t		client_name;	/* Client name */
    unsigned int	ret_flags;	/* Credential flags */


#  ifdef __APPLE__
   /*
    * If the weak-linked GSSAPI/Kerberos library is not present, don't try
    * to use it...
    */

    if (gss_init_sec_context == NULL)
    {
      cupsdLogMessage(CUPSD_LOG_WARN,
                      "GSSAPI/Kerberos authentication failed because the "
		      "Kerberos framework is not present.");
      return;
    }
#  endif /* __APPLE__ */

    con->gss_output_token.length = 0;

   /*
    * Find the start of the Kerberos input token...
    */

    authorization += 9;
    while (isspace(*authorization & 255))
      authorization ++;

    if (!*authorization)
    {
      cupsdLogMessage(CUPSD_LOG_DEBUG2,
                      "cupsdAuthorize: No authentication data specified.");
      return;
    }

   /*
    * Get the server credentials...
    */

    if ((server_creds = get_gss_creds(GSSServiceName, con->servername)) == NULL)
      return;	

   /*
    * Decode the authorization string to get the input token...
    */

    len                = strlen(authorization);
    input_token.value  = malloc(len);
    input_token.value  = httpDecode64_2(input_token.value, &len,
		                        authorization);
    input_token.length = len;

   /*
    * Accept the input token to get the authorization info...
    */

    context      = GSS_C_NO_CONTEXT;
    client_name  = GSS_C_NO_NAME;
    major_status = gss_accept_sec_context(&minor_status,
					  &context,
					  server_creds, 
					  &input_token,
					  GSS_C_NO_CHANNEL_BINDINGS,
					  &client_name,
					  NULL,
					  &con->gss_output_token,
					  &ret_flags,
					  NULL,
					  &con->gss_delegated_cred);

    if (GSS_ERROR(major_status))
    {
      cupsdLogGSSMessage(CUPSD_LOG_DEBUG, major_status, minor_status,
                         "cupsdAuthorize: Error accepting GSSAPI security "
			 "context");

      if (context != GSS_C_NO_CONTEXT)
	gss_delete_sec_context(&minor_status, &context, GSS_C_NO_BUFFER);

      gss_release_cred(&minor_status, &server_creds);
      return;
    }

   /*
    * Release our credentials...
    */

    gss_release_cred(&minor_status, &server_creds);

   /*
    * Get the username associated with the client's credentials...
    */

    if (!con->gss_delegated_cred)
      cupsdLogMessage(CUPSD_LOG_DEBUG,
                      "cupsdAuthorize: No delegated credentials!");

    if (major_status == GSS_S_CONTINUE_NEEDED)
      cupsdLogGSSMessage(CUPSD_LOG_DEBUG, major_status, minor_status,
                         "cupsdAuthorize: Credentials not complete");
    else if (major_status == GSS_S_COMPLETE)
    {
      major_status = gss_display_name(&minor_status, client_name, 
				      &output_token, NULL);

      if (GSS_ERROR(major_status))
      {
	cupsdLogGSSMessage(CUPSD_LOG_DEBUG, major_status, minor_status,
                           "cupsdAuthorize: Error getting username");
	gss_release_name(&minor_status, &client_name);
	gss_delete_sec_context(&minor_status, &context, GSS_C_NO_BUFFER);
	return;
      }

      gss_release_name(&minor_status, &client_name);
      strlcpy(username, output_token.value, sizeof(username));

      cupsdLogMessage(CUPSD_LOG_DEBUG,
		      "cupsdAuthorize: Authorized as %s using Negotiate",
		      username);

      gss_release_buffer(&minor_status, &output_token);
      gss_delete_sec_context(&minor_status, &context, GSS_C_NO_BUFFER);

      con->gss_have_creds = 1;

      con->type = CUPSD_AUTH_NEGOTIATE;
    }
    else
      gss_release_name(&minor_status, &client_name);
  }
#endif /* HAVE_GSSAPI */
  else
  {
    char	scheme[256];		/* Auth scheme... */


    if (sscanf(authorization, "%255s", scheme) != 1)
      strcpy(scheme, "UNKNOWN");

    cupsdLogMessage(CUPSD_LOG_ERROR, "Bad authentication data \"%s ...\"",
                    scheme);
    return;
  }

 /*
  * If we get here, then we were able to validate the username and
  * password - copy the validated username and password to the client
  * data and return...
  */

  strlcpy(con->username, username, sizeof(con->username));
  strlcpy(con->password, password, sizeof(con->password));
}


/*
 * 'cupsdCheckAuth()' - Check authorization masks.
 */

int					/* O - 1 if mask matches, 0 otherwise */
cupsdCheckAuth(
    unsigned         ip[4],		/* I - Client address */
    char             *name,		/* I - Client hostname */
    int              name_len,		/* I - Length of hostname */
    int              num_masks,		/* I - Number of masks */
    cupsd_authmask_t *masks)		/* I - Masks */
{
  int		i;			/* Looping var */
  cupsd_netif_t	*iface;			/* Network interface */
  unsigned	netip4;			/* IPv4 network address */
#ifdef AF_INET6
  unsigned	netip6[4];		/* IPv6 network address */
#endif /* AF_INET6 */

  while (num_masks > 0)
  {
    switch (masks->type)
    {
      case CUPSD_AUTH_INTERFACE :
         /*
	  * Check for a match with a network interface...
	  */

          netip4 = htonl(ip[3]);

#ifdef AF_INET6
          netip6[0] = htonl(ip[0]);
          netip6[1] = htonl(ip[1]);
          netip6[2] = htonl(ip[2]);
          netip6[3] = htonl(ip[3]);
#endif /* AF_INET6 */

          if (!strcmp(masks->mask.name.name, "*"))
	  {
	   /*
	    * Check against all local interfaces...
	    */

            cupsdNetIFUpdate();

	    for (iface = (cupsd_netif_t *)cupsArrayFirst(NetIFList);
		 iface;
		 iface = (cupsd_netif_t *)cupsArrayNext(NetIFList))
	    {
	     /*
	      * Only check local interfaces...
	      */

	      if (!iface->is_local)
	        continue;

              if (iface->address.addr.sa_family == AF_INET)
	      {
	       /*
	        * Check IPv4 address...
		*/

        	if ((netip4 & iface->mask.ipv4.sin_addr.s_addr) ==
	            (iface->address.ipv4.sin_addr.s_addr &
		     iface->mask.ipv4.sin_addr.s_addr))
		  return (1);
              }
#ifdef AF_INET6
	      else
	      {
	       /*
	        * Check IPv6 address...
		*/

        	for (i = 0; i < 4; i ++)
		  if ((netip6[i] & iface->mask.ipv6.sin6_addr.s6_addr32[i]) !=
		      (iface->address.ipv6.sin6_addr.s6_addr32[i] &
		       iface->mask.ipv6.sin6_addr.s6_addr32[i]))
		    break;

		if (i == 4)
		  return (1);
              }
#endif /* AF_INET6 */
	    }
	  }
	  else
	  {
	   /*
	    * Check the named interface...
	    */

	    for (iface = (cupsd_netif_t *)cupsArrayFirst(NetIFList);
	         iface;
		 iface = (cupsd_netif_t *)cupsArrayNext(NetIFList))
	    {
              if (strcmp(masks->mask.name.name, iface->name))
                continue;

              if (iface->address.addr.sa_family == AF_INET)
	      {
	       /*
		* Check IPv4 address...
		*/

        	if ((netip4 & iface->mask.ipv4.sin_addr.s_addr) ==
	            (iface->address.ipv4.sin_addr.s_addr &
		     iface->mask.ipv4.sin_addr.s_addr))
		  return (1);
              }
#ifdef AF_INET6
	      else
	      {
	       /*
		* Check IPv6 address...
		*/

        	for (i = 0; i < 4; i ++)
		  if ((netip6[i] & iface->mask.ipv6.sin6_addr.s6_addr32[i]) !=
		      (iface->address.ipv6.sin6_addr.s6_addr32[i] &
		       iface->mask.ipv6.sin6_addr.s6_addr32[i]))
		    break;

		if (i == 4)
		  return (1);
              }
#endif /* AF_INET6 */
	    }
	  }
	  break;

      case CUPSD_AUTH_NAME :
         /*
	  * Check for exact name match...
	  */

          if (!strcasecmp(name, masks->mask.name.name))
	    return (1);

         /*
	  * Check for domain match...
	  */

	  if (name_len >= masks->mask.name.length &&
	      masks->mask.name.name[0] == '.' &&
	      !strcasecmp(name + name_len - masks->mask.name.length,
	                  masks->mask.name.name))
	    return (1);
          break;

      case CUPSD_AUTH_IP :
         /*
	  * Check for IP/network address match...
	  */

          for (i = 0; i < 4; i ++)
	    if ((ip[i] & masks->mask.ip.netmask[i]) !=
	            masks->mask.ip.address[i])
	      break;

	  if (i == 4)
	    return (1);
          break;
    }

    masks ++;
    num_masks --;
  }

  return (0);
}


/*
 * 'cupsdCheckGroup()' - Check for a user's group membership.
 */

int					/* O - 1 if user is a member, 0 otherwise */
cupsdCheckGroup(
    const char    *username,		/* I - User name */
    struct passwd *user,		/* I - System user info */
    const char    *groupname)		/* I - Group name */
{
  int			i;		/* Looping var */
  struct group		*group;		/* System group info */
  char			junk[33];	/* MD5 password (not used) */
#ifdef HAVE_MBR_UID_TO_UUID
  uuid_t		useruuid,	/* UUID for username */
			groupuuid;	/* UUID for groupname */
  int			is_member;	/* True if user is a member of group */
#endif /* HAVE_MBR_UID_TO_UUID */


  cupsdLogMessage(CUPSD_LOG_DEBUG2,
                  "cupsdCheckGroup(username=\"%s\", user=%p, groupname=\"%s\")",
                  username, user, groupname);

 /*
  * Validate input...
  */

  if (!username || !groupname)
    return (0);

 /*
  * Check to see if the user is a member of the named group...
  */

  group = getgrnam(groupname);
  endgrent();

  if (group != NULL)
  {
   /*
    * Group exists, check it...
    */

    for (i = 0; group->gr_mem[i]; i ++)
      if (!strcasecmp(username, group->gr_mem[i]))
	return (1);
  }

 /*
  * Group doesn't exist or user not in group list, check the group ID
  * against the user's group ID...
  */

  if (user && group && group->gr_gid == user->pw_gid)
    return (1);

#ifdef HAVE_MBR_UID_TO_UUID
 /*
  * Check group membership through MacOS X membership API...
  */

  if (user && group)
    if (!mbr_uid_to_uuid(user->pw_uid, useruuid))
      if (!mbr_gid_to_uuid(group->gr_gid, groupuuid))
	if (!mbr_check_membership(useruuid, groupuuid, &is_member))
	  if (is_member)
	    return (1);
#endif /* HAVE_MBR_UID_TO_UUID */

 /*
  * Username not found, group not found, or user is not part of the
  * system group...  Check for a user and group in the MD5 password
  * file...
  */

  if (get_md5_password(username, groupname, junk) != NULL)
    return (1);

 /*
  * If we get this far, then the user isn't part of the named group...
  */

  return (0);
}


/*
 * 'cupsdCopyLocation()' - Make a copy of a location...
 */

cupsd_location_t *			/* O - New location */
cupsdCopyLocation(
    cupsd_location_t **loc)		/* IO - Original location */
{
  int			i;		/* Looping var */
  cupsd_location_t	*temp;		/* New location */
  char			location[HTTP_MAX_URI];
					/* Location of resource */


 /*
  * Use a local copy of location because cupsdAddLocation may cause
  * this memory to be moved...
  */

  strlcpy(location, (*loc)->location, sizeof(location));

  if ((temp = cupsdAddLocation(location)) == NULL)
    return (NULL);

 /*
  * Copy the information from the original location to the new one.
  */

  temp->limit      = (*loc)->limit;
  temp->order_type = (*loc)->order_type;
  temp->type       = (*loc)->type;
  temp->level      = (*loc)->level;
  temp->satisfy    = (*loc)->satisfy;
  temp->encryption = (*loc)->encryption;

  if ((temp->num_names  = (*loc)->num_names) > 0)
  {
   /*
    * Copy the names array...
    */

    if ((temp->names = calloc(temp->num_names, sizeof(char *))) == NULL)
    {
      cupsdLogMessage(CUPSD_LOG_ERROR,
                      "cupsdCopyLocation: Unable to allocate memory for %d names: %s",
                      temp->num_names, strerror(errno));

      cupsdDeleteLocation(temp);
      return (NULL);
    }

    for (i = 0; i < temp->num_names; i ++)
      if ((temp->names[i] = strdup((*loc)->names[i])) == NULL)
      {
	cupsdLogMessage(CUPSD_LOG_ERROR,
	                "cupsdCopyLocation: Unable to copy name \"%s\": %s",
                        (*loc)->names[i], strerror(errno));

        cupsdDeleteLocation(temp);
	return (NULL);
      }
  }

  if ((temp->num_allow  = (*loc)->num_allow) > 0)
  {
   /*
    * Copy allow rules...
    */

    if ((temp->allow = calloc(temp->num_allow, sizeof(cupsd_authmask_t))) == NULL)
    {
      cupsdLogMessage(CUPSD_LOG_ERROR,
                      "cupsdCopyLocation: Unable to allocate memory for %d allow rules: %s",
                      temp->num_allow, strerror(errno));
      cupsdDeleteLocation(temp);
      return (NULL);
    }

    for (i = 0; i < temp->num_allow; i ++)
      switch (temp->allow[i].type = (*loc)->allow[i].type)
      {
        case CUPSD_AUTH_NAME :
	    temp->allow[i].mask.name.length = (*loc)->allow[i].mask.name.length;
	    temp->allow[i].mask.name.name   = strdup((*loc)->allow[i].mask.name.name);

            if (temp->allow[i].mask.name.name == NULL)
	    {
	      cupsdLogMessage(CUPSD_LOG_ERROR,
	                      "cupsdCopyLocation: Unable to copy allow name \"%s\": %s",
                	      (*loc)->allow[i].mask.name.name, strerror(errno));
              cupsdDeleteLocation(temp);
	      return (NULL);
	    }
	    break;
	case CUPSD_AUTH_IP :
	    memcpy(&(temp->allow[i].mask.ip), &((*loc)->allow[i].mask.ip),
	           sizeof(cupsd_ipmask_t));
	    break;
      }
  }

  if ((temp->num_deny  = (*loc)->num_deny) > 0)
  {
   /*
    * Copy deny rules...
    */

    if ((temp->deny = calloc(temp->num_deny, sizeof(cupsd_authmask_t))) == NULL)
    {
      cupsdLogMessage(CUPSD_LOG_ERROR,
                      "cupsdCopyLocation: Unable to allocate memory for %d deny rules: %s",
                      temp->num_deny, strerror(errno));
      cupsdDeleteLocation(temp);
      return (NULL);
    }

    for (i = 0; i < temp->num_deny; i ++)
      switch (temp->deny[i].type = (*loc)->deny[i].type)
      {
        case CUPSD_AUTH_NAME :
	    temp->deny[i].mask.name.length = (*loc)->deny[i].mask.name.length;
	    temp->deny[i].mask.name.name   = strdup((*loc)->deny[i].mask.name.name);

            if (temp->deny[i].mask.name.name == NULL)
	    {
	      cupsdLogMessage(CUPSD_LOG_ERROR,
	                      "cupsdCopyLocation: Unable to copy deny name \"%s\": %s",
                	      (*loc)->deny[i].mask.name.name, strerror(errno));
              cupsdDeleteLocation(temp);
	      return (NULL);
	    }
	    break;
	case CUPSD_AUTH_IP :
	    memcpy(&(temp->deny[i].mask.ip), &((*loc)->deny[i].mask.ip),
	           sizeof(cupsd_ipmask_t));
	    break;
      }
  }

  return (temp);
}


/*
 * 'cupsdDeleteAllLocations()' - Free all memory used for location authorization.
 */

void
cupsdDeleteAllLocations(void)
{
  cupsd_location_t	*loc;		/* Current location */


 /*
  * Free all of the allow/deny records first...
  */

  for (loc = (cupsd_location_t *)cupsArrayFirst(Locations);
       loc;
       loc = (cupsd_location_t *)cupsArrayNext(Locations))
    cupsdDeleteLocation(loc);

 /*
  * Then free the location array...
  */

  cupsArrayDelete(Locations);
  Locations = NULL;
}


/*
 * 'cupsdDeleteLocation()' - Free all memory used by a location.
 */

void
cupsdDeleteLocation(
    cupsd_location_t *loc)		/* I - Location to delete */
{
  int			i;		/* Looping var */
  cupsd_authmask_t	*mask;		/* Current mask */


  cupsArrayRemove(Locations, loc);

  for (i = loc->num_names - 1; i >= 0; i --)
    free(loc->names[i]);

  if (loc->num_names > 0)
    free(loc->names);

  for (i = loc->num_allow, mask = loc->allow; i > 0; i --, mask ++)
    if (mask->type == CUPSD_AUTH_NAME || mask->type == CUPSD_AUTH_INTERFACE)
      free(mask->mask.name.name);

  if (loc->num_allow > 0)
    free(loc->allow);

  for (i = loc->num_deny, mask = loc->deny; i > 0; i --, mask ++)
    if (mask->type == CUPSD_AUTH_NAME || mask->type == CUPSD_AUTH_INTERFACE)
      free(mask->mask.name.name);

  if (loc->num_deny > 0)
    free(loc->deny);

  free(loc->location);
  free(loc);
}


/*
 * 'cupsdDenyHost()' - Add a host name that is not allowed to access the
 *                     location.
 */

void
cupsdDenyHost(cupsd_location_t *loc,	/* I - Location to add to */
              char             *name)	/* I - Name of host or domain to add */
{
  cupsd_authmask_t	*temp;		/* New host/domain mask */
  char			ifname[32],	/* Interface name */
			*ifptr;		/* Pointer to end of name */


  cupsdLogMessage(CUPSD_LOG_DEBUG2, "cupsdDenyHost(loc=%p(%s), name=\"%s\")",
                  loc, loc->location ? loc->location : "nil", name);

  if ((temp = add_deny(loc)) == NULL)
    return;

  if (!strcasecmp(name, "@LOCAL"))
  {
   /*
    * Deny *interface*...
    */

    temp->type             = CUPSD_AUTH_INTERFACE;
    temp->mask.name.name   = strdup("*");
    temp->mask.name.length = 1;
  }
  else if (!strncasecmp(name, "@IF(", 4))
  {
   /*
    * Deny *interface*...
    */

    strlcpy(ifname, name + 4, sizeof(ifname));

    ifptr = ifname + strlen(ifname);

    if (ifptr[-1] == ')')
    {
      ifptr --;
      *ifptr = '\0';
    }

    temp->type             = CUPSD_AUTH_INTERFACE;
    temp->mask.name.name   = strdup(ifname);
    temp->mask.name.length = ifptr - ifname;
  }
  else
  {
   /*
    * Deny name...
    */

    temp->type             = CUPSD_AUTH_NAME;
    temp->mask.name.name   = strdup(name);
    temp->mask.name.length = strlen(name);
  }
}


/*
 * 'cupsdDenyIP()' - Add an IP address or network that is not allowed to
 *                   access the location.
 */

void
cupsdDenyIP(cupsd_location_t *loc,	/* I - Location to add to */
	    const unsigned   address[4],/* I - IP address to add */
	    const unsigned   netmask[4])/* I - Netmask of address */
{
  cupsd_authmask_t	*temp;		/* New host/domain mask */


  cupsdLogMessage(CUPSD_LOG_DEBUG,
                  "cupsdDenyIP(loc=%p(%s), address=%x:%x:%x:%x, netmask=%x:%x:%x:%x)",
		  loc, loc->location ? loc->location : "nil",
		  address[0], address[1], address[2], address[3],
		  netmask[0], netmask[1], netmask[2], netmask[3]);

  if ((temp = add_deny(loc)) == NULL)
    return;

  temp->type = CUPSD_AUTH_IP;
  memcpy(temp->mask.ip.address, address, sizeof(temp->mask.ip.address));
  memcpy(temp->mask.ip.netmask, netmask, sizeof(temp->mask.ip.netmask));
}


/*
 * 'cupsdFindBest()' - Find the location entry that best matches the resource.
 */

cupsd_location_t *			/* O - Location that matches */
cupsdFindBest(const char   *path,	/* I - Resource path */
              http_state_t state)	/* I - HTTP state/request */
{
  char			uri[HTTP_MAX_URI],
					/* URI in request... */
			*uriptr;	/* Pointer into URI */
  cupsd_location_t	*loc,		/* Current location */
			*best;		/* Best match for location so far */
  int			bestlen;	/* Length of best match */
  int			limit;		/* Limit field */
  static const int	limits[] =	/* Map http_status_t to CUPSD_AUTH_LIMIT_xyz */
		{
		  CUPSD_AUTH_LIMIT_ALL,
		  CUPSD_AUTH_LIMIT_OPTIONS,
		  CUPSD_AUTH_LIMIT_GET,
		  CUPSD_AUTH_LIMIT_GET,
		  CUPSD_AUTH_LIMIT_HEAD,
		  CUPSD_AUTH_LIMIT_POST,
		  CUPSD_AUTH_LIMIT_POST,
		  CUPSD_AUTH_LIMIT_POST,
		  CUPSD_AUTH_LIMIT_PUT,
		  CUPSD_AUTH_LIMIT_PUT,
		  CUPSD_AUTH_LIMIT_DELETE,
		  CUPSD_AUTH_LIMIT_TRACE,
		  CUPSD_AUTH_LIMIT_ALL,
		  CUPSD_AUTH_LIMIT_ALL
		};


 /*
  * First copy the connection URI to a local string so we have drop
  * any .ppd extension from the pathname in /printers or /classes
  * URIs...
  */

  strlcpy(uri, path, sizeof(uri));

  if (!strncmp(uri, "/printers/", 10) ||
      !strncmp(uri, "/classes/", 9))
  {
   /*
    * Check if the URI has .ppd on the end...
    */

    uriptr = uri + strlen(uri) - 4; /* len > 4 if we get here... */

    if (!strcmp(uriptr, ".ppd"))
      *uriptr = '\0';
  }

  // cupsdLogMessage(CUPSD_LOG_DEBUG2, "cupsdFindBest: uri = \"%s\"...", uri);

 /*
  * Loop through the list of locations to find a match...
  */

  limit   = limits[state];
  best    = NULL;
  bestlen = 0;

  for (loc = (cupsd_location_t *)cupsArrayFirst(Locations);
       loc;
       loc = (cupsd_location_t *)cupsArrayNext(Locations))
  {
    cupsdLogMessage(CUPSD_LOG_DEBUG2, "cupsdFindBest: Location %s Limit %x",
                    loc->location ? loc->location : "nil", loc->limit);

    if (!strncmp(uri, "/printers/", 10) || !strncmp(uri, "/classes/", 9))
    {
     /*
      * Use case-insensitive comparison for queue names...
      */

      if (loc->length > bestlen && loc->location &&
          !strncasecmp(uri, loc->location, loc->length) &&
	  loc->location[0] == '/' &&
	  (limit & loc->limit) != 0)
      {
	best    = loc;
	bestlen = loc->length;
      }
    }
    else
    {
     /*
      * Use case-sensitive comparison for other URIs...
      */

      if (loc->length > bestlen && loc->location &&
          !strncmp(uri, loc->location, loc->length) &&
	  loc->location[0] == '/' &&
	  (limit & loc->limit) != 0)
      {
	best    = loc;
	bestlen = loc->length;
      }
    }
  }

 /*
  * Return the match, if any...
  */

  cupsdLogMessage(CUPSD_LOG_DEBUG2, "cupsdFindBest: best = %s",
                  best ? best->location : "NONE");

  printf("[auth.c: cupsdFindBest] cupsdFindBest: url = %s, best = %s\n", uri, best ? best->location : "NONE");
  return (best);
}


/*
 * 'cupsdFindLocation()' - Find the named location.
 */

cupsd_location_t *			/* O - Location that matches */
cupsdFindLocation(const char *location)	/* I - Connection */
{
  cupsd_location_t	key;		/* Search key */


  key.location = (char *)location;

  return ((cupsd_location_t *)cupsArrayFind(Locations, &key));
}


/*
 * 'cupsdIsAuthorized()' - Check to see if the user is authorized...
 */

http_status_t				/* O - HTTP_OK if authorized or error code */
cupsdIsAuthorized(cupsd_client_t *con,	/* I - Connection */
                  const char     *owner)/* I - Owner of object */
{
  int			i, j,		/* Looping vars */
			auth,		/* Authorization status */
			type;		/* Type of authentication */
  unsigned		address[4];	/* Authorization address */
  cupsd_location_t	*best;		/* Best match for location so far */
  int			hostlen;	/* Length of hostname */
  char			username[256],	/* Username to authorize */
			ownername[256],	/* Owner name to authorize */
			*ptr;		/* Pointer into username */
  struct passwd		*pw;		/* User password data */
  static const char * const levels[] =	/* Auth levels */
		{
		  "ANON",
		  "USER",
		  "GROUP"
		};
  static const char * const types[] =	/* Auth types */
		{
		  "None",
		  "Basic",
		  "Digest",
		  "BasicDigest",
		  "Negotiate"
		};


  cupsdLogMessage(CUPSD_LOG_DEBUG2,
                  "cupsdIsAuthorized: con->uri=\"%s\", con->best=%p(%s)",
                  con->uri, con->best, con->best ? con->best->location ?
                			   con->best->location : "(null)" : "");
  if (owner)
    cupsdLogMessage(CUPSD_LOG_DEBUG2,
                    "cupsdIsAuthorized: owner=\"%s\"", owner);

 /*
  * If there is no "best" authentication rule for this request, then
  * access is allowed from the local system and denied from other
  * addresses...
  */

  if (!con->best)
  {
    if (!strcmp(con->http.hostname, "localhost") ||
        !strcmp(con->http.hostname, ServerName))
      return (HTTP_OK);
    else
      return (HTTP_FORBIDDEN);
  }

  best = con->best;

  if ((type = best->type) == CUPSD_AUTH_DEFAULT)
    type = DefaultAuthType;

  cupsdLogMessage(CUPSD_LOG_DEBUG2,
                  "cupsdIsAuthorized: level=CUPSD_AUTH_%s, type=%s, "
		  "satisfy=CUPSD_AUTH_SATISFY_%s, num_names=%d",
                  levels[best->level], types[type],
	          best->satisfy ? "ANY" : "ALL", best->num_names);

  if (best->limit == CUPSD_AUTH_LIMIT_IPP)
    cupsdLogMessage(CUPSD_LOG_DEBUG2, "cupsdIsAuthorized: op=%x(%s)",
                    best->op, ippOpString(best->op));

 /*
  * Check host/ip-based accesses...
  */

#ifdef AF_INET6
  if (con->http.hostaddr->addr.sa_family == AF_INET6)
  {
   /*
    * Copy IPv6 address...
    */

    address[0] = ntohl(con->http.hostaddr->ipv6.sin6_addr.s6_addr32[0]);
    address[1] = ntohl(con->http.hostaddr->ipv6.sin6_addr.s6_addr32[1]);
    address[2] = ntohl(con->http.hostaddr->ipv6.sin6_addr.s6_addr32[2]);
    address[3] = ntohl(con->http.hostaddr->ipv6.sin6_addr.s6_addr32[3]);
  }
  else
#endif /* AF_INET6 */
  if (con->http.hostaddr->addr.sa_family == AF_INET)
  {
   /*
    * Copy IPv4 address...
    */

    address[0] = 0;
    address[1] = 0;
    address[2] = 0;
    address[3] = ntohl(con->http.hostaddr->ipv4.sin_addr.s_addr);
  }
  else
    memset(address, 0, sizeof(address));

  hostlen = strlen(con->http.hostname);

  if (!strcasecmp(con->http.hostname, "localhost"))
  {
   /*
    * Access from localhost (127.0.0.1 or ::1) is always allowed...
    */

    auth = CUPSD_AUTH_ALLOW;
  }
  else
  {
   /*
    * Do authorization checks on the domain/address...
    */

    switch (best->order_type)
    {
      default :
	  auth = CUPSD_AUTH_DENY;	/* anti-compiler-warning-code */
	  break;

      case CUPSD_AUTH_ALLOW : /* Order Deny,Allow */
          auth = CUPSD_AUTH_ALLOW;

          if (cupsdCheckAuth(address, con->http.hostname, hostlen,
	          	best->num_deny, best->deny))
	    auth = CUPSD_AUTH_DENY;

          if (cupsdCheckAuth(address, con->http.hostname, hostlen,
	        	best->num_allow, best->allow))
	    auth = CUPSD_AUTH_ALLOW;
	  break;

      case CUPSD_AUTH_DENY : /* Order Allow,Deny */
          auth = CUPSD_AUTH_DENY;

          if (cupsdCheckAuth(address, con->http.hostname, hostlen,
	        	best->num_allow, best->allow))
	    auth = CUPSD_AUTH_ALLOW;

          if (cupsdCheckAuth(address, con->http.hostname, hostlen,
	        	best->num_deny, best->deny))
	    auth = CUPSD_AUTH_DENY;
	  break;
    }
  }

  cupsdLogMessage(CUPSD_LOG_DEBUG2, "cupsdIsAuthorized: auth=CUPSD_AUTH_%s...",
                  auth ? "DENY" : "ALLOW");

  if (auth == CUPSD_AUTH_DENY && best->satisfy == CUPSD_AUTH_SATISFY_ALL)
    return (HTTP_FORBIDDEN);

#ifdef HAVE_SSL
 /*
  * See if encryption is required...
  */

  if ((best->encryption >= HTTP_ENCRYPT_REQUIRED && !con->http.tls &&
      strcasecmp(con->http.hostname, "localhost") &&
      best->satisfy == CUPSD_AUTH_SATISFY_ALL) &&
      !(type == CUPSD_AUTH_NEGOTIATE || 
        (type == CUPSD_AUTH_NONE && DefaultAuthType == CUPSD_AUTH_NEGOTIATE)))
  {
    cupsdLogMessage(CUPSD_LOG_DEBUG,
                    "cupsdIsAuthorized: Need upgrade to TLS...");
    return (HTTP_UPGRADE_REQUIRED);
  }
#endif /* HAVE_SSL */

 /*
  * Now see what access level is required...
  */

  if (best->level == CUPSD_AUTH_ANON ||	/* Anonymous access - allow it */
      (type == CUPSD_AUTH_NONE && best->num_names == 0))
    return (HTTP_OK);

  if (!con->username[0] && type == CUPSD_AUTH_NONE &&
      best->limit == CUPSD_AUTH_LIMIT_IPP)
  {
   /*
    * Check for unauthenticated username...
    */

    ipp_attribute_t	*attr;		/* requesting-user-name attribute */


    attr = ippFindAttribute(con->request, "requesting-user-name", IPP_TAG_NAME);
    if (attr)
    {
      cupsdLogMessage(CUPSD_LOG_DEBUG,
                      "cupsdIsAuthorized: requesting-user-name=\"%s\"",
                      attr->values[0].string.text);
      strlcpy(username, attr->values[0].string.text, sizeof(username));
    }
    else if (best->satisfy == CUPSD_AUTH_SATISFY_ALL || auth == CUPSD_AUTH_DENY)
      return (HTTP_UNAUTHORIZED);	/* Non-anonymous needs user/pass */
    else
      return (HTTP_OK);			/* unless overridden with Satisfy */
  }
  else
  {
    cupsdLogMessage(CUPSD_LOG_DEBUG, "cupsdIsAuthorized: username=\"%s\"",
	            con->username);

#ifdef HAVE_AUTHORIZATION_H
    if (!con->username[0] && !con->authref)
#else
    if (!con->username[0])
#endif /* HAVE_AUTHORIZATION_H */
    {
      if (best->satisfy == CUPSD_AUTH_SATISFY_ALL || auth == CUPSD_AUTH_DENY)
	return (HTTP_UNAUTHORIZED);	/* Non-anonymous needs user/pass */
      else
	return (HTTP_OK);		/* unless overridden with Satisfy */
    }

    if (con->type != type && type != CUPSD_AUTH_NONE &&
        (con->type != CUPSD_AUTH_BASIC || type != CUPSD_AUTH_BASICDIGEST))
    {
      cupsdLogMessage(CUPSD_LOG_ERROR, "Authorized using %s, expected %s!",
                      types[con->type], types[type]);

      return (HTTP_UNAUTHORIZED);
    }

    strlcpy(username, con->username, sizeof(username));
  }

 /*
  * OK, got a username.  See if we need normal user access, or group
  * access... (root always matches)
  */

  if (!strcmp(username, "root"))
    return (HTTP_OK);

 /*
  * Strip any @domain or @KDC from the username and owner...
  */

  if ((ptr = strchr(username, '@')) != NULL)
    *ptr = '\0';

  if (owner)
  {
    strlcpy(ownername, owner, sizeof(ownername));

    if ((ptr = strchr(ownername, '@')) != NULL)
      *ptr = '\0';
  }
  else
    ownername[0] = '\0';

 /*
  * Get the user info...
  */

  if (username[0])
  {
    pw = getpwnam(username);
    endpwent();
  }
  else
    pw = NULL;

  if (best->level == CUPSD_AUTH_USER)
  {
   /*
    * If there are no names associated with this location, then
    * any valid user is OK...
    */

    if (best->num_names == 0)
      return (HTTP_OK);

   /*
    * Otherwise check the user list and return OK if this user is
    * allowed...
    */

    cupsdLogMessage(CUPSD_LOG_DEBUG2,
                    "cupsdIsAuthorized: Checking user membership...");

#ifdef HAVE_AUTHORIZATION_H
   /*
    * If an authorization reference was supplied it must match a right name...
    */

    if (con->authref)
    {
      for (i = 0; i < best->num_names; i ++)
      {
	if (!strncasecmp(best->names[i], "@AUTHKEY(", 9) && 
	    check_authref(con, best->names[i] + 9))
	  return (HTTP_OK);
	else if (!strcasecmp(best->names[i], "@SYSTEM") &&
	         SystemGroupAuthKey &&
		 check_authref(con, SystemGroupAuthKey))
	  return (HTTP_OK);
      }

      return (HTTP_UNAUTHORIZED);
    }
#endif /* HAVE_AUTHORIZATION_H */

    for (i = 0; i < best->num_names; i ++)
    {
      if (!strcasecmp(best->names[i], "@OWNER") && owner &&
          !strcasecmp(username, ownername))
	return (HTTP_OK);
      else if (!strcasecmp(best->names[i], "@SYSTEM"))
      {
        for (j = 0; j < NumSystemGroups; j ++)
	  if (cupsdCheckGroup(username, pw, SystemGroups[j]))
	    return (HTTP_OK);
      }
      else if (best->names[i][0] == '@')
      {
        if (cupsdCheckGroup(username, pw, best->names[i] + 1))
          return (HTTP_OK);
      }
      else if (!strcasecmp(username, best->names[i]))
        return (HTTP_OK);
    }

    return (HTTP_UNAUTHORIZED);
  }

 /*
  * Check to see if this user is in any of the named groups...
  */

  cupsdLogMessage(CUPSD_LOG_DEBUG2,
                  "cupsdIsAuthorized: Checking group membership...");

 /*
  * Check to see if this user is in any of the named groups...
  */

  for (i = 0; i < best->num_names; i ++)
  {
    cupsdLogMessage(CUPSD_LOG_DEBUG2,
                    "cupsdIsAuthorized: Checking group \"%s\" membership...",
                    best->names[i]);

    if (!strcasecmp(best->names[i], "@SYSTEM"))
    {
      for (j = 0; j < NumSystemGroups; j ++)
	if (cupsdCheckGroup(username, pw, SystemGroups[j]))
	  return (HTTP_OK);
    }
    else if (cupsdCheckGroup(username, pw, best->names[i]))
      return (HTTP_OK);
  }

 /*
  * The user isn't part of the specified group, so deny access...
  */

  cupsdLogMessage(CUPSD_LOG_DEBUG,
                  "cupsdIsAuthorized: User not in group(s)!");

  return (HTTP_UNAUTHORIZED);
}


/*
 * 'add_allow()' - Add an allow mask to the location.
 */

static cupsd_authmask_t *		/* O - New mask record */
add_allow(cupsd_location_t *loc)	/* I - Location to add to */
{
  cupsd_authmask_t	*temp;		/* New mask record */


 /*
  * Range-check...
  */

  if (loc == NULL)
    return (NULL);

 /*
  * Try to allocate memory for the record...
  */

  if (loc->num_allow == 0)
    temp = malloc(sizeof(cupsd_authmask_t));
  else
    temp = realloc(loc->allow, sizeof(cupsd_authmask_t) * (loc->num_allow + 1));

  if (temp == NULL)
    return (NULL);

  loc->allow = temp;
  temp       += loc->num_allow;
  loc->num_allow ++;

 /*
  * Clear the mask record and return...
  */

  memset(temp, 0, sizeof(cupsd_authmask_t));
  return (temp);
}


/*
 * 'add_deny()' - Add a deny mask to the location.
 */

static cupsd_authmask_t *		/* O - New mask record */
add_deny(cupsd_location_t *loc)		/* I - Location to add to */
{
  cupsd_authmask_t	*temp;		/* New mask record */


 /*
  * Range-check...
  */

  if (loc == NULL)
    return (NULL);

 /*
  * Try to allocate memory for the record...
  */

  if (loc->num_deny == 0)
    temp = malloc(sizeof(cupsd_authmask_t));
  else
    temp = realloc(loc->deny, sizeof(cupsd_authmask_t) * (loc->num_deny + 1));

  if (temp == NULL)
    return (NULL);

  loc->deny = temp;
  temp      += loc->num_deny;
  loc->num_deny ++;

 /*
  * Clear the mask record and return...
  */

  memset(temp, 0, sizeof(cupsd_authmask_t));
  return (temp);
}


#ifdef HAVE_AUTHORIZATION_H
/*
 * 'check_authref()' - Check if an authorization services reference has the
 *		       supplied right.
 */

static int				/* O - 1 if right is valid, 0 otherwise */
check_authref(cupsd_client_t *con,	/* I - Connection */
	      const char     *right)	/* I - Right name */
{
  OSStatus		status;		/* OS Status */
  AuthorizationItem	authright;	/* Authorization right */
  AuthorizationRights	authrights;	/* Authorization rights */
  AuthorizationFlags	authflags;	/* Authorization flags */


 /*
  * Check to see if the user is allowed to perform the task...
  */

  if (!con->authref)
    return (0);

  authright.name        = right;
  authright.valueLength = 0;
  authright.value       = NULL;
  authright.flags       = 0;

  authrights.count = 1;
  authrights.items = &authright;

  authflags = kAuthorizationFlagDefaults | 
	      kAuthorizationFlagExtendRights;

  if ((status = AuthorizationCopyRights(con->authref, &authrights, 
					kAuthorizationEmptyEnvironment, 
					authflags, NULL)) != 0)
  {
    cupsdLogMessage(CUPSD_LOG_ERROR,
		    "AuthorizationCopyRights(\"%s\") returned %d (%s)",
		    authright.name, (int)status, cssmErrorString(status));
    return (0);
  }

  cupsdLogMessage(CUPSD_LOG_DEBUG2,
                  "AuthorizationCopyRights(\"%s\") succeeded!",
		  authright.name);

  return (1);
}
#endif /* HAVE_AUTHORIZATION_H */


/*
 * 'compare_locations()' - Compare two locations.
 */

static int				/* O - Result of comparison */
compare_locations(cupsd_location_t *a,	/* I - First location */
                  cupsd_location_t *b)	/* I - Second location */
{
  return (strcmp(b->location, a->location));
}


#if !HAVE_LIBPAM && !defined(HAVE_USERSEC_H)
/*
 * 'cups_crypt()' - Encrypt the password using the DES or MD5 algorithms,
 *                  as needed.
 */

static char *				/* O - Encrypted password */
cups_crypt(const char *pw,		/* I - Password string */
           const char *salt)		/* I - Salt (key) string */
{
  if (!strncmp(salt, "$1$", 3))
  {
   /*
    * Use MD5 passwords without the benefit of PAM; this is for
    * Slackware Linux, and the algorithm was taken from the
    * old shadow-19990827/lib/md5crypt.c source code... :(
    */

    int			i;		/* Looping var */
    unsigned long	n;		/* Output number */
    int			pwlen;		/* Length of password string */
    const char		*salt_end;	/* End of "salt" data for MD5 */
    char		*ptr;		/* Pointer into result string */
    _cups_md5_state_t	state;		/* Primary MD5 state info */
    _cups_md5_state_t	state2;		/* Secondary MD5 state info */
    unsigned char	digest[16];	/* MD5 digest result */
    static char		result[120];	/* Final password string */


   /*
    * Get the salt data between dollar signs, e.g. $1$saltdata$md5.
    * Get a maximum of 8 characters of salt data after $1$...
    */

    for (salt_end = salt + 3; *salt_end && (salt_end - salt) < 11; salt_end ++)
      if (*salt_end == '$')
        break;

   /*
    * Compute the MD5 sum we need...
    */

    pwlen = strlen(pw);

    _cupsMD5Init(&state);
    _cupsMD5Append(&state, (unsigned char *)pw, pwlen);
    _cupsMD5Append(&state, (unsigned char *)salt, salt_end - salt);

    _cupsMD5Init(&state2);
    _cupsMD5Append(&state2, (unsigned char *)pw, pwlen);
    _cupsMD5Append(&state2, (unsigned char *)salt + 3, salt_end - salt - 3);
    _cupsMD5Append(&state2, (unsigned char *)pw, pwlen);
    _cupsMD5Finish(&state2, digest);

    for (i = pwlen; i > 0; i -= 16)
      _cupsMD5Append(&state, digest, i > 16 ? 16 : i);

    for (i = pwlen; i > 0; i >>= 1)
      _cupsMD5Append(&state, (unsigned char *)((i & 1) ? "" : pw), 1);

    _cupsMD5Finish(&state, digest);

    for (i = 0; i < 1000; i ++)
    {
      _cupsMD5Init(&state);

      if (i & 1)
        _cupsMD5Append(&state, (unsigned char *)pw, pwlen);
      else
        _cupsMD5Append(&state, digest, 16);

      if (i % 3)
        _cupsMD5Append(&state, (unsigned char *)salt + 3, salt_end - salt - 3);

      if (i % 7)
        _cupsMD5Append(&state, (unsigned char *)pw, pwlen);

      if (i & 1)
        _cupsMD5Append(&state, digest, 16);
      else
        _cupsMD5Append(&state, (unsigned char *)pw, pwlen);

      _cupsMD5Finish(&state, digest);
    }

   /*
    * Copy the final sum to the result string and return...
    */

    memcpy(result, salt, salt_end - salt);
    ptr = result + (salt_end - salt);
    *ptr++ = '$';

    for (i = 0; i < 5; i ++, ptr += 4)
    {
      n = (((digest[i] << 8) | digest[i + 6]) << 8);

      if (i < 4)
        n |= digest[i + 12];
      else
        n |= digest[5];

      to64(ptr, n, 4);
    }

    to64(ptr, digest[11], 2);
    ptr += 2;
    *ptr = '\0';

    return (result);
  }
  else
  {
   /*
    * Use the standard crypt() function...
    */

    return (crypt(pw, salt));
  }
}
#endif /* !HAVE_LIBPAM && !HAVE_USERSEC_H */


#ifdef HAVE_GSSAPI
/*
 * 'get_gss_creds()' - Obtain GSS credentials.
 */

static gss_cred_id_t			/* O - Server credentials */
get_gss_creds(
    const char *service_name, 		/* I - Service name */
    const char *con_server_name)	/* I - Hostname of server */
{
  OM_uint32	major_status,		/* Major status code */
		minor_status;		/* Minor status code */
  gss_name_t	server_name;		/* Server name */
  gss_cred_id_t	server_creds;		/* Server credentials */
  gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
					/* Service name token */
  char		buf[1024];		/* Service name buffer */


  snprintf(buf, sizeof(buf), "%s@%s", service_name, con_server_name);

  token.value  = buf;
  token.length = strlen(buf);
  server_name  = GSS_C_NO_NAME;
  major_status = gss_import_name(&minor_status, &token,
	 			 GSS_C_NT_HOSTBASED_SERVICE,
				 &server_name);

  memset(&token, 0, sizeof(token));

  if (GSS_ERROR(major_status))
  {
    cupsdLogGSSMessage(CUPSD_LOG_WARN, major_status, minor_status, 
		       "gss_import_name() failed");
    return (NULL);
  }

  major_status = gss_display_name(&minor_status, server_name, &token, NULL);

  if (GSS_ERROR(major_status))
  {
    cupsdLogGSSMessage(CUPSD_LOG_WARN, major_status, minor_status,
                       "gss_display_name() failed"); 
    return (NULL);
  }

  cupsdLogMessage(CUPSD_LOG_DEBUG,
                  "get_gss_creds: Attempting to acquire credentials for %s...", 
                  (char *)token.value);

  server_creds = GSS_C_NO_CREDENTIAL;
  major_status = gss_acquire_cred(&minor_status, server_name, GSS_C_INDEFINITE,
			          GSS_C_NO_OID_SET, GSS_C_ACCEPT,
				  &server_creds, NULL, NULL);
  if (GSS_ERROR(major_status))
  {
    cupsdLogGSSMessage(CUPSD_LOG_WARN, major_status, minor_status,
                       "gss_acquire_cred() failed"); 
    gss_release_name(&minor_status, &server_name);
    gss_release_buffer(&minor_status, &token);
    return (NULL);
  }

  cupsdLogMessage(CUPSD_LOG_DEBUG,
                  "get_gss_creds: Credentials acquired successfully for %s.", 
                  (char *)token.value);

  gss_release_name(&minor_status, &server_name);
  gss_release_buffer(&minor_status, &token);

  return (server_creds);
}
#endif /* HAVE_GSSAPI */


/*
 * 'get_md5_password()' - Get an MD5 password.
 */

static char *				/* O - MD5 password string */
get_md5_password(const char *username,	/* I - Username */
                 const char *group,	/* I - Group */
                 char       passwd[33])	/* O - MD5 password string */
{
  cups_file_t	*fp;			/* passwd.md5 file */
  char		filename[1024],		/* passwd.md5 filename */
		line[256],		/* Line from file */
		tempuser[33],		/* User from file */
		tempgroup[33];		/* Group from file */


  cupsdLogMessage(CUPSD_LOG_DEBUG2,
                  "get_md5_password(username=\"%s\", group=\"%s\", passwd=%p)",
                  username, group ? group : "(null)", passwd);

  snprintf(filename, sizeof(filename), "%s/passwd.md5", ServerRoot);
  if ((fp = cupsFileOpen(filename, "r")) == NULL)
  {
    if (errno != ENOENT)
      cupsdLogMessage(CUPSD_LOG_ERROR, "Unable to open %s - %s", filename,
                      strerror(errno));

    return (NULL);
  }

  while (cupsFileGets(fp, line, sizeof(line)) != NULL)
  {
    if (sscanf(line, "%32[^:]:%32[^:]:%32s", tempuser, tempgroup, passwd) != 3)
    {
      cupsdLogMessage(CUPSD_LOG_ERROR, "Bad MD5 password line: %s", line);
      continue;
    }

    if (!strcmp(username, tempuser) &&
        (group == NULL || !strcmp(group, tempgroup)))
    {
     /*
      * Found the password entry!
      */

      cupsdLogMessage(CUPSD_LOG_DEBUG2, "Found MD5 user %s, group %s...",
                      username, tempgroup);

      cupsFileClose(fp);
      return (passwd);
    }
  }

 /*
  * Didn't find a password entry - return NULL!
  */

  cupsFileClose(fp);
  return (NULL);
}


#if HAVE_LIBPAM
/*
 * 'pam_func()' - PAM conversation function.
 */

static int				/* O - Success or failure */
pam_func(
    int                      num_msg,	/* I - Number of messages */
    const struct pam_message **msg,	/* I - Messages */
    struct pam_response      **resp,	/* O - Responses */
    void                     *appdata_ptr)
					/* I - Pointer to connection */
{
  int			i;		/* Looping var */
  struct pam_response	*replies;	/* Replies */
  cupsd_authdata_t	*data;		/* Pointer to auth data */


 /*
  * Allocate memory for the responses...
  */

  if ((replies = malloc(sizeof(struct pam_response) * num_msg)) == NULL)
    return (PAM_CONV_ERR);

 /*
  * Answer all of the messages...
  */

  DEBUG_printf(("pam_func: appdata_ptr = %p\n", appdata_ptr));

#ifdef __hpux
 /*
  * Apparently some versions of HP-UX 11 have a broken pam_unix security
  * module.  This is a workaround...
  */

  data = auth_data;
  (void)appdata_ptr;
#else
  data = (cupsd_authdata_t *)appdata_ptr;
#endif /* __hpux */

  for (i = 0; i < num_msg; i ++)
  {
    DEBUG_printf(("pam_func: Message = \"%s\"\n", msg[i]->msg));

    switch (msg[i]->msg_style)
    {
      case PAM_PROMPT_ECHO_ON:
          DEBUG_printf(("pam_func: PAM_PROMPT_ECHO_ON, returning \"%s\"...\n",
	                data->username));
          replies[i].resp_retcode = PAM_SUCCESS;
          replies[i].resp         = strdup(data->username);
          break;

      case PAM_PROMPT_ECHO_OFF:
          DEBUG_printf(("pam_func: PAM_PROMPT_ECHO_OFF, returning \"%s\"...\n",
	                data->password));
          replies[i].resp_retcode = PAM_SUCCESS;
          replies[i].resp         = strdup(data->password);
          break;

      case PAM_TEXT_INFO:
          DEBUG_puts("pam_func: PAM_TEXT_INFO...");
          replies[i].resp_retcode = PAM_SUCCESS;
          replies[i].resp         = NULL;
          break;

      case PAM_ERROR_MSG:
          DEBUG_puts("pam_func: PAM_ERROR_MSG...");
          replies[i].resp_retcode = PAM_SUCCESS;
          replies[i].resp         = NULL;
          break;

      default:
          DEBUG_printf(("pam_func: Unknown PAM message %d...\n",
	                msg[i]->msg_style));
          free(replies);
          return (PAM_CONV_ERR);
    }
  }

 /*
  * Return the responses back to PAM...
  */

  *resp = replies;

  return (PAM_SUCCESS);
}
#elif !defined(HAVE_USERSEC_H)


/*
 * 'to64()' - Base64-encode an integer value...
 */

static void
to64(char          *s,			/* O - Output string */
     unsigned long v,			/* I - Value to encode */
     int           n)			/* I - Number of digits */
{
  const char	*itoa64 = "./0123456789"
                          "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                          "abcdefghijklmnopqrstuvwxyz";


  for (; n > 0; n --, v >>= 6)
    *s++ = itoa64[v & 0x3f];
}
#endif /* HAVE_LIBPAM */


/*
 * End of "$Id: auth.c 7485 2008-04-21 23:13:22Z mike $".
 */
