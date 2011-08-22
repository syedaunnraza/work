#ifndef SYSCALL_PRINTERS_H_RAZA
#define SYSCALL_PRINTERS_H_RAZA

#include "pin.H"
#include "instlib.H"
#include "portability.H"
#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/socket.h>
#include <map>
#include <algorithm>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/timex.h>

#include "syscall_utils.h"
#include "syscalls_printer.h"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <utime.h>
#include <signal.h>
#include <sys/utsname.h>
#include <ustat.h>
#include <sys/resource.h>
#include <asm/ldt.h>
#include <linux/futex.h>
#include <sys/epoll.h>
#include <sys/un.h>
#include <poll.h>

using namespace INSTLIB;

LOCALVAR BOOL pr_outstanding_syscall = false;
LOCALVAR ADDRINT pr_last_syscall_number = 0;

/* ===================================================================== */
LOCALFUN string parse_domain(int domain)
{
  string domain_string = "";
  switch ( domain ) 
    {
    case PF_UNIX:
      {
	domain_string = "PF_UNIX";
      }
      break;
    case PF_INET:
      {
	domain_string = "PF_INET";
      }
      break;
    case PF_INET6:
      {
	domain_string = "PF_INET6";
      }
      break;
    case PF_IPX:
      {
	domain_string = "PF_IPX";
      }
      break;
    case PF_NETLINK:
      {
	domain_string = "PF_NETLINK";
      }
      break;
    case PF_X25:
      {
	domain_string = "PF_X25";
      }
      break;
    case PF_AX25:
      {
	domain_string = "PF_AX25";
      }
      break;
    case PF_ATMPVC:
      {
	domain_string = "PF_ATMPVC";
      }
      break;
    case PF_APPLETALK:
      {
	domain_string = "PF_APPLETALK";
      }
      break;
    case PF_PACKET:
      {
	domain_string = "PF_PACKET";
      }
      break;
    default:
      {
	domain_string = "<unknown>";
      }
      break;
    }
  return domain_string;
}

/* ===================================================================== */

LOCALFUN string parse_type(int type)
{
  string type_string = "";
  switch ( type )
    {
    case SOCK_STREAM:
      {	
	type_string = "SOCK_STREAM";
      }
      break;
    case SOCK_DGRAM:
      {	  
	type_string = "SOCK_DGRAM";
      }
      break;
    case SOCK_SEQPACKET:
      {
	type_string = "SOCK_SEQPACKET";
      }	  
      break;
    case SOCK_RAW:
      {
	type_string = "SOCK_RAW";
      }
      break;
    case SOCK_RDM:
      {	  
	type_string = "SOCK_RDM";
      }
      break;
    case SOCK_PACKET:
      {	  
	type_string = "SOCK_PACKET";
      }
      break;
    default:
      {
	type_string = "<unknown>";
      }
      break;
    }
  return type_string;
}

/* ===================================================================== */

GLOBALFUN VOID print_sockaddr(struct sockaddr * my_addr, std::ofstream & pr_out)
{
  if (my_addr != (struct sockaddr*)NULL)
    {
      int handled = 0;
      string family = "";
      sa_family_t sa_family = my_addr->sa_family;
      switch ( sa_family )
	{
	case AF_INET:
	  {
	    struct sockaddr_in *in = (struct sockaddr_in*) my_addr;
	    char *addr = inet_ntoa (in->sin_addr);

	    pr_out << "\t" << "family = AF_INET" << endl;
	    pr_out << "\t" << "addr = " << string(addr) << endl;
	    pr_out << "\t" << "port = " << ntohs(in->sin_port) << endl;
	    handled = 1;
	  }
	  break;
	case AF_INET6:
	  {
	    char dest[512];
	    
	    struct sockaddr_in6 *in = (struct sockaddr_in6*) my_addr;
	    const char* i6_rep = inet_ntop(AF_INET6, &in->sin6_addr, dest, 512);
	    
	    pr_out << "\t" << "family = AF_INET6" << endl;
	    pr_out << "\t" << "addr = " << string(i6_rep) << endl;
	    pr_out << "\t" << "port = " << ntohs(in->sin6_port) << endl;
	    pr_out << "\t" << "flow info = " << ntohl(in->sin6_flowinfo) << endl;
	    pr_out << "\t" << "scope = " << ntohl(in->sin6_scope_id) << endl;
	    handled = 1;
	  }
	  break;
	case AF_UNIX:
	  {
	    struct sockaddr_un *in = (struct sockaddr_un*)my_addr;
	    pr_out << "\t" << "family = AF_UNIX" << endl;
	    pr_out << "\t" << "addr = " << string(in->sun_path) << endl;
	    handled = 1;	
	  }
	  break;
	case AF_NETLINK:
	  {
	    struct sockaddr_nl *in = (struct sockaddr_nl*)my_addr;
	    pr_out << "\t" << "family = AF_NETLINK" << endl;
	    pr_out << "\t" << "pid = " << in->nl_pid << endl;
	    pr_out << "\t" << "groups = " << in->nl_groups << endl;
	    handled = 1;
	  }
	  break;

	case AF_PACKET:
	  family = "AF_PACKET";
	  break;	

	case AF_APPLETALK:
	  family = "AF_APPLETALK";
	  break;

	case AF_X25:
	  family = "AF_X25";
	  break;

	default:
	  family = "?";
	  break;
	}

      if (!handled)
	{
	  pr_out << "name[family]=" << family << ", name[family#] = " << sa_family << ", name[data]=<";
	  for (int i = 0; i < 14; i++)
	    {
	      pr_out << (int)my_addr->sa_data[i] << " ";
	    }
	  pr_out << endl;
	}

    }
}

/* ===================================================================== */

GLOBALFUN VOID HandleSocketCall(THREADID threadIndex, CONTEXT *ctxt, 
				SYSCALL_STANDARD std, VOID *v, 
				std::ofstream & pr_out)
{

  int call_number = PIN_GetSyscallArgument(ctxt, std, 0);
  ADDRINT args = PIN_GetSyscallArgument(ctxt, std, 1);

  pr_out << socketcalls[call_number] << "() called." << endl;

  switch( call_number )
    {
    case 1:
      // socket()      
      {
	int domain = *(int*)args;
	int type = *(int*)(args + sizeof(int));
	int protocol = *(int*)(args + 2*sizeof(int));
	
	string domain_string = parse_domain(domain);
	string type_string = parse_type(type);

	pr_out << "\t" << "domain = " << domain << " ( " << domain_string << " ) " << endl;
	pr_out << "\t" << "type = " << type << " ( " << type_string << " ) " << endl;
	pr_out << "\t" << "protocol = " << protocol << endl;
	pr_out << "\t" << "fd = " << PIN_GetSyscallReturn(ctxt, std) << endl;
      }
      break;
    case 2:
      // bind()
    case 3:
      // connect()
    case 5:
      // accept()
    case 6:
      // getsockname()
    case 7:
      // getpeername()
      {      
	int sockfd = *(int*)args;
	struct sockaddr* my_addr = *(struct sockaddr **)(args + sizeof(int));
	socklen_t addrlen = *(socklen_t*)(args  + sizeof(int) + sizeof(struct sockaddr*));
	
	pr_out << "\t" << "sockfd = " << sockfd << endl;
	pr_out << "\t" << "my_addr = " << my_addr << endl;
	pr_out << "\t" << "addrlen = " << addrlen << endl;
	pr_out << "\t" << "ret_val = " << PIN_GetSyscallReturn(ctxt, std) << endl;
	
	print_sockaddr(my_addr, pr_out);
      }
      break;
    case 4:
      // listen()
      {
	int sockfd = *(int*)args;
	int backlog = *(int*)(args + sizeof(int));
	
	pr_out << "\t" << "sockfd = " << sockfd << endl;
	pr_out << "\t" << "backlog = " << backlog << endl;
	pr_out << "\t" << "ret_val = " << PIN_GetSyscallReturn(ctxt, std) << endl;
      }      
      break;
    case 8:
      // socketpair()
      {
	int d = *(int*)args;
	int type = *(int*)(args + sizeof(int));
	int* sv = *(int**)(args + 2*sizeof(int));
	
	pr_out << "\t" << "domain = " << d << endl;
	pr_out << "\t" << "type = " << type << endl;
	pr_out << "\t" << "sv = " << sv << endl;
	pr_out << "\t" << "ret_val = " << PIN_GetSyscallReturn(ctxt, std) << endl;
	if (sv != (int*)NULL)
	  {
	    pr_out << "\t" << "sv[0] = " << sv[0] << endl;
	    pr_out << "\t" << "sv[1] = " << sv[1] << endl;
	  }
      }
      break;
    case 9:
      // send()
    case 10:
      // recv()
      {
	int s = *(int*)args;
	void* buf = *(void**)(args + sizeof(int));
	size_t len = *(int*)(args + sizeof(int) + sizeof(void*));
	int flags = *(int*)(args + sizeof(int) + sizeof(void*) + sizeof(size_t));

	pr_out << "\t" << "s = " << s << endl;
	pr_out << "\t" << "buf = " << buf << endl;
	pr_out << "\t" << "len = " << len << endl;
	pr_out << "\t" << "flags = " << flags << endl;
	pr_out << "\t" << "ret_val = " << PIN_GetSyscallReturn(ctxt, std) << endl;
	
	if (buf != (void*) NULL)
	  {
	    size_t byte_number = 0;
	    while (byte_number < len)
	      {
		pr_out << "\t" << "buf[ " << byte_number << "] = " << ((uint8_t*)buf)[byte_number] << endl;
		byte_number++;
	      }
	  }
      }
      break;    
    case 11:
      // sendto()
    case 12:
      // recvfrom()
      {
	int s = *(int*)args;
	void* buf = *(void**)(args + sizeof(int));
	size_t len = *(int*)(args + sizeof(int) + sizeof(void*));
	int flags = *(int*)(args + sizeof(int) + sizeof(void*) + sizeof(size_t));
	struct sockaddr *to = *(struct sockaddr**)(args + 2*sizeof(int) + sizeof(void*) + sizeof(size_t));
	socklen_t tolen = *(socklen_t*)(args + 2*sizeof(int) + sizeof(void*) + sizeof(size_t) + sizeof(struct sockaddr*));

	pr_out << "\t" << "s = " << s << endl;
	pr_out << "\t" << "buf = " << buf << endl;
	pr_out << "\t" << "len = " << len << endl;
	pr_out << "\t" << "flags = " << flags << endl;
	pr_out << "\t" << "to = " << to << endl;
	pr_out << "\t" << "tolen = " << tolen << endl;
	pr_out << "\t" << "ret_val = " << PIN_GetSyscallReturn(ctxt, std) << endl;
	
	if (buf != (void*) NULL)
	  {
	    size_t byte_number = 0;
	    while (byte_number < len)
	      {
		pr_out << "\t" << "buf[ " << byte_number << "] = " << ((uint8_t*)buf)[byte_number] << endl;
		byte_number++;
	      }
	  }

	print_sockaddr(to, pr_out);	
      }
      break;
    case 13:
      // shutdown()
      {	
	int s = *(int*)args;
	int how = *(int*)(args + sizeof(int));

	pr_out << "\t" << "s = " << s << endl;
	pr_out << "\t" << "how = " << how << endl;
	pr_out << "\t" << "ret_val = " << PIN_GetSyscallReturn(ctxt, std) << endl;
      }
      break;
    case 14:
      // setsockopt()
      {
	int s = *(int*)args;
	int level = *(int*)(args + sizeof(int));
	int optname = *(int*)(args + 2*sizeof(int));
	void* optval = *(void**)(args + 3*sizeof(int));
	socklen_t optlen = *(socklen_t*)(args + 3*sizeof(int) + sizeof(void*));
	

	pr_out << "\t" << "s = " << s << endl;
	pr_out << "\t" << "level = " << level << endl;
	pr_out << "\t" << "optname = " << optname << endl;
	pr_out << "\t" << "optval = " << optval << endl;
	pr_out << "\t" << "optlen = " << optlen << endl;
	
	if (optval != (void*) NULL)
	  {
	    size_t byte_number = 0;
	    while (byte_number < optlen)
	      {
		pr_out << "\t" << "optval[ " << byte_number << "] = " << ((uint8_t*)optval)[byte_number] << endl;
		byte_number++;
	      }
	  }
	
	pr_out << "\t" << "ret_val = " << PIN_GetSyscallReturn(ctxt, std) << endl;
      }
      break;
    case 15:
      // getsockopt()
      {
	int s = *(int*)args;
	int level = *(int*)(args + sizeof(int));
	int optname = *(int*)(args + 2*sizeof(int));
	void* optval = *(void**)(args + 3*sizeof(int));
	socklen_t* optlen = *(socklen_t**)(args + 3*sizeof(int) + sizeof(void*));
	

	pr_out << "\t" << "s = " << s << endl;
	pr_out << "\t" << "level = " << level << endl;
	pr_out << "\t" << "optname = " << optname << endl;
	pr_out << "\t" << "optval = " << optval << endl;
	pr_out << "\t" << "optlen = " << optlen << endl;
	
	if (optval != (void*) NULL && optlen != (socklen_t*)NULL)
	  {
	    size_t byte_number = 0;
	    while (byte_number < (*optlen))
	      {
		pr_out << "\t" << "optval[ " << byte_number << "] = " << ((uint8_t*)optval)[byte_number] << endl;
		byte_number++;
	      }
	  }
	
	pr_out << "\t" << "ret_val = " << PIN_GetSyscallReturn(ctxt, std) << endl;
      }      
      break;
    case 16:
      // sendmsg()
    case 17:
      // recvmsg
      {
	int s = *(int*)args;
	struct msghdr *h = *(struct msghdr **)(args + sizeof(int)); 
	int flags = *(int *) (args + sizeof(int) + sizeof(struct msghdr*));
	ssize_t ret_val = PIN_GetSyscallReturn(ctxt, std);

	pr_out << "\t" << "s = " << s << endl;
	pr_out << "\t" << "h = " << h << endl;
	pr_out << "\t" << "flags = " << flags << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;

	if (h != (struct msghdr*)NULL)
	  {
	    if (h->msg_name != (void*)NULL && h->msg_namelen > 0)
	      {
		print_sockaddr((struct sockaddr *)h->msg_name, pr_out);
	      }
	    
	    struct iovec* msg_iov = h->msg_iov;
	    size_t iov_len = h->msg_iovlen;
	    pr_out << "\t" << "h->msg_iov = " << msg_iov << endl;
	    pr_out << "\t" << "h->msg_iovlen = " << iov_len << endl;

	    size_t i;
	    for (i = 0; i < iov_len; i++)
	      {
		struct iovec current = msg_iov[i];
		pr_out << "\t" << "msg_iov[" << i << "] = {base=" << current.iov_base << ",len=" << current.iov_len << "}" << endl; 

		uint8_t *buf = (uint8_t*)(current.iov_base);
		size_t buf_len = current.iov_len;
		
		if (buf != ((uint8_t*)NULL) && buf_len > 0)
		  {
		    size_t j;
		    for (j = 0; j < buf_len; j++)
		      {
			pr_out << "\t\t" << "buf[" << j << "] = " << buf[j] << endl;
		      }
		  }
	      }

	    pr_out << "\t" << "h->msg_control = " << h->msg_control << endl;
	    pr_out << "\t" << "h->msg_controllen = " << h->msg_controllen << endl;
	    pr_out << "\t" << "h->msg_flags = " << h->msg_flags << endl;

	    if (h->msg_control != (void*)NULL && h->msg_controllen > 0)
	      {
		struct cmsghdr *ch = (struct cmsghdr*) h->msg_control;
		pr_out << "\t" << "ch->cmsg_len = " << ch->cmsg_len << endl;
		pr_out << "\t" << "ch->cmsg_level = " << ch->cmsg_level << endl;
		pr_out << "\t" << "ch->cmsg_type = " << ch->cmsg_type << endl;

		pr_out << "\t" << "ch->cmsg_level string = " << parse_domain(ch->cmsg_level) << endl;
		pr_out << "\t" << "ch->cmsg_type = " << parse_type(ch->cmsg_type) << endl;
	      }

	  }
      }
      break;
    default:
      break;
    }

  pr_out << socketcalls[call_number] << "() returning." << endl;
}

/* ===================================================================== */

GLOBALFUN VOID HandleSysEnd(THREADID threadIndex, CONTEXT *ctxt, 
			    SYSCALL_STANDARD std, VOID *v,
			    std::ofstream  & pr_out)
{
  if (!pr_outstanding_syscall)
    {
      pr_out << "[WARNING]: SysEnd() Interruptable " 
	   << "System Call Situation" << endl;
    }
 
  string name = syscalls[pr_last_syscall_number];
  pr_out << name << "() called." << endl;

  //      ADDRINT return_value = PIN_GetSyscallReturn(ctxt, std);
  switch( pr_last_syscall_number )
    {
    case 0:
      // restart() 
      break;
    case 1:
     {
	// exit()
	ADDRINT status = PIN_GetSyscallArgument(ctxt, std, 0);
	pr_out << "\t" << "exit status = " << status << endl;
      }
      break;
    case 2:
      // fork()
      {
	ADDRINT pid = PIN_GetSyscallReturn(ctxt, std);
	pr_out << "\t" << "pid = " << pid << endl;
      }
      break;
    case 3:
      // read()
      {      
	ADDRINT fd = PIN_GetSyscallArgument(ctxt, std, 0);
	void *buf = (void*) PIN_GetSyscallArgument(ctxt, std, 1);
	size_t count = (size_t) PIN_GetSyscallArgument(ctxt, std, 2);
	ssize_t bytes_read = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "fd = " << fd << endl;
	pr_out << "\t" << "pBuf = " << hex << buf << dec << endl;
	pr_out << "\t" << "count = " <<  count << endl;
	pr_out << "\t" << "bytes read = " << bytes_read << endl;
	
	if (bytes_read > 0)
	  {
	    pr_out << "\t" << "buf contents:" << endl;
	    ssize_t byte_num = 0;
	    while (byte_num < bytes_read)
	      {
		pr_out << "\t" << "buf[" << byte_num << "] = " << ((uint8_t*)buf)[byte_num] << endl;
		byte_num++;
	      }
	  }
      }
      break;
    case 4:
      // write()
      {
	ADDRINT fd = PIN_GetSyscallArgument(ctxt, std, 0);
	void *buf = (void*) PIN_GetSyscallArgument(ctxt, std, 1);
	size_t count = (size_t) PIN_GetSyscallArgument(ctxt, std, 2);
	ssize_t bytes_written = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "fd = " << fd << endl;
	pr_out << "\t" << "pBuf = " << hex << buf << dec << endl;
	pr_out << "\t" << "count = " <<  count << endl;
	pr_out << "\t" << "bytes written = " << bytes_written << endl;
	
	if (bytes_written > 0)
	  {
	    pr_out << "\t" << "buf contents:" << endl;
	    ssize_t byte_num = 0;
	    while (byte_num < bytes_written)
	      {
		pr_out << "\t" << "buf[" << byte_num << "] = " << ((uint8_t*)buf)[byte_num] << endl;
		byte_num++;
	      }
	  }
      }
      break;
    case 5:
      // open()
      {
	char* pathname = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	int flags = PIN_GetSyscallArgument(ctxt, std, 1);
	int mode = PIN_GetSyscallArgument(ctxt, std, 2);
	int fd = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "path = " << string(pathname) << endl;
	pr_out << "\t" << "flags = " << flags << endl;
	pr_out << "\t" << "mode = " <<  mode << endl;
	pr_out << "\t" << "fd = " << fd << endl;
      }
      break;
    case 6:
      // close ()
      {
	int fd = PIN_GetSyscallArgument(ctxt, std, 0);
	int status = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "fd = " << fd << endl;
	pr_out << "\t" << "status = " << status << endl;
      }
      break;
    case 7:
      // waitpid()
      {
	pid_t pid = (pid_t)PIN_GetSyscallArgument(ctxt, std, 0);
	int* status = (int*)PIN_GetSyscallArgument(ctxt, std, 1);
	int options = PIN_GetSyscallArgument(ctxt, std, 2);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "pid = " << pid << endl;
	pr_out << "\t" << "pStatus = " << status << endl;
	pr_out << "\t" << "options = " << options << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
	
	if (status != (int*)NULL)
	  {
	    UINT32 val = 0;
	    PIN_SafeCopy(&val, status, 4);
	    pr_out << "\t" << "status = " << val << endl;
	  }
      }
      break;
    case 8:
      // creat()
      {
	char* pathname = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	int mode = PIN_GetSyscallArgument(ctxt, std, 1);
	int fd = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "path = " << string(pathname) << endl;
	pr_out << "\t" << "mode = " <<  mode << endl;
	pr_out << "\t" << "fd = " << fd << endl;
      }
      break;
    case 39:
      // mkdir()
      {
	char* pathname = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	int mode = PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "path = " << string(pathname) << endl;
	pr_out << "\t" << "mode = " <<  mode << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 40:
      // rmdir()
    case 51:
      // acct()
    case 61:
      //chroot()
      {
	char* pathname = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "path = " << string(pathname) << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 9:
      // link()
    case 38:
      // rename()
      {
	char* old_pathname = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	char* new_pathname = (char*)PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "old path = " << string(old_pathname) << endl;
	pr_out << "\t" << "new path = " << string(new_pathname) << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 10:
      // unlink()
      {
	char* pathname = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "path = " << string(pathname) << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 11:
      // execve()
      {
	char* pathname = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	char **argv = (char**)PIN_GetSyscallArgument(ctxt, std, 1);
	char **envp = (char**)PIN_GetSyscallArgument(ctxt, std, 2);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	pr_out << "\t" << "path = " << string(pathname) << endl;
	pr_out << "\t" << "argv = " << argv << endl;
	pr_out << "\t" << "envp = " << envp << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
	
	for (int i = 0; argv[i]; i++)
	  {
	    pr_out << "\t" << "argv[" << i << "] = " << string(argv[i]) << endl;
	  }

	 for (int i = 0; envp[i]; i++)
	   {
	     pr_out << "\t" << "envp[" << i << "] = " << string(envp[i]) << endl;
	   }

       }
       break;
    case 12:
      // chdir()
      {
	char* pathname = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "path = " << string(pathname) << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 13:
      // time()
      {
	time_t* t = (time_t*)PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "t = " << t << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;

	if (t != (time_t*)NULL)
	  {
	    pr_out << "\t" << "*t = " << *t << endl;
	  }
      }
      break;
    case 259:
      // timer_create()
      {
	clockid_t clockid = (clockid_t)PIN_GetSyscallArgument(ctxt, std, 0);
	struct sigevent *sevp = (struct sigevent *)PIN_GetSyscallArgument(ctxt, std, 1);
	timer_t *timerid = (timer_t*)PIN_GetSyscallArgument(ctxt, std, 2);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" <<  "clockid = " << clockid << endl;
	pr_out << "\t" << "sevp = " << sevp << endl;	
	
	if (sevp != (struct sigevent*)NULL)
	  {
	    pr_out << "\t\t" << "sevp->sigev_notify = " << sevp->sigev_notify << endl;
	    pr_out << "\t\t" << "sevp->sigev_signo = " << sevp->sigev_signo << endl;
	    pr_out << "\t\t" << "sevp->sigev_value = " << sevp->sigev_value.sival_int
		   << endl;
	    pr_out << "\t\t" << "sevp->not_fxn = " << sevp->sigev_notify_function << endl;
	    pr_out << "\t\t" << "sevp->not_attr = " << sevp->sigev_notify_attributes << endl;
	    //pr_out << "\t\t" << "sevp->not_tid = " << sevp->sigev_notify_thread_id << endl;
	  }

	
	pr_out << "\t" << "timerid = " << timerid << endl;
	if (timerid != NULL)
	  {
	    pr_out << "\t\t" << "*timerid = " << *timerid << endl;
	  }
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 260:
      // timer_settime()
      {
        timer_t timerid = (timer_t)PIN_GetSyscallArgument(ctxt, std, 0);
	int flags = PIN_GetSyscallArgument(ctxt, std, 1);
	const struct itimerspec *new_value = 
	  (const struct itimerspec*)PIN_GetSyscallArgument(ctxt, std, 2);
	struct itimerspec *old_value = 
	  (struct itimerspec*)PIN_GetSyscallArgument(ctxt, std, 3);

	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" <<  "timerid = " << timerid << endl;
	pr_out << "\t" << "flags = " << flags << endl;	
	pr_out << "\t" << "new_value = " << new_value << endl;	
	if (new_value != NULL)
	  {
	    pr_out << "\t\t" << "new_value[interval] = {" << new_value->it_interval.
		   tv_sec << "," << new_value->it_interval.tv_nsec << "}" 
		   << endl;	
	    pr_out << "\t\t" << "new_value[value] = {" << new_value->it_value.
	      tv_sec << "," << new_value->it_value.tv_nsec << "}" 
		   << endl;	
	  }

	if (old_value != NULL)
	  {
	    pr_out << "\t\t" << "old_value[interval] = {" << old_value->it_interval.
		   tv_sec << "," << old_value->it_interval.tv_nsec << "}" 
		   << endl;	
	    pr_out << "\t\t" << "old_value[value] = {" << old_value->it_value.
	      tv_sec << "," << old_value->it_value.tv_nsec << "}" 
		   << endl;	
	  }
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 124:
      // adjtimex()
      {
	struct timex* buf = (struct timex*)PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	pr_out << "\t" << "buf = " << buf << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;

	if (buf != NULL)
	  {
	    pr_out << "\t\t" << "buf->modes = " << buf->modes << endl;
	    pr_out << "\t\t" << "buf->offset = " << buf->offset << endl;
	    pr_out << "\t\t" << "buf->freq = " << buf->freq << endl;
	    pr_out << "\t\t" << "buf->maxerror = " << buf->maxerror << endl;
	    pr_out << "\t\t" << "buf->esterror = " << buf->esterror << endl;
	    pr_out << "\t\t" << "buf->status = " << buf->status << endl;
	    pr_out << "\t\t" << "buf->constant = " << buf->constant << endl;
	    pr_out << "\t\t" << "buf->precision = " << buf->precision << endl;
	    pr_out << "\t\t" << "buf->tick = " << buf->tick << endl;
	    pr_out << "\t\t" << "buf->time = {" << buf->time.tv_sec << ","
		   << buf->time.tv_usec << "}" << endl;
	    
	  }
      }
      break;
    case 14:
      // mknod()
      {
	char* pathname = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	mode_t mode = (mode_t)PIN_GetSyscallArgument(ctxt, std, 1);
	dev_t dev = (dev_t)PIN_GetSyscallArgument(ctxt, std, 2);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "path = " << string(pathname) << endl;
	pr_out << "\t" << "mode = " << mode << endl;
	pr_out << "\t" << "dev = " << dev << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 15:
      // chmod()
    case 33:
      // access()
      {
	char* pathname = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	mode_t mode = (mode_t)PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	pr_out << "\t" << "path = " << string(pathname) << endl;
	pr_out << "\t" << "mode = " << mode << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 94:
      // fchmod()
      {
	int fd = PIN_GetSyscallArgument(ctxt, std, 0);
	mode_t mode = (mode_t)PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	pr_out << "\t" << "fd = " << fd << endl;
	pr_out << "\t" << "mode = " << mode << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 16:
      // lchown()
    case 198:
      // lchown32()
    case 182:
      // chown()
    case 212:
      // chown32()
      {
	char* pathname = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	mode_t mode = (mode_t)PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	pr_out << "\t" << "path = " << string(pathname) << endl;
	pr_out << "\t" << "mode = " << mode << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 207:
      // fchown32()
      {
	int fd = PIN_GetSyscallArgument(ctxt, std, 0);
	int owner = PIN_GetSyscallArgument(ctxt, std, 1);
	int group = PIN_GetSyscallArgument(ctxt, std, 2);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	pr_out << "\t" << "fd = " << fd << endl;
	pr_out << "\t" << "owner = " << owner << endl;
	pr_out << "\t" << "group = " << group << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 194:
      // ftruncate64
      {
        int fd = PIN_GetSyscallArgument(ctxt, std, 0);
	off_t length = (off_t)PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	pr_out << "\t" << "fd = " << fd << endl;
	pr_out << "\t" << "length = " << length << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 17:
      // break()
    case 31:
      // stty()
    case 32:
      // gtty()
    case 35:
      // ftime()
    case 188:
      // getpmsg()
    case 53:
      // lock()
    case 219:
      // madvise1()
    case 56:
      // mpx()
    case 44:
      // prof()
    case 98:
      // profil()
    case 189:
      // putpmsg()
    case 58:
      // ulimit()
    case 274:
      // verserver()
      pr_out << "\t" << "(*** warning :: unimplemented sys call)" << endl;
      break;
    case 18:
      // oldstat()
      pr_out << "\t" << "(*** warning :: obsolete sys call)" << endl;
      break;
    case 19:
      // lseek()
      {
	int fd = PIN_GetSyscallArgument(ctxt, std, 0);
	off_t offset = (off_t)PIN_GetSyscallArgument(ctxt, std, 1);
	int whence  = PIN_GetSyscallArgument(ctxt, std, 2);
	off_t ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "fd = " << fd << endl;
	pr_out << "\t" << "offset = " << offset << endl;
	pr_out << "\t" << "whence = " << whence << endl;
	pr_out << "\t" << "ret_offset = " << ret_val << endl;
      }
      break;
    case 20:
      // getpid()
    case 64:
      // getppid()
    case 65:
      // getpgrp()
    case 66:
      // setsid
      {
	pid_t pid = PIN_GetSyscallReturn(ctxt,std);
	pr_out << "\t" << "pid = " << pid << endl;
      }
      break;
    case 21:
      // mount()
      {
	char* source = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	char* target = (char*)PIN_GetSyscallArgument(ctxt, std, 1);
	char* fs_type = (char*)PIN_GetSyscallArgument(ctxt, std, 2);
	unsigned long flags = (unsigned long)PIN_GetSyscallArgument(ctxt, std, 3);
	void* data = (void*)PIN_GetSyscallArgument(ctxt, std, 4);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "source = " << string(source) << endl;
	pr_out << "\t" << "target = " << string(target) << endl;
	pr_out << "\t" << "fs_type = " << string(fs_type) << endl;
	pr_out << "\t" << "flags = " << flags << endl;
	pr_out << "\t" << "pData = " << data << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;

	// risky
	pr_out << "\t" << "data string = " << string((char*)data) << endl;
      }
      break;
    case 22:
      // umount()
      {
	char* target = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "target = " << string(target) << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 52:
      // umount2()
      {
	char* target = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	int flags = PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "target = " << string(target) << endl;
	pr_out << "\t" << "flags = " << flags << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 23:
      // setuid()
    case 46:
      // setgid()
    case 213:
      // setuid32()
    case 214:
      // setgid32()
      {
        int id = PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "id = " << id << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 24:
      // getuid()
    case 47:
      // getgid()
    case 49:
      // geuid()
    case 50:
      // geguid()
    case 199:
      // getuid32()
    case 200:
      // getgid32()
    case 201:
      // geteuid32()
    case 202:
      // getegid32()
      {
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
      
    case 25:
      // stime()
      {
	time_t* t = (time_t*)PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "t = " << t << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
	if (t != (time_t*)NULL)
	  {
	    pr_out << "\t" << "*t = " << *t << endl;
	  }
      }
      break;
    case 26:
      // ptrace()
      {
	int request = PIN_GetSyscallArgument(ctxt, std, 0);
	pid_t pid = (pid_t)PIN_GetSyscallArgument(ctxt, std, 1);
	void* addr = (void*)PIN_GetSyscallArgument(ctxt, std, 2);
	void* data = (void*)PIN_GetSyscallArgument(ctxt, std, 3);

	pr_out << "\t" << "req = " << request << endl;
	pr_out << "\t" << "pid = " << pid << endl;
	pr_out << "\t" << "addr = " << addr << endl;
	pr_out << "\t" << "data = " << data << endl;
	pr_out << "\t" << "( warning :: addr/data are pointers )" << endl;
      }
      break;
    case 27:
      // alarm()
      {
	unsigned int seconds = (unsigned int) PIN_GetSyscallArgument(ctxt, std, 0);
	unsigned int ret_val = (unsigned int) PIN_GetSyscallReturn(ctxt, std);

	pr_out << "\t" << "seconds = " << seconds << endl;
	pr_out << "\t" << "seconds remaining for prev alarm = " << ret_val  << endl;
      }
      break;
    case 28:
      // oldfstat()
      pr_out << "\t" << "(*** warning :: obsolete sys call)" << endl;
      break;
    case 29:
      // pause()
      {
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	pr_out << "\t" << "ret_val  = " << ret_val << endl;
      }
      break;
    case 30:
      // utime()
      {
	char* filename = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	struct utimbuf* times = (struct utimbuf*) PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "filename = " << string(filename) << endl;
	pr_out << "\t" << "times = " << times << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;

	if (times != (struct utimbuf*)NULL)
	  {
	    pr_out << "\t" << "times->actime = " << times->actime << endl;
	    pr_out << "\t" << "times->modtime = " << times->modtime << endl;
	  }
      }
      break;
    case 271:
      // utimes()
      {
	char* filename = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	struct timeval* times = (struct timeval*) PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "filename = " << string(filename) << endl;
	pr_out << "\t" << "times = " << times << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;

	if (times != (struct timeval*)NULL)
	  {
	    pr_out << "\t" << "times[0] = " << times[0].tv_sec << " " << times[0].tv_usec << endl;
	    pr_out << "\t" << "times[1] = " << times[1].tv_sec << " " << times[1].tv_usec << endl;
	  }
      }
      break;
    case 34:
      // nice()
      {
	int inc = PIN_GetSyscallArgument(ctxt, std, 0);
	int status = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "inc = " << inc << endl;
	pr_out << "\t" << "status = " << status << endl;
      }
      break;
    case 36:
      // sync()
      pr_out << "(void) -> (void)" << endl;
      break;
    case 37:
      // kill()
      {
	pid_t pid = PIN_GetSyscallArgument(ctxt, std, 0);
	int sig = PIN_GetSyscallArgument(ctxt, std, 1);
	int status = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "pid = " << pid << endl;
	pr_out << "\t" << "sig = " << sig << endl;
	pr_out << "\t" << "status = " << status << endl;
      }
      break;

    case 41:
      // dup()
      {
	int oldfd = PIN_GetSyscallArgument(ctxt, std, 0);
	int ret = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "old_fd = " << oldfd << endl;
	pr_out << "\t" << "ret = " << ret << endl;
      }
      break;
    case 63:
      // dup2()
      {
	int oldfd = PIN_GetSyscallArgument(ctxt, std, 0);
	int newfd = PIN_GetSyscallArgument(ctxt, std, 1);
	int ret = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "old_fd = " << oldfd << endl;
	pr_out << "\t" << "new_fd = " << newfd << endl;
	pr_out << "\t" << "ret = " << ret << endl;
      }
      break;
    case 42:
      // pipe()
      {
	int* pipefd = (int*)PIN_GetSyscallArgument(ctxt, std, 0);
	int ret = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "pipe_fd = " << pipefd << endl;
	pr_out << "\t" << "ret = " << ret << endl;
	
	if (pipefd != (int*)NULL)
	  {
	    pr_out << "\t" << "pipe_fd[0] = " << pipefd[0] << endl;
	    pr_out << "\t" << "pipe_fd[1] = " << pipefd[1] << endl;
	  }
      }
      break;
    case 43:
      // times()
	{
	  struct tms* buf = (struct tms*)PIN_GetSyscallArgument(ctxt, std, 0);
	  clock_t ret = (clock_t)PIN_GetSyscallReturn(ctxt, std);

	  pr_out << "\t" << "buf = " << buf << endl;
	  pr_out << "\t" << "ret = " << ret << endl;
	  
	  if (buf != (struct tms*)NULL)
	    {
	      pr_out << "\t" << "buf->utime = " << buf->tms_utime << endl;
	      pr_out << "\t" << "buf->stime = " << buf->tms_stime << endl;
	      pr_out << "\t" << "buf->cutime = " << buf->tms_cutime << endl;
	      pr_out << "\t" << "buf->cstime = " << buf->tms_cstime << endl;
	    }
	}
	break;
    case 45:
      // brk()
      {
	void* addr = (void*)PIN_GetSyscallArgument(ctxt, std, 0);
	int ret = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "addr = " << addr << endl;
	pr_out << "\t" << "ret = " << ret << endl;
      }
      break;
    case 48:
      // signal()
      {
	int signum = PIN_GetSyscallArgument(ctxt, std, 0);
	sighandler_t handler = (sighandler_t)PIN_GetSyscallArgument(ctxt, std, 1);
	sighandler_t ret = (sighandler_t)PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "signum = " << signum << endl;
	pr_out << "\t" << "handler = " << handler << endl;
	pr_out << "\t" << "ret = " << ret << endl;
      }
      break;
    case 67:
      // sigaction()
    case 174:
      // rt_sigaction()
      {
	int signum = PIN_GetSyscallArgument(ctxt, std, 0);
	struct sigaction* act = (struct sigaction*)PIN_GetSyscallArgument(ctxt, std, 1);
	struct sigaction* old = (struct sigaction*)PIN_GetSyscallArgument(ctxt, std, 2);
	int ret = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "signum = " << signum << endl;
	pr_out << "\t" << "act = " << act << endl;
	pr_out << "\t" << "old = " << old << endl;
	pr_out << "\t" << "ret = " << ret << endl;

	if (act != (struct sigaction*) NULL)
	  {
	    pr_out << "\t" << "act->sa_handler = " << act->sa_handler << endl;
	    pr_out << "\t" << "act->sa_sigaction = " << act->sa_sigaction << endl;
	    pr_out << "\t" << "act->sa_mask = (*** skipped *** )" << endl;
	    pr_out << "\t" << "act->sa_flags = " << act->sa_flags << endl;
	    pr_out << "\t" << "act->sa_restorer = " << act->sa_restorer << endl;
	  }

	if (old != (struct sigaction*) NULL)
	  {
	    pr_out << "\t" << "old->sa_handler = " << old->sa_handler << endl;
	    pr_out << "\t" << "old->sa_sigaction = " << old->sa_sigaction << endl;
	    pr_out << "\t" << "old->sa_mask = (*** skipped *** )" << endl;
	    pr_out << "\t" << "old->sa_flags = " << old->sa_flags << endl;
	    pr_out << "\t" << "old->sa_restorer = " << old->sa_restorer << endl;
	  }

      }
      break;
    case 54:
      // ioctl()
      {
	int d = PIN_GetSyscallArgument(ctxt, std, 0);
	int req = PIN_GetSyscallArgument(ctxt, std, 1);
	char* argp = (char*)PIN_GetSyscallArgument(ctxt, std, 2);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "d = " << d << endl;
	pr_out << "\t" << "req = " << req << endl;
	pr_out << "\t" << "argp = " << ((void*)argp) << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;

	// risky
	pr_out << "\t" << "*argp = " << string(argp) << endl;
      }
      break;
    case 55:
      // fcntl()
    case 221:
      // fcntl64()
      {
	int fd = PIN_GetSyscallArgument(ctxt, std, 0);
	int cmd = PIN_GetSyscallArgument(ctxt, std, 1);
	long arg = (long)PIN_GetSyscallArgument(ctxt, std, 2);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "fd = " << fd << endl;
	pr_out << "\t" << "cmd = " << cmd << endl;
	pr_out << "\t" << "arg = " << arg << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 57:
      // setpgid()
      {
	pid_t pid = PIN_GetSyscallArgument(ctxt, std, 0);
	pid_t pgid = PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	pr_out << "\t" << "pid = " << pid << endl;
	pr_out << "\t" << "pgid = " << pgid << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 59:
      // oldolduname()
    case 122:
      // uname()
      {
	struct utsname* buf = (struct utsname*) PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	pr_out << "\t" << "buf = " << buf << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
	
	if (buf != (struct utsname*)NULL)
	  {
	    pr_out << "\t" << "buf->sysname = " << string(buf->sysname) << endl;
	    pr_out << "\t" << "buf->nodename = " << string(buf->nodename) << endl;
	    pr_out << "\t" << "buf->release = " << string(buf->release) << endl;
	    pr_out << "\t" << "buf->version = " << string(buf->version) << endl;
	    pr_out << "\t" << "buf->machine = " << string(buf->machine) << endl;
	    pr_out << "\t" << "buf->domainname = " << string(buf->domainname) << endl;
	  }
      }
      break;
    case 60:
      // umask()
      {
	mode_t mask = PIN_GetSyscallArgument(ctxt, std, 0);
       	mode_t ret_val = PIN_GetSyscallReturn(ctxt, std);

	pr_out << "\t" << "mask = " << mask << endl;
	pr_out << "\t" << "prev_mask = " << ret_val << endl;

      }
      break;
    case 62:
      // ustat()
      {
	dev_t dev = (dev_t)PIN_GetSyscallArgument(ctxt, std, 0);
	struct ustat* ubuf = (struct ustat*) PIN_GetSyscallArgument(ctxt, std, 1);
        int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "dev = " << dev << endl;
	pr_out << "\t" << "ubuf = " << ubuf << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
	
	if (ubuf != (struct ustat*)NULL)
	  {
	    pr_out << "\t" << "ubuf->f_tfree = " << ubuf->f_tfree << endl;
	    pr_out << "\t" << "ubuf->f_tinode = " << ubuf->f_tinode << endl;
	    pr_out << "\t" << "ubuf->f_fname = " << string(ubuf->f_fname) << endl;
	  }
      }
      break;

    case 68:
      // sgetmask()
      {
	long ret_val = (long)PIN_GetSyscallReturn(ctxt, std);
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 69:
      // ssetmask()
      {
	long new_mask = (long)PIN_GetSyscallArgument(ctxt, std, 0);
	long ret_val = (long)PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "newmask = " << new_mask << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 70:
      // setreuid()
    case 71:
      // setregid()
    case 203:
      // setreuid32()
    case 204:
      // setregid32()
      {
	int rid = PIN_GetSyscallArgument(ctxt, std, 0);
	int eid = PIN_GetSyscallArgument(ctxt, std, 1);	
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "rid = " << rid << endl;
	pr_out << "\t" << "eid = " << eid << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 72:
      // sigsuspend()
    case 73:
      // sigpending()
      {
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "mask = (*** skipped *** )" << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 74:
      // sethostname()
      {
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	char* name = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	size_t len = (size_t)PIN_GetSyscallArgument(ctxt, std, 1);

	char buf[256];
	size_t i =0;
	for (i = 0; i < len; i++)
	  {
	    buf[i] = name[i];
	  }
	buf[i] = '\0';

	pr_out << "\t" << "name = " << string(buf) << endl;	
	pr_out << "\t" << "ret_val = " << ret_val << endl;	
      }
      break;
    case 75:
      // setrlimit()
    case 76:
      // getrlimit()
    case 191:
      // ugetrlimit()
      {
	int resource = PIN_GetSyscallArgument(ctxt, std, 0);
	struct rlimit* r = (struct rlimit*)PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	pr_out << "\t" << "resource = " << resource << endl;	
	pr_out << "\t" << "r = " << r << endl;	
	pr_out << "\t" << "ret_val = " << ret_val << endl;	
	
	if (r != (struct rlimit*)NULL)
	  {
	    pr_out << "\t" << "r->rlim_cur = " << r->rlim_cur << endl;	
	    pr_out << "\t" << "r->rlim_max = " << r->rlim_max << endl;	
	  }
      }
      break;
    case 77:
      // getrusage()
      {
	int who = PIN_GetSyscallArgument(ctxt, std, 0);
	struct rusage* r = (struct rusage*)PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	pr_out << "\t" << "who = " << who << endl;	
	pr_out << "\t" << "r = " << r << endl;	
	pr_out << "\t" << "ret_val = " << ret_val << endl;	
	
	if (r != (struct rusage*)NULL)
	  {
	    pr_out << "\t" << "r->ru_utime.tv_sec = " << r->ru_utime.tv_sec << endl;	
	    pr_out << "\t" << "r->ru_utime.tv_usec = " << r->ru_utime.tv_usec << endl;	
	    pr_out << "\t" << "r->ru_stime.tv_sec = " << r->ru_stime.tv_sec << endl;	
	    pr_out << "\t" << "r->ru_stime.tv_usec = " << r->ru_stime.tv_usec << endl;	

	    pr_out << "\t" << "r->ru_maxrss = " << r->ru_maxrss << endl;	
	    pr_out << "\t" << "r->ru_ixrss = " << r->ru_ixrss << endl;	
	    pr_out << "\t" << "r->ru_idrss = " << r->ru_idrss << endl;	
	    pr_out << "\t" << "r->ru_isrss = " << r->ru_isrss << endl;	
	    pr_out << "\t" << "r->ru_minflt = " << r->ru_minflt << endl;	
	    pr_out << "\t" << "r->ru_majflt = " << r->ru_majflt << endl;	
	    pr_out << "\t" << "r->ru_nswap = " << r->ru_nswap << endl;	
	    pr_out << "\t" << "r->ru_inblock = " << r->ru_inblock << endl;	
	    pr_out << "\t" << "r->ru_oublock = " << r->ru_oublock << endl;	
	    pr_out << "\t" << "r->ru_msgsnd = " << r->ru_msgsnd << endl;	
	    pr_out << "\t" << "r->ru_msgrcv = " << r->ru_msgrcv << endl;	
	    pr_out << "\t" << "r->ru_nsignals = " << r->ru_nsignals << endl;	
	    pr_out << "\t" << "r->ru_nvcsw = " << r->ru_nvcsw << endl;	
	    pr_out << "\t" << "r->ru_nivcsw = " << r->ru_nivcsw << endl;	
	  }
      }
      break;
    case 78:
      // gettimeofday()
    case 79:
      // settimeofday()
      {
	struct timeval *tv = (struct timeval*)PIN_GetSyscallArgument(ctxt, std, 0);
	struct timezone *tz = (struct timezone*)PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	pr_out << "\t" << "tv = " << tv << endl;	
	pr_out << "\t" << "tz = " << tz << endl;	
	pr_out << "\t" << "ret_val = " << ret_val << endl;	

	if (tv != (struct timeval*)NULL)
	  {
	    pr_out << "\t" << "tv->tv_sec = " << tv->tv_sec << endl;	
	    pr_out << "\t" << "tv->tv_usec = " << tv->tv_usec << endl;	
	  }

	if (tz != (struct timezone*)NULL)
	  {
	    pr_out << "\t" << "tz->tz_minuteswest = " << tz->tz_minuteswest << endl;	
	    pr_out << "\t" << "tz->tz_dsttime = " << tz->tz_dsttime << endl;	
	  }
      }
      break;
    case 80:
      // getgroups()
    case 81:
      // setgroups()
      {
	int size = PIN_GetSyscallArgument(ctxt, std, 0);
	gid_t *list = (gid_t*)PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
      
	pr_out << "\t" << "size = " << size << endl;	
	pr_out << "\t" << "list = " << list << endl;	
	pr_out << "\t" << "ret_val = " << ret_val << endl;	

	if (list != (gid_t*)NULL)
	  {
	    int i = 0;
	    for (i = 0; i < size; i++)
	      {
		pr_out << "\t" << "list[" << i << "] = " << list[i] << endl;	
	      }
	  }
      }
      break;
    case 82:
      // select()
      {
	
      }
      break;
    case 192:
      // mmap2()
      {
	void* addr = (void*)PIN_GetSyscallArgument(ctxt, std, 0);
	size_t length = (size_t)PIN_GetSyscallArgument(ctxt, std, 1);
	int prot = PIN_GetSyscallArgument(ctxt, std, 2);
	int flags = PIN_GetSyscallArgument(ctxt, std, 3);
	int fd = PIN_GetSyscallArgument(ctxt, std, 4);
	off_t pgoffset = (off_t)PIN_GetSyscallArgument(ctxt, std, 5);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
      
	pr_out << "\t" << "addr = " << hex << addr << endl;	
	pr_out << "\t" << "length = " << dec << length << endl;	
	pr_out << "\t" << "prot = " << prot << endl;	
	pr_out << "\t" << "flags = " << flags << endl;	
	pr_out << "\t" << "fd = " << fd << endl;	
	pr_out << "\t" << "pgoffset = " << pgoffset << endl;	
	pr_out << "\t" << "ret_val = " << hex << ret_val << endl << dec;	
      }
      break;
    case 195:
      // stat64()
    case 196:
      // lstat64()
      {
	char* path = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	struct stat64 *buf = (struct stat64 *)PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	pr_out << "\t" << "path = " << string(path) << endl;	
	pr_out << "\t" << "buf = " << buf << endl;	
	pr_out << "\t" << "ret_val = " << ret_val << endl;	

	if (buf != (struct stat64*)NULL)
	  {
	    pr_out << "\tbuf->st_dev:" << buf->st_dev << endl;
	    pr_out << "\tbuf->st_ino:" << buf->st_ino << endl;
	    pr_out << "\tbuf->st_mode:" << buf->st_mode << endl;
	    pr_out << "\tbuf->st_nlink:" << buf->st_nlink << endl;
	    pr_out << "\tbuf->st_uid:" << buf->st_uid << endl;
	    pr_out << "\tbuf->st_gid:" << buf->st_gid << endl;
	    pr_out << "\tbuf->st_rdev:" << buf->st_rdev << endl;
	    pr_out << "\tbuf->st_size:" << buf->st_size << endl;
	    pr_out << "\tbuf->st_atime:" << buf->st_atime << endl;
	    pr_out << "\tbuf->st_mtime:" << buf->st_mtime << endl;
	    pr_out << "\tbuf->st_ctime:" << buf->st_ctime << endl;
	    pr_out << "\tbuf->blk_size:" << buf->st_blksize << endl;
	    pr_out << "\tbuf->st_blocks:" << buf->st_blocks << endl;
	  }
      }
      break;
    case 197:
      // fstat64()
      {
	int fd = PIN_GetSyscallArgument(ctxt, std, 0);
	struct stat64 *buf = (struct stat64 *)PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	pr_out << "\t" << "fd = " << fd << endl;	
	pr_out << "\t" << "buf = " << buf << endl;	
	pr_out << "\t" << "ret_val = " << ret_val << endl;	

	if (buf != (struct stat64*)NULL)
	  {
	    pr_out << "\tbuf->st_dev:" << buf->st_dev << endl;
	    pr_out << "\tbuf->st_ino:" << buf->st_ino << endl;
	    pr_out << "\tbuf->st_mode:" << buf->st_mode << endl;
	    pr_out << "\tbuf->st_nlink:" << buf->st_nlink << endl;
	    pr_out << "\tbuf->st_uid:" << buf->st_uid << endl;
	    pr_out << "\tbuf->st_gid:" << buf->st_gid << endl;
	    pr_out << "\tbuf->st_rdev:" << buf->st_rdev << endl;
	    pr_out << "\tbuf->st_size:" << buf->st_size << endl;
	    pr_out << "\tbuf->st_atime:" << buf->st_atime << endl;
	    pr_out << "\tbuf->st_mtime:" << buf->st_mtime << endl;
	    pr_out << "\tbuf->st_ctime:" << buf->st_ctime << endl;
	    pr_out << "\tbuf->blk_size:" << buf->st_blksize << endl;
	    pr_out << "\tbuf->st_blocks:" << buf->st_blocks << endl;
	  }
      }
      break;
    case 243:
      // set_thread_area()
      {
	struct user_desc *u_info = (struct user_desc*)PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "u_info = " << u_info << endl;	
	pr_out << "\t" << "ret_val = " << ret_val << endl;	

	if (u_info != (struct user_desc*)NULL)
	  {

	    pr_out << "\t" << "u_info->entry_number = " << u_info->entry_number << endl;	
	  }
      }
      break;
    case 142:
      // new_select()
      {
        int nfds = (int)PIN_GetSyscallArgument(ctxt, std, 0);
	fd_set *readfds = (fd_set*)PIN_GetSyscallArgument(ctxt, std, 1);
	fd_set *writefds = (fd_set*)PIN_GetSyscallArgument(ctxt, std, 2);
	fd_set *exceptfds = (fd_set*)PIN_GetSyscallArgument(ctxt, std, 3);
	const struct timespec *timeout = 
	  (const struct timespec*)PIN_GetSyscallArgument(ctxt, std, 4);
	const sigset_t *sigmask = (const sigset_t*)PIN_GetSyscallArgument(ctxt, std, 5);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
      
	pr_out << "\t" << "nfds = " << nfds << endl;	
	pr_out << "\t" << "readfds = " << readfds << endl;	
	pr_out << "\t" << "writefds = " << writefds << endl;	
	pr_out << "\t" << "exceptfds = " << exceptfds << endl;	
	pr_out << "\t" << "timeout = " << timeout << endl;	
	pr_out << "\t" << "sigmask = " << sigmask << endl;	
	pr_out << "\t" << "ret_val = " << ret_val << endl;	
      }
      break;
    case 125:
      // mprotect()
      {
	void* addr = (void*)PIN_GetSyscallArgument(ctxt, std, 0);
	size_t length = (size_t)PIN_GetSyscallArgument(ctxt, std, 1);
	int prot = PIN_GetSyscallArgument(ctxt, std, 2);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
      
	pr_out << "\t" << "addr = " << addr << endl;	
	pr_out << "\t" << "length = " << length << endl;	
	pr_out << "\t" << "prot = " << prot << endl;	
	pr_out << "\t" << "ret_val = " << ret_val << endl;	
      }
      break;
    case 91:
      // munmap()
      {
	void* addr = (void*)PIN_GetSyscallArgument(ctxt, std, 0);
	size_t length = (size_t)PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
      
	pr_out << "\t" << "addr = " << addr << endl;	
	pr_out << "\t" << "length = " << length << endl;	
	pr_out << "\t" << "ret_val = " << ret_val << endl;	
      }
      break;
    case 258:
      // set_tid_address()
      {
	int* tidptr = (int*)PIN_GetSyscallArgument(ctxt, std, 0);
	long ret_val = (long)PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "tidptr = " << tidptr << endl;	
	pr_out << "\t" << "pid = " << ret_val << endl;	
	
	if (tidptr != (int*)NULL)
	  {
	    pr_out << "\t" << "*tidptr = " << *tidptr << endl;	
	  }
      }
      break;
    case 311:
      // set_robust_list()
      {
	struct robust_list_head *head = (struct robust_list_head*)PIN_GetSyscallArgument(ctxt, std, 0);
	size_t len = (size_t) PIN_GetSyscallArgument(ctxt, std, 1);
	long ret_val = (long)PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "head = " << head << endl;
	pr_out << "\t" << "len = " << len << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 240:
      // futex()
      {
	int* uaddr = (int*)PIN_GetSyscallArgument(ctxt, std, 0);
	int op = PIN_GetSyscallArgument(ctxt, std, 1);
	int val = PIN_GetSyscallArgument(ctxt, std, 2);
	struct timespec *timepr_out = (struct timespec*) PIN_GetSyscallArgument(ctxt, std, 3);
	int* uaddr2 = (int*)PIN_GetSyscallArgument(ctxt, std, 4);
	int val3 = PIN_GetSyscallArgument(ctxt, std, 5);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "uaddr = " << uaddr << endl;
	pr_out << "\t" << "op = " << op << endl;
	pr_out << "\t" << "val = " << val << endl;
	pr_out << "\t" << "timepr_out = " << timepr_out << endl;
	pr_out << "\t" << "uaddr2 = " << uaddr2 << endl;
	pr_out << "\t" << "val3 = " << val3 << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;

	if (timepr_out != (struct timespec*)NULL)
	  {
	    // pr_out << "\t" << "timepr_out->tv_sec = " << timepr_out->tv_sec << endl;
	    // pr_out << "\t" << "timepr_out->tv_nsec = " << timepr_out->tv_nsec << endl;
	  }
	

      }
      break;
    case 175:
      // rt_sigprockmask()
      {
	int how = PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "how = " << how << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
	pr_out << "\t" << "set = (*** skipped *** )" << endl;
	pr_out << "\t" << "old_set = (*** skipped *** )" << endl;
      }
      break;

    case 140:
      // llseek()
      {
	int fd = PIN_GetSyscallArgument(ctxt, std, 0);
	unsigned long off_h = (unsigned long) PIN_GetSyscallArgument(ctxt, std, 1);
	unsigned long off_l = (unsigned long) PIN_GetSyscallArgument(ctxt, std, 2);
	loff_t *result = (loff_t*) PIN_GetSyscallArgument(ctxt, std, 3);
	unsigned int whence = (unsigned int) PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "fd = " << fd << endl;
	pr_out << "\t" << "off_h = " << off_h << endl;
	pr_out << "\t" << "off_l = " << off_l << endl;
	pr_out << "\t" << "result = " << result << endl;
	pr_out << "\t" << "whence = " << whence << endl;	
	pr_out << "\t" << "ret_val = " << ret_val << endl;

	if (result != (loff_t*)NULL)
	  {
	    pr_out << "\t" << "*result = " << *result << endl;
	  }
      }
      break;
    case 254:
      // epoll_create()
      {
	int size = PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "size = " << size << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 255:
      // epoll_ctl()
      {
	int epfd = PIN_GetSyscallArgument(ctxt, std, 0);
	int op = PIN_GetSyscallArgument(ctxt, std, 1);
	int fd = PIN_GetSyscallArgument(ctxt, std, 2);
	struct epoll_event * event = (struct epoll_event*) PIN_GetSyscallArgument(ctxt, std, 3);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "epfd = " << epfd << endl;
	pr_out << "\t" << "op = " << op << endl;
	pr_out << "\t" << "fd = " << fd << endl;
	pr_out << "\t" << "event = " << event << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;

	if (event != (struct epoll_event*)NULL)
	  {
	    pr_out << "\t" << "event->events = " << event->events << endl;
	    pr_out << "\t" << "event->data = " << (event->data.u32) << endl;
	  }
      }
      break;
    case 256:
      // epoll_wait()
      {
	int epfd = PIN_GetSyscallArgument(ctxt, std, 0);
	struct epoll_event * events = (struct epoll_event*)PIN_GetSyscallArgument(ctxt, std, 1);
	int max_events = PIN_GetSyscallArgument(ctxt, std, 2);
	int timeout = PIN_GetSyscallArgument(ctxt, std, 3);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "epfd = " << epfd << endl;
	pr_out << "\t" << "events = " << events << endl;
	pr_out << "\t" << "max_events = " << max_events << endl;
	pr_out << "\t" << "timeout = " << timeout << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;

	int i;
	for (i = 0; i < epfd; i++)
	  {
	    struct epoll_event v = events[i];
	    pr_out << "\t" << "events[" << i << "] = {ev=" << v.events << ", data_ptr=" 
		   << v.data.ptr << "}" << endl;
	  }

      }
      break;
    case 168:
      // poll()
      {
	struct pollfd* fds = (struct pollfd*)PIN_GetSyscallArgument(ctxt, std, 0);
	nfds_t nfds = (nfds_t)PIN_GetSyscallArgument(ctxt, std, 1);
	int timeout = PIN_GetSyscallArgument(ctxt, std, 2);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	pr_out << "\t" << "fds = " << fds << endl;
	pr_out << "\t" << "#fds = " << nfds << endl;
	pr_out << "\t" << "timeout = " << timeout << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;

	nfds_t i;
	for (i = 0; i < nfds; i++)
	  {
	    struct pollfd f = fds[i];
	    pr_out << "\t" << "fds[" << i << "] = {fd=" << f.fd << ", events=" 
		   << f.events << ", revents=" << f.revents << "}" << endl;
	  }

      }
      break;
    case 145:
      // readv()
    case 146:
      // writev()
      {
	int fd = PIN_GetSyscallArgument(ctxt, std, 0);
	struct iovec* vector = (struct iovec*)PIN_GetSyscallArgument(ctxt, std, 1);
	int count = PIN_GetSyscallArgument(ctxt, std, 2);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	pr_out << "\t" << "fd = " << fd << endl;
	pr_out << "\t" << "vector = " << vector << endl;
	pr_out << "\t" << "count = " << count << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;

	int i;
	for (i = 0; i < count; i++)
	  {
	    struct iovec cur = vector[i];
	    pr_out << "\t" << "vector[" << i << "] = {base=" << cur.iov_base << ", iov_len=" 
		   << cur.iov_len << "}" << endl;

	    uint8_t *buf = (uint8_t*)cur.iov_base;
	    size_t buf_len = cur.iov_len;
	    if (buf != (uint8_t*)NULL && buf_len > 0)
	      {
		size_t j;
		for (j = 0; j < buf_len; j++)
		  {
		    pr_out << "\t\t" << "buf[" << j << "] = " << buf[j] << endl;
		  }
	      }
	  }
      }
      break;
    case 220:
      // getdents64()
    case 141:
      // getdents()
      {
	int fd = PIN_GetSyscallArgument(ctxt, std, 0);
	struct linux_dirent *d = (struct linux_dirent*) PIN_GetSyscallArgument(ctxt, std, 1);
	unsigned int count = (unsigned int) PIN_GetSyscallArgument(ctxt, std, 2);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "fd = " << fd << endl;
	pr_out << "\t" << "d = " << d << endl;
	pr_out << "\t" << "count = " << count << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;

	pr_out << "\t" << "actual entries in d = (*** skipped *** )" << endl;
      }
      break;
    case 120:
      // clone()
      {
	void* fn = (void*) PIN_GetSyscallArgument(ctxt, std, 0);
	void* child_stack = (void*) PIN_GetSyscallArgument(ctxt, std, 1);
	int flags = PIN_GetSyscallArgument(ctxt, std, 2);
	void* arg = (void*) PIN_GetSyscallArgument(ctxt, std, 3);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "fn = " << fn << endl;
	pr_out << "\t" << "child_stack = " << child_stack << endl;
	pr_out << "\t" << "flags = " << flags << endl;
	pr_out << "\t" << "arg = " << arg << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;

    case 102:
      // socketcall()
      HandleSocketCall(threadIndex, ctxt, std, v, pr_out);
      break;
    
    case 265:
      // clock_gettime()
      {
      	clockid_t clk_id = (clockid_t) PIN_GetSyscallArgument(ctxt, std, 0);
	struct timespec *tp = (struct timespec*) PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	pr_out << "\t" << "clk_id = " << clk_id << endl;
	pr_out << "\t" << "tp = " << tp << endl;
	pr_out << "\t" << "ret_val = " << ret_val << endl;
	
	if (tp != (struct timespec*)NULL)
	  {
	    pr_out << "\t" << "tp->tv_sec = " << tp->tv_sec << endl;
	    pr_out << "\t" << "tp->tv_nsec = " << tp->tv_nsec << endl;
	  }
      }
      break;
    default:
      pr_out << "<---------UNHANDLED (" << pr_last_syscall_number << ")-------->" << endl;	
      break;
    }     
  
  name = syscalls[pr_last_syscall_number];
  pr_out << name << "() returning." << endl;
  pr_outstanding_syscall=false;
  return;
}

/* ===================================================================== */
VOID HandleSysBegin(THREADID threadIndex, CONTEXT *ctxt, 
		    SYSCALL_STANDARD std, VOID *v,
		    std::ofstream & pr_out)
{
  if (pr_outstanding_syscall)
    {
      pr_out << "[WARNING]: SysBegin() Interruptable " 
	   << "System Call Situation" << endl;
    }
  
  pr_last_syscall_number = PIN_GetSyscallNumber(ctxt, std);
  pr_out << "SysBegin(): " << syscalls[pr_last_syscall_number] << endl;
  pr_outstanding_syscall = true;
}


#endif
