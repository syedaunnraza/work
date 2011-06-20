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

using namespace INSTLIB;

LOCALVAR BOOL outstanding_syscall = false;
LOCALVAR ADDRINT last_syscall_number = 0;

//output stream
LOCALVAR std::ofstream out;


/* ===================================================================== */
GLOBALFUN VOID SetOutputFile(string path)
{
  out.open(path.c_str());
}

/* ===================================================================== */
GLOBALFUN VOID CloseOutputFile()
{
  out.close();
}

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

LOCALFUN VOID print_sockaddr(struct sockaddr * my_addr)
{
  if (my_addr != (struct sockaddr*)NULL)
    {
      sa_family_t sa_family = my_addr->sa_family;
      switch ( sa_family )
	{
	case AF_INET:
	  {
	    struct sockaddr_in *in = (struct sockaddr_in*) my_addr;
	    char *addr = inet_ntoa (in->sin_addr);

	    out << "\t" << "family = AF_INET" << endl;
	    out << "\t" << "addr = " << string(addr) << endl;
	    out << "\t" << "port = " << in->sin_port << endl;
	  }
	  break;
	case AF_INET6:
	  {
	    char dest[512];
	    
	    struct sockaddr_in6 *in = (struct sockaddr_in6*) my_addr;
	    const char* i6_rep = inet_ntop(AF_INET6, &in->sin6_addr, dest, 512);
	    
	    out << "\t" << "family = AF_INET6" << endl;
	    out << "\t" << "addr = " << string(i6_rep) << endl;
	    out << "\t" << "port = " << in->sin6_port << endl;
	    out << "\t" << "flow info = " << ntohl(in->sin6_flowinfo) << endl;
	    out << "\t" << "scope = " << ntohl(in->sin6_scope_id) << endl;
	  }
	  break;
	case AF_UNIX:
	  {
	    struct sockaddr_un *in = (struct sockaddr_un*)my_addr;
	    out << "\t" << "family = AF_UNIX" << endl;
	    out << "\t" << "addr = " << string(in->sun_path) << endl;
	  }
	  break;
	case AF_NETLINK:
	  {
	    struct sockaddr_nl *in = (struct sockaddr_nl*)my_addr;
	    out << "\t" << "family = AF_NETLINK" << endl;
	    out << "\t" << "pid = " << in->nl_pid << endl;
	    out << "\t" << "groups = " << in->nl_groups << endl;
	  }
	  break;
	default:
	  out << "\t" << "<--unhandled packet format family--> " << endl;
	  break;
	}
    }
}

/* ===================================================================== */

GLOBALFUN VOID HandleSocketCall(THREADID threadIndex, CONTEXT *ctxt, 
		      SYSCALL_STANDARD std, VOID *v)
{
  int call_number = PIN_GetSyscallArgument(ctxt, std, 0);
  ADDRINT args = PIN_GetSyscallArgument(ctxt, std, 1);

  out << socketcalls[call_number] << "() called." << endl;

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

	out << "\t" << "domain = " << domain << " ( " << domain_string << " ) " << endl;
	out << "\t" << "type = " << type << " ( " << type_string << " ) " << endl;
	out << "\t" << "protocol = " << protocol << endl;
	out << "\t" << "fd = " << PIN_GetSyscallReturn(ctxt, std) << endl;
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
	
	out << "\t" << "sockfd = " << sockfd << endl;
	out << "\t" << "my_addr = " << my_addr << endl;
	out << "\t" << "addrlen = " << addrlen << endl;
	out << "\t" << "ret_val = " << PIN_GetSyscallReturn(ctxt, std) << endl;
	
	print_sockaddr(my_addr);
      }
      break;
    case 4:
      // listen()
      {
	int sockfd = *(int*)args;
	int backlog = *(int*)(args + sizeof(int));
	
	out << "\t" << "sockfd = " << sockfd << endl;
	out << "\t" << "backlog = " << backlog << endl;
	out << "\t" << "ret_val = " << PIN_GetSyscallReturn(ctxt, std) << endl;
      }      
      break;
    case 8:
      // socketpair()
      {
	int d = *(int*)args;
	int type = *(int*)(args + sizeof(int));
	int* sv = *(int**)(args + 2*sizeof(int));
	
	out << "\t" << "domain = " << d << endl;
	out << "\t" << "type = " << type << endl;
	out << "\t" << "sv = " << sv << endl;
	out << "\t" << "ret_val = " << PIN_GetSyscallReturn(ctxt, std) << endl;
	if (sv != (int*)NULL)
	  {
	    out << "\t" << "sv[0] = " << sv[0] << endl;
	    out << "\t" << "sv[1] = " << sv[1] << endl;
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

	out << "\t" << "s = " << s << endl;
	out << "\t" << "buf = " << buf << endl;
	out << "\t" << "len = " << len << endl;
	out << "\t" << "flags = " << flags << endl;
	out << "\t" << "ret_val = " << PIN_GetSyscallReturn(ctxt, std) << endl;
	
	if (buf != (void*) NULL)
	  {
	    size_t byte_number = 0;
	    while (byte_number < len)
	      {
		out << "\t" << "buf[ " << byte_number << "] = " << ((uint8_t*)buf)[byte_number] << endl;
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

	out << "\t" << "s = " << s << endl;
	out << "\t" << "buf = " << buf << endl;
	out << "\t" << "len = " << len << endl;
	out << "\t" << "flags = " << flags << endl;
	out << "\t" << "to = " << to << endl;
	out << "\t" << "tolen = " << tolen << endl;
	out << "\t" << "ret_val = " << PIN_GetSyscallReturn(ctxt, std) << endl;
	
	if (buf != (void*) NULL)
	  {
	    size_t byte_number = 0;
	    while (byte_number < len)
	      {
		out << "\t" << "buf[ " << byte_number << "] = " << ((uint8_t*)buf)[byte_number] << endl;
		byte_number++;
	      }
	  }

	print_sockaddr(to);	
      }
      break;
    case 13:
      // shutdown()
      {	
	int s = *(int*)args;
	int how = *(int*)(args + sizeof(int));

	out << "\t" << "s = " << s << endl;
	out << "\t" << "how = " << how << endl;
	out << "\t" << "ret_val = " << PIN_GetSyscallReturn(ctxt, std) << endl;
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
	

	out << "\t" << "s = " << s << endl;
	out << "\t" << "level = " << level << endl;
	out << "\t" << "optname = " << optname << endl;
	out << "\t" << "optval = " << optval << endl;
	out << "\t" << "optlen = " << optlen << endl;
	
	if (optval != (void*) NULL)
	  {
	    size_t byte_number = 0;
	    while (byte_number < optlen)
	      {
		out << "\t" << "optval[ " << byte_number << "] = " << ((uint8_t*)optval)[byte_number] << endl;
		byte_number++;
	      }
	  }
	
	out << "\t" << "ret_val = " << PIN_GetSyscallReturn(ctxt, std) << endl;
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
	

	out << "\t" << "s = " << s << endl;
	out << "\t" << "level = " << level << endl;
	out << "\t" << "optname = " << optname << endl;
	out << "\t" << "optval = " << optval << endl;
	out << "\t" << "optlen = " << optlen << endl;
	
	if (optval != (void*) NULL && optlen != (socklen_t*)NULL)
	  {
	    size_t byte_number = 0;
	    while (byte_number < (*optlen))
	      {
		out << "\t" << "optval[ " << byte_number << "] = " << ((uint8_t*)optval)[byte_number] << endl;
		byte_number++;
	      }
	  }
	
	out << "\t" << "ret_val = " << PIN_GetSyscallReturn(ctxt, std) << endl;
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

	out << "\t" << "s = " << s << endl;
	out << "\t" << "h = " << h << endl;
	out << "\t" << "flags = " << flags << endl;
	out << "\t" << "ret_val = " << ret_val << endl;

	if (h != (struct msghdr*)NULL)
	  {
	    if (h->msg_name != (void*)NULL && h->msg_namelen > 0)
	      {
		print_sockaddr((struct sockaddr *)h->msg_name);
	      }
	    
	    struct iovec* msg_iov = h->msg_iov;
	    size_t iov_len = h->msg_iovlen;
	    out << "\t" << "h->msg_iov = " << msg_iov << endl;
	    out << "\t" << "h->msg_iovlen = " << iov_len << endl;

	    size_t i;
	    for (i = 0; i < iov_len; i++)
	      {
		struct iovec current = msg_iov[i];
		out << "\t" << "msg_iov[" << i << "] = {base=" << current.iov_base << ",len=" << current.iov_len << "}" << endl; 
	      }

	    out << "\t" << "h->msg_control = " << h->msg_control << endl;
	    out << "\t" << "h->msg_controllen = " << h->msg_controllen << endl;
	    out << "\t" << "h->msg_flags = " << h->msg_flags << endl;

	    if (h->msg_control != (void*)NULL && h->msg_controllen > 0)
	      {
		struct cmsghdr *ch = (struct cmsghdr*) h->msg_control;
		out << "\t" << "ch->cmsg_len = " << ch->cmsg_len << endl;
		out << "\t" << "ch->cmsg_level = " << ch->cmsg_level << endl;
		out << "\t" << "ch->cmsg_type = " << ch->cmsg_type << endl;

		out << "\t" << "ch->cmsg_level string = " << parse_domain(ch->cmsg_level) << endl;
		out << "\t" << "ch->cmsg_type = " << parse_type(ch->cmsg_type) << endl;
	      }

	  }
      }
      break;
    default:
      break;
    }

  out << socketcalls[call_number] << "() returning." << endl;
}

/* ===================================================================== */

GLOBALFUN VOID HandleSysEnd(THREADID threadIndex, CONTEXT *ctxt, 
		  SYSCALL_STANDARD std, VOID *v)
{
  if (!outstanding_syscall)
    {
      out << "[WARNING]: SysEnd() Interruptable " 
	   << "System Call Situation" << endl;
    }
 
  string name = syscalls[last_syscall_number];
  out << name << "() called." << endl;

  //      ADDRINT return_value = PIN_GetSyscallReturn(ctxt, std);
  switch( last_syscall_number )
    {
    case 0:
      // restart() 
      break;
    case 1:
     {
	// exit()
	ADDRINT status = PIN_GetSyscallArgument(ctxt, std, 0);
	out << "\t" << "exit status = " << status << endl;
      }
      break;
    case 2:
      // fork()
      {
	ADDRINT pid = PIN_GetSyscallReturn(ctxt, std);
	out << "\t" << "pid = " << pid << endl;
      }
      break;
    case 3:
      // read()
      {      
	ADDRINT fd = PIN_GetSyscallArgument(ctxt, std, 0);
	void *buf = (void*) PIN_GetSyscallArgument(ctxt, std, 1);
	size_t count = (size_t) PIN_GetSyscallArgument(ctxt, std, 2);
	ssize_t bytes_read = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "fd = " << fd << endl;
	out << "\t" << "pBuf = " << hex << buf << dec << endl;
	out << "\t" << "count = " <<  count << endl;
	out << "\t" << "bytes read = " << bytes_read << endl;
	
	if (bytes_read > 0)
	  {
	    out << "\t" << "buf contents:" << endl;
	    ssize_t byte_num = 0;
	    while (byte_num < bytes_read)
	      {
		out << "\t" << "buf[" << byte_num << "] = " << ((uint8_t*)buf)[byte_num] << endl;
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
	
	out << "\t" << "fd = " << fd << endl;
	out << "\t" << "pBuf = " << hex << buf << dec << endl;
	out << "\t" << "count = " <<  count << endl;
	out << "\t" << "bytes written = " << bytes_written << endl;
	
	if (bytes_written > 0)
	  {
	    out << "\t" << "buf contents:" << endl;
	    ssize_t byte_num = 0;
	    while (byte_num < bytes_written)
	      {
		out << "\t" << "buf[" << byte_num << "] = " << ((uint8_t*)buf)[byte_num] << endl;
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
	
	out << "\t" << "path = " << string(pathname) << endl;
	out << "\t" << "flags = " << flags << endl;
	out << "\t" << "mode = " <<  mode << endl;
	out << "\t" << "fd = " << fd << endl;
      }
      break;
    case 6:
      // close ()
      {
	int fd = PIN_GetSyscallArgument(ctxt, std, 0);
	int status = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "fd = " << fd << endl;
	out << "\t" << "status = " << status << endl;
      }
      break;
    case 7:
      // waitpid()
      {
	pid_t pid = (pid_t)PIN_GetSyscallArgument(ctxt, std, 0);
	int* status = (int*)PIN_GetSyscallArgument(ctxt, std, 1);
	int options = PIN_GetSyscallArgument(ctxt, std, 2);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "pid = " << pid << endl;
	out << "\t" << "pStatus = " << status << endl;
	out << "\t" << "options = " << options << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
	
	if (status != (int*)NULL)
	  {
	    UINT32 val = 0;
	    PIN_SafeCopy(&val, status, 4);
	    out << "\t" << "status = " << val << endl;
	  }
      }
      break;
    case 8:
      // creat()
      {
	char* pathname = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	int mode = PIN_GetSyscallArgument(ctxt, std, 1);
	int fd = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "path = " << string(pathname) << endl;
	out << "\t" << "mode = " <<  mode << endl;
	out << "\t" << "fd = " << fd << endl;
      }
      break;
    case 39:
      // mkdir()
      {
	char* pathname = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	int mode = PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "path = " << string(pathname) << endl;
	out << "\t" << "mode = " <<  mode << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
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
	
	out << "\t" << "path = " << string(pathname) << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
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
	
	out << "\t" << "old path = " << string(old_pathname) << endl;
	out << "\t" << "new path = " << string(new_pathname) << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 10:
      // unlink()
      {
	char* pathname = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "path = " << string(pathname) << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 11:
      // execve()
      {
	char* pathname = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	char **argv = (char**)PIN_GetSyscallArgument(ctxt, std, 1);
	char **envp = (char**)PIN_GetSyscallArgument(ctxt, std, 2);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	out << "\t" << "path = " << string(pathname) << endl;
	out << "\t" << "argv = " << argv << endl;
	out << "\t" << "envp = " << envp << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
	
	for (int i = 0; argv[i]; i++)
	  {
	    out << "\t" << "argv[" << i << "] = " << string(argv[i]) << endl;
	  }

	 for (int i = 0; envp[i]; i++)
	   {
	     out << "\t" << "envp[" << i << "] = " << string(envp[i]) << endl;
	   }

       }
       break;
    case 12:
      // chdir()
      {
	char* pathname = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "path = " << string(pathname) << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 13:
      // time()
      {
	time_t* t = (time_t*)PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "t = " << t << endl;
	out << "\t" << "ret_val = " << ret_val << endl;

	if (t != (time_t*)NULL)
	  {
	    out << "\t" << "*t = " << *t << endl;
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
	
	out << "\t" << "path = " << string(pathname) << endl;
	out << "\t" << "mode = " << mode << endl;
	out << "\t" << "dev = " << dev << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
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

	out << "\t" << "path = " << string(pathname) << endl;
	out << "\t" << "mode = " << mode << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 94:
      // fchmod()
      {
	int fd = PIN_GetSyscallArgument(ctxt, std, 0);
	mode_t mode = (mode_t)PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	out << "\t" << "fd = " << fd << endl;
	out << "\t" << "mode = " << mode << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
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

	out << "\t" << "path = " << string(pathname) << endl;
	out << "\t" << "mode = " << mode << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 207:
      // fchown32()
      {
	int fd = PIN_GetSyscallArgument(ctxt, std, 0);
	int owner = PIN_GetSyscallArgument(ctxt, std, 1);
	int group = PIN_GetSyscallArgument(ctxt, std, 2);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	out << "\t" << "fd = " << fd << endl;
	out << "\t" << "owner = " << owner << endl;
	out << "\t" << "group = " << group << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 194:
      // ftruncate64
      {
        int fd = PIN_GetSyscallArgument(ctxt, std, 0);
	off_t length = (off_t)PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	out << "\t" << "fd = " << fd << endl;
	out << "\t" << "length = " << length << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
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
      out << "\t" << "(*** warning :: unimplemented sys call)" << endl;
      break;
    case 18:
      // oldstat()
      out << "\t" << "(*** warning :: obsolete sys call)" << endl;
      break;
    case 19:
      // lseek()
      {
	int fd = PIN_GetSyscallArgument(ctxt, std, 0);
	off_t offset = (off_t)PIN_GetSyscallArgument(ctxt, std, 1);
	int whence  = PIN_GetSyscallArgument(ctxt, std, 2);
	off_t ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "fd = " << fd << endl;
	out << "\t" << "offset = " << offset << endl;
	out << "\t" << "whence = " << whence << endl;
	out << "\t" << "ret_offset = " << ret_val << endl;
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
	out << "\t" << "pid = " << pid << endl;
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
	
	out << "\t" << "source = " << string(source) << endl;
	out << "\t" << "target = " << string(target) << endl;
	out << "\t" << "fs_type = " << string(fs_type) << endl;
	out << "\t" << "flags = " << flags << endl;
	out << "\t" << "pData = " << data << endl;
	out << "\t" << "ret_val = " << ret_val << endl;

	// risky
	out << "\t" << "data string = " << string((char*)data) << endl;
      }
      break;
    case 22:
      // umount()
      {
	char* target = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "target = " << string(target) << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 52:
      // umount2()
      {
	char* target = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	int flags = PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "target = " << string(target) << endl;
	out << "\t" << "flags = " << flags << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
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
	
	out << "\t" << "id = " << id << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
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
	out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
      
    case 25:
      // stime()
      {
	time_t* t = (time_t*)PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "t = " << t << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
	if (t != (time_t*)NULL)
	  {
	    out << "\t" << "*t = " << *t << endl;
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

	out << "\t" << "req = " << request << endl;
	out << "\t" << "pid = " << pid << endl;
	out << "\t" << "addr = " << addr << endl;
	out << "\t" << "data = " << data << endl;
	out << "\t" << "( warning :: addr/data are pointers )" << endl;
      }
      break;
    case 27:
      // alarm()
      {
	unsigned int seconds = (unsigned int) PIN_GetSyscallArgument(ctxt, std, 0);
	unsigned int ret_val = (unsigned int) PIN_GetSyscallReturn(ctxt, std);

	out << "\t" << "seconds = " << seconds << endl;
	out << "\t" << "seconds remaining for prev alarm = " << ret_val  << endl;
      }
      break;
    case 28:
      // oldfstat()
      out << "\t" << "(*** warning :: obsolete sys call)" << endl;
      break;
    case 29:
      // pause()
      {
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	out << "\t" << "ret_val  = " << ret_val << endl;
      }
      break;
    case 30:
      // utime()
      {
	char* filename = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	struct utimbuf* times = (struct utimbuf*) PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "filename = " << string(filename) << endl;
	out << "\t" << "times = " << times << endl;
	out << "\t" << "ret_val = " << ret_val << endl;

	if (times != (struct utimbuf*)NULL)
	  {
	    out << "\t" << "times->actime = " << times->actime << endl;
	    out << "\t" << "times->modtime = " << times->modtime << endl;
	  }
      }
      break;
    case 271:
      // utimes()
      {
	char* filename = (char*)PIN_GetSyscallArgument(ctxt, std, 0);
	struct timeval* times = (struct timeval*) PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "filename = " << string(filename) << endl;
	out << "\t" << "times = " << times << endl;
	out << "\t" << "ret_val = " << ret_val << endl;

	if (times != (struct timeval*)NULL)
	  {
	    out << "\t" << "times[0] = " << times[0].tv_sec << " " << times[0].tv_usec << endl;
	    out << "\t" << "times[1] = " << times[1].tv_sec << " " << times[1].tv_usec << endl;
	  }
      }
      break;
    case 34:
      // nice()
      {
	int inc = PIN_GetSyscallArgument(ctxt, std, 0);
	int status = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "inc = " << inc << endl;
	out << "\t" << "status = " << status << endl;
      }
      break;
    case 36:
      // sync()
      out << "(void) -> (void)" << endl;
      break;
    case 37:
      // kill()
      {
	pid_t pid = PIN_GetSyscallArgument(ctxt, std, 0);
	int sig = PIN_GetSyscallArgument(ctxt, std, 1);
	int status = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "pid = " << pid << endl;
	out << "\t" << "sig = " << sig << endl;
	out << "\t" << "status = " << status << endl;
      }
      break;

    case 41:
      // dup()
      {
	int oldfd = PIN_GetSyscallArgument(ctxt, std, 0);
	int ret = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "old_fd = " << oldfd << endl;
	out << "\t" << "ret = " << ret << endl;
      }
      break;
    case 63:
      // dup2()
      {
	int oldfd = PIN_GetSyscallArgument(ctxt, std, 0);
	int newfd = PIN_GetSyscallArgument(ctxt, std, 1);
	int ret = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "old_fd = " << oldfd << endl;
	out << "\t" << "new_fd = " << newfd << endl;
	out << "\t" << "ret = " << ret << endl;
      }
      break;
    case 42:
      // pipe()
      {
	int* pipefd = (int*)PIN_GetSyscallArgument(ctxt, std, 0);
	int ret = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "pipe_fd = " << pipefd << endl;
	out << "\t" << "ret = " << ret << endl;
	
	if (pipefd != (int*)NULL)
	  {
	    out << "\t" << "pipe_fd[0] = " << pipefd[0] << endl;
	    out << "\t" << "pipe_fd[1] = " << pipefd[1] << endl;
	  }
      }
      break;
    case 43:
      // times()
	{
	  struct tms* buf = (struct tms*)PIN_GetSyscallArgument(ctxt, std, 0);
	  clock_t ret = (clock_t)PIN_GetSyscallReturn(ctxt, std);

	  out << "\t" << "buf = " << buf << endl;
	  out << "\t" << "ret = " << ret << endl;
	  
	  if (buf != (struct tms*)NULL)
	    {
	      out << "\t" << "buf->utime = " << buf->tms_utime << endl;
	      out << "\t" << "buf->stime = " << buf->tms_stime << endl;
	      out << "\t" << "buf->cutime = " << buf->tms_cutime << endl;
	      out << "\t" << "buf->cstime = " << buf->tms_cstime << endl;
	    }
	}
	break;
    case 45:
      // brk()
      {
	void* addr = (void*)PIN_GetSyscallArgument(ctxt, std, 0);
	int ret = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "addr = " << addr << endl;
	out << "\t" << "ret = " << ret << endl;
      }
      break;
    case 48:
      // signal()
      {
	int signum = PIN_GetSyscallArgument(ctxt, std, 0);
	sighandler_t handler = (sighandler_t)PIN_GetSyscallArgument(ctxt, std, 1);
	sighandler_t ret = (sighandler_t)PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "signum = " << signum << endl;
	out << "\t" << "handler = " << handler << endl;
	out << "\t" << "ret = " << ret << endl;
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
	
	out << "\t" << "signum = " << signum << endl;
	out << "\t" << "act = " << act << endl;
	out << "\t" << "old = " << old << endl;
	out << "\t" << "ret = " << ret << endl;

	if (act != (struct sigaction*) NULL)
	  {
	    out << "\t" << "act->sa_handler = " << act->sa_handler << endl;
	    out << "\t" << "act->sa_sigaction = " << act->sa_sigaction << endl;
	    out << "\t" << "act->sa_mask = (*** skipped *** )" << endl;
	    out << "\t" << "act->sa_flags = " << act->sa_flags << endl;
	    out << "\t" << "act->sa_restorer = " << act->sa_restorer << endl;
	  }

	if (old != (struct sigaction*) NULL)
	  {
	    out << "\t" << "old->sa_handler = " << old->sa_handler << endl;
	    out << "\t" << "old->sa_sigaction = " << old->sa_sigaction << endl;
	    out << "\t" << "old->sa_mask = (*** skipped *** )" << endl;
	    out << "\t" << "old->sa_flags = " << old->sa_flags << endl;
	    out << "\t" << "old->sa_restorer = " << old->sa_restorer << endl;
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
	
	out << "\t" << "d = " << d << endl;
	out << "\t" << "req = " << req << endl;
	out << "\t" << "argp = " << ((void*)argp) << endl;
	out << "\t" << "ret_val = " << ret_val << endl;

	// risky
	out << "\t" << "*argp = " << string(argp) << endl;
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
	
	out << "\t" << "fd = " << fd << endl;
	out << "\t" << "cmd = " << cmd << endl;
	out << "\t" << "arg = " << arg << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 57:
      // setpgid()
      {
	pid_t pid = PIN_GetSyscallArgument(ctxt, std, 0);
	pid_t pgid = PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	out << "\t" << "pid = " << pid << endl;
	out << "\t" << "pgid = " << pgid << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 59:
      // oldolduname()
    case 122:
      // uname()
      {
	struct utsname* buf = (struct utsname*) PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	out << "\t" << "buf = " << buf << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
	
	if (buf != (struct utsname*)NULL)
	  {
	    out << "\t" << "buf->sysname = " << string(buf->sysname) << endl;
	    out << "\t" << "buf->nodename = " << string(buf->nodename) << endl;
	    out << "\t" << "buf->release = " << string(buf->release) << endl;
	    out << "\t" << "buf->version = " << string(buf->version) << endl;
	    out << "\t" << "buf->machine = " << string(buf->machine) << endl;
	    out << "\t" << "buf->domainname = " << string(buf->domainname) << endl;
	  }
      }
      break;
    case 60:
      // umask()
      {
	mode_t mask = PIN_GetSyscallArgument(ctxt, std, 0);
       	mode_t ret_val = PIN_GetSyscallReturn(ctxt, std);

	out << "\t" << "mask = " << mask << endl;
	out << "\t" << "prev_mask = " << ret_val << endl;

      }
      break;
    case 62:
      // ustat()
      {
	dev_t dev = (dev_t)PIN_GetSyscallArgument(ctxt, std, 0);
	struct ustat* ubuf = (struct ustat*) PIN_GetSyscallArgument(ctxt, std, 1);
        int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "dev = " << dev << endl;
	out << "\t" << "ubuf = " << ubuf << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
	
	if (ubuf != (struct ustat*)NULL)
	  {
	    out << "\t" << "ubuf->f_tfree = " << ubuf->f_tfree << endl;
	    out << "\t" << "ubuf->f_tinode = " << ubuf->f_tinode << endl;
	    out << "\t" << "ubuf->f_fname = " << string(ubuf->f_fname) << endl;
	  }
      }
      break;

    case 68:
      // sgetmask()
      {
	long ret_val = (long)PIN_GetSyscallReturn(ctxt, std);
	out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 69:
      // ssetmask()
      {
	long new_mask = (long)PIN_GetSyscallArgument(ctxt, std, 0);
	long ret_val = (long)PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "newmask = " << new_mask << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
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
	
	out << "\t" << "rid = " << rid << endl;
	out << "\t" << "eid = " << eid << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 72:
      // sigsuspend()
    case 73:
      // sigpending()
      {
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "mask = (*** skipped *** )" << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
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

	out << "\t" << "name = " << string(buf) << endl;	
	out << "\t" << "ret_val = " << ret_val << endl;	
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

	out << "\t" << "resource = " << resource << endl;	
	out << "\t" << "r = " << r << endl;	
	out << "\t" << "ret_val = " << ret_val << endl;	
	
	if (r != (struct rlimit*)NULL)
	  {
	    out << "\t" << "r->rlim_cur = " << r->rlim_cur << endl;	
	    out << "\t" << "r->rlim_max = " << r->rlim_max << endl;	
	  }
      }
      break;
    case 77:
      // getrusage()
      {
	int who = PIN_GetSyscallArgument(ctxt, std, 0);
	struct rusage* r = (struct rusage*)PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	out << "\t" << "who = " << who << endl;	
	out << "\t" << "r = " << r << endl;	
	out << "\t" << "ret_val = " << ret_val << endl;	
	
	if (r != (struct rusage*)NULL)
	  {
	    out << "\t" << "r->ru_utime.tv_sec = " << r->ru_utime.tv_sec << endl;	
	    out << "\t" << "r->ru_utime.tv_usec = " << r->ru_utime.tv_usec << endl;	
	    out << "\t" << "r->ru_stime.tv_sec = " << r->ru_stime.tv_sec << endl;	
	    out << "\t" << "r->ru_stime.tv_usec = " << r->ru_stime.tv_usec << endl;	

	    out << "\t" << "r->ru_maxrss = " << r->ru_maxrss << endl;	
	    out << "\t" << "r->ru_ixrss = " << r->ru_ixrss << endl;	
	    out << "\t" << "r->ru_idrss = " << r->ru_idrss << endl;	
	    out << "\t" << "r->ru_isrss = " << r->ru_isrss << endl;	
	    out << "\t" << "r->ru_minflt = " << r->ru_minflt << endl;	
	    out << "\t" << "r->ru_majflt = " << r->ru_majflt << endl;	
	    out << "\t" << "r->ru_nswap = " << r->ru_nswap << endl;	
	    out << "\t" << "r->ru_inblock = " << r->ru_inblock << endl;	
	    out << "\t" << "r->ru_oublock = " << r->ru_oublock << endl;	
	    out << "\t" << "r->ru_msgsnd = " << r->ru_msgsnd << endl;	
	    out << "\t" << "r->ru_msgrcv = " << r->ru_msgrcv << endl;	
	    out << "\t" << "r->ru_nsignals = " << r->ru_nsignals << endl;	
	    out << "\t" << "r->ru_nvcsw = " << r->ru_nvcsw << endl;	
	    out << "\t" << "r->ru_nivcsw = " << r->ru_nivcsw << endl;	
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

	out << "\t" << "tv = " << tv << endl;	
	out << "\t" << "tz = " << tz << endl;	
	out << "\t" << "ret_val = " << ret_val << endl;	

	if (tv != (struct timeval*)NULL)
	  {
	    out << "\t" << "tv->tv_sec = " << tv->tv_sec << endl;	
	    out << "\t" << "tv->tv_usec = " << tv->tv_usec << endl;	
	  }

	if (tz != (struct timezone*)NULL)
	  {
	    out << "\t" << "tz->tz_minuteswest = " << tz->tz_minuteswest << endl;	
	    out << "\t" << "tz->tz_dsttime = " << tz->tz_dsttime << endl;	
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
      
	out << "\t" << "size = " << size << endl;	
	out << "\t" << "list = " << list << endl;	
	out << "\t" << "ret_val = " << ret_val << endl;	

	if (list != (gid_t*)NULL)
	  {
	    int i = 0;
	    for (i = 0; i < size; i++)
	      {
		out << "\t" << "list[" << i << "] = " << list[i] << endl;	
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
      
	out << "\t" << "addr = " << addr << endl;	
	out << "\t" << "length = " << length << endl;	
	out << "\t" << "prot = " << prot << endl;	
	out << "\t" << "flags = " << flags << endl;	
	out << "\t" << "fd = " << fd << endl;	
	out << "\t" << "pgoffset = " << pgoffset << endl;	
	out << "\t" << "ret_val = " << ret_val << endl;	
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

	out << "\t" << "path = " << string(path) << endl;	
	out << "\t" << "buf = " << buf << endl;	
	out << "\t" << "ret_val = " << ret_val << endl;	

	if (buf != (struct stat64*)NULL)
	  {
	    out << "\tbuf->st_dev:" << buf->st_dev << endl;
	    out << "\tbuf->st_ino:" << buf->st_ino << endl;
	    out << "\tbuf->st_mode:" << buf->st_mode << endl;
	    out << "\tbuf->st_nlink:" << buf->st_nlink << endl;
	    out << "\tbuf->st_uid:" << buf->st_uid << endl;
	    out << "\tbuf->st_gid:" << buf->st_gid << endl;
	    out << "\tbuf->st_rdev:" << buf->st_rdev << endl;
	    out << "\tbuf->st_size:" << buf->st_size << endl;
	    out << "\tbuf->st_atime:" << buf->st_atime << endl;
	    out << "\tbuf->st_mtime:" << buf->st_mtime << endl;
	    out << "\tbuf->st_ctime:" << buf->st_ctime << endl;
	    out << "\tbuf->blk_size:" << buf->st_blksize << endl;
	    out << "\tbuf->st_blocks:" << buf->st_blocks << endl;
	  }
      }
      break;
    case 197:
      // fstat64()
      {
	int fd = PIN_GetSyscallArgument(ctxt, std, 0);
	struct stat64 *buf = (struct stat64 *)PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);

	out << "\t" << "fd = " << fd << endl;	
	out << "\t" << "buf = " << buf << endl;	
	out << "\t" << "ret_val = " << ret_val << endl;	

	if (buf != (struct stat64*)NULL)
	  {
	    out << "\tbuf->st_dev:" << buf->st_dev << endl;
	    out << "\tbuf->st_ino:" << buf->st_ino << endl;
	    out << "\tbuf->st_mode:" << buf->st_mode << endl;
	    out << "\tbuf->st_nlink:" << buf->st_nlink << endl;
	    out << "\tbuf->st_uid:" << buf->st_uid << endl;
	    out << "\tbuf->st_gid:" << buf->st_gid << endl;
	    out << "\tbuf->st_rdev:" << buf->st_rdev << endl;
	    out << "\tbuf->st_size:" << buf->st_size << endl;
	    out << "\tbuf->st_atime:" << buf->st_atime << endl;
	    out << "\tbuf->st_mtime:" << buf->st_mtime << endl;
	    out << "\tbuf->st_ctime:" << buf->st_ctime << endl;
	    out << "\tbuf->blk_size:" << buf->st_blksize << endl;
	    out << "\tbuf->st_blocks:" << buf->st_blocks << endl;
	  }
      }
      break;
    case 243:
      // set_thread_area()
      {
	struct user_desc *u_info = (struct user_desc*)PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "u_info = " << u_info << endl;	
	out << "\t" << "ret_val = " << ret_val << endl;	

	if (u_info != (struct user_desc*)NULL)
	  {

	    out << "\t" << "u_info->entry_number = " << u_info->entry_number << endl;	
	  }
      }
      break;
    case 125:
      // mprotect()
      {
	void* addr = (void*)PIN_GetSyscallArgument(ctxt, std, 0);
	size_t length = (size_t)PIN_GetSyscallArgument(ctxt, std, 1);
	int prot = PIN_GetSyscallArgument(ctxt, std, 2);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
      
	out << "\t" << "addr = " << addr << endl;	
	out << "\t" << "length = " << length << endl;	
	out << "\t" << "prot = " << prot << endl;	
	out << "\t" << "ret_val = " << ret_val << endl;	
      }
      break;
    case 91:
      // munmap()
      {
	void* addr = (void*)PIN_GetSyscallArgument(ctxt, std, 0);
	size_t length = (size_t)PIN_GetSyscallArgument(ctxt, std, 1);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
      
	out << "\t" << "addr = " << addr << endl;	
	out << "\t" << "length = " << length << endl;	
	out << "\t" << "ret_val = " << ret_val << endl;	
      }
      break;
    case 258:
      // set_tid_address()
      {
	int* tidptr = (int*)PIN_GetSyscallArgument(ctxt, std, 0);
	long ret_val = (long)PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "tidptr = " << tidptr << endl;	
	out << "\t" << "pid = " << ret_val << endl;	
	
	if (tidptr != (int*)NULL)
	  {
	    out << "\t" << "*tidptr = " << *tidptr << endl;	
	  }
      }
      break;
    case 311:
      // set_robust_list()
      {
	struct robust_list_head *head = (struct robust_list_head*)PIN_GetSyscallArgument(ctxt, std, 0);
	size_t len = (size_t) PIN_GetSyscallArgument(ctxt, std, 1);
	long ret_val = (long)PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "head = " << head << endl;
	out << "\t" << "len = " << len << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;
    case 240:
      // futex()
      {
	int* uaddr = (int*)PIN_GetSyscallArgument(ctxt, std, 0);
	int op = PIN_GetSyscallArgument(ctxt, std, 1);
	int val = PIN_GetSyscallArgument(ctxt, std, 2);
	struct timespec *timeout = (struct timespec*) PIN_GetSyscallArgument(ctxt, std, 3);
	int* uaddr2 = (int*)PIN_GetSyscallArgument(ctxt, std, 4);
	int val3 = PIN_GetSyscallArgument(ctxt, std, 5);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "uaddr = " << uaddr << endl;
	out << "\t" << "op = " << op << endl;
	out << "\t" << "val = " << val << endl;
	out << "\t" << "timeout = " << timeout << endl;
	out << "\t" << "uaddr2 = " << uaddr2 << endl;
	out << "\t" << "val3 = " << val3 << endl;
	out << "\t" << "ret_val = " << ret_val << endl;

	if (timeout != (struct timespec*)NULL)
	  {
	    out << "\t" << "timeout->tv_sec = " << timeout->tv_sec << endl;
	    out << "\t" << "timeout->tv_nsec = " << timeout->tv_nsec << endl;
	  }
	

      }
      break;
    case 175:
      // rt_sigprockmask()
      {
	int how = PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "how = " << how << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
	out << "\t" << "set = (*** skipped *** )" << endl;
	out << "\t" << "old_set = (*** skipped *** )" << endl;
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
	
	out << "\t" << "fd = " << fd << endl;
	out << "\t" << "off_h = " << off_h << endl;
	out << "\t" << "off_l = " << off_l << endl;
	out << "\t" << "result = " << result << endl;
	out << "\t" << "whence = " << whence << endl;	
	out << "\t" << "ret_val = " << ret_val << endl;

	if (result != (loff_t*)NULL)
	  {
	    out << "\t" << "*result = " << *result << endl;
	  }
      }
      break;
    case 254:
      // epoll_create()
      {
	int size = PIN_GetSyscallArgument(ctxt, std, 0);
	int ret_val = PIN_GetSyscallReturn(ctxt, std);
	
	out << "\t" << "size = " << size << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
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
	
	out << "\t" << "epfd = " << epfd << endl;
	out << "\t" << "op = " << op << endl;
	out << "\t" << "fd = " << fd << endl;
	out << "\t" << "event = " << event << endl;
	out << "\t" << "ret_val = " << ret_val << endl;

	if (event != (struct epoll_event*)NULL)
	  {
	    out << "\t" << "event->events = " << event->events << endl;
	    out << "\t" << "event->data = " << (event->data.u32) << endl;
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
	
	out << "\t" << "fd = " << fd << endl;
	out << "\t" << "d = " << d << endl;
	out << "\t" << "count = " << count << endl;
	out << "\t" << "ret_val = " << ret_val << endl;

	out << "\t" << "actual entries in d = (*** skipped *** )" << endl;
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
	
	out << "\t" << "fn = " << fn << endl;
	out << "\t" << "child_stack = " << child_stack << endl;
	out << "\t" << "flags = " << flags << endl;
	out << "\t" << "arg = " << arg << endl;
	out << "\t" << "ret_val = " << ret_val << endl;
      }
      break;

    case 102:
      // socketcall()
      HandleSocketCall(threadIndex, ctxt, std, v);
      break;
    
    default:
      out << "<---------UNHANDLED (" << last_syscall_number << ")-------->" << endl;	
      break;
    }     
  
  name = syscalls[last_syscall_number];
  out << name << "() returning." << endl;
  outstanding_syscall=false;
  return;
}

/* ===================================================================== */
VOID HandleSysBegin(THREADID threadIndex, CONTEXT *ctxt, 
		    SYSCALL_STANDARD std, VOID *v)
{
  if (outstanding_syscall)
    {
      out << "[WARNING]: SysBegin() Interruptable " 
	   << "System Call Situation" << endl;
    }
  
  last_syscall_number = PIN_GetSyscallNumber(ctxt, std);
  out << "SysBegin(): " << syscalls[last_syscall_number] << endl;
  outstanding_syscall = true;
}
