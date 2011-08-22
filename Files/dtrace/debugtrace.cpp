#include "pin.H"
#include "instlib.H"
#include "portability.H"

using namespace INSTLIB;

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
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_link.h>

#include "syscalls_printer_mult.h"
#include "syscall_utils.h"

#define DEBUG 1
#define DEBUG_MEMORY 1

#include <errno.h>

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

// Important Options
KNOB<string> KnobSysFile(KNOB_MODE_WRITEONCE, "pintool",
			    "sysfile", "systracer.out", "syscalls output file");
KNOB<BOOL>   KnobTraceSys(KNOB_MODE_WRITEONCE,  "pintool",
		       "sys", "1", "determinize sys calls");

// Syscalls

// --------------------------------------------------------
KNOB<string> KnobAtRandomAddress(KNOB_MODE_WRITEONCE,  "pintool",
				 "atraddr", "0", "at random addr");
KNOB<BOOL>   KnobFixPid(KNOB_MODE_WRITEONCE,  "pintool",
		       "pid", "0", "determinize pid");
KNOB<BOOL>   KnobFixStat(KNOB_MODE_WRITEONCE,  "pintool",
			 "stat", "0", "determinize stat");
KNOB<BOOL>   KnobFixNetInit(KNOB_MODE_WRITEONCE,  "pintool",
			    "netinit", "0", "determinize netlink/socket");
KNOB<BOOL>   KnobFixTime(KNOB_MODE_WRITEONCE,  "pintool",
			 "time", "0", "determinize time");
KNOB<BOOL> KnobEpoll(KNOB_MODE_WRITEONCE, "pintool",
			    "epoll", "0", "order epolls");
KNOB<BOOL> KnobDevRandom(KNOB_MODE_WRITEONCE, "pintool",
			   "devrand", "0", "trace file");
KNOB<BOOL> KnobFixFork(KNOB_MODE_WRITEONCE, "pintool",
			 "fix_fork", "0", "trace file");
KNOB<BOOL> KnobFixPorts(KNOB_MODE_WRITEONCE, "pintool",
			"ports", "0", "fix ephemeral ports");
KNOB<BOOL> KnobFixSignals(KNOB_MODE_WRITEONCE, "pintool",
			  "sig", "0", "fix signals");

KNOB<BOOL> KnobFixAdjustTimex(KNOB_MODE_WRITEONCE, "pintool",
			  "timex", "0", "fix adjtimex");
// --------------------------------------------------------

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
			    "o", "trace.log", "trace file");
KNOB<string> KnobTimeFile(KNOB_MODE_WRITEONCE, "pintool",
			    "timefile", "time.out", "trace file");
KNOB<string> KnobClockFile(KNOB_MODE_WRITEONCE, "pintool",
			   "clockfile", "clock.out", "clock trace file");
KNOB<string> KnobAdjTimexFile(KNOB_MODE_WRITEONCE, "pintool",
			      "adjtimexfile", "adjtimex.out", "adjtimex trace file");
KNOB<string> KnobSignalFile(KNOB_MODE_WRITEONCE, "pintool",
			   "signalfile", "signal.out", "signal trace file");

KNOB<string> KnobDayFile(KNOB_MODE_WRITEONCE, "pintool",
			    "dayfile", "day.out", "trace file");
KNOB<string> KnobEpollFile(KNOB_MODE_WRITEONCE, "pintool",
			    "epollfile", "epoll.out", "epoll trace file");

KNOB<BOOL> KnobLeader(KNOB_MODE_WRITEONCE, "pintool",
		      "leader", "1", "trace file");

KNOB<BOOL>   KnobSymbols(KNOB_MODE_WRITEONCE, "pintool",
			 "symbols", "0", "include symbol information");
KNOB<BOOL>   KnobRdtsc(KNOB_MODE_WRITEONCE,  "pintool",
		       "rdtsc", "0", "emulate rdtsc");

KNOB<BOOL>   KnobCpuid(KNOB_MODE_WRITEONCE,  "pintool",
		       "cpuid", "0", "emulate cpuid");

KNOB<BOOL>   KnobMem(KNOB_MODE_WRITEONCE,  "pintool",
		     "dmem", "0", "dump process memory");
KNOB<BOOL>   KnobPrintFunc(KNOB_MODE_WRITEONCE,  "pintool",
			   "print_func", "0", 
			   "print image/func for every instruction");
KNOB<BOOL>   KnobFixCanary(KNOB_MODE_WRITEONCE,  "pintool",
			   "canary", "0", "fix canary or not");
KNOB<BOOL>   KnobFixPointerGuard(KNOB_MODE_WRITEONCE,  "pintool",
				 "guard", "0", "fix pointer guard or not");

KNOB<BOOL>   KnobOptBB(KNOB_MODE_WRITEONCE,  "pintool",
		       "optbb", "0", "one instr per bb or not");
KNOB<string> KnobMemoryFile(KNOB_MODE_WRITEONCE, "pintool",
			    "fmem", "/dev/null", "memory dump file");
// Less Frequently Uosed Options
KNOB<BOOL>   KnobPid(KNOB_MODE_WRITEONCE, "pintool",
		     "i", "0", "append pid to output");
KNOB<THREADID>   KnobWatchThread(KNOB_MODE_WRITEONCE, "pintool",
				 "watch_thread", "-1", 
				 "thread to watch, -1 for all");
KNOB<BOOL>   KnobFlush(KNOB_MODE_WRITEONCE, "pintool",
		       "flush", "0", "Flush output after every instruction");
KNOB<BOOL>   KnobLines(KNOB_MODE_WRITEONCE, "pintool",
		       "lines", "0", "Include line number information");
KNOB<BOOL>   KnobTraceInstructions(KNOB_MODE_WRITEONCE, "pintool",
				   "instruction", "1", "Trace instructions");
KNOB<BOOL>   KnobTraceCalls(KNOB_MODE_WRITEONCE, "pintool",
			    "call", "0", "Trace calls");
KNOB<BOOL>   KnobTraceMemory(KNOB_MODE_WRITEONCE, "pintool",
			     "memory", "0", "Trace memory");
KNOB<BOOL>   KnobSilent(KNOB_MODE_WRITEONCE, "pintool",
			"silent", "0", 
			"Do everything but write file (for debugging).");
KNOB<BOOL> KnobEarlyOut(KNOB_MODE_WRITEONCE, "pintool", "early_out", "0" , 
			"Exit after tracing the first region.");


/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

#if DEBUG_MEMORY
LOCALVAR BOOL armed = 0;
LOCALVAR string print = "A";
LOCALVAR BOOL first_print = 0;
#endif

// -1 => starting phase of program
LOCALVAR int next_signal = -1;
LOCALVAR UINT64 next_instr_num = 0;
LOCALVAR BOOL signal_eof = 0; 

// the first instruction flag is used to dump memory
LOCALVAR INT32 firstInstruction = 1;
LOCALVAR std::ofstream outmem;

LOCALVAR BOOL forked = 0;

// signal output stream
LOCALVAR std::ofstream signal_out;
LOCALVAR std::ifstream signal_in;

// adjtimex output stream
LOCALVAR std::ofstream timex_out;
LOCALVAR std::ifstream timex_in;

// trace output stream
LOCALVAR std::ofstream out;
LOCALVAR std::ofstream sysout;

// timing output stream
LOCALVAR std::ofstream timing_out;
LOCALVAR std::ifstream timing_in;
LOCALVAR std::ofstream gettimeofday_out;
LOCALVAR std::ifstream gettimeofday_in;

// epoll events stream
LOCALVAR std::ifstream epoll_in;
LOCALVAR std::ofstream epoll_out;

// clock output stream
LOCALVAR std::ifstream clock_in;
LOCALVAR std::ofstream clock_out;

GLOBALVAR vector<struct epoll_event*> e;
LOCALVAR struct epoll_event* next;

// set this for every program separately
LOCALVAR ADDRINT AT_RANDOM_ADDRESS; //  = 0xbffff49b;

// system call related stuff
LOCALVAR BOOL outstanding_syscall = false;
LOCALVAR ADDRINT last_syscall_number = 0;

LOCALVAR BOOL canary_done = false;
LOCALVAR BOOL guard_done = false;

// fd for dev_urandom
LOCALVAR vector<ADDRINT> urandom_fds;

// fd for /etc/ files
LOCALVAR vector<ADDRINT> stat_fds;

// my own pid
LOCALVAR int my_original_pid = -1;
LOCALVAR int my_simulated_pid = 0x7003;

// child pids
LOCALVAR map<int,int> pid_child_trans_table;
int next_child_pid = 30000;


// socket
LOCALVAR map<int,int> socket_translation_table;
int next_socket_fd = 60000;

// stored times
LOCALVAR time_t root_dir_time = (time_t)0;
LOCALVAR time_t job_cache_time = (time_t)0;

// instructions executed
LOCALVAR UINT64 instrs = 0;

typedef UINT64 COUNTER;
LOCALVAR INT32 enabled = 0;
LOCALVAR FILTER filter;
LOCALVAR ICOUNT icount;

// Netlink Sockets
LOCALVAR vector<ADDRINT> netlink_sockets;

LOCALFUN BOOL Emit(THREADID threadid)
{
  if (!enabled || 
      KnobSilent || 
      (KnobWatchThread != static_cast<THREADID>(-1) 
       && KnobWatchThread != threadid))
    return false;
  return true;
}

LOCALFUN VOID Flush()
{
  if (KnobFlush)
    out << flush;
}


/* ===================================================================== */

/* ===================================================================== */

LOCALFUN VOID log_epoll(struct epoll_event *events)
{
  epoll_out << "<epoll_begin>" << endl;
  epoll_out << "events[0].events=" << dec << events[0].events << endl;
  epoll_out << "events[0].data.ptr=" << dec << (ADDRINT)events[0].data.ptr << endl; 
  epoll_out << "<epoll_end>" << endl;
}

struct epoll_event* extract_next_epoll_event()
{
  struct epoll_event *next = new struct epoll_event;
  
  ADDRINT val_buf = 0;
  char str[255];
  string tmp;
  
  // <epoll_begin>
  epoll_in.getline(str, 255);  
  tmp = string(str);
  
  if (tmp.find("<epoll_begin>") == string::npos)
    cerr << "error: expected \"<epoll_begin>\" , saw:" << tmp << endl;  
 
  // events[0].events=#
  epoll_in.getline(str, 255);  
  tmp = string(str);
  if (tmp.find("events[0].events=") == string::npos)
    cerr << "error: expected \"events[0].events=#\", saw:" << tmp << endl;  
  tmp = tmp.substr(tmp.find("=") + 1);
  istringstream s6(tmp);
  s6 >> val_buf;
  next->events = val_buf;


  // events[0].data.ptr=#
  epoll_in.getline(str, 255);  
  tmp = string(str);
  if (tmp.find("events[0].data.ptr=") == string::npos)
    cerr << "error: expected \"events[0].data.ptr=#\", saw:" << tmp << endl;  
  tmp = tmp.substr(tmp.find("=") + 1);
  istringstream s7(tmp);
  s7 >> val_buf;
  next->data.ptr = (void*)val_buf;
  
  // <epoll_end>
  epoll_in.getline(str, 255);  
  tmp = string(str);
  if (tmp.find("<epoll_end>") == string::npos)
    cerr << "error: expected \"<epoll_end>\", saw:" << tmp << endl;  
  
  return next;
}


/*
// keep this in case this later needed for debugging
static void print_gs_stuff(ADDRINT baseAddr)
{ 
  UINT32 * pid_address = (UINT32*)((UINT32)baseAddr+0x68);
  UINT32 * canary_address = (UINT32*)((UINT32)baseAddr+0x14);
  UINT32 * guard_address = (UINT32*)((UINT32)baseAddr+0x18);

  cout << "<------ PID = " << dec << (*pid_address) << " ----------->" << endl;
  cout << "<----- CANARY = " << hex << (*canary_address) << "  ------>" << endl;
  cout << "<---- GUARD = " << hex << (*guard_address) << "  ------->" << endl;

  out << "<-------- PID = " << dec  << (*pid_address) << " ----------->" << endl;
  out << "<----- CANARY = " << hex << (*canary_address) << "  -------->" << endl;
  out << "<----- GUARD = " << hex << (*guard_address) << "  -------->" << endl;
} 
*/

static void overwrite_AT_RANDOM()
{
  *((int*)AT_RANDOM_ADDRESS) = 0x12345678;
  cerr << "AT_RANDOM[0] i.e. libc canary src =  0x12345678" << endl;

#if DEBUG
  cout << "AT_RANDOM[0] i.e. libc canary src =  0x12345678" << endl;
#endif
}

static void overwrite_AT_RANDOM_4()
{
  *(((int*)AT_RANDOM_ADDRESS)+1) = 0x87654321;
  cerr << "AT_RANDOM[1] i.e. stack guard src =  0x87654321" << endl;

#if DEBUG
  cout << "AT_RANDOM[1] i.e. stack guard src =  0x87654321" << endl;
#endif
}

INT32 Usage()
{
  cerr <<
      "This pin tool collects an instruction trace for debugging" << endl;
  cerr << KNOB_BASE::StringKnobSummary();
  cerr << endl;
  return -1;
}

// Emulate Cpuid
VOID EmulateCpuid(PIN_REGISTER *rax, PIN_REGISTER *rbx, PIN_REGISTER *rcx,
		  PIN_REGISTER *rdx)
{
  rax->dword[0] = 0x1067a;
  rbx->dword[0] = 0x10800;
  rcx->dword[0] = 0x80082201;
  rdx->dword[0] = 0xfebfbff;
  return;
}

// Move 0x7eab816a into rax
ADDRINT SendToRax()
{
  return 0x7eab816a;
}

// Move 0x6b7 into rdx
ADDRINT SendToRdx()
{
  return 0x6b7;
}

LOCALFUN VOID Fini(int, VOID * v);

LOCALFUN VOID Handler(CONTROL_EVENT ev, VOID *, CONTEXT * ctxt, VOID *, THREADID)
{
  switch(ev)
    {
    case CONTROL_START:
      enabled = 1;
      PIN_RemoveInstrumentation();
#if defined(TARGET_IA32) || defined(TARGET_IA32E)
      // So that the rest of the current trace is re-instrumented.
      if (ctxt) PIN_ExecuteAt (ctxt);
#endif   
      break;
      
    case CONTROL_STOP:
      enabled = 0;
      PIN_RemoveInstrumentation();
      if (KnobEarlyOut)
        {
	  cerr << "Exiting due to -early_out" << endl;
	  Fini(0, NULL);
	  exit(0);
        }
#if defined(TARGET_IA32) || defined(TARGET_IA32E)
      // So that the rest of the current trace is re-instrumented.
      if (ctxt) PIN_ExecuteAt (ctxt);
#endif   
      break;
      
    default:
      ASSERTX(false);
    }
}


/* ===================================================================== */

VOID EmitNoValues(THREADID threadid, string * str)
{
  if (!Emit(threadid))
    return;

  if (KnobFixFork && forked && PIN_GetPid() != my_original_pid)
    return;

  out
    << *str
    << endl;
  
  Flush();
}

VOID Emit1Values(THREADID threadid, string * str, string * reg1str, 
		 ADDRINT reg1val)
{
  if (!Emit(threadid))
    return;

  if (KnobFixFork && forked && PIN_GetPid() != my_original_pid)
    return;
  
  out
    << *str << " $ "
    << *reg1str << " = " << reg1val
    << endl;
  
  Flush();
}

VOID Emit2Values(THREADID threadid, string * str, string * reg1str,
		 ADDRINT reg1val, string * reg2str, ADDRINT reg2val)
{
  if (!Emit(threadid))
    return;

  if (KnobFixFork && forked && PIN_GetPid() != my_original_pid)
    return;
 
  
  out
    << *str << " $ "
    << *reg1str << " = " << reg1val
    << ", " << *reg2str << " = " << reg2val
    << endl;
  
  Flush();
}

VOID Emit3Values(THREADID threadid, string * str, string * reg1str, 
		 ADDRINT reg1val, string * reg2str, 
		 ADDRINT reg2val, string * reg3str, ADDRINT reg3val)
{
  if (!Emit(threadid))
    return;

  if (KnobFixFork && forked && PIN_GetPid() != my_original_pid)
    return;
  
  out
    << *str << " $ "
    << *reg1str << " = " << reg1val
    << ", " << *reg2str << " = " << reg2val
    << ", " << *reg3str << " = " << reg3val
    << endl;
  
  Flush();
}


VOID Emit4Values(THREADID threadid, string * str, string * reg1str, 
		 ADDRINT reg1val, string * reg2str, ADDRINT reg2val, 
		 string * reg3str, ADDRINT reg3val, string * reg4str, 
		 ADDRINT reg4val)
{
  if (!Emit(threadid))
    return;

  if (KnobFixFork && forked && PIN_GetPid() != my_original_pid)
    return;
  
  out
    << *str << " $ "
    << *reg1str << " = " << reg1val
    << ", " << *reg2str << " = " << reg2val
    << ", " << *reg3str << " = " << reg3val
    << ", " << *reg4str << " = " << reg4val
    << endl;
    
  Flush();
}


const UINT32 MaxEmitArgs = 4;

AFUNPTR emitFuns[] = 
  {
    AFUNPTR(EmitNoValues), AFUNPTR(Emit1Values), AFUNPTR(Emit2Values),
    AFUNPTR(Emit3Values), AFUNPTR(Emit4Values)
  };

/* ===================================================================== */
#if !defined(TARGET_IPF)

VOID EmitXMM(THREADID threadid, UINT32 regno, PIN_REGISTER* xmm)
{
  if (!Emit(threadid))
        return;

  if (KnobFixFork && forked && PIN_GetPid() != my_original_pid)
    return;

  out << "\t\t\tXMM" << dec << regno << " := " << setfill('0') << hex;
  out.unsetf(ios::showbase);
  for(int i=0;i<16;i++) {
    if (i==4 || i==8 || i==12)
      out << "_";
    out << setw(2) << (int)xmm->byte[15-i]; // msb on the left as in registers
  }
  out  << setfill(' ') << endl;
  out.setf(ios::showbase);
  Flush();
}

VOID AddXMMEmit(INS ins, IPOINT point, REG xmm_dst) 
{
  INS_InsertCall(ins, point, AFUNPTR(EmitXMM), IARG_THREAD_ID,
		 IARG_UINT32, xmm_dst - REG_XMM0,
		 IARG_REG_CONST_REFERENCE, xmm_dst,
		 IARG_END);
}
#endif

VOID PrintRdtsc(string & traceString)
{
  if (KnobFixFork && forked && PIN_GetPid() != my_original_pid)
    return;

  out << traceString << endl;
}

LOCALFUN VOID read_next_signal()
{
  if (!signal_eof)
    {
      char str[255];
      string tmp;
      
      // signal=#
      signal_in.getline(str, 255);
      tmp = string(str);

      if (tmp.find("eof") != string::npos)
	{
	  signal_eof = 1;
	  next_instr_num = 0;
	  next_signal = 0;
	  return;
	}

      if (tmp.find("signal=") == string::npos)
	cerr << "error: expected \"signal=#\" , saw:" << tmp << endl;  

      tmp = tmp.substr(tmp.find("=")+1);
      istringstream s1(tmp);
      s1 >> dec >> next_signal;

      // instrs=#
      signal_in.getline(str, 255);
      tmp = string(str);
      if (tmp.find("instrs=") == string::npos)
	cerr << "error: expected \"instrs=#\" , saw:" << tmp << endl;  
      tmp = tmp.substr(tmp.find("=")+1);
      istringstream s2(tmp);
      s2 >> dec >> next_instr_num;

      // cerr << "\tnext_signal = " << next_signal << ", next_i = " << next_instr_num << endl;
   } 
}

VOID CountInstruction()
{
  if (KnobFixFork && forked && PIN_GetPid() != my_original_pid)
    return;

  instrs++;
  if (KnobFixSignals)
    {
      if (!KnobLeader && !signal_eof)
	{
	  if (next_signal == -1)
	    {
	      read_next_signal();
	    }
	  if (next_instr_num == instrs)
	    {
	      kill(PIN_GetPid(), next_signal);
	    }
	  else if (next_instr_num < instrs && !signal_eof)
	    {
	      // cerr << "\t WARNING: next_instr = " << next_instr_num 
	      //  << " but instrs = " << instrs << endl;
	      kill(PIN_GetPid(), next_signal);
	    }
	}
    }
}

VOID AddEmit(INS ins, IPOINT point, 
	     string & traceString, UINT32 regCount, REG regs[])
{
  if (regCount > MaxEmitArgs)
    regCount = MaxEmitArgs;
  
    IARGLIST args = IARGLIST_Alloc();
    for (UINT32 i = 0; i < regCount; i++)
      {
        IARGLIST_AddArguments(args, 
			      IARG_PTR, new string(REG_StringShort(regs[i])), 
			      IARG_REG_VALUE, regs[i], IARG_END);
      }
    
    INS_InsertCall(ins, point, emitFuns[regCount], IARG_THREAD_ID,
                   IARG_PTR, new string(traceString),
                   IARG_IARGLIST, args,
                   IARG_END);
    IARGLIST_Free(args);
}

LOCALVAR VOID *WriteEa[PIN_MAX_THREADS];

VOID CaptureWriteEa(THREADID threadid, VOID * addr)
{
  WriteEa[threadid] = addr;
}

VOID ShowN(UINT32 n, VOID *ea)
{
  out.unsetf(ios::showbase);
  // Print out the bytes in "big endian 
  // even though they are in memory little endian.
  // This is most natural for 8B and 16B quantities that show up most frequently.
  // The address pointed to 
  out << std::setfill('0');
  UINT8 b[512];
  UINT8* x;
    if (n > 512)
      x = new UINT8[n];
    else
      x = b;
    PIN_SafeCopy(x,static_cast<UINT8*>(ea),n);    
    for (UINT32 i = 0; i < n; i++)
      {
        out << std::setw(2) <<  static_cast<UINT32>(x[n-i-1]);
        if (((reinterpret_cast<ADDRINT>(ea)+n-i-1)&0x3)==0 && i<n-1)
	  out << "_";
    }
    out << std::setfill(' ');
    out.setf(ios::showbase);
    if (n>512)
      delete [] x;
}


VOID EmitWrite(THREADID threadid, UINT32 size)
{
    if (!Emit(threadid))
        return;

  if (KnobFixFork && forked && PIN_GetPid() != my_original_pid)
    return;
    
    out << "\tWrite ";
    
    VOID * ea = WriteEa[threadid];
    
    switch(size)
    {
      case 0:
        out << "0 repeat count" << endl;
        break;
        
      case 1:
        {
            UINT8 x;
            PIN_SafeCopy(&x, static_cast<UINT8*>(ea), 1);
            out << "*(UINT8*)" << ea << " = " << static_cast<UINT32>(x) << endl;
        }
        break;
        
      case 2:
        {
            UINT16 x;
            PIN_SafeCopy(&x, static_cast<UINT16*>(ea), 2);
            out << "*(UINT16*)" << ea << " = " << x << endl;
        }
        break;
        
      case 4:
        {
	  UINT32 x;
            PIN_SafeCopy(&x, static_cast<UINT32*>(ea), 4);
            out << "*(UINT32*)" << ea << " = " << x << endl;
        }
        break;
        
      case 8:
        {
            UINT64 x;
            PIN_SafeCopy(&x, static_cast<UINT64*>(ea), 8);
            out << "*(UINT64*)" << ea << " = " << x << endl;
        }
        break;
        
      default:
        out << "*(UINT" << dec << size * 8 << hex << ")" << ea << " = ";
        ShowN(size,ea);
        out << endl;
        break;
    }

    Flush();
}

VOID EmitRead(THREADID threadid, VOID * ea, UINT32 size)
{
    if (!Emit(threadid))
        return;
    
    if (KnobFixFork && forked && PIN_GetPid() != my_original_pid)
      return;

    out << "\tRead ";

    switch(size)
    {
      case 0:
        out << "0 repeat count" << endl;
        break;
        
      case 1:
        {
            UINT8 x;
            PIN_SafeCopy(&x,static_cast<UINT8*>(ea),1);
            out << static_cast<UINT32>(x) << " = *(UINT8*)" << ea << endl;
        }
        break;
        
      case 2:
        {
            UINT16 x;
            PIN_SafeCopy(&x,static_cast<UINT16*>(ea),2);
            out << x << " = *(UINT16*)" << ea << endl;
        }
        break;
        
      case 4:
        {
            UINT32 x;
            PIN_SafeCopy(&x,static_cast<UINT32*>(ea),4);

	    /*
	    if (ea == (VOID*)0xb6030718)
	      {
		if (x != (UINT32)my_simulated_pid && my_simulated_pid != -1)
		  {
		    *(int*)ea = my_simulated_pid;
		    x = (UINT32)my_simulated_pid;
		  }

		out << x << " = <after intervention> *(UINT32*)" << ea << endl;
	      }
	    else {	    */
	    out << x << " = *(UINT32*)" << ea << endl;
	    //}

        }
        break;
        
      case 8:
        {
            UINT64 x;
            PIN_SafeCopy(&x,static_cast<UINT64*>(ea),8);
            out << x << " = *(UINT64*)" << ea << endl;
        }
        break;
        
      default:
        ShowN(size,ea);
        out << " = *(UINT" << dec << size * 8 << hex << ")" << ea << endl;
        break;
    }

    Flush();
}


LOCALVAR INT32 indent = 0;

VOID Indent()
{
    for (INT32 i = 0; i < indent; i++)
    {
        out << "| ";
    }
}

VOID EmitICount()
{
  out << setw(10) << dec << icount.Count() << hex << " ";
}

VOID EmitDirectCall(THREADID threadid, string * str, INT32 tailCall, ADDRINT arg0, ADDRINT arg1)
{
    if (!Emit(threadid))
        return;

    if (KnobFixFork && forked && PIN_GetPid() != my_original_pid)
      return;
  
    EmitICount();

    if (tailCall)
    {
        // A tail call is like an implicit return followed by an immediate call
        indent--;
    }
    
    Indent();
    out << *str << "(" << arg0 << ", " << arg1 << ", ...)" << endl;

    indent++;

    Flush();
}

/* ===================================================================== */      
string FormatAddress(ADDRINT address, RTN rtn)
{
    string s = StringFromAddrint(address);
    
    if (KnobSymbols && RTN_Valid(rtn))
    {
        s += " " + IMG_Name(SEC_Img(RTN_Sec(rtn))) + ":";
        s += RTN_Name(rtn);

        ADDRINT delta = address - RTN_Address(rtn);
        if (delta != 0)
        {
            s += "+" + hexstr(delta, 4);
        }
    }

    if (KnobLines)
    {
        INT32 line;
        string file;
        
        PIN_GetSourceLocation(address, NULL, &line, &file);

        if (file != "")
        {
            s += " (" + file + ":" + decstr(line) + ")";
        }
    }
    return s;
}

/* ===================================================================== */      
VOID EmitIndirectCall(THREADID threadid, string * str, ADDRINT target, 
		      ADDRINT arg0, ADDRINT arg1)
{
    if (!Emit(threadid))
        return;

    if (KnobFixFork && forked && PIN_GetPid() != my_original_pid)
    return;

    
    EmitICount();
    Indent();
    out << *str;

    PIN_LockClient();
    
    string s = FormatAddress(target, RTN_FindByAddress(target));
    
    PIN_UnlockClient();
    
    out << s << "(" << arg0 << ", " << arg1 << ", ...)" << endl;
    indent++;

    Flush();
}

/* ===================================================================== */      
VOID EmitReturn(THREADID threadid, string * str, ADDRINT ret0)
{
    if (!Emit(threadid))
        return;
    
  if (KnobFixFork && forked && PIN_GetPid() != my_original_pid)
    return;



    EmitICount();
    indent--;
    if (indent < 0)
    {
        out << "@@@ return underflow\n";
        indent = 0;
    }
    
    Indent();
    out << *str << " returns: " << ret0 << endl;

    Flush();
}
       
/* ===================================================================== */      
VOID CallTrace(TRACE trace, INS ins)
{
    if (!KnobTraceCalls)
        return;

    if (INS_IsCall(ins) && !INS_IsDirectBranchOrCall(ins))
    {
        // Indirect call
        string s = "Call " + FormatAddress(INS_Address(ins), TRACE_Rtn(trace));
        s += " -> ";

        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(EmitIndirectCall), 
		       IARG_THREAD_ID,
                       IARG_PTR, new string(s), IARG_BRANCH_TARGET_ADDR,
                       IARG_G_ARG0_CALLER, IARG_G_ARG1_CALLER, IARG_END);
    }
    else if (INS_IsDirectBranchOrCall(ins))
    {
        // Is this a tail call?
        RTN sourceRtn = TRACE_Rtn(trace);
        RTN destRtn = 
	  RTN_FindByAddress(INS_DirectBranchOrCallTargetAddress(ins));

        if (INS_IsCall(ins)         // conventional call
            || sourceRtn != destRtn // tail call
        )
        {
            BOOL tailcall = !INS_IsCall(ins);
            
            string s = "";
            if (tailcall)
            {
                s += "Tailcall ";
            }
            else
            {
                if( INS_IsProcedureCall(ins) )
                    s += "Call ";
                else
                {
                    s += "PcMaterialization ";
                    tailcall=1;
                }
                
            }

            //s += INS_Mnemonic(ins) + " ";
            
            s += FormatAddress(INS_Address(ins), TRACE_Rtn(trace));
            s += " -> ";

            ADDRINT target = INS_DirectBranchOrCallTargetAddress(ins);
        
            s += FormatAddress(target, RTN_FindByAddress(target));

            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(EmitDirectCall),
                           IARG_THREAD_ID, IARG_PTR, new string(s),
			   IARG_UINT32, tailcall,
                           IARG_G_ARG0_CALLER, IARG_G_ARG1_CALLER, IARG_END);
        }
    }
    else if (INS_IsRet(ins))
    {
        RTN rtn =  TRACE_Rtn(trace);
        
#if defined(TARGET_LINUX) && defined(TARGET_IA32)
//        if( RTN_Name(rtn) ==  "_dl_debug_state") return;
        if( RTN_Valid(rtn) && RTN_Name(rtn) ==  "_dl_runtime_resolve") return;
#endif
        string tracestring = "Return " + FormatAddress(INS_Address(ins), rtn);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(EmitReturn),
                       IARG_THREAD_ID, IARG_PTR, new string(tracestring), 
		       IARG_G_RESULT0, IARG_END);
    }
}

/* ===================================================================== */ 
VOID PrintImageMemory(IMG img) 
{
  if (KnobFixFork && forked && PIN_GetPid() != my_original_pid)
    return;


  outmem << "----------------------------" << endl;
  outmem << "Image: " << IMG_Name(img) << endl;
  outmem << "Image ID:  " << IMG_Id(img) << endl;
  outmem << "Image Type: ";

  outmem.unsetf(ios::showbase);
  outmem << std::setfill('0');

  string typeStr = "";
  if (IMG_Type(img) == IMG_TYPE_STATIC)
    typeStr = string("Static");
  else if (IMG_Type(img) == IMG_TYPE_SHARED)
    typeStr = string("Shared");
  else if (IMG_Type(img) == IMG_TYPE_SHAREDLIB)
    typeStr = string("SharedLib");
  else if (IMG_Type(img) == IMG_TYPE_RELOCATABLE)
    typeStr = string("Relocatable");
  outmem << typeStr << endl;
  
  outmem << "Image Low Address: " << IMG_LowAddress(img) << endl;
  outmem << "Image High Address: " << IMG_HighAddress(img) << endl;
  
  UINT8* start = (UINT8*)IMG_LowAddress(img);
  UINT8* end = (UINT8*)IMG_HighAddress(img);
  UINT8* current = start;
  
  UINT32 buffer[128];
  while ((end - current) >= 511) {
    PIN_SafeCopy(buffer, current, 512);
    for (UINT32 i = 0; i < 128; i++) 
      {
	if (i%16 == 0) {
	  outmem << endl;
	  outmem << "address [0x" << (ADDRINT)(current)
		 << "-0x" << (ADDRINT)(current+63) <<"]" 
		 << endl;
	}
	outmem << std::setw(2) << buffer[i] << " ";
	current+=4;
      }
  }
  
  if (end > current) {
    UINT8* temp = new UINT8[end-current+1];
    PIN_SafeCopy(temp, current, end-current+1);
    outmem << endl;
    outmem << "address [0x" << ADDRINT(current) << "-0x" << ADDRINT(end) <<"]" 
	   << endl;
    for (UINT32 i = 0; i < (UINT32)(end-current+1); i++) 
      {
	outmem << std::setw(2) << static_cast<UINT32>(temp[i]) << " ";
      }
    delete[] temp;
  }
  
  outmem << std::setfill(' ');
  outmem.setf(ios::showbase);
  outmem << endl;
  outmem << "----------------------------" << endl;
}
/* ===================================================================== */
VOID SysBegin(THREADID threadIndex, CONTEXT *ctxt, 
	      SYSCALL_STANDARD std, VOID *v)
{
  if (!KnobTraceSys)
    {
      return;
    }

  if (KnobFixFork && forked && PIN_GetPid() != my_original_pid)
    return;
  
  if (outstanding_syscall)
    cout << "***WARNING***: [SysBegin] Interruptable " 
	 << "System Call Situation" << endl;

  last_syscall_number = PIN_GetSyscallNumber(ctxt, std);
  outstanding_syscall = true;

#if DEBUG_MEMORY
  // mmap2
  if (armed && last_syscall_number == 192)
    {
      string mapin_file = string("/proc/") + decstr(PIN_GetPid()) + string("/maps");
      string mapout_file = string("./TMP/map_") + string(KnobLeader ? "L" : "F") 
	+ string("pre") + print	+ string(".txt");
      string command = string("cat ") + mapin_file + string(" > ") + mapout_file;
      system(command.c_str());
    }
#endif

  // epoll_wait()
  if (KnobEpoll && last_syscall_number == 256)
    {
      if (KnobLeader)
	{
	  // cerr << "SysBegin (epoll) leader is about to make call" << endl;
      
	  // int max_events = PIN_GetSyscallArgument(ctxt, std, 2);
	  // int timeout = PIN_GetSyscallArgument(ctxt, std, 3);
	  
	  // cout << "\t" << "changing max_events -> 1 rather than " << max_events << endl;
	  // cout << "\t" << "changing time_out -> -1 rather than " << timeout << endl;
	  
	  PIN_SetSyscallArgument(ctxt, std, 2, 1);
	  PIN_SetSyscallArgument(ctxt, std, 3, -1);
	}
      else 
	{
	  // epoll_out << "SysBegin (epoll) follower is about to make call:" << endl;
	  
	  // int max_events = PIN_GetSyscallArgument(ctxt, std, 2);
	  // int timeout = PIN_GetSyscallArgument(ctxt, std, 3);
	  
	  int handled = 0;

	  next = extract_next_epoll_event();
	  
	  /*
	  epoll_out << "\t Expected Event (next):" << endl;
	  epoll_out << "\t\t next->events = " << next->events << endl;
	  epoll_out << "\t\t next->data.ptr = " << next->data.ptr << endl << endl;
	  
	  epoll_out << "\t Going Through Pending Events (# = " << e.size() << "):" << endl; 
	  */

	  size_t i;
	  for (i = 0; i < e.size(); i++)
	    {
	      struct epoll_event* v =  e[i];	     
	      // epoll_out << "\t\t e[" << i << "] = {events=" << v->events << ",data.ptr=" << v->data.ptr << "}" << endl;
	      if (v->events == next->events
		  && v->data.ptr == next->data.ptr)
		{
		  // epoll_out << "SysBegin (epoll) the next event has been already received (skipping call)" << endl;
		  PIN_SetSyscallArgument(ctxt, std, 2, -1);
		  handled = 1;
		  break;
		}
	    }
	  
	  if (! handled )
	    {
	      // epoll_out << "SysBegin (epoll) the next event has not been received (making call)" << endl;
	      PIN_SetSyscallArgument(ctxt, std, 2, 1);
	      PIN_SetSyscallArgument(ctxt, std, 3, -1);
	      // cout << "\t" << "changing max_events -> 1 rather than " << max_events << endl;
	      // cout << "\t" << "changing time_out -> -1 rather than " << timeout << endl;
	    }
	}
    }

  // HandleSysBegin(threadIndex, ctxt, std, v, out);
  HandleSysBegin(threadIndex, ctxt, std, v, sysout);
}

VOID FixSockets(THREADID threadIndex, CONTEXT *ctxt, 
		SYSCALL_STANDARD std, VOID *v)
{
  
}

VOID SysEnd(THREADID threadIndex, CONTEXT *ctxt, 
	    SYSCALL_STANDARD std, VOID *v)

{
  if (!KnobTraceSys)
    return;

  if (KnobFixFork && forked && PIN_GetPid() != my_original_pid)
    return;
  
  if (!outstanding_syscall)
        cout << "***WARNING***: [SysEnd] No outstanding " 
	 << "System Call Situation" << endl;

#if DEBUG_MEMORY
  // mmap2
  if (armed && last_syscall_number == 192)
    {
      string mapin_file = string("/proc/") + decstr(PIN_GetPid()) + string("/maps");
      string mapout_file = string("./TMP/map_") + string((KnobLeader ? "L" : "F")) 
	+ string("post") + print + string(".txt");
      string command = string("cat ") + mapin_file + string(" > ") + mapout_file;
      system(command.c_str());

      print = "B";
      armed = 0;
      //      PIN_SetContextReg(ctxt, REG_GAX, (ADDRINT)bu)f;      
    }
#endif

  if (KnobEpoll && last_syscall_number == 256)
    {
      int epfd = PIN_GetSyscallArgument(ctxt, std, 0);
      struct epoll_event * events = (struct epoll_event*)PIN_GetSyscallArgument(ctxt, std, 1);
      int ret_val = PIN_GetSyscallReturn(ctxt, std);
  
      if (KnobLeader)
	{
	  // cout << "SysBegin (epoll) leader is logging call (ret_val =" << ret_val << ")" << endl;
	  // cout << "SysBegin (epoll) leader is logging call (event[0].events=" << events[0].events << ",event[0].data.ptr="
	  //      << events[0].data.ptr << endl;
	  log_epoll(events);
	}
      else
	{
	  // epoll_out << "SysEnd (epoll) follower returned from call (ret_val =" << ret_val << ")" << endl;
	  if (ret_val == -1)
	    {
	      // epoll_out << "\t SysEnd (epoll) follower is handling skipped call...\n" << endl;
	      
	      // we skipped a system call earlier
	      size_t i;
	      int handled = 0;

	      epoll_out << "\t Going Through Pending Events (# = " << e.size() << "):" << endl; 

	      for (i = 0; i < e.size(); i++)
		{
		  struct epoll_event* v = e[i];
		  epoll_out << "\t\t e[" << i << "] = {events=" << (v->events) << ",data.ptr=" << (v->data.ptr) << "}" << endl;
		  if (v->events == next->events
		      && v->data.ptr == next->data.ptr)
		    {
		      handled = 1;
		      epoll_out << "SysEnd (epoll) follower has found a matching event, and is using it" << endl;

		      PIN_SetContextReg(ctxt, REG_GAX, 1);
		      events[0].events = next->events;
		      events[0].data.ptr = next->data.ptr;

		      delete next;
		      next = (struct epoll_event*)NULL;

		      delete v;
		      e.erase(e.begin()+i);

		      break;
		    }
		}

	      if (!handled)
		{
		  // epoll_out << "ERROR : SysEnd (epoll) follower has NOT found a matching event" << endl;
		  cerr << "ERROR : SysEnd (epoll) follower has NOT found a matching event" << endl;
		}
	    }
	  else 
	    {
	      if (ret_val == 0)
		{
		  // epoll_out << "error: SysEnd (epoll) follower has ret_val = 0" << endl;
		  cerr << "error: SysEnd (epoll) follower has ret_val = 0" << endl;
		}

	      // we made a system call, and received the expected event
	      if (events[0].events == next->events
		    && events[0].data.ptr == next->data.ptr)
		{
		  // epoll_out << "SysEnd (epoll) follower got expected event!" << endl;
		  delete next;
		  next = (struct epoll_event*)NULL;
		}
	      else 
		{
		  // keep trying till you get the damn event
		  struct epoll_event * rcvd = new struct epoll_event;
		  rcvd->events = events[0].events;
		  rcvd->data.ptr = events[0].data.ptr;
		  e.push_back(rcvd);
		  
		  // epoll_out << "\t SysEnd (epoll) follower got unexpected event, trying again ... " << endl;
		  // epoll_out << "\t\t rcvd->events=" << rcvd->events << ", rcvd->data.ptr=" << rcvd->data.ptr << endl;
		  
		  int done = 0;
		  while (! done )
		    {
		      // epoll_out << "\t SysEnd (epoll) follower making nested epoll_wait call ..." << endl;
		      int nfds = epoll_wait(epfd, events, 1, -1);

		      if (nfds != 1)
			cerr << "\t ERROR: SysEnd (epoll) follower got: " << nfds << endl;
		      // else
		      // epoll_out << "\t\t SysEnd (epoll) follower got: " << nfds << endl;
		      		      
		      if (events[0].events == next->events
			  && events[0].data.ptr == next->data.ptr)
			{
			  // epoll_out << "\t SysEnd (epoll) got expected event!" << endl;
			  delete next;
			  next = (struct epoll_event*)NULL;
			  // epoll_out << "SysEnd (epoll) got expected event in nested call" << endl;
			  done = 1;
			}
		      else 
			{

			  struct epoll_event * rcvd = new struct epoll_event;
			  rcvd->events = events[0].events;
			  rcvd->data.ptr = events[0].data.ptr;
			  e.push_back(rcvd);
			  // epoll_out << "\t SysEnd (epoll) got unexpected event in nested call..." << endl;
			  // epoll_out << "\t\t rcvd->events=" << rcvd->events <<  ",rcvd->data.ptr=" << rcvd->data.ptr << endl;
			}
		      
		      sleep(1);
		    }
		}
	    }
	}
    }
  
  // SET TID ADDRESS
  else if (last_syscall_number == 258)
    {
      if (KnobFixPid)
	{
	  my_original_pid = PIN_GetSyscallReturn(ctxt, std);
	  cout << dec << "Changing Pid " << my_original_pid << " to " << my_simulated_pid << endl;
	  PIN_SetContextReg(ctxt, REG_GAX, my_simulated_pid);
	} 
    }
  // ADJUSTTIMEX
  else if (last_syscall_number == 124)
    {
      if (KnobFixAdjustTimex)
	{
	  struct timex* buf = (struct timex*)PIN_GetSyscallArgument(ctxt, std, 0);
	  int ret_val = PIN_GetSyscallReturn(ctxt, std);
	  
	  if (KnobLeader)
	    {
	      timex_out << "buf=" << dec << (ADDRINT)buf << endl;
	      timex_out << "ret_val=" << dec << ret_val << endl;
	      
	      // fields of buf:
	      timex_out << "buf->modes= " << dec << buf->modes << endl;
	      timex_out << "buf->offset= " << dec << buf->offset << endl;
	      timex_out << "buf->freq= " << dec << buf->freq << endl;
	      timex_out << "buf->maxerror= " << dec << buf->maxerror << endl;
	      timex_out << "buf->esterror= " << dec << buf->esterror << endl;
	      timex_out << "buf->status= " << dec << buf->status << endl;
	      timex_out << "buf->constant= " << dec << buf->constant << endl;
	      timex_out << "buf->precision= " << dec << buf->precision << endl;
	      timex_out << "buf->tolerance= " << dec << buf->tolerance << endl;
	      timex_out << "buf->tick= " << dec << buf->tick << endl;
	      timex_out << "buf->time1= " << dec << buf->time.tv_sec << endl;
	      timex_out << "buf->time2= " << dec << buf->time.tv_usec << endl;
	    }
	  else 
	    {
	      ADDRINT val_buf = 0;
	      char str[255];
	      string tmp;
	      istringstream s;

	      // buf=
	      timex_in.getline(str, 255);  
	      tmp = string(str);
	      if (tmp.find("buf=") == string::npos)
		cerr << "error: expected \"buf=\" , saw:" << tmp << endl;  
	      tmp = tmp.substr(tmp.find("=")+1);
	      s.clear();
	      s.str(tmp);
	      s >> dec >> val_buf;
	      if (val_buf != (ADDRINT)buf)
		{
		  cerr << " HERE WTF" << endl;
		  cerr << " LEADER BUF = " << dec << val_buf << endl;
		  cerr << " FOLLOWER BUF = " << dec << (ADDRINT)buf << endl;
		  cerr << "error: expected \"buf=" << (ADDRINT)buf << "\" , saw:" << 
		    string(str) << endl;  
		}
	      // ret_val= 
	      timex_in.getline(str, 255);  
	      tmp = string(str);
	      if (tmp.find("ret_val=") == string::npos)
		cerr << "error: expected \"ret_val=\" , saw:" << tmp << endl;  
	      tmp = tmp.substr(tmp.find("=")+1);
	      s.clear();
	      s.str(tmp);
	      s >> dec >> val_buf;
	      if ((int)val_buf != ret_val)
		PIN_SetContextReg(ctxt, REG_GAX, val_buf);

	      // buf->modes=
	      timex_in.getline(str, 255);  
	      tmp = string(str);
	      if (tmp.find("buf->modes=") == string::npos)
		cerr << "error: expected \"buf->modes=\" , saw:" << tmp << endl;  
	      tmp = tmp.substr(tmp.find("=")+1);
	      s.clear();
	      s.str(tmp);
	      s >> dec >> buf->modes;	

	      // buf->offset=
	      timex_in.getline(str, 255);  
	      tmp = string(str);
	      if (tmp.find("buf->offset=") == string::npos)
		cerr << "error: expected \"buf->offset=\" , saw:" << tmp << endl;  
	      tmp = tmp.substr(tmp.find("=")+1);
	      s.clear();
	      s.str(tmp);
	      s >> dec >> buf->offset;	

	      // buf->freq=
	      timex_in.getline(str, 255);  
	      tmp = string(str);
	      if (tmp.find("buf->freq=") == string::npos)
		cerr << "error: expected \"buf->freq=\" , saw:" << tmp << endl;  
	      tmp = tmp.substr(tmp.find("=")+1);
	      s.clear();
	      s.str(tmp);
	      s >> dec >> buf->freq;	

	      // buf->maxerror=
	      timex_in.getline(str, 255);  
	      tmp = string(str);
	      if (tmp.find("buf->maxerror=") == string::npos)
		cerr << "error: expected \"buf->maxerror=\" , saw:" << tmp << endl;  
	      tmp = tmp.substr(tmp.find("=")+1);
	      s.clear();
	      s.str(tmp);
	      s >> dec >> buf->maxerror;	

	      // buf->esterror=
	      timex_in.getline(str, 255);  
	      tmp = string(str);
	      if (tmp.find("buf->esterror=") == string::npos)
		cerr << "error: expected \"buf->esterror=\" , saw:" << tmp << endl;  
	      tmp = tmp.substr(tmp.find("=")+1);
	      s.clear();
	      s.str(tmp);
	      s >> dec >> buf->esterror;	

	      // buf->status=
	      timex_in.getline(str, 255);  
	      tmp = string(str);
	      if (tmp.find("buf->status=") == string::npos)
		cerr << "error: expected \"buf->status=\" , saw:" << tmp << endl;  
	      tmp = tmp.substr(tmp.find("=")+1);
	      s.clear();
	      s.str(tmp);
	      s >> dec >> buf->status;	

	      // buf->constant=
	      timex_in.getline(str, 255);  
	      tmp = string(str);
	      if (tmp.find("buf->constant=") == string::npos)
		cerr << "error: expected \"buf->constant=\" , saw:" << tmp << endl;  
	      tmp = tmp.substr(tmp.find("=")+1);
	      s.clear();
	      s.str(tmp);
	      s >> dec >> buf->constant;	

	      // buf->precision=
	      timex_in.getline(str, 255);  
	      tmp = string(str);
	      if (tmp.find("buf->precision=") == string::npos)
		cerr << "error: expected \"buf->precision=\" , saw:" << tmp << endl;  
	      tmp = tmp.substr(tmp.find("=")+1);
	      s.clear();
	      s.str(tmp);
	      s >> dec >> buf->precision;	

	      // buf->tolerance=
	      timex_in.getline(str, 255);  
	      tmp = string(str);
	      if (tmp.find("buf->tolerance=") == string::npos)
		cerr << "error: expected \"buf->tolerance=\" , saw:" << tmp << endl;  
	      tmp = tmp.substr(tmp.find("=")+1);
	      s.clear();
	      s.str(tmp);
	      s >> dec >> buf->tolerance;	

	      // buf->tick=
	      timex_in.getline(str, 255);  
	      tmp = string(str);
	      if (tmp.find("buf->tick=") == string::npos)
		cerr << "error: expected \"buf->tick=\" , saw:" << tmp << endl;  
	      tmp = tmp.substr(tmp.find("=")+1);
	      s.clear();
	      s.str(tmp);
	      s >> dec >> buf->tick;	

	      // buf->time1=
	      timex_in.getline(str, 255);  
	      tmp = string(str);
	      if (tmp.find("buf->time1=") == string::npos)
		cerr << "error: expected \"buf->time1=\" , saw:" << tmp << endl;  
	      tmp = tmp.substr(tmp.find("=")+1);
	      s.clear();
	      s.str(tmp);
	      s >> dec >> buf->time.tv_sec;	

	      // buf->time2=
	      timex_in.getline(str, 255);  
	      tmp = string(str);
	      if (tmp.find("buf->time2=") == string::npos)
		cerr << "error: expected \"buf->time2=\" , saw:" << tmp << endl;  
	      tmp = tmp.substr(tmp.find("=")+1);
	      s.clear();
	      s.str(tmp);
	      s >> dec >> buf->time.tv_usec;	
	    }
	}
    }      
  // FSTAT64 SYSTEM CALL
  else if (last_syscall_number == 197)
    {

      ADDRINT arg1 = PIN_GetSyscallArgument(ctxt, std, 0);
      ADDRINT arg2 = PIN_GetSyscallArgument(ctxt, std, 1);
      cout << "FSTAT_64 (fd=" << dec << arg1 <<  ", buf=0x"<< hex << arg2 << ")" << endl;
      if (KnobFixStat)
	{
	  struct stat64* buf = (struct stat64*) arg2;
	  if (find(stat_fds.begin(), stat_fds.end(), arg1) != stat_fds.end())
	    {
	      cout << "fixing a time!" << endl;
	      buf->st_atime = (time_t)0x4df153d6;	  
	    }
	}      
    }
  // STAT64 / LSTAT64 SYSTEM CALLS
  else if (last_syscall_number == 195 || last_syscall_number == 196)
    {
      ADDRINT arg1 = PIN_GetSyscallArgument(ctxt, std, 0);
      ADDRINT arg2 = PIN_GetSyscallArgument(ctxt, std, 1);
      string  path = string((char*)arg1);
      
      cout << "STAT_64 (path=" << string((char*)arg1) << ", buf=0x" << hex << arg2 << ")" << endl;
      struct stat64* buf = (struct stat64*) arg2;
      
      if (KnobFixStat)
	{
	  if (path.find("var/spool/cups") != string::npos)
	    {
	      root_dir_time = buf->st_mtime;
	      if (root_dir_time > job_cache_time)
		{
		  buf->st_mtime=(time_t)2;
		}
	      else
		{
		  buf->st_mtime=(time_t)0;
		}
	    }
	  else if (path.find("var/cache/cups/job.cache") 
		   != string::npos)
	    {
	      job_cache_time = buf->st_mtime;
	      buf->st_mtime = (time_t)1;
	    }
	  else if (path.find("etc/resolv.conf"))
	    {
	      buf->st_atime = (time_t)0x4df153d6;
	      buf->st_ctime = (time_t)0x4df153c4;
	    }
	}
    }
  // TIME SYSTEM CALL
  else if (last_syscall_number == 0xd && KnobFixTime)
    {
      ADDRINT return_value = PIN_GetSyscallReturn(ctxt, std);
      //ADDRINT argument = PIN_GetSyscallArgument(ctxt, std, 0)
      if(KnobLeader)
	{
	  timing_out << hex << return_value << endl;
	  // cout << return_value << endl;
	}
      else
	{
	  ADDRINT new_value = 0;
	  char str[255];
	  timing_in.getline(str, 255);
	  
	  istringstream s(str);
	  s >> hex >> new_value;
	  PIN_SetContextReg(ctxt, REG_GAX, new_value);
	  // cout << new_value << endl;	
	}
    }
  // CLOCK_GETTIME SYSTEM CALL
  else if (last_syscall_number == 265 && KnobFixTime)
    {
      clockid_t clk_id = (clockid_t) PIN_GetSyscallArgument(ctxt, std, 0);
      struct timespec *tp = (struct timespec*) PIN_GetSyscallArgument(ctxt, std, 1);
      if (KnobLeader)
	{
	  clock_out << hex << clk_id << endl;
	  if (tp != NULL)
	    {
	      clock_out << hex << tp->tv_sec << endl;
	      clock_out << hex << tp->tv_nsec << endl;
	    }
	  else 
	    {
	      clock_out << hex << 0 << endl;
	      clock_out << hex << 0 << endl;
	    }
	}
      else 
	{
	  ADDRINT val1;
	  ADDRINT val2;
	  ADDRINT val3;
	  char str[255];
	  
	  clock_in.getline(str, 255);
	  istringstream s1(str);
	  s1 >> hex >> val1;

	  clock_in.getline(str, 255);
	  istringstream s2(str);
	  s2 >> hex >> val2;
	  
	  clock_in.getline(str, 255);
	  istringstream s3(str);
	  s3 >> hex >> val3;
	  
	  if ((clockid_t)val1 != clk_id)
	    {
	      cerr << "WARNING: CLOCK IDs don't match... (" << val1 << " vs " << clk_id << ")" << endl;
	    }

	  if (tp != NULL)
	    {
	      tp->tv_sec = val2;
	      tp->tv_nsec = val3;
	    }
	}
    }
  // GETTIMEOFDAY SYSTEM CALL
  else if (last_syscall_number == 0x4e && KnobFixTime)
    {
      ADDRINT arg1 = PIN_GetSyscallArgument(ctxt, std, 0);
      ADDRINT arg2 = PIN_GetSyscallArgument(ctxt, std, 1);
      ADDRINT v1 = 0;
      ADDRINT v2 = 0;
      ADDRINT v3 = 0;
      ADDRINT v4 = 0;
      if(KnobLeader)
	{
	  timeval* tv = (timeval*)arg1;
	  if (tv != NULL)
	    {
	      v1 = tv->tv_sec;
	      v2 = tv->tv_usec;
	      gettimeofday_out << hex << tv->tv_sec << endl;
	      gettimeofday_out << hex << tv->tv_usec << endl;
	    }
	  else
	    {
	      v1 = 0;
	      v2 = 0;
	      gettimeofday_out << hex << 0 << endl;
	      gettimeofday_out << hex << 0 << endl;
	    }
	  
	  if (arg2 != 0)
	    {
	      v3 = *(int*)arg2;
	      v4 = *(((int*)arg2)+1);;
	      gettimeofday_out << *(int*)arg2 << endl;
	      gettimeofday_out << *(((int*)arg2)+1) << endl;
	    }
	  else
	    {
	      v3 = 0;
	      v4 = 0;
	      gettimeofday_out << 0 << endl;
	      gettimeofday_out << 0 << endl;
	    }
	}
      else
	{
	  char str[255];
	  
	  gettimeofday_in.getline(str, 255);
	  istringstream s1(str);
	  s1 >> hex >> v1;

	  gettimeofday_in.getline(str, 255);
	  istringstream s2(str);
	  s2 >> hex >> v2;
	  
	  gettimeofday_in.getline(str, 255);
	  istringstream s3(str);
	  s3 >> hex >> v3;

	  gettimeofday_in.getline(str, 255);
	  istringstream s4(str);
	  s4 >> hex >> v4;

	  if (arg1 != 0)
	    {
	      timeval* tv = (timeval*)arg1;
	      tv->tv_sec = v1;
	      tv->tv_usec = v2;
	    }
	  
	  if (arg2 != 0)
	    {
	      *(int*)arg2 = v3;
	      *(((int*)arg2)+1) = v4;
	    }
	}
    }
  // OPEN SYSTEM CALL 
  else if (last_syscall_number == 0x5)
    {
      ADDRINT arg1 = PIN_GetSyscallArgument(ctxt, std, 0);
      string  path = string((char*)arg1);
      
#if DEBUG_MEMORY
      if (path.find("proc/net/if_inet6") != string::npos)
	{
	  armed = 1;
	}
#endif

      if (KnobDevRandom)
	{
	  if (path.find("urandom") != string::npos)
	    {
	      ADDRINT ret_val = PIN_GetSyscallReturn(ctxt, std);
	      urandom_fds.push_back(ret_val);
	      cout << "Added fd = " << dec << ret_val << " into dev/urandom/ intercepted." << endl; 
	    }
	}

      if(KnobFixStat)
	{
	  if (//path.find("etc/host.conf") != string::npos
	      //|| path.find("etc/hosts") != string::npos
	      //|| path.find("etc/services") != string::npos
	      //||
	      path.find("etc/gai.conf") != string::npos)
	    {
	      ADDRINT ret_val = PIN_GetSyscallReturn(ctxt, std);
	      stat_fds.push_back(ret_val);
	      cout << "Added fd = " << dec << ret_val << " into stat intercepted." << endl; 
	    }
	}
      
    }
  // READ SYSTEM CALL
  else if (last_syscall_number == 0x3)
    {
      if (KnobDevRandom && !urandom_fds.empty())
	{
	  ADDRINT read_fd = PIN_GetSyscallArgument(ctxt, std, 0);
	  if (find(urandom_fds.begin(), urandom_fds.end(), read_fd) != urandom_fds.end())
	    {
	      ADDRINT bufferarg = PIN_GetSyscallArgument(ctxt, std, 1);
	      ADDRINT count = PIN_GetSyscallArgument(ctxt, std, 2);
	      char* buf = (char*)bufferarg;
	      for (uint i = 0; i < count; i++)
		{
		  buf[i] = 0x1;
		}
	    }
	}
    }
  // CLOSE SYSTEM CALL
  else if (last_syscall_number == 0x6)
    {

      ADDRINT close_fd = PIN_GetSyscallArgument(ctxt, std, 0);
      if (KnobDevRandom && !urandom_fds.empty())
	{
	  if (find(urandom_fds.begin(), urandom_fds.end(), close_fd) != urandom_fds.end())
	    {
	      urandom_fds.erase(find(urandom_fds.begin(), urandom_fds.end(), close_fd));
	    }
	}
      
      if(KnobFixStat)
	{
	  if (find(stat_fds.begin(), stat_fds.end(), close_fd) != stat_fds.end())
	    {
	      stat_fds.erase(find(stat_fds.begin(), stat_fds.end(), close_fd));
	    }
	}

      if(KnobFixNetInit)
	{
	  if (find(netlink_sockets.begin(), netlink_sockets.end(), close_fd) != netlink_sockets.end())
	    {
	      netlink_sockets.erase(find(netlink_sockets.begin(), netlink_sockets.end(), close_fd));
	    }
	}
    }
  else if (last_syscall_number == 0xE0)
    {
      // GET_TID
      ADDRINT ret_val = PIN_GetSyscallReturn(ctxt, std);
      cout << "GET_TID() -> 0x" << hex << ret_val << endl;
    }
  else if (last_syscall_number == 0x14)
    {
      if (KnobFixPid)
	{
	  // GET PID
	  ADDRINT ret_val = PIN_GetSyscallReturn(ctxt, std);
	  if (my_original_pid == -1)
	    my_original_pid = ret_val;
	  
	  cout << "GET_PID() -> 0x" << hex << ret_val << endl;
	  cout << "Changing Pid to 0x" << hex << my_simulated_pid << endl;
	  out << "Changing Pid to 0x" << hex << my_simulated_pid << endl;
	  PIN_SetContextReg(ctxt, REG_GAX, my_simulated_pid);
	}
    }

  else if (last_syscall_number == 0x40)
    {
      // GET PPID
      ADDRINT ret_val = PIN_GetSyscallReturn(ctxt, std);
      cout << "GET_PPID() -> 0x" << hex << ret_val << endl;
    }
  else if (last_syscall_number == 320)
    {
      // UTIMENSAT
      ADDRINT arg1 = PIN_GetSyscallArgument(ctxt, std, 1);
      cout << "UTIMESAT(" << string((char*)arg1) << ")" << endl;
    }
  else if (last_syscall_number == 120)
    {
      // CLONE()
      if (KnobFixPid)
	{
	  ADDRINT ret_val = PIN_GetSyscallReturn(ctxt, std);
	  pid_child_trans_table[ret_val] = next_child_pid++;
	  cout << "clone(): 0x" << hex << ret_val << "-->" << pid_child_trans_table[ret_val] << endl;
	  PIN_SetContextReg(ctxt, REG_GAX, pid_child_trans_table[ret_val]);
	}
    }
  else if (last_syscall_number == 43)
    {
      if(KnobFixTime)
	{
	  // TIMES
	  ADDRINT arg1 = PIN_GetSyscallArgument(ctxt, std, 1);
	  struct tms* t = (struct tms *)arg1;
	  cout << "TIMES[0]:" << t->tms_utime << endl;
	  cout << "TIMES[1]:" << t->tms_stime << endl;
	  cout << "TIMES[2]:" << t->tms_cutime << endl;
	  cout << "TIMES[3]:" << t->tms_cstime << endl;
	  
	  cout << "TIMES : " << hex << PIN_GetSyscallReturn(ctxt, std) << " -> " << hex << 0x67F011AE << endl;
	  PIN_SetContextReg(ctxt, REG_GAX, 0x67F011AE);
	}
    }
  else if (last_syscall_number == 102)
    {
      // SOCKET CALL
      ADDRINT call_number = PIN_GetSyscallArgument(ctxt, std, 0);

      cout << "SOCKET CALL ( " << call_number << " i.e. " << (call_number < 16 ? socketcalls[call_number] : string("")) <<  " )" << 
	endl;


      if (call_number == 5)
	{
	  ADDRINT args = PIN_GetSyscallArgument(ctxt, std, 1);
	  struct sockaddr* my_addr = *(struct sockaddr **)(args + sizeof(int));
	  if (my_addr != (struct sockaddr*)NULL)
	    {
	      sa_family_t sa_family = my_addr->sa_family;
	      switch ( sa_family )
		{
		case AF_INET:
		  {
		    struct sockaddr_in *in = (struct sockaddr_in*) my_addr;
		    in->sin_port = htons(next_socket_fd++);
		  }
		  break;
		case AF_INET6:
		  {
		    struct sockaddr_in6 *in = (struct sockaddr_in6*) my_addr;
		    in->sin6_port = htons(next_socket_fd++);
		  }
		  break;
		default:
		  cerr << "WTF" << endl;
		  break;
		}
	    }
	}
      
      // send to
      if (call_number == 11)
	{
	  ADDRINT args = PIN_GetSyscallArgument(ctxt, std, 1);
	  int s = *(int*)args;
	  void *buf = *(void **)(args + sizeof(int)); 
	  int len = *(int *) (args + sizeof(int) + sizeof(void*));
	  int flags = *(int *) (args + sizeof(int) + sizeof(void*) + sizeof(int));
	  struct sockaddr * to = *(struct sockaddr **)(args + sizeof(int) + sizeof(void*) + sizeof(int) + sizeof(int));
	  socklen_t tolen = *(socklen_t *)(args + sizeof(int) + sizeof(void*) + 2*sizeof(int) + sizeof(struct sockaddr*));
	  
	  cout << "sendto( s = " << s << "# buf=" << buf << " # len=" << len << " # flags=" << flags << " # to=" << to 
	       << "# tolen=" << tolen << " )" << endl;
	}

      // recv msg
      if (call_number == 17)
	{
	  ADDRINT args = PIN_GetSyscallArgument(ctxt, std, 1);
	  int s = *(int*)args;
	  void *_msg = *(void **)(args + sizeof(int)); 
	  int flags = *(int *) (args + sizeof(int) + sizeof(void*));
	  size_t read_len = PIN_GetSyscallReturn(ctxt, std);

	  cout << "recvmsg ( s= " << s << "# _msg=" << _msg << "# flags=" << flags << ") - >" << 
	    read_len << endl;

	  if (KnobFixNetInit)
	    {
	      netlink_sockets.push_back(s);

	      if (find(netlink_sockets.begin(), netlink_sockets.end(), s) != netlink_sockets.end())
		{
		  struct msghdr * pmsg = (struct msghdr*)_msg;
		  char *buf = (char*)pmsg->msg_iov->iov_base;
		  size_t len = pmsg->msg_iov->iov_len;

		  sysout << "[NETLINK:]" << endl;
		  sysout << "buf = " << (size_t)buf << " len = " << len << endl;
		  sysout << " about to enter loop" << endl;
		  
		  struct nlmsghdr *nh;
		  for (nh = (struct nlmsghdr*) buf;
		       NLMSG_OK(nh, (size_t)read_len);
		       nh = (struct nlmsghdr*) NLMSG_NEXT(nh, read_len))
		    {
		      sysout << "nh = " << nh << endl;
		      sysout << "pid in message = " << dec << nh->nlmsg_pid  << endl;
		      sysout << "seqno in message = " << nh->nlmsg_seq << endl;		      
		      if (nh->nlmsg_pid == (uint)my_original_pid)
			{
			  sysout << "changing pid in message to : " << my_simulated_pid << endl;
			  nh->nlmsg_pid = my_simulated_pid;
			}
		      else
			{
			  continue;
			}

		      if (nh->nlmsg_type == NLMSG_DONE)
			break;		/* ok */
		      
		      if (nh->nlmsg_type == RTM_NEWLINK)
			{
			  /* A RTM_NEWLINK message can have IFLA_STATS data. We need to
			     know the size before creating the list to allocate enough
			     memory.  */
			  sysout << "[RTM_NEWLINK]: "<< endl;

			  struct ifinfomsg *ifim = (struct ifinfomsg *) NLMSG_DATA (nh);

			  sysout << "\t[IFINFOMSG]: " << endl;
			  sysout << "\t\t ifi_family: " << ifim->ifi_family << endl;
			  sysout << "\t\t ifi_type: " << ifim->ifi_type << endl;
			  sysout << "\t\t ifi_index: " << ifim->ifi_index << endl;
			  sysout << "\t\t ifi_flags: " << ifim->ifi_flags << endl;
			  sysout << "\t\t ifi_change: " << ifim->ifi_change << endl;

			  struct rtattr *rta = IFLA_RTA (ifim);
			  size_t rtasize = IFLA_PAYLOAD (nh);
			  
			  while (RTA_OK (rta, rtasize))
			    {
			      size_t rta_payload = RTA_PAYLOAD (rta);
			      char *rta_data = (char*) RTA_DATA (rta);
			      switch (rta->rta_type)
				{
				case IFLA_ADDRESS:
				  {
				    sysout << "\t [IFLA_ADDRESS]: "<< endl;
				    size_t k;
				    for (k = 0; k < rta_payload; k++)
				      {
					sysout << "\t\t\t rta_data[" << k << "] = " << rta_data[k] << endl;
				      }
				  }
				  break;
				  
				case IFLA_BROADCAST:
				  {
				    sysout << "\t [IFLA_BROADCAST]: "<< endl;
				    size_t k;
				    for (k = 0; k < rta_payload; k++)
				      {
					sysout << "\t\t\t rta_data[" << k << "] = " << rta_data[k] << endl;
				      }
				  }				   
				  break;
				  
				case IFLA_IFNAME:	/* Name of Interface */
				  {
				    sysout << "\t [IFLA_IFNAME]: "<< endl;
				    sysout << "\t\t\t name = " << string(rta_data) << endl;

				  }
				  break;
				  
				case IFLA_STATS:	/* Statistics of Interface */
				  {  
				    sysout << "\t [IFLA_STATS]: "<< endl;
				    size_t k;
				    for (k = 0; k < rta_payload; k++)
				      {
					sysout << "\t\t\t rta_data[" << k << "] = " << rta_data[k] << endl;
				      }
				    
				    // struct net_device_stats st;
				    struct rtnl_link_stats st;
				    size_t c = PIN_SafeCopy(&st, (void*)rta_payload, 
							    sizeof(struct rtnl_link_stats));;    

				    sysout << "\t\t\t (" << c << " bytes copied)" << endl;
				    sysout << "\t\t\t st.rx_packets=" << st.rx_packets << endl;
				    sysout << "\t\t\t st.tx_packets=" << st.tx_packets << endl;
				    sysout << "\t\t\t st.rx_bytes=" << st.rx_bytes << endl;
				    sysout << "\t\t\t st.tx_bytes=" << st.tx_bytes << endl;

				    sysout << "\t\t\t st.rx_errors=" << st.rx_errors << endl;
				    sysout << "\t\t\t st.tx_errors=" << st.tx_errors << endl;
				    sysout << "\t\t\t st.rx_dropped=" << st.rx_dropped << endl;
				    sysout << "\t\t\t st.tx_dropped=" << st.tx_dropped << endl;

				    sysout << "\t\t\t st.multicast=" << st.multicast << endl;
				    sysout << "\t\t\t st.collisions=" << st.collisions << endl;

				    sysout << "\t\t\t st.rx_length_errors=" << st.rx_length_errors << endl;
				    sysout << "\t\t\t st.rx_over_errors=" << st.rx_over_errors << endl;
				    sysout << "\t\t\t st.rx_crc_errors=" << st.rx_crc_errors << endl;
				    sysout << "\t\t\t st.rx_frame_errors=" << st.rx_frame_errors << endl;
				    sysout << "\t\t\t st.rx_fifo_errors=" << st.rx_fifo_errors << endl;
				    sysout << "\t\t\t st.tx_missed_errors=" << st.rx_missed_errors << endl;				    

				    sysout << "\t\t\t st.tx_aborted_errors=" << st.tx_aborted_errors << endl;
				    sysout << "\t\t\t st.tx_carrier_errors=" << st.tx_carrier_errors << endl;
				    sysout << "\t\t\t st.tx_fifo_errors=" << st.tx_fifo_errors << endl;
				    sysout << "\t\t\t st.tx_heartbeat_errors=" << st.tx_heartbeat_errors << endl;
				    sysout << "\t\t\t st.tx_window_errors=" << st.tx_window_errors << endl;

				    sysout << "\t\t\t st.rx_compressed=" << st.tx_compressed << endl;
				    sysout << "\t\t\t st.tx_compressed=" << st.rx_compressed << endl;

				    for (k = 0; k < rta_payload; k++)
				      {
					sysout << "\t\t\t rta_data[" << k << "] = " << 0x1 << endl;
				      }

				  }
				  break;
				case IFLA_UNSPEC:
				  break;
				case IFLA_MTU:
				  break;
				case IFLA_LINK:
				  break;
				case IFLA_QDISC:
				  break;
				default:
				  break;
				}

			      rta = RTA_NEXT (rta, rtasize);			     
			    }
			}
		      else if (nh->nlmsg_type == RTM_NEWADDR)
			{
			  sysout << "[RTM_NEWADDR]: "<< endl;
			  struct ifaddrmsg *ifam = (struct ifaddrmsg *) NLMSG_DATA (nh);
			  
			  struct rtattr *rta = IFA_RTA (ifam);
			  size_t rtasize = IFA_PAYLOAD (nh);

			  while(RTA_OK(rta, rtasize))
			    {
			      char *rta_data = (char*) RTA_DATA (rta);
			      size_t rta_payload = RTA_PAYLOAD (rta);
			      
			      switch (rta->rta_type)
				{
				case IFA_ADDRESS:
				  {
				    sysout << "\t [IFLA_ADDRESS]: "<< endl;
				    switch(ifam->ifa_family)
				      {
				      case AF_INET:
					if (rta_payload == 4)
					  {
					    sysout << "\t\t [AF_INET]: "<< endl;
					    print_sockaddr((struct sockaddr*)rta_data, sysout); 
					  }
					break;
				      case AF_INET6:
					if (rta_payload == 16)
					  {
					    sysout << "\t\t [AF_INET6]: "<< endl;
					    print_sockaddr((struct sockaddr*)rta_data, sysout); 
					  }
					break;
				      default:
					print_sockaddr((struct sockaddr*)rta_data, sysout); 
					break;
				      }
				  }
				  break;
				case IFA_LOCAL:
				  {
				    sysout << "\t [IFLA_LOCAL]: "<< endl;
				    switch(ifam->ifa_family)
				      {
				      case AF_INET:
					if (rta_payload == 4)
					  {
					    sysout << "\t\t [AF_INET]: "<< endl;
					    print_sockaddr((struct sockaddr*)rta_data, sysout); 
					  }
					break;
				      case AF_INET6:
					if (rta_payload == 16)
					  {
					    sysout << "\t\t [AF_INET6]: "<< endl;
					    print_sockaddr((struct sockaddr*)rta_data, sysout); 
					  }
					break;
				      default:
					print_sockaddr((struct sockaddr*)rta_data, sysout); 
					break;
				      }
				  }
				  break;

				case IFA_BROADCAST:
				  {
				    sysout << "\t [IFLA_LOCAL]: "<< endl;
				    switch(ifam->ifa_family)
				      {
				      case AF_INET:
					if (rta_payload == 4)
					  {
					    sysout << "\t\t [AF_INET]: "<< endl;
					    print_sockaddr((struct sockaddr*)rta_data, sysout); 
					  }
					break;
				      case AF_INET6:
					if (rta_payload == 16)
					  {
					    sysout << "\t\t [AF_INET6]: "<< endl;
					    print_sockaddr((struct sockaddr*)rta_data, sysout); 
					  }
					break;
				      default:
					print_sockaddr((struct sockaddr*)rta_data, sysout); 
					break;
				      }
				  }
				  break;
				case IFA_LABEL:
				  {
				    sysout << "\t [IFLA_LABEL]: "<< endl;
				    sysout << "\t " << string(rta_data) << endl;
				  }
				  break;
				default:
				  break;
				}
			      rta = RTA_NEXT(rta, rtasize);
			    }
			}
		    }
		  cout << " done with loop" << endl;
		}
	    }
	}
      // getsockname
      if (call_number == 6)
	{
	  ADDRINT args = PIN_GetSyscallArgument(ctxt, std, 1);
	  int s = *(int*)args;
	  struct sockaddr *name = *(struct sockaddr **)(((int*)args)+1);
	  socklen_t* namelen = *(socklen_t**)(args + sizeof(int) + sizeof(struct sockaddr*));
 
	  cout << "getsockname ( s = " << dec << s << ", " << "name = " << name << ")" << endl;
	  unsigned short f = name->sa_family;
	  string family;

	  int handled = 0;
	  
	  if (f == AF_INET)
	    {
	      family = "AF_INET";
	    }
	  else if (f == AF_INET6)
	    {
	      family = "AF_INET6";
	      struct sockaddr_in6 *in6 =  (struct sockaddr_in6*)name;
	      if (KnobFixNetInit)
		{	      
		  cout << "thinking about changing ipv6 port " << ntohs(in6->sin6_port) <<  " / " << in6->sin6_port << " to some random #: " << 33748 << endl; 
		  in6->sin6_port = 33748;
		  cout << "changed it " << endl;
		}
	      handled = 1;
	    }
	  else if (f == AF_UNIX)
	    {
	      family = "AF_INET6";
	    }
	  else if (f == AF_APPLETALK)
	    {
	      family = "AF_APPLETALK";
	    }
	  else if (f == AF_PACKET)
	    {
	      family = "AF_PACKET";
	    }
	  else if (f == AF_UNIX)
	    {
	      family = "AF_UNIX";
	    }
	  else if (f == AF_NETLINK)
	    {
	      netlink_sockets.push_back(s);

	      family = "AF_NETLINK";
	      struct sockaddr_nl *nl =  (struct sockaddr_nl*)name;
	      cout << "{family=" << family << ", pad=" << nl->nl_pad << ", pid=" << nl->nl_pid << ", groups=" << 
		nl->nl_groups << "}" << endl;
	      handled = 1;
	      if (KnobFixNetInit)
		{	      
		  cout << "changing pid in AF_NETLINK packet to " << my_simulated_pid << endl;
		  nl->nl_pid = my_simulated_pid;
		}
	    }
	  else if (f == AF_X25)
	    {
	      family = "AF_X25";
	    }
	  else 
	    {
	      family = "?";
	    }
	  
	  if (!handled)
	    {
	      cout << "name[family]=" << family << ", name[family#] = " << f << ", name[data]=<";
	      for (int i = 0; i < 14; i++)
		{
		  cout << (int)name->sa_data[i] << " ";
		}
	      cout << ">, namelen = " << *namelen << endl;
	    }
	}
    }
  else if (last_syscall_number == 25 || last_syscall_number == 30 || last_syscall_number == 35 || last_syscall_number == 79 || last_syscall_number == 104 || last_syscall_number == 105
	   || last_syscall_number == 124 || last_syscall_number == 177 || (last_syscall_number >= 259 && last_syscall_number <= 267) || last_syscall_number == 271 || last_syscall_number == 299
	   || last_syscall_number == 322 || last_syscall_number == 325 || last_syscall_number == 326 || last_syscall_number == 279 || last_syscall_number == 280)
    {
      cout << "Warning: TIME RELATED SYSCALL" << endl;
    }


  cout << "System Call End: " << syscalls[last_syscall_number] << " () ->" << PIN_GetSyscallReturn(ctxt, std) << endl;

  // HandleSysEnd(threadIndex, ctxt, std, v, out);
  HandleSysEnd(threadIndex, ctxt, std, v, sysout);
  outstanding_syscall = false;
  return;
}

/* ===================================================================== */
VOID InstructionTrace(TRACE trace, INS ins)
{
  if (!KnobTraceInstructions)
    return;
  
  ADDRINT addr = INS_Address(ins);
  string s = StringFromAddrint(addr);
  string dis = INS_Disassemble(ins);

  if (KnobMem && firstInstruction) 
    {
      // Visit every loaded image
      for(IMG img= APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) 
	{
	  PrintImageMemory(img);
	}	
      
      firstInstruction = 0;
    }
  
  if (!canary_done && KnobFixCanary)
    {
      INS_InsertCall(ins, IPOINT_BEFORE, 
		     (AFUNPTR)overwrite_AT_RANDOM, 
		     IARG_END);
      canary_done = true;
    }
  
#if DEBUG_MEMORY
  if (!first_print)
    {
      string mapin_file = string("/proc/") + decstr(PIN_GetPid()) + string("/maps");
      string mapout_file = string("./TMP/map_") + string(KnobLeader ? "L" : "F") 
	+ string("start") + string(".txt");
      string command = string("cat ") + mapin_file + string(" > ") + mapout_file;
      system(command.c_str());
      first_print = 1;
    }
#endif

  if (!guard_done && KnobFixPointerGuard)
    {
      INS_InsertCall(ins, IPOINT_BEFORE, 
		     (AFUNPTR)overwrite_AT_RANDOM_4, 
		     IARG_END);
      guard_done = true;
    }

  //  eax = 0x1067a, ebx = 0x10800, ecx = 0x80082201, edx = 0xfebfbff 
  if (KnobCpuid && dis.find("cpuid") != string::npos)
    {
      INS_InsertCall(ins,
		     IPOINT_BEFORE,
		     AFUNPTR(EmulateCpuid),
		     IARG_REG_REFERENCE,
		     REG_GAX,
		     IARG_REG_REFERENCE,
		     REG_GBX,
		     IARG_REG_REFERENCE,
		     REG_GCX,
		     IARG_REG_REFERENCE,
		     REG_GDX,
		     IARG_END);
      // Delete the instruction
      INS_Delete(ins);	
      return;
    }
  
  if(KnobRdtsc && INS_IsRDTSC(ins))
    {
      // rax = 0x7eab816a, rdx = 0x6b7
      INS_InsertCall(ins,
		     IPOINT_BEFORE,
		     AFUNPTR(SendToRax),
		     IARG_RETURN_REGS,
		     REG_GAX,
		     IARG_END);
      
      INS_InsertCall(ins,
		     IPOINT_BEFORE,
		     AFUNPTR(SendToRdx),
		     IARG_RETURN_REGS,
		     REG_GDX,
		     IARG_END);
      
      s += "\t {----rdtsc replaced----}";
      
      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(PrintRdtsc), 
		     IARG_PTR, new string(s),
		     IARG_END);
      /*
	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(print_gs_stuff), 
		       IARG_REG_VALUE, REG_SEG_GS_BASE,
		       IARG_END);
	*/
	/*
	// [Debugging] print the deleted instruction address
	ADDRINT addr = INS_Address(ins);
	string traceString = "Deleted " + StringFromAddrint(addr);
	out << traceString << endl;
	*/
	
	// Delete the instruction
	INS_Delete(ins);	
	return;
      }

  // count instructions
  INS_InsertCall(ins, IPOINT_BEFORE, 
		 (AFUNPTR)CountInstruction,
		 IARG_END);
  

    
    // Format the string at instrumentation time
    string function = "";
    if (KnobPrintFunc) 
      {
	function = RTN_FindNameByAddress(addr) + "\t"; 
      }	
    
    //string traceString = "";
    // string astring = FormatAddress(addr, TRACE_Rtn(trace));
    //for (INT32 length = astring.length(); length < 30; length++)
    //  {
    //    traceString += " ";
    //  }

    //traceString = function + astring + traceString;
    string traceString = function + s + "  " + dis;
    if (traceString.length() < 50 && (traceString.length() >= 10))
      {
	traceString += " ";
      }

    INT32 regCount = 0;
    REG regs[20];
#if !defined(TARGET_IPF)
    REG xmm_dst = REG_INVALID();
#endif
      
    for (UINT32 i = 0; i < INS_MaxNumWRegs(ins); i++)
    {
        REG x = REG_FullRegName(INS_RegW(ins, i));
        
        if (REG_is_gr(x) 
#if defined(TARGET_IA32)
            || x == REG_EFLAGS
#elif defined(TARGET_IA32E)
            || x == REG_RFLAGS
#elif defined(TARGET_IPF)
            || REG_is_pr(x)
            || REG_is_br(x)
#endif
        )
        {
            regs[regCount] = x;
            regCount++;
        }
#if !defined(TARGET_IPF)
        if (REG_is_xmm(x)) 
            xmm_dst = x;
#endif

    }
#if defined(TARGET_IPF)
    if (INS_IsCall(ins) || INS_IsRet(ins) || INS_Category(ins) == CATEGORY_ALLOC)
    {
        regs[regCount] = REG_CFM;
        regCount++;
    }
#endif

    if (INS_HasFallThrough(ins))
    {
        AddEmit(ins, IPOINT_AFTER, traceString, regCount, regs);
    }
    if (INS_IsBranchOrCall(ins))
    {
        AddEmit(ins, IPOINT_TAKEN_BRANCH, traceString, regCount, regs);
    }
#if !defined(TARGET_IPF)
    if (xmm_dst != REG_INVALID()) 
    {
        if (INS_HasFallThrough(ins))
            AddXMMEmit(ins, IPOINT_AFTER, xmm_dst);
        if (INS_IsBranchOrCall(ins))
            AddXMMEmit(ins, IPOINT_TAKEN_BRANCH, xmm_dst);
    }
#endif        
}

/* ===================================================================== */
VOID MemoryTrace(INS ins)
{
    if (!KnobTraceMemory)
        return;
    
    if (INS_IsMemoryWrite(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, 
		       AFUNPTR(CaptureWriteEa), 
		       IARG_THREAD_ID, 
		       IARG_MEMORYWRITE_EA, 
		       IARG_END);

        if (INS_HasFallThrough(ins))
        {
            INS_InsertPredicatedCall(ins, 
				     IPOINT_AFTER, 
				     AFUNPTR(EmitWrite), 
				     IARG_THREAD_ID, 
				     IARG_MEMORYWRITE_SIZE,
				     IARG_END);
        }
        if (INS_IsBranchOrCall(ins))
        {
            INS_InsertPredicatedCall(ins, IPOINT_TAKEN_BRANCH,
				     AFUNPTR(EmitWrite), 
				     IARG_THREAD_ID, IARG_MEMORYWRITE_SIZE, 
				     IARG_END);
        }
    }

    if (INS_HasMemoryRead2(ins))
    {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(EmitRead), 
				 IARG_THREAD_ID, IARG_MEMORYREAD2_EA, 
				 IARG_MEMORYREAD_SIZE, IARG_END);
    }

    if (INS_IsMemoryRead(ins) && !INS_IsPrefetch(ins))
    {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(EmitRead),
				 IARG_THREAD_ID, IARG_MEMORYREAD_EA, 
				 IARG_MEMORYREAD_SIZE, IARG_END);
    }
}


/* ===================================================================== */
VOID Trace(TRACE trace, VOID *v)
{
    if (!filter.SelectTrace(trace))
        return;

    if (enabled)
    {
        for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
        {
	  bool first=true;
	  for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
            {
	      if (KnobOptBB && !first)
		{
		  break;
		}

	      InstructionTrace(trace, ins);
	      
	      CallTrace(trace, ins);
	      
	      MemoryTrace(ins);

	      first=false;
            }
        }
    }
}


/* ===================================================================== */

VOID Fini(int, VOID * v)
{
    out << "# $eof" <<  endl;
    out.close();
    
    if (KnobLeader)
      {
	signal_out << " # $eof" << endl;
	signal_out.close();
      }
}
    
/* ===================================================================== */

/*
static void OnSig(THREADID threadIndex, 
                  CONTEXT_CHANGE_REASON reason, 
                  const CONTEXT *ctxtFrom,
                  CONTEXT *ctxtTo,
                  INT32 sig, 
                  VOID *v)
{
  if (ctxtFrom != 0)
    {
        ADDRINT address = PIN_GetContextReg(ctxtFrom, REG_INST_PTR);
        out << "SIG signal=" << dec << sig << " on thread " << threadIndex
            << " at address " << hex << address << dec << " #instrs = " << instrs << " ";
        cout << "SIG signal=" << dec << sig << " on thread " << threadIndex
            << " at address " << hex << address << dec << " #instrs = " << instrs << " ";
        cerr << "SIG signal=" << dec << sig << " on thread " << threadIndex
	     << " at address " << hex << address << dec << " #instrs = " << instrs << " "; 

    }
    else
      {
	out << "SIG signal=" << dec << sig << " on thread " << threadIndex
	    << " #instrs = " << instrs << " ";
	cout << "SIG signal=" << dec << sig << " on thread " << threadIndex
	    << " #instrs = " << instrs << " ";
	cerr << "SIG signal=" << dec << sig << " on thread " << threadIndex
	    << " #instrs = " << instrs << " ";
      }

    switch (reason)
    {
      case CONTEXT_CHANGE_REASON_FATALSIGNAL:
        out << "FATALSIG " << sig;
        break;
      case CONTEXT_CHANGE_REASON_SIGNAL:
        out << "SIGNAL " << sig;
        break;
      case CONTEXT_CHANGE_REASON_SIGRETURN:
        out << "SIGRET ";
        break;
   
      case CONTEXT_CHANGE_REASON_APC:
        out << "APC ";
        break;

      case CONTEXT_CHANGE_REASON_EXCEPTION:
        out << "EXCEPTION ";
        break;

      case CONTEXT_CHANGE_REASON_CALLBACK:
        out << "CALLBACK ";
        break;

      default: 
        break;
    }
    out << std::endl;
    cout << std::endl;
    cerr << std::endl;
}
*/

VOID ForkParent(THREADID tid, const CONTEXT *ctxt, VOID* v)
{
  cout << "PARENT HERE " << tid << "," << PIN_GetPid() << endl;
  cerr << "PARENT HERE " << tid << "," << PIN_GetPid() << endl;
  forked = 1;
}

VOID ForkChild(THREADID tid, const CONTEXT *ctxt, VOID* v)
{
  cout << "Child HERE " << tid << "," << PIN_GetPid() << endl;
  cerr << "Child HERE " << tid << "," << PIN_GetPid() << endl;
  forked = 1;
}
/* ===================================================================== */

LOCALVAR CONTROL control;
LOCALVAR SKIPPER skipper;

/* ===================================================================== */

/* 
BOOL FollowChild(CHILD_PROCESS childProcess, VOID*val)
{
  return TRUE;
}
*/


BOOL signal_callback(THREADID tid, INT32 sig, 
		     CONTEXT *ctxt, BOOL hasHandler, 
		     const EXCEPTION_INFO *pExceptInfo, 
		     VOID *v)
{
  if (KnobLeader)
    {
      signal_out << dec << "signal=" << sig << endl;
      signal_out << dec << "instrs=" << instrs << endl;
      cerr << "delivering signal = " << sig << ", instrs = " << instrs << endl;
      out << "delivering signal = " << sig << ", instrs = " << instrs << endl;
      return TRUE;
    }
  else 
    {
      if (signal_eof)
	{
	  return FALSE;
	}

      if (instrs == next_instr_num && sig == next_signal)
	{
	  // cerr << "replaying signal = " << sig << ", instrs = " << instrs << endl;
	  out << "delivering signal = " << sig << ", instrs = " << instrs << endl;
	  read_next_signal();
	  return TRUE;
	}
      else if (next_instr_num < instrs)
	{ 
	  // cerr << "replaying signal = " << sig << ", instrs = " << instrs << endl;
	  out << "delivering signal = " << sig << ", instrs = " << instrs << endl;
	  read_next_signal();
	  return TRUE;
	}
      else
	{
	  return FALSE;
	}
    }
}


int main(int argc, CHAR *argv[], CHAR* envp[])
{

    PIN_InitSymbols();

    /*
    // PRINT ARGUMENTS 
    int i = 0;
    for (; i < argc; i++)
      {
	cerr << "argv[" << i << "] = string(\"" << string(argv[i]) << "\").c_str();"  << endl;
      }
    */

    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    
    string t = KnobAtRandomAddress.Value();
    t = t.substr(2);
    istringstream s(t);
    s >> hex >> AT_RANDOM_ADDRESS;
    cerr << "AT_RANDOM_ADDRESS = " << hex << AT_RANDOM_ADDRESS << dec << endl;
    
    my_original_pid = PIN_GetPid();

    string filename =  KnobOutputFile.Value();
    string memfilename = KnobMemoryFile.Value();
    string timefilename = KnobTimeFile.Value();
    string dayfilename = KnobDayFile.Value();
    string sysoutfile = KnobSysFile.Value();
    string epollfilename = KnobEpollFile.Value();
    string clockfilename = KnobClockFile.Value();
    string signalfilename = KnobSignalFile.Value();
    string timexfilename = KnobAdjTimexFile.Value();

    if (KnobPid)
      filename += "." + decstr( getpid_portable() );
    
    sysout.open(sysoutfile.c_str());
    
    out.open(filename.c_str());
    out << hex << right;
    out.setf(ios::showbase);
    
    outmem.open(memfilename.c_str());
    outmem << hex << right;
    outmem.setf(ios::showbase);

    
    if (KnobLeader)
      {
	timing_out.open(timefilename.c_str());
	gettimeofday_out.open(dayfilename.c_str());
	epoll_out.open(epollfilename.c_str());
	clock_out.open(clockfilename.c_str());
	signal_out.open(signalfilename.c_str());
	timex_out.open(timexfilename.c_str());
      }
    else
      {
	timing_in.open(timefilename.c_str());
	gettimeofday_in.open(dayfilename.c_str());
	epoll_in.open(epollfilename.c_str());
	clock_in.open(clockfilename.c_str());
	signal_in.open(signalfilename.c_str());
	timex_in.open(timexfilename.c_str());
      }
    
    control.CheckKnobs(Handler, 0);
    skipper.CheckKnobs(0);

    if (KnobFixSignals)
      {

	PIN_InterceptSignal(14, signal_callback, (void*)NULL);
	// PIN_InterceptSignal(0, signal_callback, (void*)NULL);
      }
    
    TRACE_AddInstrumentFunction(Trace, 0);
    // PIN_AddContextChangeFunction(OnSig, 0);
     
    PIN_AddForkFunction(FPOINT_AFTER_IN_PARENT, ForkParent, 0);
    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, ForkChild, 0);
    
    PIN_AddSyscallEntryFunction(SysBegin, 0);
    PIN_AddSyscallExitFunction(SysEnd, 0);
       
    // Ignoring this because of PIN errors 
    // PIN_AddFollowChildProcessFunction(FollowChild, 0);

    PIN_AddFiniFunction(Fini, 0);


    filter.Activate();
    icount.Activate();
    
    // Never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
