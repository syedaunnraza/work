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
#include <netinet/in.h>
#include <arpa/inet.h>

#include "syscalls_printer_mult.h"
#include "syscall_utils.h"

#define DEBUG 1

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

// Important Options
KNOB<string> KnobSysFile(KNOB_MODE_WRITEONCE, "pintool",
			    "sysfile", "systracer.out", "syscalls output file");
KNOB<BOOL>   KnobTraceSys(KNOB_MODE_WRITEONCE,  "pintool",
		       "sys", "1", "determinize sys calls");
KNOB<BOOL>   KnobFixPid(KNOB_MODE_WRITEONCE,  "pintool",
		       "pid", "0", "determinize pid");
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
			    "o", "trace.log", "trace file");
KNOB<BOOL> KnobDevRandom(KNOB_MODE_WRITEONCE, "pintool",
			   "devrand", "0", "trace file");

KNOB<string> KnobTimeFile(KNOB_MODE_WRITEONCE, "pintool",
			    "time", "time.out", "trace file");
KNOB<string> KnobDayFile(KNOB_MODE_WRITEONCE, "pintool",
			    "day", "day.out", "trace file");

KNOB<BOOL> KnobLeader(KNOB_MODE_WRITEONCE, "pintool",
		      "leader", "1", "trace file");

KNOB<BOOL>   KnobSymbols(KNOB_MODE_WRITEONCE, "pintool",
			 "symbols", "0", "include symbol information");
KNOB<BOOL>   KnobRdtsc(KNOB_MODE_WRITEONCE,  "pintool",
		       "rdtsc", "0", "emulate rdtsc");
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
// Less Frequently Used Options
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

/* ===================================================================== */
/* Thread Data */
/* ===================================================================== */

static TLS_KEY tls_key;
PIN_LOCK lock;
INT32 numThreads = 0;
BOOL forked = 0;

class thread_data_t 
{
public:
  // my id
  INT32 myThreadId;

  // the first instruction flag is used to dump memory
  INT32 firstInstruction;
  std::ofstream outmem;
  
  // trace output stream
  std::ofstream out;
  std::ofstream sys_out;

  // timing output stream
  std::ofstream timing_out;
  std::ifstream timing_in;
  std::ofstream gettimeofday_out;
  std::ifstream gettimeofday_in;
  
  typedef UINT64 COUNTER;
  INT32 enabled;
  FILTER filter;
  ICOUNT icount;
  
  // set this for every program separately
  ADDRINT AT_RANDOM_ADDRESS;
  
  // system call related stuff
  BOOL outstanding_syscall;
  ADDRINT last_syscall_number;
  
  BOOL canary_done;
  BOOL guard_done;
  
  // fd for dev_urandom
  vector<ADDRINT> urandom_fds;
  
  // my own pid
  int my_original_pid;
  int my_simulated_pid;
  
  // child pids
  map<int,int> pid_child_trans_table;
  int next_child_pid;
  
  // stored times
  time_t root_dir_time;
  time_t job_cache_time;
  
  // instructions executed
  UINT64 instrs;
};

thread_data_t* get_tls(THREADID tid);



/*
LOCALFUN BOOL Emit(THREADID threadid)
{
  return true;
}

LOCALFUN VOID Flush()
{

}
*/

VOID EmitNoValues(THREADID threadid, string * str)
{

}

VOID Emit1Values(THREADID threadid, string * str, string * reg1str, 
		 ADDRINT reg1val)
{

}

VOID Emit2Values(THREADID threadid, string * str, string * reg1str,
		 ADDRINT reg1val, string * reg2str, ADDRINT reg2val)
{

}

VOID Emit3Values(THREADID threadid, string * str, string * reg1str, 
		 ADDRINT reg1val, string * reg2str, 
		 ADDRINT reg2val, string * reg3str, ADDRINT reg3val)
{

}


VOID Emit4Values(THREADID threadid, string * str, string * reg1str, 
		 ADDRINT reg1val, string * reg2str, ADDRINT reg2val, 
		 string * reg3str, ADDRINT reg3val, string * reg4str, 
		 ADDRINT reg4val)
{

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

}

VOID AddXMMEmit(INS ins, IPOINT point, REG xmm_dst) 
{

}
#endif

VOID PrintRdtsc(string & traceString)
{
 
}

VOID CountInstruction()
{

}

VOID AddEmit(INS ins, IPOINT point, 
	     string & traceString, UINT32 regCount, REG regs[])
{
 
}

LOCALVAR VOID *WriteEa[PIN_MAX_THREADS];

VOID CaptureWriteEa(THREADID threadid, VOID * addr)
{
  WriteEa[threadid] = addr;
}

VOID ShowN(UINT32 n, VOID *ea)
{

}


VOID EmitWrite(THREADID threadid, UINT32 size)
{

}

VOID EmitRead(THREADID threadid, VOID * ea, UINT32 size)
{

}


VOID Indent()
{

}

VOID EmitICount()
{

}

VOID EmitDirectCall(THREADID threadid, string * str, INT32 tailCall, ADDRINT arg0, ADDRINT arg1)
{

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

}

/* ===================================================================== */      
VOID EmitReturn(THREADID threadid, string * str, ADDRINT ret0)
{

}
       
/* ===================================================================== */      
VOID CallTrace(TRACE trace, INS ins)
{

}

/* ===================================================================== */ 
VOID PrintImageMemory(IMG img) 
{

}

/* ===================================================================== */
VOID SysBegin(THREADID threadIndex, CONTEXT *ctxt, 
	      SYSCALL_STANDARD std, VOID *v)
{
  thread_data_t* tdata = get_tls(threadIndex);

  if (forked && getpid() != tdata->my_original_pid)
    return;

  HandleSysBegin(threadIndex, ctxt, std, v, tdata->sys_out);
}

VOID SysEnd(THREADID threadIndex, CONTEXT *ctxt, 
	    SYSCALL_STANDARD std, VOID *v)
{
  thread_data_t* tdata = get_tls(threadIndex);
  if (forked && getpid() != tdata->my_original_pid)
    return;
  HandleSysEnd(threadIndex, ctxt, std, v, tdata->sys_out);
}

/* ===================================================================== */
VOID InstructionTrace(TRACE trace, INS ins)
{

}

/* ===================================================================== */
VOID MemoryTrace(INS ins)
{

}


/* ===================================================================== */
VOID Trace(TRACE trace, VOID *v)
{

}


/* ===================================================================== */

VOID Fini(int, VOID * v)
{

}
    
/* ===================================================================== */

static void OnSig(THREADID threadIndex, 
                  CONTEXT_CHANGE_REASON reason, 
                  const CONTEXT *ctxtFrom,
                  CONTEXT *ctxtTo,
                  INT32 sig, 
                  VOID *v)
{

}

/* ===================================================================== */
INT32 Usage()
{
  cerr <<
      "This pin tool collects an instruction trace for debugging" << endl;
  cerr << KNOB_BASE::StringKnobSummary();
  cerr << endl;
  return -1;
}

/* ===================================================================== */
thread_data_t* get_tls(THREADID tid)
{
  thread_data_t* tdata =
    static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, tid));
  return tdata;
}

VOID ThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
  cerr << string("THREAD START") << endl;
  
  GetLock(&lock, tid+1);
  
  // Iniitalize TLS
  thread_data_t *tdata = new thread_data_t;

  tdata->myThreadId = numThreads++;
  tdata->firstInstruction = 0;
  tdata->enabled = 0;
  tdata->AT_RANDOM_ADDRESS = 0xbffff49b;

  tdata->outstanding_syscall = false;
  tdata->last_syscall_number = 0;

  tdata->canary_done = false;
  tdata->guard_done = false;

  tdata->my_original_pid = getpid();
  tdata->my_simulated_pid = 0x7003;
  tdata->next_child_pid = 30000;
  
  tdata->root_dir_time = (time_t)0;
  tdata->job_cache_time = (time_t)0;

  tdata->instrs = 0;
  
  string filename =  (KnobOutputFile.Value()) + "." + decstr(tdata->myThreadId);
  string memfilename = KnobMemoryFile.Value() + "." + decstr(tdata->myThreadId);
  string timefilename = KnobTimeFile.Value()+ "." + decstr(tdata->myThreadId);
  string dayfilename = KnobDayFile.Value()+ "." + decstr(tdata->myThreadId);
  string sysoutfile = KnobSysFile.Value()+ "." + decstr(tdata->myThreadId);
  
  tdata->out.open(filename.c_str());
  tdata->out << hex << right;
  tdata->out.setf(ios::showbase);
    
  tdata->sys_out.open(sysoutfile.c_str());

  tdata->outmem.open(memfilename.c_str());
  tdata->outmem << hex << right;
  tdata->outmem.setf(ios::showbase);
  
  if (KnobLeader)
    {
      tdata->timing_out.open(timefilename.c_str());
      tdata->gettimeofday_out.open(dayfilename.c_str());
    }
  else
    {
      tdata->timing_in.open(timefilename.c_str());
      tdata->gettimeofday_in.open(dayfilename.c_str());
    }
  
  ReleaseLock(&lock);
  PIN_SetThreadData(tls_key, tdata, tid);

}

VOID ThreadFini(THREADID tid, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    GetLock(&lock, tid+1);
    // do nothing for now
    ReleaseLock(&lock);
}

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

int main(int argc, CHAR *argv[], CHAR* envp[])
{
    PIN_InitSymbols();
    
    if(PIN_Init(argc,argv)) return Usage();

    // Initialize Lock
    InitLock(&lock);
    
    // Obtain Key for TLS
    tls_key = PIN_CreateThreadDataKey(0);
    
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);

    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddContextChangeFunction(OnSig, 0);
    
    PIN_AddSyscallEntryFunction(SysBegin, 0);
    PIN_AddSyscallExitFunction(SysEnd, 0);
    
    PIN_AddForkFunction(FPOINT_AFTER_IN_PARENT, ForkParent, 0);
    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, ForkChild, 0);

    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
