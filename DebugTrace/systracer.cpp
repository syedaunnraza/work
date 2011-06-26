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

#include "syscall_utils.h"
#include "syscalls_printer.h"

/*
#include <syscalls_
#include <utime.h>
#include <signal.h>
#include <sys/utsname.h>
#include <ustat.h>
#include <sys/resource.h>
#include <asm/ldt.h>
#include <linux/futex.h>
#include <sys/epoll.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <arpa/inet.h>
*/

using namespace INSTLIB;

#define DEBUG 1

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

// Important Options
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
			    "o", "systracer.out", "output file");


/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

// trace output stream
LOCALVAR std::ofstream out;

/* ===================================================================== */
/* Function Definitions */
/* ===================================================================== */

INT32 Usage()
{
  cerr <<
      "This pin tool translates system calls for debugging" << endl;
  cerr << KNOB_BASE::StringKnobSummary();
  cerr << endl;
  return -1;
}

LOCALFUN VOID Fini(int, VOID * v);


VOID SysBegin(THREADID threadIndex, CONTEXT *ctxt, 
	      SYSCALL_STANDARD std, VOID *v)
{
  HandleSysBegin(threadIndex, ctxt, std, v);
}

VOID SysEnd(THREADID threadIndex, CONTEXT *ctxt, 
	    SYSCALL_STANDARD std, VOID *v)
{
  HandleSysEnd(threadIndex, ctxt, std, v);
}

/* ===================================================================== */

VOID InstructionTrace(TRACE trace, INS ins)
{
  return;
}

/* ===================================================================== */
VOID MemoryTrace(INS ins)
{
  return;
}

/* ===================================================================== */
VOID Trace(TRACE trace, VOID *v)
{
  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
      for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
	{
	  InstructionTrace(trace, ins);
	  MemoryTrace(ins);
	}
    }
}


/* ===================================================================== */

VOID Fini(int, VOID * v)
{
  CloseOutputFile();
}
    
/* ===================================================================== */

int main(int argc, CHAR *argv[], CHAR* envp[])
{
    PIN_InitSymbols();
    
    if( PIN_Init(argc,argv) )
    {
      return Usage();
    }
    
    string filename =  KnobOutputFile.Value();
    SetOutputFile(filename);
    
    TRACE_AddInstrumentFunction(Trace, 0);
    
    PIN_AddSyscallEntryFunction(SysBegin, 0);
    PIN_AddSyscallExitFunction(SysEnd, 0);
    
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
