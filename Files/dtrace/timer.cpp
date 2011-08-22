#include "pin.H"
#include "instlib.H"
#include "portability.H"
#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <elf.h>
#include <time.h>

using namespace INSTLIB;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobIn(KNOB_MODE_WRITEONCE, "pintool", 
		    "input", "", "input");

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */
LOCALVAR ADDRINT pc;
LOCALVAR ADDRINT target_count;
LOCALVAR ADDRINT count_so_far;
LOCALVAR ADDRINT percent;

LOCALVAR clock_t start_time;
LOCALVAR clock_t end_time;
LOCALVAR clock_t execution_finish_time;

LOCALVAR BOOL done_timing = false;

LOCALVAR time_t Atime;
LOCALVAR time_t Btime;

#define CLOCKS_PER_MS (CLOCKS_PER_SEC / 1000);

static void update_count()
{
  count_so_far ++;
  cout << "count_so_far = " << count_so_far << ". want = " << target_count  << "." << endl;
  if (count_so_far == target_count)
    {
      end_time = clock() / CLOCKS_PER_MS;
      PIN_ExitApplication(0);
      // PIN_ExitProcess(0);
    }
}

INT32 Usage()
{
  cerr <<
      "This pin tool times program until a certain PC is seen a given number of times" << endl;
  cerr << KNOB_BASE::StringKnobSummary();
  cerr << endl;
  return -1;
}

LOCALFUN VOID Fini(int, VOID * v);

/* ===================================================================== */
VOID InstructionTrace(TRACE trace, INS ins)
{
  ADDRINT addr = INS_Address(ins);
  if (addr == pc)
    {
      INS_InsertCall(ins, IPOINT_BEFORE, 
		     (AFUNPTR)update_count, 
		     IARG_END);
    }
}

/* ===================================================================== */
VOID Trace(TRACE trace, VOID *v)
{
  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
      for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
	{
	  InstructionTrace(trace, ins);
	}
    }
}

/* ===================================================================== */

VOID Fini(int, VOID * v)
{
  cout << "Fini" << endl;
  UINT64 diff_time = (UINT64) (end_time - start_time);
  cout << "time elapsed = <" << diff_time << "> ms." << endl;
  
  execution_finish_time = clock() / CLOCKS_PER_MS;
  UINT64 execution_diff_time = (UINT64) (execution_finish_time - start_time);
  cout << "total time elapsed = <" << execution_diff_time << "> ms." << endl;

  time(&Btime);
  double dif = difftime(Btime, Atime);
  cout << "dif = " << dif << endl;
}

static void OnSig(THREADID threadIndex, 
                  CONTEXT_CHANGE_REASON reason, 
                  const CONTEXT *ctxtFrom,
                  CONTEXT *ctxtTo,
                  INT32 sig, 
                  VOID *v)
{
    switch (reason)
    {
    case CONTEXT_CHANGE_REASON_FATALSIGNAL:
      if (!done_timing)
	{
	  cout << "Fatal Sig" << endl;
	  UINT64 diff_time = (UINT64) (end_time - start_time);
	  cout << "time elapsed = <" << diff_time << "> ms." << endl;
	  
	  execution_finish_time = clock() / CLOCKS_PER_MS;
	  UINT64 execution_diff_time = (UINT64) (execution_finish_time - start_time);
	  cout << "total time elapsed = <" << execution_diff_time << "> ms." << endl;

	  time(&Btime);
	  double dif = difftime(Btime, Atime);
	  cout << "dif = " << dif << endl;
	}
      break;
    default: 
        break;
    }
}
    
/* ===================================================================== */

int main(int argc, CHAR *argv[], CHAR* envp[])
{
    PIN_InitSymbols();
    
    if( PIN_Init(argc,argv) )
    {
      cout << "Expected Input Looks Like:" << endl;
      cout << "percent <10> pc <b640a358> count <1>" << endl << endl;
      return Usage();
    }

    string input = KnobIn.Value();
    cout << input << endl;

    string _percent_str = input.substr(9, 2);
    // cout << "_percent_str = " << _percent_str << endl;    

    string _pc_str = input.substr(17, 8);
    // cout << "_pc_str = " << _pc_str << endl;

    input = input.substr(26);
    int first = input.find('<');
    int next = input.find('>');

    string _count_str = input.substr(first+1, next-first-1);

    istringstream myStream1(_percent_str);    
    myStream1 >> percent;

    istringstream myStream2(_pc_str);    
    myStream2 >> hex >> pc;

    istringstream myStream3(_count_str);    
    myStream3 >> target_count;

    count_so_far = 0;

    // cout << "percent = " << percent << endl;
    // cout << "count = " << target_count << endl;
    // cout << "pc = " << hex << pc << endl;

    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_AddContextChangeFunction(OnSig, 0);
    
    // Never returns
    time(&Atime);

    start_time = clock() / CLOCKS_PER_MS;
    end_time = start_time;

    PIN_StartProgram();
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
