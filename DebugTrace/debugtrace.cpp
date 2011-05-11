#include "pin.H"
#include "instlib.H"
#include "portability.H"
#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <elf.h>

using namespace INSTLIB;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

// Important Options
KNOB<BOOL>   KnobFixPid(KNOB_MODE_WRITEONCE,  "pintool",
		       "pid", "0", "determinize pid");
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
			    "o", "trace.log", "trace file");
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
KNOB<BOOL>   KnobSilent(KNOB_MODE_WRITEONCE, "pintool",
			"silent", "0", 
			"Do everything but write file (for debugging).");
KNOB<BOOL> KnobEarlyOut(KNOB_MODE_WRITEONCE, "pintool", "early_out", "0" , 
			"Exit after tracing the first region.");

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

// the first instruction flag is used to dump memory
LOCALVAR INT32 firstInstruction = 1;
LOCALVAR std::ofstream outmem;

// trace output stream
LOCALVAR std::ofstream out;

typedef UINT64 COUNTER;
LOCALVAR INT32 enabled = 0;
LOCALVAR FILTER filter;
LOCALVAR ICOUNT icount;

LOCALVAR ADDRINT AT_RANDOM_ADDRESS = 0xbffff49b;

LOCALVAR BOOL outstanding_syscall = false;
LOCALVAR ADDRINT last_syscall_number = 0;

LOCALVAR BOOL canary_done = false;
LOCALVAR BOOL guard_done = false;

LOCALVAR string fillers[] = 
  {
    "                                       ",
    "                                      ", 
    "                                     ",
    "                                    ",
    "                                   ",
    "                                  ",
    "                                 ",
    "                                ",
    "                               ",
    "                              ",
    "                             ",
    "                            ",
    "                           ",
    "                          ",
    "                         ",
    "                        ",
    "                       ",
    "                      ",
    "                     ",
    "                    ",
    "                   ",
    "                  ",
    "                 ",
    "                ",
    "               ",
    "              ",
    "             ",
    "            ",
    "           ",
    "          ",
    "         ",
    "        ",
    "       ",
    "      ",
    "     ",
    "    ",
    "   ",
    "  ",
    " ",
    ""
  };

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
  cout << "AT_RANDOM[0] i.e. libc canary src =  0x12345678" << endl;
}

static void overwrite_AT_RANDOM_4()
{
  *(((int*)AT_RANDOM_ADDRESS)+1) = 0x87654321;
  cout << "AT_RANDOM[1] i.e. stack guard src =  0x87654321" << endl;
}

INT32 Usage()
{
  cerr <<
      "This pin tool collects an instruction trace for debugging" << endl;
  cerr << KNOB_BASE::StringKnobSummary();
  cerr << endl;
  return -1;
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
  out << traceString << endl;
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
            out << x << " = *(UINT32*)" << ea << endl;
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
  if (outstanding_syscall)
    cout << "***WARNING***: [SysBegin] Interruptable " 
	 << "System Call Situation" << endl;
  
  last_syscall_number = PIN_GetSyscallNumber(ctxt, std);
  outstanding_syscall = true;
}

VOID SysEnd(THREADID threadIndex, CONTEXT *ctxt, 
	    SYSCALL_STANDARD std, VOID *v)

{
  if (!outstanding_syscall)
        cout << "***WARNING***: [SysEnd] No outstanding " 
	 << "System Call Situation" << endl;
  
  if (last_syscall_number == 0x102)
    {
      PIN_SetContextReg(ctxt, REG_EAX, 0x7003);
      cout << "Changing Pid to 0x" << hex << 0x7003 << endl;
      out << "Changing Pid to 0x" << hex << 0x7003 << endl;
    }
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
  
  if (!guard_done && KnobFixPointerGuard)
    {
      INS_InsertCall(ins, IPOINT_BEFORE, 
		     (AFUNPTR)overwrite_AT_RANDOM_4, 
		     IARG_END);
      guard_done = true;
    }
  
    if(KnobRdtsc && INS_IsRDTSC(ins))
      {
	// rax = 0x7eab816a, rdx = 0x6b7
	INS_InsertCall(ins,
		       IPOINT_BEFORE,
		       AFUNPTR(SendToRax),
		       IARG_RETURN_REGS,
		       REG_EAX,
		       IARG_END);
	
	INS_InsertCall(ins,
		       IPOINT_BEFORE,
		       AFUNPTR(SendToRdx),
		       IARG_RETURN_REGS,
		       REG_EDX,
		       IARG_END);
	
	s += "\t <----rdtsc replaced---->";
	
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
    
    // Format the string at instrumentation time
    string function = "";
    if (KnobPrintFunc) 
      {
	function = RTN_FindNameByAddress(addr) + "\r\n"; 
      }	
    
    //string traceString = "";
    // string astring = FormatAddress(addr, TRACE_Rtn(trace));
    //for (INT32 length = astring.length(); length < 30; length++)
    //  {
    //    traceString += " ";
    //  }

    //traceString = function + astring + traceString;
    string traceString = s + "  " + dis;
    if (traceString.length() < 50 && (traceString.length() >= 10))
      {
	traceString += fillers[traceString.length() - 10];
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
}
    
/* ===================================================================== */

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
        out << "SIG signal=" << sig << " on thread " << threadIndex
            << " at address " << hex << address << dec << " ";
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
}

/* ===================================================================== */

LOCALVAR CONTROL control;
LOCALVAR SKIPPER skipper;

/* ===================================================================== */

int main(int argc, CHAR *argv[], CHAR* envp[])
{
    PIN_InitSymbols();
    
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    
    string filename =  KnobOutputFile.Value();
    string memfilename = KnobMemoryFile.Value();

    if( KnobPid )
    {
      filename += "." + decstr( getpid_portable() );
    }
    
    // Do this before we activate controllers 
    out.open(filename.c_str());
    out << hex << right;
    out.setf(ios::showbase);

    outmem.open(memfilename.c_str());
    outmem << hex << right;
    outmem.setf(ios::showbase);
    
    control.CheckKnobs(Handler, 0);
    skipper.CheckKnobs(0);
    
    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddContextChangeFunction(OnSig, 0);
  
    if (KnobFixPid)
      {
	PIN_AddSyscallEntryFunction(SysBegin, 0);
	PIN_AddSyscallExitFunction(SysEnd, 0);
      }
    
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