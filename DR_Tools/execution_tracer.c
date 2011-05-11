#include <stddef.h> /* for offsetof */
#include "dr_api.h"
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

/*** FUNCTION PROTOTYPES ***/
static void event_exit(void);
static dr_emit_flags_t event_basic_block(void *drcontext, 
					 void *tag,
					 instrlist_t *bb,
                                         bool for_trace, 
					 bool translating);

static void event_thread_init(void* drcontext);
static void event_thread_exit(void* drcontext);

static file_t open_file(const char*, uint flags);
static void trace_instr(app_pc instr_pc);
static void trace_instr_reg(void);

static void print_mangler(void);
static void print_canary_value(void);

/*** GLOBAL VARIABLES ***/
int number_threads;

bool mangler_printed = false;
int mangler_value = 0;

bool canary_printed = false;
int canary_value = 0;

bool mangler_fixed = false;

// Flags
#define DEBUG 0
#define DISASSEMBLE 1
#define PRINT_REG 1

#define OPTIMIZE_BBLOCK 0

#define PRINT_MANGLER 0
#define MANGLER_OFFSET 0x18

#define PRINT_CANARY 0
#define CANARY_OFFSET 0x14

#define DETERMINIZE_MANGLER 1
#define MANGLER_FIXED_VALUE 0x11989d2e

// Files 
file_t output_handle;

/*** FUNCTION DEFINITIONS ***/
static void
print_mangler(void)
{
  dr_fprintf(output_handle, "gs:%x = %x\n", MANGLER_OFFSET,
	     mangler_value);
}

static void 
print_canary_value(void)
{
  dr_fprintf(output_handle, "gs:%x = %x\n", CANARY_OFFSET,
	     canary_value);
}

static void 
trace_instr(app_pc instr_pc)
{
  void* dr_context = dr_get_current_drcontext();
  disassemble_with_info(dr_context, 
			instr_pc, 
			output_handle,
			true, /* show app_pc */
			true  /* don't show raw bytes */
			);
}

static void 
trace_instr_reg(void)
{
  void* dr_context = dr_get_current_drcontext();
  dr_mcontext_t mcontext;
  int temp;

  dr_get_mcontext(dr_context, &mcontext, NULL);
  
  dr_fprintf(output_handle, 
	     "rax = %x, rbx = %x, rcx = %x, rdx = %x, rdi = %x, rsi = %x,\
	     rbp = %x, rsp = %x\n",
	     mcontext.xax, mcontext.xbx, mcontext.xcx, mcontext.xdx,
	     mcontext.xdi, mcontext.xsi, mcontext.xbp, mcontext.xsp
	     );
  /*
  dr_fprintf(STDOUT, 
	     "rax = %x, rbx = %x, rcx = %x, rdx = %x, rdi = %x, rsi = %x,\
	     rbp = %x, rsp = %x\n",
	     mcontext.xax, mcontext.xbx, mcontext.xcx, mcontext.xdx,
	     mcontext.xdi, mcontext.xsi, mcontext.xbp, mcontext.xsp
	     );
  */
}

static file_t
open_file(const char * file_name, uint flags)
{
  file_t file_handle = dr_open_file(file_name, flags);
  if (file_handle == INVALID_FILE)
    {
      dr_fprintf(STDERR, "dr_open(%s) failed\n", file_name);
      exit(-1);
    }
  return file_handle;
}

static void 
event_thread_init(void* drcontext)
{
  number_threads++;
#if DEBUG
  dr_fprintf(output_handle, "Some Thread is Being Spawned\n");
#endif
}

static void
event_thread_exit(void* drcontext)
{
#if DEBUG
  dr_fprintf(output_handle, "Some Thread is Exiting\n");
#endif
}

DR_EXPORT void 
dr_init(client_id_t id)
{
  output_handle = open_file("trace.log", DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);

  /* register events */
  dr_register_exit_event(event_exit);
  dr_register_bb_event(event_basic_block);
  dr_register_thread_init_event(event_thread_init);
  dr_register_thread_exit_event(event_thread_exit);
  
  /* make it easy to tell, by looking at log file, which client executed */
  dr_log(NULL, LOG_ALL, 1, "client 'execution tracer' initializing\n");

  /* also give notification to stderr */
  if (dr_is_notify_on())
    dr_fprintf(STDERR, "client 'execution tracer' is running\n");
}

static void 
event_exit(void)
{
#if DEBUG
  dr_fprintf(output_handle, "there were %d threads in total\n", 
	     number_threads);
#endif
  //dr_close_file(output_handle);
}

static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating)
{
  instr_t *instr, *new_instr;
  int i;
  app_pc instr_pc;
  opnd_t opnd1, opnd2;

  bool first_instruction = true;

  for (instr  = instrlist_first(bb); 
       instr != NULL; 
       instr  = instr_get_next(instr)) 
    {
      instr_pc = instr_get_app_pc(instr);

#if PRINT_MANGLER
      if (!mangler_printed)
	{
	  reg_id_t reg1 = DR_REG_XCX;
	  
	  // save reg
	  dr_save_reg(drcontext, bb, instr, reg1, SPILL_SLOT_2);
	  
	  // mov gs:<mangler_offset> -> reg
	  opnd_t opnd1 = opnd_create_reg(reg1);
	  opnd_t opnd2 = opnd_create_far_abs_addr(DR_SEG_GS, 
						  (void*)MANGLER_OFFSET,
						  OPSZ_4);
	  instr_t* new_instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
	  instrlist_meta_preinsert(bb, instr, new_instr);
	  
	  // mov reg-> global var
	  opnd2 = OPND_CREATE_ABSMEM(&mangler_value, OPSZ_4);
	  new_instr = INSTR_CREATE_mov_st(drcontext, opnd2, opnd1);
	  instrlist_meta_preinsert(bb, instr, new_instr);
	  
	  // insert call to print the mangler value
	  dr_insert_clean_call(drcontext, bb, instr, 
			       (void*)print_mangler, false, 0);
	  // restore reg
	  dr_restore_reg(drcontext, bb, instr, reg1, SPILL_SLOT_2);

	  mangler_printed=true;
	}
#endif

#if PRINT_CANARY
      if (!canary_printed)
	{
	  reg_id_t reg1 = DR_REG_XCX;
	  
	  // save reg
	  dr_save_reg(drcontext, bb, instr, reg1, SPILL_SLOT_2);
	  
	  // mov gs:<canary_offset> -> reg
	  opnd_t opnd1 = opnd_create_reg(reg1);
	  opnd_t opnd2 = opnd_create_far_abs_addr(DR_SEG_GS, 
						  (void*)CANARY_OFFSET,
						  OPSZ_4);
	  instr_t* new_instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
	  instrlist_meta_preinsert(bb, instr, new_instr);
	  
	  // mov reg-> global var
	  opnd2 = OPND_CREATE_ABSMEM(&canary_value, OPSZ_4);
	  new_instr = INSTR_CREATE_mov_st(drcontext, opnd2, opnd1);
	  instrlist_meta_preinsert(bb, instr, new_instr);
	  
	  // insert call to print the canary value
	  dr_insert_clean_call(drcontext, bb, instr, 
			       (void*)print_canary_value, false, 0);
	  // restore reg
	  dr_restore_reg(drcontext, bb, instr, reg1, SPILL_SLOT_2);

	  canary_printed = true;
	}
#endif

#if DETERMINIZE_MANGLER
      if (!mangler_fixed)
	{
	  // move a fixed value into gs:<mangler_offset>
	  opnd1 = opnd_create_far_abs_addr(DR_SEG_GS, 
					   (void*)MANGLER_OFFSET,
					   OPSZ_4);
	  opnd2 = OPND_CREATE_INT32(MANGLER_FIXED_VALUE);
	  new_instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
	  instrlist_meta_preinsert(bb, instr, new_instr);
	  mangler_fixed = true;
	  continue;
	}
#endif

      if (instr_pc == NULL)
	continue;

#if OPTIMIZE_BBLOCK
      if(!first_instruction)
	{
	  continue;
	}
      first_instruction=false;
#endif

#if PRINT_REG
      dr_insert_clean_call(drcontext, 
			   bb, 
			   instr, 
			   (void*)trace_instr_reg, 
			   false,
			   0);
#endif

#if DISASSEMBLE
      dr_insert_clean_call(drcontext, 
			   bb, 
			   instr, 
			   (void*)trace_instr, 
			   false,
			   1,
			   OPND_CREATE_INTPTR(instr_pc));
#endif
    }

  return DR_EMIT_DEFAULT;
}

