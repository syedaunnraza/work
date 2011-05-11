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

static void check_count(void*);

/*** GLOBAL VARIABLES ***/
uint address_to_instrument;
uint count_target;

uint count_so_far;

#define OPTIMIZE_BBLOCK 0
#define DEBUG 0

/*** FUNCTION DEFINITIONS ***/
static void check_count(void* drcontext)
{
  count_so_far++;
  if (count_so_far == count_target)
    {
      exit(0);
    }
}

static char* 
substring(const char* str, size_t begin, size_t len) 
{ 
  if (str == 0 || strlen(str) == 0
      || strlen(str) < begin || strlen(str) < (begin+len)) 
    return NULL; 

  char* toReturn = (char*)malloc((len+1)*sizeof(char));
  memcpy(toReturn, str + begin, len);
  toReturn[len] = '\0';
  return toReturn;
} 

static void
parse_arguments(uint *address, uint *count, const char* argument_string)
{
  char* a = substring(argument_string, 0, 10);
  char* c = substring(argument_string, 11, strlen(argument_string)-11);
  
  sscanf(a, "%x", address);
  sscanf(c, "%d", count);

  free(a);
  free(c);
}

DR_EXPORT void 
dr_init(client_id_t id)
{
  const char* options = dr_get_options(id);
  parse_arguments(&address_to_instrument, &count_target, options);

#if DEBUG
  dr_fprintf(STDOUT, "client options = %s\n", options);
#endif
  dr_fprintf(STDOUT, "address = 0x%x\n", address_to_instrument);
  dr_fprintf(STDOUT, "count = %d\n", count_target);


  /* register events */
  dr_register_exit_event(event_exit);
  dr_register_bb_event(event_basic_block);
  
  /* make it easy to tell, by looking at log file, which client executed */
  dr_log(NULL, LOG_ALL, 1, "client 'execution tracer' initializing\n");

  /* also give notification to stderr */
#if DEBUG
  if (dr_is_notify_on())
    dr_fprintf(STDERR, "client 'execution tracer' is running\n");
#endif
}

static void 
event_exit(void)
{
  
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
      if (instr_pc == NULL)
	continue;

#if OPTIMIZE_BBLOCK
      if(!first_instruction)
	{
	  return;
	}
      first_instruction=false;
#endif

      instr_pc = instr_get_app_pc(instr);
      if ((uint)instr_pc == address_to_instrument)
	{
	  // insert call to increment / exit
	  dr_insert_clean_call(drcontext, bb, instr, 
			       (void*)check_count, false, 0);
	  
	}
    }

  return DR_EMIT_DEFAULT;
}

