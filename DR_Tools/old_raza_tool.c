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
static void set_master_or_slave_role(void);
static void master_setup(void);
static void slave_setup(void);
static void read_address_space(void);
static void open_log_files(void);
static void dump_memory(void);
static void assert_equals(int, int, char*);

static void insert_diff(void* address);
static bool is_diff_address(void* address);

/** GLOBAL VARIABLES **/
#define MAX_BUF_SIZE 512
#define MAX_PATH 256
#define LARGE_BUFFER_SIZE (10*1024)
#define DUMP_MEM_BUFFER_SIZE 512
#define ENTRIES_PER_NODE 64

#define MASTER_SIGNAL_DONE 0
#define MASTER_SIGNAL_FORK 1

// Master/Slave Communication
static bool am_i_master;
static const char* NAMED_PIPE_1 = "/tmp/NP1";
static const char* NAMED_PIPE_2 = "/tmp/NP2";

// Temporary Variable For Instrumenting Memory References
uint memory_ref_addr;
uint memory_ref_pc;
bool memory_ref_is_write;

// header for each segment of memory sent
typedef struct _Header {
  uint start_addr;
  uint end_addr;
} Header, pHeader;

// parsed entries from /proc/pid/map
typedef struct _Mapping {
  uint used;
  uint start_address;
  uint end_address;
  char permission_bits[5];
  uint offset;
  char owner[MAX_PATH];
} Mapping, *pMapping;

typedef struct _Diff_List {
  uint count;
  uint entries[ENTRIES_PER_NODE];
  struct _Diff_List* next;
} DiffList, *pDiffList;

// Proc Map Parsing Variables
#define MAX_LINES 200
Mapping maps[MAX_LINES];

// Flags
#define DEBUG 1
#define PRINT_MAP 1
#define DUMP_MEMORY 0

// Files 
file_t debug_file_handle;
file_t proc_map_file_handle;
file_t memory_dump_file_handle;

file_t named_pipe_read_handle;
file_t named_pipe_write_handle;

pDiffList diffList;

/***FUNCTION DEFINITIONS ***/
static void
assert_equals(int first, int second, char* msg)
{
  if (first != second)
    {
      dr_fprintf(STDERR, "%s (%d != %d)\n", msg,
		 first, second);
      perror(msg);
      exit(-1);
    }
}

static void
set_master_or_slave_role(void) 
{
  char* master = getenv("master");
  am_i_master = (master != NULL);
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
open_log_files()
{
  char file_buf[255];

  char * my_role = NULL;
  if (am_i_master)
    my_role = "master";
  else
    my_role = "slave";

  // open debug log
  sprintf(file_buf, "%s_debug.tmp", my_role);
  debug_file_handle = open_file(file_buf, DR_FILE_WRITE_OVERWRITE);
  // open proc_map log 
  sprintf(file_buf, "%s_pmap.tmp", my_role);
  proc_map_file_handle = open_file(file_buf, DR_FILE_WRITE_OVERWRITE);
  // open memory dump file
  sprintf(file_buf, "%s_memdump.tmp", my_role);
  memory_dump_file_handle = open_file(file_buf, DR_FILE_WRITE_OVERWRITE);
}

static void
close_log_files()
{
  dr_close_file(debug_file_handle);
  dr_close_file(proc_map_file_handle);
  dr_close_file(memory_dump_file_handle);
}

static void
master_setup(void)
{
  int numread, i, numwritten, ret_val;
  char rdbuf[MAX_BUF_SIZE];
  Header h;
  uint* cur;
  uint bytes_sent, bytes_received;
  int my_int, received_int;
  int bytes_different, bytes_similar;

#if DEBUG
  dr_fprintf(debug_file_handle, "Master Setup Start\n");
#endif

  ret_val = mkfifo(NAMED_PIPE_1, 0666);
  if ((ret_val == -1) && (errno != EEXIST))
    {
      dr_fprintf(STDERR, "Unable To Create Pipe: %s\n", 
		 NAMED_PIPE_1);
      perror(NAMED_PIPE_1);
      exit(-1);
    }

  ret_val = mkfifo(NAMED_PIPE_2, 0666);
  if ((ret_val == -1) && (errno != EEXIST))
    {
      dr_fprintf(STDERR, "Unable To Create Pipe: %s\n", 
		 NAMED_PIPE_2);
      perror(NAMED_PIPE_2);
      exit(-1);
    }

#if DEBUG
  dr_fprintf(debug_file_handle, "Master Has Checked For Named Pipes \n");
#endif
  
  /* Open the first named pipe for writing */
  named_pipe_write_handle = open_file(NAMED_PIPE_1, DR_FILE_WRITE_APPEND);
  /* Open the second named pipe for reading */
  named_pipe_read_handle = open_file(NAMED_PIPE_2, DR_FILE_READ);
 
#if DEBUG
  dr_fprintf(debug_file_handle, "Master Has Opened Named Pipes \n");
#endif

  /* Send Master Memory To Slave */
  bytes_sent = 0;
  for (i = 0; i < MAX_LINES; i++)
    {
      Mapping m = maps[i];
      if (!m.used) break;
      if (m.permission_bits[0] == '-' &&
	  m.permission_bits[1] == '-')
	continue;
      
      h.start_addr = m.start_address;
      h.end_addr = m.end_address;

      // dr_fprintf(debug_file_handle, "H: %x %x\n", h.start_addr, h.end_addr);
      
      numwritten = dr_write_file(named_pipe_write_handle, &h, sizeof(Header));
      assert_equals(numwritten, (int)sizeof(Header), "Master Write Header");

      cur = (uint*)m.start_address;
      while (cur < (uint*)m.end_address)
	{
	  my_int = 0;
      	  dr_safe_read(cur, sizeof(uint), &my_int, NULL);
	  numwritten = dr_write_file(named_pipe_write_handle, 
				     &my_int, sizeof(uint));
	  assert_equals(numwritten, (int) sizeof(uint), "Master Write Int");
	  cur++;
	  bytes_sent += numwritten;
	  // dr_fprintf(debug_file_handle, "\tM: %x\n", my_int);
	}
    }

  // Write Special Header to Signal That The Master Is Done
  h.start_addr = 0;
  h.end_addr = 0;
  numwritten = dr_write_file(named_pipe_write_handle,  &h, sizeof(Header));
  assert_equals(numwritten, (int) sizeof(Header), "Master Write 0_Header"); 

#if DEBUG
  dr_fprintf(debug_file_handle, "Master Done Sending Memory (%d bytes)\n",
	     bytes_sent);
  dr_fprintf(debug_file_handle, "Master Reading Slave Memory \n");
#endif

  /* Read Slave's Memory */
  bytes_received = 0;
  int map_number = 0;
  bytes_different = 0;
  bytes_similar = 0;

  numread = dr_read_file(named_pipe_read_handle, &h.start_addr, sizeof(uint));
  assert_equals(numread, (int) sizeof(uint), "Master Read Slave Header 1"); 

  numread = dr_read_file(named_pipe_read_handle, &h.end_addr, sizeof(uint));
  assert_equals(numread, (int) sizeof(uint), "Master Read Slave Header 2"); 

  while(true)
    {
      if (h.start_addr == 0 &&
	  h.end_addr == 0)
	break;
      cur = (uint*)h.start_addr;
      while (cur < (uint*)h.end_addr)
	{
	  received_int  = 0;
	  numread = dr_read_file(named_pipe_read_handle, &received_int,
				 sizeof(uint));
	  assert_equals(numread, (int) sizeof(uint),
			"Master Read Slave Memory"); 
	  bytes_received += numread;

	  if (h.start_addr == maps[map_number].start_address)
	    {
	      my_int=0;
	      dr_safe_read(cur, sizeof(uint), &my_int, NULL);
	      if (my_int != received_int) 
		{
		  bytes_different += 4;
		  insert_diff(cur);
		}
	      else
		{
		  bytes_similar+=4;
		}
	    }
	  else
	    {
	      /* DR SPECIFIC MEMORY
	      uint byte_offset = (uint)cur-h.start_addr;
	      uint* my_addr = (uint*)maps[map_number].start_address + 
		byte_offset;
	      dr_safe_read(my_addr, sizeof(uint), &my_int, NULL);
	      if (my_int != received_int)
		bytes_different += 4;
	      */
	    }
	  cur++;
	}
      
      numread = dr_read_file(named_pipe_read_handle, &h.start_addr, 
			     sizeof(uint));
      assert_equals(numread, (int) sizeof(uint), 
		    "Master Read Slave Header 1#"); 
      numread = dr_read_file(named_pipe_read_handle, &h.end_addr, sizeof(uint));
      assert_equals(numread, (int) sizeof(uint),
		    "Master Read Slave Header 2#"); 
      map_number++;
    }

#if DEBUG
  dr_fprintf(debug_file_handle, "Master Done Reading Slave Memory\n", 
	     bytes_received);
  dr_fprintf(debug_file_handle, "%d/%d (rcvd total: %d) bytes were different\n", 
	     bytes_different, bytes_different + bytes_similar,
	     bytes_received);
#endif
}

static void
slave_setup(void)
{
  int numread, i, numwritten, ret_val;
  int received_int, my_int;
  int different_bytes, similar_bytes;
  char rdbuf[MAX_BUF_SIZE];
  Header h;
  uint* cur;
  uint bytes_sent, bytes_received;

#if DEBUG  
  dr_fprintf(debug_file_handle, "Slave Setup Start\n");  
#endif
  
  ret_val = mkfifo(NAMED_PIPE_1, 0666);
  if ((ret_val == -1) && (errno != EEXIST))
    {
      dr_fprintf(STDERR, "Unable To Create Pipe: %s\n", 
		 NAMED_PIPE_1);
      perror(NAMED_PIPE_1);
      exit(-1);
    }

  ret_val = mkfifo(NAMED_PIPE_2, 0666);
  if ((ret_val == -1) && (errno != EEXIST))
    {
      dr_fprintf(STDERR, "Unable To Create Pipe: %s\n", 
		 NAMED_PIPE_2);
      perror(NAMED_PIPE_2);
      exit(-1);
    }

#if DEBUG  
  dr_fprintf(debug_file_handle, "Slave has Checked For Pipes \n");
#endif

  /* Open the first named pipe for reading */
  named_pipe_read_handle = open_file(NAMED_PIPE_1, DR_FILE_READ);
  /* Open the second named pipe for writing */
  named_pipe_write_handle = open_file(NAMED_PIPE_2, DR_FILE_WRITE_APPEND);

#if DEBUG  
  dr_fprintf(debug_file_handle, "Slave is Receiving Master Memory\n");
#endif

  /* Read Master's Memory */
  int map_number = 0;
  different_bytes = similar_bytes = 0;
  bytes_received = 0;

  numread = read(named_pipe_read_handle, &h.start_addr, sizeof(uint));
  assert_equals(numread, (int) sizeof(uint), "Slave Read Master Header 1"); 
  numread = read(named_pipe_read_handle, &h.end_addr, sizeof(uint));
  assert_equals(numread, (int) sizeof(uint), "Slave Read Master Header 2"); 

  while(true)
    {
      if (h.start_addr == 0 &&
	  h.end_addr == 0)
	break;
      // dr_fprintf(debug_file_handle, "H: %x %x\n", h.start_addr, h.end_addr);
      cur = (uint*)h.start_addr;
      while (cur < (uint*)h.end_addr)
	{
	  received_int = 0;
	  numread = read(named_pipe_read_handle, &received_int, sizeof(uint));
	  assert_equals(numread, (int) sizeof(uint), 
			"Slave Read Master Memory"); 
	  bytes_received += numread;
	  if (maps[map_number].start_address == h.start_addr)
	    {
	      my_int=0;
	      dr_safe_read(cur, sizeof(uint), &my_int, NULL);
	      // dr_fprintf(debug_file_handle, "\tM: %x\n", my_int);
	      if (received_int != my_int)
		{
		  different_bytes += 4;
		  insert_diff(cur);
		}
	      else 
		{
		  similar_bytes += 4;
		}
	    }
	  else
	    {
	      /* DR SPECIFIC MEMORY 
	      uint byte_offset = (uint)cur - (uint)h.start_addr;
	      uint* my_addr = (uint*)maps[map_number].start_address + 
		byte_offset;
	      dr_safe_read(my_addr, sizeof(uint), &my_int, NULL);
	      if (received_int != my_int)
		different_bytes += 4;
	      */
	    }
	  cur++;
	}
      numread = dr_read_file(named_pipe_read_handle, 
			     &h.start_addr, sizeof(uint));
      assert_equals(numread, (int) sizeof(uint), 
		    "Slave Read Master Header 1#"); 
      numread = dr_read_file(named_pipe_read_handle, 
			     &h.end_addr, sizeof(uint));
      assert_equals(numread, (int) sizeof(uint), 
		    "Slave Read Master Header 2#"); 
      map_number++;
    }
 
#if DEBUG 
  dr_fprintf(debug_file_handle, "Slave Done Reading Master Memory\n");
  dr_fprintf(debug_file_handle, "%d/%d (raw %d) total bytes were different\n",
	     different_bytes, different_bytes + similar_bytes,
	     bytes_received);
#endif

  /* Send Slave Memory To Master */
#if DEBUG  
  dr_fprintf(debug_file_handle, "Slave Sending Memory\n");
#endif
  bytes_sent=0;
  for (i = 0; i < MAX_LINES; i++)
    {
      Mapping m = maps[i];
      if (!m.used) break;
      if (m.permission_bits[0] == '-' &&
	  m.permission_bits[1] == '-')
	continue;
      
      h.start_addr = m.start_address;
      h.end_addr = m.end_address;
      numwritten = dr_write_file(named_pipe_write_handle, &h, sizeof(Header));
      assert_equals(numwritten, (int)sizeof(Header), "Slave Write Header");

      cur = (uint*)m.start_address;
      my_int = 0;
      while (cur < (uint*)h.end_addr)
	{
	  dr_safe_read(cur, sizeof(uint), &my_int, NULL);
	  numwritten = dr_write_file(named_pipe_write_handle,
				     &my_int, sizeof(uint));
	  assert_equals(numwritten, (int) sizeof(uint), 
			"Slave Write Memory"); 
	  cur++;
	  bytes_sent += numwritten;
	}
    }

  // Write Special Header To End Transfer
  h.start_addr = 0;
  h.end_addr = 0;
  numwritten = dr_write_file(named_pipe_write_handle, &h, sizeof(Header));
  assert_equals(numwritten, (int) sizeof(Header), 
		"Slave Write Header_0"); 
  
#if DEBUG
  dr_fprintf(debug_file_handle, "Slave Done Sending Memory (%d) bytes\n",
	     bytes_sent);
  dr_fprintf(debug_file_handle, "Slave Waiting For Master Terminal Command\n",
	     bytes_sent);
#endif

  received_int = 0;
  numread = read(named_pipe_read_handle, &received_int, sizeof(uint));
  assert_equals(numread, (int) sizeof(uint), 
		"Slave Read Master Terminal Signal");
  if (received_int == MASTER_SIGNAL_DONE)
    {
#if DEBUG
      dr_fprintf(debug_file_handle, "Slave Exiting on Master's Directive\n",
		 bytes_sent);      
#endif
      exit(0);
    }
  else if (received_int == MASTER_SIGNAL_FORK)
    {
      // TODO
    }
}


DR_EXPORT void 
dr_init(client_id_t id)
{
  diffList = NULL;
  
  set_master_or_slave_role();
  open_log_files();
  read_address_space();

#if DUMP_MEMORY
  dump_memory();
#endif

  if (am_i_master)
      master_setup();
  else
      slave_setup();


  /* register events */
  dr_register_exit_event(event_exit);
  dr_register_bb_event(event_basic_block);
  
  /* make it easy to tell, by looking at log file, which client executed */
  dr_log(NULL, LOG_ALL, 1, "client 'raza-tool' initializing\n");

  /* also give notification to stderr */
  if (dr_is_notify_on())
    dr_fprintf(STDERR, "client 'raza-tool' is running\n");
}

static void 
event_exit(void)
{

  if (am_i_master)
    {
      uint temp = MASTER_SIGNAL_DONE;
      dr_write_file(named_pipe_write_handle, &temp, sizeof(uint));
#if DEBUG
      dr_fprintf(debug_file_handle, "Master Sent DONE signal to Slave\n");
#endif  
    } 
  // dr_fprintf(STDOUT, "client 'raza-tool' is exiting\n");
  close_log_files();
  dr_close_file(named_pipe_read_handle);
  dr_close_file(named_pipe_write_handle);
}

static void
taint_check()
{
  uint* memory_ref = (uint*)memory_ref_addr;
  void* dr_context = dr_get_current_drcontext();
  if (is_diff_address(memory_ref))
    {
      dr_fprintf(debug_file_handle, "mem = %x pc = %x iswrite = %x\n",
		  memory_ref_addr,
		  memory_ref_pc,
		  memory_ref_is_write);
      disassemble(dr_context, (byte*)&memory_ref_pc, debug_file_handle);
    }
}

static void
instrument_mem(void* drcontext,
	       instrlist_t *ilist,
	       instr_t *where,
	       int pos,
	       bool isWrite)
{
  // 1. we want to load the memory address into %rcx 
  // 2. we want to move the %rcx into global mem_ref_addr
  // 3. we want to move the app_pc into memory_ref_pc;
  // 4. we want to insert a clean call to check if address is tainted
  // 5. we restore %rcx 

  reg_id_t reg1 = DR_REG_XCX;
  opnd_t ref, opnd1, opnd2;
  instr_t *instr;
  app_pc original_pc = instr_get_app_pc(where);
  
  // save reg
  dr_save_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);
  
  if (isWrite)
    ref = instr_get_dst(where, pos);
  else
    ref = instr_get_src(where, pos);

  // load memory address into reg
  opnd1 = opnd_create_reg(reg1);
  if (opnd_is_base_disp(ref)) {
    /* lea [ref] => reg */
    opnd2 = ref; 
    opnd_set_size(&opnd2, OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
  } else if(opnd_is_abs_addr(ref)) {
    /* mov addr => reg */
    opnd2 = OPND_CREATE_INTPTR(opnd_get_addr(ref));
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
  } else {
    instr = NULL;
    dr_fprintf(STDERR, "Unhandled Instructions\n");
  }

  instrlist_meta_preinsert(ilist, where, instr);
  
  // move reg value into global reference
  opnd2 = OPND_CREATE_ABSMEM(&memory_ref_addr, OPSZ_4);
  instr = INSTR_CREATE_mov_st(drcontext, opnd2, opnd1);
  instrlist_meta_preinsert(ilist, where, instr);
  
  // move app_pc into reg
  opnd2 = OPND_CREATE_INT32(original_pc);
  instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
  instrlist_meta_preinsert(ilist, where, instr);
  
  // move reg into global reference
  opnd2 = OPND_CREATE_ABSMEM(&memory_ref_pc, OPSZ_4);
  instr = INSTR_CREATE_mov_st(drcontext, opnd2, opnd1);
  instrlist_meta_preinsert(ilist, where, instr);

  if (isWrite)
    {
      // move 1 into global reference
      opnd1 = OPND_CREATE_INT32(1);
      opnd2 = OPND_CREATE_ABSMEM(&memory_ref_is_write, OPSZ_4);
      instr = INSTR_CREATE_mov_st(drcontext, opnd2, opnd1);
      instrlist_meta_preinsert(ilist, where, instr);
    }
  else
    {
      // move 0 into global reference
      opnd1 = OPND_CREATE_INT32(0);
      opnd2 = OPND_CREATE_ABSMEM(&memory_ref_is_write, OPSZ_4);
      instr = INSTR_CREATE_mov_st(drcontext, opnd2, opnd1);
      instrlist_meta_preinsert(ilist, where, instr);
    }

  // insert clean call to our taint_check() function
  dr_insert_clean_call(drcontext, ilist, where, (void*)taint_check, false, 0);
  
  // restore reg
  dr_restore_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);
}

static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating)
{
  instr_t *instr;
  int i;
  
  for (instr  = instrlist_first(bb); 
       instr != NULL; 
       instr  = instr_get_next(instr)) {
    if (instr_get_app_pc(instr) == NULL)
      continue;
    
    if (instr_reads_memory(instr)) {
      for (i = 0; i < instr_num_srcs(instr); i++) {
	if (opnd_is_memory_reference(instr_get_src(instr, i))) {
	  instrument_mem(drcontext, bb, instr, i, false);
	}
      }
    }
    if (instr_writes_memory(instr)) {
      for (i = 0; i < instr_num_dsts(instr); i++) {
	if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
	  instrument_mem(drcontext, bb, instr, i, true);
	}
      }
    }
  }
  return DR_EMIT_DEFAULT;
}

static void 
parse_lines(char* content, char** lines_buffer, int max_lines)
{
  int lines_seen = 0;
  char *current_line = strtok(content, "\n");
  while (current_line != NULL)
    {
      lines_buffer[lines_seen] = (char*)malloc((1+strlen(current_line))
					       *sizeof(char));
      strcpy(lines_buffer[lines_seen], current_line);
      lines_seen++;
      current_line = strtok(NULL, "\n");
      if (lines_seen > max_lines)
	{
	  dr_fprintf(STDERR, "parse_lines overflow: %d > %d\n",
		     lines_seen, 
		     max_lines);
	  exit(-1);
	}
    }
}

char* 
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
get_start_end(char *string, uint* start, uint* end)
{
  char *s = substring(string, 0, 8);
  char *e = substring(string, 9, 8);
  
  sscanf(s, "%x", start);
  sscanf(e, "%x", end);
  
  free(s);
  free(e);
}

static void 
populate_info(char** lines_buffer, int num_lines)
{
  int i;
  for (i = 0; i < num_lines; i++)
    {
      pMapping m = (pMapping)maps + i;
      char *start, *end, *perm, *owner, *temp;

      if (lines_buffer[i] == NULL) { m->used = 0; continue; }

      m->used = 1;
      // get start & end addresses
      start = strtok(lines_buffer[i], " ");
      get_start_end(start, &m->start_address, &m->end_address);      
      // get perm
      perm = strtok(NULL, " ");
      strcpy(m->permission_bits, perm);
      // offset
      temp = strtok(NULL, " ");
      sscanf(temp, "%x", &m->offset);
      // 00:00
      temp = strtok(NULL, " ");
      // inode number
      temp = strtok(NULL, " ");
      // owner
      owner = strtok(NULL, " ");
      if (owner != NULL) 
	  strcpy(m->owner, owner);
    }
}

static void 
dump_memory()
{
  char buf[DUMP_MEM_BUFFER_SIZE];
  int i;
  for (i = 0; i < MAX_LINES; i++)
    {
      Mapping m = maps[i];
      if (!m.used) break;
      sprintf(buf, "Start=%x \nEnd=%x \nOwner=%s \n\n\n", 
	      m.start_address, m.end_address, m.owner);
      dr_write_file(memory_dump_file_handle, buf, strlen(buf));

      if (m.permission_bits[0] == '-' 
	  && m.permission_bits[1] == '-')
	continue;
	
      uint* start = (uint*)m.start_address;
      uint* end = (uint*)m.end_address;
      uint *cur = start;
      int val = 0;
      int count = 0;
      while (cur < end)
	{
	  dr_safe_read(cur, sizeof(uint), &val, NULL);
	  cur++; count++;
	  sprintf(buf, "%08x ", val);
	  dr_write_file(memory_dump_file_handle, buf, strlen(buf));	  
	  if (count % 10 == 0)
	    {
	      sprintf(buf, "\n");
	      dr_write_file(memory_dump_file_handle, buf, strlen(buf));
	    }
	}
      sprintf(buf, "\n\n\n");
      dr_write_file(memory_dump_file_handle, buf, strlen(buf));
    }
}

static void
read_address_space() 
{
  int i;
  char map_file[MAX_PATH];
  char *start = "/proc/";
  char *end = "/maps";
  int my_pid = (int) getpid();
  
  sprintf(map_file, "%s%d%s", start, my_pid, end);
  file_t map_file_handle = open_file(map_file, DR_FILE_READ);

#if DEBUG
  dr_fprintf(debug_file_handle, "about to read from: %s\n", map_file);  
#endif

  ssize_t bytes_read = -1;
  ssize_t total_bytes_read = 0;
  char read_buf[MAX_BUF_SIZE];
  char complete_file[LARGE_BUFFER_SIZE];
  while (bytes_read != 0)
    {
      bytes_read = dr_read_file(map_file_handle, read_buf, MAX_BUF_SIZE);
      memcpy((char*)complete_file + total_bytes_read,
	     (char*)read_buf, 
	     bytes_read);
      total_bytes_read += bytes_read;
      if (total_bytes_read > LARGE_BUFFER_SIZE) {
	dr_fprintf(STDERR, "read buffer too small: %d < %d\n",
		   LARGE_BUFFER_SIZE,
		   total_bytes_read);
	exit(-1);
      }
    }
  complete_file[total_bytes_read] = '\0';

#if PRINT_MAP
  dr_write_file(proc_map_file_handle, complete_file, total_bytes_read);
#endif

  char* lines_buffer[MAX_LINES];
  for (i = 0; i < MAX_LINES; i++)
    lines_buffer[i] = NULL;
  parse_lines(complete_file, lines_buffer, MAX_LINES);
  populate_info(lines_buffer, MAX_LINES);
  for (i = 0; i < MAX_LINES; i++)
    {
      if (lines_buffer[i] != NULL)
	free(lines_buffer[i]);
    }
  
#if PRINT_MAP
  for (i = 0; i < MAX_LINES; i++)
    {
      if (!maps[i].used) continue;
      dr_fprintf(debug_file_handle, "%d\n", i);
      dr_fprintf(debug_file_handle, 
		 "\tstart=%x, end=%x, perm=%s\n", 
		 maps[i].start_address,
		 maps[i].end_address,
		 maps[i].permission_bits);
      dr_fprintf(debug_file_handle, 
		 "\toffset=%x, owner=%s\n",
		 maps[i].offset, maps[i].owner);
      dr_fprintf(debug_file_handle, 
		 "\tsize=%d\n",
		 maps[i].end_address - maps[i].start_address);
    }
#endif
  dr_close_file(map_file_handle);
}

static
bool is_diff_address(void* address)
{
  pDiffList current = diffList;
  while (current != NULL)
    {
      int index = 0;
      while (index < current->count)
	{
	  if (current->entries[index++] == (uint)address)
	    return true;
	}
      current = current->next;
    }
  return false;
}

static
void insert_diff(void* address)
{
  if (diffList == NULL)
    {
      diffList = (pDiffList) malloc(sizeof(DiffList));
      diffList->count = 1;
      diffList->entries[0]= (uint)address;
      diffList->next = NULL;
      return;
    }
  else
    {
      if (diffList->count < (ENTRIES_PER_NODE - 1))
	{
	  diffList->entries[diffList->count++] = (uint)address;
	}
      else
	{
	  pDiffList previous_head = diffList; 
	  diffList = (pDiffList) malloc(sizeof(DiffList));
	  diffList->count = 1;
	  diffList->entries[0]= (uint)address;
	  diffList->next = previous_head;
	}
    }
}
