#include <stddef.h> /* for offsetof */
#include "dr_api.h"
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

typedef struct _Info {
  int magic1;
  int items[10];
  int magic2;
} Info;

typedef struct _Mapping {
  uint used;
  uint start_address;
  uint end_address;
  char permission_bits[5];
  uint offset;
  char owner[255];
} Mapping, *pMapping;

/*** FUNCTION PROTOTYPES ***/
static void event_exit(void);
static dr_emit_flags_t event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                                         bool for_trace, bool translating);
static void populate_master_state(void);
static void master_setup(void);
static void slave_setup(void);
static void read_address_space(void);
 
/*** GLOBAL VARIABLES ***/
static bool am_i_master;
static const char* NAMED_PIPE_1 = "/tmp/NP1";
static const char* NAMED_PIPE_2 = "/tmp/NP2";
static const int MAX_BUF_SIZE = 512;

static const MAX_LINES=100;

static const bool DEBUG = true;

char* lines_buffer[100];
file_t temp_file_handle;

Mapping maps[100];

/***FUNCTION DEFINITIONS ***/
static void
populate_master_state(void) 
{
  char* master = getenv("master");
  if (master != NULL)
    {
      dr_fprintf(STDOUT, "master = true [%s]\n", master);
      am_i_master = true;
    } 
  else 
    { 
      dr_fprintf(STDOUT, "slave = true\n");
      am_i_master = false;
    }
}

static void
master_setup(void)

{
}

static void
slave_setup(void)
{
  int wrfd, rdfd, numread, i;
  char rdbuf[MAX_BUF_SIZE];
  Info info_snd, *info_rcv;
  
  /* Open the first named pipe for writing */
  wrfd = open(NAMED_PIPE_1, O_WRONLY);
  /* Open the second named pipe for reading */
  rdfd = open(NAMED_PIPE_2, O_RDONLY);
 
  /* Populate the Information Structure */
  info_snd.magic1 = 1234567;
  for (i = 0; i < 10; i++)
    {
      info_snd.items[i] = 10-i;
    }
  info_snd.magic2 = 7654321;
  
  printf("Duplex Client: Sending Structure To Server\n");
  printf("\tMagic 1: %d\n", info_snd.magic1);
  printf("\tArray:\n");
  for (i = 0; i < 10; i++)
    {
      printf("\t\tNumber[%d]: %d\n", i, info_snd.items[i]);
    }
  printf("\tMagic 2: %d\n", info_snd.magic2);
  

  /* Write to the first pipe */
  write(wrfd, &info_snd, sizeof(Info));
  /* Read from the pipe */
  numread = read(rdfd, rdbuf, MAX_BUF_SIZE);
  
  info_rcv = (Info*)rdbuf;
  printf("Duplex Client: Received Structure From Server\n");
  printf("\tMagic 1: %d\n", info_rcv->magic1);
  printf("\tArray:\n");
  for (i = 0; i < 10; i++)
    {
      printf("\t\tNumber[%d]: %d\n", i, info_rcv->items[i]);
    }
  printf("\tMagic 2: %d\n", info_rcv->magic2);
}


DR_EXPORT void 
dr_init(client_id_t id)
{
  int i;
  for (i = 0; i < 100; i++)
    lines_buffer[i] = NULL;

  temp_file_handle = dr_open_file("temp.out", DR_FILE_WRITE_OVERWRITE);
  if (temp_file_handle == INVALID_FILE) 
    {
      dr_fprintf(STDERR, "dr_open() failed\n");
      exit(-1);
    }
  
  read_address_space();
  populate_master_state();
  if (am_i_master)
    {
      // master_setup();
    }
  else
    {
      // slave_setup();
    }
  
  
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
  dr_close_file(temp_file_handle);
  dr_fprintf(STDOUT, "client 'raza-tool' is exiting\n");
}

static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating)
{
  instr_t *instr, *first = instrlist_first(bb);
  uint flags;
  return DR_EMIT_DEFAULT;
}


static void break_strings(char* content)
{
  int lines_seen = 0;
  // dr_fprintf(STDOUT, "in break_strings \n");
  
  char *current_line = strtok(content, "\n");
  while (current_line != NULL)
    {
      // dr_fprintf(STDOUT, "current line: %s \n", current_line);
      // dr_fprintf(STDOUT, "str len: %d \n", strlen(current_line));

      lines_buffer[lines_seen] = (char*)malloc((1+strlen(current_line))*sizeof(char));
      strcpy(lines_buffer[lines_seen], current_line);
      lines_buffer[lines_seen][strlen(current_line)] = '\0';
      
      // dr_fprintf(STDOUT, "stored line: %s \n",lines_buffer[lines_seen]);
      
      lines_seen ++;
      current_line = strtok(NULL, "\n");
    }
  
  int i;
  // dr_fprintf(STDOUT, "Printing Lines\n");
  for (i = 0; i < lines_seen; i++)
    {
      // dr_fprintf(STDOUT, "[%d] %s\n", i, (char*)lines_buffer[i]);
    }
}


char* substring(const char* str, size_t begin, size_t len) 
{ 
  if (str == 0 || strlen(str) == 0 || strlen(str) < begin || strlen(str) < (begin+len)) 
    return 0; 

  char* toReturn = (char*)malloc((len+1)*sizeof(char));
  memcpy(toReturn, str + begin, len);
  toReturn[len] = '\0';
  return toReturn;
} 


static void get_start_end(char *string, uint* start, uint* end)
{
  char *s = substring(string, 0, 8);
  char *e = substring(string, 9, 8);
  
  sscanf(s, "%x", start);
  sscanf(e, "%x", end);
  
  //*start = atoi(s,8);
  //*end = atoi(e,8);
  
  free(s);
  free(e);
}

static void populate_info()
{
  int i;
  for (i = 0; i < 100; i++)
    {
      if (lines_buffer[i] == NULL)
	break;
      
      dr_fprintf(STDOUT, "%d\n", i);
      dr_fprintf(STDOUT, "\tline = <%s>\n", lines_buffer[i]);

      pMapping m = (pMapping)maps + i;
      char *start, *end, *perm, *owner, *temp;

      m->used = 1;

      // get start & end addresses
      start = strtok(lines_buffer[i], " ");
      get_start_end(start, &m->start_address, &m->end_address);      
      //dr_fprintf(STDOUT, "\tstart=%x end=%x\n", m->start_address, m->end_address);
      
      // get perm
      perm = strtok(NULL, " ");
      strcpy(m->permission_bits, perm);
      // dr_fprintf(STDOUT, "\tperm = %s\n", perm);

      // offset
      temp = strtok(NULL, " ");
      sscanf(temp, "%x", &m->offset);
      //dr_fprintf(STDOUT, "\toffset = %s vs stored %x\n", temp, m->offset);
      
      // 00:00
      temp = strtok(NULL, " ");
      //dr_fprintf(STDOUT, "\tdev = %s\n", temp);

      // number
      temp = strtok(NULL, " ");
      //dr_fprintf(STDOUT, "\tinode = %s\n", temp);
      
      // owner
      owner = strtok(NULL, " ");
      if (owner != NULL) 
	{
	  strcpy(m->owner, owner);
	  //  dr_fprintf(STDOUT, "\towner = %s\n", owner);
	}
    }
}

static void 
dump_memory()
{
  char buf[1024];
  int i;
  for (i = 0; i < 100; i++)
    {
      Mapping m = maps[i];
      dr_fprintf(STDOUT, "%d\n", i);
      if (!m.used)
	break;
      
      if (m.owner != NULL) 
	{
	  sprintf(buf, "Start=%x \nEnd=%x \nOwner=<none> \n\n\n", 
		  i, m.start_address, m.end_address);
	}
      else 
	{
	  sprintf(buf, "Start=%x \nEnd=%x \nOwner=%s \n\n\n", 
		  i, m.start_address, m.end_address, m.owner);
	}

      dr_write_file(temp_file_handle, buf, strlen(buf));
      
      uint* start = (uint*)m.start_address;
      uint* end = (uint*)m.end_address;
      uint *cur = start;

      int val = 0;
      buf[0] = '\0';
      int count = 0;

      while (cur < end)
	{
	  dr_safe_read(cur, sizeof(uint), &val, NULL);
	  cur++;
	  count++;
	  
	  sprintf(buf, "%08x ", val);
	  dr_write_file(temp_file_handle, buf, strlen(buf));	  
	  
	  if (count % 10 == 0)
	    {
	      sprintf(buf, "\n", val);
	      dr_write_file(temp_file_handle, buf, strlen(buf));
	      count = 0;
	    }
	}
     
      sprintf(buf, "\n\n\n", 3);
      dr_write_file(temp_file_handle, buf, strlen(buf));
    }
}

static void
read_address_space() 
{
  char proc_map_file[255];
  char *start = "/proc/";
  char *end = "/maps";
  int my_pid = (int) getpid();

  sprintf(proc_map_file, "%s%d%s", start, my_pid, end);

  file_t proc_file_handle = dr_open_file(proc_map_file, DR_FILE_READ);
  if (proc_file_handle == INVALID_FILE) 
    {
      dr_fprintf(STDERR, "dr_open() failed\n");
      exit(-1);
    }

  dr_fprintf(STDOUT, "about to read from: %s\n", proc_map_file);
  
  ssize_t bytes_read = -1;
  ssize_t total_bytes_read = 0;

  char read_buf[MAX_BUF_SIZE];
  char complete_file[1024*10];

  while (bytes_read != 0)
    {
      bytes_read = dr_read_file(proc_file_handle, read_buf, MAX_BUF_SIZE);
      memcpy((char*)complete_file + total_bytes_read, (char*)read_buf, bytes_read);
      total_bytes_read += bytes_read;
    }

  complete_file[total_bytes_read] = '\0';

  // dr_write_file(temp_file_handle, complete_file, total_bytes_read);

  dr_fprintf(STDOUT, "break strings start\n");  
  break_strings(complete_file);
  dr_fprintf(STDOUT, "break strings end\n");

  populate_info();
  dr_fprintf(STDOUT, "pop info end\n");

  int i;
  for (i = 0; i < 100; i++)
    {
      Mapping m = maps[i];
      dr_fprintf(STDOUT, "%d\n", i);
      dr_fprintf(STDOUT, "\tstart=%x, end=%x, perm=%s\n", 
		 m.start_address,
		 m.end_address,
		 m.permission_bits);
      dr_fprintf(STDOUT, "\toffset=%x, owner=%s\n", m.offset, m.owner);
    }
 
  dr_close_file(proc_file_handle);
  dump_memory();
}
