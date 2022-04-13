#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"            // For process_execute, process_wait
#include "devices/shutdown.h"   // For shutdown_power_off
#include "filesys/filesys.h"    // For filesys_create, filesys_remove, filesys_open
#include "filesys/file.h"       // For file_length, file_read, file_write, file_seek, file_tell, file_close
#include "threads/vaddr.h"      // For is_user_vaddr
#include "user/syscall.h"       // For pid_t
#include "list.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* 1. syscall number 확인.
   2. address가 valid한지 확인.
   3. 알맞은 function 호출. */
static void
syscall_handler (struct intr_frame *f) 
{
  //printf ("syscall number : %d\n", *(int *)(f->esp));

  switch(*(int *)(f->esp))
  {
    case SYS_HALT: // syscall0
      //printf("SYS_HALT!\n");
      halt();           
      break;

    case SYS_EXIT: // syscall1
      //printf("SYS_EXIT!\n");
      if (is_user_vaddr (f->esp + 4) == 0)
        exit (-1);
      exit ((int)*(uint32_t *)(f->esp + 4)); 
      break;

    case SYS_EXEC: // syscall1
      //printf("SYS_EXEC!\n");
      if (is_user_vaddr (f->esp + 4) == 0)
        exit (-1);
      f->eax = exec ((const char *)*(uint32_t *)(f->esp + 4));
      break;

    case SYS_WAIT: // syscall1
      //printf("SYS_WAIT!\n");
      if (is_user_vaddr (f->esp + 4) == 0)
        exit (-1);
      f->eax = wait ((pid_t)*(uint32_t *)(f->esp + 4));
      break; 

    case SYS_CREATE: // syscall2
      //printf("SYS_CREATE!\n");
      if (is_user_vaddr (f->esp + 4) == 0)
        exit (-1);
      if (is_user_vaddr (f->esp + 8) == 0)
        exit (-1);
      f->eax = create ((char *)*(uint32_t *)(f->esp + 4), (unsigned int)*(uint32_t *)(f->esp + 8));
      break;  

    case SYS_REMOVE: // syscall1
      //printf("SYS_REMOVE!\n");
      if (is_user_vaddr (f->esp + 4) == 0)
        exit (-1);
      f->eax = remove ((char *)*(uint32_t *)(f->esp + 4));
      break;    

    case SYS_OPEN: // syscall1
      //printf("SYS_OPEN!\n");
      if (is_user_vaddr (f->esp + 4) == 0)
        exit (-1);
      f->eax = open ((const char *)*(uint32_t *)(f->esp + 4));    
      break;     

    case SYS_FILESIZE: // syscall1
      //printf("SYS_FILESIZE!\n");
      if (is_user_vaddr (f->esp + 4) == 0)
        exit (-1);
      f->eax = filesize ((int)*(uint32_t *)(f->esp + 4)); 
      break;     

    case SYS_READ: // syscall3
      //printf("SYS_READ!\n");
      if (is_user_vaddr (f->esp + 4) == 0)
        exit (-1);
      if (is_user_vaddr (f->esp + 8) == 0)
        exit (-1);
      if (is_user_vaddr (f->esp + 12) == 0)
        exit (-1);
      f->eax = read ((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), (unsigned int)*(uint32_t *)(f->esp + 12));
      break;         

    case SYS_WRITE: // syscall3 
      //printf("SYS_WRITE!\n");
      if (is_user_vaddr (f->esp + 4) == 0)
        exit(-1);
      if (is_user_vaddr (f->esp + 8) == 0)
        exit(-1);
      if (is_user_vaddr (f->esp + 12) == 0)
        exit(-1);
      f->eax = write ((int)*(uint32_t *)(f->esp + 4), (const void *)*(uint32_t *)(f->esp + 8), (unsigned int)*(uint32_t *)(f->esp + 12));    
      break;        

    case SYS_SEEK: // syscall2
      //printf("SYS_SEEK!\n");
      if (is_user_vaddr (f->esp + 4) == 0)
        exit (-1);
      if (is_user_vaddr (f->esp + 8) == 0)
        exit (-1);
      seek ((int)*(uint32_t *)(f->esp + 4), (unsigned int)*(uint32_t *)(f->esp + 8));               
      break;

    case SYS_TELL: // syscall1
      //printf("SYS_TELL!\n");
      if (is_user_vaddr (f->esp + 4) == 0)
        exit (-1);
      f->eax = tell ((int)*(uint32_t *)(f->esp + 4));
      break;             

    case SYS_CLOSE: // syscall1
      //printf("SYS_CLOSE!\n");
      if (is_user_vaddr (f->esp + 4) == 0)
        exit (-1);
      close ((int)*(uint32_t *)(f->esp + 4));
      break;       

    case SYS_SIGACTION: // syscall2
      //printf("SYS_SIGACTION!\n");
      if (is_user_vaddr (f->esp + 4) == 0)
        exit (-1);
      if (is_user_vaddr (f->esp + 8) == 0)
        exit (-1);
      sigaction ((int)*(uint32_t *)(f->esp + 4), (void (*)(void))*(uint32_t *)(f->esp + 8));
      break;           

    case SYS_SENDSIG:  // syscall2
      //printf("SYS_SENDSIG!\n");
      if (is_user_vaddr (f->esp + 4) == 0)
        exit (-1);
      if (is_user_vaddr (f->esp + 4) == 0)
        exit (-1);
      sendsig ((pid_t)*(uint32_t *)(f->esp + 4), (int)*(uint32_t *)(f->esp + 8));
      break;     
             
    case SYS_YIELD:  // syscall0
      //printf("SYS_YIELD!\n");
      sched_yield ();
      break;
  }
}

void
halt (void)
{
  shutdown_power_off ();
}

void
exit (int status) 
{
  struct thread *cur = thread_current ();
  struct thread *t = NULL;
  struct list_elem *e;

  printf ("%s: exit(%d)\n", cur->name, status);
  cur->exit_status = status;
  
  for (e = list_begin (&cur->child); e != list_end (&cur->child); e = list_next (e)) 
  {
    t = list_entry (e, struct thread, child_elem);
    wait (t->tid);
  }

  thread_exit ();
}

pid_t 
exec (const char *cmd_line) 
{
  return process_execute (cmd_line);
}

int 
wait (pid_t pid) 
{
  return process_wait (pid);
}

bool 
create (const char *file, unsigned initial_size) 
{
  if (file == NULL)
    exit (-1);

  return filesys_create (file, initial_size);
}

bool 
remove (const char *file)
{
  return filesys_remove (file);
}

int 
open (const char *file)
{
  lock_acquire (&filesys_lock);

  if (file == NULL)
  {
    lock_release (&filesys_lock);
    return -1;
  }

  struct thread *cur = thread_current ();
  struct file *fp = filesys_open (file);

  if (fp == NULL) 
  {
    lock_release (&filesys_lock);
    return -1;
  }
  else
  {
    for (int i = 2; i < 128; i++) // i = 0 -> STDIN, i = 1 -> STDOUT이므로 i = 2부터 탐색.
    {
      if (cur->fd_table[i] == NULL)
        {
          cur->fd_table[i] = fp;
          lock_release (&filesys_lock);
          return i;
        }
    }
  }
  lock_release (&filesys_lock);
  return -1; // File Descriptor Table이 꽉 찬 상태.
}

int 
filesize (int fd)
{
  struct thread *cur = thread_current ();
  struct file *fp = cur->fd_table[fd];

  if (fp == NULL)
    exit (-1);

  off_t size = file_length (fp);

  return size;
}

int 
read (int fd, void* buffer, unsigned size) 
{
  lock_acquire (&filesys_lock);

  struct thread *cur = thread_current ();
  struct file *fp = cur -> fd_table[fd];
  
  if (is_user_vaddr (buffer) == 0 || fp == NULL)
  {
    lock_release (&filesys_lock);
    exit (-1);
  }

  if (fd == 0)
  {
    lock_release (&filesys_lock);
    return input_getc ();
  }
  else
  {
    lock_release (&filesys_lock);
    return file_read (fp, buffer, size);
  }
}

int 
write (int fd, const void *buffer, unsigned size)
{
  lock_acquire (&filesys_lock);

  struct thread *cur = thread_current ();
  struct file *fp = cur->fd_table[fd];

  if (is_user_vaddr (buffer) == 0)
  {
    lock_release (&filesys_lock);
    exit(-1);
  }

  if (fd == 1)
  {
    putbuf (buffer, size);
    lock_release (&filesys_lock);
    return size;
  }
  else
  {
    if (fp == NULL)
    {
      lock_release (&filesys_lock);
      exit(-1);
    }
    lock_release (&filesys_lock);
    return file_write (fp, buffer, size);
  }
  lock_release (&filesys_lock);
  return -1;
}

void 
seek (int fd, unsigned position)
{
  struct thread *cur = thread_current ();
  struct file *fp = cur->fd_table[fd];
  
  file_seek (fp, position);
}

unsigned 
tell (int fd)
{
  struct thread *cur = thread_current ();
  struct file *fp = cur->fd_table[fd];

  return file_tell (fp);
}

void 
close (int fd)
{
  struct thread *cur = thread_current ();
  struct file *fp = cur->fd_table[fd];

  if (fp == NULL)
    exit (-1);

  cur->fd_table[fd] = NULL; // fd에 해당하는 table 값을 다시 NULL로 초기화.
  file_close (fp);
}

void 
sigaction (int signum, void (*handler)(void))
{
  struct thread *cur = thread_current ();

  cur->signal_handler[signum - 1] = handler;
}

void 
sendsig (pid_t pid, int signum)
{ 
  struct thread *cur = thread_current ();
  struct thread *t = NULL;
  struct list_elem *e;

  for (e = list_begin (&cur->child); e != list_end (&cur->child); e = list_next (e)) 
  {
    t = list_entry (e, struct thread, child_elem);
    if (t->tid == pid)
      break;
  }

  if (t->signal_handler[signum - 1] != NULL)
    printf("Signum: %d, Action: 0x%x\n", signum, t->signal_handler[signum-1]);
}

void sched_yield (void)
{
  thread_yield ();
}

