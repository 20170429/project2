#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"


static void syscall_handler (struct intr_frame *);
void halt (void);

void exit (int status);

tid_t exec (const char *cmd_line);

int wait (tid_t tid);

int read (int fd, void* buffer, unsigned size);

int write (int fd, const void *buffer, unsigned size);

bool create (const char *file, unsigned initial_size);

int open (const char *file);

bool remove(const char *file);

void close(int fd);

int filesize(int fd);

void seek(int fd, unsigned position);

unsigned tell(int fd);

void sigaction (int signum, void (*handler) (void));

void sendsig (tid_t tid, int signum);

void sched_yield (void);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  
  if(!is_user_vaddr(f->esp))
    exit(-1);
  int *number = f->esp;
  switch(*(uint32_t *) number){
  case SYS_HALT:
  //printf("a\n"); 
    halt();   
    break;      
  case SYS_EXIT:
   //printf("b\n"); 
    if(!is_user_vaddr(number + 1))
      exit(-1);
    exit(*(uint32_t *)(number + 1));
    break;                  
  case SYS_EXEC:          
  //printf("c\n");
    if(!is_user_vaddr(number + 1))
      exit(-1);
    f->eax = exec(*(uint32_t *)(number + 1));
    break;
  case SYS_WAIT:
   //printf("d\n");
    if(!is_user_vaddr(number + 1))
     exit(-1);
    f->eax = wait(*(uint32_t *)(number + 1));
    break;                         
  case SYS_READ:
  //printf("e\n");
    if(!is_user_vaddr(number + 3) || !is_user_vaddr(*(uint32_t *)(number + 2)) || *(uint32_t *)(number + 1) == 1 || *(uint32_t *)(number + 1) <0)
      exit(-1);
    lock_acquire(&filesys_lock);  
    f->eax = read(*(uint32_t *)(number + 1),*(uint32_t *)(number + 2),*(uint32_t *)(number + 3));
    lock_release(&filesys_lock);
    break;                   
  case SYS_WRITE:
   //printf("f\n");
   //printf("%s\n",*(uint32_t *)(number + 2));
  // hex_dump((uintptr_t) f->esp , f->esp , PHYS_BASE - f->esp , true);
    if(!is_user_vaddr(number + 3))
      exit(-1);
    lock_acquire(&filesys_lock);  
      f->eax = write(*(uint32_t *)(number + 1),*(uint32_t *)(number + 2),*(uint32_t *)(number + 3));
    lock_release(&filesys_lock);  
   break;     
  case SYS_CREATE:
   //printf("g\n");
    if(!is_user_vaddr(number + 2) || *(uint32_t *)(number + 1)==NULL || !strcmp(*(uint32_t *)(number + 1),""))
    exit(-1);
   // hex_dump((uintptr_t) f->esp , f->esp , PHYS_BASE - f->esp , true);
    lock_acquire(&filesys_lock); 
    f->eax = create(*(uint32_t *)(number + 1), *(uint32_t *)(number + 2));
    lock_release(&filesys_lock);  
    //printf("%x,%d\n",f->eip,*(uint32_t *)f->eip);
     //hex_dump((uintptr_t)  0xbffffec0 ,  0xbffffec0 , PHYS_BASE - 0xbffffec0 , true);
    break;   
  case SYS_OPEN:
  // printf("h\n");
   if(!is_user_vaddr(number + 1) || *(uint32_t *)(number + 1) == NULL)
      exit(-1);
    lock_acquire(&filesys_lock);   
    f->eax = open(*(uint32_t *)(number + 1));
    lock_release(&filesys_lock);  
    break;       
  case SYS_CLOSE:
 // printf("i\n");
    if(!is_user_vaddr(number + 1))
      exit(-1);
    lock_acquire(&filesys_lock);     
    close(*(uint32_t *)(number + 1));
    lock_release(&filesys_lock);  
    break;             
  case SYS_REMOVE:
   //printf("j\n");
   if(!is_user_vaddr(number + 1))
      exit(-1);
    lock_acquire(&filesys_lock);       
    f->eax = remove(*(uint32_t *)(number + 1));
    lock_release(&filesys_lock);  
    break;    
  case SYS_FILESIZE:
   //printf("k\n");
  if(!is_user_vaddr(number + 1))
      exit(-1);
    lock_acquire(&filesys_lock);         
    f->eax = filesize(*(uint32_t *)(number + 1));
    lock_release(&filesys_lock);  
    break;      
  case SYS_SEEK:
   //printf("l\n");
   if(!is_user_vaddr(number + 2))
      exit(-1);
    lock_acquire(&filesys_lock);           
    seek(*(uint32_t *)(number + 1), *(uint32_t *)(number + 2));
    lock_release(&filesys_lock);  
    break;      
  case SYS_TELL:
   //printf("m\n");
   if(!is_user_vaddr(number + 1))
      exit(-1);
    lock_acquire(&filesys_lock);             
    f->eax = tell(*(uint32_t *)(number + 1));
    lock_release(&filesys_lock);  
    break;
  case SYS_SIGACTION:
   //printf("n\n");
   if(!is_user_vaddr(number + 2))
      exit(-1);
    sigaction(*(uint32_t *)(number + 1), *(uint32_t *)(number + 2));
    break;     
  case SYS_SENDSIG:
   //printf("o\n");
   if(!is_user_vaddr(number + 2))
      exit(-1);
    sendsig(*(uint32_t *)(number + 1), *(uint32_t *)(number + 2));
    break;  
  case SYS_YIELD:
   //printf("p\n");
   if(!is_user_vaddr(number))
      exit(-1);
      sched_yield();
    break;                                                                   
  } 
  

}

void halt (void) {
 shutdown_power_off();
}

void exit (int status) {
   printf("%s: exit(%d)\n" , thread_current() -> name , status);
   thread_current()->exit_status = status;
  thread_exit ();
}

tid_t exec (const char *cmd_line) {
  return process_execute(cmd_line);
}

int wait (tid_t tid) {
  return process_wait(tid);
}

int read (int fd, void* buffer, unsigned size) {
  if (fd == 0)
    return input_getc();
  else
    return file_read(thread_current()->fdt[fd], buffer, size);
}

int write (int fd, const void *buffer, unsigned size) {

  if (fd == 1) {
    putbuf(buffer, size);
    return size;
  }
  else {
    if(thread_current()->fdt[fd]!=NULL)
   return file_write(thread_current()->fdt[fd], buffer, size);
  }
}

bool create (const char *file, unsigned initial_size) {
   if(strlen(file)<200)
   return filesys_create(file, initial_size);
   return 0;
}

bool remove(const char *file){
  return filesys_remove(file);
}


int open (const char *file){
  if(thread_current()->next_fd>63)
  return -1;
  struct file *f = filesys_open(file);
  if(f!=NULL){
  thread_current()->fdt[thread_current()->next_fd++] = f;
  return (thread_current()->next_fd - 1 );
  }
  return -1;
  
}

void close(int fd){
  if(fd>1){
  file_close(thread_current()->fdt[fd]);
  thread_current()->fdt[fd] = NULL;
  }
}

int filesize(int fd){
return file_length(thread_current()->fdt[fd]);
}

void seek(int fd, unsigned position){
   file_seek(thread_current()->fdt[fd], position);
}

unsigned tell(int fd){
  return file_tell(thread_current()->fdt[fd]);
}

void sigaction (int signum, void (*handler) (void)){
struct thread *cur = thread_current ();

  cur->signal_handler[signum - 1] = handler;
}

void sendsig (tid_t tid, int signum){
struct thread *cur = thread_current ();
  struct thread *t = NULL;
  struct list_elem *e;

  for (e = list_begin (&cur->child_list); e != list_end (&cur->child_list); e = list_next (e)) 
  {
    t = list_entry (e, struct thread, child_elem);
    if (t->tid == tid)
      break;
  }

  if (t->signal_handler[signum - 1] != NULL)
    printf("Signum: %d, Action: 0x%x\n", signum, t->signal_handler[signum-1]);
}

void sched_yield (void)
{
  thread_yield ();
}
