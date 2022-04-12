#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "user/syscall.h"       // For pid_t

struct lock filesys_lock;       // race condition 방지를 위한 lock.

void syscall_init (void);
void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid); 
bool create (const char *file, unsigned initial_size);
bool remove (const char *file); 
int open (const char *file);
int filesize (int fd);
int read (int fd, void* buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
void sigaction (int signum, void (*handler)(void));
void sendsig (pid_t pid, int signum);
void sched_yield (void);

#endif /* userprog/syscall.h */
