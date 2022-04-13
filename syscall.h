#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
struct lock filesys_lock;  //for race condition prevention

#endif /* userprog/syscall.h */
