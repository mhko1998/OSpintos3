#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/off_t.h"
#include "devices/block.h"


static void syscall_handler (struct intr_frame *);
void exit (int status);
int write (int fd, const void *buffer, unsigned size);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  //printf ("system call!\n");
  //thread_exit ();

  //printf("syscall: %d\n", *(uint32_t *)(f->esp));
  //hex_dump(f->esp, f->esp, 100, 1);
  void *esp = f->esp;

  switch (*(uint32_t *)esp){
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      if(!is_user_vaddr(esp + 4)) exit(-1);
      //exit(*(uint32_t *)(f->esp + 4));
      exit(*(uint32_t *)(esp + 4));
      break;
    case SYS_EXEC:
      if(!is_user_vaddr(esp + 4)) exit(-1);
      f->eax = exec((const char *)*(uint32_t *)(esp + 4));
      break;
    case SYS_WAIT:
      //if(!is_user_vaddr(esp + 4)) exit(-1);
      f->eax = wait((pid_t *)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_CREATE:
      //if(!is_user_vaddr(f->esp + 4)) exit(-1);
      //f->eax = create((const char *)*(uint32_t *)(f->esp + 4), (const char *)*(uint32_t *)(f->esp + 8));
      break;
    case SYS_REMOVE:
      //if(!is_user_vaddr(f->esp + 4)) exit(-1);
      //f->eax = remove((const char *)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_OPEN:
      //if(!is_user_vaddr(f->esp + 4)) exit(-1);
      //f->eax = open((const char *)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_FILESIZE:
      //if(!is_user_vaddr(f->esp + 4)) exit(-1);
      //f->eax = filesize((int)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_READ:
      if(!is_user_vaddr(esp + 4)) exit(-1);
      f->eax = read((int)*(uint32_t *)(esp + 4), (void *)*(uint32_t *)(esp + 8), (unsigned)*((uint32_t *)(esp + 12)));
      break;
    case SYS_WRITE:
      if(!is_user_vaddr(esp + 4)) exit(-1);
      //f->eax = write((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
      f->eax = write((int)*(uint32_t *)(esp + 4), (void *)*(uint32_t *)(esp + 8), (unsigned)*((uint32_t *)(esp + 12)));
      break;
    case SYS_SEEK:
      //if(!is_user_vaddr(f->esp + 4)) exit(-1);
      //f->eax = seek((int)*(uint32_t *)(f->esp + 4), (unsigned)*((uint32_t *)(f->esp + 8)));
      break;
    case SYS_TELL:
      //if(!is_user_vaddr(f->esp + 4)) exit(-1);
      //f->eax = tell((int)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_CLOSE:
      //if(!is_user_vaddr(f->esp + 4)) exit(-1);
      //close((int)*(uint32_t *)(f->esp + 4));
      break;
    default:
      exit(-1);
      break;
  }

}

void halt (void)
{
  shutdown_power_off();
}

void exit (int status)
{

  //int i;
  //struct thread *cur = thread_current();
  //cur->exit_status = status;
  printf("%s: exit(%d)\n", thread_name(), status);
  //for(i = 3; i < 128; i++){
  //  if(getfile(i) != NULL)
  //    close(i);
  //}
  thread_exit();
}

pid_t exec (const char *cmd_line)
{
  return process_execute(cmd_line);
}

int wait (pid_t pid)
{
  return process_wait(pid);
}
/*
bool create (const char *file, unsigned initial_size)
{
  if(file == NULL) exit(-1);
  return filesys_create(file, initial_size);
}

bool remove (const char *file)
{
  if(file == NULL) exit(-1);
  return filesys_remove(file);
}

int open (const char *file)
{
  if(f == NULL) exit(-1);
  if(!is_user_vaddr(file)) exit(-1);
  struct file *return_file = filesys_open(file);
  if(return_file == NULL) return -1;
  else{
    for(int i = 3; i < 128; i++){
      if(getfile(i) == NULL){
        if(strcmp(thread_current()->name, file) == false) file_deny_write(return_file);
      thread_current()->fd[i] = return_file;
        return i;
      }
    }
  }
  return -1;
}

int filesize (int fd)
{
  struct file *f = getfile(fd);
  if(f == NULL) exit(-1);
  else return file_length(f);
}
*/
int read (int fd, void *buffer, unsigned size)
{
  //if(!is_user_vaddr(buffer)) exit(-1);
  int i;
  if(fd == 0){
    for(i = 0; i < size; i++){
      if(((char *)buffer)[i] == '\0') break;
    }
    //return i;
  }
  return i;
  /*
  else{
    struct file *f = getfile(fd);
    if(f == NULL) exit(-1);
    else return file_read(f, buffer, size);
  }
*/
}

int write (int fd, const void *buffer, unsigned size)
{
  //if(!is_user_vaddr(buffer)) exit(-1);
  if(fd == 1){
    putbuf(buffer, size);
    return size;
  }
  /*
  else{
    struct file *f = getfile(fd);
    if(f == NULL) exit(-1);
    if(f->deny_write) file_deny_write(f);
    return file_write(f, buffer, size);
  }*/
  return -1;
}
/*
void seek (int fd, unsigned position)
{
  struct file *f = getfile(fd);
  if(f == NULL) exit(-1);
  else return file_seek(f, position);
}

unsigned tell (int fd)
{
  struct file *f = getfile(fd);
  if(f == NULL) exit(-1);
  else return file_tell(f);
}

void close (int fd)
{
  struct file *f = getfile(fd);
  if(f == NULL) exit(-1);
  else{
    f = NULL;
    file_close(f);
  }
}

struct file *getfile (int fd)
{
 return (thread_current()->fd[fd]);
}
*/
