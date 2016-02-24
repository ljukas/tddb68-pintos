#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "lib/kernel/bitmap.h"

static void syscall_handler (struct intr_frame *);
static int get_four_user_bytes(const void * addr);
static int get_user(const uint8_t *uaddr);
static bool put_user(uint8_t *udst, uint8_t byte);

void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
void close(int fd);
int read(int fd, void *buffer, unsigned size);
int open(const char *file);
int write(int fd, const void *buffer, unsigned size);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Halts pintos */
void halt(void) {
  power_off();
}

/* Exit thread */
void exit(int status) {
  // needs to be filled with more, status isn't handled atm for example
  thread_exit();
}


/* Create a file */
bool create(const char *file, unsigned initial_size) {
  
  if(file + initial_size - 1 >= PHYS_BASE || get_user((uint8_t*)(file + initial_size - 1)) == -1) {
    exit(-1);
    return -1;
  }

  return filesys_create(file, initial_size);
}

/* Close a file if it is open */
void close(int fd) {
  
  struct thread *cur = thread_current();
  if(!bitmap_test(cur->fd_map, fd)) {
    struct file *my_file = cur->file_list[fd];
    file_close(my_file);
    bitmap_reset(cur->fd_map, fd);
  }
}

/* Read an open file */
int read(int fd, void *buffer, unsigned size) {
  
  if(buffer + size - 1 >= PHYS_BASE || get_user(buffer + size - 1) == -1) {
    exit(-1);
    return -1;
  }

  int offset;
   
  if(fd >= FD_SIZE) {
    return -1;
  }
  
  if(fd == STDIN_FILENO) {
      for(offset = 0; offset != size; ++offset) {
	*(uint8_t *)(buffer + offset) = input_getc();
      }
      return size;
  }
  
  struct thread *cur = thread_current();
  struct file *my_file = cur->file_list[fd];

  if(bitmap_test(cur->fd_map, fd)) { 
    return (int) file_read(my_file, buffer, size);
  }
  
  return -1;
}

/* Open a created file */
int open(const char* file) {
  struct file *f;
  
  // Check that we are in uaddr and there are no segfaults
  if(file >= PHYS_BASE || get_user(file) == -1) {
    exit(-1);
    return -1;
  }

  // Check if its OK to open one more file for the thread
  int fd = bitmap_scan_and_flip(thread_current()->fd_map, 2, 1, 0);
  if (fd == BITMAP_ERROR) {
    return -1;
  }

  // Open the file
  f = filesys_open(file);
  if(f == NULL) {
    bitmap_reset(thread_current()->fd_map, fd);
    return -1;
  }

  // Put the open file in our file_list
  struct thread *cur = thread_current();
  cur->file_list[fd] = f;
  
  // Return file descriptor
  return fd;
}

/* Write in an open file */
int write(int fd, const void *buffer, unsigned size) {
  int retval = -1;

  // Check that we are in uaddr and there are no segfaults
  if(buffer + size - 1 >= PHYS_BASE || get_user(buffer + size - 1) == -1) {
    exit(-1);
    return retval;
  }

  if(fd >= FD_SIZE) {
    return retval;
  }

  // Make sure we dont try to write to a file with an index larger than the maximum allowed open programs
  if(fd >= FD_SIZE) {
     return -1;
  }

  // Write to console
  if(fd == STDOUT_FILENO) {
    size_t offset = 0;
    while(offset + 150 < size) {
      putbuf((char*) (buffer + offset), (size_t) 150);
	offset += 150;
    }
    putbuf((char*) (buffer + offset), (size_t) (size - offset));
    return size;
  }


  struct thread *cur = thread_current(); 
  if(!bitmap_test(cur->fd_map, fd)) {
    return retval;
  }  

  struct file *my_file = cur->file_list[fd];
  retval = file_write(my_file, buffer, size);
  return retval;
}

pid_t exec(const char *cmd_line) {

  if(cmd_line >= PHYS_BASE || get_user(cmd_line) == -1) {
    exit(-1);
    return -1;
  }

  
  // Returns child tid
  return process_execute(cmd_line);
}

/* Handle all syscalls */
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int sys_call = get_four_user_bytes(f->esp);
  
  switch(sys_call) {  
  case SYS_HALT:
    halt();
    NOT_REACHED();
  case SYS_EXIT:
    //TODO Return status and free allocated memory
    exit(-1);
    NOT_REACHED();
  case SYS_CREATE:
    f->eax = (uint32_t) create((const char*) get_four_user_bytes(f->esp+4),
			       (unsigned) get_four_user_bytes(f->esp+8));
    break;
  case SYS_CLOSE:
    close(get_four_user_bytes(f->esp+4));
    break;
  case SYS_READ:
    f->eax = (uint32_t) read(get_four_user_bytes(f->esp+4),
			      (const void*) get_four_user_bytes(f->esp+8),
			      (unsigned) get_four_user_bytes(f->esp+12));
    break;
  case SYS_OPEN:
    f->eax = (uint32_t) open((const char*) get_four_user_bytes(f->esp+4));
    break;
  case SYS_WRITE:
    f->eax = (uint32_t) write(get_four_user_bytes(f->esp+4),
			      (const void*) get_four_user_bytes(f->esp+8),
			      (unsigned) get_four_user_bytes(f->esp+12));
    break;
  case SYS_EXEC:
    f->eax = (pid_t) exec((const char*)get_four_user_bytes(f->esp+4));
    break;
  default:
    printf("Non-implemented syscall called for - crash successful \n");
    thread_exit();
    break;
  }
}

/* All system call arguments, weather integer or pointer
   takes up 4 bytes on the stack. This function gets those 4 bytes
   and returns them as an int.

   Param: In-parameter should be f->esp, which is the pointer to the stack */
static int get_four_user_bytes(const void * addr) {
  if(is_kernel_vaddr(addr)) { exit(-1); }

  uint8_t *uaddr = (uint8_t*) addr;
  

  int temp;
  int result = 0;
  temp = get_user(uaddr);
  if(temp == -1) { exit(-1); }
  result += (temp << 0);
  temp = get_user(uaddr + 1);
  if(temp == -1) { exit(-1); }
  result += (temp << 8);
  temp = get_user(uaddr + 2);
  if(temp == -1) { exit(-1); }
  result += (temp << 16);
  temp = get_user(uaddr + 3); 
  if(temp == -1) { exit(-1); }
  result += (temp << 24);

  return result;
}


  // ######################################
  // NOT MADE BY US, PROVIDED BY THE MANUAL
  // ######################################

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}
