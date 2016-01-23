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
void exit(int status);

void halt(void);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


void halt(void) {
  power_off();
}

bool create(const char *file, unsigned initial_size) {
  return filesys_create(file, initial_size);
}

int read(int fd, void *buffer, unsigned size) {
  //unsigned i = 0;
  if(buffer + size - 1 >= PHYS_BASE || get_user(buffer + size - 1) == -1) {
  if(fd >= BITMAPSIZE) return -1;
  struct thread *cur = thread_current();
  struct file *my_file = cur->file_list[fd];
  if(fd == STDIN_FILENO) {
      for(unsigned i = 0; i < size; ++i) {
	  buffer[i] = input_getc();
      }
      return size;
  }
  int lenght = (int) file_read(my_file, buffer, size);
  return lenght;
  }
}

int open(const char* file) {
  struct file *f;
  
  // Check that we are in uaddr and there are no segfaults
  if(file >= PHYS_BASE || get_user(file) == -1) {
    exit(-1);
    NOT_REACHED();
    return -1;
  }
  f = file_open(file);
  if(!f) {
    return -1;
  }

  //int fd = bitmap_scan_and_flip(thread_current()->fd_map, 2, 1, 0);
  //if (fd == BITMAP_ERROR || STDIN_FILENO || STDOUT_FILENO) {
  //  file_close(f);
    //  return -1;
    //}

  return -1;
}

int write(int fd, const void *buffer, unsigned size) {
  int retval = -1;

  //Check that we are in uaddr and there are no segfaults
  if(buffer + size - 1 >= PHYS_BASE || get_user(buffer + size - 1) == -1) {
    exit(-1);
    NOT_REACHED();
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
  
  // Missing code about writing to files
  
  return retval;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /*
  printf ("system call!\n");
  printf ("You moma so fat!\n");

  */
  
  // What to do next?
  
  /*
    - Function for getting four bytes from the stack
    - Make sure those four bytes are below PHYS_BASE
    - Implement syscall HALT
    - Implement syscall WRITE
    - Implement the rest in any order we want
   */

  int sys_call = get_four_user_bytes(f->esp);
  printf("Executing syscall: %d\n", sys_call);
  
  switch(sys_call) {  
  case SYS_HALT:
    halt();
    NOT_REACHED();
  case SYS_EXIT:
    exit(-1);
    NOT_REACHED();
  case SYS_CREATE:
    f->eax = (uint32_t) create((const char *file) get_four_user_bytes(f->esp+4),
			       (unsigned) get_four_user_bytes(f->esp+8));
    break;
  case SYS_READ:
    f->eax = (uint32_t) read(get_four_user_bytes(f->esp+4),
			      (const void*) get_four_user_bytes(f->esp+8),
			      (unsigned) get_four_user_bytes(f->esp+12));
  case SYS_OPEN:
    f->eax = (uint32_t) open((const char*) get_four_user_bytes(f->esp+4));
    break;
  case SYS_WRITE:
    f->eax = (uint32_t) write(get_four_user_bytes(f->esp+4),
			      (const void*) get_four_user_bytes(f->esp+8),
			      (unsigned) get_four_user_bytes(f->esp+12));
    break;
  default:
    printf("Non-implemented syscall called for\n");
    thread_exit();
    break;
  }
}

void exit(int status) {
    thread_exit();
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
