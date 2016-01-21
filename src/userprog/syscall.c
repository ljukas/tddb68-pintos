#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"

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
