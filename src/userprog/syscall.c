#include "userprog/syscall.h"
#include <stdio.h>
#include "user/syscall.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "lib/kernel/bitmap.h"

static void syscall_handler (struct intr_frame *);
static uint32_t get_arg(const void * addr);
static int get_user(const uint8_t *uaddr);
static bool put_user(uint8_t *udst, uint8_t byte);
static void validate_pointer(char *c, unsigned int size);

static bool debug_print = false;

void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
void close(int fd);
int read(int fd, void *buffer, unsigned size);
int open(const char *file);
int write(int fd, const void *buffer, unsigned size);
pid_t exec(const char*);
int wait(pid_t);

static void
validate_pointer(char *c, unsigned int size) {
  if(debug_print) printf("s: 34: validate pointer\n");
  if (size == 0) {
    if(c == NULL || !is_user_vaddr(c) || get_user(c) == -1) {
      exit(-1);
    }
  } else {
    int n;
    for(n = 0; n < size; n++) {
      if(c+n == NULL || !is_user_vaddr(c+n) || get_user(c+n) == -1) {
        exit(-1);
      }
    }
  }
}

void
syscall_init (void) 
{
  if(debug_print) printf("s: syscall_init\n");
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Halts pintos */
void halt(void) {
  if(debug_print) printf("s: halt \n");
  power_off();
}

/* Exit thread */
void exit(int status) {
  printf("%s: exit(%d)\n", thread_current()->name, status);

    struct thread *cur = thread_current();
    struct list_elem *e;
    
    // Update children
    // Tell the chilren that we've exited
    // That is they don't have a parent anymore
    for(e = list_begin(&(cur->child_threads));
	e != list_end(&(cur->child_threads));
	e = list_next(e)) {
	struct child_status *child_s = list_entry(e, struct child_status, elem);

	if(!child_s->exited) {
	    struct thread *child_t = get_thread_with_tid(child_s->pid);
	    child_t->parent_pid = 1;
	}
	list_remove(&(child_s->elem));
	palloc_free_page(child_s);
    }
    
    
    // Update parent
    // Tell the parent that we've exited
    struct thread *parent_thread = get_thread_with_tid(cur->parent_pid);
    for(e = list_begin(&(parent_thread->child_threads));
	e != list_end(&(parent_thread->child_threads));
	e = list_next(e)) {
	struct child_status *child_s = list_entry(e, struct child_status, elem);

	if(child_s->pid == cur->tid) {
	    child_s->exited = true;
	    child_s->exit_status = status;
	    if(child_s->waiting) {
		thread_unblock(parent_thread);
	    }
	}
    }
    
     /* Free resources for all open files */
    int pos;
    for(pos = 2; pos < FD_SIZE; pos++) {     // Added lab 1
	if(bitmap_test(cur->fd_map, pos)) {
	    bitmap_reset(cur->fd_map, pos);
	    free(cur->file_list[pos]);
	}
    }
    
    
  thread_exit();
}


/* Create a file */
bool create(const char *file, unsigned initial_size) {
  if(debug_print) printf("s: create \n");
  if(file + initial_size - 1 >= PHYS_BASE || get_user(file + initial_size - 1) == -1) {
    exit(-1);
    return -1;
  }

  return filesys_create(file, initial_size);
}

/* Close a file if it is open */
void close(int fd) {
  if(debug_print) printf("s: close \n");
  struct thread *cur = thread_current();
  if(!bitmap_test(cur->fd_map, fd)) {
    struct file *my_file = cur->file_list[fd];
    file_close(my_file);
    bitmap_reset(cur->fd_map, fd);
  }
}

/* Read an open file */
int read(int fd, void *buffer, unsigned size) {
  if(debug_print) printf("s: read \n");
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
  if(debug_print) printf("s: open \n");
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
  if(debug_print) printf("s: write \n");
  int retval = -1;

  // Check that we are in uaddr and there are no segfaults
  if(debug_print) printf("s: 206\n");
  if(buffer + size - 1 >= PHYS_BASE || get_user(buffer + size - 1) == -1) {
    if(debug_print) printf("s: 208: we are not in uaddr and there are no segfaults\n");
    exit(-1);
    return retval;
  }

  // Make sure we dont try to write to a file with an index larger than the maximum allowed open programs
  if(fd >= FD_SIZE) {
    if(debug_print) printf("s: 219: fd >= FD_SIZE\n");
     return -1;
  }

  // Write to console
  if(fd == STDOUT_FILENO) {
    if(debug_print) printf("s: 225: going to write to console\n");
    size_t offset = 0;
    while(offset + 150 < size) {
      putbuf((char*) (buffer + offset), (size_t) 150);
	offset += 150;
    }
    putbuf((char*) (buffer + offset), (size_t) (size - offset));
    if(debug_print) printf("s: 232: write to console complete\n");
    return size;
  }


  struct thread *cur = thread_current(); 
  if(!bitmap_test(cur->fd_map, fd)) {
    if(debug_print) printf("s: 239\n");
    return retval;
  }  

  struct file *my_file = cur->file_list[fd];
  retval = file_write(my_file, buffer, size);
  if(debug_print) printf("s: 225: write complete\n");
  return retval;
}

pid_t exec(const char *cmd_line) {
  if(debug_print) printf("s: exec \n");
  if(cmd_line >= PHYS_BASE || get_user(cmd_line) == -1) {
    exit(-1);
    return -1;
  }
 
  
  // Returns child tid
  return process_execute(cmd_line);;
}

int wait(pid_t pid) {
  if(debug_print) printf("s: wait \n");

    return process_wait(pid);
}

/* Handle all syscalls */
static void
syscall_handler (struct intr_frame *f) 
{
  int* esp = f->esp;
  if(debug_print) printf("%d\n",esp);
  if(debug_print) printf("s: 268: esp: %d syscall: %d\n",esp,*esp);
  printf("esp = %d",esp);
  int noll = 0;
  printf(", noll = %d\n",noll);  
  if(esp > noll){
    //if(debug_print) 
    printf("s: 271: %d > 0 ... obviusly.. \n",esp);
    exit(-1);
  }
  
  if(!is_user_vaddr(esp) || !is_user_vaddr(esp + 1) || !is_user_vaddr(esp + 2) || !is_user_vaddr(esp + 3)) {
    if(debug_print) printf("s: 276\n");
    exit(-1);
  }
  if(debug_print) printf("s: 279: esp: %d\n",esp);
  if(get_user(esp) == -1 || get_user(esp + 1) == -1 || get_user(esp + 2) == -1 || get_user(esp + 3) == -1){
    if(debug_print) printf("s: 281\n");
    exit(-1);
  }

  if(debug_print) printf("s: 285\n");

  //int sys_call = *esp;
  int sys_call = get_arg(f->esp);
  
  switch(sys_call) {  
  case SYS_HALT:
    halt();
    NOT_REACHED();
  case SYS_EXIT:
      exit((int) get_arg(f->esp+4));
      NOT_REACHED();
  case SYS_CREATE:
    f->eax = (uint32_t) create((const char*) get_arg(f->esp+4),
			       (unsigned) get_arg(f->esp+8));
    break;
  case SYS_CLOSE:
    close(get_arg(f->esp+4));
    break;
  case SYS_READ:
    f->eax = (uint32_t) read(get_arg(f->esp+4),
			      (const void*) get_arg(f->esp+8),
			      (unsigned) get_arg(f->esp+12));
    break;
  case SYS_OPEN:
    f->eax = (uint32_t) open((const char*) get_arg(f->esp+4));
    break;
  case SYS_WRITE:
    f->eax = (uint32_t) write(get_arg(f->esp+4),
			      (const void*) get_arg(f->esp+8),
			      (unsigned) get_arg(f->esp+12));
    if(debug_print) printf("s: 316\n");
    break;
  case SYS_EXEC:
    f->eax = (pid_t) exec((const char*)get_arg(f->esp+4));
    break;
  case SYS_WAIT:
      f->eax = (int) wait((pid_t) get_arg(f->esp+4));
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
static uint32_t get_arg(const void *addr) {
  if(debug_print) printf("s: 321: get_arg\n");
  if(is_kernel_vaddr(addr))
    exit(-1);
  if(debug_print) printf("s: 322: passed the check\n");
  uint32_t *uaddr = (uint32_t *) addr;
  
  if(get_user(uaddr + 3) != -1)
    return *uaddr;
  exit(-1);
  NOT_REACHED();
}


/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  if(debug_print) printf("s: 354: uaddr: %d\n",uaddr);
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
