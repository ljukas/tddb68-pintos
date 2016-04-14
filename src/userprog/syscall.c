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

#define USER_VADDR_BOTTOM ((void *) 0x08048000)


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
 
  int offset;

   
  if(fd >= FD_SIZE || fd < 0) {
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

void check_valid_ptr(const void *vaddr) {
  if(!is_user_vaddr(vaddr)) 
    {
      if(debug_print) printf("s: %d, ptr: %d\n", __LINE__, vaddr);
      exit(-1);
    }
  if(vaddr < USER_VADDR_BOTTOM) 
    {
      if(debug_print) printf("s: %d, ptr: %d\n", __LINE__, vaddr);
      exit(-1);
    }
}

int user_to_kernel_ptr(const void *vaddr) {
  check_valid_ptr(vaddr);
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if(!ptr) {
    exit(-1);
  }
  return (int) ptr;
}

void check_valid_buffer(void* buffer, unsigned size) 
{
  unsigned i;
  char* local_buffer = (char*) buffer;
  for(i = 0; i < size; i++) 
    {
      if(debug_print) printf("s: %d, asd: %d\n", __LINE__, local_buffer);
      //check_valid_ptr((const void*) local_buffer);
      local_buffer++;
    }
  check_valid_ptr((const void*) local_buffer);
  
}


void get_arg_v2(struct intr_frame *f, int *arg, int n) {
  int i;
  int *ptr;
  for (i = 0; i < n; i++) {
    ptr = (int*) f->esp + i + 1;
    check_valid_ptr((const void*) ptr);
    arg[i] = *ptr;
  }
}

/* Handle all syscalls */
static void
syscall_handler (struct intr_frame *f) 
{
  //int* esp = f->esp;
  /* 
  if(!is_user_vaddr(esp) || !is_user_vaddr(esp + 1) || !is_user_vaddr(esp + 2) || !is_user_vaddr(esp + 3)) {
    if(debug_print) printf("s: 276\n");
    exit(-1);
  }
 
  if(get_user(esp) == -1 || get_user(esp + 1) == -1 || get_user(esp + 2) == -1 || get_user(esp + 3) == -1){
    if(debug_print) printf("s: 281\n");
    exit(-1);
  }

  if(*esp < SYS_HALT || *esp > SYS_REMOVE) {
    exit(-1);
  }
  */

  if(debug_print) printf("s: %d\n", __LINE__);

  //int sys_call = *esp;
  //int sys_call = get_arg(f->esp);

  check_valid_ptr((const void*)f->esp);
  
  int arg[3];
  

  switch(* (int*) f->esp) {  
  case SYS_HALT:
    halt();
    NOT_REACHED();
  case SYS_EXIT:
    get_arg_v2(f, &arg[0], 1);
    exit(arg[0]);
    NOT_REACHED();
    break;
    
  case SYS_CREATE:
    get_arg_v2(f, &arg[0], 2);
    arg[0] = user_to_kernel_ptr((const void*) arg[0]);
    f->eax = create((const char*)arg[0], (unsigned) arg[1]);
    break;
  case SYS_CLOSE:
    close(get_arg(f->esp+4));
    break;
  case SYS_READ:
    get_arg_v2(f, &arg[0], 3);
    check_valid_buffer((void*) arg[1], (unsigned)arg[2]);
    arg[1] = user_to_kernel_ptr((void*) arg[1]);
    f->eax = read((int)arg[0], (const void*)arg[1], (unsigned)arg[2]);
    break;
    
    /*
    f->eax = (uint32_t) read(get_arg(f->esp+4),
			      (const void*) get_arg(f->esp+8),
			      (unsigned) get_arg(f->esp+12));
    break;
    */
  case SYS_OPEN:
    get_arg_v2(f, &arg[0], 1);
    arg[0] = user_to_kernel_ptr((const void*) arg[0]);
    f->eax = open((const char*)arg[0]);
    

    //f->eax = (uint32_t) open((const char*) get_arg(f->esp+4));
    break;
  case SYS_WRITE:
    f->eax = (uint32_t) write(get_arg(f->esp+4),
			      (const void*) get_arg(f->esp+8),
			      (unsigned) get_arg(f->esp+12));
    if(debug_print) printf("s: %d\n", __LINE__);
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
  
  check_valid_ptr(addr);
  
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
