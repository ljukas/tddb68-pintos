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
void seek(int fd, unsigned pos);
unsigned tell(int fd);
int filesize(int fd);
bool remove(const char *file);

void is_buffer_ok(const char *f);

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

void
syscall_init (void) 
{
  if(debug_print) printf("s: syscall_init\n");
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


void 
seek(int fd, unsigned pos){
  file_seek(thread_current()->file_list[fd], pos);
}

unsigned 
tell(int fd){
  return file_tell(thread_current()->file_list[fd]);
}

int 
filesize(int fd){
  return file_length(thread_current()->file_list[fd]);
}

bool 
remove(const char *file){
  return filesys_remove(file);
}


/* Halts pintos */
void 
halt(void) {
  if(debug_print) printf("s: halt \n");
  power_off();
}

/* Exit thread */
void 
exit(int status) {
  struct thread *cur = thread_current();
  cur->exit_status = status;  
  thread_exit();
}


/* Create a file */
bool 
create(const char *file, unsigned initial_size) {
  if(debug_print) printf("s: create \n");
  is_buffer_ok(file);
  return filesys_create(file, initial_size);
}

/* Close a file if it is open */
void 
close(int fd) {
  if(debug_print) printf("s: t: %d close fd: %d \n",thread_current()->tid, fd);
  if(fd >= FD_SIZE || fd < 0) {
    return -1;
  }

  struct thread *cur = thread_current();
  if(bitmap_test(cur->fd_map, fd)) {
    struct file *my_file = cur->file_list[fd];
    file_close(my_file);
    bitmap_reset(cur->fd_map, fd);
  }
}

/* Read an open file */
int 
read(int fd, void *buffer, unsigned size) {
  if(debug_print) printf("s: t: %d read \n", thread_current()->tid);
 
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
int 
open(const char* file) {
  struct file *f;
  if(debug_print) printf("s: t: %d  open \n", thread_current()->tid);
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
int 
write(int fd, const void *buffer, unsigned size) {
  if(debug_print) printf("s: t: %d write %d\n", fd, thread_current()->tid);
  int retval = -1;

  // Make sure we dont try to write to a file with an index larger than the maximum allowed open programs
  if(fd >= FD_SIZE || fd < 0) {
    if(debug_print) printf("s: %d: fd(%d) >= FD_SIZE\n", __LINE__, fd);
     return -1;
  }

  // Write to console
  if(fd == STDOUT_FILENO) {
    if(debug_print) printf("s: %d: going to write to console\n",__LINE__);
    size_t offset = 0;
    while(offset + 150 < size) {
      putbuf((char*) (buffer + offset), (size_t) 150);
	offset += 150;
    }
    putbuf((char*) (buffer + offset), (size_t) (size - offset));
    if(debug_print) printf("s: %d: write to console complete\n", __LINE__);
    return size;
  }


  struct thread *cur = thread_current(); 
  if(!bitmap_test(cur->fd_map, fd)) {
    if(debug_print) printf("s: %d\n", __LINE__);
    return retval;
  }  

  struct file *my_file = cur->file_list[fd];
  retval = file_write(my_file, buffer, size);
  if(debug_print) printf("s: %d: write complete\n", __LINE__);
  return retval;
}

pid_t 
exec(const char *cmd_line) {
  if(debug_print) printf("s: exec \n");
  
  
  // Returns child tid
  return process_execute(cmd_line);;
}

int 
wait(pid_t pid) {
  if(debug_print) printf("s: wait \n");

    return process_wait(pid);
}

void 
check_valid_ptr(const void *vaddr) {

  //if(debug_print) printf("s: %d, ptr: %d\n", __LINE__, vaddr); 
  struct thread *t = thread_current();

  if(vaddr == NULL || !is_user_vaddr(vaddr) ||
     pagedir_get_page(t->pagedir, vaddr) == NULL){
    exit(-1);
  }
}

int 
user_to_kernel_ptr(const void *vaddr) {
  check_valid_ptr(vaddr);
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if(!ptr) {
    exit(-1);
  }
  return (int) ptr;
}

void 
check_valid_buffer(void* buffer, unsigned size) 
{
  unsigned i;
  char* local_buffer = (char*) buffer;
  for(i = 0; i < size; i++) 
    {
      check_valid_ptr((const void*) local_buffer);
      local_buffer++;
    }
}


void 
get_arg(struct intr_frame *f, int *arg, int n) {
  int i;
  int *ptr;
  for (i = 0; i < n; i++) {
    ptr = (int*) f->esp + i + 1;
    check_valid_ptr((const void*) ptr);
    arg[i] = *ptr;
  }
}

void
is_buffer_ok(const char *f){
  const char *p;
  for(p = f; *p != '\0'; p++) {
    if(debug_print) printf("s: %d\n", __LINE__);
    if(is_user_vaddr(p)) 
    {
      if(debug_print) printf("s: %d\n", __LINE__);
      exit(-1);
    }
  }
}

/* Handle all syscalls */
static void
syscall_handler (struct intr_frame *f) 
{
  //if(debug_print) printf("s: %d\n", __LINE__);

  check_valid_ptr((const void*)f->esp);
  int arg[3];
  int *esp = f->esp;

  // (find null-terminator for strings

  /* Check so pointers aren't in kernel memory. */
  if(!is_user_vaddr(esp) || !is_user_vaddr(esp + 1) || !is_user_vaddr(esp + 2) || !is_user_vaddr(esp + 3)) {
    if(debug_print) printf("s: %d: %d\n", __LINE__,f->esp);
    exit(-1);
  }
  
  if(get_user(esp) == -1 || get_user(esp + 1) == -1 || get_user(esp + 2) == -1 || get_user(esp + 3) == -1){
    if(debug_print) printf("s: %d: %d\n", __LINE__,f->esp);
    exit(-1);
  }

  
  if(*esp < SYS_HALT || *esp > SYS_INUMBER){
    if(debug_print) printf("s: %d\n", __LINE__);
    exit(-1);
  }

  switch(* (int*) f->esp) {
  if(debug_print) printf("s: %d\n", __LINE__);
  case SYS_HALT:
    halt();
    NOT_REACHED();

  case SYS_EXIT:
    //if(debug_print) printf("s: %d\n", __LINE__);
    get_arg(f, &arg[0], 1);
    exit(arg[0]);
    NOT_REACHED();
    break;
    
  case SYS_CREATE:
    //if(debug_print) printf("s: %d\n", __LINE__);
    get_arg(f, &arg[0], 2);
    arg[0] = user_to_kernel_ptr((const void*) arg[0]);
    f->eax = create((const char*)arg[0], (unsigned) arg[1]);
    break;

  case SYS_CLOSE:
    //if(debug_print) printf("s: %d\n", __LINE__);
    get_arg(f, &arg[0], 1);
    close(arg[0]);
    break;

  case SYS_READ:
    //if(debug_print) printf("s: %d\n", __LINE__);
    get_arg(f, &arg[0], 3);
    check_valid_buffer((void*) arg[1], (unsigned)arg[2]);
    arg[1] = user_to_kernel_ptr((void*) arg[1]);
    f->eax = read((int)arg[0], (const void*)arg[1], (unsigned)arg[2]);
    break;
   
  case SYS_OPEN:
    //if(debug_print) printf("s: %d\n", __LINE__);
    get_arg(f, &arg[0], 1);
    arg[0] = user_to_kernel_ptr((const void*) arg[0]);
    f->eax = open((const char*)arg[0]);
    break;

  case SYS_WRITE:
    //if(debug_print) printf("s: %d\n", __LINE__);
    get_arg(f, &arg[0], 3);
    check_valid_buffer((void*)arg[1], (unsigned)arg[2]);
    arg[1] = user_to_kernel_ptr((void*)arg[1]);
    f->eax = write((int)arg[0], (const void*)arg[1], (unsigned)arg[2]);
    break;

  case SYS_EXEC:
    //if(debug_print) printf("s: %d\n", __LINE__);
    get_arg(f, &arg[0], 1);
    arg[0] = user_to_kernel_ptr((const void*)arg[0]);
    f->eax = exec((const void*)arg[0]);
    break;

  case SYS_WAIT:
    //if(debug_print) printf("s: %d\n", __LINE__);
    get_arg(f, &arg[0], 1);
    f->eax = wait(arg[0]);
    break;

  case SYS_REMOVE:
    //if(debug_print) printf("s: %d\n", __LINE__);
    get_arg(f, &arg[0], 1);
    f->eax = remove((const char *)arg[0]);
    break;

  case SYS_FILESIZE:
    //if(debug_print) printf("s: %d\n", __LINE__);
    get_arg(f, &arg[0], 1);
    f->eax = filesize((int) arg[0]);
    break;

  case SYS_SEEK:
    //if(debug_print) printf("s: %d\n", __LINE__);
    get_arg(f, &arg[0], 2);
    seek((int) arg[0], (unsigned) arg[1]);
    break;

  case SYS_TELL:
    //if(debug_print) printf("s: %d\n", __LINE__);
    get_arg(f, &arg[0], 1);
    f->eax = tell((int) arg[0]);
    break;
  default:
    printf("Non-implemented syscall called for - crash successful \n");
    thread_exit();
    break;
  }
}


