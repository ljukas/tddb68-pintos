#include <stdio.h>
#include <string.h>
#include <syscall.h>
#include <stdarg.h>

int main(void) {
  char *shortStr = "This is a short string, can you write this to console?\n";
  char *longStr  = "This is a longer stringer, can you perhaps if you are a little lucky\n \
with you typing you can succeed in being a stripper, or even a programmer?\n";
  char sbuf[50];
  int file[3];

  write(STDOUT_FILENO, shortStr, strlen(shortStr));
  write(STDOUT_FILENO, longStr, strlen(longStr));

  for(unsigned i = 0; i < 2; i++){
    snprintf(sbuf, 50, "test%d", i);
    file[i] = open(sbuf);
    if(file[i] > 1){
    }
    else{
      printf("Could not open %s\n", sbuf);
      halt();
    }
  }

  printf("Syscall test successful.\n");
  halt();

   
}
