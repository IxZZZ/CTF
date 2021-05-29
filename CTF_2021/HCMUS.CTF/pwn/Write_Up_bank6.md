# **bank6**

# Task

nc 61.28.237.24 30207

File: bank6

## Solution

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setbuf(stdout, 0);
  welcome();
  puts("[+] Good bye!");
  return 0;
}
```

```c
void welcome()
{
  puts("[+] Welcome");
  Register();
}
```

```c
void Register()
{
  char name[1024]; // [esp+Ch] [ebp-40Ch] BYREF
  int balance; // [esp+40Ch] [ebp-Ch]

  balance = 0;
  printf("[+] Here is a gift: %p\n", name);
  printf("[+] Please enter your name: ");
  __isoc99_scanf("%1036s", name);
  printf("[+] Thanks for the registration, your balance is %d.\n", balance);
}
```


