# **bank 1*

## bài này không có file thực thi nên mình thử lỗi bufferoverflow nhập một số chữ A và đã leak được luôn flag
### (do khi viết write up server đã đóng nên không có hình minh họa)


# **bank 2*

## Task
nc 61.28.237.24 30203

file: bank2
## Solution

### load file bank2 lên IDA pro và phân tích

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setbuf(stdout, 0);
  Register();
  puts("[+] Good bye!");
  return 0;
}
```

```c
void Register()
{
  char name[64]; // [esp+Ch] [ebp-4Ch] BYREF
  int balance; // [esp+4Ch] [ebp-Ch]

  balance = 0;
  printf("[+] Please enter your name: ");
  gets(name);
  printf("[+] Thanks for the registration, your balance is %d.\n", balance);
  if ( balance == 0x66A44 )
    getFlag();

```

```c
void getFlag()
{
  system("cat flag.txt");
}
```
Hàm `main` sẽ gọi hàm `Register`, nên ta sẽ tập trung phân tích hàm này

để `Register` gọi được hàm  `getFlag` in ra flag thì biến `balance` phải bằng `0x66A44` 
