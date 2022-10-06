import os, sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE,QL_INTERCEPT
from qiling.os.const import UINT, POINTER

def hook_init_sock(ql: Qiling):
    br0_addr = 0x0040BAC0
    ql.mem.write(br0_addr, b'lo\x00')

def my_setsockopt(ql: Qiling):
    print("*" * 20)
    params = ql.os.resolve_fcall_params(
        {'sockfd': UINT,
         'level': UINT,
         'optname': UINT,
         'optval': POINTER,
         'optlen': UINT
         }
    )
    sockfd = params['sockfd']
    level = params['level']
    optname = params['optname']
    optval = params['optval']
    optlen = params['optlen']
    print(f'sockfd: {sockfd}, level : {level}, optname: {optname}, optval: {optval}, optlen: {optlen}')


def my_sendto(ql: Qiling):
    return 0


def hook_to_packet_handle(ql: Qiling):
    ql.arch.regs.write("pc", 0x00403978)

def hook_004034D4(ql: Qiling):
    ql.arch.regs.write("v0", 0x1)

def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, verbose=QL_VERBOSE.DEFAULT)
    ql.root = True
    ql.debugger = True

    call_protocol_handler_addr = 0x00403540
    main_addr = 0x0403660
    init_sock_addr = 0x00402BA8
    after_initrsock_addr = 0x004038E8

    #hook_init_sock()
    # after finish sock init, jump to packet handle function
    ql.hook_address(hook_to_packet_handle,after_initrsock_addr)
    ql.hook_address(hook_004034D4, 0x04034D4)
    ql.patch(0x0040BAC0, b'lo\x00')
    ql.os.set_api('setsockopt', my_setsockopt, QL_INTERCEPT.CALL)
    ql.os.set_api('sendto', my_sendto,QL_INTERCEPT.CALL)

    ql.run()

if __name__ == "__main__":
    cur_dir = os.path.abspath(".")
    my_sandbox([cur_dir+"/rootfs/device_discover"], cur_dir+"/rootfs")

