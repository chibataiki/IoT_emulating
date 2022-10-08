import sys, os
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions import afl


size=1472

def main(input_file, enable_trace=False):
    cur_dir = os.path.abspath(".")
    ql = Qiling([cur_dir+"/rootfs/device_discover"],
                cur_dir+"/rootfs",
                verbose=QL_VERBOSE.DEFAULT,
                console = True if enable_trace else False)
    # ql.debugger = True
    def hook_main_fun(ql):
        ql.arch.regs.write("a0", 1) # sockfd
        ql.arch.regs.write("a1", buf_addr)
        #     .text:00403544                 move    $a2, $s7
        ql.arch.regs.write("s7", 1) # src_addr
        ql.arch.regs.write("t9", 0x00404D48)
        ql.arch.regs.write("pc", 0x00403540)

    def place_input_callback(_ql: Qiling, input: bytes, _):
        _ql.mem.write(buf_addr, input)

    def start_afl(ql: Qiling):
        afl.ql_afl_fuzz(ql, input_file=input_file, place_input_callback=place_input_callback, exits=[ql.os.exit_point])

    buf = ql.mem.map_anywhere(size)
    buf_addr = buf + 1000

    call_protocol_handler_addr = 0x00403540
    main_addr = 0x0403660
    ql.hook_address(hook_main_fun,main_addr+4)
    ql.hook_address(start_afl, main_addr)

    try:
        ql.run(end= call_protocol_handler_addr+0x8)
        os._exit(0)
    except:
        if enable_trace:
            print("\nFuzzer Went Shit")
        os._exit(0)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        raise ValueError("No input file provided.")
    if len(sys.argv) > 2 and sys.argv[1] == "-t":
        main(sys.argv[2], enable_trace=True)
    else:
        main(sys.argv[1])
