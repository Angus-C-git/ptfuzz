from ptfuzz.bindings import (
    ptrace_requests,
    registers_struct,
    ptrace
)
from ptfuzz.utils.functions import get_functions
from ptfuzz.utils.rebase import rebase
from ptfuzz.utils.convert import bytes2word
from pwn import p64

SIGTRAP = 0xcc000000

# INT3
TRAP_CODE = 0xCC

ADDRESS_MASK_x86 = 0xFFFFFF00
ADDRESS_MASK_x86_64 = 0xFFFFFFFFFFFFFF00


class BreakpointMap:
    """
    Create a map of soft breakpoints 
    in the target process given a pid.
    """

    def __init__(self, pid, binary):

        # self.map = {
        #     # breakpoint :
        #     # {
        #     #    'address' : hex,
        #     #    'instruction' : hex,
        #     #    'function_name' : string
        #     # }
        # }
        # assume 16 bytes for now
        self.size = 4
        # rebase the process
        self.proc_base = rebase(pid)
        self.pid = pid
        self.binary = binary
        self.func_map = get_functions(binary, self.proc_base)

        self.breakpoints = {}
        for fname, address in self.func_map.items():
            # print(f"[>>] {fname} : {hex(address)}")
            self.breakpoints[self.gen_breakpoint(address)] = {
                'address': address,
                'function_name': fname,
                'triggered': False,
            }

    def read_mem(self, address):
        """
        Read memory from the target process using 
        /proc/{pid}/mem.
        """
        try:
            with open(f"/proc/{self.pid}/mem", "rb") as f:
                res = f.seek(address)
                return f.read(self.size)
        except Exception as e:
            # ideally fallback to ptrace here, but peektext
            # is crippled
            print("[!] Error reading memory:", e)
            return None

    def gen_breakpoint(self, address, arch='x86_64'):
        """ 
        Swap out the last byte of instruction with trap code
        """

        # extract instruction candidate
        instruction = bytes2word(self.read_mem(address))
        print("[>>] set bp", hex(
            ((instruction & ADDRESS_MASK_x86_64) | TRAP_CODE)))

        if (arch == 'x86'):
            return ((instruction & ADDRESS_MASK_x86) | TRAP_CODE)

        return ((instruction & ADDRESS_MASK_x86_64) | TRAP_CODE)

    def remove(self, breakpoint):
        try:
            ptrace.write_addr(
                self.pid,
                self.breakpoints[breakpoint.address],
                self.breakpoints[breakpoint.instruction]
            )
        except KeyError:
            return

    def set_breakpoints(self):
        """
        Set breakpoints in the target process.
        """
        for bp, data in self.breakpoints.items():
            res = ptrace.write_addr(
                self.pid,
                data['address'],
                bp
            )
            # print(f"[>>] set bp {hex(data['address'])}")
