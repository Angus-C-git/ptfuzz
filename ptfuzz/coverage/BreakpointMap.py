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

    breakpoint_map = {
        address :
        {
           'instruction' : int,
           'breakpoint' : int,
           'function_name' : string,
           'triggered' : bool
        }
    }
    """

    def __init__(self, pid, binary):

        # assume 4 bytes for now
        self.size = 4
        # rebase the process
        self.proc_base = rebase(pid)
        self.pid = pid
        self.binary = binary
        self.func_map = get_functions(binary, self.proc_base)

        self.breakpoints = {}
        for fname, address in self.func_map.items():
            # retrieve the instruction for address
            instruction = bytes2word(self.read_mem(address))
            # print(f"[>>] {fname}:{hex(address)}:{hex(instruction)}")

            # populate breakpoint map, keyed by address
            self.breakpoints.update(
                {
                    address:
                    {
                        'instruction': instruction,
                        'breakpoint': self.gen_breakpoint(address, instruction),
                        'function_name': fname,
                        'triggered': False,
                    }
                }
            )

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

    def gen_breakpoint(self, address, instruction=None, arch='x86_64'):
        """ 
        Swap out the last byte of instruction with trap code
        """

        if not instruction:
            # extract instruction candidate
            instruction = bytes2word(self.read_mem(address))

        # print(
        #     f"[>>] set bp {hex(address)}:{hex(((instruction & ADDRESS_MASK_x86_64) | TRAP_CODE))}")

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
        for address, data in self.breakpoints.items():
            res = ptrace.write_addr(
                self.pid,
                address,
                data['breakpoint']
            )
            # print(f"[>>] set bp {hex(data['address'])}")


''' dev notes:

+ TODO -> setup debug logging to replace print statements

'''
