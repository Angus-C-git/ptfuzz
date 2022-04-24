# tmp import of print
from rich import print
from ptfuzz.bindings import (
    ptrace_requests,
    registers_struct,
    ptrace
)
from ptfuzz.utils.functions import get_functions
from ptfuzz.utils.rebase import rebase
from ptfuzz.utils.convert import bytes2word
from pwn import p64
from ctypes import addressof
import logging
logging.basicConfig(level=logging.DEBUG)

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

        logging.debug(f"[>>] ===== breakpoints ==== \n{self.breakpoints}")

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
            logging.error("[!] Error reading memory:", e)
            return None

    def gen_breakpoint(self, address, instruction=None, arch='x86_64'):
        """ 
        Swap out the last byte of instruction with trap code
        """

        if not instruction:
            # extract instruction candidate
            instruction = bytes2word(self.read_mem(address))

        logging.debug(
            f"[>>] set bp {hex(address)}:{hex(((instruction & ADDRESS_MASK_x86_64) | TRAP_CODE))}"
        )

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

    # >>> TODO: fix instruction ptr restoration
    def update(self):
        """
        Restore the breakpoint at the current address with the 
        instruction stored in the breakpoint map, roll back the 
        instruction pointer and continue.
        """

        # get the current register state
        registers = ptrace.get_regs(self.pid)

        # read the rip register
        bp_address = registers.rip - 1
        print(f"[>>] current rip: {' ' * 5} {hex(bp_address)} -> {bp_address}")

        # update the breakpoint status
        self.breakpoints[bp_address]['triggered'] = True
        print(f"[>>] map ref  {' ' * 9} {self.breakpoints[bp_address]}")

        try:
            ptrace.write_addr(
                self.pid,
                bp_address,
                self.breakpoints[bp_address]['instruction']
            )
        except KeyError:
            return

        # restore the rip register
        registers.rip = bp_address - 1
        res = ptrace.set_regs(self.pid, registers)

        print(
            f"[>>] restore to -> {' ' * 4} {hex(bp_address)}:{hex(self.breakpoints[bp_address]['instruction'])}")

        # ================= DEBUG =================
        modified_registers = ptrace.get_regs(self.pid)
        print(f"[>>] modified rip: {' ' * 4} {hex(modified_registers.rip)}")
        restored_instruction = bytes2word(
            self.read_mem(modified_registers.rip + 1))
        print(
            f"[>>] restored ins: {' ' * 4} {hex(restored_instruction)}")
        # ========================================

        # continue execution
        ptrace.cont(self.pid)


''' dev notes:

    + TODO -> Fix breakpoint restoration on SIGTRAP 
'''
