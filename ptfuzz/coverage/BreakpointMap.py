from ptfuzz.bindings import (
    ptrace_requests,
    registers_struct,
    ptrace
)
from ptfuzz.utils.functions import get_functions
from ptfuzz.utils.rebase import rebase


SIGTRAP = 0xCC


def gen_breakpoint(address, size):
    """
    Generate a breakpoint instruction
    """
    return bytes([SIGTRAP]) * size


class BreakpointMap:
    """
    Create a map of soft breakpoints 
    in the target process given a pid.
    """

    def __init__(self, pid, binary):
        self.breakpoints = {
            # breakpoint :
            # {
            #    'address' : hex,
            #    'instruction' : hex,
            #    'function_name' : string
            # }
        }

        # rebase the process
        self.proc_base = rebase(pid)
        self.pid = pid
        self.binary = binary
        self.func_map = get_functions(binary, self.proc_base)

    def remove(self, breakpoint):
        try:
            ptrace.write_addr(
                self.pid,
                self.breakpoints[breakpoint.address],
                self.breakpoints[breakpoint.instruction]
            )
        except KeyError:
            return

    def set_breakpoints(self, pid):
        """
        Set all breakpoints in the target process.
        """
        for breakpoint in self.breakpoints:
            ptrace.write_addr(
                pid,
                self.breakpoints[breakpoint],
                gen_breakpoint(
                    breakpoint,
                    self.breakpoints[breakpoint]
                )
            )
