from rich import print
import pytest
from pwn import process

# :::::::::::::::::: config ::::::::::::::::::

from ptfuzz.coverage.BreakpointMap import BreakpointMap
from rich.console import Console
TEST_BIN_PATH = 'targets/tracee'


def test_get_breakpoints():
    """
    Test that we can get the breakpoints
    for a process
    """
    proc = process(TEST_BIN_PATH)
    pid = proc.pid

    bp_map = BreakpointMap(pid, TEST_BIN_PATH)
    print(f"[>>] process base: {hex(bp_map.proc_base)}")
    print(f"[>>] function map")
    print(bp_map.func_map)

    assert len(bp_map.func_map) == 6
