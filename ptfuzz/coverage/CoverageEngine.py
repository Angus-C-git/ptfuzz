from bindings import ptrace_requests, ptrace


class CoverageEngine:
    """
    CoverageEngine is a wrapper for the ptrace library.
    """

    def __init__(self):
        """
        Initialize the CoverageEngine.
        """
        pass

    def start_trace(self, pid):
        """
        Initialize the tracee.
        """
        if (not ptrace.attach(pid)):
            raise Exception("[!] Could not attach to tracee")

    def map_breakpoints(self, pid, breakpoints):
        """
        Map breakpoints to the tracee.
        """
        for breakpoint in breakpoints:
            ptrace.set_breakpoint(pid, breakpoint)

    # these methods are in place for completness their
    # usage is not expected in the majority of cases
    def init_tracee(self, pid):
        """
        Initialize the tracee using ptrace
        seize.
        """
        ptrace.seize(pid)
