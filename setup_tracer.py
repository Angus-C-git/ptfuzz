from distutils.core import setup, Extension

tracer = Extension('tracer', sources=['tracer/ptrace.c'])

setup(
    name='tracer',
    version='1.0',
    description='A python C extension to wrap the ptrace syscall',
    ext_modules=[tracer]
)
