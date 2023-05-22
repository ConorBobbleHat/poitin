from typing import List
from driver import Driver
import time


class WiboDriver(Driver):
    def __init__(self, command: List[str], start_address: int, cwd: str=".") -> None:
        super().__init__(["wsl", "--cd", cwd, "gdb", "--args", "./build/wibo"] + command, start_address, cwd)
        self.prompt = "(gdb)"

        self.read_until_prompt() # discard welcome text

        # With wibo, we presume we're running a special augmented version
        # that has a breakpoint right before the jump to windows code
        # TODO: verify here we're actually at the start address!
        self.run_command(f"r")
        self.run_command("si")
        self.run_command("si")