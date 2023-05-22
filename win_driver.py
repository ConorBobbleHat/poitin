from typing import List
from driver import Driver

CDB_LOCATION = "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x86\\cdb.exe"

class WinDriver(Driver):
    def __init__(self, command: List[str], start_address: int, cwd: str=".") -> None:
        super().__init__([CDB_LOCATION] + command, start_address, cwd)
        self.prompt = "0:000>"

        self.read_until_prompt() # discard welcome text

        self.run_command(f"bu {start_address:x}")
        self.run_command(f"g")