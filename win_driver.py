import re

from driver import Driver, ExecutionState

from typing import Dict, List, Tuple


CDB_LOCATION = "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x86\\cdb.exe"

class WinDriver(Driver):
    def __init__(self, command: List[str], start_address: int, cwd: str=".", env: Dict[str, str]={}) -> None:
        super().__init__([CDB_LOCATION] + command, start_address, cwd, env)
        self.prompt = "0:000>"

        self.read_until_prompt() # discard welcome text

        self.run_command(f"bu {start_address:#x}")
        self.run_command(f"g")


    def step(self) -> ExecutionState:
        return self.parse_state_from_output(self.run_command("t"))
    
    def step_out(self) -> ExecutionState:
        x = self.run_command("gu")
        return self.parse_state_from_output(x)
    
    def fetch_state(self) -> ExecutionState:
        return self.parse_state_from_output(self.run_command("r"))
    
    def set_state(self, state: ExecutionState) -> None:
        raise NotImplementedError("set_state is not implemented for WinDriver!")

    def parse_state_from_output(self, output: str) -> ExecutionState:
        reg_info_raw = " ".join(output.splitlines())
        reg_info: List[Tuple[str, str]] = re.findall(r"([a-z]*)=([0-9a-f]*)", reg_info_raw)
        reg_dict = {reg_name: int(reg_val, 16) for reg_name, reg_val in reg_info if reg_name in self.EXECUTION_STATE_FIELDS}
        
        return ExecutionState(**reg_dict)
    
    def get_current_function_name(self) -> str:
        raise NotImplementedError("get_current_function_name is not implemented for WinDriver!")

    def read_half_word(self, address: int) -> int:
        raw_output = self.run_command(f"dw /c1 {address:#x} {address:#x}")
        parts = raw_output.split()
        return int(parts[1], 16) # skip address, return value, skip ascii

    def read_word(self, address: int) -> int:
        raw_output = self.run_command(f"dc /c1 {address:#x} {address:#x}")
        parts = raw_output.split()
        return int(parts[1], 16) # skip address, return value, skip ascii

    def read_string_at_address(self, address: int) -> str:
        raw_output = self.run_command(f'.printf "%ma", {address:#x}')
        return raw_output.split("0:000>")[0].strip()

    def run_to_completion(self) -> None:
        self.run_command("g")