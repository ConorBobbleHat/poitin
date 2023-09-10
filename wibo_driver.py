from driver import Driver, ExecutionState

import subprocess

from typing import Dict, List, Optional


class WiboDriver(Driver):
    def __init__(self, command: List[str], cwd: str=".", env: Dict[str, str]={}) -> None:
        # In order to ferry through environmental variables to WSL,
        # we need to inject them into the command string
        command_env_part = [f"{key}={val}" for (key, val) in env.items()]

        subprocess.run("wsl killall gdb")

        super().__init__(["wsl", "--cd", cwd] + command_env_part + ["gdb", "--args", "./build/wibo"] + command, cwd, env)
        self.prompt = "(gdb)"

        self.read_until_prompt() # discard welcome text

        # With wibo, we presume we're running a special augmented version
        # that has a breakpoint right before the jump to windows code
        # TODO: verify here we're actually at the start address!
        self.run_command("r")
        self.run_command("si")


    def step(self) -> ExecutionState:
        self.run_command("si")
        return self.fetch_state()

    def step_out(self) -> ExecutionState:
        self.run_command("fin")
        return self.fetch_state()

    def fetch_state(self) -> ExecutionState:
        return self.parse_state_from_output(self.run_command("i r"))

    def set_state(self, state: ExecutionState) -> None:
        for field_name in self.EXECUTION_STATE_FIELDS:
            self.run_command(f"set ${field_name}={getattr(state, field_name)}")

    def parse_state_from_output(self, output: str) -> ExecutionState:
        reg_vals_raw = output.splitlines()[:-1] # skip last prompt line
        reg_vals_split = [i.split()[:2] for i in reg_vals_raw]
        reg_dict = {reg_name : int(reg_val, 16) for (reg_name, reg_val) in reg_vals_split if reg_name in self.EXECUTION_STATE_FIELDS}

        return ExecutionState(**reg_dict)
    
    def get_function_name(self, address: int) -> Optional[str]:
        function_name = self.run_command(f"info symbol {address:#x}").split()[0].split("(")[0]
        if function_name == "No":
            return None
        return function_name

    def get_current_function_name(self) -> Optional[str]:
        function_name = self.run_command("info symbol $eip").split()[0].split("(")[0]
        if function_name == "No":
            return None
        return function_name
    
    def read_byte(self, address: int) -> Optional[int]:
        out = self.run_command(f"x/1xb {address:#x}")
        try:
            return int(out.splitlines()[0].split(":")[1], 16)
        except ValueError:
            return None

    def read_half_word(self, address: int) -> int:
        raise NotImplementedError("read_half_word not implemented for WiboDriver!")

    def read_word(self, address: int) -> int:
        raise NotImplementedError("read_word not implemented for WiboDriver!")

    def read_string_at_address(self, address: int) -> str:
        raise NotImplementedError("read_string_at_address not implemented for WiboDriver!")

    def continue_execution(self) -> None:
        self.run_command("c")