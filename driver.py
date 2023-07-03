from abc import ABC, abstractmethod
from dataclasses import dataclass, fields

import subprocess
import os

from typing import Dict, List, Optional

@dataclass
class ExecutionState:
    eax: int
    ebx: int
    ecx: int
    edx: int
    esi: int
    edi: int
    eip: int
    esp: int
    ebp: int


class Driver(ABC):
    def __init__(self, command: List[str], start_address: int, cwd: str=".", env: Dict[str, str]={}) -> None:
        self.command = command
        self.start_address = start_address
        self.cwd = cwd
        self.prompt = ""
        self.env = env

        self.process = subprocess.Popen(self.command, stdout=subprocess.PIPE, stdin=subprocess.PIPE, env=dict(os.environ, **self.env))

        self.EXECUTION_STATE_FIELDS = [f.name for f in fields(ExecutionState) if f.init]

    def read_until_prompt(self, prompt: Optional[str] = None) -> str:
        if prompt is None:
            prompt = self.prompt

        if self.process.stdout is None:
            raise ValueError("Process has no stdout!")

        out_buf = ""
        while True:
            out_buf += self.process.stdout.read(1).decode("utf8")
            if out_buf.endswith(prompt):
                break

        return out_buf

    def write_line(self, line: str) -> None:
        if self.process.stdin is None:
            raise ValueError("Process has no stdin!")

        self.process.stdin.write(f"{line}\n".encode("utf8"))
        self.process.stdin.flush()

    def run_command(self, command: str) -> str:
        self.write_line(command)
        return self.read_until_prompt()

    @abstractmethod
    def step(self) -> ExecutionState:
        pass
    
    @abstractmethod
    def step_out(self) -> ExecutionState:
        pass

    @abstractmethod
    def fetch_state(self) -> ExecutionState:
        pass

    @abstractmethod
    def set_state(self, state: ExecutionState) -> None:
        pass

    @abstractmethod
    def parse_state_from_output(self, output: str) -> ExecutionState:
        pass

    @abstractmethod
    def get_current_function_name(self) -> str:
        pass

    @abstractmethod
    def read_half_word(self, address: int) -> int:
        pass

    @abstractmethod
    def read_word(self, address: int) -> int:
        pass

    @abstractmethod
    def read_string_at_address(self, address: int) -> str:
        pass

    @abstractmethod
    def run_to_completion(self) -> None:
        pass