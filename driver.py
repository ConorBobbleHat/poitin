from typing import List, Optional
import subprocess


class Driver:
    def __init__(self, command: List[str], start_address: int, cwd: str=".") -> None:
        self.command = command
        self.start_address = start_address
        self.cwd = cwd
        self.prompt = ""

        self.process = subprocess.Popen(self.command, stdout=subprocess.PIPE, stdin=subprocess.PIPE)

    def read_until_prompt(self, prompt: Optional[str] = None) -> None:
        if prompt is None:
            prompt = self.prompt

        out_buf = ""
        while True:
            out_buf += self.process.stdout.read(1).decode("utf8")
            if out_buf.endswith(prompt):
                break

        return out_buf

    def write_line(self, line: str):
        self.process.stdin.write(f"{line}\n".encode("utf8"))
        self.process.stdin.flush()

    def run_command(self, command: str):
        self.write_line(command)
        return self.read_until_prompt()