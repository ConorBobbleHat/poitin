from termcolor import cprint
import pefile # type: ignore

import dataclasses
import socket
import struct
import configparser
import shlex

from win_driver import WinDriver
from wibo_driver import WiboDriver

_CONFIG = configparser.ConfigParser()
_CONFIG.read(["config.ini", "config.local.ini"])
CONFIG = _CONFIG["poitin"]

def setup_output_discrepency_check() -> None:
    return

def check_output_discrepency_present() -> None:
    return

def main() -> None:
    setup_output_discrepency_check()
    
    COMMAND = shlex.split(CONFIG.get("Command"))
    CYCLE_ACCURATE = CONFIG.getboolean("CycleAccurate")
    CYCLE_ACCURATE_TRIGGER = CONFIG.get("CycleAccurateTrigger")

    win_driver = WinDriver(COMMAND)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("0.0.0.0", 8088))

    win_state = win_driver.fetch_state()
    wibo_driver = WiboDriver(COMMAND, cwd="/home/conor/projects/wibo", env={
        "POITIN_STACK_BASE": str(win_state.ebp)
    })

    # 32-bit windows isn't amazingly strict on the starting value
    # of registers when execution is handed over to a newly created process.
    # As such: there's a bunch of unimportant registers we need to copy over from windows to wibo to ensure
    # cycle-level matching in execution. (Most will be immediately discarded, anyways)
    # We're safe to do things like override the stack registers - wibo will have mapped the stack for us
    wibo_driver.set_state(win_state)
    
    if not CYCLE_ACCURATE:
        # Set up breakpoints at syscalls.
        pe = pefile.PE(COMMAND[0])
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll: str = entry.dll.decode("utf8")
            module_name = dll.split(".")[0].lower()

            for imp in entry.imports:
                fun_name: str = imp.name.decode("utf8")
                
                out = win_driver.run_command(f"bu {module_name}!{fun_name}")

                if "Couldn't resolve" in out:
                    win_driver.run_command(f"bu {module_name}!{fun_name}Stub")

                wibo_driver.run_command(f"b {module_name}::{fun_name}")

    while True:
        if CYCLE_ACCURATE:
            win_state = win_driver.step()
            wibo_state = wibo_driver.step() 
        else:
            win_driver.continue_execution()
            win_state = win_driver.fetch_state()

            wibo_driver.continue_execution()
            wibo_state = wibo_driver.fetch_state()

        print (f"{win_state.eip:#10x}")

        if win_state == wibo_state:
            continue

        # If we're here, there's a discrepancy of some sort.
        
        # Possibility one: we're about to make a kernel call,
        # and eip is different as we've begun executing code
        # from some system dll (or wibo's implementation thereof)
        if win_state.eip != wibo_state.eip:
            syscall_name = wibo_driver.get_current_function_name()
            return_address = win_driver.read_word(win_state.esp)

            if syscall_name == CYCLE_ACCURATE_TRIGGER:
                cprint ("Switching to cycle accurate mode!", "red")
                CYCLE_ACCURATE = True

            cprint (f"SYSTEM CALL DETECTED: {syscall_name}", "red")
            cprint (f"({win_state.eip:#x} vs {wibo_state.eip:#x})", "yellow")

            wibo_driver.continue_execution()

            # This is where the meat and potatoes of poitin begins
            # Respond to requests from our wibo guest for information about
            # the windows program running in tandem to it
            while True:
                data, client = server_socket.recvfrom(1024)
                if len(data) != data[0]:
                    print ("Corrupt packet!")
                    import sys; sys.exit(1)

                opcode = data[1]

                if opcode == 0:
                    # Windows step out
                    win_driver.run_command(f"bu {return_address:#x}")
                    win_driver.run_command("g")
                    win_state = win_driver.fetch_state()
                elif opcode == 1:
                    # Request fetch register
                    reg_index = data[2]
                    reg_name = wibo_driver.EXECUTION_STATE_FIELDS[reg_index]
                    reg_value = getattr(win_state, reg_name)

                    server_socket.sendto(struct.pack("I", reg_value), client)
                elif opcode == 2:
                    # Hand back execution to wibo
                    break
                elif opcode == 3:
                    # memcpy
                    addr = struct.unpack("I", data[4:8])[0]
                    l = struct.unpack("I", data[8:12])[0]
                    
                    d = b""
                    for i in range(l):
                        b = win_driver.read_byte(addr + i)
                        if b is None:
                            raise ValueError(f"Attempted to read invalid memory from windows: {addr + i:#x}")
                        
                        d += bytearray([b])

                    server_socket.sendto(d, client)
                elif opcode == 4:
                    # strlen
                    addr = struct.unpack("I", data[4:8])[0]
                    s = win_driver.read_string_at_address(addr)
                    if s is None:
                        raise ValueError(f"Attempted to read invalid string from windows at {addr:#x}")

                    l = len(s)
                    server_socket.sendto(struct.pack("I", l), client)
                elif opcode == 5:
                    # strlenWide
                    addr = struct.unpack("I", data[4:8])[0]
                    l = 0

                    while win_driver.read_half_word(addr) != 0:
                        l += 1
                        addr += 2

                    server_socket.sendto(struct.pack("I", l), client)
                elif opcode == 6:
                    # check address mapped
                    addr = struct.unpack("I", data[4:8])[0]
                    executor = struct.unpack("I", data[8:12])[0]

                    ret = (win_driver if executor == 0 else wibo_driver).read_byte(addr)
                    server_socket.sendto(struct.pack("I", 0 if ret is None else 1), client)
                elif opcode == 7:
                    # dynamic pointer substitution
                    addr = struct.unpack("I", data[4:8])[0]
                    windows_function_name = win_driver.get_function_name(addr)
                    wibo_function_name = windows_function_name.replace("!", "::")
                    if wibo_function_name.endswith("Stub"):
                        wibo_function_name = wibo_function_name.split("Stub")[0]

                    wibo_function_name = wibo_function_name.replace("KERNEL32", "kernel32")

                    out = wibo_driver.run_command(f"info address {wibo_function_name}")
                    if out.strip() == "(gdb)":
                        raise ValueError("Dynamic pointer substitution requested for unimplemented function!")

                    wibo_addr = int(out.splitlines()[0].strip()[:-1].split()[-1], 16)
                    server_socket.sendto(struct.pack("I", wibo_addr), client)
                else:
                    raise ValueError(f"Unknown opcode: {opcode}")

                wibo_driver.continue_execution()

            wibo_driver.run_command(f"b *{return_address:#x}")
            wibo_driver.run_command("c")
            wibo_state = wibo_driver.fetch_state()

            # The stdcall calling convention designates EAX, ECX, and EDX for use
            # inside a callee function.
            # EAX is the return value - we don't want to mess with that.
            # But ECX and EDX could differ due to differences in window's vs wibo's
            # implementation, despite them being semantically identical.
            # As such: copy over ECX and EDX to wibo to prevent false positive
            # discrepencies.
            wibo_state = dataclasses.replace(wibo_state, ecx=win_state.ecx, edx=win_state.edx)

            if syscall_name in ["kernel32::GetSystemTimeAsFileTime"]:
                # The only exception to the above are void functions.
                # There, EAX is a scratch register too.
                wibo_state = dataclasses.replace(wibo_state, eax=win_state.eax)

            wibo_driver.set_state(wibo_state)

            if win_state == wibo_state:
                continue

        # Possibility two: our executable's loaded an address of a kernel32 function.
        # For this to be the case: there can only be a single register different between the two
        field_discrepencies = { i : getattr(win_state, i) != getattr(wibo_state, i) for i in win_driver.EXECUTION_STATE_FIELDS }
        all_kernel32_addresses = True
        
        for (field, is_discrepant) in field_discrepencies.items():
            if not is_discrepant:
                continue

            function_name = wibo_driver.get_function_name(getattr(wibo_state, field))
            if not function_name:
                all_kernel32_addresses = False

        if all_kernel32_addresses:
            continue

        # Possibility three: it's a bonafide difference!
        print ("============== DISCREPANCY DETECTED ==============")
        print ("Register\tWindows\t\t\tWibo")
        for field_name in win_driver.EXECUTION_STATE_FIELDS:
            win_val = getattr(win_state, field_name)
            wibo_val = getattr(wibo_state, field_name)

            cprint (f"{field_name}\t\t{win_val:#010x}\t\t{wibo_val:#010x}", "white" if win_val == wibo_val else "red")

        break

    win_driver.continue_execution()
    wibo_driver.continue_execution()

    check_output_discrepency_present()  

if __name__ == "__main__":
    main()