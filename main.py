from termcolor import cprint

import dataclasses
import socket
import struct

from win_driver import WinDriver
from wibo_driver import WiboDriver

COMMAND = ["armcc/5.04/b82/armcc.exe", "armcc/test.c"]
START_ADDRESS = 0x0c8df39

def setup_output_discrepency_check() -> None:
    return

def check_output_discrepency_present() -> None:
    return

def send_on_wibo_socket(data: bytes) -> None:
    wibo_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
    wibo_socket.sendto(data, ("172.25.101.16", 8088))

def main() -> None:
    setup_output_discrepency_check()
    
    win_driver = WinDriver(COMMAND, START_ADDRESS)
    
    ebx_val = win_driver.fetch_state().ebx
    wibo_driver = WiboDriver(COMMAND, START_ADDRESS, cwd="/home/conor/projects/wibo", env={"WIBO_EBX_OVERRIDE": str(ebx_val)})

    while True:
        win_state = win_driver.step()
        wibo_state = wibo_driver.step()

        print (f"{win_state.eip:#10x}")

        if win_state == wibo_state:
            continue

        # If we're here, there's a discrepancy of some sort.
        
        # Possibility one: we're about to make a kernel call,
        # and eip is different as we've begun executing code
        # from some system dll (or wibo's implementation thereof)
        if win_state == dataclasses.replace(wibo_state, eip=win_state.eip):
            syscall_name = wibo_driver.get_current_function_name()
            cprint (f"SYSTEM CALL DETECTED: {syscall_name}", "red")
            cprint (f"({win_state.eip:#x} vs {wibo_state.eip:#x})", "yellow")

            if syscall_name in ["kernel32::GetCurrentProcessId()", "kernel32::GetTickCount()"]:
                # For whatever reason, stepping out of these syscalls is broken.
                # Not sure why!
                ret = win_driver.read_word(win_state.esp)

                win_driver.run_command(f"bu {ret:#x}")
                win_driver.run_command("g")
                win_state = win_driver.fetch_state()
            else:
                win_state = win_driver.step_out()
            
            UNSIGNED_INT_SYSCALLS = [
                "kernel32::GetCurrentThreadId()",
                "kernel32::GetStdHandle(unsigned",
                "kernel32::VirtualAlloc(void*,",
                "kernel32::CreateFileA(char",
                "kernel32::SetFilePointer(void*,",
                "kernel32::GetCurrentProcessId()",
                "kernel32::HeapCreate(unsigned",
                "kernel32::GetModuleHandleW(unsigned"
            ]

            if syscall_name in UNSIGNED_INT_SYSCALLS:
                send_on_wibo_socket(struct.pack("I", win_state.eax)) # unsigned int

            if syscall_name in ["kernel32::GetTickCount()"]:
                send_on_wibo_socket(struct.pack("i", win_state.eax)) # int

            if syscall_name in ["kernel32::GetFileType(void*)"]:
                send_on_wibo_socket(struct.pack("H", win_state.eax)) # unsigned short

            if syscall_name == "kernel32::GetEnvironmentStrings()":
                # Grab the environment string
                # Windows makes things complicated.
                # We can only read a single null-terminated string at a time
                # but the environment variables are a list of null terminated strings
                # that we don't know the length of
                pointer = win_state.eax
                environment_variables = []

                while True:
                    environment_variable = win_driver.read_string_at_address(pointer)

                    if len(environment_variable) == 0:
                        break
                    
                    pointer += len(environment_variable) + 1
                    environment_variables.append(environment_variable)

                env_string = b"\x00".join([i.encode() for i in environment_variables]) + b"\x00\x00"

                send_on_wibo_socket(struct.pack("I", win_state.eax))
                send_on_wibo_socket(struct.pack("I", len(env_string)))
                send_on_wibo_socket(env_string)
                
            if syscall_name == "kernel32::GetModuleFileNameA(void*,":
                module_file_name = win_driver.read_string_at_address(win_state.esp + 0)
                send_on_wibo_socket(struct.pack("I", len(module_file_name) + 1))
                send_on_wibo_socket(module_file_name.encode() + b"\x00")

            if syscall_name == "kernel32::GetCommandLineA()":
                command_line = win_driver.read_string_at_address(win_state.eax)
                send_on_wibo_socket(struct.pack("I", win_state.eax))
                send_on_wibo_socket(struct.pack("I", len(command_line) + 1))
                send_on_wibo_socket(command_line.encode() + b"\x00")

            if syscall_name == "kernel32::GetCurrentDirectoryA(unsigned":
                current_directory = win_driver.read_string_at_address(win_state.esp + 0)
                send_on_wibo_socket(struct.pack("I", len(current_directory) + 1))
                send_on_wibo_socket(current_directory.encode() + b"\x00")

            if syscall_name == "kernel32::ReadFile(void*,":
                # TODO: this is blatantly tailered towards one file in particular
                # It breaks on whitespace.
                # It breaks on unicode.
                # Everything about this is bad.
                print ("YOU SHOULD FIX READFILE")
                import sys; sys.exit(1)

                file_contents = win_driver.read_string_at_address(win_driver.read_word(win_state.esp + 0x14))
                if len(file_contents.strip()) == 0:
                    send_on_wibo_socket(struct.pack("I", 0))
                else:    
                    file_contents = "\t" + file_contents + "\r\n"
                    send_on_wibo_socket(struct.pack("I", len(file_contents)))
                    send_on_wibo_socket(file_contents.encode())

            if syscall_name == "kernel32::GetSystemTimeAsFileTime(kernel32::FILETIME*)":
                filetime_low = win_driver.read_word(win_state.ecx)
                filetime_high = win_driver.read_word(win_state.ecx + 4)
                filetime = filetime_low + (filetime_high << 32)
                send_on_wibo_socket(struct.pack("Q", filetime))

                # Void function - EAX is a scratch register.
                # Copy it over.
                wibo_state = dataclasses.replace(wibo_state, eax=win_state.eax)
                wibo_driver.set_state(wibo_state)

            if syscall_name == "kernel32::QueryPerformanceCounter(unsigned":
                # TODO: reading from ECX like this is brittle - a windows update
                # could change where this value appears.
                # We should grab this *before* executing QueryPerformanceCounter
                filetime_low = win_driver.read_word(win_state.ecx)
                filetime_high = win_driver.read_word(win_state.ecx + 4)
                filetime = filetime_low + (filetime_high << 32)
                send_on_wibo_socket(struct.pack("Q", filetime))

                send_on_wibo_socket(struct.pack("I", win_state.eax)) # unsigned int

            """if syscall_name == "kernel32::GetModuleHandleW(unsigned":
                module_name_ptr = win_driver.read_word(win_state.esp - 0x4)
                module_name = b""

                while (read_half_word := win_driver.read_half_word(module_name_ptr)) != 0:
                    module_name += struct.pack("H", read_half_word)
                    module_name_ptr += 2

                module_name += b"\x00\x00" # terminating null byte

                send_on_wibo_socket(struct.pack("I", len(module_name)))
                send_on_wibo_socket(module_name)"""
            



            wibo_state = wibo_driver.step_out()
            
            # The stdcall calling convention designates EAX, ECX, and EDX for use
            # inside a callee function.
            # EAX is the return value - we don't want to mess with that.
            # But ECX and EDX could differ due to differences in window's vs wibo's
            # implementation, despite them being semantically identical.
            # As such: copy over ECX and EDX to wibo to prevent false positive
            # discrepencies.
            wibo_state = dataclasses.replace(wibo_state, ecx=win_state.ecx, edx=win_state.edx)

            if syscall_name in ["kernel32::GetSystemTimeAsFileTime(kernel32::FILETIME*)"]:
                # The only exception to the above are void functions.
                # There, EAX is a scratch register too.
                wibo_state = dataclasses.replace(wibo_state, eax=win_state.eax)

            wibo_driver.set_state(wibo_state)

            if win_state == wibo_state:
                continue

        # Possibility two: it's a bonafide difference!
        print ("============== DISCREPANCY DETECTED ==============")
        print ("Register\tWindows\t\t\tWibo")
        for field_name in win_driver.EXECUTION_STATE_FIELDS:
            win_val = getattr(win_state, field_name)
            wibo_val = getattr(wibo_state, field_name)

            cprint (f"{field_name}\t\t{win_val:#010x}\t\t{wibo_val:#010x}", "white" if win_val == wibo_val else "red")

        break

    win_driver.run_to_completion()
    wibo_driver.run_to_completion()

    check_output_discrepency_present()  

if __name__ == "__main__":
    main()