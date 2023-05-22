from win_driver import WinDriver
from wibo_driver import WiboDriver

COMMAND = ["aspsx.exe", "psyq_test_files/wibo_psyq.s", "-o", "wibo_psyq.obj"]
START_ADDRESS = 0x40d29c

def main() -> None:
    win_driver = WinDriver(COMMAND, START_ADDRESS)
    wibo_driver = WiboDriver(COMMAND, START_ADDRESS, cwd="/home/conor/projects/wibo")
    
if __name__ == "__main__":
    main()