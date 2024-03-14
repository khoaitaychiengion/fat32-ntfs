import cmd
from typing import Union
from FAT32 import Fat32_Main
from NTFS import NTFS


class UI(cmd.Cmd):
    intro = ("COMMANDS LIST.\n"
             "1. Type 'info' to print information of volume.\n"
             "2. Type 'tree' to print root directory tree.\n"
             "3. Type 'data + filename' to retrieve file content.\n"
             "     - First, you have to be into the directory that contains this file.\n"
             "4. Type 'cd + directory' to change the current directory.\n"
             "5. Type 'exit' to quit the program.\n")

    def __init__(self, volume: Union[Fat32_Main, NTFS]) -> None:
        super(UI, self).__init__()
        self.vol = volume
        self.updateDirectory()

    def updateDirectory(self):
        UI.prompt = f'┌──[{self.vol.getCWD()}]\n└──$ '

    def do_cd(self, arg):
        try:
            self.vol.changeDirectory(arg)
            self.updateDirectory()
        except Exception as e:
            print(f"[ERROR] {e}")

    def do_tree(self, arg):
        def printTree(entry, prefix="", last=False):
            print(f'{prefix + ("└── " if last else "├── ") + entry["Name"]:<40}', end=' ')

            # print status of file/folder
            entryStatus = entry["Name"][:1]
            if entryStatus == b'\xe5':
                print(f'{"| Deleted":<30}', end="  ")
            elif entryStatus == b'\x00':
                print(f'{"| Empty":<30}', end="  ")
            elif entryStatus == b'\x05':
                print(f'{"| Initial character is 0xE5":<30}', end="  ")
            else:
                print(f'{"| DOT Entry":<30}', end="  ")

            # print size of file/folder
            print("| Size: " + str(entry["Size"]))

            # check if is archive
            if entry["Flags"] & 0b100000:
                return

            self.vol.changeDirectory(entry["Name"])
            entries = self.vol.getDirectory()
            numberOfEntry = len(entries)

            for i in range(numberOfEntry):
                if entries[i]["Name"] in (".", ".."):
                    continue
                prefixChar = "    " if last else "│   "
                printTree(entries[i], prefix + prefixChar, i == numberOfEntry - 1)

            self.vol.changeDirectory("..")

        cwd = self.vol.getCWD()
        try:
            print(cwd)
            entries = self.vol.getDirectory()
            numberOfEntry = len(entries)

            for i in range(numberOfEntry):
                if entries[i]["Name"] in (".", ".."):
                    continue
                printTree(entries[i], "", i == numberOfEntry - 1)

        except Exception as e:
            print(f"[ERROR] {e}")
        finally:
            self.vol.changeDirectory(cwd)

    def do_data(self, arg):
        if arg == "":
            print(f"[ERROR] Please provide a path")
            return
        try:
            print(self.vol.getText(arg))

        except Exception as e:
            print(f"[ERROR] {e}")

    def do_info(self, arg):
        print(self.vol)

    def do_exit(self, arg):
        print('Exit the program...')
        self.close()
        return True

    def close(self):
        if self.vol:
            del self.vol
            self.vol = None
