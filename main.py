from FAT32 import Fat32_Main
from UI import UI
from NTFS import NTFS
import os


if __name__ == "__main__":
    os.system("cls")
    volumes = [chr(x) + ":" for x in range(65, 91) if os.path.exists(chr(x) + ":")]
    print("Available volumes in your computer:")
    for i in range(len(volumes)):
        print(f"{i + 1}.", volumes[i])
    try:
        volumeChoice = int(input("Which volume you want to use: "))
    except Exception as e:
        print(f"[ERROR] {e}")
        exit()

    if not 1 <= volumeChoice <= len(volumes):
        print("[ERROR] Invalid choice!")
        exit()

    volume_name = volumes[volumeChoice - 1]
    if Fat32_Main.isFAT32(volume_name):
        vol = Fat32_Main(volume_name)
    elif NTFS.isNTFS(volume_name):
        vol = NTFS(volume_name)
    else:
        print("[ERROR] This volume type is unsupported")
        exit()

    os.system("cls")
    ui = UI(vol)
    ui.cmdloop()
