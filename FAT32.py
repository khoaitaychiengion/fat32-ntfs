from enum import Flag, auto
from datetime import datetime
from itertools import chain
import re

BOOT_SECTOR_SIZE = 512


class FAT:
    def __init__(self, data):
        self.raw_data = data
        self.elements = []

    def get_cluster_chain(self, starting_index: int) -> 'list[int]':
        for i in range(0, len(self.raw_data), 4):
            self.elements.append(int.from_bytes(self.raw_data[i:i + 4], 'little'))

        cluster_list = []
        while True:
            cluster_list.append(starting_index)
            starting_index = self.elements[starting_index]
            if starting_index == 0x0FFFFFFF or starting_index == 0x0FFFFFF7:
                return cluster_list


class Attribute(Flag):
    READ_ONLY = auto()
    HIDDEN = auto()
    SYSTEM = auto()
    VOL_LABLE = auto()
    DIRECTORY = auto()
    ARCHIVE = auto()


class RDETentry:
    def __init__(self, data) -> None:
        self.raw_data = data
        self.entry_name = ''
        self.parse_entry()

    def parse_entry(self):
        self.flag = self.raw_data[0xB:0xC]
        # so sanh flag co bang \xof ko roi gan true false vo is_subentry
        # cac dong con lai lam tuong tu
        self.is_subentry = self.flag == b'\x0f'
        self.is_deleted = self.raw_data[0] == 0xe5
        self.is_empty = self.raw_data[0] == 0x00
        self.is_label = Attribute.VOL_LABLE in Attribute(int.from_bytes(self.flag, byteorder='little'))

        if not self.is_subentry:
            self.name = self.raw_data[:0x8]
            self.ext = self.raw_data[0x8:0xB]

            if self.is_deleted or self.is_empty:
                self.name = ""
                return

            self.attr = Attribute(int.from_bytes(self.flag, byteorder='little'))
            if Attribute.VOL_LABLE in self.attr:
                self.is_label = True
                return

            self.set_date_time()
            self.start_cluster, self.size = self.extract_start_cluster_size()
        else:
            self.index = self.raw_data[0]
            self.name = self.extract_long_name()

    def set_date_time(self):
        self.time_created_raw = int.from_bytes(self.raw_data[0xD:0x10], byteorder='little')
        self.date_created_raw = int.from_bytes(self.raw_data[0x10:0x12], byteorder='little')
        self.date_last_accessed_raw = int.from_bytes(self.raw_data[0x12:0x14], byteorder='little')

        self.time_updated_raw = int.from_bytes(self.raw_data[0x16:0x18], byteorder='little')
        self.date_updated_raw = int.from_bytes(self.raw_data[0x18:0x1A], byteorder='little')

        hours = (self.time_created_raw & 0b111110000000000000000000) >> 19
        minutes = (self.time_created_raw & 0b000001111110000000000000) >> 13
        seconds = (self.time_created_raw & 0b000000000001111110000000) >> 7
        ms = (self.time_created_raw & 0b000000000000000001111111)
        year = 1980 + ((self.date_created_raw & 0b1111111000000000) >> 9)
        month = (self.date_created_raw & 0b0000000111100000) >> 5
        day = self.date_created_raw & 0b0000000000011111
        self.date_created = datetime(year, month, day, hours, minutes, seconds, ms)

        year = 1980 + ((self.date_last_accessed_raw & 0b1111111000000000) >> 9)
        mon = (self.date_last_accessed_raw & 0b0000000111100000) >> 5
        day = self.date_last_accessed_raw & 0b0000000000011111
        self.last_accessed = datetime(year, mon, day)

        hours = (self.time_updated_raw & 0b1111100000000000) >> 11
        minutes = (self.time_updated_raw & 0b0000011111100000) >> 5
        seconds = (self.time_updated_raw & 0b0000000000011111) * 2
        year = 1980 + ((self.date_updated_raw & 0b1111111000000000) >> 9)
        month = (self.date_updated_raw & 0b0000000111100000) >> 5
        day = self.date_updated_raw & 0b0000000000011111
        self.date_updated = datetime(year, month, day, hours, minutes, seconds)

    def extract_start_cluster_size(self):
        start_cluster_bytes = self.raw_data[0x14:0x16][::-1] + self.raw_data[0x1A:0x1C][::-1]
        start_cluster = int.from_bytes(start_cluster_bytes, byteorder='big')
        size = int.from_bytes(self.raw_data[0x1C:0x20], byteorder='little')
        return start_cluster, size

    def extract_long_name(self):
        name = b""
        for i in chain(range(0x1, 0xB), range(0xE, 0x1A), range(0x1C, 0x20)):
            name += int.to_bytes(self.raw_data[i], 1, byteorder='little')
            if name.endswith(b"\xff\xff"):
                name = name[:-2]
                break
        return name.decode('utf-16le').strip('\x00')

    def is_active_entry(self) -> bool:
        return not (
                    self.is_empty or self.is_subentry or self.is_deleted or self.is_label or Attribute.SYSTEM in self.attr)

    def is_directory(self) -> bool:
        return Attribute.DIRECTORY in self.attr

    def is_archive(self) -> bool:
        return Attribute.ARCHIVE in self.attr


class RDET:
    def __init__(self, data: bytes) -> None:
        self.raw_data = data
        self.entries: list[RDETentry] = []
        self.entries = self.get_full_entry_name()

    def get_full_entry_name(self) -> list[RDETentry]:
        entry_name = ''
        entries: list[RDETentry] = []

        for i in range(0, len(self.raw_data), 32):
            entries.append(RDETentry(self.raw_data[i: i + 32]))
            if entries[-1].is_empty or entries[-1].is_deleted:
                entry_name = ''
                continue
            elif entries[-1].is_subentry:
                entry_name = entries[-1].name + entry_name
                continue

            if entry_name != '':
                entries[-1].entry_name = entry_name
            else:
                extension = entries[-1].ext.strip().decode()
                if extension != '':
                    entries[-1].entry_name = entries[-1].name.strip().decode() + '.' + extension
                else:
                    entries[-1].entry_name = entries[-1].name.strip().decode()
            entry_name = ''
        return entries

    def get_active_entries(self) -> 'list[RDETentry]':
        entry_list = []
        for i in range(len(self.entries)):
            if self.entries[i].is_active_entry():
                entry_list.append(self.entries[i])
        return entry_list

    def find_entry(self, name) -> RDETentry:
        for i in range(len(self.entries)):
            if self.entries[i].is_active_entry() and self.entries[i].entry_name.lower() == name.lower():
                return self.entries[i]
        return None


class Fat32_Main:
    def __init__(self, volume_name) -> None:
        self.volume_name = volume_name
        self.cwd = [self.volume_name]

        try:
            self.bin_raw_data = open(rf"\\.\{self.volume_name}", 'rb')
            self.boot_sector = {}

            self.boot_sector_data = self.bin_raw_data.read(BOOT_SECTOR_SIZE)
            self.extract_boot_sector()
            if self.boot_sector['FAT Name'] != b'FAT32   ':
                raise Exception('NOT FAT32')

            # Important Info
            self.boot_sector['FAT Name'] = self.boot_sector['FAT Name'].decode()
            self.bytes_per_sector = self.boot_sector['Bytes Per Sector']
            self.sectors_per_cluster = self.boot_sector['Sectors Per Cluster']
            self.sectors_in_boot_sectors = self.boot_sector['Reserved Sectors']
            self.numbers_of_fats = self.boot_sector["Number of FATs"]
            self.sectors_in_volumes = self.boot_sector['Sectors In Volume']
            self.sectors_per_fats = self.boot_sector['Sectors Per FAT']
            self.starting_cluster_of_rdet = self.boot_sector['Starting Cluster of RDET']
            self.starting_sector_of_data = self.boot_sector['Starting Sector of Data']

            # Read FAT's info
            # Move cursor in file to the 1st FAT
            self.temp = self.bin_raw_data.read(self.bytes_per_sector * (self.sectors_in_boot_sectors - 1))
            FAT_size = self.bytes_per_sector * self.sectors_per_fats

            self.list_FAT: list[FAT] = []
            for _ in range(self.numbers_of_fats):
                self.list_FAT.append(FAT(self.bin_raw_data.read(FAT_size)))

            # Handle RDET
            starting_cluster_index = self.boot_sector["Starting Cluster of RDET"]
            self.RDET = RDET(self.get_all_cluster_data(starting_cluster_index))
            self.DET = {}
            self.DET[starting_cluster_index] = self.RDET

        except Exception as error:
            print(f"Error: {error}")
            exit()

    def __str__(self) -> str:
        result = "---VOLUME INFORMATION---\n"
        result += "Volume name: " + self.volume_name + '\n'
        items = self.boot_sector.items()

        for i in items:
            result += str(i[0]) + ': ' + str(i[1]) + '\n'
        return result

    def __del__(self):
        if getattr(self, "bin_raw_data", None):
            print("Closing Volume...")
            self.bin_raw_data.close()

    def extract_boot_sector(self):
        self.boot_sector['Bytes Per Sector'] = int.from_bytes(self.boot_sector_data[0xB:0xD], 'little')
        self.boot_sector['Sectors Per Cluster'] = int.from_bytes(self.boot_sector_data[0xD:0xE], 'little')
        self.boot_sector['Reserved Sectors'] = int.from_bytes(self.boot_sector_data[0xE:0x10], 'little')
        self.boot_sector['Number of FATs'] = int.from_bytes(self.boot_sector_data[0x10:0x11], 'little')
        self.boot_sector['Sectors In Volume'] = int.from_bytes(self.boot_sector_data[0x20:0x24], 'little')
        self.boot_sector['Sectors Per FAT'] = int.from_bytes(self.boot_sector_data[0x24:0x28], 'little')
        self.boot_sector['Starting Cluster of RDET'] = int.from_bytes(self.boot_sector_data[0x2C:0x30], 'little')
        self.boot_sector['FAT Name'] = self.boot_sector_data[0x52:0x5A]
        self.boot_sector['Starting Sector of Data'] = self.boot_sector['Reserved Sectors'] + self.boot_sector[
            'Number of FATs'] * self.boot_sector['Sectors Per FAT']

    def convert_cluster_to_sector_index(self, index):
        return self.sectors_in_boot_sectors + self.sectors_per_fats * self.numbers_of_fats + (
                    index - 2) * self.sectors_per_cluster

    def get_all_cluster_data(self, cluster_index):
        cluster_list = self.list_FAT[0].get_cluster_chain(cluster_index)
        data = b""

        for i in cluster_list:
            sector_index = self.convert_cluster_to_sector_index(i)
            self.bin_raw_data.seek(sector_index * self.bytes_per_sector)
            data += self.bin_raw_data.read(self.bytes_per_sector * self.sectors_per_cluster)
        return data

    @staticmethod
    def isFAT32(volume_name):
        try:
            boot_sector = open(rf'\\.\{volume_name}', 'rb')
            boot_sector.read(1)  # Ensure file pointer correctly point to boot sector
            boot_sector.seek(0x52)
            fat_type = boot_sector.read(8)

            if fat_type == b'FAT32   ':
                return True
            return False
        except Exception as error:
            print(f'Error: {error}')
            exit()

    def parsePath(self, path):
        dirs = re.sub(r"[/\\]+", r"\\", path).strip("\\").split("\\")
        return dirs

    def visitDirectory(self, path) -> RDET:
        if path == "":
            raise Exception("Require a directory!")
        path = self.parsePath(path)

        if path[0] == self.volume_name:
            cdet = self.DET[self.boot_sector["Starting Cluster of RDET"]]
            path.pop(0)
        else:
            cdet = self.RDET

        for dir in path:
            entry = cdet.find_entry(dir)
            if entry is None:
                raise Exception("Directory not found!")

            if entry.is_directory():
                if entry.start_cluster == 0:
                    cdet = self.DET[self.boot_sector["Starting Cluster of RDET"]]
                    continue
                if entry.start_cluster in self.DET:
                    cdet = self.DET[entry.start_cluster]
                    continue
                self.DET[entry.start_cluster] = RDET(self.get_all_cluster_data(entry.start_cluster))
                cdet = self.DET[entry.start_cluster]
            else:
                raise Exception("Not a directory")
        return cdet

    def getCWD(self):
        if len(self.cwd) == 1:
            return self.cwd[0] + "\\"
        return "\\".join(self.cwd)

    def getDirectory(self, path=""):
        try:
            if path != "":
                cdet = self.visitDirectory(path)
                print(cdet)
                entry_list = cdet.get_active_entries()
            else:
                entry_list = self.RDET.get_active_entries()

            ret = []
            for entry in entry_list:
                obj = {}
                obj["Flags"] = entry.attr.value
                obj["Date Modified"] = entry.date_updated
                obj["Size"] = entry.size
                obj["Name"] = entry.entry_name

                if entry.start_cluster == 0:
                    obj["Sector"] = (entry.start_cluster + 2) * self.sectors_per_cluster
                else:
                    obj["Sector"] = entry.start_cluster * self.sectors_per_cluster
                ret.append(obj)
            return ret
        except Exception as error:
            raise (error)

    def changeDirectory(self, path=""):
        if path == "":
            raise Exception("Path to directory is required!")

        try:
            cdet = self.visitDirectory(path)
            self.RDET = cdet

            dirs = self.parsePath(path)
            if dirs[0] == self.volume_name:
                self.cwd.clear()
                self.cwd.append(self.volume_name)
                dirs.pop(0)

            for d in dirs:
                if d == "..":
                    self.cwd.pop()
                elif d != ".":
                    self.cwd.append(d)
        except Exception as e:
            raise e

    def getText(self, path: str) -> str:
        path_parts = self.parsePath(path)

        if len(path_parts) > 1:
            volume_name = path_parts[-1]
            dir_path = "\\".join(path_parts[:-1])
            cdet = self.visitDirectory(dir_path)
            entry = cdet.find_entry(volume_name)
        else:
            entry = self.RDET.find_entry(path_parts[0])

        if entry is None:
            raise Exception("File doesn't exist")
        if entry.is_directory():
            raise Exception("Is a directory")

        index_list = self.list_FAT[0].get_cluster_chain(entry.start_cluster)
        data = ""
        size_left = entry.size

        for i in index_list:
            if size_left <= 0:
                break

            off = self.convert_cluster_to_sector_index(i)
            self.bin_raw_data.seek(off * self.bytes_per_sector)
            raw_data = self.bin_raw_data.read(min(self.sectors_per_cluster * self.bytes_per_sector, size_left))
            size_left -= self.sectors_per_cluster * self.bytes_per_sector

            try:
                data += raw_data.decode()
            except UnicodeDecodeError as e:
                raise Exception("Not a text file, please use appropriate software to open.")
            except Exception as e:
                raise e
        return data
