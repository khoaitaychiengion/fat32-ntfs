import re
from enum import Flag, auto
from datetime import datetime


class Attribute(Flag):
    READ_ONLY = auto()
    HIDDEN = auto()
    SYSTEM = auto()
    VOLLABLE = auto()
    DIRECTORY = auto()
    ARCHIVE = auto()


def getDatetime(timestamp):
    return datetime.fromtimestamp((timestamp - 116444736000000000) // 10000000)


class MFTRecord:
    def __init__(self, data) -> None:
        self.raw = data
        self.fileID = int.from_bytes(self.raw[0x2C:0x30], byteorder='little')
        self.flag = self.raw[0x16]

        if self.flag == 0 or self.flag == 2:
            # Deleted record
            raise Exception("Skip this record")

        infoStart = int.from_bytes(self.raw[0x14:0x16], byteorder='little')
        infoSize = int.from_bytes(self.raw[infoStart + 4:infoStart + 8], byteorder='little')

        self.info = {}
        self.parseInfo(infoStart)
        fileNameStart = infoStart + infoSize
        fileNameSize = int.from_bytes(self.raw[fileNameStart + 4:fileNameStart + 8], byteorder='little')

        self.fileName = {}
        self.parseFileName(fileNameStart)
        dataStart = fileNameStart + fileNameSize
        dataSignature = self.raw[dataStart:dataStart + 4]

        if dataSignature[0] == 64:
            dataStart += int.from_bytes(self.raw[dataStart + 4:dataStart + 8], byteorder='little')
        dataSignature = self.raw[dataStart:dataStart + 4]

        self.data = {}
        if dataSignature[0] == 128:
            self.parseData(dataStart)

        elif dataSignature[0] == 144:
            self.info['flags'] |= Attribute.DIRECTORY
            self.data['size'] = 0
            self.data['residence'] = True
        self.childs: list[MFTRecord] = []
        del self.raw

    def isDirectory(self):
        return Attribute.DIRECTORY in self.info['flags']

    def isLeaf(self):
        return not len(self.childs)

    def isActive(self):
        flags = self.info['flags']
        if Attribute.SYSTEM in flags or Attribute.HIDDEN in flags:
            return False
        return True

    def findRecord(self, name: str):
        for record in self.childs:
            if record.fileName['longName'] == name:
                return record
        return None

    def getRecords(self) -> 'list[MFTRecord]':
        recordList: list[MFTRecord] = []
        for record in self.childs:
            if record.isActive():
                recordList.append(record)
        return recordList

    def parseData(self, start):
        self.data['residence'] = not bool(self.raw[start + 0x8])
        if self.data['residence']:
            offset = int.from_bytes(self.raw[start + 0x14:start + 0x16], byteorder='little')
            self.data['size'] = int.from_bytes(self.raw[start + 0x10:start + 0x14], byteorder='little')
            self.data['content'] = self.raw[start + offset:start + offset + self.data['size']]
        else:
            clusterChain = self.raw[start + 0x40]
            offset = (clusterChain & 0xF0) >> 4
            size = clusterChain & 0x0F
            self.data['size'] = int.from_bytes(self.raw[start + 0x30: start + 0x38], byteorder='little')
            self.data['clusterSize'] = int.from_bytes(self.raw[start + 0x41: start + 0x41 + size], byteorder='little')
            self.data['clusterOffset'] = int.from_bytes(self.raw[start + 0x41 + size: start + 0x41 + size + offset], byteorder='little')

    def parseFileName(self, start):
        signature = int.from_bytes(self.raw[start:start + 4], byteorder='little')
        if signature != 0x30:
            raise Exception("Skip this record")

        # header = self.raw_data[start:start + 0x10]
        size = int.from_bytes(self.raw[start + 0x10:start + 0x14], byteorder='little')
        offset = int.from_bytes(self.raw[start + 0x14: start + 0x16], byteorder='little')
        body = self.raw[start + offset: start + offset + size]

        self.fileName["parentID"] = int.from_bytes(body[:6], byteorder='little')
        nameLength = body[64]
        self.fileName["longName"] = body[66:66 + nameLength * 2].decode('utf-16le')  # unicode

    def parseInfo(self, start):
        sig = int.from_bytes(self.raw[start:start + 4], byteorder='little')
        if sig != 0x10:
            raise Exception("Something Wrong!")

        offset = int.from_bytes(self.raw[start + 20:start + 21], byteorder='little')
        begin = start + offset

        self.info["createdTime"] = getDatetime(int.from_bytes(self.raw[begin:begin + 8], byteorder='little'))
        self.info["lastModified"] = getDatetime(int.from_bytes(self.raw[begin + 8:begin + 16], byteorder='little'))
        self.info["flags"] = Attribute(int.from_bytes(self.raw[begin + 32:begin + 36], byteorder='little') & 0xFFFF)


class DirectoryTree:
    def __init__(self, nodes: 'list[MFTRecord]') -> None:
        self.root = None
        self.nodeDict: dict[int, MFTRecord] = {}
        for node in nodes:
            self.nodeDict[node.fileID] = node

        for key in self.nodeDict:
            parentID = self.nodeDict[key].fileName['parentID']
            if parentID in self.nodeDict:
                self.nodeDict[parentID].childs.append(self.nodeDict[key])

        for key in self.nodeDict:
            parent_id = self.nodeDict[key].fileName['parentID']
            if parent_id == self.nodeDict[key].fileID:
                self.root = self.nodeDict[key]
                break
        self.currentDir = self.root

    def findRecord(self, name: str):
        return self.currentDir.findRecord(name)

    def getParentRecord(self, record: MFTRecord):
        return self.nodeDict[record.fileName['parentID']]

    def getActiveRecords(self) -> 'list[MFTRecord]':
        return self.currentDir.getRecords()


class MFTFile:
    def __init__(self, data: bytes) -> None:
        self.raw = data
        self.infoOffset = int.from_bytes(self.raw[0x14:0x16], byteorder='little')
        self.infoLen = int.from_bytes(self.raw[0x3C:0x40], byteorder='little')
        self.fileNameOffset = self.infoOffset + self.infoLen
        self.fileNameLen = int.from_bytes(self.raw[0x9C:0xA0], byteorder='little')
        self.dataOffset = self.fileNameOffset + self.fileNameLen
        self.dataLen = int.from_bytes(self.raw[0x104:0x108], byteorder='little')
        self.numSector = (int.from_bytes(self.raw[0x118:0x120], byteorder='little') + 1) * 8
        del self.raw


class NTFS:
    importantInfo = [
        "OEM ID",
        "Serial Number",
        "Bytes Per Sector",
        "Sectors Per Cluster",
        "Reserved Sectors",
        "No. Sectors In Volume",
        "First Cluster of $MFT",
        "First Cluster of $MFTMirr",
        "MFT record size"
    ]

    def __init__(self, name: str) -> None:
        self.name = name
        self.cwd = [self.name]
        try:
            self.fd = open(r'\\.\%s' % self.name, 'rb')
        except FileNotFoundError:
            print(f"[ERROR] No volume named {name}")
            exit()
        except PermissionError:
            print("[ERROR] Permission denied, try again as admin/root")
            exit()
        except Exception as e:
            print(e)
            print("[ERROR] Unknown error occurred")
            exit()

        try:
            self.bootSectorRaw = self.fd.read(0x200)
            self.bootSector = {}
            self.extractBootSector()

            if self.bootSector["OEM ID"] != b'NTFS    ':
                raise Exception("Not NTFS")
            self.bootSector["OEM ID"] = self.bootSector["OEM ID"].decode()
            self.bootSector['Serial Number'] = hex(self.bootSector['Serial Number'] & 0xFFFFFFFF)[2:].upper()
            self.bootSector['Serial Number'] = self.bootSector['Serial Number'][:4] + "-" + self.bootSector['Serial Number'][4:]
            self.spc = self.bootSector["Sectors Per Cluster"]
            self.bps = self.bootSector["Bytes Per Sector"]

            self.recordSize = self.bootSector["MFT record size"]
            self.mftOffset = self.bootSector['First Cluster of $MFT']
            self.fd.seek(self.mftOffset * self.spc * self.bps)
            self.mftFile = MFTFile(self.fd.read(self.recordSize))

            mftRecord: list[MFTRecord] = []
            for _ in range(2, self.mftFile.numSector, 2):
                dat = self.fd.read(self.recordSize)
                if dat[:4] == b"FILE":
                    try:
                        mftRecord.append(MFTRecord(dat))
                    except Exception as e:
                        pass
            self.dirTree = DirectoryTree(mftRecord)
        except Exception as e:
            print(f"[ERROR] {e}")
            exit()

    @staticmethod
    def isNTFS(name: str):
        try:
            with open(r'\\.\%s' % name, 'rb') as fd:
                oem_id = fd.read(0xB)[3:]
                if oem_id == b'NTFS    ':
                    return True
                return False
        except Exception as e:
            print(f"[ERROR] {e}")
            exit()

    def extractBootSector(self):
        self.bootSector['OEM ID'] = self.bootSectorRaw[3:0xB]
        self.bootSector['Bytes Per Sector'] = int.from_bytes(self.bootSectorRaw[0xB:0xD], byteorder='little')
        self.bootSector['Sectors Per Cluster'] = int.from_bytes(self.bootSectorRaw[0xD:0xE], byteorder='little')
        self.bootSector['Reserved Sectors'] = int.from_bytes(self.bootSectorRaw[0xE:0x10], byteorder='little')
        self.bootSector['No. Sectors In Volume'] = int.from_bytes(self.bootSectorRaw[0x28:0x30], byteorder='little')
        self.bootSector['First Cluster of $MFT'] = int.from_bytes(self.bootSectorRaw[0x30:0x38], byteorder='little')
        self.bootSector['First Cluster of $MFTMirr'] = int.from_bytes(self.bootSectorRaw[0x38:0x40], byteorder='little')
        self.bootSector['Clusters Per File Record Segment'] = int.from_bytes(self.bootSectorRaw[0x40:0x41], byteorder='little', signed=True)
        self.bootSector['MFT record size'] = 2 ** abs(self.bootSector['Clusters Per File Record Segment'])
        self.bootSector['Serial Number'] = int.from_bytes(self.bootSectorRaw[0x48:0x50], byteorder='little')
        self.bootSector['Signature'] = self.bootSectorRaw[0x1FE:0x200]

    def parsePath(self, path):
        directory = re.sub(r"[/\\]+", r"\\", path).strip("\\").split("\\")
        return directory

    def visitDir(self, path) -> MFTRecord:
        if path == "":
            raise Exception("Directory name is required!")

        path = self.parsePath(path)
        if path[0] == self.name:
            curDir = self.dirTree.root
            path.pop(0)
        else:
            curDir = self.dirTree.currentDir

        for dir in path:
            if dir == "..":
                curDir = self.dirTree.getParentRecord(curDir)
                continue
            elif dir == ".":
                continue
            record = curDir.findRecord(dir)

            if record is None:
                raise Exception("Directory not found!")
            if record.isDirectory():
                curDir = record
            else:
                raise Exception("Not a directory")
        return curDir

    def getDirectory(self, path=""):
        try:
            if path != "":
                nextDir = self.visitDir(path)
                recordList = nextDir.getRecords()
            else:
                recordList = self.dirTree.getActiveRecords()

            ret = []
            for record in recordList:
                obj = {}
                obj["Flags"] = record.info["flags"].value
                obj["Date Modified"] = record.info["lastModified"]
                obj["Size"] = record.data["size"]
                obj["Name"] = record.fileName["longName"]

                if record.data["residence"]:
                    obj["Sector"] = self.mftOffset * self.spc + record.fileID
                else:
                    obj["Sector"] = record.data["clusterOffset"] * self.spc
                ret.append(obj)
            return ret
        except Exception as e:
            raise (e)

    def changeDirectory(self, path=""):
        if path == "":
            raise Exception("Path to directory is required!")

        try:
            nextDir = self.visitDir(path)
            self.dirTree.currentDir = nextDir

            directories = self.parsePath(path)
            if directories[0] == self.name:
                self.cwd.clear()
                self.cwd.append(self.name)
                directories.pop(0)

            for dir in directories:
                if dir == "..":
                    if len(self.cwd) > 1: self.cwd.pop()
                elif dir != ".":
                    self.cwd.append(dir)
        except Exception as e:
            raise (e)

    def getCWD(self):
        if len(self.cwd) == 1:
            return self.cwd[0] + "\\"
        return "\\".join(self.cwd)

    def getText(self, path: str) -> str:
        path = self.parsePath(path)
        if len(path) > 1:
            name = path[-1]
            path = "\\".join(path[:-1])
            nextDir = self.visitDir(path)
            record = nextDir.findRecord(name)
        else:
            record = self.dirTree.findRecord(path[0])

        if record is None:
            raise Exception("File doesn't exist")
        if record.isDirectory():
            raise Exception("Is a directory")
        if 'residence' not in record.data:
            return ''

        if record.data['residence']:
            try:
                data = record.data['content'].decode()
            except UnicodeDecodeError as e:
                raise Exception(
                    "Not a text file, please use appropriate software to open.")
            except Exception as e:
                raise (e)
            return data

        else:
            data = ""
            sizeLeft = record.data['size']
            offset = record.data['clusterOffset'] * self.spc * self.bps
            clusterNum = record.data['clusterSize']
            self.fd.seek(offset)

            for _ in range(clusterNum):
                if sizeLeft <= 0:
                    break
                raw_data = self.fd.read(min(self.spc * self.bps, sizeLeft))
                sizeLeft -= self.spc * self.bps

                try:
                    data += raw_data.decode()
                except UnicodeDecodeError as e:
                    raise Exception("Not a text file, please use appropriate software to open.")
                except Exception as e:
                    raise (e)
            return data

    def __str__(self) -> str:
        s = "---VOLUME INFORMATION---\n"
        s += "Volume name: " + self.name + '\n'
        for key in NTFS.importantInfo:
            s += f"{key}: {self.bootSector[key]}\n"
        return s

    def __del__(self):
        if getattr(self, "fd", None):
            print("Closing Volume...")
            self.fd.close()
