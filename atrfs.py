#!/usr/bin/env python

import os
import sys
import errno
import struct
import stat
import collections

from fuse import FUSE, FuseOSError, Operations

class atrfs(Operations):
    def __init__(self, root):
        self.root = root
        self.directory_size = 64
        self.handles = {}

        self.atr_file = open(self.root, mode="rb")
        header = self.atr_file.read(7);
        atr_magic, data_size, self.sector_size, hi_data_size = \
            struct.unpack("<HHHB", header)

        disk_bytes = (data_size + (hi_data_size << 16)) * 16
        self.sector_count = (disk_bytes - 3 * 128) / self.sector_size + 3

        print atr_magic, data_size, self.sector_size, self.sector_count

        #TODO how should we report an error?
        if atr_magic != 0x0296:
            return -1

        self.handles = collections.OrderedDict()
        self.handles["\x00"] = 0

    def _full_path(self, partial):
        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path

    def to_unix_notation(self, name):
        prefix = name[0:8].strip()
        extension = name[8:12].strip()

        return prefix + ("." + extension if extension else "")

    def to_dos_notation(self, name):
        parts = name.split('.')

        return parts[0].ljust(8) + (parts[1].ljust(3) if len(parts) > 1 else "   ")

    def read_sector(self, sector_number):
#        print "Reading sector: ", sector_number
        if sector_number == 0 or sector_number > self.sector_count:
            return ""

        self.atr_file.seek(16 + (sector_number - 1) * self.sector_size);
        return bytearray(self.atr_file.read(self.sector_size))

    def sector_chain(self, sector):
        while True:
            data = self.read_sector(sector)
            next_sector, fill = struct.unpack(">HB", data[125:128])
            yield sector, fill, data

            sector = next_sector & (1 << 10) - 1

            if sector == 0:
                return

    def get_actual_size(self, sector):
        file_size = 0

        # TODO: make sure we're not inflooping
        for sector, size, _ in self.sector_chain(sector):
#            print sector, size, 
            file_size += size

        return file_size

    def load_atari_file(self, sector):

        data = bytearray("")
        for sector, size, sector_data in self.sector_chain(sector):
            print "Adding ", size, " bytes to the buffer"
            data.extend(sector_data[0:size])

        return data


    def find_dir_entry(self, path):

        for sector in range(361, 369):
            data = self.read_sector(sector)
            for entry in range(0, 8):
                offset = entry * 16;
                (flag, sectors, start) = struct.unpack("<BHH", data[offset:offset+5])
                name = str(data[offset + 5:offset+16])
                if flag != 0 and not(flag & 0x80) and name == path:
                    #print start
                    return flag, sectors, start

        return 0, 0, 0

    def access(self, path, mode):
        print "Access called:" + path
        full_path = self._full_path(path)
        return 
        #if not os.access(full_path, mode):
        #    raise FuseOSError(errno.EACCES)

    def chmod(self, path, mode):
        full_path = self._full_path(path)
        return os.chmod(full_path, mode)

    def chown(self, path, uid, gid):
        full_path = self._full_path(path)
        return os.chown(full_path, uid, gid)

    def getattr(self, path, fh=None):
        print "getattr called:", path

        if path == "/":
            return {"st_gid": os.getgid(),
                    "st_uid": os.getuid(),
                    "st_size": 1,
                    "st_mode": stat.S_IFDIR | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH,
                    }

        full_path = self._full_path(path)

        if path.startswith("/"):
            path = path[1:]

        (flag, sectors, start) = self.find_dir_entry(self.to_dos_notation(path))

        if start == 0:
            raise FuseOSError(errno.ENOENT)

        return {"st_gid": os.getgid(),
                "st_uid": os.getuid(),
                #"st_size": sectors * self.sector_size,
                "st_size": self.get_actual_size(start),
                "st_ino": 2,
                "st_nlink": 1,
                "st_mode": stat.S_IFREG | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH,
               }

    def readdir(self, path, fh):
        print "readdir called:", path
        full_path = self._full_path(path)

        dirents = ['.', '..']

        for sector in range(361, 369):
            data = self.read_sector(sector)
            for entry in range(0, 8):
                offset = entry * 16;
                flag, sectors, start = struct.unpack("<BHH", data[offset:offset+5])
                name = str(data[offset + 5 : offset + 16])
                if flag != 0 and not(flag & 0x80):
                    #print "direns: ",name
                    dirents.append(self.to_unix_notation(name))

        for r in dirents:
            #print r
            yield r

    def statfs(self, path):
        print "statfs called"
        full_path = self._full_path(path)
        data = self.read_sector(360)
        free_sectors = struct.unpack("<H", data[3:5])[0]

        if self.sector_count >= 1024:
            data = self.read_sector(1024)
            free_sectors += struct.unpack("<H", data[122:124])[0]

        used_entries = 0

        for sector in range(361, 369):
            data = self.read_sector(sector)
            for entry in range(0, 8):
                offset = entry * 16;
                (flag, sectors, start) = struct.unpack("<BHH", data[offset:offset+5])
                name = str(data[offset + 5:offset+16])
                if flag != 0 and not(flag & 0x80):
                    used_entries += 1

        return {"f_bavail": free_sectors,
                "f_bfree": free_sectors,
                'f_blocks': 707 + (304 if self.sector_count >= 1024 else 0),
                'f_bsize': self.sector_size - 3,
                'f_favail': self.directory_size - used_entries,
                'f_ffree': self.directory_size - used_entries,
                'f_files': self.directory_size,
                'f_flag': 0, 
                'f_frsize': self.sector_size,
                'f_namemax': 11
               }

    # File methods
    # ============

    def open(self, path, flags):
        print "file open called:", path, flags
        full_path = self._full_path(path)

        if path.startswith("/"):
            path = path[1:]

        path = self.to_dos_notation(path)

        (flag, sectors, start) = self.find_dir_entry(path)

        #print flag, sectors, start

        if start and not flag & 0x80:
            if path not in self.handles:
                print "Inserting: ", path
                self.handles[path] = self.load_atari_file(start)

        print "Returning handle: ", self.handles.keys().index(path)
        return self.handles.keys().index(path)
        #return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
        full_path = self._full_path(path)
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    def read(self, path, length, offset, fh):
    #    print "file read called: ", path, length, offset, fh
        full_path = self._full_path(path)

        if path.startswith("/"):
            path = path[1:]

        contents = self.handles.values()[fh]

        if offset >= len(contents):
            return bytes("")

        length = min(length, len(contents) - offset)
        #print "contents: ",contents[offset:offset+length]

        return bytes(contents[offset:offset+length])

    def write(self, path, buf, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, buf)

    def truncate(self, path, length, fh=None):
        full_path = self._full_path(path)
        with open(full_path, 'r+') as f:
            f.truncate(length)

    def flush(self, path, fh):
        print "flush called"
        return 0

    def release(self, path, fh):
        print "Release called", fh
        return 0

    def fsync(self, path, fdatasync, fh):
        print "fsync called"
        return self.flush(path, fh)


def main(mountpoint, root):
    FUSE(atrfs(root), mountpoint, nothreads=True, foreground=True)

if __name__ == '__main__':
    main(sys.argv[2], sys.argv[1])
