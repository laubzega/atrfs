#!/usr/bin/env python

import collections
import errno
import os
import re
import sys
import struct
import stat
import threading

from fuse import FUSE, FuseOSError, Operations
from functools import partial
from pprint import pprint

class DirEntry:
    def __init(self):
        self.flag = 0
        self.sector = 0
        self.position = 0
        self.name = ""
        self.first = 0
        self.sectors = 0

    def is_unused(self):
        return self.flag == 0

    def is_deleted(self):
        return self.flag & 0x80

    def is_locked(self):
        return self.flag & 0x20

    def is_valid(self):
        return not self.is_unused() and not self.is_deleted()
        #return self.flag != 0 and not (self.flag & 0x80)

    
class atrfs(Operations):
    def __init__(self, root):
        self.root = root
        self.directory_size = 64
        self.handles = {}
        self.vtoc_lock = threading.Lock()
        self.filename_regex = re.compile(R"^[a-zA-Z0-9]{1,8}(\.[a-zA-Z0-9]{1,3}|)$")

        self.atr_file = open(self.root, mode="r+b")
        header = self.atr_file.read(7);
        atr_magic, data_size, self.sector_size, hi_data_size = \
            struct.unpack("<HHHB", header)

        disk_bytes = (data_size + (hi_data_size << 16)) * 16
        self.sector_count = (disk_bytes - 3 * 128) / self.sector_size + 3

        print atr_magic, data_size, self.sector_size, self.sector_count

        #TODO how should we report an error?
        if atr_magic != 0x0296:
            return -1

        data = self.read_sector(360)
        # Check if the ATR is an AtariDOS image
        if data[0] != 2 and data[0] != 0:
            return -1

        self.handles = collections.OrderedDict()
        # We'll use the index as inode number, so we need to block the one
        # at position 0.
        self.handles["\x00"] = 0

    def vtoc_lock_acquire(self, method_name):
        print method_name + ": waiting for VTOC lock"
        self.vtoc_lock.acquire()
        print "VTOC lock acquired"

    def vtoc_lock_release(self, method_name):
        self.vtoc_lock.release()
        print method_name + ": VTOC lock released"


    def _full_path(self, partial):
        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path

    def to_unix_notation(self, name):
        prefix = name[0:8].strip()
        extension = name[8:12].strip()

        return prefix + ("." + extension if extension else "")

    def is_filename_valid(self, name):
        return self.filename_regex.match(name)
        
    #TODO This will fail for hand-edited file names with multiple dots, etc.
    def to_dos_notation(self, name):
        parts = name.split('.')

        return parts[0].ljust(8) + (parts[1].ljust(3) if len(parts) > 1 else "   ")

    def sector_to_atr_offset(self, sector_number):
        return 16 + min(sector_number - 1, 3) * 128 \
                  + ((sector_number - 4) * self.sector_size) if sector_number \
                  >= 4 else 0
 
    def read_sector(self, sector_number):
        #print "Reading sector: ", sector_number
        if sector_number == 0 or sector_number > self.sector_count:
            return ""

        offset = self.sector_to_atr_offset(sector_number)
        self.atr_file.seek(offset);

        return bytearray(self.atr_file.read(self.sector_size))

    def write_sector(self, sector_number, data):
        #print "Writing sector: ", sector_number
        if sector_number == 0 or sector_number > self.sector_count:
            return False

        offset = self.sector_to_atr_offset(sector_number)
        self.atr_file.seek(offset);
        self.atr_file.write(data)

        return True

    def sector_chain(self, sector):
        while True:
            data = self.read_sector(sector)
            next_sector, fill = struct.unpack(">HB", data[-3:])
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

    def directory_walker(self, function):
        de = DirEntry()
        for sector in range(361, 369):
            de.sector = sector
            data = self.read_sector(sector)

            for pos in range(0, 8):
                offset = pos * 16;
                de.position = pos
                de.flag, de.sectors, de.first = \
                    struct.unpack("<BHH", data[offset:offset+5])
                de.name = str(data[offset + 5:offset+16])

                retval = function(de)

                if retval:
                    return retval

        return None

    def name_matcher(self, path, dir_entry):
        if dir_entry.is_valid() and dir_entry.name == path:
            print "matcher: " , path
            pprint (vars(dir_entry))
            return dir_entry


    def find_dir_entry(self, path):
        return self.directory_walker(partial(self.name_matcher, path)) or None


    def count_valid_dir_entries(self):
        def entry_counter(dir_entry):
            if dir_entry.is_valid():
                entry_counter.entries += 1

        # Poor man's mutable closure variables
        entry_counter.entries = 0
        self.directory_walker(entry_counter)

        return entry_counter.entries

    def get_dir_entries(self):
        dirents = ['.', '..']
        def entry_getter(entries, dir_entry):
            if dir_entry.is_valid():
                entries.append(self.to_unix_notation(dir_entry.name))

        self.directory_walker(partial(entry_getter, dirents))

        return dirents


    def access(self, path, mode):
        print "Access called:" + path
        if mode & os.W_OK:
            raise FuseOSError(errno.EACCES)

        return 0
        #if not os.access(full_path, mode):

    def chmod(self, path, mode):
        full_path = self._full_path(path)
        return os.chmod(full_path, mode)

    def getattr(self, path, fh=None):
        print "getattr called:", path

        if path == "/":
            return {"st_gid": os.getgid(),
                    "st_uid": os.getuid(),
                    "st_size": 2,
                    "st_mode": stat.S_IFDIR | stat.S_IRUSR |stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH,
                    }

        full_path = self._full_path(path)

        if path.startswith("/"):
            path = path[1:]

        self.vtoc_lock_acquire("getattr")
        dir_entry = self.find_dir_entry(self.to_dos_notation(path))
        self.vtoc_lock_release("getattr")

        if not dir_entry:
            raise FuseOSError(errno.ENOENT)

        return {"st_gid": os.getgid(),
                "st_uid": os.getuid(),
                #"st_size": sectors * self.sector_size,
                "st_size": self.get_actual_size(dir_entry.first),
                "st_ino": dir_entry.sector * 8 + dir_entry.position,
                "st_nlink": 1,
                "st_mode": (0 if dir_entry.is_locked() else stat.S_IWUSR)
                        | stat.S_IFREG | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH,
               }

    def readdir(self, path, fh):
        print "readdir called:", path
        full_path = self._full_path(path)

        self.vtoc_lock_acquire("readdir")
        direntry_iterator = iter(self.get_dir_entries())
        self.vtoc_lock_release("readdir")

        return direntry_iterator


    def statfs(self, path):
        print "statfs called"
        full_path = self._full_path(path)

        self.vtoc_lock_acquire("statfs")

        data = self.read_sector(360)
        free_sectors = struct.unpack("<H", data[3:5])[0]

        if self.sector_count >= 1024:
            data = self.read_sector(1024)
            free_sectors += struct.unpack("<H", data[122:124])[0]

        used_entries = self.count_valid_dir_entries();
        print "Total used: ", used_entries

        self.vtoc_lock_release("statfs")

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

    def rename(self, path, new_name):
        print "rename called", path, new_name
        if path.startswith("/"):
            path = path[1:]

        if new_name.startswith("/"):
            new_name = new_name[1:]

        if not self.is_filename_valid(new_name):
            # This is questionable, but how to report invalid names?
            raise FuseOSError(errno.ENAMETOOLONG)

        if self.find_dir_entry(self.to_dos_notation(new_name)):
            raise FuseOSError(errno.EEXIST)

        path = self.to_dos_notation(path)

        self.vtoc_lock_acquire("rename")

        dir_entry = self.find_dir_entry(path)

        pprint (dir_entry)

        if dir_entry:
            data = self.read_sector(dir_entry.sector)
            pprint(data)
            offset = dir_entry.position * 16
            data[offset + 5:offset + 16] = \
                bytes(self.to_dos_notation(new_name))
            pprint(data)
            self.write_sector(dir_entry.sector, data)

        self.vtoc_lock_release("rename")

        if not dir_entry:
            raise FuseOSError(errno.ENOENT)


    # File methods
    # ============

    def open(self, path, flags):
        print "file open called:", path, flags
        full_path = self._full_path(path)

        error = 0

        if path.startswith("/"):
            path = path[1:]

        path = self.to_dos_notation(path)

        self.vtoc_lock_acquire("open")

        dir_entry = self.find_dir_entry(path)

        if dir_entry:
            if path not in self.handles:
                print "Inserting: ", path
                self.handles[path] = self.load_atari_file(dir_entry.first)
        else:
            error = errno.ENOENT

        self.vtoc_lock_release("open")

        if error:
            raise FuseOSError(error)

        print "Returning handle: ", self.handles.keys().index(path)
        return self.handles.keys().index(path)

    def create(self, path, mode, fi=None):
        print "create called: ", path, mode
        #full_path = self._full_path(path)
        #return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

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
        return
        #os.lseek(fh, offset, os.SEEK_SET)
        #return os.write(fh, buf)

    def truncate(self, path, length, fh=None):
        print "truncate called: ", path
        return
        #full_path = self._full_path(path)
        #with open(full_path, 'r+') as f:
        #    f.truncate(length)

    def free_bitmap(self, sectors_to_free):
        vtocs = [None] * 2
        vtocs[0] = self.read_sector(360)

        if self.sector_count >= 1024:
            vtocs[1] = self.read_sector(1024)

        for sector, _, _ in sectors_to_free:
            print "Freeing sector: ", sector
            if sector < 720:
                vtoc = vtocs[0]
                sector_number = 10 + sector / 8
                bit_mask = 1 << (7 - (sector % 8))
                free_sectors_index = 3
            else:
                vtoc = vtocs[1]
                sector_number = 84 + (sector - 720) / 8
                bit_mask = 1 << (7 - (sector % 8))
                free_sectors_index = 122
 
            if vtoc[sector_number] & bit_mask == 1:
                print "Bitmap inconsistency detected: file's sector marked free."

            vtoc[sector_number] |= bit_mask;

            free_sectors = struct.unpack(
                "<H", vtoc[free_sectors_index:free_sectors_index+2])[0]

            free_sectors += 1
            print "Current free sectors: ", free_sectors

            vtoc[free_sectors_index:free_sectors_index +  2] = struct.pack(
                "<H", free_sectors)

        self.write_sector(360, vtocs[0])
        if vtocs[1]:
            # copy bitmap of sectors 48-719 to VTOC2
            vtocs[1][0:84] = vtocs[0][10 + 48 / 8 : 10 + 719 / 8 + 1]
            self.write_sector(1024, vtocs[1])


    def mark_direntry_deleted(self, dir_entry):
        data = self.read_sector(dir_entry.sector)
        data[dir_entry.position * 16] = 0x80
        self.write_sector(dir_entry.sector, data)


    def unlink(self, path):
        print "unlink called"

        error = 0
        if path.startswith("/"):
            path = path[1:]

        path = self.to_dos_notation(path)

        self.vtoc_lock_acquire("unlink")

        dir_entry = self.find_dir_entry(path)

        if dir_entry:
            if not dir_entry.is_locked():
                print "Deleting: ", path
                # Free cached file, but keep the inode number. If we just delete the key,
                # OrderedDict would change the indices (which we use as inodes).
                if path in self.handles:
                    self.handles[path] = None
                
                self.free_bitmap(self.sector_chain(dir_entry.first))
                self.mark_direntry_deleted(dir_entry)
            else:
                error = errno.EACCES
        else:
            error = errno.ENOENT

        self.vtoc_lock_release("unlink")

        if error:
            raise FuseOSError(error)


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
    if len(sys.argv) != 3:
        raise SystemExit("Usage: %s <diskimage.atr> <mountpoint>" % sys.argv[0])

    main(sys.argv[2], sys.argv[1])
