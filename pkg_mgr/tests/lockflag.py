#!/usr/bin/env python3
"""lockflag.py - read or set the immutable flag on a directory (chattr +i/-i).

Usage: lockflag.py get|set|clear DIR
'get' prints yes or no. 'set' and 'clear' need CAP_LINUX_IMMUTABLE (root).
"""
import fcntl
import os
import struct
import sys

FS_IOC_GETFLAGS = 0x80086601  # _IOR('f', 1, long), 64-bit Linux
FS_IOC_SETFLAGS = 0x40086602  # _IOW('f', 2, long)
FS_IMMUTABLE_FL = 0x00000010


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("get", "set", "clear"):
        sys.exit("usage: lockflag.py get|set|clear DIR")
    fd = os.open(sys.argv[2], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        buf = bytearray(8)
        fcntl.ioctl(fd, FS_IOC_GETFLAGS, buf)
        flags = struct.unpack("l", bytes(buf))[0]
        if sys.argv[1] == "get":
            print("yes" if flags & FS_IMMUTABLE_FL else "no")
            return
        if sys.argv[1] == "set":
            flags |= FS_IMMUTABLE_FL
        else:
            flags &= ~FS_IMMUTABLE_FL
        fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack("l", flags))
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
