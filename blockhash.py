#!/usr/bin/env python
#encoding=utf8

import os
import sys
import hashlib

DEFAULT_BLOCK_SIZE = 1024*1024

def usage():
    pname = sys.argv[0]
    print "Usage: %s <filename> [blocksize in kb]" % (pname)
    print """

Default block size if %s bytes

Examples: 
    %s /tmp/foo.dat         Compute block hashes for /tmp/foo.dat with default block size
    %s /tmp/foo.dat 32      Compute block hashes for /tmp/foo.dat with block size of 32 kb
    cat /tmp/foo.dat | %s - Compute block hashes for STDIN with default block size
""" % (DEFAULT_BLOCK_SIZE, pname, pname, pname)

    sys.exit(1)
try:
    filename = sys.argv[1]
except:
    filename ="C:\Python27\\tcl\\tkconfig.sh"
    usage()

try:
    blocksize = int(sys.argv[2])*1024
    print "Blocksize: %d bytes" % (blocksize)
except:
    blocksize = DEFAULT_BLOCK_SIZE
    print "Using default blocksize: %d bytes" % (blocksize)
    #usage()

def header():
    print
    print "%16s %16s %42s" % ("Block start", "Block end", "Hash")

def progress(i, blocksize, num_bytes_read, hash):
    bs_start = i*blocksize
    bs_end   = min(bs_start + num_bytes_read - 1, num_bytes_read)
    #print "%16d %16d %42s" % (bs_start, bs_end, hash)
    print "0x%14.14x 0x%14.14x %42s" % (bs_start, bs_end, hash)


def hashblock(f, blocksize):
    block = f.read(blocksize)
    num_bytes_read = len(block)
    hash = hashlib.md5(block).hexdigest()
    return num_bytes_read, hash


total_bytes_read = 0
i = 0
try:
    if filename == '-':
        f = sys.stdin
    else:
        f = open(filename, 'rb')
    (num_bytes_read, hash) = hashblock(f, blocksize)
    total_bytes_read += num_bytes_read
    header()

    while num_bytes_read > 0:
        i += 1
        progress(i, blocksize, num_bytes_read, hash)
        (num_bytes_read, hash) = hashblock(f, blocksize)
        total_bytes_read += num_bytes_read

except KeyboardInterrupt:
    print "Aborted by user"
print
print "%d bytes read" % (total_bytes_read)


