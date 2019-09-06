import struct
import random
import socket
import time
import io
import re
import collections


HEADER_SIZE = 12

Header = collections.namedtuple('Header', ['msg', 'len', 'sync'])


def unpack_header(buf):
    msg, len_, sync = struct.unpack('<III', buf[:HEADER_SIZE])
    return Header(msg, len_, sync), buf[HEADER_SIZE:]


def pack_header(header):
    return struct.pack('<III', header.msg, header.len, header.sync)


def scanf(fmt, buf):
    """return <values: tuple>, <error: str>, <remain: bytes>"""

    vals = []
    for f in fmt:

        if f == 'u':
            if len(buf) < 4:
                return tuple(vals), \
                            "decoding error (fmt:'u'): too small buffer", buf
            vals.append(struct.unpack_from('<I', buf)[0])
            buf = buf[4:]

        elif f == 'w':
            val, err, new_buf = _berint_decode(buf)
            if err:
                return tuple(vals), f"decoding error (fmt:'w'): {err}", buf
            vals.append(val)
            buf = new_buf

        elif f == 'W':
            val, err, new_buf = _berstr_decode(buf)
            if err:
                return tuple(vals), f"decoding error (fmt:'W'): {err}", buf
            vals.append(val)
            buf = new_buf

        else:
            return tuple(vals), "not implemented", buf

    return tuple(vals), None, buf


def printf(fmt, vals):
    """return <blob: bytes>, <error: str>"""
    return


def _mp_fmt(key):
    key >>= 5
    if key == 0:
        return 'w'
    elif key == 1:
        return 'W'
    return None


def unpack_mp(buf):

    vals = {}
    while len(buf) > 0:

        key, err, buf = scanf('w', buf)
        if err:
            return None, err
        key = key[0]

        val, err, buf = scanf(_mp_fmt(key), buf)
        if err:
            return None, err
        vals[key] = val[0]

    return vals, None


def _berint_decode(buf):
    val = 0
    for i in range(5):
        if len(buf) < 1:
            return None, "too small buffer", buf
        val = (val << 7) | buf[0] & 0x7F
        next = buf[0] & 0x80
        buf = buf[1:]
        if not next:
            break
    return val, None, buf


def _berstr_decode(buf):
    len_, err, new_buf = _berint_decode(buf)
    if err:
        return None, err, buf
    if len_ > len(new_buf):
        return None, "too small buffer", buf
    return new_buf[:len_], None, new_buf[len_:]
