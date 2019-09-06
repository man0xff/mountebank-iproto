import aiohttp
import asyncio
import json
import socket
import sys
import typing

import iproto


class Logger(object):

    _titles = ['debug', 'info', 'warn', 'error']

    def __init__(self, level):
        assert(level in self._titles)
        self._level = self._titles.index(level)

    def _write(self, level, *args):
        if level >= self._level:
            print(self._titles[level], *args)
            sys.stdout.flush()

    def debug(self, *args):
        self._write(0, *args)

    def info(self, *args):
        self._write(1, *args)

    def warn(self, *args):
        self._write(2, *args)

    def error(self, *args):
        self._write(3, *args)


class App:
    config: dict
    rules:  dict
    log:    Logger


def header_to_str(header):
    return f"{header.msg}:{header.len}:{header.sync}"


def unserialize(rules, header, payload):

    if str(header.msg) in rules:
        rules = rules[str(header.msg)]

        if 'format' in rules:
            fmt = rules['format']

            if fmt == 'mp':

                pairs, err = iproto.unpack_mp(payload)
                if err:
                    return None, f"decoding failed (fmt:'{fmt}'): {err}"
                names = {v: k for k, v in rules['names'].items()}
                vals = {
                    'msg': header.msg,
                }
                for k, v in pairs.items():
                    if type(v) == bytearray or type(v) == bytes:
                        v = v.hex()
                    vals[names[k]] = v
                return vals, None

            else:
                vals, err, _ = iproto.scanf(fmt, payload)
                if err:
                    return None, f"decoding failed (fmt:'{fmt}'): {err}"
                if len(vals) != len(rules['names']):
                    return None, f"incorrect number of names (msg:{header.msg})"
                vals = dict(zip(rules['names'], vals))
                vals['msg'] = header.msg
                return vals, None

        else:
            return {'msg': header.msg}, None

    return None, f"no rule (msg:{header.msg})"


def serialize(rules, header, request, response):

    if 'blob' in response:
        return bytes.fromhex(response['blob']), None

    elif 'payload' in response:
        r_payload = bytes.fromhex(response['payload'])
        r_header = iproto.Header(msg=header.msg, len=len(r_payload), sync=header.sync)
        return iproto.pack_header(r_header) + r_payload, None

    return None, f"unsupported response (response:'{response}')"


async def post(url, data):
    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=data) as resp:
            return await resp.json()


async def start_server(ip: str, port: int, serve: typing.Coroutine):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setblocking(False)
    s.bind((ip, port))
    s.listen(10)

    loop = asyncio.get_running_loop()

    while True:
        conn, addr = await loop.sock_accept(s)
        loop.create_task(serve(conn, addr))


async def read_exactly(sock: socket.socket, size: int):
    buf = bytearray()
    loop = asyncio.get_running_loop()

    while len(buf) < size:
        portion = await loop.sock_recv(sock, size - len(buf))
        if len(portion) == 0:
            return bytearray(), True
        buf += portion

    return buf, True


async def process_request(app, sock, addr, header, payload):

    req, err = unserialize(app.rules, header, payload)
    if err:
        app.log.error("unserializing failed:", err)
        return
    app.log.info(f"unserializing successfully done "
                 f"(header:'{header_to_str(header)}', "
                 f"payload:'{payload.hex()}', output:{req})")

    resp = await post(app.url, {'ip': addr[0], 'request': req})
    if 'response' not in resp:
        app.log.error(f"incorrect response from mountebank (resp:'{resp}')")
        return

    resp = resp['response']
    if not resp:
        app.log.info(f"using default response (header:'{header_to_str(header)}')")
        resp = app.default_response

    out, err = serialize(app.rules, header, req, resp)
    if err:
        app.log.error("serialization failed:", err)
        return
    app.log.info(f"serializing successfully done "
                 f"(input:'{resp}', output:'{out.hex()}')")

    await app.loop.sock_sendall(sock, out)


async def main():
    app = App()
    app.loop = asyncio.get_running_loop()

    config = {
        'loglevel': 'debug',
        'port': 2526,
        'iproto_rules': {},
        'defaultResponse': None,
    }
    config.update(json.loads(sys.argv[1]) if len(sys.argv) > 1 else {})
    app.config = config

    log = Logger(config['loglevel'])
    app.log = log

    log.info(config)

    app.rules = config['iproto_rules']
    app.default_response = config['defaultResponse']
    app.url = config['callbackURLTemplate'].replace(':port', str(config['port']))

    async def serve(sock, addr):
        while True:

            buf, ok = await read_exactly(sock, 12)
            if not ok or not buf:
                break
            header, _ = iproto.unpack_header(buf)

            payload = b''
            if header.len:
                payload, ok = await read_exactly(sock, header.len)
                if not ok or not payload:
                    break

            app.loop.create_task(process_request(app, sock, addr, header, payload))
        sock.close()

    await start_server('0.0.0.0', config['port'], serve)


asyncio.run(main())
