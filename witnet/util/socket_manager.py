import json
import socket
import struct

from witnet.util.transformations import bytes_to_hex
class SocketManager(object):
    def __init__(self, ip, port, internal, socket_options=None):
        self.ip = ip
        self.port = int(port)

        self.internal = internal

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set socket options
        # Allows close and immediate reuse of an address, ignoring TIME_WAIT
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Always and immediately close a socket, ignoring pending data
        so_onoff, so_linger = 1, 0
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', so_onoff, so_linger))

    def connect(self):
        print(f'Connecting to {self.ip}:{self.port}')
        self.socket.connect((self.ip, self.port))

    def disconnect(self):
        print('disconnected')
        self.socket.close()

    def fetch(self, request):
        self.socket.send((json.dumps(request) + "\n").encode("utf-8"), )
        response = ""
        while True:
            response += self.socket.recv(1024).decode("utf-8")

            if 'Error' in response:
                break
            if len(response) == 0 or response[-1] == "\n":
                break
        if response != "":
            try:
                return json.loads(response)
            except json.decoder.JSONDecodeError:
                return {"error": {"code": -1337, "message": "malformed response"}}
        else:
            return {"error": {"code": -1337, "message": "response was empty"}}

    def query(self, request):
        try:
            response = self.fetch(request)
        except Exception as e:
            print(e)
        reason = "unknown"
        if type(response) is dict and "error" in response:
            reason = response["error"]
            if "reason" in response:
                reason = response["reason"]
            if "params" in request:
                return {
                    "error": "could not execute " + request["method"] + " with parameters " + str(request["params"]),
                    "reason": reason}
            else:
                return {"error": "could not execute " + request["method"], "reason": reason}
        if type(response) is dict and "result" in response:
            return response["result"]
        else:
            return response

    def close_connection(self):
        self.socket.send(b"\n")
        self.disconnect()
