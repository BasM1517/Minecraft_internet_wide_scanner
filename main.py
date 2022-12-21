# Press the green button in the gutter to run the script.
import json
import random
import socket
import struct
import time

import masscan
import pymongo

client = pymongo.MongoClient("mongodb+srv://r3dp:bF30CMjYbp8LhA6C@mcserverstorage.jkzmh.mongodb.net/?retryWrites=true&w=majority")
mydb = client['db_mcservers']
collection = mydb["cn_mcservers"]
collection2 = mydb["cn_players"]
#ip 49.12.0.0 may has to be scanned again
ipdone = ["116.202.0.0","116.203.0.0","135.181.0.0","136.243.0.0","138.201.0.0","144.76.0.0","148.251.0.0","157.90.0.0""159.69.0.0","162.55.0.0","167.233.0.0","167.235.0.0","168.119.0.0","176.9.0.0","178.63.0.0","188.40.0.0","195.201.0.0","46.4.0.0","49.12.0.0"]
ip_ranges_hetzner_16 = ["49.13.0.0","5.9.0.0","65.108.0.0","65.109.0.0","65.21.0.0","88.198.0.0","88.99.0.0","94.130.0.0","95.216.0.0","95.217.0.0"]
#bF30CMjYbp8LhA6C
global ip_ranges


class StatusPing:
    """ Get the ping status for the Minecraft server """

    def __init__(self, host='localhost', port=25565, timeout=5):
        """ Init the hostname and the port """
        self._host = host
        self._port = port
        self._timeout = timeout

    def _unpack_varint(self, sock):
        """ Unpack the varint """
        data = 0
        for i in range(5):
            ordinal = sock.recv(1)

            if len(ordinal) == 0:
                break

            byte = ord(ordinal)
            data |= (byte & 0x7F) << 7*i

            if not byte & 0x80:
                break

        return data

    def _pack_varint(self, data):
        """ Pack the var int """
        ordinal = b''

        while True:
            byte = data & 0x7F
            data >>= 7
            ordinal += struct.pack('B', byte | (0x80 if data > 0 else 0))

            if data == 0:
                break

        return ordinal

    def _pack_data(self, data):
        """ Page the data """
        if type(data) is str:
            data = data.encode('utf8')
            return self._pack_varint(len(data)) + data
        elif type(data) is int:
            return struct.pack('H', data)
        elif type(data) is float:
            return struct.pack('L', int(data))
        else:
            return data

    def _send_data(self, connection, *args):
        """ Send the data on the connection """
        data = b''

        for arg in args:
            data += self._pack_data(arg)

        connection.send(self._pack_varint(len(data)) + data)

    def _read_fully(self, connection, extra_varint=False):
        """ Read the connection and return the bytes """
        packet_length = self._unpack_varint(connection)
        packet_id = self._unpack_varint(connection)
        byte = b''

        if extra_varint:
            # Packet contained netty header offset for this
            if packet_id > packet_length:
                self._unpack_varint(connection)

            extra_length = self._unpack_varint(connection)

            while len(byte) < extra_length:
                byte += connection.recv(extra_length)

        else:
            byte = connection.recv(packet_length)

        return byte

    def get_status(self):
        """ Get the status response """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(25)
            connection.connect((self._host, self._port))

            # Send handshake + status request
            self._send_data(connection, b'\x00\x00', self._host, self._port, b'\x01')
            self._send_data(connection, b'\x00')

            # Read response, offset for string length
            data = self._read_fully(connection, extra_varint=True)

            # Send and read unix time
            self._send_data(connection, b'\x01', time.time() * 1000)
            unix = self._read_fully(connection)

        # Load json and return
        response = json.loads(data.decode('utf8'))
        response['ping'] = int(time.time() * 1000) - struct.unpack('L', unix)[0]

        return response

def getip():
    global ip_ranges
    A = list(range(1, 0xff))
    B = list(range(1, 0xff))
    random.shuffle(B)
    random.shuffle(A)
    ip_ranges = []
    for a in A:
        for b in B:
            ip_range = f"{a}.{b}.0.0/16"
            ip_ranges.append(ip_range)

def Scanning():
    while True:
        random.shuffle(ip_ranges)
        for ip_range in ip_ranges_hetzner_16:
            print(ip_range)
            ip_range = ip_range + "/16"
            ipdone.append(ip_range)
            try:
                mas = masscan.PortScanner()
                mas.scan(ip_range, ports='25565', arguments='--max-rate 15000')
                delay = 5000
                for ip in mas.scan_result['scan']:
                    host = mas.scan_result['scan'][ip]
                    print(f"{ip}&{host}")
                    if "tcp" in host and 25565 in host['tcp']:
                        print(f"{ip}")
                        try:
                            status_ping = StatusPing(ip)
                            serverinfo = {
                                "Ip": ip,
                                "description": status_ping.get_status()["description"],
                                "version": status_ping.get_status()["version"],
                                "players": status_ping.get_status()["players"]
                            }
                            try:
                                for i in status_ping.get_status()["players"]["sample"]:
                                    playerinfo = {
                                    "uuid": i["id"],
                                    "name": i["name"],
                                    "Ip": ip
                                    }
                                    print(playerinfo)
                                    collection2.insert_one(playerinfo)
                            except KeyError:
                                print("there are no players")
                            try:
                                if status_ping.get_status()["mods"] in locals():
                                    serverinfo["mods"] = status_ping.get_status()["mods"]
                                else:
                                    print("server has no mods")
                                    continue
                            except KeyError:
                                print("no mods where active")
                            print(serverinfo)
                            collection.insert_one(serverinfo)
                        except socket.timeout:
                            print("took to long")
                        except:
                            print(1)
            except masscan.NetworkConnectionError:
                print("error")
            except ConnectionResetError:
                print("connectionerror")


def main():
    getip()
    Scanning()

main()
