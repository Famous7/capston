import requests
import argparse
import json
import threading
import socketio
import gc
import socket
import os
import struct
import sys
import queue
from ctypes import (CDLL, get_errno)
from ctypes.util import find_library


oui_dict = {}
station_dict = {}
job_queue = queue.Queue()
sio = socketio.Client()
send_event = threading.Event()
MIDDLEWARE_NAMESPACE = '/middleware'


class Station:
    def __init__(self, mac, rssi, vendor, count=1):
        self.mac = mac
        self.rssi = [rssi]
        self.vendor = vendor
        self.count = count

    def push_rssi(self, rssi):
        self.rssi.append(rssi)

    def to_dict(self):
        return {'MAC': self.mac,
                'RSSI': int(sum(self.rssi) / len(self.rssi)),
                'vendor': self.vendor,
                'count': self.count}


def load_oui_dict(path):
    try:
        with open(path, encoding='utf-8-sig') as f:
            return {x[:8]: x[9:].rstrip('\n') for x in f if x}
    except FileNotFoundError:
        print('No such file or directory: {}'.format(path))
        return None


def get_vendor_of_oui(mac):
    oui = mac[:8].upper()
    return oui_dict[oui].split('\t')[0] if oui in oui_dict else "Unknown"


def make_ble_socket():
    btlib = find_library("bluetooth")
    if not btlib:
        raise Exception(
            "Can't find required bluetooth libraries"
            " (need to install bluez)"
        )
    bluez = CDLL(btlib, use_errno=True)
    dev_id = bluez.hci_get_route(None)

    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
    sock.bind((dev_id,))

    err = bluez.hci_le_set_scan_parameters(sock.fileno(), 0, 0x10, 0x10, 0, 0, 1000)
    if err < 0:
        raise Exception("Set scan parameters failed")
        # occurs when scanning is still enabled from previous call

    # allows LE advertising events
    hci_filter = struct.pack(
        "<IQH",
        0x00000010,
        0x4000000000000000,
        0
    )
    sock.setsockopt(socket.SOL_HCI, socket.HCI_FILTER, hci_filter)

    err = bluez.hci_le_set_scan_enable(
        sock.fileno(),
        1,  # 1 - turn on;  0 - turn off
        0,  # 0-filtering disabled, 1-filter out duplicates
        1000  # timeout
    )
    if err < 0:
        errnum = get_errno()
        raise Exception("{} {}".format(
            errno.errorcode[errnum],
            os.strerror(errnum)
        ))

    return sock


def main_func(server_url):
    try:
        print('Connect to: ', server_url)
        sio.connect(server_url, namespaces=[MIDDLEWARE_NAMESPACE])

        global station_dict
        while True:
            try:
                seq, timeout = job_queue.get(timeout=1)
            except queue.Empty:
                continue

            try:
                os.system('hciconfig hci0 down')
                os.system('hciconfig hci0 up')

                ble_sock = make_ble_socket()
            except Exception as e:
                sys.exit(e)

            timeout_event = threading.Event()
            threading.Timer(timeout, lambda x: x.set(), args=(timeout_event,)).start()

            global station_dict
            while not timeout_event.is_set() and send_event.is_set():
                data = ble_sock.recv(1024)
                sta_mac = ':'.join("{0:02x}".format(x) for x in data[12:6:-1])
                rssi = int(data[len(data) - 1]) - 256

                if sta_mac in station_dict:
                    station_dict[sta_mac].push_rssi(rssi)
                    station_dict[sta_mac].count += 1
                else:
                    station_dict[sta_mac] = Station(mac=sta_mac, rssi=rssi, vendor=get_vendor_of_oui(sta_mac[:8]))

            if send_event.is_set():
                data = {'seq': seq, 'ble': [sta.to_dict() for sta in station_dict.values()]}
                print(json.dumps(data))
                try:
                    requests.post(url=server_url, json=data)
                except requests.exceptions.ConnectionError:
                    print('HTTP connection error')

                station_dict = {}
                gc.collect()

    except KeyboardInterrupt:
        print('Exit...')
    except socketio.exceptions.ConnectionError:
        sys.exit('Connection refused by the server')
    finally:
        sio.disconnect()


@sio.event
def connect():
    print('Connection established, sid: ', sio.sid)
    sio.emit('monitor_online', {'type': 'BLE'}, namespace=MIDDLEWARE_NAMESPACE)


@sio.on('start_collecting', namespace=MIDDLEWARE_NAMESPACE)
def start_collecting(data):
    seq = data['seq']
    timeout = data['timeout']
    send_event.set()
    job_queue.put((seq, timeout))


@sio.on('stop_collecting', namespace=MIDDLEWARE_NAMESPACE)
def stop_collecting(data):
    send_event.clear()
    print('Stop')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", help="server address", type=str, required=True)
    parser.add_argument("-f", help="oui file path", type=str, required=True)
    args = parser.parse_args()

    if not os.geteuid() == 0:
        sys.exit("Script only works as root")

    oui_file_path = args.f
    oui_dict = load_oui_dict(oui_file_path)

    if not oui_dict:
        sys.exit(-1)

    server_url = args.u

    main_func(server_url=server_url)