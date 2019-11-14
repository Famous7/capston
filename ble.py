from urllib.parse import urlparse
import requests
import argparse
import errno
import os
import gc
import sys
import socket
import struct
import threading
import queue
import time
import json
from ctypes import (CDLL, get_errno)
from ctypes.util import find_library


job_queue = queue.Queue()
station_dict = {}


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
        sys.exit(-1)


def get_vendor_of_oui(mac):
    oui = mac[:8].upper()
    return oui_dict[oui].split('\t')[0] if oui in oui_dict else "Unknown"


def worker_thread_func(server_url, exit_event, stop_event):
    while not exit_event.is_set():
        try:
            seq, timeout = job_queue.get(timeout=5)
        except queue.Empty:
            continue

        if stop_event.is_set():
            time.sleep(0.25)
            continue

        try:
            os.system('hciconfig hci0 down')
            os.system('hciconfig hci0 up')

            ble_sock = make_ble_socket()
        except Exception as e:
            print(e)
            exit_event.set()
            sys.exit(-1)
        else:
            timeout_event = threading.Event()
            threading.Timer(timeout, lambda x: x.set(), args=(timeout_event,)).start()

            global station_dict
            while not timeout_event.is_set() and not stop_event.is_set():
                data = ble_sock.recv(1024)
                sta_mac = ':'.join("{0:02x}".format(x) for x in data[12:6:-1])
                rssi = int(data[len(data)-1]) - 256

                if sta_mac in station_dict:
                    station_dict[sta_mac].push_rssi(rssi)
                    station_dict[sta_mac].count += 1
                else:
                    station_dict[sta_mac] = Station(mac=sta_mac, rssi=rssi, vendor=get_vendor_of_oui(sta_mac[:8]))

            if not stop_event.is_set():
                data = {'seq': seq, 'ble': [sta.to_dict() for sta in station_dict.values()]}
                print(json.dumps(data))
                try:
                    requests.post(url=server_url, json=data)
                except requests.exceptions.ConnectionError:
                    print('HTTP connection error')
                    exit_event.set()
                    #sys.exit(-1)

                station_dict = {}
                gc.collect()


def main_func(server_url, server_ip, server_port):
    retry = 1
    exit_event = threading.Event()
    stop_event = threading.Event()

    worker_thread = threading.Thread(target=worker_thread_func, args=(server_url, exit_event, stop_event))
    worker_thread.start()

    global station_dict
    try:
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                if retry > 5:
                    print('Connection error')
                    break
                try:
                    sock.connect((server_ip, server_port))
                    sock.send('BLE/CONN'.encode())
                except ConnectionRefusedError:
                    print('Connection refused by server... retry [{}/5]'.format(retry))
                    time.sleep(1)
                    retry += 1
                    continue
                except BrokenPipeError:
                    print('Connection refused by server... retry [{}/5]'.format(retry))
                    time.sleep(1)
                    retry += 1
                    continue

                while True:
                    data = sock.recv(65535)

                    if not data:
                        break

                    if exit_event.is_set():
                        sys.exit(-1)

                    command, seq, timeout = data.decode().upper().split('/')
                    timeout = int(timeout)
                    seq = int(seq)

                    if command == 'START':
                        station_dict = {}
                        stop_event.clear()
                        job_queue.put((seq, timeout))

                    elif command == 'STOP':
                        print('stop')
                        stop_event.set()

                    else:
                        print('Unknown command {}'.format(data))
                        break

    except KeyboardInterrupt:
        print('Exit')

    finally:
        if worker_thread.is_alive():
            stop_event.set()
            exit_event.set()
            worker_thread.join(timeout=5)


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


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", help="server address", type=str, required=True)
    parser.add_argument("-f", help="oui file path", type=str, required=True)
    args = parser.parse_args()

    if not os.geteuid() == 0:
        sys.exit("script only works as root")

    server_url = args.u
    url_part = urlparse(server_url)

    server_ip = url_part.hostname
    server_port = int(url_part.port) + 1

    oui_file_path = args.f
    oui_dict = load_oui_dict(oui_file_path)

    main_func(server_url=server_url, server_ip=server_ip, server_port=server_port)