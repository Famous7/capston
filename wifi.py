from scapy.all import *
import requests
import argparse
import json
import threading
import socketio
import gc
import re
import os
import subprocess
import queue
import random
from we import WirelessExtension

oui_dict = {}
station_dict = {}
job_queue = queue.Queue()
sio = socketio.Client()
send_event = threading.Event()
MIDDLEWARE_NAMESPACE = '/middleware'
FILTER_EXP = '(type mgt subtype assoc-req) or (type mgt subtype probe-req) or (type data)'


class Station:
    def __init__(self, mac, rssi, channel, vendor, count=1):
        self.mac = mac
        self.rssi = [rssi]
        self.channel = [channel]
        self.vendor = vendor
        self.count = count

    def push_rssi(self, rssi):
        self.rssi.append(rssi)

    def push_channel(self, channel):
        self.channel.append(channel)

    def most_frequent(self, l):
        return max(set(l), key=l.count)

    def to_dict(self):
        return {'MAC': self.mac,
                'RSSI': int(sum(self.rssi) / len(self.rssi)),
                'vendor': self.vendor,
                'channel': self.most_frequent(self.channel),
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


def is_to_ds(dot11):
    DS = dot11.FCfield & 0x3
    to_DS = DS & 0x1 != 0
    from_DS = DS & 0x2 != 0

    return to_DS and not from_DS


def is_monitor_mode(iface):
    output = subprocess.Popen(['iwconfig', iface], stdout=subprocess.PIPE).communicate()

    pattern = re.compile(r'Mode:Monitor')

    if pattern.search(output[0].decode()):
        return True
    else:
        return False


def packet_handler(pkt):
    if not send_event.is_set():
        return True

    if not pkt.haslayer(RadioTap):
        return False

    rssi = pkt.dBm_AntSignal

    # sometime it received malformed packet
    if not rssi:
        return False

    channel = pkt.ChannelFrequency if pkt.ChannelFrequency else pkt.Channel

    # data frame
    if pkt.type == 2:
        if not is_to_ds(pkt):
            return False

    sta_mac = pkt.addr2
    if sta_mac in station_dict:
        station = station_dict[sta_mac]
        station.push_channel(channel)
        station.push_rssi(rssi)
        station.count += 1
    else:
        station_dict[sta_mac] = Station(mac=sta_mac, rssi=rssi, channel=channel, vendor=get_vendor_of_oui(sta_mac[:8]))

    return False


def main_func(iface, server_url, static_channel):
    wireless_ext = WirelessExtension(iface=iface.encode())

    if static_channel:
        wireless_ext.set_channel(static_channel)

    try:
        print('Connect to: ', server_url)
        sio.connect(server_url, namespaces=[MIDDLEWARE_NAMESPACE])

        global station_dict
        while True:
            try:
                seq, timeout = job_queue.get(timeout=1)
            except queue.Empty:
                continue

            timeout_event = threading.Event()
            threading.Timer(interval=timeout, function=lambda ev: ev.set(), args=(timeout_event,)).start()

            while not timeout_event.is_set() and send_event.is_set():
                try:
                    if not static_channel:
                        ch = random.randint(1, wireless_ext.get_max_channel())
                        wireless_ext.set_channel(ch)

                    sniff(iface=iface, monitor=True, filter=FILTER_EXP, store=False, timeout=0.5,
                          stop_filter=packet_handler)

                except Scapy_Exception as e:
                    print(e)
                    send_event.clear()
                    break
                except Exception as e:
                    print(e)
                    raise e

            if send_event.is_set():
                data = {'seq': seq, 'wi-fi': [sta.to_dict() for sta in station_dict.values()]}
                print(json.dumps(data))
                try:
                    requests.post(url=server_url, json=data)
                except requests.exceptions.ConnectionError:
                    print('HTTP connection error')

                station_dict = {}
                gc.collect()

    except socketio.exceptions.ConnectionError:
        print('Connection refused by the server...')
    except KeyboardInterrupt:
        print('Exit...')
    finally:
        sio.disconnect()


@sio.event
def connect():
    print('Connection established, sid: ', sio.sid)
    sio.emit('monitor_online', {'type': 'WI-FI'}, namespace=MIDDLEWARE_NAMESPACE)


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
    parser.add_argument("-I", help="nic name", type=str, required=True)
    parser.add_argument("-u", help="server address", type=str, required=True)
    parser.add_argument("-f", help="oui file path", type=str, required=True)
    parser.add_argument("-c", help="static channel", type=int)
    args = parser.parse_args()

    if not os.geteuid() == 0:
        sys.exit("Script only works as root")

    nic = args.I

    if not is_monitor_mode(nic):
        sys.exit('{} is not running monitor mode...'.format(nic))

    static_channel = args.c

    oui_file_path = args.f
    oui_dict = load_oui_dict(oui_file_path)

    if not oui_dict:
        sys.exit(-1)

    server_url = args.u
    static_channel = args.c if args.c else None

    main_func(iface=nic, server_url=server_url, static_channel=static_channel)