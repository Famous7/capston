from pythonosc import udp_client
import dbhelper
import random
import time


OPTION_PATH = 'options.txt'

db = dbhelper.DBHelper()

notes_and_durations_list = ['r1_notes', 'r1_durations', 'r2_notes', 'r2_durations', 'l1_notes', 'l1_durations',
                            'l2_notes', 'l2_durations']
music_tempo_dict = {'bts': 0.15, 'maple': 0.08, 'chop': 0.125, 'shape': 0.15}
last_tempo_dict = {'bts': 0.15, 'maple': 0.08, 'chop': 0.125, 'shape': 0.15}

with open(OPTION_PATH, 'r') as f:
    lineList = [line.rstrip('\n').split(':') for line in f]

options = {x[0]: x[1] for x in lineList}

sender = udp_client.SimpleUDPClient(options['OSC_host'], int(options['OSC_port']))


def rearrange_music(title, tempo):
    if tempo == last_tempo_dict[title]:
        return

    last_tempo_dict[title] = tempo
    sender.send_message('/stop', 0)
    data = get_notes_and_durations(options[title], tempo)
    for k in data:
        sender.send_message('/' + k, data[k])
        time.sleep(0.05)
    time.sleep(1)
    sender.send_message('/start', 1)


def send_message(command, param):
    if command == 'play':
        title = param['title']
        tempo = round(music_tempo_dict[title] + float(param['tempo']), 3)
        data = get_notes_and_durations(options[title], tempo)
        for k in data:
            sender.send_message('/' + k, data[k])
            time.sleep(0.05)

        music_param = [int(param['sFlag']),
                       int(param['sHeight']),
                       float(param['sPosition']),
                       int(param['wFlag']),
                       int(param['wHeight']),
                       float(param['wPosition'])
                       ]

        sender.send_message('/music_param', music_param)
        sender.send_message('/start', 1)

    elif command == 'stop':
        sender.send_message('/stop', 0)
    elif command == 'reset':
        sender.send_message('/music_param', [0, 0, 0, 0, 0, 0])
    elif command == 'live':
        tempo, command = build_command()
        sender.send_message('/music_param', command)
    elif command == 'setting':
        title = param['title']
        tempo = round(music_tempo_dict[title] + float(param['tempo']), 3)

        music_param = [int(param['sFlag']),
                       int(param['sHeight']),
                       float(param['sPosition']),
                       int(param['wFlag']),
                       int(param['wHeight']),
                       float(param['wPosition'])
                       ]

        sender.send_message('/music_param', music_param)
        rearrange_music(title, tempo)
    elif command == 'test':
        sender.send_message('/notes', db.get_wi_fi_notes())
    elif command == 'edm':
        sender.send_message('/edm', 0)
    elif command == 'edm_notes':
        sender.send_message('/notes', db.get_wi_fi_notes())

def make_duration_dict(base_tempo=0.15):
    q = 2 * base_tempo
    c = 2 * q
    a = 4 * q
    d = 8 * q

    q_sq = round(q + base_tempo, 2)
    a_c = round(a + c, 2)
    c_q = round(c + q, 2)
    q_a = round(q + a, 2)
    c_q_sq = round(c + q + base_tempo, 2)
    sq_c = round(base_tempo + c, 2)

    return {'sq': base_tempo, 'q': q, 'c': c, 'a': a, 'd': d, 'q_sq': q_sq, 'a_c': a_c, 'c_q': c_q, 'q_a': q_a,
            'c_q_sq': c_q_sq, 'sq_c': sq_c}


def make_durations(durations, tempo):
    ret = []
    durations = durations.replace('[', '')
    durations = durations.replace(']', '')
    durations = durations.split(",")
    duration_dict = make_duration_dict(tempo)
    for duration in durations:
        if duration in duration_dict:
            ret.append(duration_dict[duration])

    return ret


def get_notes_and_durations(path, tempo):
    with open(path, 'r') as f:
        line_list = [x.rstrip('\n').split('=') for x in f]

    ret = {x[0]: x[1] for x in line_list}

    for x in ret:
        if 'durations' in x:
            ret[x] = make_durations(ret[x], tempo)
        else:
            ret[x] = ret[x].replace('[', '')
            ret[x] = ret[x].replace(']', '')
            ret[x] = [int(x) for x in ret[x].split(',')]

    for x in notes_and_durations_list:
        if x not in ret:
            ret[x] = [1]

    return ret


def build_command():
    random.seed(db.get_wi_fi_rssi_avg())
    s_height = random.randrange(-12, 13, 12)
    s_flag = 0 if db.get_num_of_wi_fi_dev() < int(options['Wi-Fi_num']) else 1
    s_position = db.get_wi_fi_vendor_ratio()

    random.seed(db.get_ble_rssi_avg())
    w_height = random.randrange(-12, 13, 12)
    w_flag = 0 if db.get_num_of_ble_dev() < int(options['BLE_num']) else 1
    w_position = db.get_ble_vendor_ratio()

    num_of_visitors = db.get_num_of_visitors()

    return 0.01 * num_of_visitors, [s_flag, s_height, s_position, w_flag, w_height, w_position]