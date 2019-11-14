from flask import Flask, render_template, request
from flask_restful import Resource, Api
from flask_restful import reqparse
from flask_socketio import SocketIO, join_room, leave_room
import time
import threading
from radioinfo import *
from dbconnection import Database, Config
import logging


app = Flask(__name__)
app.config['SECRET_KEY'] = 'famous'
api = Api(app)
socketio = SocketIO(app)

monitors = {RadioInfo.WI_FI_TYPE: None, RadioInfo.BLE_TYPE: None, RadioInfo.CAM_TYPE: None}
start_event = threading.Event()
MIDDLEWARE_NAMESPACE = '/middleware'
ROOM_NAME = 'monitors'
TIMEOUT = 15
SEQUENCE = 0
db = Database(Config())
radio_info_list = RadioInfoList()

parser = reqparse.RequestParser()
parser.add_argument('wi-fi', type=str, action='append')
parser.add_argument('ble', type=str, action='append')
parser.add_argument('cam', type=int)
parser.add_argument('seq', type=int)
parser.add_argument('timeout', type=int)


class WiFi(Resource):
    def post(self):
        try:
            args = parser.parse_args()

            _wi_fi = args['wi-fi']
            _seq = args['seq']

            insert_data(_seq, RadioInfo.WI_FI_TYPE, _wi_fi)

            return {'wi-fi': _wi_fi}, 201
        except Exception as e:
            logging.error(e)
            return {'error': str(e)}, 500


class BLE(Resource):
    def post(self):
        try:
            args = parser.parse_args()

            _ble = args['ble']
            _seq = args['seq']

            insert_data(_seq, RadioInfo.BLE_TYPE, _ble)

            return {'ble': _ble}, 201
        except Exception as e:
            logging.error(e)
            return {'error': str(e)}, 500


class CAMERA(Resource):
    def post(self):
        try:
            args = parser.parse_args()

            _cam = args['cam']
            _seq = args['seq']

            insert_data(_seq, RadioInfo.CAM_TYPE, _cam)

            return {'cam': _cam}, 201
        except Exception as e:
            logging.error(e)
            return {'error': str(e)}, 500


api.add_resource(WiFi, '/wi-fi')
api.add_resource(BLE, '/ble')
api.add_resource(CAMERA, '/cam')


def insert_data(seq, monitor_type, data):
    radio_info_list.add_data(seq=seq, monitor_type=monitor_type, result=data)
    if not radio_info_list.is_end(seq):
        return

    print('seq: {} is end'.format(seq))
    query, args = radio_info_list.get_query(seq)

    db.exec_query(query, args)
    radio_info_list.remove(seq)


@socketio.on('monitor_online', namespace=MIDDLEWARE_NAMESPACE)
def handle_monitor_online(data):
    monitor_type = data['type'].upper()
    if monitor_type not in [RadioInfo.WI_FI_TYPE, RadioInfo.BLE_TYPE, RadioInfo.CAM_TYPE]:
        raise ('Invalid monitor type: ' + monitor_type)

    monitors[monitor_type] = request.sid
    join_room(room=ROOM_NAME, sid=request.sid)

    if is_all_online():
        start_event.set()


@socketio.on('connect')
def connect():
    if is_all_online():
        raise socketio.exceptions.ConnectionError

    print('connect: ' + request.sid)


@socketio.on('disconnect')
def disconnect():
    print('disconnect: ' + request.sid)
    for monitor_type in monitors:
        if monitors[monitor_type] == request.sid:
            monitors[monitor_type] = None
            print('{} disconnected'.format(monitor_type))
            start_event.clear()
            send_stop()


@app.route('/')
def hello():
    return render_template('index.html')


@app.route('/stop')
def manual_stop():
    send_stop()
    start_event.clear()
    print('Manual stop')
    return 'stop'


@app.route('/start')
def manual_start():
    start_event.set()
    print('Manual start')
    return 'start'


@app.route('/setting')
def setting():
    global TIMEOUT, SEQUENCE
    _timeout = request.args.get('timeout')
    _seq = request.args.get('seq')
    TIMEOUT = _timeout if _timeout else TIMEOUT
    SEQUENCE = _seq if _seq else SEQUENCE
    return {'timeout': TIMEOUT, 'seq': SEQUENCE}


@app.route('/statutes')
def print_radion_info():
    return radio_info_list.to_dict()


def send_stop():
    socketio.emit('stop_collecting', {'command': 'stop'}, namespace=MIDDLEWARE_NAMESPACE, room=ROOM_NAME)
    print('Send stop')


def send_start(timeout):
    global SEQUENCE
    socketio.emit('start_collecting', {'seq': SEQUENCE, 'timeout': timeout},
                  namespace=MIDDLEWARE_NAMESPACE,
                  room=ROOM_NAME)
    print('Send start/{}/{}'.format(TIMEOUT, SEQUENCE))
    SEQUENCE += 1


def is_all_online():
    return None not in monitors.values()


def command_thread_func():
    while True:
        if not start_event.is_set():
            time.sleep(0.25)
            continue

        send_start(timeout=TIMEOUT)
        time.sleep(TIMEOUT + 1)

    logging.info('Command thread is killed...')


command_thread = threading.Thread(target=command_thread_func, daemon=True)
command_thread.start()

socketio.run(app)