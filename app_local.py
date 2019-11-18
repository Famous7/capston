from flask import Flask, render_template, request
import osccontroller


app = Flask(__name__)


@app.route('/music/play', methods=['POST'])
def play():
    data = request.form.to_dict()

    if 'sFlag' not in data:
        data['sFlag'] = 0
    if 'wFlag' not in data:
        data['wFlag'] = 0

    osccontroller.send_message('play', data)
    return '', 204


@app.route('/music/stop', methods=['GET'])
def stop():
    osccontroller.send_message('stop', None)
    return '', 204


@app.route('/music/live', methods=['GET'])
def live():
    osccontroller.send_message('live', None)
    return '', 204


@app.route('/music/reset', methods=['GET'])
def reset():
    osccontroller.send_message('reset', None)
    return '', 204


@app.route('/music/setting', methods=['POST'])
def setting():
    data = request.form.to_dict()

    if 'sFlag' not in data:
        data['sFlag'] = 0
    if 'wFlag' not in data:
        data['wFlag'] = 0

    osccontroller.send_message('setting', data)
    return '', 204


@app.route('/')
def index():
    return render_template('index2.html')


@app.route('/test')
def index2():
    osccontroller.send_message('test', 0)
    return 'Hello'


@app.route('/edm')
def edm():
    osccontroller.send_message('edm', 0)
    return '', 204


@app.route('/music/notes')
def notes():
    osccontroller.send_message('edm_notes', 0)
    return '', 204



app.run()