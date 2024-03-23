import os
import logging
import datetime
import functools
import jwt

from flask import Flask, jsonify, request, abort

JWT_SECRET = os.environ.get('JWT_SECRET', 'abc123abc1234')
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')

def _logger():
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    log = logging.getLogger(__name__)
    log.setLevel(LOG_LEVEL)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    log.addHandler(stream_handler)
    return log


LOG = _logger()
LOG.debug("Starting with log level: %s" % LOG_LEVEL )
APP = Flask(__name__)

def require_the_jwt(function):
    @functools.wraps(function)
    def decorated_function(*args, **kws):
        if not 'Authorization' in request.headers:
            abort(401)
        data = request.headers['Authorization']
        token = str.replace(str(data), 'Bearer ', '')
        
        try:
            jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        except: # pylint: disable=bare-except
            abort(401)

        return function(*args, **kws)
    return decorated_function


@APP.route('/', methods=['POST', 'GET'])
def health():
    return jsonify("Healthy")

@APP.route('/auth', methods=['POST'])
def auth():

    request_data = request.get_json()
    email = request_data.get('email')
    password = request_data.get('password')
    if not email:
        LOG.error("there isn't email provided")
        return jsonify({"message": "Missing parameter: email"}, 400)
    if not password:
        LOG.error("there isn't password provided")
        return jsonify({"message": "Missing parameter: password"}, 400)
    body = {'email': email, 'password': password}

    users_data = body
    return jsonify(token=get_jwt(users_data).decode('utf-8'))

@APP.route('/contents', methods=['GET'])
def decode_the_jwt():

    if not 'Authorization' in request.headers:
        abort(401)
    data = request.headers['Authorization']
    token = str.replace(str(data), 'Bearer ', '')
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except: # pylint: disable=bare-except
        abort(401)


    response = {'email': data['email'],
                'exp': data['exp'],
                'nbf': data['nbf'] 
                }
    return jsonify(**response)


def get_jwt(users_data):
    exp_time = datetime.datetime.utcnow() + datetime.timedelta(weeks=2)
    payload = {'exp': exp_time,
               'nbf': datetime.datetime.utcnow(),
               'email': users_data['email']}
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')


if __name__ == '__main__':
    APP.run(host='127.0.0.1', port=8080, debug=True)
