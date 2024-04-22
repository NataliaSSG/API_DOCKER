# Natalia Salgado A01571008

from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import datetime

app = Flask(__name__)

# Generar key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Guardar tokens
tokens = set()

# ********************************** ROUTES **********************************
@app.route('/', methods=['GET'])
def hello_world():
    return jsonify(message='Wii si funciona')


@app.route('/generate_token', methods=['GET'])
def generate_token():
    token_data = datetime.datetime.now().isoformat().encode()
    token = cipher_suite.encrypt(token_data)
    tokens.add(token)
    return jsonify(token=token.decode())


@app.route('/validate_token', methods=['GET'])
def validate_token():
    token = request.json.get('token').encode()
    if token not in tokens:
        return jsonify(message='Invalid token'), 401
    return jsonify(message='Valid token'), 200


@app.route('/delete_token', methods=['DELETE'])
def delete_token():
    token = request.json.get('token').encode()
    if token in tokens:
        # print("lol")
        tokens.remove(token)
        return jsonify(message='Token deleted'), 200
    else:
        return jsonify(message='Invalid token'), 401


@app.route('/encrypt_message', methods=['POST'])
def encrypt_message():
    # Checar si se tiene un JSON
    if not request.is_json:
        return jsonify(message='Missing JSON in request'), 400

    json_data = request.get_json()

    # Checar si el message existe en el JSON
    if 'message' not in json_data:
        return jsonify(message="Missing 'message' in JSON"), 400

    message = json_data.get('message')
    headers = request.headers
    
    # Checar si el token existe en el header y regresarlo si si
    if not headers:
        return jsonify(message="Missing Authorization header"), 401
    
    bearer = headers.get('Authorization')
     
    # Checar si el token esta en el formato correcto como Bearer
    if not bearer or not bearer.startswith('Bearer '):
        return jsonify(message="Invalid Authorization header format"), 401
    
    token = bearer.split()[1].encode()
    print(token)
    # print("Current tokens:\n" + '\n'.join([t.decode() for t in tokens]))

    # Checar si el token es valido
    if token not in tokens:
        return jsonify(message="Invalid token"), 401

    # Encriptar el message
    cipher_suite = Fernet(key)
    encrypted_message = cipher_suite.encrypt(message.encode())

    return jsonify(encrypted_message=encrypted_message.decode()), 200


@app.route('/decrypt_message', methods=['POST'])
def decrypt_message():
    # Checar si se tiene un JSON
    if not request.is_json:
        return jsonify(message="Missing JSON in request"), 400

    json_data = request.get_json()

    # Checar si el message encriptado existe en el cuerpo del JSON
    if 'encrypted_message' not in json_data:
        return jsonify(message="Missing 'encrypted_message' in JSON"), 400

    encrypted_message = json_data.get('encrypted_message')
    headers = request.headers
    
    # Checar si el token existe en el header y regresarlo si si
    if not headers:
        return jsonify(message="Missing Authorization header"), 401
    
    bearer = headers.get('Authorization')
     
    # Checar si el token esta en el formato correcto como Bearer
    if not bearer or not bearer.startswith('Bearer '):
        return jsonify(message="Invalid Authorization header format"), 401
    
    token = bearer.split()[1].encode()
    print(token)

    # Checar si el token es valido
    if token not in tokens:
        return jsonify(message="Invalid token"), 401

    # Desencriptar el message
    cipher_suite = Fernet(key)
    decrypted_message = cipher_suite.decrypt(encrypted_message.encode())
    return jsonify(decrypted_message=decrypted_message.decode()), 200


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3000)