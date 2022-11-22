import requests
from flask import Flask, session, abort, redirect, request

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)



from flask_cors import CORS
app = Flask(__name__)
CORS(app)
cors = CORS(app, resources={r"/api/*": {"origins": "*"}})


@app.route('/signature', methods=['POST'])
def signature():
    try:
        req = request.get_json()
        payload = req['payload']
        private_hex = req['private_hex']

        # private_hex = "dCQg3VMoqJpJWrWiyjjtmkXAqNQaWXD8iEescWgqAEBsrTaie2RdSim2nmsHsSnqz8yHt8qQiAzVk3mHfT1LaZP"
        private_bytes = bytes.fromhex(private_hex)
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)

        # inp = open('payload.json').read()
        inp = payload

        signed_bytes = private_key.sign(bytes(inp, 'utf-8'))
        new_data = {"signature": signed_bytes.hex()}
        print("Signature: ", signed_bytes.hex())
        return new_data
    except Exception as e:
        return str(e), 400



if __name__ == '__main__':
    app.run(port=3000)