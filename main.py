
import os
import pathlib

import requests
from flask import Flask, session, abort, redirect, request
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

from random import randint
from database import find, add
from utils import sendemail


from base64 import encode
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

# allow all cross origin requests


from pprint import pprint


from flask_cors import CORS
app = Flask(__name__)
CORS(app)
cors = CORS(app, resources={r"/api/*": {"origins": "*"}})


app.secret_key = "CodeSpecialist.com"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

api_key = '51f2cf5c-54af-4be5-b08f-e7f6b05b08f4'


GOOGLE_CLIENT_ID = "112204471961-strsij09f31id3dvj0c0v7b8a89jfuqt.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="https://colonyapp.herokuapp.com/callback"
)



def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper


@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    check_email = find({"email":id_info.get("email")})
    if not check_email:
        add({"email":id_info.get("email")})

    return redirect("/protected_area")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/loginwithgoogle")


@app.route("/loginwithgoogle")
def index():
    return "Hello World <a href='/login'><button>Login</button></a>"


@app.route("/protected_area")
@login_is_required
def protected_area():
    return f"Hello {session['name']}! <br/> <a href='/logout'><button>Logout</button></a>"



@app.route('/api/signup', methods=['POST'])
def apisignup():

    if request.headers.get('api-key') == api_key:
        req = request.get_json()
        email = req['email']
        password = req['password']
        check = find({'email':email})
        if check:
            response = {"status": "error", "message": "User already exists"}
        else:
            code = randint(1000, 9999)
            data = {'email':email, 'password':password, 'code':code}
            add(data)
            email_message = f"Your verification code is {code}"
            sendemail(email, "Colony Verfication Code", email_message)
            response = {"status": "success", "message": "code sent to email"}
    else:
        response = {"status": "error", "message": "Invalid API Key"}

    return response

@app.route('/api/login', methods=['POST'])
def apilogin():

    if request.headers.get('api-key') == api_key:
        req = request.get_json()
        email = req['email']
        password = req['password']
        check = find({'email':email, 'password':password})
        if check:
            response = {"status": "success", "message": "login authentication successful"}
        else:
            response = {"status":"error", "message":"No user was found with this credentials"}
    else:
        response = {"status": "error", "message": "Invalid API Key"}

    return response



@app.route('/api/verifycode', methods=['POST'])
def verifycode():
    if request.headers.get('api-key') == api_key:
        req = request.get_json()
        email = req['email']
        code = req['code']
        check = find({'email':email, 'code':int(code)})
        if check:
            response = {"status": "success", "message": "User verified"}
        else:
            response = {"status": "error", "message": "Invalid code"}
    else:
        response = {"status": "error", "message": "Invalid API Key"}

    return response





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