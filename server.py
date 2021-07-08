# FastAPI Server
import base64
import hmac
import hashlib
import json

from typing import Optional
from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response


app = FastAPI()

SECRET_KEY = "9ff8d3a69f2c6bf4305e09e75d626c816608490c7e9fec678a76cef1c976e9dd"
PASSWORD_SALT = "50a170b9f4a70ea11d3c6153421fa20c113c4e8984f5f14aeffdbc4b04b77f6b"

def verify_password(username: str , password : str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return hmac.compare_digest(password_hash, stored_password_hash)


users = {
    "alexey@user.com" : {
        "name": "Алексей",
        "password": "e8a587b2b92087a4e41025b5d7d37d689ddff9dcca788b2d7423d1f559991536",
        "balance" : 100_000,
    },
    "petr@user.com": {
        "name" :"Пётр",
        "password" : "a3a923a2159d5fb49152cc6d258ceab2e8808c5de0e87979fc8905d3892e3655",
        "balance" : 555_555,
    },
}

def sign_data(data:str) ->str:
    """returns signed data"""
    return hmac.new(SECRET_KEY.encode(), msg=data.encode(),
        digestmod=hashlib.sha256).hexdigest().upper()

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    if username_signed.count(".") != 1:
        return
    username_base64, sign = username_signed.split('.')
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username






@app.get("/")
def index_page(username: Optional[str] = Cookie(default= None)):
    with open("templates/login.html", 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type='text/html')
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(f"Hello, {users[valid_username]['name']}<br />"
                    f"Balance: {users[valid_username]['balance']}",
                     media_type='text/html')
    

@app.post("/login")
def process_login_page(data : dict = Body(...)):
    username = data["username"]
    password = data["password"]
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(json.dumps({
            "succes": False,
            "message" : "Я вас не знаю!",
        }), media_type='application/json')

    response = Response(
        json.dumps({
            "succes" : True,
            "message" : f"Hello, {user['name']}! <br />Balance: {user['balance']}",
        }), media_type='application/json')

    username_signed = base64.b64encode(username.encode()).decode() + '.' +\
        sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response