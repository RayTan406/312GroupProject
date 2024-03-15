from flask import Flask, request, render_template, make_response, redirect, url_for
import pymongo
from dbHelper import add, find, findOne, update
from datetime import datetime, timedelta
import html
import hashlib
import os

client = pymongo.MongoClient("mongo")
db = client["CLUELESS"]

def validate_password(password):
    specialChar = {'!', '@', '#', '$', '%', '^', '&', '(', ')', '-', '_', '='}
    validChar = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&()-_=')
    if len(password) < 8:
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char in specialChar for char in password):
        return False
    if not all(char in validChar for char in password):
        return False
    return True

app = Flask(__name__)
 
@app.route("/", methods=["GET"])
def root():
    loggedin = False
    user_name_here = ""
    if request.method == "GET":
        TokensCol = db["Tokens"]
        auth_token = request.cookies.get('authToken')
        if auth_token:
            auth = hashlib.sha256(auth_token.encode()).hexdigest()  # Encode the token before hashing
            token = TokensCol.find_one({"authToken": auth})
            if token and token["expire"] > datetime.now():
                user_name_here = token["username"]
                loggedin = True
    return render_template("index.html", user_name_here=user_name_here, loggedin=loggedin)

@app.route("/register", methods=["POST"])
def register():
    if request.method == "POST":
        username = html.escape(request.form.get('username'))
        password = request.form.get('password')
        repeatPassword = request.form.get("repeat password")
        AccountCol = db["Accounts"]
        account = AccountCol.find_one({"username": username})
        if account:
            return redirect(url_for(root, registerError = "Username taken"))
        else:
            if repeatPassword == password:
                if(validate_password(password)):
                    salt = os.urandom(16)
                    salted_password = password.encode() + salt
                    hashed_password = hashlib.sha256(salted_password).hexdigest()
                    user_info = {
                        "username": username,
                        "password": hashed_password,
                        "salt": salt
                    }
                    AccountCol.insert_one(user_info)
                    return redirect(url_for("/", registerError = "Account created"))
                else:
                    return redirect(url_for("/", registerError = "Password needs: 1 uppercase, 1 lowercase, 1 special character, and one number"))
            else:
                return redirect(url_for("/", registerError = "Passwords don't match"))

@app.route("/login", methods=["POST"])
def login():
    if request.method == "POST":
        username = html.escape(request.form.get('username'))
        password = request.form.get('password')
        AccountCol = db["Accounts"]
        TokensCol = db["Tokens"]
        account = AccountCol.find_one({"username": username})
        if account:
            salt = account["salt"]
            salted_password = password.encode() + salt
            hashed_password = hashlib.sha256(salted_password).hexdigest()
            if hashed_password == account["password"]:
                auth = os.urandom(16)
                authHashed = hashlib.sha256(auth).hexdigest()
                token = TokensCol.find_one({"username": username})
                if token:
                    expire = datetime.now() + timedelta(minutes = 60)
                    TokensCol.update_one({"username": username}, {"$set":{"authToken": authHashed, "expire": expire}})
                else:
                    expire = datetime.now() + timedelta(minutes = 60)
                    TokensCol.insert_one({"username":username, "authToken": authHashed, "expire": expire})
                response = make_response(url_for("/"))
                response.set_cookie('authToken', auth, expires=datetime.now() + timedelta(minutes=60), httponly=True, samesite='Strict')
                return response
        else:
            return redirect(url_for("/", error = "Invalid Login"))


@app.after_request
def nosniff(response):
    paths200OK = ["/static/clue.JPG", "/static/style.css"]
    if(request.path in paths200OK):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.status_code = 200
        return response
    print(request.path)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.status_code = 200
    return response

@app.errorhandler(404)
def page_not_found(error):
    return "This page is not found.", 404

if __name__ == "__main__":
    app.run(debug=True,host='0.0.0.0',port=8080)