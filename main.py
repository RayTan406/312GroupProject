from flask import Flask, request, render_template, make_response, redirect, url_for, flash
import pymongo
from dbHelper import add, find, findOne, update
from datetime import datetime, timedelta
import html
import hashlib
import os
import bcrypt

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
 
@app.route("/")
def root():
    loggedin = False
    user_name_here = ""
    auth_token = request.cookies.get("authToken")
    TokensCol = db["Tokens"]
    if auth_token:
        auth = hashlib.sha256(auth_token.encode()).hexdigest()
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
        repeatPassword = request.form.get("confirmpassword")
        AccountCol = db["Accounts"]
        account = AccountCol.find_one({"username": username})
        if account:
            flash("Username taken", "error")
        else:
            if repeatPassword == password:
                if validate_password(password):
                    salt = bcrypt.gensalt()
                    hashed_password = bcrypt.hashpw(password.encode(), salt)
                    user_info = {
                        "username": username,
                        "password": hashed_password,
                        "salt": salt
                    }
                    AccountCol.insert_one(user_info)
                    flash("Account created", "success")
                else:
                    flash("Password needs: 1 uppercase, 1 lowercase, 1 special character, and one number", "error")
            else:
                flash("Passwords don't match", "error")
    return redirect(url_for("root"))

@app.route("/login", methods=["POST"])
def login():
    if request.method == "POST":
        username = html.escape(request.form.get('username'))
        password = request.form.get('password')
        AccountCol = db["Accounts"]
        TokensCol = db["Tokens"]
        account = AccountCol.find_one({"username": username})
        if account:
            hashed_password = account["password"]
            if bcrypt.checkpw(password.encode(), hashed_password):
                auth_token = bcrypt.gensalt().decode()
                hashed = hashlib.sha256(auth_token.encode()).hexdigest()
                expire = datetime.now() + timedelta(minutes=60)
                TokensCol.update_one({"username": username}, {"$set": {"authToken": hashed, "expire": expire}}, upsert=True)
                response = make_response(redirect(url_for("root")))
                response.set_cookie('authToken', auth_token, expires=expire, httponly=True, samesite='Strict')
                return response
            else:
                flash("Invalid credentials", "error")
        else:
            flash("Invalid credentials", "error")

    return redirect(url_for("root"))

@app.route("/logout", methods=["POST"])
def logout():
    response = make_response(redirect(url_for("root")))
    response.delete_cookie("authToken")
    return response

@app.route("/chatroom", methods=["GET"])
def chatroom():
    return render_template("chatroom.html")

@app.route("/chatroom-message", methods=["POST"])
def chatroom_post():
    AccountCol = db["Accounts"]
    TokensCol = db["Tokens"]
    MessagesCol = db["Messages"]
    IDCol = db["UID"]

    # Get unique ID from database and increment it by 1
    get_id = IDCol.find_one({"unique_id": {"$exists": True}})
    if get_id is None:
        IDCol.insert_one({"unique_id": 1})
    get_id = IDCol.find_one({"unique_id": {"$exists": True}})
    uid = get_id["unique_id"]
    uid += 1
    IDCol.update_one({"_id": get_id["_id"]}, {"$set": {"unique_id": uid}})

    #check if user authenticated
    found_user = ""
    auth_token = request.cookies.get("authToken")
    if auth_token:
        auth = hashlib.sha256(auth_token.encode()).hexdigest()
        token = TokensCol.find_one({"authToken": auth})
        if token and token["expire"] > datetime.now():
            found_user = token["username"]

    message_json = json.loads(request.body)
    sent_message = html.escape(message_json["message"])
    


            





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
    secret_key = os.urandom(24)
    secret_key = str(secret_key)
    app.secret_key = secret_key
    app.run(debug=True,host='0.0.0.0',port=8080)