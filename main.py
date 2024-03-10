from flask import Flask, request, render_template, make_response
import pymongo
import bcrypt
from dbHelper import add, find, findOne, update
import datetime

mongoIP = 'INSERT HERE'
client = pymongo.MongoClient(mongoIP)
db = client["312"]

app = Flask(__name__)
 
@app.route("/")
def root():
    return render_template("index.html")

@app.route("/register")
def register():
    pass

@app.route("/login")
def login():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        col = db["Accounts"]
        d = {"username": username}
        filter = {"_id": 0, "username": 1, "password": 1, "salt": 1}
        details = findOne(col,d,filter)
        hashedPassword = bcrypt.hashpw(password.encode("utf-8"), details["salt"])
        if details["password"] == hashedPassword:
            response = Flask.make_response()
            authToken = bcrypt.gensalt()
            response.set_cookie("auth", authToken, max_age=3600, httponly=True)
            response.status_code = 200
            update(col, d, { "$set": {"authToken": bcrypt.hashpw(authToken), "expire": datetime.datetime.now() + datetime.timedelta(minutes=60)}})

            # notes for future changes: add html replacement of <div class="forms"> to <div class="forms" hidden> and
            # <div class="logged_in_stuff" hidden> to <div class="logged_in_stuff">. Also change {{user_name_here}} to username
            return response
        else:
            Flask.abort(404, "Login info wrong!")

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
    Flask.abort(404, "This page is not found.")

if __name__ == "__main__":
    app.run(debug=True,host='0.0.0.0',port=8080)