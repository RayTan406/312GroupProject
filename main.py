from flask import Flask, request, render_template, make_response
app = Flask(__name__)
 
@app.route("/")
def root():
    return render_template("index.html")

@app.after_request
def nosniff(response):
    if(request.path == "/static/clue.JPG" or request.path == "/static/style.css"):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.status_code = 200
        return response
    print(request.path)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.status_code = 200
    return response
if __name__ == "__main__":
    app.run(debug=True,host='0.0.0.0',port=8080)