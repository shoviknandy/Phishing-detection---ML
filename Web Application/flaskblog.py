from flask import Flask, render_template, request
from app import *

app = Flask(__name__,static_url_path="/static")

@app.route('/',methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
def home():
    result = ""
    if request.method == 'POST':
        url = request.form["url"]
        result = check(url)
    return render_template('home.html', data=result)


if __name__ == "__main__":
    app.run(debug=True)
