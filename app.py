from flask import Flask, render_template, url_for

app = Flask(__name__)

UPLOAD_FOLDER = 'Images/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/')
def index():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
