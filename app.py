from flask import Flask, request, jsonify
from routes.user import user_bp

app = Flask(__name__)

app.register_blueprint(user_bp, url_prefix="/user")


@app.route("/")
def hello_world():
    return "Hello, World!"

if __name__ == "__main__":
    app.debug = True
    app.run(port=5000)
