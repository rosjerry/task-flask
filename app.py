from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash

app = Flask(__name__)


@app.route("/")
def hello_world():
    return "Hello, World!"


@app.route("/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json()

        if data is None:
            return (
                jsonify({"error": "Invalid JSON data or missing Content-Type header"}),
                400,
            )

        required_fields = ["name", "email", "password"]
        missing_fields = [field for field in required_fields if field not in data]

        if missing_fields:
            return (
                jsonify(
                    {
                        "error": "Missing required fields",
                        "missing_fields": missing_fields,
                    }
                ),
                400,
            )

        name = data["name"]
        email = data["email"]
        password = data["password"]

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        return (
            jsonify(
                {
                    "message": "User created successfully",
                    "user": {
                        "name": name,
                        "email": email,
                        "hashed_password": hashed_password,
                    },
                }
            ),
            201,
        )
    except Exception as e:
        app.logger.error(f"Error in signup: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/login")
def login():
    return "token"


if __name__ == "__main__":
    app.debug = True
    app.run(port=5000)
