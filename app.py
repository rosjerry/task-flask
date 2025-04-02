from flask import Flask, request, jsonify
import datetime
import boto3
from werkzeug.security import generate_password_hash, check_password_hash
from botocore.exceptions import ClientError
import uuid
from functools import wraps
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
)

app = Flask(__name__)
jwt = JWTManager(app)

app.config["SECRET_KEY"] = "983dfb25-16cc-42ee-8907-a6bc05900277"
app.config["JWT_BLACKLIST_ENABLED"] = True
app.config["JWT_BLACKLIST_TOKEN_CHECKS"] = ["access"]

jwt_blacklist = set()

table_name = "users_test_4"
gsi_name = "email_id_gsi_4"

dynamodb_client = boto3.client(
    "dynamodb",
    region_name="test",
    endpoint_url="http://localhost:8000",
    aws_access_key_id="test",
    aws_secret_access_key="test",
)


@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in jwt_blacklist


def create_table(table, gsi):
    try:
        dynamodb_client.create_table(
            TableName=table,
            KeySchema=[
                {"AttributeName": "id", "KeyType": "HASH"},
                {"AttributeName": "email", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "id", "AttributeType": "S"},
                {"AttributeName": "email", "AttributeType": "S"},
            ],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            GlobalSecondaryIndexes=[
                {
                    "IndexName": gsi,
                    "KeySchema": [
                        {"AttributeName": "email", "KeyType": "HASH"},
                        {"AttributeName": "id", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": 5,
                        "WriteCapacityUnits": 5,
                    },
                }
            ],
        )
        dynamodb_client.get_waiter("table_exists").wait(TableName=table)
        print(f"Table {table} created successfully.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceInUseException":
            print(f"Table {table} already exists.")
        else:
            raise e


def check_email_exists(email):
    try:
        response = dynamodb_client.query(
            TableName=table_name,
            IndexName=gsi_name,
            KeyConditionExpression="email = :email",
            ExpressionAttributeValues={":email": {"S": email}},
        )
        return response["Count"] > 0
    except ClientError as e:
        print(f"Error checking email existence: {e}")
        return False


def increment_login_counter(user_id, user_email):
    try:
        current_count_response = dynamodb_client.get_item(
            TableName=table_name,
            Key={"id": {"S": user_id}, "email": {"S": user_email}},
            ProjectionExpression="login_counter",
        )

        if (
            "Item" not in current_count_response
            or "login_counter" not in current_count_response["Item"]
        ):
            dynamodb_client.update_item(
                TableName=table_name,
                Key={"id": {"S": user_id}, "email": {"S": user_email}},
                UpdateExpression="SET login_counter = :start",
                ExpressionAttributeValues={":start": {"N": "1"}},
            )
            return jsonify({f"message": "Login counter initialized to 1."}), 200

        dynamodb_client.update_item(
            TableName=table_name,
            Key={"id": {"S": user_id}, "email": {"S": user_email}},
            UpdateExpression="ADD login_counter :increment",
            ExpressionAttributeValues={":increment": {"N": "1"}},
            ReturnValues="UPDATED_NEW",
        )
        return jsonify({f"message": "Login counter incremented."}), 200
    except ClientError as e:
        print(f"Error incrementing login counter: {e}")
        return None


@app.route("/")
def hello_world():
    create_table(table_name, gsi_name)
    return jsonify({"message": "Hello, World!"})


@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": "This is a protected route", "user": current_user}), 200


@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()

        if not data or "email" not in data or "password" not in data:
            return jsonify({"error": "Not enough credentials"}), 400

        if check_email_exists(data["email"]) == False:
            return jsonify({"error": "Email does not exist"}), 400

        response = dynamodb_client.query(
            TableName=table_name,
            IndexName=gsi_name,
            KeyConditionExpression="email = :email",
            ExpressionAttributeValues={":email": {"S": data["email"]}},
        )

        stored_id = response["Items"][0]["id"]["S"]
        stored_password_hash = response["Items"][0]["password_hash"]["S"]
        stored_email = response["Items"][0]["email"]["S"]

        if check_password_hash(stored_password_hash, data["password"]) == False:
            return jsonify({"error": "Invalid password"}), 400

        expiration_time = datetime.timedelta(days=1)
        token = create_access_token(
            identity=str(stored_id), expires_delta=expiration_time
        )

        if not token:
            return jsonify({"error": "Failed to auth"}), 500

        increment_login_counter(stored_id, stored_email)

        return token
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json()

        if (
            not data
            or "name" not in data
            or "email" not in data
            or "password" not in data
        ):
            return jsonify({"error": "Not enough credentials"}), 400

        if check_email_exists(data["email"]):
            return jsonify({"error": "Email already exists"}), 400

        user_uuid = str(uuid.uuid4().hex)
        hashed_password = generate_password_hash(
            data["password"], method="pbkdf2:sha256"
        )

        user_data = {
            "id": user_uuid,
            "name": data["name"],
            "email": data["email"],
            "password_hash": hashed_password,
        }

        db_response = dynamodb_client.put_item(
            TableName=table_name,
            Item={
                "id": {"S": user_data["id"]},
                "name": {"S": user_data["name"]},
                "email": {"S": user_data["email"]},
                "password_hash": {"S": user_data["password_hash"]},
            },
        )

        if db_response["ResponseMetadata"]["HTTPStatusCode"] != 200:
            return jsonify({"error": "Failed to create user"}), 500

        return {"message": "User created successfully", "status": 201}
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    try:
        jti = get_jwt()["jti"]
        jwt_blacklist.add(jti)
        return jsonify({"msg": "Successfully logged out"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)
