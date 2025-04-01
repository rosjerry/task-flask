from flask import Flask, request, jsonify
from routes.user import user_bp
import boto3
from werkzeug.security import generate_password_hash

app = Flask(__name__)

users_table = "users_test_2"
users_table_gsi = "email_id_gsi_2"

dynamodb = boto3.resource(
    'dynamodb',
    region_name='test',
    endpoint_url='http://localhost:8000',
    aws_access_key_id='test',
    aws_secret_access_key='test'
)

# app.register_blueprint(user_bp, url_prefix="/user")

@app.route("/")
def test_dynamodb():
    try:
        table = dynamodb.Table(users_table)        
        try:
            table = dynamodb.create_table(
                TableName=users_table,
                KeySchema=[
                    {
                        'AttributeName': 'id',
                        'KeyType': 'HASH'
                    },
                    {
                        'AttributeName': 'email',
                        'KeyType': 'RANGE'
                    }
                ],
                AttributeDefinitions=[
                    {
                        'AttributeName': 'id',
                        'AttributeType': 'S'
                    },
                    {
                        'AttributeName': 'email',
                        'AttributeType': 'S'
                    },
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
            table.wait_until_exists()
        except dynamodb.meta.client.exceptions.ResourceInUseException:
            pass

        table.put_item(
            Item={
                'id': '1',
                'name': 'Test Item',
                'email': 'user@example.com',
                'password_hash': 'hashed_password',
            }
        )

        # Example: Get an item
        response = table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('id').eq('1')
        )
        
        items = response.get('Items', [])
        item = items[0] if items else "Item not found"
        return f"Connected successfully! Retrieved item: {item}"
    
    except Exception as e:
        return f"Error connecting to DynamoDB: {str(e)}"

@app.route("/login")
def login():
    return "token"

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
        user_bp.logger.error(f"Error in signup: {str(e)}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.debug = True
    app.run(port=5000)
