from flask import Flask, request, jsonify
import boto3
from werkzeug.security import generate_password_hash
from botocore.exceptions import ClientError
import uuid

app = Flask(__name__)

table_name = "users_test_3"
gsi_name = "email_id_gsi_3"

dynamodb_client = boto3.client(
    'dynamodb',
    region_name='test',
    endpoint_url='http://localhost:8000',
    aws_access_key_id='test',
    aws_secret_access_key='test'
)

def create_table(table, gsi):
    try:
        dynamodb_client.create_table(
            TableName=table,
            KeySchema=[
                {'AttributeName': 'id', 'KeyType': 'HASH'},
                {'AttributeName': 'email', 'KeyType': 'RANGE'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'id', 'AttributeType': 'S'},
                {'AttributeName': 'email', 'AttributeType': 'S'}
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            },
            GlobalSecondaryIndexes=[
                {
                    'IndexName': gsi,
                    'KeySchema': [
                        {'AttributeName': 'email', 'KeyType': 'HASH'},
                        {'AttributeName': 'id', 'KeyType': 'RANGE'}
                    ],
                    'Projection': {
                        'ProjectionType': 'ALL'
                    },
                    'ProvisionedThroughput': {
                        'ReadCapacityUnits': 5,
                        'WriteCapacityUnits': 5
                    }
                }
            ]
        )
        dynamodb_client.get_waiter('table_exists').wait(TableName=table)
        print(f"Table {table} created successfully.")
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceInUseException':
            print(f"Table {table} already exists.")
        else:
            raise e

def check_email_exists(email):
    try:
        response = dynamodb_client.query(
            TableName=table_name,
            IndexName=gsi_name,
            KeyConditionExpression='email = :email',
            ExpressionAttributeValues={':email': {'S': email}}
        )
        print(f"Query response: {response}")
        print(response['Count'] > 0)
        return response['Count'] > 0
    except ClientError as e:
        print(f"Error checking email existence: {e}")
        return False

@app.route("/")
def hello_world():
    create_table(table_name, gsi_name)
    return jsonify({"message": "Hello, World!"})

@app.route("/login", methods=["POST"])
def login():
    return "token"

@app.route("/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json()
        
        if not data or 'name' not in data or 'email' not in data or 'password' not in data:
            return jsonify({'error': 'Not enough credentials'}), 400
        
        if check_email_exists(data['email']):
            return jsonify({'error': 'Email already exists'}), 400
        
        user_uuid = str(uuid.uuid4().hex)
        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        
        user_data = {
            'id': user_uuid,
            'name': data['name'],
            'email': data['email'],
            'password_hash': hashed_password
        }
        
        db_response = dynamodb_client.put_item(
            TableName=table_name,
            Item={
                'id': {'S': user_data['id']},
                'name': {'S': user_data['name']},
                'email': {'S': user_data['email']},
                'password_hash': {'S': user_data['password_hash']}
            }
        )
        
        if db_response['ResponseMetadata']['HTTPStatusCode'] != 200:
            return jsonify({'error': 'Failed to create user'}), 500
        
        return {
            'message': 'User created successfully',
            'status': 201
        }
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == "__main__":
    app.debug = True
    app.run(port=5000)
