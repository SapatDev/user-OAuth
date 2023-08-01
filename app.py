from flask import Flask, request, jsonify
import boto3
import hmac
import hashlib
import base64

app = Flask(__name__)

POOL_ID='3d9752e9-d5a8-4bcf-9e77-52fba059da32'
CLIENT_ID = '5lcoco8uaalng85s3atpn19q06'
REGION_NAME = 'ap-south-1'
CLIENT_SECRET='17dqiq7v31bmnoqho3ssc8ug5odeu7q2tfimahrccqjvvaikonff'

ACCESS_KEY='AKIAYJJVOXVV6EBT7R4W'


def generate_secret_hash(client_id, client_secret, username):
    message = username + client_id
    digest = hmac.new(str(client_secret).encode('utf-8'), msg=str(message).encode('utf-8'), digestmod=hashlib.sha256).digest()
    return base64.b64encode(digest).decode()

def get_cognito_client():
    return boto3.client('cognito-idp', region_name=REGION_NAME)


@app.route('/signup', methods=['POST'])
def signup():
    cognito_client = get_cognito_client()

    # Get user details from the request
    username = request.json.get('username')
    password = request.json.get('password')
    secret_hash = generate_secret_hash(CLIENT_ID, CLIENT_SECRET, username)

    try:
        response = cognito_client.initiate_auth(
            ClientId=CLIENT_ID,
            UserPoolId=POOL_ID,
            SecretHash=secret_hash, 
            Username=username,
            Password=password,
            
            UserAttributes=[
                {
                    'Name': 'email',
                    'Value': username
                },
                 {
                    'Name': 'name',
                    'Value': 'kunal'
                }
            ]
        )
        return jsonify({'message': 'User signed up successfully'})
    except cognito_client.exceptions.UsernameExistsException:
        return jsonify({'error': 'Username already exists'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/login', methods=['POST'])
def signin():
    cognito_client = get_cognito_client()

    username = request.json.get('username')
    password = request.json.get('password')
    try:
        secret_hash = generate_secret_hash(CLIENT_ID, CLIENT_SECRET, username)
        response = cognito_client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
                'SECRET_HASH':secret_hash
                
            }
        )
        return jsonify({'message': 'Success', 'AccessToken': response['AuthenticationResult']['AccessToken']})
    except cognito_client.exceptions.NotAuthorizedException:
        return jsonify({'error': 'username or password Wrong'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80, debug=False)
