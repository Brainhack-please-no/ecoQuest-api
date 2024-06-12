# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from datetime import datetime, timezone, timedelta

from functools import wraps
import json

from dotenv import load_dotenv

from flask import request, jsonify
from flask_restx import Api, Resource, fields

from werkzeug.utils import secure_filename

import requests
import base64
import jwt
import os

from .models import db, Users, JWTTokenBlocklist
from .config import BaseConfig
import requests

rest_api = Api(version="1.0", title="Users API")
load_dotenv('.env__')

"""
    Flask-Restx models for api request and response data
"""

signup_model = rest_api.model('SignUpModel', {"username": fields.String(required=True, min_length=2, max_length=32),
                                              "password": fields.String(required=True, min_length=4, max_length=16)
                                              })

login_model = rest_api.model('LoginModel', {"username": fields.String(required=True, min_length=2, max_length=32),
                                            "password": fields.String(required=True, min_length=4, max_length=16)
                                            })

user_edit_model = rest_api.model('UserEditModel', {"userID": fields.String(required=True, min_length=1, max_length=32),
                                                   "username": fields.String(required=True, min_length=2, max_length=32),

                                                   })


"""
   Helper function for JWT token required
"""


def token_required(f):

    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if "authorization" in request.headers:
            token = request.headers["authorization"]

        if not token:
            return {"success": False, "msg": "Valid JWT token is missing"}, 400

        try:
            data = jwt.decode(token, BaseConfig.SECRET_KEY,
                              algorithms=["HS256"])
            current_user = Users.get_by_username(data["username"])

            if not current_user:
                return {"success": False,
                        "msg": "Sorry. Wrong auth token. This user does not exist."}, 400

            token_expired = db.session.query(
                JWTTokenBlocklist.id).filter_by(jwt_token=token).scalar()

            if token_expired is not None:
                return {"success": False, "msg": "Token revoked."}, 400

            if not current_user.check_jwt_auth_active():
                return {"success": False, "msg": "Token expired."}, 400

        except:
            return {"success": False, "msg": "Token is invalid"}, 400

        return f(current_user, *args, **kwargs)

    return decorator


"""
    Flask-Restx routes
"""


@rest_api.route('/api/users/register')
class Register(Resource):
    """
       Creates a new user by taking 'signup_model' input
    """

    @rest_api.expect(signup_model, validate=True)
    def post(self):

        req_data = request.get_json()

        _username = req_data.get("username")
        _password = req_data.get("password")

        user_exists = Users.get_by_username(_username)
        if user_exists:
            return {"success": False,
                    "msg": "Email already taken"}, 400

        new_user = Users(username=_username)

        new_user.set_password(_password)
        new_user.save()

        return {"success": True,
                "userID": new_user.id,
                "msg": "The user was successfully registered"}, 200


@rest_api.route('/api/users/login')
class Login(Resource):
    """
       Login user by taking 'login_model' input and return JWT token
    """

    @rest_api.expect(login_model, validate=True)
    def post(self):

        req_data = request.get_json()

        _username = req_data.get("username")
        _password = req_data.get("password")

        user_exists = Users.get_by_username(_username)

        if not user_exists:
            return {"success": False,
                    "msg": "This username does not exist."}, 400

        if not user_exists.check_password(_password):
            return {"success": False,
                    "msg": "Wrong credentials."}, 400

        # create access token uwing JWT
        token = jwt.encode({'username': _username, 'exp': datetime.utcnow(
        ) + timedelta(minutes=30)}, BaseConfig.SECRET_KEY)

        user_exists.set_jwt_auth_active(True)
        user_exists.save()

        return {"success": True,
                "token": token,
                "user": user_exists.toJSON()}, 200


@rest_api.route('/api/users/edit')
class EditUser(Resource):
    """
       Edits User's username or password or both using 'user_edit_model' input
    """

    @rest_api.expect(user_edit_model)
    @token_required
    def post(self, current_user):

        req_data = request.get_json()

        _new_username = req_data.get("username")

        if _new_username:
            self.update_username(_new_username)

        self.save()

        return {"success": True}, 200


@rest_api.route('/api/users/logout')
class LogoutUser(Resource):
    """
       Logs out User using 'logout_model' input
    """

    @token_required
    def post(self, current_user):

        _jwt_token = request.headers["authorization"]

        jwt_block = JWTTokenBlocklist(
            jwt_token=_jwt_token, created_at=datetime.now(timezone.utc))
        jwt_block.save()

        self.set_jwt_auth_active(False)
        self.save()

        return {"success": True}, 200


@rest_api.route('/api/sessions/oauth/github/')
class GitHubLogin(Resource):
    def get(self):
        code = request.args.get('code')
        client_id = BaseConfig.GITHUB_CLIENT_ID
        client_secret = BaseConfig.GITHUB_CLIENT_SECRET
        root_url = 'https://github.com/login/oauth/access_token'

        params = {'client_id': client_id,
                  'client_secret': client_secret, 'code': code}

        data = requests.post(root_url, params=params, headers={
            'Content-Type': 'application/x-www-form-urlencoded',
        })

        response = data._content.decode('utf-8')
        access_token = response.split('&')[0].split('=')[1]

        user_data = requests.get('https://api.github.com/user', headers={
            "Authorization": "Bearer " + access_token
        }).json()

        user_exists = Users.get_by_username(user_data['login'])
        if user_exists:
            user = user_exists
        else:
            try:
                user = Users(
                    username=user_data['login'], email=user_data['email'])
                user.save()
            except:
                user = Users(username=user_data['login'])
                user.save()

        user_json = user.toJSON()

        token = jwt.encode({"username": user_json['username'], 'exp': datetime.utcnow(
        ) + timedelta(minutes=30)}, BaseConfig.SECRET_KEY)
        user.set_jwt_auth_active(True)
        user.save()

        return {"success": True,
                "user": {
                    "_id": user_json['_id'],
                    "email": user_json['email'],
                    "username": user_json['username'],
                    "token": token,
                }}, 200


@rest_api.route('/api/users/data/<int:user_id>')
class UserData(Resource):
    @token_required
    def get(self, user_id):
        user = Users.query.get(user_id)
        if user is None:
            return {"error": "User not found"}, 404
        return {"id": user.id, "username": user.username, "points": user.points, "xp": user.xp, "level": user.level, "family_size": user.family_size}, 200

    @token_required
    def post(self, user_id):
        user = Users.query.get(user_id)
        if user is None:
            return {"error": "User not found"}, 404

        data = request.get_json()
        user.id = data.get('id', user.id)
        user.username = data.get('username', user.username)
        user.points = data.get('points', user.points)
        user.xp = data.get('xp', user.xp)
        user.level = data.get('level', user.level)
        user.family_size = data.get('family_size', user.family_size)
        user.save()

        return {"id": user.id, "name": user.name, "points": user.points, "xp": user.xp, "level": user.level, "family_size": user.family_size}, 200

@rest_api.route('/api/users/')
@rest_api.route('/api/leaderboard')
class Leaderboard(Resource):
    @token_required
    def get(self, user_id):
        users = Users.query.all()
        leaderboard = [{"id": user.id, "username": user.username, "points": user.points, "xp": user.xp, "level": user.level, 'family_size': user.family_size} for user in users]
        leaderboard.sort(key=lambda user: -user["points"])
        return jsonify(leaderboard)


@rest_api.route('/api/scanner')
class Scanner(Resource):
    @token_required
    def post(self, user_id):
        if 'photo' not in request.files:
            return jsonify({"error": "No photo provided"})

        file = request.files['photo']
        if file.filename == '':
            return jsonify({"error": "No selected file"})

        # Convert the image file to a base64 string
        image_string_b64 = base64.b64encode(file.read()).decode('utf-8')

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.getenv('API_KEY')}"
        }

        payload = {
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{image_string_b64}"
                            }
                        }
                    ]
                },
                {
                    "role": "system",
                    "content": [
                        {
                            "type": "text",
                            # "text": "You will be presented with an image containing a receipt. Please parse the receipt and respond only with the format below: [{receipt_item: 'raw_receipt_name', value: 'no.of.items', name: 'name'}]. Based on the receipt item, find the closest corresponding actual item name as the name key, and the raw name as receipt_item. If the image does not contain a receipt, return an empty array. Do not respond to anything else.",
                            "text": """
You are an AI trained to process and analyze receipts. Your task is to:

1. *Scan the Receipt:*
   - Read and extract all text from the provided receipt image or digital copy.
   - Identify individual product entries on the receipt, including the product name, quantity, and price.

2. *Identify Products:*
   - Match each product entry with the closest known real-life product from a comprehensive database. Consider factors such as product name similarity, category, and price range.
   - If multiple matches are possible, select the most likely option based on contextual clues and common purchasing patterns.

3. *Evaluate Environmental Metrics:*
   - For each identified product, determine the type and quantity of plastic packaging used.
   - Assess the eco-friendliness of the product packaging and assign an eco-friendliness score out of 5, considering factors such as the use of recycled materials, recyclability, biodegradability, and overall environmental impact.

4. *Output the Results:*
   - Generate a structured list of the identified products with the following details:
     - Original product name from the receipt
     - Closest known real-life product name
     - Category of the product
     - Quantity
     - Price per unit (if available)
     - Total price
     - Number of plastic packaging used
     - Eco-friendliness score (0 - 1)

5. *Tabulate Metrics:*
   - Provide a summary of the following metrics:
     - No. of items with plastic-free packaging
     - No. of plastic bags used
     - No. of clothing items bought from sustainable sources

### Example Output:
{
details: [
    {
        'original_name': 'Organic Bananas',
        'matched_name': 'Chiquita Organic Bananas',
        'category': 'Produce',
        'quantity': '1 bunch',
        'price_per_unit': '$0.59',
        'total_price': '$1.77',
        'plastic_packaging_count': 0,
        'eco-friendliness_score': 1
    },
    {
        'original_name': '2L Diet Soda',
        'matched_name': 'Coca-Cola Diet Soda 2L',
        'category': 'Beverages',
        'quantity': '1 bottle',
        'price_per_unit': '$1.99',
        'total_price': '$1.99',
        'plastic_packaging_count': 1,
        'eco-friendliness_score': 0.5
    },
    {
        'original_name': 'Unknown Item',
        'matched_name': 'N/A',
        'category': 'N/A',
        'quantity': 'N/A',
        'price_per_unit': 'N/A',
        'total_price': 'N/A',
        'plastic_packaging_count': 0,
        'eco-friendliness_score': 0
    }
],
metrics: {
    'plastic_free_packaging': 1,
    'plastic_bags_used': 1,
    'sustainable_clothing': 0
}
}
---

Ensure that the information is accurate and strictly presented in json, without any white spaces or newlines.
If the receipt is not parsable, return 
{
    'details': [],
    'metrics': {}
}
                        """
                        }

                    ]
                }
            ],
            "max_tokens": 4096
        }

        response = requests.post(
            "https://api.openai.com/v1/chat/completions", headers=headers, json=payload)

        json_data = response.json()
        # print(json_data)
        message = json_data['choices'][0]['message']['content']
        print(message)
        # try:
        parsed_data = jsonify(json.loads(message.strip()))
        return parsed_data
        # except json.JSONDecodeError:
        #     return jsonify({"error": "Invalid JSON response from OpenAI API"})

# @rest_api("/api/")