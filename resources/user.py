from flask.views import MethodView
from flask_smorest import Blueprint, abort
from passlib.hash import pbkdf2_sha256
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    get_jwt,
    jwt_required,
)
import requests
import os
from db import db
from models import UserModel
from schemas import UserSchema
from blocklist import BLOCKLIST


blp = Blueprint("Users", "users", description="Operations on users")

def send_simple_message():
  	return requests.post(
  		"https://api.mailgun.net/v3/sandboxc7318e9cc7a44de3bc5174bc9ed1ce67.mailgun.org/messages",
  		auth=("api", os.getenv("MAILGUN_API_KEY")),
  		data={"from": "Mailgun Sandbox <postmaster@sandboxc7318e9cc7a44de3bc5174bc9ed1ce67.mailgun.org>",
			"to": "Evashan Govender <evashan.govender@sambeconsulting.com>",
  			"subject": "Hello Evashan Govender",
  			"text": "Congratulations Evashan Govender, you just sent an email with Mailgun! You are truly awesome!"})

@blp.route("/logout")
class UserLogout(MethodView):
    @jwt_required()
    def post(self):
        jti = get_jwt()["jti"]
        BLOCKLIST.add(jti)
        return {"message": "Successfully logged out"}, 200

@blp.route("/register")
class UserRegister(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        # Check if a user with the given username already exists in the database
        if UserModel.query.filter(UserModel.username == user_data["username"]).first():
            # If user exists, abort the request with a 409 Conflict error
            abort(409, message="A user with that username already exists.")

        # Create a new user with the provided username and a hashed password
        user = UserModel(
            username=user_data["username"],
            password=pbkdf2_sha256.hash(user_data["password"]),
        )
        # Add the new user to the database session
        db.session.add(user)
        # Commit the session to save the user in the database
        db.session.commit()
        send_simple_message()  # Send a welcome email


        # Return a success message and HTTP status code 201 (Created)
        return {"message": "User created successfully."}, 201

@blp.route("/user/<int:user_id>")
class User(MethodView):
    """
    This resource can be useful when testing our Flask app.
    We may not want to expose it to public users, but for the
    sake of demonstration in this course, it can be useful
    when we are manipulating data regarding the users.
    """

    @blp.response(200, UserSchema)
    def get(self, user_id):
        user = UserModel.query.get_or_404(user_id)
        return user

    def delete(self, user_id):
        user = UserModel.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return {"message": "User deleted."}, 200
    
@blp.route("/login")
class UserLogin(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        user = UserModel.query.filter(
            UserModel.username == user_data["username"]
        ).first()

        if user and pbkdf2_sha256.verify(user_data["password"], user.password):
            access_token = create_access_token(identity=str(user.id), fresh=True)
            refresh_token = create_refresh_token(user.id)
            return {"access_token": access_token, "refresh_token": refresh_token}, 200

        abort(401, message="Invalid credentials.")

@blp.route("/refresh")
class TokenRefresh(MethodView):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)
        # Make it clear that when to add the refresh token to the blocklist will depend on the app design
        jti = get_jwt()["jti"]
        BLOCKLIST.add(jti)
        return {"access_token": new_token}, 200