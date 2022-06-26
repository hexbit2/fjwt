from crypt import methods
from datetime import timedelta
from os import access
import re
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, get_jwt, get_jwt_identity, jwt_required
from flask_sqlalchemy import SQLAlchemy
from hmac import compare_digest

from sqlalchemy import Identity

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=2)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(minutes=4)
app.config["JWT_SECRET_KEY"] = "sup"

jwt = JWTManager(app)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, nullable=False, unique=True)
    full_name = db.Column(db.Text, nullable=False)

    def check_password(self, password):
        return compare_digest(password, "password")

@jwt.user_identity_loader
def _user_identity_loader(user):
    return user.id

@jwt.user_lookup_loader
def _user_lookup_loader(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    user = User.query.filter_by(username=username).one_or_none()

    if not user or not user.check_password(password):
        return jsonify("Wrong username or password"), 401

    access_token = create_access_token(identity=user, fresh=True)
    refresh_token = create_refresh_token(identity=user)
    return jsonify(access_token=access_token, refresh_token=refresh_token)

@app.route("/tes")
def tes():
    id = get_jwt_identity()
    user = User.query.filter_by(id=id).one_or_none()
    #jt = get_jwt()
    print(id)
    print(jt)

    return "test"

@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    id = get_jwt_identity()
    user = User.query.filter_by(id=id).one_or_none()
    access_token = create_access_token(identity=user, fresh=False)
    return jsonify(access_token=access_token)

@app.route("/pro")
@jwt_required()
def pro():
    return {"secret msg": "classified messages"}

if __name__ == "__main__":
    db.create_all()
    db.session.add(User(full_name="Bruce Wayne", username="batman"))
    db.session.add(User(full_name="Ann Takamaki", username="panther"))
    db.session.add(User(full_name="Jester Lavore", username="little_sapphire"))
    db.session.commit()

    app.run(debug=True)
