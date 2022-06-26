

from crypt import methods
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, current_user, jwt_required
from flask_sqlalchemy import SQLAlchemy
from hmac import compare_digest

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

jwt = JWTManager(app)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, nullable=False, unique=True)
    full_name = db.Column(db.Text, nullable=False)

    def check_password(self, password):
        return compare_digest(password, "password")

# This callback will be called during the login, 
#   i.e when creating JWT token using create_access_token
@jwt.user_identity_loader
def _user_identity_loader(user):
    return user.id

# This callback will load the user when even a protected end point is accessed.
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
    
    additional_claims = {"aud": "some_audience", "foo": "bar"}
    access_token = create_access_token(identity=user, additional_claims=additional_claims)
    return jsonify(access_token=access_token)

@app.route("/whoami")
@jwt_required()
def protected():
    return jsonify(
        id=current_user.id,
        full_name=current_user.full_name,
        username=current_user.username,
    )

if __name__ == "__main__":
    db.create_all()
    db.session.add(User(full_name="Bruce Wayne", username="batman"))
    db.session.add(User(full_name="Ann Takamaki", username="panther"))
    db.session.add(User(full_name="Jester Lavore", username="little_sapphire"))
    db.session.commit()

    app.run(debug=True)
