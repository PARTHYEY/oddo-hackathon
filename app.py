from flask import Flask, request, jsonify
from supabase import create_client
from dotenv import load_dotenv
import bcrypt
import jwt
import datetime
import os

load_dotenv()

app = Flask(__name__)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

SECRET_KEY = "mysecretkey"


# ---------------- REGISTER ---------------- #

@app.route("/register", methods=["POST"])
def register():

    data = request.get_json()

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({
            "error": "Email and password required"
        }), 400

    hashed_password = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    existing_user = supabase.table("users") \
        .select("*") \
        .eq("email", email) \
        .execute()

    if existing_user.data:
        return jsonify({
            "error": "User already exists"
        }), 400

    supabase.table("users").insert({
        "email": email,
        "password": hashed_password
    }).execute()

    return jsonify({
        "message": "User registered successfully"
    }), 201


# ---------------- LOGIN ---------------- #

@app.route("/login", methods=["POST"])
def login():

    data = request.get_json()

    email = data.get("email")
    password = data.get("password")

    response = supabase.table("users") \
        .select("*") \
        .eq("email", email) \
        .execute()

    if not response.data:
        return jsonify({
            "error": "Invalid email"
        }), 401

    user = response.data[0]

    if not bcrypt.checkpw(
        password.encode("utf-8"),
        user["password"].encode("utf-8")
    ):
        return jsonify({
            "error": "Invalid password"
        }), 401

    token = jwt.encode({
        "email": user["email"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, SECRET_KEY, algorithm="HS256")

    return jsonify({
        "message": "Login successful",
        "token": token
    })


# ---------------- PROFILE ---------------- #

@app.route("/profile", methods=["GET"])
def profile():

    auth_header = request.headers.get("Authorization")

    if not auth_header:
        return jsonify({
            "error": "Token missing"
        }), 401

    try:

        token = auth_header.split(" ")[1]

        decoded = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        return jsonify({
            "email": decoded["email"]
        })

    except:
        return jsonify({
            "error": "Invalid token"
        }), 401


# ---------------- RUN ---------------- #

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)