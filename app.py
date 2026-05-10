from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client
from dotenv import load_dotenv
import bcrypt
import jwt
import datetime
import os

load_dotenv()

app = Flask(__name__)
CORS(app)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


# ============================================
# HOME
# ============================================

@app.route("/")
def home():
    return jsonify({
        "message": "Traveloop API Running"
    })


# ============================================
# REGISTER
# ============================================

@app.route("/register", methods=["POST"])
def register():

    try:

        data = request.get_json()

        first_name = data.get("first_name")
        last_name = data.get("last_name")
        email = data.get("email")
        phone = data.get("phone")
        country = data.get("country")
        info = data.get("info")
        password = data.get("password")

        if not email or not password:
            return jsonify({
                "error": "Email and password required"
            }), 400

        existing_user = supabase.table("users") \
            .select("*") \
            .eq("email", email) \
            .execute()

        if existing_user.data:
            return jsonify({
                "error": "User already exists"
            }), 400

        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        supabase.table("users").insert({
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "phone": phone,
            "country": country,
            "info": info,
            "password": hashed_password
        }).execute()

        return jsonify({
            "message": "User registered successfully"
        }), 201

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# ============================================
# LOGIN
# ============================================

@app.route("/login", methods=["POST"])
def login():

    try:

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
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }, JWT_SECRET, algorithm="HS256")

        return jsonify({
            "message": "Login successful",
            "token": token,
            "user": {
                "first_name": user["first_name"],
                "last_name": user["last_name"],
                "email": user["email"],
                "phone": user["phone"],
                "country": user["country"],
                "info": user["info"]
            }
        })

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# ============================================
# PROFILE
# ============================================

@app.route("/profile", methods=["GET"])
def profile():

    try:

        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return jsonify({
                "error": "Token missing"
            }), 401

        token = auth_header.split(" ")[1]

        decoded = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"]
        )

        response = supabase.table("users") \
            .select("*") \
            .eq("email", decoded["email"]) \
            .execute()

        if not response.data:
            return jsonify({
                "error": "User not found"
            }), 404

        user = response.data[0]

        return jsonify({
            "first_name": user["first_name"],
            "last_name": user["last_name"],
            "email": user["email"],
            "phone": user["phone"],
            "country": user["country"],
            "info": user["info"]
        })

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 401


# ============================================
# RUN
# ============================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
