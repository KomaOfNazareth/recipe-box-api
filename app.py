"""Recipe Box API — BE104 course skeleton.

A working Flask + SQLite CRUD API for recipes. It stores data perfectly —
and it trusts everyone. There is no authentication and no authorization yet.
That is the point: you will add both, lesson by lesson, in Units 2 and 3.
"""

import sqlite3
import os
import jwt
import hashlib
import hmac
import base64

from flask import Flask, g, jsonify, request
from datetime import datetime, timedelta, timezone
from functools import wraps

DATABASE = "recipes.db"
JWT_SECRET = os.getenv("JWT_SECRET")
PBKDF2_ITERATIONS = 200_000 # how many iterations to use for PBKDF2

app = Flask(__name__)

# Password hashing and verification functions
def hash_password(password: str) -> str:
    # random 16-byte salt
    salt = os.urandom(16)
    # derive a key with pbkdf2_hmac
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    # store as: iterations$salt$hash (base64-encoded)
    return "$".join([
        str(PBKDF2_ITERATIONS),
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    ])

def verify_password(stored_hash: str, password: str) -> bool:
    try:
        iterations_str, salt_b64, hash_b64 = stored_hash.split("$")
        iterations = int(iterations_str)
        salt = base64.b64decode(salt_b64)
        expected_hash = base64.b64decode(hash_b64)
    except Exception:
        return False

    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return hmac.compare_digest(dk, expected_hash)

# Authentication and authorization decorators
def require_auth(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Authentication Check
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Authorization token required"}), 401

        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({"error": "Invalid authorization header format"}), 401

        token = parts[1]

        JWT_SECRET = os.getenv("JWT_SECRET")
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid or expired token"}), 401

        user_id = payload.get("sub")
        if user_id is None:
            return jsonify({"error": "Invalid token payload"}), 401

        role = payload.get("role")
        if role is None:
            return jsonify({"error": "Invalid token payload"}), 401

        # Attach identity for later authorization
        request.user_id = user_id
        request.role = role

        # Hand off to the original route
        return func(*args, **kwargs)

    return wrapper

# Database connection and teardown
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# Helper function to convert a recipe row to a dictionary
def recipe_to_dict(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "ingredients": row["ingredients"],
        "instructions": row["instructions"],
        "is_public": bool(row["is_public"]),
    }

################
# API endpoints
################

# GET endpoints
@app.get("/")
def hello():
    return jsonify({"message": "Recipe Box API", "recipes": "/recipes"})


@app.get("/recipes")
def list_recipes():
    rows = get_db().execute("SELECT * FROM recipes ORDER BY id").fetchall()
    return jsonify([recipe_to_dict(r) for r in rows])


@app.get("/recipes/<int:recipe_id>")
def get_recipe(recipe_id):
    row = get_db().execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404
    return jsonify(recipe_to_dict(row))


# POST endpoints

# User registration endpoint
@app.post("/register")
def register_user():
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "Invalid input"}), 400
    
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    
    if (
        not isinstance (username, str) or not username.strip()
        or not isinstance(email, str) or not email.strip()
        or not isinstance(password, str) or not password.strip()
    ):
        return jsonify({"error": "Invalid input"}), 400
    
    # Hash the password
    password_hash = hash_password(password)
    
    # Insert it into the database using parameters
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute(
            """
        INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
            """,
            (username, email, password_hash)
        )
        db.commit()
    
    except sqlite3.IntegrityError as e:
        if "UNIQUE constraint failed: users.username" in str(e):
            return jsonify({"error": "username already exists"}), 409
        elif "UNIQUE constraint failed: users.email" in str(e):
            return jsonify({"error": "email already exists"}), 409
        else:
            return jsonify({"error": "database error"}), 500
    
    # Respond with 201 and safe fields only
    return jsonify({
        "id": cursor.lastrowid,
        "username": username,
        "email": email
    }), 201

# Login endpoint
@app.post("/login")
def user_login():
    data = request.get_json(silent=True)
    
    if data is None:
        return jsonify({"error": "Invalid JSON"}), 400
    
    if not data.get("username") or not data.get("password"):
        return jsonify({"error": "Missing username or password"}), 400
    
    username = data.get("username")
    password = data.get("password")
    
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(
            "SELECT id, username, email, password_hash, role FROM users WHERE username = ?", (username,)
        )
        user = cursor.fetchone()
        if user is None:
            return jsonify({"error": "Invalid username or password"}), 401
        
        if not verify_password(user["password_hash"], password):
            return jsonify({"error": "Invalid username or password"}), 401
        
        # Successful login - issue JWT
        payload = {
            "sub": str(user["id"]),
            "role": user["role"],
            "exp": datetime.now(timezone.utc) + timedelta(hours=1)  # Token expires in 1 hour
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        
        return jsonify({"token": token}), 200
        
    except sqlite3.Error as e:
        return jsonify({"error": "database error"}), 500

# Recipe CRUD endpoints

# Create recipe
@app.post("/recipes")
@require_auth
def create_recipe():
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"error": "Invalid JSON"}), 400
    if not data.get("title") or not data.get("ingredients"):
        return jsonify({"error": "title and ingredients are required"}), 400
    
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO recipes (title, ingredients, instructions, is_public, owner_id)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                data["title"],
                data["ingredients"],
                data.get("instructions", ""),
                1 if data.get("is_public", True) else 0,
                request.user_id  # Use the authenticated user's ID
            ),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (cur.lastrowid,)
    ).fetchone()
    
    print("CREATED BY USER:", getattr(request, "user_id", None))
    
    return jsonify(recipe_to_dict(row)), 201

# Update recipe
@app.patch("/recipes/<int:recipe_id>")
@require_auth
def update_recipe(recipe_id):
    db = get_db()
    row = db.execute(
        "SELECT owner_id FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()

    if row is None:
        return jsonify({"error": "recipe not found"}), 404

    if row["owner_id"] != int(request.user_id) and request.role != "admin":
        return jsonify({"error": "You cannot update a recipe you do not own"}), 403
    
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "a JSON body is required"}), 400
    
    fields, values = [], []
    
    for column in ("title", "ingredients", "instructions"):
        if column in data:
            fields.append(f"{column} = ?")
            values.append(data[column])
    
    if "is_public" in data:
        fields.append("is_public = ?")
        values.append(1 if data["is_public"] else 0)
    
    if not fields:
        return jsonify({"error": "nothing to update"}), 400
    
    values.append(recipe_id)
    
    db = get_db()
    try:
        cur = db.execute(
            f"UPDATE recipes SET {', '.join(fields)} WHERE id = ?", values
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409
    if cur.rowcount == 0:
        return jsonify({"error": "recipe not found"}), 404
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    return jsonify(recipe_to_dict(row))

# Delete recipe
@app.delete("/recipes/<int:recipe_id>")
@require_auth
def delete_recipe(recipe_id):
    db = get_db()
    row = db.execute("SELECT owner_id FROM recipes WHERE id = ?", (recipe_id,)).fetchone()
    
    if row is None:
        return jsonify({"error": "recipe not found"}), 404
    
    if row["owner_id"] != int(request.user_id) and request.role != "admin":
        return jsonify({"error": "You cannot delete a recipe you do not own"}), 403

    db = get_db()
    cur = db.execute("DELETE FROM recipes WHERE id = ?", (recipe_id,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "recipe not found"}), 404
    return "", 204


if __name__ == "__main__":
    app.run(debug=True)
