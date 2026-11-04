"""Recipe Box API — BE104 course skeleton.

A working Flask + SQLite CRUD API for recipes. It stores data perfectly —
and it trusts everyone. There is no authentication and no authorization yet.
That is the point: you will add both, lesson by lesson, in Units 2 and 3.
"""

import sqlite3

from flask import Flask, g, jsonify, request

from werkzeug.security import generate_password_hash, check_password_hash

DATABASE = "recipes.db"

app = Flask(__name__)

# Password hashing and verification functions
def hash_password(plain_password: str) -> str:
    """Take a plain-text password and return a hashed version of it."""
    return generate_password_hash(plain_password)

def verify_password(stored_hash: str, candidate_password: str) -> bool:
    """Return True if the candidate password matches the stored hash."""
    return check_password_hash(stored_hash, candidate_password)


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
            "SELECT id, username, email, password_hash FROM users WHERE username = ?", (username,)
        )
        user = cursor.fetchone()
        if user is None:
            return jsonify({"error": "Invalid username or password"}), 401
        
        if not verify_password(user["password_hash"], password):
            return jsonify({"error": "Invalid username or password"}), 401
        
        # Successful login
        return jsonify({
            "id": user["id"],
            "username": user["username"],
            "email": user["email"]
        }), 200
        
    except sqlite3.Error as e:
        return jsonify({"error": "database error"}), 500

# Recipe CRUD endpoints

# Create recipe
@app.post("/recipes")
def create_recipe():
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"error": "Invalid JSON"}), 400
    if not data.get("title") or not data.get("ingredients"):
        return jsonify({"error": "title and ingredients are required"}), 400
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO recipes (title, ingredients, instructions, is_public)"
            " VALUES (?, ?, ?, ?)",
            (
                data["title"],
                data["ingredients"],
                data.get("instructions", ""),
                1 if data.get("is_public", True) else 0,
            ),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (cur.lastrowid,)
    ).fetchone()
    return jsonify(recipe_to_dict(row)), 201

# Update recipe
@app.patch("/recipes/<int:recipe_id>")
def update_recipe(recipe_id):
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
def delete_recipe(recipe_id):
    db = get_db()
    cur = db.execute("DELETE FROM recipes WHERE id = ?", (recipe_id,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "recipe not found"}), 404
    return "", 204


if __name__ == "__main__":
    app.run(debug=True)
