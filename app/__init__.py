"""Recipe Box API — BE104 course skeleton.

A working Flask + SQLite CRUD API for recipes. It stores data perfectly —
and it trusts everyone. There is no authentication and no authorization yet.
That is the point: you will add both, lesson by lesson, in Units 2 and 3.
"""

# Imports make code from Python's standard library and installed packages
# available by name in this file.
import sqlite3  # Python's built-in interface for SQLite databases.
import os  # Lets this program read environment variables and secure random bytes.
import jwt  # The PyJWT package creates and checks JSON Web Tokens.
import hashlib  # Provides secure hashing functions, including PBKDF2.
import hmac  # Provides a timing-safe comparison for password hashes.
import base64  # Converts bytes to text so they can be stored in the database.

# Flask names used to build the app, access request-scoped data, and send JSON.
from flask import Flask, g, jsonify, request
# datetime/timezone build expiration timestamps; timedelta represents a duration.
from datetime import datetime, timedelta, timezone
# wraps preserves the original function's metadata when a decorator wraps it.
from functools import wraps

# ALL_CAPS is the common naming style for module-level constants.
DATABASE = "recipes.db"  # SQLite will open this database file in the app's working directory.
JWT_SECRET = os.getenv("JWT_SECRET")  # Read the secret from the process environment; None if unset.
PBKDF2_ITERATIONS = 200_000 # how many iterations to use for PBKDF2

def create_app(config_name):
    app = Flask(__name__)

    # Password hashing and verification functions
    def hash_password(password: str) -> str:  # Type hints document that this takes and returns text.
        # random 16-byte salt
        salt = os.urandom(16)  # A fresh random salt prevents identical passwords having identical hashes.

        # derive a key with pbkdf2_hmac
        dk = hashlib.pbkdf2_hmac(
            "sha256",  # Use SHA-256 as the underlying digest algorithm.
            password.encode("utf-8"),  # Hashing APIs take bytes, so encode the password from text.
            salt,  # Mix the random salt into the derived key.
            PBKDF2_ITERATIONS,  # Repeat the work this many times to make guessing slower.
        )

        # store as: iterations$salt$hash (base64-encoded)
        return "$".join([
            str(PBKDF2_ITERATIONS),  # Convert the integer to text for storage.
            base64.b64encode(salt).decode("ascii"),  # Encode bytes as ASCII-safe text.
            base64.b64encode(dk).decode("ascii"),  # Store the derived key beside its salt/settings.
        ])


    def verify_password(stored_hash: str, password: str) -> bool:  # -> bool documents a True/False result.
        try:
            # Unpack the three pieces produced by hash_password; split returns a list.
            iterations_str, salt_b64, hash_b64 = stored_hash.split("$")
            iterations = int(iterations_str)  # Convert saved text back into an integer.
            salt = base64.b64decode(salt_b64)  # Decode stored text back into bytes.
            expected_hash = base64.b64decode(hash_b64)
        except Exception:  # Malformed stored data can fail during splitting/conversion/decoding.
            return False  # Invalid saved data must not count as a matching password.

        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )
        return hmac.compare_digest(dk, expected_hash)  # Compare bytes without leaking timing differences.


    # Authentication and authorization decorators
    def require_auth(func):  # A decorator receives a route function and returns a replacement function.
        @wraps(func)  # Keep the route's name/docstring so Flask and debugging tools see the original.
        def wrapper(*args, **kwargs):  # *args/**kwargs forward any positional and named route arguments.
            # Authentication Check
            auth_header = request.headers.get("Authorization")  # .get returns None when the header is absent.
            if not auth_header:
                return jsonify({"error": "Authorization token required"}), 401

            parts = auth_header.split()  # Split "Bearer <token>" on whitespace into two pieces.
            if len(parts) != 2 or parts[0].lower() != "bearer":
                return jsonify({"error": "Invalid authorization header format"}), 401

            token = parts[1]

            JWT_SECRET = os.getenv("JWT_SECRET")  # Re-read the secret when handling each request.
            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # Verify signature and expiry.
            except jwt.InvalidTokenError:  # PyJWT raises this for invalid, expired, or unverifiable tokens.
                return jsonify({"error": "Invalid or expired token"}), 401

            user_id = payload.get("sub")  # Dictionary .get avoids a KeyError for a missing claim.
            if user_id is None:
                return jsonify({"error": "Invalid token payload"}), 401

            role = payload.get("role")
            if role is None:
                return jsonify({"error": "Invalid token payload"}), 401

            # Attach identity for later authorization
            g.user_id = user_id  # Flask's g is request-scoped storage shared with this request's route.
            g.role = role

            # Hand off to the original route
            return func(*args, **kwargs)  # Call the wrapped route with its original arguments.

        return wrapper  # The decorator replaces the route function with this checked wrapper.


    # Database connection and teardown
    def get_db():
        if "db" not in g:  # Reuse one connection during a request; create it the first time only.
            g.db = sqlite3.connect(DATABASE)  # Open the SQLite file and save the connection on g.
            g.db.row_factory = sqlite3.Row  # Let query results be accessed by column name.
            g.db.execute("PRAGMA foreign_keys = ON")  # Ask SQLite to enforce declared foreign keys.
        return g.db  # Return the cached connection to the caller.


    @app.teardown_appcontext  # Flask calls this after an app/request context is finished.
    def close_db(exception):
        db = g.pop("db", None)  # Remove and return the connection; use None if it was never created.
        if db is not None:
            db.close()  # Release the SQLite connection when the request is done.


    # Helper function to convert a recipe row to a dictionary
    def recipe_to_dict(row):
        return {  # Build a plain Python dictionary that jsonify can turn into JSON.
            "id": row["id"],
            "title": row["title"],
            "ingredients": row["ingredients"],
            "instructions": row["instructions"],
            "is_public": bool(row["is_public"]),  # Convert SQLite's 0/1 value into a Python boolean.
        }

    ################
    # API endpoints
    ################

    # GET endpoints
    @app.get("/")  # Register hello as the handler for HTTP GET requests to the root URL.
    @require_auth  # Check the token first; the wrapper then passes control to hello().
    def hello():
        return jsonify({"message": "Recipe Box API", "recipes": "/recipes"})


    @app.get("/recipes")  # Route decorator connects this URL and method to the function below.
    @require_auth  # This decorator wraps the route function to check for a valid JWT first.
    def list_recipes():
        rows = get_db().execute("SELECT * FROM recipes WHERE is_public = 1 ORDER BY id").fetchall()  # Run SQL and collect all rows.
        return jsonify([recipe_to_dict(r) for r in rows])  # List comprehension converts each row, then JSON encodes the list.


    @app.get("/recipes/<int:recipe_id>")  # <int:...> captures part of the URL and converts it to an integer.
    @require_auth  # Check the token first; the wrapper then passes the URL's recipe_id to this function.
    def get_recipe(recipe_id):
        row = get_db().execute(
            "SELECT * FROM recipes WHERE id = ?", (recipe_id,)  # ? is a placeholder; tuple binds its value safely.
        ).fetchone()  # fetchone returns the first matching row, or None if there is no match.
        if row is None:
            return jsonify({"error": "recipe not found"}), 404
        return jsonify(recipe_to_dict(row))


    # POST endpoints

    # User registration endpoint
    @app.post("/register")  # Register this function as the handler for POST /register.
    def register_user():
        data = request.get_json()  # Parse the incoming JSON request body into Python data.

        if not data:
            return jsonify({"error": "Invalid input"}), 400

        username = data.get("username")  # Read each submitted field; .get gives None if it is absent.
        email = data.get("email")
        password = data.get("password")

        if (  # Parentheses allow this multi-line condition to be formatted clearly.
            not isinstance (username, str) or not username.strip()
            or not isinstance(email, str) or not email.strip()
            or not isinstance(password, str) or not password.strip()
        ):
            return jsonify({"error": "Invalid input"}), 400

        # Hash the password
        password_hash = hash_password(password)  # Store a derived hash, not the submitted password.

        # Insert it into the database using parameters
        db = get_db()  # Get this request's SQLite connection.
        cursor = db.cursor()  # A cursor executes SQL and exposes metadata such as lastrowid.

        try:
            cursor.execute(  # Execute SQL with values supplied separately from the SQL text.
                """
            INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (username, email, password_hash)  # Tuple values fill the three ? placeholders in order.
            )
            db.commit()  # Persist the successful insert transaction to the database file.

        except sqlite3.IntegrityError as e:  # Catch database constraint violations; "as e" keeps the error object.
            if "UNIQUE constraint failed: users.username" in str(e):
                return jsonify({"error": "username already exists"}), 409
            elif "UNIQUE constraint failed: users.email" in str(e):
                return jsonify({"error": "email already exists"}), 409
            else:
                return jsonify({"error": "database error"}), 500

        # Respond with 201 and safe fields only
        return jsonify({  # Return selected safe fields; the password hash is deliberately omitted.
            "id": cursor.lastrowid,
            "username": username,
            "email": email
        }), 201  # Flask accepts (response, status_code) as a route result.

    # Login endpoint
    @app.post("/login")  # Register the login handler for HTTP POST requests.
    def user_login():
        data = request.get_json(silent=True)  # silent=True returns None for malformed JSON instead of raising.

        if data is None:
            return jsonify({"error": "Invalid JSON"}), 400

        if not data.get("username") or not data.get("password"):
            return jsonify({"error": "Missing username or password"}), 400

        username = data.get("username")
        password = data.get("password")

        db = get_db()
        cursor = db.cursor()  # Create an object for executing and reading SQL query results.

        try:
            cursor.execute(  # Bind username into the query; the comma makes this a one-item tuple.
                "SELECT id, username, email, password_hash, role FROM users WHERE username = ?", (username,)
            )
            user = cursor.fetchone()
            if user is None:  # No matching account; use the same message as a bad password below.
                return jsonify({"error": "Invalid username or password"}), 401

            if not verify_password(user["password_hash"], password):
                return jsonify({"error": "Invalid username or password"}), 401

            # Successful login - issue JWT
            payload = {  # JWT claims are ordinary dictionary entries encoded into the token.
                "sub": str(user["id"]),
                "role": user["role"],
                "exp": datetime.now(timezone.utc) + timedelta(hours=1)  # UTC now plus one hour is the expiry time.
            }
            token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")  # Sign claims with the shared secret.

            return jsonify({"token": token}), 200

        except sqlite3.Error as e:  # Catch SQLite failures from this database operation.
            return jsonify({"error": "database error"}), 500

    # Create recipe
    @app.post("/recipes")  # Attach the handler to POST /recipes.
    @require_auth  # Decorators apply bottom-up: this wraps the function, then @app.post registers the wrapper.
    def create_recipe():
        data = request.get_json(silent=True)  # Parse JSON, returning None instead of raising on malformed input.
        if data is None:
            return jsonify({"error": "Invalid JSON"}), 400
        if not data.get("title") or not data.get("ingredients"):  # or means either missing/empty field triggers the check.
            return jsonify({"error": "title and ingredients are required"}), 400

        db = get_db()
        try:
            cur = db.execute(  # Execute one insert; parameter values stay separate from SQL syntax.
                "INSERT INTO recipes (title, ingredients, instructions, is_public, owner_id)"
                " VALUES (?, ?, ?, ?, ?)",
                (
                    data["title"],
                    data["ingredients"],
                    data.get("instructions", ""),
                    1 if data.get("is_public", True) else 0,  # Conditional expression: choose 1 when truthy, else 0.
                    g.user_id  # Use the authenticated user's ID
                ),
            )
            db.commit()  # Save the new recipe.
        except sqlite3.IntegrityError:
            return jsonify({"error": "a recipe with that title already exists"}), 409
        row = db.execute(
            "SELECT * FROM recipes WHERE id = ?", (cur.lastrowid,)  # lastrowid is the inserted recipe's ID.
        ).fetchone()

        return jsonify(recipe_to_dict(row)), 201

    # Update recipe
    @app.patch("/recipes/<int:recipe_id>")  # PATCH usually changes selected fields on an existing resource.
    @require_auth  # Check the token first; the wrapper then passes the URL's recipe_id to this function.
    def update_recipe(recipe_id):
        db = get_db()
        row = db.execute(
            "SELECT owner_id FROM recipes WHERE id = ?", (recipe_id,)
        ).fetchone()

        if row is None:
            return jsonify({"error": "recipe not found"}), 404

        if row["owner_id"] != int(g.user_id) and g.role != "admin":  # Reject only when not the owner AND not an admin.
            return jsonify({"error": "You cannot update a recipe you do not own"}), 403

        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "a JSON body is required"}), 400

        fields, values = [], []  # Build SQL fragments and their bound values together, in matching order.

        for column in ("title", "ingredients", "instructions"):  # Loop through the allowed editable column names.
            if column in data:  # Membership checks whether the JSON object supplied this key.
                fields.append(f"{column} = ?")  # f-string inserts the known column name into the SQL fragment.
                values.append(data[column])  # Add its actual value for safe placeholder binding.

        if "is_public" in data:
            fields.append("is_public = ?")
            values.append(1 if data["is_public"] else 0)  # Convert JSON true/false to SQLite's 1/0 convention.

        if not fields:  # An empty list is falsey, so this means no editable field was provided.
            return jsonify({"error": "nothing to update"}), 400

        values.append(recipe_id)  # Final ? placeholder identifies which recipe to update.

        db = get_db()
        try:
            cur = db.execute(
                f"UPDATE recipes SET {', '.join(fields)} WHERE id = ?", values  # Join assignments with commas; bind values as a sequence.
            )
            db.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error": "a recipe with that title already exists"}), 409
        if cur.rowcount == 0:  # SQLite reports zero changed rows when the ID matched no recipe.
            return jsonify({"error": "recipe not found"}), 404
        row = db.execute(
            "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
        ).fetchone()
        return jsonify(recipe_to_dict(row))

    # Delete recipe
    @app.delete("/recipes/<int:recipe_id>")  # Register the delete handler for one integer recipe ID.
    @require_auth  # Authentication wrapper runs before the handler.
    def delete_recipe(recipe_id):
        db = get_db()
        row = db.execute("SELECT owner_id FROM recipes WHERE id = ?", (recipe_id,)).fetchone()

        if row is None:
            return jsonify({"error": "recipe not found"}), 404

        if row["owner_id"] != int(g.user_id) and g.role != "admin":  # Allow the owner or an admin to continue.
            return jsonify({"error": "You cannot delete a recipe you do not own"}), 403

        db = get_db()
        cur = db.execute("DELETE FROM recipes WHERE id = ?", (recipe_id,))  # Bind the ID as a one-item tuple.
        db.commit()


    if __name__ == "__main__":  # This condition is true only when this file is run directly.
        app.run(debug=True)  # Start Flask's development server; importing this module won't start it.

    return app