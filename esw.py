import logging
import os
import jwt
import datetime
import bcrypt
import secrets
import psycopg2
from flask import Flask, jsonify, request, render_template

app = Flask(__name__)

# Set the secret key
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(64))

# Database configuration
DB_CONFIG = {
    'dbname': 'tbken',
    'user': 'postgres',
    'password': 'Ahmad',
    'host': 'localhost',
    'port': '5432'
}

# Token expiration time in minutes
TOKEN_EXPIRATION_MINUTES = int(os.environ.get('TOKEN_EXPIRATION_MINUTES', 15))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize the database and create the token table if it doesn't exist
def init_db():
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cursor:
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS token (
                        id SERIAL PRIMARY KEY,
                        user_id TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,  -- Store hashed password
                        app_key TEXT UNIQUE NOT NULL
                    )
                ''')
                conn.commit()
    except Exception as e:
        logging.error("Error initializing database: %s", e, exc_info=True)

@app.route('/')
def home():
    return render_template('register-form.html')

@app.route('/login', methods=['GET'])
def login():
    return render_template('login-form.html')

@app.route('/register', methods=['POST'])
def register_user():
    try:
        data = request.get_json(force=True)
        user_id = data.get('user_id')
        password = data.get('password')

        # Validate input
        if not user_id:
            return jsonify({"error": "user_id is required!"}), 400
        if not password:
            return jsonify({"error": "password is required!"}), 400

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Generate a unique app key
        app_key = secrets.token_hex(32)

        # Store the user in the database
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cursor:
                cursor.execute("INSERT INTO token (user_id, password, app_key) VALUES (%s, %s, %s)",
                               (user_id, hashed_password.decode('utf-8'), app_key))
                conn.commit()

        return jsonify({"message": "User registered successfully!", "app_key": app_key})

    except psycopg2.IntegrityError:
        return jsonify({"error": "user_id already exists!"}), 400
    except Exception as e:
        logging.error("Error registering user: %s", e, exc_info=True)
        return jsonify({"error": "An error occurred during registration."}), 500


@app.route('/generate-token', methods=['POST'])
def generate_token():
    try:
        data = request.get_json(force=True)
        user_id = data.get('user_id')
        password = data.get('password')  # This is the plaintext password
        app_key = data.get('app_key')

        # Validate input
        if not user_id:
            return jsonify({"error": "user_id is required!"}), 400
        if not password:
            return jsonify({"error": "password is required!"}), 400
        if not app_key:
            return jsonify({"error": "app_key is required!"}), 400

        # Fetch user details from the database
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT password, app_key FROM token WHERE user_id = %s", (user_id,))
                user = cursor.fetchone()

        # Check if user exists
        if user is None:
            logging.warning("User not found: %s", user_id)
            return jsonify({"error": "Invalid user_id or app_key!"}), 404

        # Retrieve the stored hashed password and app_key
        stored_hashed_password = user[0].encode('utf-8')  # Convert memoryview to bytes
        stored_app_key = user[1]                   # App key from database

        # Check if the provided app_key matches the stored app_key
        if stored_app_key != app_key:
            logging.warning("App key mismatch for user: %s", user_id)
            return jsonify({"error": "Invalid user_id or app_key!"}), 404

        # Compare the provided plaintext password with the stored hashed password using bcrypt
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
            logging.warning("Incorrect password attempt for user: %s", user_id)
            return jsonify({"error": "Incorrect password!"}), 401

        # Generate the token if password and app_key are correct
        payload = {
            'user_id': user_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=TOKEN_EXPIRATION_MINUTES)
        }

        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        return jsonify({'token': token})

    except Exception as e:
        logging.error("Error processing token request: %s", e, exc_info=True)
        return jsonify({"error": "An error occurred."}), 500

@app.route('/check-token', methods=['POST'])
def check_token():
    try:
        data = request.get_json(force=True)
        token = data.get('token')

        if not token:
            return jsonify({"error": "token is required!"}), 400

        try:
            decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_payload['user_id']

            # Check if user_id exists in the database
            with psycopg2.connect(**DB_CONFIG) as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT * FROM token WHERE user_id = %s", (user_id,))
                    user = cursor.fetchone()

            if user is None:
                return jsonify({"error": "user_id not found in database!"}), 404

            return jsonify({"message": "Token is valid and user_id exists", "payload": decoded_payload})

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token!"}), 401
        except Exception as e:
            logging.error("Error checking token: %s", e, exc_info=True)
            return jsonify({"error": "An error occurred while checking the token."}), 500

    except Exception as e:
        logging.error("Error processing token check request: %s", e, exc_info=True)
        return jsonify({"error": "An error occurred."}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true')
