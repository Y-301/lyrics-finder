from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import jwt
from functools import wraps # Import wraps for decorators

# Initialize the Flask application
app = Flask(__name__)

# --- Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# !!! IMPORTANT: Set a secret key for signing JWTs.
# Replace 'your_super_secret_key_here' with a long, random string.
# This should be kept secret and not exposed publicly.
app.config['SECRET_KEY'] = 'your_super_secret_key_here_replace_with_a_long_random_string'


# Initialize the SQLAlchemy database instance
db = SQLAlchemy(app)

# --- Database Models ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    history = db.relationship('SearchHistory', backref='author', lazy=True, cascade="all, delete-orphan") # Added cascade for easy history deletion

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

class SearchHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    artist = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    lyrics = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"SearchHistory('{self.artist}', '{self.title}', '{self.timestamp}')"


# --- JWT Authentication Decorator ---

def token_required(f):
    """
    Decorator to protect routes, requiring a valid JWT token.
    Extracts the token from the 'Authorization' header.
    If valid, passes the current user object to the decorated function.
    """
    @wraps(f) # Helps maintain original function's name and docstring
    def decorated(*args, **kwargs):
        token = None
        # JWT is typically sent in the Authorization header as 'Bearer <token>'
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            # Check if the header starts with 'Bearer ' and extract the token
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1] # Get the token part

        # If no token is provided
        if not token:
            return jsonify({"message": "Token is missing!"}), 401 # Unauthorized

        try:
            # Decode the token using the secret key
            # This verifies the token's signature and checks expiration if 'exp' is in payload
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            # Find the user based on the user_id in the token payload
            current_user = User.query.get(data['user_id'])

            # If user not found (e.g., user deleted after token issued)
            if not current_user:
                 return jsonify({"message": "User not found!"}), 401 # Unauthorized

        except jwt.ExpiredSignatureError:
             # Handle expired token specifically if 'exp' is used
             return jsonify({"message": "Token has expired!"}), 401 # Unauthorized
        except jwt.InvalidTokenError:
            # Handle any other invalid token errors (e.g., wrong signature)
            return jsonify({"message": "Token is invalid!"}), 401 # Unauthorized
        except Exception as e:
            # Catch any other unexpected errors during token processing
            print(f"Error processing token: {e}")
            return jsonify({"message": "Token processing error!"}), 500 # Internal Server Error


        # Pass the current_user object to the decorated function
        return f(current_user, *args, **kwargs)

    return decorated


# --- API Endpoints ---

# 1. User Registration Endpoint (already implemented)
@app.route('/api/register', methods=['POST'])
def register_user():
    """
    Handles user registration requests.
    Expects JSON with email, username, and password.
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 415 # Unsupported Media Type

    data = request.get_json()

    email = data.get('email')
    username = data.get('username')
    password = data.get('password')

    # --- Input Validation ---
    if not email or not username or not password:
        return jsonify({"error": "Missing email, username, or password"}), 400 # Bad Request

    # Basic email format check (can be more robust)
    if '@' not in email:
         return jsonify({"error": "Invalid email format"}), 400

    # Password length check (example)
    if len(password) < 6:
         return jsonify({"error": "Password must be at least 6 characters long"}), 400


    # --- Check if user already exists in the database ---
    existing_user = User.query.filter(
        (User.email == email) | (User.username == username)
    ).first()

    if existing_user:
        if existing_user.email == email:
            return jsonify({"error": "Email address already registered"}), 409 # Conflict
        else:
            return jsonify({"error": "Username already taken"}), 409 # Conflict

    # --- Create and Save new user to the database ---
    new_user = User(email=email, username=username)
    new_user.set_password(password)

    try:
        db.session.add(new_user)
        db.session.commit()

        return jsonify({
            "message": "User registered successfully",
            "userId": new_user.id
        }), 201 # Created

    except Exception as e:
        db.session.rollback()
        print(f"Database error during registration: {e}")
        return jsonify({"error": "An error occurred during registration"}), 500 # Internal Server Error


# 2. User Login Endpoint (already implemented)
@app.route('/api/login', methods=['POST'])
def login_user():
    """
    Handles user login requests.
    Expects JSON with email/username and password.
    Returns a JWT token on success.
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 415 # Unsupported Media Type

    data = request.get_json()

    email_or_username = data.get('email_or_username')
    password = data.get('password')

    # --- Input Validation ---
    if not email_or_username or not password:
        return jsonify({"error": "Missing email/username or password"}), 400 # Bad Request

    # --- Find user in the database ---
    user = User.query.filter(
        (User.email == email_or_username) | (User.username == email_or_username)
    ).first()

    # --- Verify password and generate token ---
    if user and user.check_password(password):
        token_payload = {
            'user_id': user.id,
            'username': user.username,
            # Add an expiration time (recommended for security)
            # 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30) # Example: expires in 30 minutes
        }
        # Encode the payload using the secret key
        # Use str(app.config['SECRET_KEY']) to ensure it's a string
        token = jwt.encode(token_payload, str(app.config['SECRET_KEY']), algorithm='HS256')


        # Return success response with the token
        return jsonify({
            "message": "Login successful",
            "token": token,
            "userId": user.id,
            "username": user.username
        }), 200 # OK
    else:
        # User not found or password incorrect
        return jsonify({"error": "Invalid email/username or password"}), 401 # Unauthorized


# 3. Search History Endpoint (Handles POST, GET, DELETE)
@app.route('/api/history', methods=['POST', 'GET', 'DELETE'])
@token_required # Apply the JWT authentication decorator
def manage_history(current_user):
    """
    Handles search history operations for the authenticated user.
    POST: Save a new history item.
    GET: Retrieve user's history.
    DELETE: Clear user's history.
    """
    # The 'current_user' object is automatically passed by the @token_required decorator

    if request.method == 'POST':
        # --- Save History Item ---
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 415

        data = request.get_json()
        artist = data.get('artist')
        title = data.get('title')
        lyrics = data.get('lyrics')

        # Input validation for history item
        if not artist or not title or not lyrics:
            return jsonify({"error": "Missing artist, title, or lyrics"}), 400

        # Create a new SearchHistory item linked to the current user
        new_history_item = SearchHistory(
            artist=artist,
            title=title,
            lyrics=lyrics,
            author=current_user # Link to the user object
        )

        try:
            db.session.add(new_history_item)
            db.session.commit()
            return jsonify({"message": "History item saved successfully"}), 201 # Created
        except Exception as e:
            db.session.rollback()
            print(f"Database error saving history: {e}")
            return jsonify({"error": "An error occurred while saving history"}), 500

    elif request.method == 'GET':
        # --- Get History ---
        # Query history items for the current user, ordered by timestamp descending
        user_history = SearchHistory.query.filter_by(user_id=current_user.id).order_by(SearchHistory.timestamp.desc()).all()

        # Format the history items for JSON response
        history_list = []
        for item in user_history:
            history_list.append({
                'id': item.id,
                'artist': item.artist,
                'title': item.title,
                'lyrics': item.lyrics,
                'timestamp': item.timestamp.isoformat() # Format timestamp as ISO string
            })

        return jsonify(history_list), 200 # OK

    elif request.method == 'DELETE':
        # --- Clear History ---
        try:
            # Delete all history items for the current user
            # The cascade="all, delete-orphan" on the User model relationship
            # ensures history items are deleted when the user is deleted,
            # but here we want to delete history without deleting the user.
            # We can query and delete all items for the user.
            SearchHistory.query.filter_by(user_id=current_user.id).delete()
            db.session.commit()
            return jsonify({"message": "Search history cleared successfully"}), 200 # OK
        except Exception as e:
            db.session.rollback()
            print(f"Database error clearing history: {e}")
            return jsonify({"error": "An error occurred while clearing history"}), 500


# --- Running the Flask app ---
if __name__ == '__main__':
    # Create the database tables if they don't exist
    with app.app_context():
        db.create_all()
        print("Database tables created if they didn't exist.")

    # Run the app in debug mode.
    # In production, you would use a production-ready WSGI server.
    app.run(debug=True)
