from flask import Blueprint, request, jsonify

auth_bp = Blueprint('auth', __name__)

# In-memory users for demo (replace with DB in production)
users = [{'username': 'user@example.com', 'password': 'pass'}]

@auth_bp.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password or '@' not in username:
        return jsonify({'success': False, 'message': 'Invalid email or password.'}), 400
    if any(u['username'] == username for u in users):
        return jsonify({'success': False, 'message': 'User already exists.'}), 409
    users.append({'username': username, 'password': password})
    return jsonify({'success': True, 'username': username})

@auth_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = next((u for u in users if u['username'] == username and u['password'] == password), None)
    if user:
        return jsonify({'success': True, 'username': username})
    else:
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401