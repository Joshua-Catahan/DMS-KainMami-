from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import json
import jwt
import datetime
from functools import wraps
from flask import render_template
import os 
from dotenv import load_dotenv
import re
from flask import send_file

load_dotenv()
app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-dev-key-only')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///food_ordering.db') + '?check_same_thread=False&timeout=20'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
CORS(app)

# ============ DATABASE MODELS ============
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    role = db.Column(db.String(20), default='client')
    orders = db.relationship('Order', backref='user', lazy=True)
    cart = db.relationship('Cart', backref='user', uselist=False)

class Food(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(500))
    description = db.Column(db.Text)
    is_available = db.Column(db.Boolean, default=True)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    food_items = db.Column(db.Text, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='in_process')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    food_items = db.Column(db.Text, default='[]')
    total_price = db.Column(db.Float, default=0.0)

# ============ DATABASE INITIALIZATION ============
def initialize_database():
    """Initialize database with admin user and sample data"""
    print("🔄 Initializing database...")
    
    # Create all tables
    db.create_all()
    
    # Check if admin user exists
    admin_user = User.query.filter_by(username='kainmamiadm15@gmail.com').first()
    if not admin_user:
        print("👑 Creating admin user...")
        
        # Create admin user in a separate transaction
        try:
            hashed_password = generate_password_hash('Admin123!', method='pbkdf2:sha256')
            admin_user = User(
                username='kainmamiadm15@gmail.com',
                password=hashed_password,
                name='Administrator',
                phone='+1234567890',
                role='admin'
            )
            db.session.add(admin_user)
            db.session.commit()  # Commit to get the user ID
            print(f"✅ Admin user created with ID: {admin_user.id}")
        except Exception as e:
            print(f"❌ Failed to create admin user: {e}")
            db.session.rollback()
            return False
        
        # Now create cart for the admin user
        try:
            admin_cart = Cart(user_id=admin_user.id)
            db.session.add(admin_cart)
            db.session.commit()
            print("✅ Admin cart created!")
        except Exception as e:
            print(f"❌ Failed to create admin cart: {e}")
            db.session.rollback()
            return False
    else:
        print("✅ Admin user already exists")
    
    # Check if sample foods exist
    if Food.query.count() == 0:
        print("🍕 Creating sample foods...")
        try:
            foods = [
                Food(name='Pancakes', category='Breakfast', price=5.99, image_url='https://via.placeholder.com/200', description='Fluffy pancakes with syrup'),
                Food(name='Omelette', category='Breakfast', price=4.99, image_url='https://via.placeholder.com/200', description='Three egg omelette'),
                Food(name='Burger', category='Lunch', price=8.99, image_url='https://via.placeholder.com/200', description='Classic beef burger'),
                Food(name='Pizza', category='Lunch', price=12.99, image_url='https://via.placeholder.com/200', description='Margherita pizza'),
                Food(name='Fries', category='Snacks', price=3.99, image_url='https://via.placeholder.com/200', description='Crispy french fries'),
                Food(name='Wings', category='Snacks', price=7.99, image_url='https://via.placeholder.com/200', description='Spicy chicken wings')
            ]
            db.session.add_all(foods)
            db.session.commit()
            print("✅ Sample foods created!")
        except Exception as e:
            print(f"❌ Failed to create sample foods: {e}")
            db.session.rollback()
            return False
    
    print("🎉 Database initialization complete!")
    return True

# ============ ROLE DETECTION ============
def detect_user_role(username):
    """Automatically detect if user is admin based on username/email"""
    ADMIN_USERNAME = 'kainmamiadm15@gmail.com'
    return 'admin' if username.lower() == ADMIN_USERNAME.lower() else 'client'

# ============ PASSWORD VALIDATION FUNCTION ============
def validate_password(password):
    """
    Validate password strength
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character (!@#$% etc.)"
    
    return True, "Password is strong"

# ============ AUTHENTICATION DECORATOR ============
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
        except Exception as e:
            return jsonify({'message': 'Token is invalid', 'error': str(e)}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.role != 'admin':
            return jsonify({'message': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# ============ AUTH ROUTES ============
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Validate password
    is_valid, message = validate_password(data['password'])
    if not is_valid:
        return jsonify({'message': message}), 400
    
    # Auto-detect role based on username
    auto_role = detect_user_role(data['username'])
    
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    
    new_user = User(
        username=data['username'],
        password=hashed_password,
        name=data['name'],
        phone=data['phone'],
        role=auto_role
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        
        # Create cart for user after user is committed
        cart = Cart(user_id=new_user.id)
        db.session.add(cart)
        db.session.commit()
        
        return jsonify({
            'message': 'User registered successfully',
            'role': auto_role
        }), 201
    except Exception as e:
        return jsonify({'message': 'Username already exists', 'error': str(e)}), 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    
    if user and check_password_hash(user.password, data['password']):
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
            'role': user.role
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'token': token,
            'user': {
                'id': user.id,
                'username': user.username,
                'name': user.name,
                'phone': user.phone,
                'role': user.role
            }
        }), 200
    
    return jsonify({'message': 'Invalid credentials'}), 401

# ============ FOOD ROUTES ============
@app.route('/api/foods', methods=['GET'])
def get_foods():
    category = request.args.get('category')
    search = request.args.get('search')
    
    query = Food.query.filter_by(is_available=True)
    
    if category:
        query = query.filter_by(category=category)
    if search:
        query = query.filter(Food.name.contains(search))
    
    foods = query.all()
    return jsonify([{
        'id': f.id,
        'name': f.name,
        'category': f.category,
        'price': f.price,
        'image_url': f.image_url,
        'description': f.description,
        'is_available': f.is_available
    } for f in foods]), 200

@app.route('/api/foods/<int:food_id>', methods=['GET'])
def get_food(food_id):
    food = Food.query.get_or_404(food_id)
    return jsonify({
        'id': food.id,
        'name': food.name,
        'category': food.category,
        'price': food.price,
        'image_url': food.image_url,
        'description': food.description,
        'is_available': food.is_available
    }), 200

@app.route('/api/foods', methods=['POST'])
@token_required
@admin_required
def create_food(current_user):
    data = request.get_json()
    new_food = Food(
        name=data['name'],
        category=data['category'],
        price=data['price'],
        image_url=data.get('image_url', ''),
        description=data.get('description', ''),
        is_available=data.get('is_available', True)
    )
    
    db.session.add(new_food)
    db.session.commit()
    
    return jsonify({'message': 'Food created successfully', 'id': new_food.id}), 201

@app.route('/api/foods/<int:food_id>', methods=['PUT'])
@token_required
@admin_required
def update_food(current_user, food_id):
    food = Food.query.get_or_404(food_id)
    data = request.get_json()
    
    food.name = data.get('name', food.name)
    food.category = data.get('category', food.category)
    food.price = data.get('price', food.price)
    food.image_url = data.get('image_url', food.image_url)
    food.description = data.get('description', food.description)
    food.is_available = data.get('is_available', food.is_available)
    
    db.session.commit()
    return jsonify({'message': 'Food updated successfully'}), 200

@app.route('/api/foods/<int:food_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_food(current_user, food_id):
    food = Food.query.get_or_404(food_id)
    db.session.delete(food)
    db.session.commit()
    return jsonify({'message': 'Food deleted successfully'}), 200

@app.route('/api/foods/<int:food_id>/availability', methods=['PUT'])
@token_required
@admin_required
def toggle_food_availability(current_user, food_id):
    food = Food.query.get_or_404(food_id)
    data = request.get_json()
    
    food.is_available = data.get('is_available', not food.is_available)
    db.session.commit()
    
    return jsonify({
        'message': f'Food {"available" if food.is_available else "unavailable"}',
        'is_available': food.is_available
    }), 200

# ============ CART ROUTES ============
@app.route('/api/cart', methods=['GET'])
@token_required
def get_cart(current_user):
    cart = Cart.query.filter_by(user_id=current_user.id).first()
    if not cart:
        cart = Cart(user_id=current_user.id)
        db.session.add(cart)
        db.session.commit()
    
    items = json.loads(cart.food_items) if cart.food_items else []
    
    return jsonify({
        'id': cart.id,
        'items': items,
        'total_price': cart.total_price
    }), 200

@app.route('/api/cart', methods=['POST'])
@token_required
def update_cart(current_user):
    data = request.get_json()
    cart = Cart.query.filter_by(user_id=current_user.id).first()
    
    cart.food_items = json.dumps(data['items'])
    cart.total_price = data['total_price']
    
    db.session.commit()
    return jsonify({'message': 'Cart updated successfully'}), 200

@app.route('/api/cart/clear', methods=['POST'])
@token_required
def clear_cart(current_user):
    cart = Cart.query.filter_by(user_id=current_user.id).first()
    cart.food_items = '[]'
    cart.total_price = 0.0
    db.session.commit()
    return jsonify({'message': 'Cart cleared successfully'}), 200

# ============ ORDER ROUTES ============
@app.route('/api/orders', methods=['GET'])
@token_required
def get_orders(current_user):
    if current_user.role == 'admin':
        orders = Order.query.all()
    else:
        orders = Order.query.filter_by(user_id=current_user.id).all()
    
    return jsonify([{
        'id': o.id,
        'user_id': o.user_id,
        'user_name': o.user.name,
        'items': json.loads(o.food_items),
        'total_price': o.total_price,
        'status': o.status,
        'created_at': o.created_at.strftime('%Y-%m-%d %H:%M:%S')
    } for o in orders]), 200

@app.route('/api/orders', methods=['POST'])
@token_required
def create_order(current_user):
    data = request.get_json()
    
    new_order = Order(
        user_id=current_user.id,
        food_items=json.dumps(data['items']),
        total_price=data['total_price'],
        status='in_process'
    )
    
    db.session.add(new_order)
    
    # Clear cart
    cart = Cart.query.filter_by(user_id=current_user.id).first()
    cart.food_items = '[]'
    cart.total_price = 0.0
    
    db.session.commit()
    
    return jsonify({'message': 'Order placed successfully', 'order_id': new_order.id}), 201

@app.route('/api/orders/<int:order_id>', methods=['PUT'])
@token_required
@admin_required
def update_order_status(current_user, order_id):
    order = Order.query.get_or_404(order_id)
    data = request.get_json()
    
    order.status = data['status']
    db.session.commit()
    
    return jsonify({'message': 'Order status updated successfully'}), 200

# ============ ACCOUNT ROUTES ============
@app.route('/api/account', methods=['GET'])
@token_required
def get_account(current_user):
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'name': current_user.name,
        'phone': current_user.phone,
        'role': current_user.role
    }), 200

@app.route('/api/account', methods=['PUT'])
@token_required
def update_account(current_user):
    data = request.get_json()
    
    current_user.name = data.get('name', current_user.name)
    current_user.phone = data.get('phone', current_user.phone)
    
    if 'password' in data and data['password']:
        current_user.password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    
    db.session.commit()
    return jsonify({'message': 'Account updated successfully'}), 200

# ============ DEBUG ROUTES ============
@app.route('/api/debug/users', methods=['GET'])
def debug_users():
    """Debug route to see all users in database"""
    users = User.query.all()
    user_list = []
    for user in users:
        user_list.append({
            'id': user.id,
            'username': user.username,
            'name': user.name,
            'role': user.role,
            'has_password': bool(user.password)
        })
    return jsonify(user_list), 200

@app.route('/api/debug/test-login', methods=['POST'])
def debug_test_login():
    """Debug route to test login credentials"""
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    
    if user:
        password_match = check_password_hash(user.password, data['password'])
        return jsonify({
            'user_exists': True,
            'password_match': password_match,
            'user_id': user.id,
            'username': user.username,
            'role': user.role
        }), 200
    else:
        return jsonify({'user_exists': False}), 200

# ============ INITIALIZE DATABASE ============
@app.route('/api/init', methods=['GET'])
def init_db():
    """Manual database initialization endpoint"""
    try:
        success = initialize_database()
        if success:
            return jsonify({'message': 'Database initialized successfully'}), 200
        else:
            return jsonify({'message': 'Database initialization failed'}), 500
    except Exception as e:
        return jsonify({'message': 'Initialization failed', 'error': str(e)}), 500

# ============ FRONTEND ROUTES ============
@app.route('/')
def client_page():
    return render_template('client.html')

@app.route('/admin')
def admin_page():
    return render_template('admin.html')

# ============ START APP ============
if __name__ == '__main__':
    with app.app_context():
        initialize_database()
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)