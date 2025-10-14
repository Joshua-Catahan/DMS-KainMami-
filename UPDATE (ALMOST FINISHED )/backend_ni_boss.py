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
from sqlalchemy.pool import StaticPool
import uuid
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from datetime import datetime, timedelta
import pytz  # Add this import at the top

# Philippines timezone
PH_TIMEZONE = pytz.timezone('Asia/Manila')

# ============ INPUT SANITIZATION ============
def sanitize_input(text):
    """Basic input sanitization"""
    if not text:
        return text
    # Remove potentially dangerous characters
    return re.sub(r'[<>"\']', '', text.strip())

load_dotenv()
app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-dev-key-only')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///food_ordering.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'poolclass': StaticPool,
    'connect_args': {'check_same_thread': False}
}

# Image upload configuration
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

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
    status = db.Column(db.String(20), default='waiting_approval')
    order_type = db.Column(db.String(20), default='delivery')
    delivery_address = db.Column(db.Text)
    special_instructions = db.Column(db.Text)
    payment_method = db.Column(db.String(20))
    payment_details = db.Column(db.Text)
    rating = db.Column(db.Integer)
    comment = db.Column(db.Text)
    rated = db.Column(db.Boolean, default=False)
    delivery_confirmed = db.Column(db.Boolean, default=False)
    delivery_confirmation_sent = db.Column(db.Boolean, default=False)
    notification_shown = db.Column(db.Boolean, default=False)
    proof_image = db.Column(db.String(500))  # NEW: Store proof of payment image
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    food_items = db.Column(db.Text, default='[]')
    total_price = db.Column(db.Float, default=0.0)

class SystemSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ordering_enabled = db.Column(db.Boolean, default=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class PaymentSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    gcash_enabled = db.Column(db.Boolean, default=True)
    paymaya_enabled = db.Column(db.Boolean, default=True)
    cash_enabled = db.Column(db.Boolean, default=True)
    cash_min_orders = db.Column(db.Integer, default=3)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class OrderTypeSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    delivery_enabled = db.Column(db.Boolean, default=True)
    pickup_enabled = db.Column(db.Boolean, default=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# NEW: Freedom Wall Model
class FreedomWall(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='freedom_wall_posts')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(PH_TIMEZONE))

# NEW: Notifications Model
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=True)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='notifications')
    order = db.relationship('Order', backref='notifications')

# ============ HELPER FUNCTIONS ============
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_uploaded_file(file):
    """Save uploaded file and return the URL"""
    if file and allowed_file(file.filename):
        file_ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"{uuid.uuid4().hex}.{file_ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return f"/static/uploads/{filename}"
    return None

def get_system_settings():
    settings = SystemSettings.query.first()
    if not settings:
        settings = SystemSettings(ordering_enabled=True)
        db.session.add(settings)
        db.session.commit()
    return settings

def get_payment_settings():
    settings = PaymentSettings.query.first()
    if not settings:
        settings = PaymentSettings(
            gcash_enabled=True,
            paymaya_enabled=True,
            cash_enabled=True,
            cash_min_orders=3
        )
        db.session.add(settings)
        db.session.commit()
    return settings

def get_order_type_settings():
    settings = OrderTypeSettings.query.first()
    if not settings:
        settings = OrderTypeSettings(
            delivery_enabled=True,
            pickup_enabled=True
        )
        db.session.add(settings)
        db.session.commit()
    return settings

def check_cash_eligibility(user_id):
    """Check if user is eligible for cash payment"""
    payment_settings = get_payment_settings()
    if not payment_settings.cash_enabled:
        return False, "Cash payment is currently unavailable"
    
    completed_online_orders = Order.query.filter(
        Order.user_id == user_id,
        Order.status == 'delivered',
        Order.payment_method.in_(['gcash', 'paymaya'])
    ).count()
    
    if completed_online_orders < payment_settings.cash_min_orders:
        return False, f"Cash payment requires {payment_settings.cash_min_orders} completed online payments. You have {completed_online_orders}."
    
    return True, "Eligible for cash payment"

def check_order_type_availability(order_type):
    """Check if order type is available"""
    order_settings = get_order_type_settings()
    
    if order_type == 'delivery':
        if not order_settings.delivery_enabled:
            return False, "Delivery is currently unavailable"
    elif order_type == 'pickup':
        if not order_settings.pickup_enabled:
            return False, "Pickup is currently unavailable"
    
    return True, "Order type available"

# NEW: Create notification function
def create_notification(user_id, message, order_id=None):
    """Create a new notification for user"""
    try:
        notification = Notification(
            user_id=user_id,
            message=message,
            order_id=order_id
        )
        db.session.add(notification)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        print(f"Error creating notification: {e}")
        return False

# ============ DATABASE INITIALIZATION ============
def initialize_database():
    """Initialize database with admin user and sample data"""
    print("🔄 Initializing database...")
    
    db.create_all()
    
    get_system_settings()
    get_payment_settings()
    get_order_type_settings()
    
    admin_user = User.query.filter_by(username='kainmamiadm15@gmail.com').first()
    if not admin_user:
        print("👑 Creating admin user...")
        
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
            db.session.commit()
            print(f"✅ Admin user created with ID: {admin_user.id}")
        except Exception as e:
            print(f"❌ Failed to create admin user: {e}")
            db.session.rollback()
            return False
        
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
    
    if Food.query.count() == 0:
        print("🍕 Creating sample foods...")
        try:
            sample_foods = [
                {
                    "name": "Classic Pancakes",
                    "category": "Breakfast",
                    "price": 120.00,
                    "image_url": "https://images.unsplash.com/photo-1567620905732-2d1ec7ab7445?w=400&h=300&fit=crop",
                    "description": "Fluffy buttermilk pancakes served with maple syrup and butter"
                },
                {
                    "name": "Bacon & Eggs",
                    "category": "Breakfast", 
                    "price": 150.00,
                    "image_url": "https://images.unsplash.com/photo-1551892374-ecf8754cf8b0?w=400&h=300&fit=crop",
                    "description": "Crispy bacon with sunny-side-up eggs and toast"
                },
                {
                    "name": "Breakfast Burrito",
                    "category": "Breakfast",
                    "price": 130.00,
                    "image_url": "https://images.unsplash.com/photo-1626700051175-6818013e1bd4?w=400&h=300&fit=crop",
                    "description": "Scrambled eggs, cheese, and sausage wrapped in a warm tortilla"
                },
                {
                    "name": "Classic Burger",
                    "category": "Lunch",
                    "price": 180.00,
                    "image_url": "https://images.unsplash.com/photo-1568901346375-23c9450c58cd?w=400&h=300&fit=crop",
                    "description": "Beef patty with lettuce, tomato, cheese, and special sauce"
                },
                {
                    "name": "Chicken Caesar Salad",
                    "category": "Lunch",
                    "price": 160.00,
                    "image_url": "https://images.unsplash.com/photo-1546793665-c74683f339c1?w=400&h=300&fit=crop",
                    "description": "Fresh romaine lettuce with grilled chicken and Caesar dressing"
                },
                {
                    "name": "Margherita Pizza",
                    "category": "Lunch",
                    "price": 220.00,
                    "image_url": "https://images.unsplash.com/photo-1604068549290-dea0e4a305ca?w=400&h=300&fit=crop",
                    "description": "Classic pizza with tomato sauce, mozzarella, and fresh basil"
                },
                {
                    "name": "French Fries",
                    "category": "Snacks",
                    "price": 80.00,
                    "image_url": "https://images.unsplash.com/photo-1573080496219-bb080dd4f877?w=400&h=300&fit=crop",
                    "description": "Crispy golden fries served with ketchup"
                },
                {
                    "name": "Chicken Wings",
                    "category": "Snacks",
                    "price": 140.00,
                    "image_url": "https://images.unsplash.com/photo-1567620832903-9fc6debc209f?w=400&h=300&fit=crop",
                    "description": "Spicy buffalo wings with blue cheese dip"
                },
                {
                    "name": "Mozzarella Sticks",
                    "category": "Snacks",
                    "price": 100.00,
                    "image_url": "https://images.unsplash.com/photo-1531749668029-2db88e4276c7?w=400&h=300&fit=crop",
                    "description": "Breaded mozzarella sticks with marinara sauce"
                },
                {
                    "name": "Grilled Salmon",
                    "category": "Dinner",
                    "price": 280.00,
                    "image_url": "https://images.unsplash.com/photo-1467003909585-2f8a72700288?w=400&h=300&fit=crop",
                    "description": "Fresh salmon fillet with lemon butter sauce and vegetables"
                },
                {
                    "name": "Beef Steak",
                    "category": "Dinner",
                    "price": 350.00,
                    "image_url": "https://images.unsplash.com/photo-1600891964092-4316c288032e?w=400&h=300&fit=crop",
                    "description": "Tender beef steak with mashed potatoes and gravy"
                },
                {
                    "name": "Pasta Carbonara",
                    "category": "Dinner",
                    "price": 190.00,
                    "image_url": "https://images.unsplash.com/photo-1621996346565-e3dbc353d2e5?w=400&h=300&fit=crop",
                    "description": "Creamy pasta with bacon, eggs, and parmesan cheese"
                },
                {
                    "name": "Chocolate Cake",
                    "category": "Dessert",
                    "price": 120.00,
                    "image_url": "https://images.unsplash.com/photo-1578985545062-69928b1d9587?w=400&h=300&fit=crop",
                    "description": "Rich chocolate cake with chocolate frosting"
                },
                {
                    "name": "Ice Cream Sundae",
                    "category": "Dessert",
                    "price": 90.00,
                    "image_url": "https://images.unsplash.com/photo-1563805042-7684c019e1cb?w=400&h=300&fit=crop",
                    "description": "Vanilla ice cream with chocolate sauce and sprinkles"
                },
                {
                    "name": "Cheesecake",
                    "category": "Dessert",
                    "price": 140.00,
                    "image_url": "https://images.unsplash.com/photo-1567306301408-9b74779a11af?w=400&h=300&fit=crop",
                    "description": "Creamy New York style cheesecake with berry compote"
                }
            ]
            
            for food_data in sample_foods:
                food = Food(
                    name=food_data['name'],
                    category=food_data['category'],
                    price=food_data['price'],
                    image_url=food_data['image_url'],
                    description=food_data['description'],
                    is_available=True
                )
                db.session.add(food)
            
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

# ============ IMAGE UPLOAD ROUTE ============
@app.route('/api/upload', methods=['POST'])
@token_required
def upload_image(current_user):
    """Handle image uploads for food items and payment proofs"""
    if 'image' not in request.files:
        return jsonify({'message': 'No image file provided'}), 400
    
    file = request.files['image']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400
    
    try:
        image_url = save_uploaded_file(file)
        if image_url:
            return jsonify({
                'message': 'Image uploaded successfully',
                'image_url': image_url
            }), 200
        else:
            return jsonify({'message': 'Invalid file type. Allowed types: PNG, JPG, JPEG, GIF, WEBP'}), 400
    except Exception as e:
        return jsonify({'message': 'Failed to upload image', 'error': str(e)}), 500

# ============ SYSTEM SETTINGS ROUTES ============
@app.route('/api/system/ordering', methods=['GET'])
def get_ordering_status():
    settings = get_system_settings()
    return jsonify({'enabled': settings.ordering_enabled})

@app.route('/api/system/ordering', methods=['PUT'])
@token_required
@admin_required
def update_ordering_status(current_user):
    data = request.get_json()
    settings = get_system_settings()
    
    try:
        settings.ordering_enabled = data.get('enabled', True)
        db.session.commit()
        
        status = "enabled" if settings.ordering_enabled else "disabled"
        return jsonify({
            'message': f'Ordering system {status}',
            'enabled': settings.ordering_enabled
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to update system settings', 'error': str(e)}), 500

# ============ PAYMENT SETTINGS ROUTES ============
@app.route('/api/payment-methods', methods=['GET'])
def get_payment_methods():
    settings = get_payment_settings()
    order_settings = get_order_type_settings()
    
    return jsonify({
        'methods': {
            'gcash': settings.gcash_enabled,
            'paymaya': settings.paymaya_enabled,
            'cash': settings.cash_enabled
        },
        'cash_min_orders': settings.cash_min_orders,
        'order_types': {
            'delivery': order_settings.delivery_enabled,
            'pickup': order_settings.pickup_enabled
        }
    }), 200

@app.route('/api/payment-methods', methods=['PUT'])
@token_required
@admin_required
def update_payment_methods(current_user):
    data = request.get_json()
    settings = get_payment_settings()
    
    try:
        if 'gcash' in data:
            settings.gcash_enabled = data['gcash']
        if 'paymaya' in data:
            settings.paymaya_enabled = data['paymaya']
        if 'cash' in data:
            settings.cash_enabled = data['cash']
        if 'cash_min_orders' in data:
            settings.cash_min_orders = data['cash_min_orders']
        
        db.session.commit()
        
        return jsonify({
            'message': 'Payment methods updated successfully',
            'methods': {
                'gcash': settings.gcash_enabled,
                'paymaya': settings.paymaya_enabled,
                'cash': settings.cash_enabled
            },
            'cash_min_orders': settings.cash_min_orders
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to update payment methods', 'error': str(e)}), 500

# ============ ORDER TYPE SETTINGS ROUTES ============
@app.route('/api/order-types', methods=['PUT'])
@token_required
@admin_required
def update_order_types(current_user):
    data = request.get_json()
    settings = get_order_type_settings()
    
    try:
        if 'delivery' in data:
            settings.delivery_enabled = data['delivery']
        if 'pickup' in data:
            settings.pickup_enabled = data['pickup']
        
        db.session.commit()
        
        return jsonify({
            'message': 'Order types updated successfully',
            'order_types': {
                'delivery': settings.delivery_enabled,
                'pickup': settings.pickup_enabled
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to update order types', 'error': str(e)}), 500

# ============ AUTH ROUTES ============
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    is_valid, message = validate_password(data['password'])
    if not is_valid:
        return jsonify({'message': message}), 400
    
    auto_role = detect_user_role(data['username'])
    
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    
    new_user = User(
        username=sanitize_input(data['username']),
        password=hashed_password,
        name=sanitize_input(data['name']),
        phone=sanitize_input(data['phone']),
        role=auto_role
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        
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
            'exp': datetime.utcnow() + timedelta(hours=24),
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
    settings = get_system_settings()
    if not settings.ordering_enabled and not request.headers.get('Authorization'):
        return jsonify([]), 200
    
    category = request.args.get('category')
    search = request.args.get('search')
    
    query = Food.query
    
    if not request.headers.get('Authorization'):
        query = query.filter_by(is_available=True)
    
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
    
    if not data.get('name') or not data.get('category') or not data.get('price'):
        return jsonify({'message': 'Name, category, and price are required'}), 400
    
    new_food = Food(
        name=sanitize_input(data['name']),
        category=sanitize_input(data['category']),
        price=float(data['price']),
        image_url=sanitize_input(data.get('image_url', '')),
        description=sanitize_input(data.get('description', '')),
        is_available=data.get('is_available', True)
    )
    
    try:
        db.session.add(new_food)
        db.session.commit()
        
        return jsonify({
            'message': 'Food created successfully', 
            'id': new_food.id,
            'food': {
                'id': new_food.id,
                'name': new_food.name,
                'category': new_food.category,
                'price': new_food.price,
                'image_url': new_food.image_url,
                'description': new_food.description,
                'is_available': new_food.is_available
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to create food', 'error': str(e)}), 500

@app.route('/api/foods/<int:food_id>', methods=['PUT'])
@token_required
@admin_required
def update_food(current_user, food_id):
    food = Food.query.get_or_404(food_id)
    data = request.get_json()
    
    try:
        food.name = sanitize_input(data.get('name', food.name))
        food.category = sanitize_input(data.get('category', food.category))
        food.price = float(data.get('price', food.price))
        food.image_url = sanitize_input(data.get('image_url', food.image_url))
        food.description = sanitize_input(data.get('description', food.description))
        food.is_available = data.get('is_available', food.is_available)
        
        db.session.commit()
        return jsonify({'message': 'Food updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to update food', 'error': str(e)}), 500

@app.route('/api/foods/<int:food_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_food(current_user, food_id):
    food = Food.query.get_or_404(food_id)
    try:
        db.session.delete(food)
        db.session.commit()
        return jsonify({'message': 'Food deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to delete food', 'error': str(e)}), 500

@app.route('/api/foods/<int:food_id>/availability', methods=['PUT'])
@token_required
@admin_required
def toggle_food_availability(current_user, food_id):
    food = Food.query.get_or_404(food_id)
    data = request.get_json()
    
    try:
        food.is_available = data.get('is_available', not food.is_available)
        db.session.commit()
        
        return jsonify({
            'message': f'Food {"available" if food.is_available else "unavailable"}',
            'is_available': food.is_available
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to update food availability', 'error': str(e)}), 500

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
        orders = Order.query.order_by(Order.created_at.desc()).all()
    else:
        orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    
    return jsonify([{
        'id': o.id,
        'user_id': o.user_id,
        'user_name': o.user.name,
        'items': json.loads(o.food_items),
        'total_price': o.total_price,
        'status': o.status,
        'order_type': o.order_type,
        'delivery_address': o.delivery_address,
        'payment_method': o.payment_method,
        'payment_details': json.loads(o.payment_details) if o.payment_details else None,
        'proof_image': o.proof_image,  # NEW: Include proof image in response
        'rating': o.rating,
        'comment': o.comment,
        'rated': o.rated,
        'delivery_confirmed': o.delivery_confirmed,
        'notification_shown': o.notification_shown,
        'created_at': o.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'updated_at': o.updated_at.strftime('%Y-%m-%d %H:%M:%S')
    } for o in orders]), 200

@app.route('/api/orders/<int:order_id>', methods=['GET'])
@token_required
def get_order(current_user, order_id):
    order = Order.query.get_or_404(order_id)
    
    if current_user.role != 'admin' and order.user_id != current_user.id:
        return jsonify({'message': 'Access denied'}), 403
    
    return jsonify({
        'id': order.id,
        'user_id': order.user_id,
        'user_name': order.user.name,
        'items': json.loads(order.food_items),
        'total_price': order.total_price,
        'status': order.status,
        'order_type': order.order_type,
        'delivery_address': order.delivery_address,
        'special_instructions': order.special_instructions,
        'payment_method': order.payment_method,
        'payment_details': json.loads(order.payment_details) if order.payment_details else None,
        'proof_image': order.proof_image,  # NEW: Include proof image
        'rating': order.rating,
        'comment': order.comment,
        'rated': order.rated,
        'delivery_confirmed': order.delivery_confirmed,
        'notification_shown': order.notification_shown,
        'created_at': order.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'updated_at': order.updated_at.strftime('%Y-%m-%d %H:%M:%S')
    }), 200

@app.route('/api/orders', methods=['POST'])
@token_required
def create_order(current_user):
    settings = get_system_settings()
    if not settings.ordering_enabled:
        return jsonify({'message': 'Ordering system is currently closed'}), 400
    
    data = request.get_json()
    
    if not data.get('items') or len(data['items']) == 0:
        return jsonify({'message': 'Order must contain at least one item'}), 400
    
    order_type = data.get('order_type', 'delivery')
    is_available, message = check_order_type_availability(order_type)
    if not is_available:
        return jsonify({'message': message}), 400
    
    payment_settings = get_payment_settings()
    payment_method = data.get('payment_method', 'cash')
    
    if payment_method == 'gcash' and not payment_settings.gcash_enabled:
        return jsonify({'message': 'GCash payment is currently unavailable'}), 400
    elif payment_method == 'paymaya' and not payment_settings.paymaya_enabled:
        return jsonify({'message': 'PayMaya payment is currently unavailable'}), 400
    elif payment_method == 'cash' and not payment_settings.cash_enabled:
        return jsonify({'message': 'Cash payment is currently unavailable'}), 400
    
    if payment_method == 'cash':
        is_eligible, message = check_cash_eligibility(current_user.id)
        if not is_eligible:
            return jsonify({'message': message}), 400
    
    if order_type == 'delivery' and not data.get('delivery_address'):
        return jsonify({'message': 'Delivery address is required for delivery orders'}), 400
    
    # Handle proof image for online payments
    proof_image = None
    if payment_method in ['gcash', 'paymaya']:
        payment_details = data.get('payment_details', {})
        if not payment_details.get('account_name') or not payment_details.get('account_number') or not payment_details.get('reference_number'):
            return jsonify({'message': 'Payment details are required for online payments'}), 400
        
        # Store proof image URL if provided
        proof_image = payment_details.get('proof_image')
    
    try:
        new_order = Order(
            user_id=current_user.id,
            food_items=json.dumps(data['items']),
            total_price=float(data['total_price']),
            status='waiting_approval',
            order_type=order_type,
            delivery_address=data.get('delivery_address'),
            special_instructions=data.get('special_instructions'),
            payment_method=data.get('payment_method', 'cash'),
            payment_details=json.dumps(data.get('payment_details')) if data.get('payment_details') else None,
            proof_image=proof_image  # NEW: Store proof image
        )
        
        db.session.add(new_order)
        
        # Clear cart
        cart = Cart.query.filter_by(user_id=current_user.id).first()
        cart.food_items = '[]'
        cart.total_price = 0.0
        
        db.session.commit()
        
        # NEW: Create notification for admin
        create_notification(
            user_id=current_user.id,  # Notify admin in real app, here notifying user
            message=f"New order #{new_order.id} received from {current_user.name}",
            order_id=new_order.id
        )
        
        return jsonify({
            'message': 'Order placed successfully', 
            'order_id': new_order.id
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to place order', 'error': str(e)}), 500

@app.route('/api/orders/<int:order_id>', methods=['PUT'])
@token_required
@admin_required
def update_order_status(current_user, order_id):
    order = Order.query.get_or_404(order_id)
    data = request.get_json()
    
    valid_statuses = ['waiting_approval', 'in_process', 'ready', 'delivered']
    if data['status'] not in valid_statuses:
        return jsonify({'message': 'Invalid status'}), 400
    
    try:
        old_status = order.status
        order.status = data['status']
        order.updated_at = datetime.utcnow()
        
        # Reset notification shown flag when status changes to ready
        if data['status'] == 'ready':
            order.notification_shown = False
            
        db.session.commit()
        
        # NEW: Create notification for client when status changes
        if old_status != data['status']:
            status_messages = {
                'in_process': 'Your order is now being prepared',
                'ready': 'Your order is ready for pickup/delivery',
                'delivered': 'Your order has been delivered'
            }
            if data['status'] in status_messages:
                create_notification(
                    user_id=order.user_id,
                    message=f"Order #{order_id}: {status_messages[data['status']]}",
                    order_id=order_id
                )
        
        return jsonify({'message': 'Order status updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to update order status', 'error': str(e)}), 500

@app.route('/api/orders/<int:order_id>/approve', methods=['PUT'])
@token_required
@admin_required
def approve_order(current_user, order_id):
    order = Order.query.get_or_404(order_id)
    
    try:
        order.status = 'in_process'
        order.updated_at = datetime.utcnow()
        db.session.commit()
        
        # NEW: Notify client
        create_notification(
            user_id=order.user_id,
            message=f"Order #{order_id}: Payment approved! Your order is now being prepared.",
            order_id=order_id
        )
        
        return jsonify({'message': 'Order approved successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to approve order', 'error': str(e)}), 500

@app.route('/api/orders/<int:order_id>/notify-ready', methods=['POST'])
@token_required
@admin_required
def notify_order_ready(current_user, order_id):
    order = Order.query.get_or_404(order_id)
    
    try:
        order.notification_shown = True
        db.session.commit()
        
        # NEW: Enhanced notification
        create_notification(
            user_id=order.user_id,
            message=f"Order #{order_id}: Your order is ready for {order.order_type}!",
            order_id=order_id
        )
        
        app.logger.info(f"Order {order_id} ready notification sent to customer {order.user_id}")
        
        return jsonify({'message': 'Ready notification sent successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to send notification', 'error': str(e)}), 500

# NEW: Follow-up message route
@app.route('/api/orders/<int:order_id>/follow-up', methods=['POST'])
@token_required
@admin_required
def send_follow_up(current_user, order_id):
    order = Order.query.get_or_404(order_id)
    data = request.get_json()
    
    message = data.get('message', '')
    if not message:
        return jsonify({'message': 'Message is required'}), 400
    
    try:
        # Create notification for client
        create_notification(
            user_id=order.user_id,
            message=f"Order #{order_id}: {message}",
            order_id=order_id
        )
        
        return jsonify({'message': 'Follow-up message sent successfully'}), 200
    except Exception as e:
        return jsonify({'message': 'Failed to send follow-up message', 'error': str(e)}), 500

# NEW: Client ready for pickup notification
@app.route('/api/orders/<int:order_id>/client-ready', methods=['POST'])
@token_required
def client_ready_for_pickup(current_user, order_id):
    order = Order.query.get_or_404(order_id)
    
    if order.user_id != current_user.id:
        return jsonify({'message': 'Access denied'}), 403
    
    if order.status != 'ready':
        return jsonify({'message': 'Order is not ready for pickup'}), 400
    
    try:
        # Find admin user to notify
        admin_user = User.query.filter_by(role='admin').first()
        if admin_user:
            create_notification(
                user_id=admin_user.id,
                message=f"Client ready for pickup: Order #{order_id} from {current_user.name} is about to be picked up. Please prepare the order.",
                order_id=order_id
            )
        
        # Also notify the client
        create_notification(
            user_id=current_user.id,
            message=f"Order #{order_id}: We've notified the admin that you're ready for pickup. Your order will be prepared shortly.",
            order_id=order_id
        )
        
        return jsonify({'message': 'Pickup notification sent successfully'}), 200
    except Exception as e:
        return jsonify({'message': 'Failed to send pickup notification', 'error': str(e)}), 500

@app.route('/api/orders/<int:order_id>/deliver', methods=['POST'])
@token_required
@admin_required
def mark_order_delivered(current_user, order_id):
    order = Order.query.get_or_404(order_id)
    
    try:
        order.status = 'delivered'
        order.delivery_confirmation_sent = True
        order.updated_at = datetime.utcnow()
        db.session.commit()
        
        # NEW: Enhanced notification
        create_notification(
            user_id=order.user_id,
            message=f"Order #{order_id}: Your order has been delivered! Please confirm receipt.",
            order_id=order_id
        )
        
        return jsonify({'message': 'Order marked as delivered'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to mark order as delivered', 'error': str(e)}), 500

@app.route('/api/orders/pending-delivery', methods=['GET'])
@token_required
def get_pending_delivery_confirmations(current_user):
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    orders = Order.query.filter(
        Order.user_id == current_user.id,
        Order.status == 'delivered',
        Order.delivery_confirmation_sent == True,
        Order.delivery_confirmed == False,
        Order.updated_at >= one_hour_ago
    ).all()
    
    return jsonify({
        'orders': [{
            'id': o.id,
            'items': json.loads(o.food_items),
            'total_price': o.total_price,
            'created_at': o.created_at.strftime('%Y-%m-%d %H:%M:%S')
        } for o in orders]
    }), 200

@app.route('/api/orders/<int:order_id>/confirm-delivery', methods=['POST'])
@token_required
def confirm_delivery(current_user, order_id):
    order = Order.query.get_or_404(order_id)
    
    if order.user_id != current_user.id:
        return jsonify({'message': 'Access denied'}), 403
    
    try:
        order.delivery_confirmed = True
        order.updated_at = datetime.utcnow()
        db.session.commit()
        
        # NEW: Notify admin
        admin_user = User.query.filter_by(role='admin').first()
        if admin_user:
            create_notification(
                user_id=admin_user.id,
                message=f"Order #{order_id}: Delivery confirmed by {current_user.name}",
                order_id=order_id
            )
        
        return jsonify({'message': 'Delivery confirmed successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to confirm delivery', 'error': str(e)}), 500

@app.route('/api/orders/<int:order_id>/report-issue', methods=['POST'])
@token_required
def report_delivery_issue(current_user, order_id):
    order = Order.query.get_or_404(order_id)
    data = request.get_json()
    
    if order.user_id != current_user.id:
        return jsonify({'message': 'Access denied'}), 403
    
    try:
        app.logger.info(f"Delivery issue reported for order {order_id}: {data.get('issue')}")
        
        # NEW: Notify admin about issue
        admin_user = User.query.filter_by(role='admin').first()
        if admin_user:
            create_notification(
                user_id=admin_user.id,
                message=f"ISSUE: Order #{order_id} - {data.get('issue', 'Unknown issue')} reported by {current_user.name}",
                order_id=order_id
            )
        
        return jsonify({'message': 'Issue reported successfully'}), 200
    except Exception as e:
        return jsonify({'message': 'Failed to report issue', 'error': str(e)}), 500

@app.route('/api/orders/<int:order_id>/request-rating', methods=['POST'])
@token_required
@admin_required
def request_rating(current_user, order_id):
    order = Order.query.get_or_404(order_id)
    
    try:
        create_notification(
            user_id=order.user_id,
            message=f"Order #{order_id}: How was your experience? Please rate your order!",
            order_id=order_id
        )
        
        app.logger.info(f"Rating requested for order {order_id}")
        
        return jsonify({'message': 'Rating request sent'}), 200
    except Exception as e:
        return jsonify({'message': 'Failed to send rating request', 'error': str(e)}), 500

@app.route('/api/orders/<int:order_id>/rate', methods=['POST'])
@token_required
def rate_order(current_user, order_id):
    order = Order.query.get_or_404(order_id)
    data = request.get_json()
    
    if order.user_id != current_user.id:
        return jsonify({'message': 'Access denied'}), 403
    
    if order.status != 'delivered':
        return jsonify({'message': 'Can only rate delivered orders'}), 400
    
    try:
        order.rating = data.get('rating')
        order.comment = data.get('comment')
        order.rated = True
        order.updated_at = datetime.utcnow()
        db.session.commit()
        
        # NEW: Notify admin about rating
        admin_user = User.query.filter_by(role='admin').first()
        if admin_user:
            create_notification(
                user_id=admin_user.id,
                message=f"Order #{order_id} rated {data.get('rating')}/5 by {current_user.name}",
                order_id=order_id
            )
        
        return jsonify({'message': 'Rating submitted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to submit rating', 'error': str(e)}), 500

# ============ NOTIFICATION ROUTES ============
@app.route('/api/notifications', methods=['GET'])
@token_required
def get_notifications(current_user):
    """Get user's notifications"""
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    
    return jsonify([{
        'id': n.id,
        'message': n.message,
        'order_id': n.order_id,
        'is_read': n.is_read,
        'created_at': n.created_at.strftime('%Y-%m-%d %H:%M:%S')
    } for n in notifications]), 200

@app.route('/api/notifications/<int:notification_id>/read', methods=['PUT'])
@token_required
def mark_notification_read(current_user, notification_id):
    """Mark notification as read"""
    notification = Notification.query.get_or_404(notification_id)
    
    if notification.user_id != current_user.id:
        return jsonify({'message': 'Access denied'}), 403
    
    try:
        notification.is_read = True
        db.session.commit()
        return jsonify({'message': 'Notification marked as read'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to mark notification as read', 'error': str(e)}), 500

@app.route('/api/notifications/read-all', methods=['PUT'])
@token_required
def mark_all_notifications_read(current_user):
    """Mark all user notifications as read"""
    try:
        Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
        db.session.commit()
        return jsonify({'message': 'All notifications marked as read'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to mark notifications as read', 'error': str(e)}), 500

# ============ FREEDOM WALL ROUTES ============
@app.route('/api/freedom-wall', methods=['GET'])
def get_freedom_wall():
    """Get all freedom wall posts"""
    posts = FreedomWall.query.order_by(FreedomWall.created_at.desc()).all()
    
    posts_data = []
    for p in posts:
        # CHANGE: Check if user is admin or client
        if p.user.role == 'admin':
            user_name = 'Administrator'
        else:
            user_name = 'Anonymous'
        
        posts_data.append({
            'id': p.id,
            'content': p.content,
            'user_name': user_name,  # Show 'Administrator' or 'Anonymous'
            'user_role': p.user.role,  # Include role for frontend if needed
            'created_at': p.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify(posts_data), 200

@app.route('/api/freedom-wall', methods=['POST'])
@token_required
def create_freedom_wall_post(current_user):
    """Create a new freedom wall post"""
    data = request.get_json()
    content = data.get('content', '').strip()
    
    if not content:
        return jsonify({'message': 'Content is required'}), 400
    
    # CHANGE: Update max characters from 500 to 100
    if len(content) > 100:
        return jsonify({'message': 'Content too long (max 100 characters)'}), 400
    
    try:
        post = FreedomWall(
            content=content,
            user_id=current_user.id
        )
        db.session.add(post)
        db.session.commit()
        
        # CHANGE: Return appropriate display name based on role
        display_name = 'Administrator' if current_user.role == 'admin' else 'Anonymous'
        
        return jsonify({
            'message': 'Post created successfully',
            'post': {
                'id': post.id,
                'content': post.content,
                'user_name': display_name,  # 'Administrator' or 'Anonymous'
                'user_role': current_user.role,
                'created_at': post.created_at.strftime('%Y-%m-%d %I:%M %p')
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to create post', 'error': str(e)}), 500
    
# ============ ANALYTICS ROUTES ============
@app.route('/api/analytics', methods=['GET'])
@token_required
@admin_required
def get_analytics(current_user):
    period = request.args.get('period', 'today')
    
    now = datetime.utcnow()
    if period == 'today':
        start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif period == 'week':
        start_date = now - timedelta(days=7)
    elif period == 'month':
        start_date = now - timedelta(days=30)
    elif period == 'year':
        start_date = now - timedelta(days=365)
    else:
        start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
    
    try:
        orders = Order.query.filter(
            Order.created_at >= start_date,
            Order.status == 'delivered'
        ).all()
        
        total_revenue = sum(order.total_price for order in orders)
        total_orders = len(orders)
        
        item_sales = {}
        for order in orders:
            items = json.loads(order.food_items)
            for item in items:
                item_id = item['id']
                if item_id not in item_sales:
                    item_sales[item_id] = {
                        'name': item['name'],
                        'category': Food.query.get(item_id).category if Food.query.get(item_id) else 'Unknown',
                        'quantity_sold': 0,
                        'revenue': 0
                    }
                item_sales[item_id]['quantity_sold'] += item['quantity']
                item_sales[item_id]['revenue'] += item['price'] * item['quantity']
        
        top_items = sorted(item_sales.values(), key=lambda x: x['revenue'], reverse=True)[:5]
        
        popular_item = max(item_sales.values(), key=lambda x: x['quantity_sold'])['name'] if item_sales else None
        
        return jsonify({
            'total_revenue': total_revenue,
            'total_orders': total_orders,
            'popular_item': popular_item,
            'top_items': top_items
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to generate analytics', 'error': str(e)}), 500

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
    
    try:
        current_user.name = sanitize_input(data.get('name', current_user.name))
        current_user.phone = sanitize_input(data.get('phone', current_user.phone))

        if 'password' in data and data['password']:
            is_valid, message = validate_password(data['password'])
            if not is_valid:
                return jsonify({'message': message}), 400
            current_user.password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        
        db.session.commit()
        return jsonify({'message': 'Account updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to update account', 'error': str(e)}), 500

# ============ DEBUG ROUTES ============
@app.route('/api/debug/users', methods=['GET'])
def debug_users():
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
    try:
        success = initialize_database()
        if success:
            return jsonify({'message': 'Database initialized successfully'}), 200
        else:
            return jsonify({'message': 'Database initialization failed'}), 500
    except Exception as e:
        return jsonify({'message': 'Initialization failed', 'error': str(e)}), 500

# ============ STATIC FILE SERVING ============
@app.route('/static/uploads/<filename>')
def serve_uploaded_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

# ============ FRONTEND ROUTES ============
@app.route('/')
def client_page():
    return render_template('client.html')

@app.route('/admin')
def admin_page():
    return render_template('admin.html')

# ============ ERROR HANDLERS ============
@app.errorhandler(404)
def not_found(error):
    return jsonify({'message': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'message': 'Internal server error'}), 500

# ============ START APP ============
if __name__ == '__main__':
    with app.app_context():
        initialize_database()
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)