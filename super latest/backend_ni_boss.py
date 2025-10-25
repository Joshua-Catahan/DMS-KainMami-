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
from flask import send_from_directory  
from dotenv import load_dotenv
import re
from flask import send_file
from sqlalchemy.pool import StaticPool
import uuid
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import pytz
import time
from sqlalchemy import text
from collections import defaultdict
from werkzeug.exceptions import BadRequest
import logging  # ADD THIS LINE


# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Philippines timezone
PH_TIMEZONE = pytz.timezone('Asia/Manila')
current_time = datetime.now(PH_TIMEZONE)
# ✅ ADD RATE LIMITING STORAGE
request_log = defaultdict(list)


# ✅ ADD RATE LIMITING DECORATOR FUNCTION
def rate_limit(max_requests=100, window_seconds=60):
    """Rate limiting decorator to prevent API abuse"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client IP address
            client_ip = request.remote_addr
            
            # For development/localhost, use a fallback identifier
            if client_ip in ['127.0.0.1', 'localhost']:
                client_ip = 'local_development'
            
            current_time = time.time()
            
            # Clean old requests (older than the time window)
            request_log[client_ip] = [
                req_time for req_time in request_log[client_ip] 
                if current_time - req_time < window_seconds
            ]
            
            # Check if client has exceeded the rate limit
            if len(request_log[client_ip]) >= max_requests:
                return jsonify({
                    'message': f'Too many requests. Please try again in {window_seconds} seconds.',
                    'error': 'RATE_LIMIT_EXCEEDED'
                }), 429  # HTTP 429 Too Many Requests
            
            # Add current request timestamp
            request_log[client_ip].append(current_time)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

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

# ✅ ADD SECURITY HEADERS MIDDLEWARE
@app.after_request
def set_security_headers(response):
    """Set security headers for all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Content Security Policy for XSS protection
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://cdnjs.cloudflare.com;"
    )
    
    return response

@app.errorhandler(BadRequest)
def handle_bad_request(e):
    """Handle bad requests including malformed JSON"""
    if 'JSON' in str(e) or 'json' in str(e).lower():
        return jsonify({
            'message': 'Invalid JSON data in request',
            'error': 'The request contains malformed JSON data. Please check your request body.'
        }), 400
    return jsonify({
        'message': 'Bad request',
        'error': str(e)
    }), 400

# ============ ENHANCED JSON VALIDATION ============
def validate_json_request():
    """Enhanced JSON validation with better error handling"""
    # Skip validation for non-JSON endpoints
    if request.endpoint in ['upload_image', 'serve_uploaded_file']:
        return None
        
    if request.method in ['POST', 'PUT', 'PATCH']:
        # Check if request has content
        if request.content_length and request.content_length > 0:
            if request.is_json:
                try:
                    # Force parsing to validate
                    request.get_json(force=True, silent=False, cache=True)
                except Exception as e:
                    print(f"❌ JSON Validation Failed: {str(e)}")
                    return jsonify({
                        'message': 'Invalid JSON format in request body',
                        'error': 'Please check your request data format'
                    }), 400
            elif request.content_type and 'application/json' in request.content_type:
                return jsonify({
                    'message': 'Content-Type indicates JSON but content is not valid JSON',
                    'error': 'Invalid JSON data'
                }), 400
    
    return None

@app.before_request
def before_request():
    """Enhanced request validation"""
    # Skip validation for specific endpoints
    if request.endpoint in ['upload_image', 'serve_uploaded_file', 'static']:
        return None
        
    # Enhanced JSON validation with better error messages
    if request.method in ['POST', 'PUT', 'PATCH'] and request.content_length:
        content_type = request.headers.get('Content-Type', '')
        
        if 'application/json' in content_type:
            try:
                # Try to parse JSON to validate
                if request.get_data():
                    request.get_json(force=True, silent=False, cache=True)
            except Exception as e:
                logger.error(f"JSON parsing error: {str(e)}")
                return jsonify({
                    'message': 'Invalid JSON data in request body',
                    'error': 'Please check your request format. Make sure you are not double-stringifying JSON.'
                }), 400
    
    return None

# ✅ ADD SECURITY LOGGING
def log_security_event(event_type, user_id=None, ip_address=None, details=None):
    """Log security-related events"""
    timestamp = datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M:%S')
    ip = ip_address or request.remote_addr
    user_info = f"user_id:{user_id}" if user_id else "anonymous"
    
    log_message = f"[SECURITY] {timestamp} | {event_type} | {user_info} | IP:{ip}"
    if details:
        log_message += f" | Details: {details}"
    
    print(log_message)  # In production, this would go to a proper log file

# ✅ APPLY SECURITY LOGGING TO KEY ENDPOINTS


# ============ INPUT SANITIZATION ============
def sanitize_input(text):
    """Enhanced input sanitization"""
    if not text:
        return text
    
    # Remove potentially dangerous characters and scripts
    text = str(text)
    
    # Remove HTML tags
    text = re.sub(r'<[^>]*>', '', text)
    
    # Remove dangerous characters
    text = re.sub(r'[<>"\']', '', text)
    
    # Remove JavaScript events
    text = re.sub(r'on\w+=\s*"[^"]*"', '', text, flags=re.IGNORECASE)
    text = re.sub(r"on\w+=\s*'[^']*'", '', text, flags=re.IGNORECASE)
    
    # Remove SQL injection patterns
    sql_patterns = [
        r'\b(OR|AND)\b.*=', 
        r'\b(SELECT|UPDATE|DELETE|INSERT|DROP|CREATE)\b',
        r'--', r';', r'\/\*', r'\*\/'
    ]
    for pattern in sql_patterns:
        text = re.sub(pattern, '', text, flags=re.IGNORECASE)
    
    return text.strip()

# ADD input length validation
def validate_input_length(text, max_length=1000, field_name="Input"):
    if text and len(text) > max_length:
        return False, f"{field_name} too long (max {max_length} characters)"
    return True, "Valid"

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
    anonymous_identifier = db.Column(db.String(50), unique=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(pytz.UTC))

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
    payment_status = db.Column(db.String(20), default='pending')
    rating = db.Column(db.Integer)
    comment = db.Column(db.Text)
    rated = db.Column(db.Boolean, default=False)
    delivery_confirmed = db.Column(db.Boolean, default=False)
    delivery_confirmation_sent = db.Column(db.Boolean, default=False)
    notification_shown = db.Column(db.Boolean, default=False)
    proof_image = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(pytz.UTC))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(pytz.UTC), onupdate=lambda: datetime.now(pytz.UTC))

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    food_items = db.Column(db.Text, default='[]')
    total_price = db.Column(db.Float, default=0.0)

class SystemSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ordering_enabled = db.Column(db.Boolean, default=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(pytz.UTC), onupdate=lambda: datetime.now(pytz.UTC))

class PaymentSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    gcash_enabled = db.Column(db.Boolean, default=True)
    paymaya_enabled = db.Column(db.Boolean, default=True)
    cash_enabled = db.Column(db.Boolean, default=True)
    cash_min_orders = db.Column(db.Integer, default=0)  # CHANGED TO 0
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(pytz.UTC), onupdate=lambda: datetime.now(pytz.UTC))

class OrderTypeSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    delivery_enabled = db.Column(db.Boolean, default=True)
    pickup_enabled = db.Column(db.Boolean, default=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(pytz.UTC), onupdate=lambda: datetime.now(pytz.UTC))

class FreedomWall(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='freedom_wall_posts')
    is_anonymous = db.Column(db.Boolean, default=False)  # ADD THIS LINE
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(PH_TIMEZONE))

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=True)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(pytz.UTC))
    user = db.relationship('User', backref='notifications')
    order = db.relationship('Order', backref='notifications')

class OrderMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    sender = db.Column(db.String(20), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    order = db.relationship('Order', backref='messages')

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

def safe_db_commit():
    """Safely commit database changes with proper error handling"""
    try:
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        print(f"❌ Database commit error: {str(e)}")
        raise e
    
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
        # ✅ FIXED: Default to 0 instead of 3
        settings = PaymentSettings(
            gcash_enabled=True,
            paymaya_enabled=True,
            cash_enabled=True,
            cash_min_orders=0  # CHANGED FROM 3 TO 0
        )
        db.session.add(settings)
        db.session.commit()
    
    print(f"💰 Current cash_min_orders: {settings.cash_min_orders}")
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
    """Check if user is eligible for cash payment - FIXED LOGIC"""
    payment_settings = get_payment_settings()
    
    print(f"🔍 Cash eligibility check - User: {user_id}")
    print(f"🔍 Cash settings - enabled: {payment_settings.cash_enabled}, min_orders: {payment_settings.cash_min_orders}")
    
    if not payment_settings.cash_enabled:
        return False, "Cash payment is currently unavailable"
    
    # ✅ FIXED: If admin set to 0, allow immediately
    if payment_settings.cash_min_orders == 0:
        return True, "Eligible for cash payment"
    
    # Count completed online payments (GCash/PayMaya only)
    completed_online_orders = Order.query.filter(
        Order.user_id == user_id,
        Order.status == 'delivered',
        Order.payment_method.in_(['gcash', 'paymaya'])
    ).count()
    
    print(f"📊 User {user_id} has {completed_online_orders} completed online orders (needs {payment_settings.cash_min_orders})")
    
    if completed_online_orders < payment_settings.cash_min_orders:
        message = f"Cash payment requires {payment_settings.cash_min_orders} completed online payments. You have {completed_online_orders}."
        return False, message
    
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

def create_notification(user_id, message, order_id=None):
    """Create notification for specific user ONLY - FIXED VERSION"""
    try:
        user = User.query.get(user_id)
        if not user:
            print(f"❌ User {user_id} not found for notification")
            return False
            
        print(f"📢 Creating notification for user {user_id} ({user.role}): {message}")
        
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
        print(f"❌ Error creating notification: {e}")
        return False
        
def get_anonymous_identifier(user_id):
    user = User.query.get(user_id)
    if not user.anonymous_identifier:
        anonymous_users = User.query.filter(
            User.anonymous_identifier.isnot(None),
            User.role == 'client'
        ).count()
        user.anonymous_identifier = f"Anonymous #{anonymous_users + 1}"
        db.session.commit()
    return user.anonymous_identifier

def mark_all_notifications_read(user_id):
    """Mark all notifications as read for a user"""
    try:
        Notification.query.filter_by(user_id=user_id, is_read=False).update({'is_read': True})
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        return False

def validate_gcash_input(account_number, reference_number):
    """Validate GCash inputs"""
    if not account_number.isdigit() or len(account_number) != 11:
        return False, "GCash mobile number must be 11 digits"
    if not reference_number.isdigit() or len(reference_number) != 13:
        return False, "GCash reference number must be 13 digits"
    return True, "Valid"

def validate_paymaya_input(account_number, reference_number):
    """Validate PayMaya inputs"""
    if not account_number.isdigit() or len(account_number) != 11:
        return False, "PayMaya mobile number must be 11 digits"
    return True, "Valid"

# ============ DATABASE INITIALIZATION ============
def initialize_database():
    """Initialize database with admin user and sample data"""
    print("🔄 Initializing database...")
    
    db.create_all()
    
    # Initialize settings FIRST
    settings = get_system_settings()
    payment_settings = get_payment_settings()  # This now creates with cash_min_orders=0
    order_settings = get_order_type_settings()


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
                role='admin',
                anonymous_identifier='Administrator'
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
    """Enhanced password validation with common password check"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if len(password) > 128:
        return False, "Password too long (max 128 characters)"
    
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character (!@#$% etc.)"
    
    # Check for common weak passwords
    common_passwords = [
        'password', '123456', '12345678', '123456789', 'admin123',
        'qwerty', 'abc123', 'letmein', 'welcome', 'password1'
    ]
    
    if password.lower() in common_passwords:
        return False, "Password is too common. Please choose a stronger password."
    
    # Check for sequential characters
    if re.search(r'(.)\1{2,}', password):
        return False, "Password contains too many repeating characters"
    
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
            
            # Validate token format
            if not re.match(r'^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$', token):
                return jsonify({'message': 'Invalid token format'}), 401
                
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = db.session.get(User, data['user_id'])
            
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired. Please login again.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token. Please login again.'}), 401
        except Exception as e:
            return jsonify({'message': 'Token verification failed', 'error': str(e)}), 401
            
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
    """Handle image uploads for food items and payment proofs - FIXED VERSION"""
    print("🔄 Upload endpoint hit")
    
    # Check if request contains files
    if 'image' not in request.files:
        print("❌ No image file in request.files")
        return jsonify({'message': 'No image file provided'}), 400
    
    file = request.files['image']
    print(f"📁 File received: {file.filename}")
    
    if file.filename == '':
        print("❌ Empty filename")
        return jsonify({'message': 'No selected file'}), 400
    
    # Check if file is allowed BEFORE trying to save
    if not allowed_file(file.filename):
        print(f"❌ File type not allowed: {file.filename}")
        return jsonify({'message': 'Invalid file type. Allowed types: PNG, JPG, JPEG, GIF, WEBP'}), 400
    
    try:
        # Generate secure filename
        file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        if not file_ext:
            return jsonify({'message': 'File must have an extension'}), 400
            
        filename = f"{uuid.uuid4().hex}.{file_ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        print(f"💾 Saving file to: {filepath}")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        # Save file
        file.save(filepath)
        
        # Verify file was saved
        if not os.path.exists(filepath):
            print("❌ File was not saved successfully")
            return jsonify({'message': 'Failed to save file'}), 500
        
        # Return full URL for web access
        image_url = f"/static/uploads/{filename}"
        
        print(f"✅ Image uploaded successfully: {image_url}")
        
        return jsonify({
            'message': 'Image uploaded successfully',
            'image_url': image_url
        }), 200
        
    except Exception as e:
        print(f"❌ Upload error: {str(e)}")
        # Clean up if file was partially saved
        if 'filepath' in locals() and os.path.exists(filepath):
            try:
                os.remove(filepath)
            except:
                pass
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
    
    # ✅ ADD VALIDATION
    if data is None:
        return jsonify({'message': 'No data provided'}), 400
        
    if 'enabled' not in data:
        return jsonify({'message': 'Missing enabled field'}), 400
        
    settings = get_system_settings()
    
    try:
        settings.ordering_enabled = bool(data['enabled'])
        db.session.commit()
        
        status = "enabled" if settings.ordering_enabled else "disabled"
        return jsonify({
            'message': f'Ordering system {status}',
            'enabled': settings.ordering_enabled
        }), 200
    except Exception as e:
        db.session.rollback()
        print(f"❌ System status update failed: {str(e)}")
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
    # ✅ FIXED: Better JSON handling
    if not request.is_json:
        return jsonify({'message': 'Content-Type must be application/json'}), 415
        
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Invalid JSON data'}), 400
        
    settings = get_payment_settings()
    
    try:
        if 'gcash' in data:
            settings.gcash_enabled = data['gcash']
        if 'paymaya' in data:
            settings.paymaya_enabled = data['paymaya']
        if 'cash' in data:
            settings.cash_enabled = data['cash']
        if 'cash_min_orders' in data:
            settings.cash_min_orders = int(data['cash_min_orders'])
        
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
@rate_limit(max_requests=3, window_seconds=15)  # ✅ 3 registrations per 5 minutes
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
@rate_limit(max_requests=5, window_seconds=60)
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    
    if user and check_password_hash(user.password, data['password']):
        # In login route, extend token expiration:
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.now(pytz.UTC) + timedelta(days=30),  # Extended to 30 days
            'role': user.role,
            'iat': datetime.now(pytz.UTC)
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

# ============ TOKEN REFRESH ENDPOINT ============
@app.route('/api/refresh-token', methods=['POST'])
@token_required
def refresh_token(current_user):
    """Refresh JWT token to prevent session expiry - FIXED"""
    try:
        # Create new token with extended expiration
        new_token = jwt.encode({
            'user_id': current_user.id,
            'exp': datetime.now(pytz.UTC) + timedelta(days=30),  # 30 days
            'role': current_user.role,
            'iat': datetime.now(pytz.UTC)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        print(f"🔄 Token refreshed for user {current_user.id}")
        
        return jsonify({
            'token': new_token,
            'message': 'Token refreshed successfully'
        }), 200
        
    except Exception as e:
        print(f"❌ Token refresh failed: {str(e)}")
        return jsonify({'message': 'Failed to refresh token'}), 500
        
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
    # ✅ FIXED: Better JSON handling
    if not request.is_json:
        return jsonify({'message': 'Content-Type must be application/json'}), 415
        
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Invalid JSON data'}), 400
    
    if not data.get('name') or not data.get('category') or not data.get('price'):
        return jsonify({'message': 'Name, category, and price are required'}), 400
    
    # Image URL is optional - set to empty string if not provided
    image_url = data.get('image_url', '')

    new_food = Food(
        name=sanitize_input(data['name']),
        category=sanitize_input(data['category']),
        price=float(data['price']),
        image_url=sanitize_input(image_url),  # Use the variable we set above
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
    
@app.route('/api/orders/<int:order_id>/complete-delivery', methods=['POST'])
@token_required
@admin_required
def complete_delivery(current_user, order_id):
    """Mark order as delivered and trigger confirmation"""
    order = Order.query.get_or_404(order_id)
    
    try:
        order.status = 'delivered'
        order.delivery_confirmation_sent = True
        order.updated_at = datetime.now(pytz.UTC)
        
        # Notify client to confirm delivery
        create_notification(
            user_id=order.user_id,
            message=f'Your order #{order_id} has been delivered. Please confirm receipt.',
            order_id=order_id
        )
        
        db.session.commit()
        return jsonify({'message': 'Delivery completed. Waiting for client confirmation.'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to complete delivery', 'error': str(e)}), 500

# ADD this route to get ratings for admin
@app.route('/api/ratings', methods=['GET'])
@token_required
@admin_required
def get_all_ratings(current_user):
    """Get all ratings and feedback for admin"""
    try:
        rated_orders = Order.query.filter(
            Order.rated == True,
            Order.rating.isnot(None)
        ).order_by(Order.updated_at.desc()).all()
        
        ratings_data = []
        for order in rated_orders:
            ratings_data.append({
                'order_id': order.id,
                'user_name': order.user.name,
                'rating': order.rating,
                'comment': order.comment,
                'rated_at': order.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
                'items': json.loads(order.food_items)
            })
        
        return jsonify({
            'total_ratings': len(ratings_data),
            'average_rating': sum(r['rating'] for r in ratings_data) / len(ratings_data) if ratings_data else 0,
            'ratings': ratings_data
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to load ratings', 'error': str(e)}), 500
    
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
        # Image URL is optional - use empty string if not provided
        new_image_url = data.get('image_url', food.image_url)
        food.image_url = sanitize_input(new_image_url) if new_image_url else ''
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
        'special_instructions': o.special_instructions,
        'payment_method': o.payment_method,
        'payment_details': json.loads(o.payment_details) if o.payment_details else None,
        'payment_status': o.payment_status,
        'proof_image': o.proof_image,
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
        'payment_status': order.payment_status,
        'proof_image': order.proof_image,
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
@rate_limit(max_requests=10, window_seconds=60)
def create_order(current_user):
    settings = get_system_settings()
    if not settings.ordering_enabled:
        return jsonify({'message': 'Ordering system is currently closed'}), 400
    
    data = request.get_json()
    
    # Debug logging
    print(f"🔄 Creating order for user {current_user.id}, data: {data}")
    
    if not data.get('items') or len(data['items']) == 0:
        return jsonify({'message': 'No items in order'}), 400
    
    order_type = data.get('order_type', 'delivery')
    is_available, message = check_order_type_availability(order_type)
    if not is_available:
        return jsonify({'message': message}), 400
    
    payment_method = data.get('payment_method')
    payment_settings = get_payment_settings()
    
    if payment_method == 'gcash' and not payment_settings.gcash_enabled:
        return jsonify({'message': 'GCash payment is currently unavailable'}), 400
    elif payment_method == 'paymaya' and not payment_settings.paymaya_enabled:
        return jsonify({'message': 'PayMaya payment is currently unavailable'}), 400
    elif payment_method == 'cash':
        is_eligible, message = check_cash_eligibility(current_user.id)
        if not is_eligible:
            return jsonify({'message': message}), 400
    
    if order_type == 'delivery' and not data.get('delivery_address'):
        return jsonify({'message': 'Delivery address is required for delivery orders'}), 400
    
    if payment_method in ['gcash', 'paymaya']:
        payment_details = data.get('payment_details', {})
        account_number = payment_details.get('account_number', '')
        reference_number = payment_details.get('reference_number', '')
        
        if payment_method == 'gcash':
            is_valid, validation_message = validate_gcash_input(account_number, reference_number)
            if not is_valid:
                return jsonify({'message': validation_message}), 400
        elif payment_method == 'paymaya':
            is_valid, validation_message = validate_paymaya_input(account_number, reference_number)
            if not is_valid:
                return jsonify({'message': validation_message}), 400
    
    try:
        new_order = Order(
            user_id=current_user.id,
            food_items=json.dumps(data['items']),
            total_price=float(data['total_price']),
            order_type=order_type,
            delivery_address=sanitize_input(data.get('delivery_address')),
            special_instructions=sanitize_input(data.get('special_instructions')),
            payment_method=payment_method,
            payment_details=json.dumps(data.get('payment_details')) if data.get('payment_details') else None,
            proof_image=data.get('proof_image'),
            status=data.get('status', 'waiting_approval'),
            # ✅ FIXED: Cash payments start as pending, online payments as pending until approved
            payment_status='pending'  # Both cash and online start as pending
        )
        
        db.session.add(new_order)
        
        # Clear user's cart
        cart = Cart.query.filter_by(user_id=current_user.id).first()
        if cart:
            cart.food_items = '[]'
            cart.total_price = 0.0
        
        db.session.commit()
        
        # Send notification to all admins about new order
        admin_users = User.query.filter_by(role='admin').all()
        for admin in admin_users:
            create_notification(
                user_id=admin.id,
                message=f'New order #{new_order.id} received from {current_user.name}',
                order_id=new_order.id
            )
        
        print(f"✅ Order created successfully: {new_order.id}")
                
        return jsonify({
            'message': 'Order placed successfully',
            'order_id': new_order.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Order creation failed: {str(e)}")
        return jsonify({'message': 'Failed to create order', 'error': str(e)}), 500
    
@app.route('/api/orders/<int:order_id>', methods=['PUT'])
@token_required
def update_order(current_user, order_id):
    order = Order.query.get_or_404(order_id)
    
    if current_user.role != 'admin' and order.user_id != current_user.id:
        return jsonify({'message': 'Access denied'}), 403
    
    data = request.get_json()
    
    try:
        # ✅ FIXED: Allow clients to cancel their own orders
        if 'status' in data and data['status'] == 'cancelled':
            # Clients can only cancel orders that are waiting approval
            if current_user.role != 'admin' and order.status != 'waiting_approval':
                return jsonify({'message': 'Can only cancel orders that are waiting approval'}), 400
            
            order.status = 'cancelled'
            order.updated_at = datetime.now(pytz.UTC)
            
            # Notify appropriate users
            if current_user.role == 'admin':
                create_notification(
                    user_id=order.user_id,
                    message=f'Your order #{order_id} has been cancelled by admin',
                    order_id=order_id
                )
            else:
                # Notify admins about client cancellation
                admin_users = User.query.filter_by(role='admin').all()
                for admin in admin_users:
                    create_notification(
                        user_id=admin.id,
                        message=f'Order #{order_id} has been cancelled by {current_user.name}',
                        order_id=order_id
                    )
        
        elif current_user.role == 'admin' and 'status' in data:
            # Admin status updates (existing logic)
            old_status = order.status
            new_status = data['status']
            
            valid_statuses = ['waiting_approval', 'in_process', 'ready', 'delivered', 'cancelled']
            if new_status not in valid_statuses:
                return jsonify({'message': f'Invalid status: {new_status}'}), 400
            
            order.status = new_status
            order.updated_at = datetime.now(pytz.UTC)
            
            # Notify client about status changes
            if old_status != new_status:
                create_notification(
                    user_id=order.user_id,
                    message=f'Order #{order_id} status changed to {new_status.replace("_", " ").title()}',
                    order_id=order_id
                )
        
        db.session.commit()
        return jsonify({'message': 'Order updated successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to update order', 'error': str(e)}), 500
        
@app.route('/api/orders/<int:order_id>/approve', methods=['PUT'])
@token_required
@admin_required
def approve_order(current_user, order_id):
    try:
        order = Order.query.get_or_404(order_id)
        
        if order.status != 'waiting_approval':
            return jsonify({
                'message': f'Order is not pending approval. Current status: {order.status}'
            }), 400
        
        # ✅ FIXED: Only update payment status for online payments, keep cash as pending
        if order.payment_method in ['gcash', 'paymaya']:
            order.payment_status = 'paid'
        # For cash payments, payment_status remains 'pending' until delivered
        
        order.status = 'in_process'
        order.updated_at = datetime.now(pytz.UTC)
        
        create_notification(
            user_id=order.user_id,
            message=f'Your order #{order_id} has been approved and is being processed',
            order_id=order_id
        )
        
        db.session.commit()
        return jsonify({'message': 'Order approved successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to approve order', 'error': str(e)}), 500

# ============ ORDER NOTIFICATION ROUTES ============
@app.route('/api/orders/<int:order_id>/notify-ready', methods=['POST'])
@token_required
@admin_required
def notify_order_ready(current_user, order_id):
    order = Order.query.get_or_404(order_id)
    
    try:
        if order.status != 'ready':
            order.status = 'ready'
            order.updated_at = datetime.now(datetime.UTC)
        
        create_notification(
            user_id=order.user_id,
            message=f'Your order #{order_id} is ready for {order.order_type}',
            order_id=order_id
        )
        
        db.session.commit()
        return jsonify({'message': 'Ready notification sent successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to send ready notification', 'error': str(e)}), 500

@app.route('/api/orders/<int:order_id>/client-ready', methods=['POST'])
@token_required
def client_ready_for_pickup(current_user, order_id):
    order = Order.query.get_or_404(order_id)
    
    if order.user_id != current_user.id:
        return jsonify({'message': 'Access denied'}), 403
    
    try:
        admin_users = User.query.filter_by(role='admin').all()
        
        for admin in admin_users:
            if admin.id != current_user.id:
                create_notification(
                    user_id=admin.id,
                    message=f'Client ready for pickup - Order #{order_id} from {current_user.name}',
                    order_id=order_id
                )
        
        return jsonify({'message': 'Pickup notification sent to admin'}), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to send pickup notification', 'error': str(e)}), 500

# ============ DELIVERY CONFIRMATION ROUTES ============
@app.route('/api/orders/pending-delivery', methods=['GET'])
@token_required
def get_pending_delivery_confirmations(current_user):
    """Get orders pending delivery confirmation - FIXED"""
    try:
        if current_user.role == 'admin':
            orders = Order.query.filter(
                Order.status == 'delivered',
                Order.delivery_confirmed == False
            ).all()
        else:
            orders = Order.query.filter(
                Order.user_id == current_user.id,
                Order.status == 'delivered',
                Order.delivery_confirmed == False
            ).all()
        
        return jsonify([{
            'id': o.id,
            'user_name': o.user.name,
            'items': json.loads(o.food_items),
            'total_price': o.total_price,
            'order_type': o.order_type,
            'delivery_address': o.delivery_address,
            'created_at': o.created_at.strftime('%Y-%m-%d %H:%M:%S')
        } for o in orders]), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to load pending deliveries', 'error': str(e)}), 500

# ============ COMPLETE DELIVERY & RATING FLOW ============
@app.route('/api/orders/<int:order_id>/deliver', methods=['POST'])
@token_required
@admin_required
def mark_order_delivered(current_user, order_id):
    """Mark order as delivered and update cash payment status"""
    order = Order.query.get_or_404(order_id)
    
    try:
        # Validate order can be marked as delivered
        if order.status not in ['ready', 'in_process']:
            return jsonify({
                'message': f'Order must be ready or in process to mark as delivered. Current status: {order.status}'
            }), 400
        
        order.status = 'delivered'
        order.updated_at = datetime.now(pytz.UTC)
        
        # ✅ FIXED: Update cash payment status to paid when delivered
        if order.payment_method == 'cash':
            order.payment_status = 'paid'
        
        # Notify client to confirm delivery
        create_notification(
            user_id=order.user_id,
            message=f'Your order #{order_id} has been delivered. Please confirm receipt.',
            order_id=order_id
        )
        
        db.session.commit()
        
        return jsonify({
            'message': 'Order marked as delivered successfully',
            'order_id': order_id,
            'status': 'delivered'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to mark order as delivered', 'error': str(e)}), 500

@app.route('/api/orders/<int:order_id>/confirm-delivery', methods=['POST'])
@token_required
def confirm_delivery(current_user, order_id):
    """Client confirms delivery - FIXED"""
    order = Order.query.get_or_404(order_id)
    
    if order.user_id != current_user.id:
        return jsonify({'message': 'Access denied'}), 403
    
    try:
        if order.status != 'delivered':
            return jsonify({'message': 'Order is not marked as delivered'}), 400
        
        if order.delivery_confirmed:
            return jsonify({'message': 'Delivery already confirmed'}), 400
        
        order.delivery_confirmed = True
        order.updated_at = datetime.now(pytz.UTC)
        
        db.session.commit()
        
        # Automatically show rating modal after confirmation
        return jsonify({
            'message': 'Delivery confirmed successfully!',
            'show_rating': True,
            'order_id': order_id
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to confirm delivery', 'error': str(e)}), 500


@app.route('/api/orders/<int:order_id>/report-issue', methods=['POST'])
@token_required
def report_delivery_issue(current_user, order_id):
    order = Order.query.get_or_404(order_id)
    
    if order.user_id != current_user.id:
        return jsonify({'message': 'Access denied'}), 403
    
    data = request.get_json()
    issue = data.get('issue', 'Delivery issue reported')
    
    try:
        admin_users = User.query.filter_by(role='admin').all()
        
        for admin in admin_users:
            if admin.id != current_user.id:
                create_notification(
                    user_id=admin.id,
                    message=f'Delivery issue reported for order #{order_id}: {issue}',
                    order_id=order_id
                )
        
        return jsonify({'message': 'Issue reported successfully'}), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to report issue', 'error': str(e)}), 500

# ============ RATING SYSTEM ROUTES ============
@app.route('/api/orders/<int:order_id>/request-rating', methods=['POST'])
@token_required
@admin_required
def request_rating(current_user, order_id):
    order = Order.query.get_or_404(order_id)
    
    try:
        if order.status != 'delivered' or order.rated:
            return jsonify({'message': 'Cannot request rating for this order'}), 400
        
        create_notification(
            user_id=order.user_id,
            message=f'Please rate your experience with order #{order_id}',
            order_id=order_id
        )
        
        return jsonify({'message': 'Rating request sent successfully'}), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to send rating request', 'error': str(e)}), 500

@app.route('/api/orders/<int:order_id>/rate', methods=['POST'])
@token_required
def rate_order(current_user, order_id):
    """Submit rating for delivered order - FIXED"""
    order = Order.query.get_or_404(order_id)
    
    if order.user_id != current_user.id:
        return jsonify({'message': 'Access denied'}), 403
    
    data = request.get_json()
    
    # Validate input
    if not data:
        return jsonify({'message': 'No rating data provided'}), 400
    
    rating = data.get('rating')
    comment = sanitize_input(data.get('comment', ''))
    
    # Validate rating
    if not rating or not isinstance(rating, int) or rating < 1 or rating > 5:
        return jsonify({'message': 'Valid rating (1-5) is required'}), 400
    
    try:
        # Check if order can be rated
        if order.status != 'delivered':
            return jsonify({'message': 'Can only rate delivered orders'}), 400
        
        if order.rated:
            return jsonify({'message': 'Order already rated'}), 400
        
        if not order.delivery_confirmed:
            return jsonify({'message': 'Please confirm delivery before rating'}), 400
        
        # Update order with rating
        order.rating = rating
        order.comment = comment
        order.rated = True
        order.updated_at = datetime.now(pytz.UTC)
        
        # Notify admin about the rating
        admin_users = User.query.filter_by(role='admin').all()
        for admin in admin_users:
            if admin.id != current_user.id:
                create_notification(
                    user_id=admin.id,
                    message=f'Order #{order_id} rated {rating} stars by {current_user.name}',
                    order_id=order_id
                )
        
        db.session.commit()
        
        return jsonify({
            'message': 'Rating submitted successfully! Thank you for your feedback.',
            'order_id': order_id,
            'rating': rating
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Rating submission error: {str(e)}")
        return jsonify({'message': 'Failed to submit rating', 'error': str(e)}), 500



# ============ FOLLOW-UP MESSAGES ROUTES ============
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
        create_notification(
            user_id=order.user_id,
            message=f'Follow-up for order #{order_id}: {message}',
            order_id=order_id
        )
        
        return jsonify({'message': 'Follow-up message sent successfully'}), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to send follow-up message', 'error': str(e)}), 500

# ============ FREEDOM WALL ROUTES ============
@app.route('/api/freedom-wall', methods=['GET'])
def get_freedom_wall():
    try:
        posts = FreedomWall.query.order_by(FreedomWall.created_at.desc()).limit(50).all()
        
        posts_data = []
        for post in posts:
            if post.is_anonymous and post.user.role != 'admin':
                display_name = get_anonymous_identifier(post.user_id)
            elif post.user.role == 'admin':
                display_name = 'Administrator'
            else:
                display_name = post.user.name
                
            posts_data.append({
                'id': post.id,
                'content': post.content,
                'user_name': display_name,
                'created_at': post.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'is_anonymous': post.is_anonymous
            })
        
        return jsonify(posts_data), 200
    except Exception as e:
        return jsonify({'message': 'Failed to load freedom wall', 'error': str(e)}), 500

@app.route('/api/freedom-wall', methods=['POST'])
@token_required
@rate_limit(max_requests=10, window_seconds=60)
def create_freedom_wall_post(current_user):
    data = request.get_json()
    content = sanitize_input(data.get('content', '').strip())
    is_anonymous = data.get('is_anonymous', False)
    
    if not content:
        return jsonify({'message': 'Content is required'}), 400
    
    if len(content) > 500:
        return jsonify({'message': 'Content too long (max 500 characters)'}), 400
    
    try:
        post = FreedomWall(
            content=content,
            user_id=current_user.id,
            is_anonymous=is_anonymous
        )
        
        db.session.add(post)
        db.session.commit()
        
        # Determine display name
        if current_user.role == 'admin':
            display_name = 'Administrator'
        elif is_anonymous:
            display_name = get_anonymous_identifier(current_user.id)
        else:
            display_name = current_user.name
        
        return jsonify({
            'message': 'Post created successfully',
            'post': {
                'id': post.id,
                'content': post.content,
                'user_name': display_name,
                'created_at': post.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'is_anonymous': is_anonymous
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to create post', 'error': str(e)}), 500
    
# ============ NOTIFICATION ROUTES ============
@app.route('/api/notifications', methods=['GET'])
@token_required
def get_notifications(current_user):
    try:
        # ✅ FIXED: Each user only sees their own notifications
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).limit(50).all()
        
        return jsonify([{
            'id': n.id,
            'message': n.message,
            'order_id': n.order_id,
            'is_read': n.is_read,
            'created_at': n.created_at.strftime('%Y-%m-%d %H:%M:%S')
        } for n in notifications]), 200
    except Exception as e:
        return jsonify({'message': 'Failed to load notifications', 'error': str(e)}), 500

# ============ FIXED NOTIFICATION ENDPOINTS ============
@app.route('/api/notifications/mark-all-read', methods=['PUT'])
@token_required
def mark_all_notifications_read_route(current_user):
    """Fixed: Mark all notifications as read for current user"""
    try:
        # Use proper SQLAlchemy update syntax
        notifications_to_update = Notification.query.filter_by(
            user_id=current_user.id, 
            is_read=False
        ).all()
        
        for notification in notifications_to_update:
            notification.is_read = True
            
        db.session.commit()
        return jsonify({
            'message': 'All notifications marked as read',
            'updated_count': len(notifications_to_update)
        }), 200
    except Exception as e:
        db.session.rollback()
        print(f"❌ Mark all read error: {str(e)}")
        return jsonify({
            'message': 'Failed to mark all notifications as read', 
            'error': str(e)
        }), 500

@app.route('/api/notifications/<int:notification_id>/read', methods=['PUT'])
@token_required
def mark_notification_read(current_user, notification_id):
    """Fixed: Mark single notification as read"""
    try:
        notification = Notification.query.get_or_404(notification_id)
        
        # Check if user owns this notification
        if notification.user_id != current_user.id:
            return jsonify({'message': 'Access denied'}), 403
        
        notification.is_read = True
        db.session.commit()
        
        return jsonify({
            'message': 'Notification marked as read',
            'notification_id': notification_id
        }), 200
    except Exception as e:
        db.session.rollback()
        print(f"❌ Mark read error: {str(e)}")
        return jsonify({
            'message': 'Failed to mark notification as read', 
            'error': str(e)
        }), 500

# ============ ORDER MESSAGES ROUTES ============
@app.route('/api/orders/<int:order_id>/messages', methods=['GET'])
@token_required
def get_order_messages(current_user, order_id):
    order = Order.query.get_or_404(order_id)
    
    if current_user.role != 'admin' and order.user_id != current_user.id:
        return jsonify({'message': 'Access denied'}), 403
    
    try:
        messages = OrderMessage.query.filter_by(order_id=order_id).order_by(OrderMessage.timestamp.asc()).all()
        
        return jsonify([{
            'id': msg.id,
            'sender': msg.sender,
            'content': msg.content,
            'image_url': msg.image_url,
            'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        } for msg in messages]), 200
    except Exception as e:
        return jsonify({'message': 'Failed to load messages', 'error': str(e)}), 500

@app.route('/api/orders/<int:order_id>/messages', methods=['POST'])
@token_required
def send_order_message(current_user, order_id):
    order = Order.query.get_or_404(order_id)
    
    if current_user.role != 'admin' and order.user_id != current_user.id:
        return jsonify({'message': 'Access denied'}), 403
    
    data = request.get_json()
    content = sanitize_input(data.get('content', '').strip())
    image_url = data.get('image_url')
    
    if not content and not image_url:
        return jsonify({'message': 'Message content or image is required'}), 400
    
    try:
        sender = 'admin' if current_user.role == 'admin' else 'client'
        
        message = OrderMessage(
            order_id=order_id,
            sender=sender,
            content=content,
            image_url=image_url
        )
        
        db.session.add(message)
        
        # ✅ FIXED: Proper notification targeting
        if current_user.role == 'admin':
            # Admin sending to client - notify CLIENT only
            create_notification(
                user_id=order.user_id,
                message=f'New message from admin regarding order #{order_id}',
                order_id=order_id
            )
        else:
            # Client sending to admin - notify ALL admins (except themselves if they're also admin)
            admin_users = User.query.filter_by(role='admin').all()
            for admin in admin_users:
                if admin.id != current_user.id:  # Don't notify yourself
                    create_notification(
                        user_id=admin.id,
                        message=f'New message from {current_user.name} regarding order #{order_id}',
                        order_id=order_id
                    )
        
        db.session.commit()
        return jsonify({'message': 'Message sent successfully'}), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to send message', 'error': str(e)}), 500
    
@app.route('/api/analytics', methods=['GET'])
@token_required
@admin_required
def get_analytics(current_user):
    period = request.args.get('period', 'today')
    
    try:
        # ✅ FIXED: Use UTC time for calculations
        now = datetime.now(pytz.UTC)
        if period == 'today':
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif period == 'week':
            start_date = now - timedelta(days=now.weekday())
            start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
        elif period == 'month':
            start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        elif period == 'year':
            start_date = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        else:
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
        
        # ✅ FIXED: Handle case where there are no orders
        orders = Order.query.filter(
            Order.created_at >= start_date,
            Order.status == 'delivered'
        ).all()
        
        total_revenue = sum(order.total_price for order in orders)
        total_orders = len(orders)
        
        item_sales = {}
        for order in orders:
            try:
                items = json.loads(order.food_items)
                for item in items:
                    item_id = item.get('id')
                    item_name = item.get('name')
                    quantity = item.get('quantity', 1)
                    price = item.get('price', 0)
                    
                    if item_id not in item_sales:
                        item_sales[item_id] = {
                            'name': item_name,
                            'quantity_sold': 0,
                            'revenue': 0
                        }
                    
                    item_sales[item_id]['quantity_sold'] += quantity
                    item_sales[item_id]['revenue'] += price * quantity
            except Exception as e:
                print(f"❌ Error processing order {order.id}: {e}")
                continue
        
        # ✅ FIXED: Handle empty top_items
        top_items = sorted(item_sales.values(), key=lambda x: x['quantity_sold'], reverse=True)[:5]
        popular_item = top_items[0]['name'] if top_items else "No items sold"
        
        return jsonify({
            'total_revenue': total_revenue,
            'total_orders': total_orders,
            'popular_item': popular_item,
            'top_items': top_items
        }), 200
        
    except Exception as e:
        print(f"❌ Analytics error: {str(e)}")
        # ✅ FIXED: Return empty data instead of 500 error
        return jsonify({
            'total_revenue': 0,
            'total_orders': 0,
            'popular_item': "No data",
            'top_items': []
        }), 200

# ============ USER OVERVIEW ROUTES ============
@app.route('/api/users', methods=['GET'])
@token_required
def get_users(current_user):
    """Get all users for admin overview"""
    if current_user.role != 'admin':
        return jsonify({'message': 'Admin access required'}), 403
    
    try:
        users = User.query.filter(User.role != 'admin').all()
        return jsonify([{
            'id': user.id,
            'username': user.username,
            'name': user.name,
            'phone': user.phone,
            'role': user.role,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S')
        } for user in users]), 200
    except Exception as e:
        return jsonify({'message': 'Failed to load users', 'error': str(e)}), 500
    
@app.route('/api/admin/users', methods=['GET'])
@token_required
@admin_required
def get_users_overview(current_user):
    try:
        users = User.query.filter(User.role != 'admin').all()
        
        user_data = []
        for user in users:
            total_orders = Order.query.filter_by(user_id=user.id).count()
            completed_orders = Order.query.filter_by(user_id=user.id, status='delivered').count()
            pending_orders = Order.query.filter_by(user_id=user.id, status='waiting_approval').count()
            
            last_order = Order.query.filter_by(user_id=user.id).order_by(Order.created_at.desc()).first()
            last_order_date = last_order.created_at.strftime('%Y-%m-%d %H:%M:%S') if last_order else 'No orders'
            
            user_data.append({
                'id': user.id,
                'username': user.username,
                'name': user.name,
                'phone': user.phone,
                'total_orders': total_orders,
                'completed_orders': completed_orders,
                'pending_orders': pending_orders,
                'anonymous_identifier': user.anonymous_identifier,
                'last_order': last_order_date
            })
        
        return jsonify({
            'total_users': len(users),
            'users': user_data
        }), 200
    except Exception as e:
        return jsonify({'message': 'Failed to load user overview', 'error': str(e)}), 500

@app.route('/api/users', methods=['GET'])
@token_required
@admin_required
def get_all_users(current_user):
    try:
        users = User.query.filter(User.role != 'admin').all()
        
        return jsonify([{
            'id': user.id,
            'username': user.username,
            'name': user.name,
            'phone': user.phone,
            'role': user.role,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S')
        } for user in users]), 200
    except Exception as e:
        return jsonify({'message': 'Failed to load users', 'error': str(e)}), 500

# ============ USER DETAILS ENDPOINT ============
@app.route('/api/users/<int:user_id>', methods=['GET'])
@token_required
@admin_required
def get_user_details(current_user, user_id):
    user = User.query.get_or_404(user_id)
    return jsonify({
        'id': user.id,
        'username': user.username,
        'name': user.name,
        'phone': user.phone,
        'role': user.role,
        'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S')
    }), 200

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
        if 'name' in data:
            current_user.name = sanitize_input(data['name'])
        if 'phone' in data:
            current_user.phone = sanitize_input(data['phone'])
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

# ============ STATIC FILE SERVING ============
@app.route('/static/uploads/<path:filename>')
def serve_uploaded_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        return jsonify({'message': 'File not found'}), 404

# ============ ERROR HANDLERS ============
@app.errorhandler(404)
def not_found(error):
    return jsonify({'message': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'message': 'Internal server error'}), 500

@app.errorhandler(413)
def too_large(error):
    return jsonify({'message': 'File too large. Maximum size is 5MB.'}), 413

# ============ APPLICATION STARTUP ============
@app.route('/')
def serve_client():
    return render_template('client.html')

@app.route('/admin')
def serve_admin():
    return render_template('admin.html')

if __name__ == '__main__':
    with app.app_context():
        print("🚀 Starting Food Ordering System...")
        if initialize_database():
            print("✅ Database initialized successfully!")
            print("\n📋 Available Routes:")
            print("   👤 Client: http://localhost:5000")
            print("   👑 Admin:  http://localhost:5000/admin")
            print("\n🔑 Admin Credentials:")
            print("   Email: kainmamiadm15@gmail.com")
            print("   Password: Admin123!")
            print("\n🎯 System is ready!")
        else:
            print("❌ Failed to initialize database!")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
        