from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from models import db, User, Product, Order, OrderItem, CartItem, Favorite, AuditLog, PIIViolation
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
import stripe
import os
import sys
from dotenv import load_dotenv
from datetime import datetime, timedelta
import secrets

# Force unbuffered output
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

load_dotenv()

# Middleware to handle /eshop prefix
class PrefixMiddleware:
    def __init__(self, app, prefix='/eshop'):
        self.app = app
        self.prefix = prefix

    def __call__(self, environ, start_response):
        # Set SCRIPT_NAME so Flask knows to prefix all URLs
        if environ.get('HTTP_X_FORWARDED_PREFIX'):
            environ['SCRIPT_NAME'] = environ['HTTP_X_FORWARDED_PREFIX']
        return self.app(environ, start_response)

app = Flask(__name__)

# Flask Configuration
app.config['SECRET_KEY'] = 'dev-secret-key-12345'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///eshop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['WTF_CSRF_ENABLED'] = False

# Apply middleware stack
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.wsgi_app = PrefixMiddleware(app.wsgi_app)

# Email configuration - load from environment variables
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'demo@securebook.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', 'demo-password')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'SecureBook E-Shop <noreply@securebook.com>')

stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
STRIPE_PUBLIC_KEY = os.getenv('STRIPE_PUBLIC_KEY')

# Verify keys are loaded
if not stripe.api_key or not STRIPE_PUBLIC_KEY:
    print("⚠️  WARNING: Stripe keys not found in environment variables!", flush=True)
    print("⚠️  Please copy .env.example to .env and add your keys", flush=True)

print(f"\n{'='*60}", flush=True)
print("CONFIGURATION CHECK:", flush=True)
print(f"Stripe API key configured: {stripe.api_key is not None}", flush=True)
print(f"Stripe public key configured: {STRIPE_PUBLIC_KEY is not None}", flush=True)
print(f"{'='*60}\n", flush=True)

# Initialize extensions
db.init_app(app)
mail = Mail(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==================== DECORATORS ====================

def seller_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['seller', 'admin']:
            flash('You need seller privileges to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== EMAIL FUNCTIONS ====================

def send_email(to, subject, template):
    """Send email using Flask-Mail"""
    try:
        msg = Message(
            subject=subject,
            recipients=[to],
            html=template
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}", flush=True)
        return False

def send_2fa_code(user, code, purpose="payment"):
    """Send 2FA verification code via email"""
    # FORCE PRINT 2FA CODE FOR DEMO
    print("\n" + "="*70, flush=True)
    print("🔐🔐🔐 TWO-FACTOR AUTHENTICATION CODE 🔐🔐🔐", flush=True)
    print("="*70, flush=True)
    print(f"User: {user.username}", flush=True)
    print(f"Email: {user.email}", flush=True)
    print(f"Purpose: {purpose}", flush=True)
    print("="*70, flush=True)
    print(f"\n    YOUR 2FA CODE: {code}\n", flush=True)
    print("="*70 + "\n", flush=True)
    
    subject = "🔒 SecureBook - Verification Code"
    template = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px; background-color: #f4f4f4;">
        <div style="max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px;">
            <h2 style="color: #667eea;">🔒 SecureBook Security Verification</h2>
            <p>Hello {user.username},</p>
            <p>Your verification code for {purpose} is:</p>
            <div style="background-color: #667eea; color: white; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; border-radius: 5px; margin: 20px 0;">
                {code}
            </div>
            <p style="color: #666;">This code will expire in 10 minutes.</p>
        </div>
    </body>
    </html>
    """
    
    try:
        send_email(user.email, subject, template)
    except:
        pass

def send_order_confirmation(order, user):
    """Send order confirmation email"""
    subject = f"✅ Order Confirmation - {order.order_number}"
    
    items_html = ""
    for item in order.items:
        items_html += f"""
        <tr>
            <td>{item.product.title}</td>
            <td>{item.quantity}</td>
            <td>${item.price_at_purchase:.2f}</td>
            <td>${item.quantity * item.price_at_purchase:.2f}</td>
        </tr>
        """
    
    template = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px; background-color: #f4f4f4;">
        <div style="max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px;">
            <h2 style="color: #28a745;">✅ Order Confirmed!</h2>
            <p>Hello {user.username},</p>
            <p>Thank you for your purchase! Your order has been confirmed.</p>
            
            <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <h3>Order Details</h3>
                <p><strong>Order Number:</strong> {order.order_number}</p>
                <p><strong>Order Date:</strong> {order.created_at.strftime('%Y-%m-%d %H:%M')}</p>
            </div>
            
            <h3>Items Ordered</h3>
            <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                <thead>
                    <tr style="background-color: #667eea; color: white;">
                        <th style="padding: 10px; text-align: left;">Product</th>
                        <th style="padding: 10px; text-align: center;">Qty</th>
                        <th style="padding: 10px; text-align: right;">Price</th>
                        <th style="padding: 10px; text-align: right;">Total</th>
                    </tr>
                </thead>
                <tbody>
                    {items_html}
                </tbody>
                <tfoot>
                    <tr style="background-color: #f8f9fa; font-weight: bold;">
                        <td colspan="3" style="padding: 10px; text-align: right;">Total:</td>
                        <td style="padding: 10px; text-align: right;">${order.total_amount:.2f}</td>
                    </tr>
                </tfoot>
            </table>
            
            <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <h3>Shipping Address</h3>
                <p><strong>{order.shipping_name}</strong></p>
                <p>{order.shipping_address}</p>
                <p>Singapore {order.shipping_postal_code}</p>
                <p>Phone: {order.shipping_phone}</p>
            </div>
            
            <p style="color: #666; margin-top: 30px;">Your order will be processed shortly. You will receive another email when your order ships.</p>
            
            <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
            <p style="font-size: 12px; color: #999;">SecureBook E-Shop - Secure Shopping Platform</p>
        </div>
    </body>
    </html>
    """
    send_email(user.email, subject, template)

# ==================== ROUTES ====================

@app.route('/')
def index():
    products = Product.query.filter_by(is_active=True, pii_scan_status='clean').order_by(Product.created_at.desc()).all()
    
    favorite_ids = []
    if current_user.is_authenticated:
        favorite_ids = [f.product_id for f in Favorite.query.filter_by(user_id=current_user.id).all()]
    
    return render_template('index.html', products=products, favorite_ids=favorite_ids)

@app.route('/test')
def test():
    try:
        user_count = User.query.count()
        product_count = Product.query.count()
        return f"""
        <h1>✅ Flask is working!</h1>
        <ul>
            <li>Database has {user_count} users</li>
            <li>Database has {product_count} products</li>
        </ul>
        <p><a href="/">Go to homepage</a></p>
        """
    except Exception as e:
        return f"<h1>❌ Error</h1><p>{str(e)}</p>"

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            phone = request.form.get('phone', '')
            password = request.form.get('password')
            role = request.form.get('role', 'buyer')
            
            if User.query.filter_by(username=username).first():
                flash('Username already exists', 'danger')
                return redirect(url_for('register'))
            
            if User.query.filter_by(email=email).first():
                flash('Email already exists', 'danger')
                return redirect(url_for('register'))
            
            user = User(username=username, email=email, phone=phone, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            
            AuditLog.log_action(user.id, 'user_registered', f'New {role} registered', request.remote_addr)
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            
            user = User.query.filter_by(username=username).first()
            
            if user and user.check_password(password):
                login_user(user)
                AuditLog.log_action(user.id, 'user_login', 'Successful login', request.remote_addr)
                flash(f'Welcome back, {user.username}!', 'success')
                return redirect(url_for('index'))
            else:
                AuditLog.log_action(None, 'login_failed', f'Failed login attempt for {username}', request.remote_addr, 'warning')
                flash('Invalid username or password', 'danger')
                
        except Exception as e:
            flash(f'Login error: {str(e)}', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    AuditLog.log_action(current_user.id, 'user_logout', 'User logged out', request.remote_addr)
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

# ==================== PRODUCT ROUTES ====================

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    is_favorited = False
    if current_user.is_authenticated:
        is_favorited = Favorite.query.filter_by(user_id=current_user.id, product_id=product_id).first() is not None
    return render_template('product_detail.html', product=product, is_favorited=is_favorited)

@app.route('/seller/dashboard')
@login_required
@seller_required
def seller_dashboard():
    products = Product.query.filter_by(seller_id=current_user.id).all()
    
    total_sales = 0
    total_revenue = 0
    orders = []
    
    for product in products:
        order_items = OrderItem.query.filter_by(product_id=product.id).all()
        for item in order_items:
            if item.order.status == 'paid':
                total_sales += item.quantity
                total_revenue += item.quantity * item.price_at_purchase
                orders.append(item.order)
    
    return render_template('seller_dashboard.html', 
                         products=products,
                         total_sales=total_sales,
                         total_revenue=total_revenue,
                         recent_orders=orders[:10])

@app.route('/seller/product/new', methods=['GET', 'POST'])
@login_required
@seller_required
def create_product():
    if request.method == 'POST':
        try:
            title = request.form.get('title')
            description = request.form.get('description')
            price = float(request.form.get('price'))
            quantity = int(request.form.get('quantity', 1))
            
            combined_text = f"{title} {description}"
            is_clean, violations = Product.detect_pii(combined_text)
            
            if not is_clean:
                violation = PIIViolation(
                    user_id=current_user.id,
                    violation_type=', '.join(violations),
                    detected_content=combined_text[:500],
                    action_taken='blocked'
                )
                db.session.add(violation)
                db.session.commit()
                
                AuditLog.log_action(current_user.id, 'pii_detected', f'PII violations: {violations}', request.remote_addr, 'warning')
                
                flash(f'❌ Product rejected! Personal information detected: {", ".join(violations)}. Please remove sensitive data.', 'danger')
                return redirect(url_for('create_product'))
            
            image_filename = None
            if 'image' in request.files:
                file = request.files['image']
                if file and file.filename:
                    filename = secure_filename(file.filename)
                    import uuid
                    unique_filename = f"{uuid.uuid4()}_{filename}"
                    
                    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                    image_filename = unique_filename
            
            product = Product(
                title=title,
                description=description,
                price=price,
                quantity=quantity,
                image_filename=image_filename,
                seller_id=current_user.id,
                pii_scan_status='clean'
            )
            db.session.add(product)
            db.session.commit()
            
            AuditLog.log_action(current_user.id, 'product_created', f'Product: {title}', request.remote_addr)
            
            flash('✅ Product listed successfully! PII scan passed.', 'success')
            return redirect(url_for('seller_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating product: {str(e)}', 'danger')
    
    return render_template('create_product.html')

# ==================== SHOPPING CART ROUTES ====================

@app.route('/cart')
@login_required
def view_cart():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    total = sum(item.product.price * item.quantity for item in cart_items)
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/cart/add/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    try:
        product = Product.query.get_or_404(product_id)
        quantity = int(request.form.get('quantity', 1))
        
        cart_item = CartItem.query.filter_by(user_id=current_user.id, product_id=product_id).first()
        
        if cart_item:
            cart_item.quantity += quantity
        else:
            cart_item = CartItem(user_id=current_user.id, product_id=product_id, quantity=quantity)
            db.session.add(cart_item)
        
        db.session.commit()
        flash(f'✅ {product.title} added to cart!', 'success')
        
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    
    return redirect(url_for('view_cart'))

@app.route('/cart/update/<int:item_id>', methods=['POST'])
@login_required
def update_cart(item_id):
    try:
        cart_item = CartItem.query.get_or_404(item_id)
        if cart_item.user_id != current_user.id:
            flash('Unauthorized', 'danger')
            return redirect(url_for('view_cart'))
        
        quantity = int(request.form.get('quantity', 1))
        if quantity > 0:
            cart_item.quantity = quantity
            db.session.commit()
        else:
            db.session.delete(cart_item)
            db.session.commit()
        
        flash('Cart updated', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    
    return redirect(url_for('view_cart'))

@app.route('/cart/remove/<int:item_id>')
@login_required
def remove_from_cart(item_id):
    try:
        cart_item = CartItem.query.get_or_404(item_id)
        if cart_item.user_id != current_user.id:
            flash('Unauthorized', 'danger')
            return redirect(url_for('view_cart'))
        
        db.session.delete(cart_item)
        db.session.commit()
        flash('Item removed from cart', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    
    return redirect(url_for('view_cart'))

# ==================== FAVORITES ROUTES ====================

@app.route('/favorites')
@login_required
def view_favorites():
    favorites = Favorite.query.filter_by(user_id=current_user.id).all()
    return render_template('favorites.html', favorites=favorites)

@app.route('/favorite/toggle/<int:product_id>', methods=['POST'])
@login_required
def toggle_favorite(product_id):
    try:
        product = Product.query.get_or_404(product_id)
        favorite = Favorite.query.filter_by(user_id=current_user.id, product_id=product_id).first()
        
        if favorite:
            db.session.delete(favorite)
            db.session.commit()
            return jsonify({'status': 'removed', 'message': 'Removed from favorites'})
        else:
            favorite = Favorite(user_id=current_user.id, product_id=product_id)
            db.session.add(favorite)
            db.session.commit()
            return jsonify({'status': 'added', 'message': 'Added to favorites'})
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

# ==================== CHECKOUT & PAYMENT ROUTES ====================

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    
    if not cart_items:
        flash('Your cart is empty', 'warning')
        return redirect(url_for('view_cart'))
    
    total = sum(item.product.price * item.quantity for item in cart_items)
    
    if request.method == 'POST':
        session['shipping_info'] = {
            'name': request.form.get('shipping_name'),
            'phone': request.form.get('shipping_phone'),
            'address': request.form.get('shipping_address'),
            'postal_code': request.form.get('shipping_postal_code')
        }
        return redirect(url_for('payment'))
    
    return render_template('checkout.html', cart_items=cart_items, total=total)

@app.route('/payment', methods=['GET', 'POST'])
@login_required
def payment():
    if 'shipping_info' not in session:
        flash('Please provide shipping information', 'warning')
        return redirect(url_for('checkout'))
    
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    total = sum(item.product.price * item.quantity for item in cart_items)
    
    return render_template('payment.html', cart_items=cart_items, total=total, stripe_public_key=STRIPE_PUBLIC_KEY)

@app.route('/create-payment-intent', methods=['POST'])
@login_required
def create_payment_intent():
    try:
        print("\n=== PAYMENT INTENT DEBUG ===", flush=True)
        print(f"User: {current_user.username}", flush=True)
        
        cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
        print(f"Cart items: {len(cart_items)}", flush=True)
        
        if not cart_items:
            print("ERROR: Cart is empty", flush=True)
            return jsonify({'error': 'Cart is empty'}), 400
        
        total = sum(item.product.price * item.quantity for item in cart_items)
        print(f"Total: ${total:.2f}", flush=True)
        
        shipping_info = session.get('shipping_info')
        print(f"Shipping info: {shipping_info}", flush=True)
        
        if not shipping_info:
            print("ERROR: No shipping info", flush=True)
            return jsonify({'error': 'Shipping information missing'}), 400
        
        print(f"Stripe API key set: {stripe.api_key is not None}", flush=True)
        print(f"Stripe API key starts with: {stripe.api_key[:20]}...", flush=True)
        
        print("Creating Stripe PaymentIntent...", flush=True)
        
        try:
            intent = stripe.PaymentIntent.create(
                amount=int(total * 100),
                currency='sgd',
                payment_method_types=['card'],
            )
            print(f"PaymentIntent created successfully: {intent.id}", flush=True)
            
        except stripe.error.StripeError as stripe_err:
            print(f"Stripe API Error: {str(stripe_err)}", flush=True)
            return jsonify({'error': f'Stripe error: {str(stripe_err)}'}), 400
        
        order = Order(
            order_number=Order.generate_order_number(),
            buyer_id=current_user.id,
            stripe_payment_intent_id=intent.id,
            total_amount=total,
            shipping_name=shipping_info.get('name'),
            shipping_phone=shipping_info.get('phone'),
            shipping_address=shipping_info.get('address'),
            shipping_postal_code=shipping_info.get('postal_code'),
            status='pending'
        )
        db.session.add(order)
        db.session.flush()
        
        print(f"Order created: {order.order_number}", flush=True)
        
        for cart_item in cart_items:
            order_item = OrderItem(
                order_id=order.id,
                product_id=cart_item.product_id,
                quantity=cart_item.quantity,
                price_at_purchase=cart_item.product.price
            )
            db.session.add(order_item)
        
        db.session.commit()
        print("Order items saved", flush=True)
        
        # Generate 2FA code
        code = current_user.generate_2fa_code()

        # FORCE PRINT 2FA CODE FOR DEMO
        print("\n" + "="*70, flush=True)
        print("🔐🔐🔐 TWO-FACTOR AUTHENTICATION CODE 🔐🔐🔐", flush=True)
        print("="*70, flush=True)
        print(f"USER: {current_user.username}", flush=True)
        print(f"EMAIL: {current_user.email}", flush=True)
        print("="*70, flush=True)
        print(f"\n>>> ENTER THIS CODE: {code} <<<\n", flush=True)
        print("="*70 + "\n", flush=True)

        try:
            send_2fa_code(current_user, code, "payment verification")
        except Exception as e:
            print(f"Email sending failed (expected): {e}", flush=True)

        AuditLog.log_action(
            current_user.id,
            'payment_initiated',
            f'Order: {order.order_number}',
            request.remote_addr
        )
        
        response_data = {
            'clientSecret': intent.client_secret,
            'order_id': order.id
        }
        
        print(f"Returning client_secret: {intent.client_secret[:20]}...", flush=True)
        print("=== END DEBUG ===\n", flush=True)
        
        return jsonify(response_data)
        
    except Exception as e:
        print(f"\n!!! EXCEPTION !!!", flush=True)
        print(f"Error type: {type(e).__name__}", flush=True)
        print(f"Error message: {str(e)}", flush=True)
        import traceback
        traceback.print_exc()
        print("!!! END EXCEPTION !!!\n", flush=True)
        
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/verify-payment-2fa/<int:order_id>', methods=['GET', 'POST'])
@login_required
def verify_payment_2fa(order_id):
    order = Order.query.get_or_404(order_id)
    
    if order.buyer_id != current_user.id:
        flash('Unauthorized', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        code = request.form.get('code')
        
        if current_user.verify_2fa_code(code):
            order.payment_2fa_verified = True
            order.status = 'verified_2fa'
            db.session.commit()
            
            AuditLog.log_action(current_user.id, '2fa_verified', f'Payment 2FA passed for order {order.order_number}', request.remote_addr)
            
            return redirect(url_for('confirm_payment', order_id=order.id))
        else:
            order.payment_2fa_attempts += 1
            db.session.commit()
            
            AuditLog.log_action(current_user.id, '2fa_failed', f'Failed 2FA attempt for order {order.order_number}', request.remote_addr, 'warning')
            
            flash('Invalid verification code. Please try again.', 'danger')
    
    return render_template('verify_2fa.html', order=order)

@app.route('/confirm-payment/<int:order_id>')
@login_required
def confirm_payment(order_id):
    order = Order.query.get_or_404(order_id)
    
    if not order.payment_2fa_verified:
        flash('Please verify 2FA first', 'warning')
        return redirect(url_for('verify_payment_2fa', order_id=order_id))
    
    order.status = 'paid'
    db.session.commit()
    
    CartItem.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    
    send_order_confirmation(order, current_user)
    order.confirmation_sent = True
    db.session.commit()
    
    session.pop('shipping_info', None)
    
    AuditLog.log_action(current_user.id, 'payment_completed', f'Order {order.order_number} completed', request.remote_addr)
    
    flash('✅ Payment successful! Confirmation email sent.', 'success')
    return render_template('payment_success.html', order=order)

@app.route('/my-orders')
@login_required
def my_orders():
    orders = Order.query.filter_by(buyer_id=current_user.id).order_by(Order.created_at.desc()).all()
    return render_template('my_orders.html', orders=orders)

# ==================== ADMIN ROUTES ====================

@app.route('/admin/audit-logs')
@login_required
def audit_logs():
    if current_user.role != 'admin':
        flash('Admin access required', 'danger')
        return redirect(url_for('index'))
    
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    pii_violations = PIIViolation.query.order_by(PIIViolation.timestamp.desc()).limit(50).all()
    
    return render_template('audit_logs.html', logs=logs, pii_violations=pii_violations)

# ==================== DATABASE INITIALIZATION ====================

def init_database():
    with app.app_context():
        print("🔄 Initializing database...", flush=True)
        db.drop_all()
        db.create_all()
        print("✅ Database tables created!", flush=True)
        
        try:
            admin = User(username='admin', email='admin@securebook.com', phone='+6512345678', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            
            seller = User(username='seller1', email='seller@securebook.com', phone='+6587654321', role='seller')
            seller.set_password('seller123')
            db.session.add(seller)
            
            buyer = User(username='buyer1', email='buyer@securebook.com', phone='+6598765432', role='buyer')
            buyer.set_password('buyer123')
            db.session.add(buyer)
            
            db.session.commit()
            print("✅ Test users created!", flush=True)
            print("\n" + "="*60, flush=True)
            print("📋 LOGIN CREDENTIALS:", flush=True)
            print("="*60, flush=True)
            print("   👤 Admin:  admin / admin123", flush=True)
            print("   🛒 Seller: seller1 / seller123", flush=True)
            print("   💰 Buyer:  buyer1 / buyer123", flush=True)
            print("="*60, flush=True)
            print("\n🎯 START WITH 0 PRODUCTS - Login as seller to create your first product!", flush=True)
            print("🔒 PII DETECTION ACTIVE - Try adding NRIC/phone/address to test!", flush=True)
            print("\n", flush=True)
            
        except Exception as e:
            print(f"❌ Error creating test data: {e}", flush=True)
            db.session.rollback()

if __name__ == '__main__':
    init_database()
    print("🚀 Starting SecureBook E-Shop...", flush=True)
    print("🌐 Access at: http://localhost:5000\n", flush=True)
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)