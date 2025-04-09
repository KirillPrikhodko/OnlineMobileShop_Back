import os
import psycopg2
import bcrypt
import jwt
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}


# Database connection
def get_db_connection():
    conn = psycopg2.connect(
        host="localhost",
        database="mobile_shop",
        user="postgres",
        password="123",
        port="5432"
    )
    return conn


# Helper functions
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def generate_token(user_id):
    payload = {
        'exp': datetime.utcnow() + timedelta(days=1),
        'iat': datetime.utcnow(),
        'sub': user_id
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')


# Auth middleware
def token_required(f):
    def decorator(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['sub']
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorator


# API Endpoints
@app.route('/')
def index():
    return jsonify({
        'message': 'Mobile Shop API',
        'endpoints': [
            '/products',
            '/categories',
            '/register',
            '/login',
            '/orders'
        ]
    })


@app.route('/products', methods=['GET'])
def get_products():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Filter parameters
        category = request.args.get('category')
        search = request.args.get('search')
        min_price = request.args.get('min_price')
        max_price = request.args.get('max_price')

        base_query = "SELECT * FROM Products WHERE 1=1"
        params = []

        if category:
            base_query += " AND CategoryID = %s"
            params.append(category)
        if search:
            base_query += " AND LOWER(ProductName) LIKE %s"
            params.append(f"%{search.lower()}%")
        if min_price:
            base_query += " AND Price >= %s"
            params.append(min_price)
        if max_price:
            base_query += " AND Price <= %s"
            params.append(max_price)

        cursor.execute(base_query, params)
        products = cursor.fetchall()

        product_list = []
        for product in products:
            product_list.append({
                'id': product[0],
                'name': product[1],
                'brand': product[2],
                'model': product[3],
                'category_id': product[4],
                'price': float(product[5]),
                'description': product[6],
                'image': product[7],
                'stock': product[8],
                'date_added': product[9].isoformat()
            })

        return jsonify(product_list)

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/products/<int:product_id>/reviews', methods=['GET'])
def get_product_reviews(product_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT r.ReviewID, u.FullName, r.Rating, r.Comment, r.ReviewDate 
            FROM Reviews r
            JOIN Users u ON r.UserID = u.UserID
            WHERE r.ProductID = %s
        """, (product_id,))

        reviews = cursor.fetchall()
        review_list = []

        for review in reviews:
            review_list.append({
                'id': review[0],
                'author': review[1],
                'rating': review[2],
                'comment': review[3],
                'date': review[4].isoformat()
            })

        return jsonify(review_list)

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/orders', methods=['POST'])
@token_required
def create_order(current_user):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        data = request.get_json()

        # Validate input
        if not all(key in data for key in ['items', 'shipping_address', 'payment_method']):
            return jsonify({'error': 'Missing required fields'}), 400

        # Calculate total amount
        total = 0.0
        order_items = []

        for item in data['items']:
            cursor.execute("SELECT Price FROM Products WHERE ProductID = %s", (item['product_id'],))
            product = cursor.fetchone()

            if not product:
                return jsonify({'error': f"Product {item['product_id']} not found"}), 404

            price = float(product[0])
            total += price * item['quantity']
            order_items.append((item['product_id'], item['quantity'], price))

        # Create order
        cursor.execute("""
            INSERT INTO Orders (UserID, TotalAmount, ShippingAddress, PaymentMethod)
            VALUES (%s, %s, %s, %s)
            RETURNING OrderID
        """, (current_user, total, data['shipping_address'], data['payment_method']))

        order_id = cursor.fetchone()[0]

        # Add order items
        for item in order_items:
            cursor.execute("""
                INSERT INTO OrderItems (OrderID, ProductID, Quantity, UnitPrice)
                VALUES (%s, %s, %s, %s)
            """, (order_id, item[0], item[1], item[2]))

        conn.commit()

        return jsonify({
            'message': 'Order created successfully',
            'order_id': order_id
        }), 201

    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/register', methods=['POST'])
def register():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        data = request.get_json()

        if not all(key in data for key in ['full_name', 'email', 'password']):
            return jsonify({'error': 'Missing required fields'}), 400

        # Check if user exists
        cursor.execute("SELECT UserID FROM Users WHERE Email = %s", (data['email'],))
        if cursor.fetchone():
            return jsonify({'error': 'User already exists'}), 409

        # Hash password
        hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())

        # Create user
        cursor.execute("""
            INSERT INTO Users (FullName, Email, PasswordHash, Phone)
            VALUES (%s, %s, %s, %s)
            RETURNING UserID
        """, (
            data['full_name'],
            data['email'],
            hashed_password.decode('utf-8'),
            data.get('phone', '')
        ))

        user_id = cursor.fetchone()[0]
        conn.commit()

        return jsonify({
            'message': 'User registered successfully',
            'user_id': user_id,
            'token': generate_token(user_id)
        }), 201

    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/login', methods=['POST'])
def login():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        data = request.get_json()

        if not all(key in data for key in ['email', 'password']):
            return jsonify({'error': 'Missing email or password'}), 400

        cursor.execute("SELECT UserID, PasswordHash FROM Users WHERE Email = %s", (data['email'],))
        user = cursor.fetchone()

        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401

        user_id, hashed_password = user

        if bcrypt.checkpw(data['password'].encode('utf-8'), hashed_password.encode('utf-8')):
            return jsonify({
                'message': 'Login successful',
                'user_id': user_id,
                'token': generate_token(user_id)
            })
        else:
            return jsonify({'error': 'Invalid credentials'}), 401

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(host='0.0.0.0',debug=True)