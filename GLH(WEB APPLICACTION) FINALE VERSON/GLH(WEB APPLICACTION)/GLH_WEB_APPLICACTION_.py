
import sqlite3
import os  # Standard library, no install needed
from flask import Flask, render_template, url_for, redirect, g, session, jsonify, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename # This helps save files safely
from functools import wraps
import http.client
import requests
from collections import Counter

app = Flask(__name__)
app.secret_key = 'some_random_secret_string'
app.config["SECRET_KEY"] = "supersecretkey" # This encrypts your session cookie
DATABASE = "db.sqlite"
UPLOAD_FOLDER = 'static/uploads/certs' # this is for the certicates to be uploaded 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)# creates a folder if its not already there

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'} #these are the type of files  allowed 
# --- DATABASE SETUP ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row#this allows accessing colums by name 
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()




with app.app_context():
    db = get_db()
    
    #  Update existing tables if needed
    try:
        db.execute('ALTER TABLE foods ADD COLUMN farm_name TEXT')
        db.commit()
    except:
        pass

    # Users Table
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            firstname TEXT,
            secondname TEXT,
            farm_name TEXT,
            phone TEXT,
            email TEXT UNIQUE,
            dob TEXT,
            password TEXT,
            city TEXT,
            county TEXT,
            postcode TEXT,
            crn TEXT UNIQUE,
            businesstype TEXT,
            tax TEXT,
            acc_name TEXT,
            sort TEXT,
            acc_number TEXT UNIQUE
        )
    ''')

    #  Foods Table 
    db.execute('''
        CREATE TABLE IF NOT EXISTS foods (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            farmer_id INTEGER,
            farm_name TEXT NOT NULL,          
            food_name TEXT NOT NULL,
            description TEXT NOT NULL,
            image_filename TEXT,
            quantity INTEGER,
            price REAL,
            FOREIGN KEY (farmer_id) REFERENCES users (id)
        )
    ''')

    #  Admins Table
    db.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            Admin_username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            access_level TEXT DEFAULT 'full'
        )
    ''')

    # . Product Movements Table (Fixed the missing db.execute)
    db.execute('''
        CREATE TABLE IF NOT EXISTS product_movements (
            movement_id INTEGER PRIMARY KEY AUTOINCREMENT,
            farmer_id INTEGER NOT NULL,
            product_name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending',
            FOREIGN KEY (farmer_id) REFERENCES users(id)
        )
    ''')
     # Orders Table (The "Header" of the receipt)
    db.execute('''
         CREATE TABLE IF NOT EXISTS orders (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             user_id INTEGER NOT NULL,
             order_date DATETIME DEFAULT CURRENT_TIMESTAMP,
             total_price REAL NOT NULL,
             FOREIGN KEY (user_id) REFERENCES users (id)
         )
     ''')

     # Order Items Table (The specific list of products in that order)
    db.execute('''
         CREATE TABLE IF NOT EXISTS order_items (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             order_id INTEGER NOT NULL,
             food_name TEXT NOT NULL,
             price REAL NOT NULL,
             quantity INTEGER NOT NULL,
             FOREIGN KEY (order_id) REFERENCES orders (id)
         )
     ''')

    db.commit()






# --- LOGIN LOGIC ---

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        db = get_db()

        # 1. Check if name is taken by an ADMIN first (Safety Check)
        existing_admin = db.execute("SELECT 1 FROM admins WHERE Admin_username = ?", (username,)).fetchone()
        if existing_admin:
            return render_template("register.html", error="This username is reserved for staff.")

        try:
            # 2. Hash the password and save the new customer
            hashed_pw = generate_password_hash(password, method="pbkdf2:sha256")
            db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
            db.commit()

            # 3. Clear any old session and set as 'customer'
            session.clear()
            session['username'] = username
            session['is_farmer'] = False  # They are a customer, not a farmer
            session['role'] = 'customer'
            
            flash("Account created! Welcome to the shop.")
            print('you are in ')
            return redirect(url_for("home")) # Send customers to the shop home page
            
        except sqlite3.IntegrityError:
            return render_template("register.html", error="Username already taken!")
    
    return render_template("register.html")


def login_required_farmers(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If there is no user_id in the session, kick them out
        if 'user_id' not in session:
            flash("Please log in to access this page.")
            return redirect(url_for('FarmersOnBoarding')) 
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If there is no user_id in the session, kick them out
        if 'user_id' not in session:
            flash("Please log in to access this page.")
            return redirect(url_for('login')) #this is for the users
        return f(*args, **kwargs)
    return decorated_function


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        db = get_db()

        #  Check if they are a regular user/farmer
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = 'user' # Helpful to track role
            
            if user['farm_name']:
                session['is_farmer'] = True
                return redirect(url_for('Dashboard'))
            else:
                session['user_onboarding'] = username
                session['is_farmer'] = False
                return redirect(url_for('Dashboard')) # 

        #  If not found, check if they are an ADMIN
        admin = db.execute("SELECT * FROM admins WHERE Admin_username = ?", (username,)).fetchone()

        if admin and check_password_hash(admin['password'], password):
            session['user_id'] = admin['id']
            session['username'] = admin['Admin_username'] 
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))

        flash("Invalid username or password")
    return render_template("login.html")



from werkzeug.security import generate_password_hash

@app.route('/GLHAdminregister', methods=['GET', 'POST'])
def GLHAdminregister():
    if request.method == "POST":
        db = get_db() #
        username = request.form.get("username")
        password = request.form.get("password")
        security_code = request.form.get("security_code", "").strip() 
        
        #  Check users table for duplicates
        existing_user = db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if existing_user:
            flash("This username is already taken by a farmer.")
            return render_template("GLHAdminregister.html")

        # Check security code
        if security_code != "YOUR_MASTER_CODE_123":
            flash("Invalid Security Code.")
            return render_template("GLHAdminregister.html")

        try:
            hashed_pw = generate_password_hash(password)
            
            #  Insert into admins table (using correct column name Admin_username)
            db.execute(
                "INSERT INTO admins (Admin_username, password, access_level) VALUES (?, ?, ?)", 
                (username, hashed_pw, 'full')
            )
            db.commit()

            flash("Admin account created! Please log in.")
            return redirect(url_for('login'))
            
        except Exception as e:
            print(f"Database Error: {e}")
            flash("Username already exists in admins or a database error occurred.")
            return render_template("GLHAdminregister.html")

    return render_template("GLHAdminregister.html")

@app.route("/admin_dashboard")
def admin_dashboard():
    if not session.get('is_admin'):
        flash("Admins only!")
        return redirect(url_for("login"))
    return render_template("admin_dashboard.html") 




@app.route('/managefarmer')
def managefarmer():
    if not session.get('is_admin'):
        flash("Unauthorized access!")
        return redirect(url_for('login'))

    path = "./"  # The directory where your folders are located
    folders_data = []

    # Loop through items in your directory
    for item in os.listdir(path):
        item_path = os.path.join(path, item)
        
        # Check if the item is a folder
        if os.path.isdir(item_path):
            file_path = os.path.join(item_path, 'farmer_details.txt')
            
            # Read the file if it exists
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    farmer_names = f.read().strip()
                
                folders_data.append({
                    'display_name': item.replace('_', ' ').title(),
                    'names': farmer_names
                })
    
    return render_template('managefarmer.html', folders=folders_data, is_admin=True)

@app.route('/Moved_products')
def Moved_products():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
        
    db = get_db()
    # Join with users to see which farmer sent the goods
    movements = db.execute('''
        SELECT m.*, u.farm_name 
        FROM product_movements m
        JOIN users u ON m.farmer_id = u.id
        ORDER BY m.timestamp DESC
    ''').fetchall()
    return render_template('moved_products.html', movements=movements)



@app.route('/receive_goods/<int:movement_id>', methods=['POST'])
def receive_goods(movement_id):
    db = get_db()
    # Update status to 'received'
    db.execute('UPDATE product_movements SET status = "received" WHERE movement_id = ?', (movement_id,))
    db.commit()
    flash("Inventory updated: Goods received in warehouse.")
    return redirect(url_for('Moved_products'))
    
    return render_template('receive_good.html', movements=movements)

@app.route('/send_to_warehouse', methods=['GET', 'POST'])
def send_to_warehouse():
    # Security: Ensure only logged-in farmers can access
    if not session.get('is_farmer'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        product = request.form.get('product_name')
        qty = request.form.get('quantity')
        farmer_id = session.get('user_id')

        db = get_db()
        db.execute('''
            INSERT INTO product_movements (farmer_id, product_name, quantity, status) 
            VALUES (?, ?, ?, 'Pending')
        ''', (farmer_id, product, qty))
        db.commit()
        
        flash(f"Success! {qty} of {product} is now marked as 'In Transit'.")
        return redirect(url_for('Dashboard'))

    return render_template('send_to_warehouse.html')

@app.route("/logout")
def logout():
    session.clear() # Clears the login cookie
    return redirect(url_for("home"))


@app.route('/Dashboard')
@login_required_farmers
def Dashboard():
    user_id = session.get('user_id')
    db = get_db()

    #  Double-check the database for this specific user's farm_name
    user = db.execute('SELECT farm_name FROM users WHERE id = ?', (user_id,)).fetchone()

    # If the user doesn't have a farm_name in the DB, they shouldn't be here
    if not user or not user['farm_name']:
        flash("You need to register a farm name before accessing the dashboard.")
        # Send them back to onboarding or a profile  page
        return redirect(url_for('FarmersOnBoarding'))

    # If they passed the check, get their foods
    farm_name = user['farm_name']
    cur = db.execute('SELECT * FROM foods WHERE farm_name = ?', (farm_name,))
    my_foods = cur.fetchall()

    return render_template('Dashboard.html', farm_name=farm_name, foods=my_foods)

@app.route("/delete/<int:item_id>", methods=["GET", "POST"])
def delete_item(item_id):
    db = get_db()
    db.execute("DELETE FROM foods WHERE id = ?", (item_id,))
    db.commit()
    
    # 5. Redirect back to the Dashboard to see the updated list
    return redirect(url_for('StockManagement'))






@app.route('/')
def links():
   return render_template('links.html')#i use this page to help me navigate through the site a bit easier 

@app.route('/home')
def home():
    # 1. Check if they are logged in as an Admin
    if session.get('is_admin'):
        # Send them straight to the admin response page
        return redirect(url_for('admin_dashboard'))

    # 2. Check if they are logged in as a Farmer
    if session.get('is_farmer'):
        # Send them straight to their dashboard
        return redirect(url_for('Dashboard')) 
    
    # 3. Otherwise, treat them as a normal user/guest
    username = session.get('username') 
    return render_template('home.html', username=username)




@app.route('/supportcontact')
def supportcontact():
    username = session.get('username') 
    return render_template('supportcontact.html' , username=username)

@app.route('/submit-support', methods=['POST'])
def submit_support():
    user_name = request.form.get('name')
    user_email = request.form.get('email')
    user_type = request.form.get('user-type')
    user_message = request.form.get('message')

    #  Define the folder name
    folder_name = "needed_support"
    
    #  Create the folder if it doesn't exist yet
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)

    #  Create the filename and full path
    file_name = f"{user_name.replace(' ', '_')}.txt"
    file_path = os.path.join(folder_name, file_name)

    #  Save the file into that specific folder
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(f"Name: {user_name}\nEmail: {user_email}\nType: {user_type}\nMessage: {user_message}")

    return render_template('supportcontact.html', success_message="Message saved!")

@app.route('/MeetTheMaker')
def MeetTheMaker():
    return render_template('MeetTheMaker.html')#this will take you the the meet the maker page 




@app.route('/about')
def about():
    username = session.get('username') 
    return render_template('about.html ', username=username)#this will take you to the about page

@app.route('/ProductCatalog')
def ProductCatalog():
    db = get_db()
    # Fetch all products that have stock
    products = db.execute('SELECT * FROM foods WHERE quantity > 0').fetchall()

  
    html = """
  <!DOCTYPE html>
<html>
<head>
    <title>Product Catalogue</title>
    <link rel="stylesheet" href="/static/part1.css">
    <style>
        .cart-nav { text-align: right; padding: 20px; }
        .view-cart-btn { background-color: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="cart-nav">
        <a href="/cart" class="view-cart-btn"> View Cart</a>
    </div>
    <h1 style="text-align:center;">Fresh From The Farms Of GLH</h1>
    <div class="catalogue-container">
    """

    #  THE LOOP Building a card for every product)
    for p in products:
        img_name = p['image_filename'] if p['image_filename'] else 'default.jpg'
        html += f"""
        <div class="product-card">
    <img src="/static/uploads/{p['image_filename'] or 'default.jpg'}" alt="{p['food_name']}">
    <h3>{p['food_name']}</h3>
    <p class="description">{p['description']}</p>
    <p class="price">&pound;{p['price']}</p>
    
    <!-- Link the button to the 'add_to_cart' route with the product ID -->
    <a href="/add_to_cart/{p['id']}" style="text-decoration: none;">
        <button class="buy-btn" style="width: 100%;">Add to Cart</button>
    </a>
</div>
"""

    #  THE FOOTER (Closing the container and body)
    html += """
        </div>
    </body>
    </html>
    """

    return html
@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    db = get_db()
    
    # Check current database stock
    product = db.execute('SELECT quantity, food_name FROM foods WHERE id = ?', (product_id,)).fetchone()
    if not product:
        return "Product not found", 404
        
    db_stock = product['quantity']
    
    #  Only add if there is at least 1 left in the DB
    if db_stock > 0:
        #  SUBTRACT FROM DATABASE IMMEDIATELY 
        db.execute('UPDATE foods SET quantity = quantity - 1 WHERE id = ?', (product_id,))
        db.commit()

        # Add to session cart
        cart = session.get('cart', [])
        cart.append(product_id)
        session['cart'] = cart
    else:
        return f"<h1>Sorry!</h1><p>{product['food_name']} is currently out of stock.</p><a href='/ProductCatalog'>Go Back</a>"
    
    return redirect(request.referrer or url_for('ProductCatalog'))



from collections import Counter

@app.route('/cart')
def view_cart():
    cart_ids = session.get('cart', [])
    if not cart_ids:
        return "<h1>Your cart is empty!</h1><a href='/ProductCatalog'>Go back</a>"

    counts = Counter(cart_ids)
    db = get_db()
    
    # Get the product details
    placeholders = ', '.join(['?'] * len(counts))
    products = db.execute(f"SELECT * FROM foods WHERE id IN ({placeholders})", list(counts.keys())).fetchall()

    # Calculate total price here to pass it to the template
    total_price = sum(p['price'] * counts[p['id']] for p in products)

    return render_template('cart.html', products=products, counts=counts, total_price=total_price)

@app.route('/remove_from_cart/<int:product_id>')
def remove_from_cart(product_id):
    cart = session.get('cart', [])
    # This keeps everything EXCEPT the ID you want to remove
    session['cart'] = [item for item in cart if item != product_id]
    return redirect(url_for('view_cart'))

@app.route('/remove_one/<int:product_id>')
def remove_one(product_id):
    cart = session.get('cart', [])
    if product_id in cart:
        cart.remove(product_id)  # This only removes ONE instance of the ID
        session['cart'] = cart
    db = get_db()
    db.execute('UPDATE foods SET quantity = quantity + 1 WHERE id = ?', (product_id,))
    db.commit()
    return redirect(url_for('view_cart'))


@app.route('/checkout', methods=['GET', 'POST'])
def process_checkout():
    # If they are just LOOKING at the page
    if request.method == 'GET':
        return render_template('checkout.html')

    #  If they clicked "PLACE ORDER" (The POST request)
    cart_ids = session.get('cart', [])
    user_id = session.get('user_id')
    
    if not cart_ids:
        return redirect(url_for('ProductCatalog'))

    counts = Counter(cart_ids)
    db = get_db()
    
    # Get product details to calculate total
    placeholders = ', '.join(['?'] * len(counts))
    products = db.execute(f"SELECT * FROM foods WHERE id IN ({placeholders})", list(counts.keys())).fetchall()
    total_price = sum(p['price'] * counts[p['id']] for p in products)

    # Save the main order
    cursor = db.execute(
        'INSERT INTO orders (user_id, total_price) VALUES (?, ?)',
        (user_id, total_price)
    )
    order_id = cursor.lastrowid 

    # Save every item specifically to history
    for p in products:
        db.execute(
            'INSERT INTO order_items (order_id, food_name, price, quantity) VALUES (?, ?, ?, ?)',
            (order_id, p['food_name'], p['price'], counts[p['id']])
        )
    
    db.commit()
    session['cart'] = [] # Successfully clear the cart
    
    # Redirect them to their history to see the new order
    return redirect(url_for('PurchaseHistory'))


@app.route('/QrScanAndGo')
@login_required
def QrScanAndGo():
    return render_template('QrScanAndGo.html') #this is for the pick up for  when the customer wants to pick something up form 

@app.route('/PurchaseHistory')
@login_required
def PurchaseHistory():
    user_id = session.get('user_id')
    db = get_db()
    
    # Get all orders for this user
    orders = db.execute('SELECT * FROM orders WHERE user_id = ? ORDER BY order_date DESC', (user_id,)).fetchall()
    
    history_data = []
    for order in orders:
        # For each order, get the items bought
        items = db.execute('SELECT * FROM order_items WHERE order_id = ?', (order['id'],)).fetchall()
        history_data.append({'order': order, 'items': items})
    return render_template('PurchaseHistory.html',PurchaseHistory = history_data )#this is where customers see their previouse sales if any at all 


@app.route('/StockManagement')
@login_required_farmers
def StockManagement():
        user_id = session.get('user_id')
        db = get_db()

        #  Double-check the database for this specific user's farm_name
        user = db.execute('SELECT farm_name FROM users WHERE id = ?', (user_id,)).fetchone()

        # If the user doesn't have a farm_name in the DB, they shouldn't be here
        if not user or not user['farm_name']:
            flash("You need to register a farm name before accessing the dashboard.")
            # Send them back to onboarding or a profile  page
            return redirect(url_for('FarmersOnBoarding'))

        # If they passed the check, get their foods
        farm_name = user['farm_name']
        cur = db.execute('SELECT * FROM foods WHERE farm_name = ?', (farm_name,))
        my_foods = cur.fetchall()
        return render_template('StockManagement.html', foods=my_foods, farm_name=farm_name)#this is a page whenre ther famers can add or remove things form the online shop 

@app.route('/MoveProduct')
@login_required_farmers
def MoveProduct():
    return render_template('MoveProduct.html') # this is the page where the farmers move products form their farms to their storage and form the the glh facility for deliveries 


@app.route('/OrdersFullfillments')
@login_required_farmers
def OrdersFullfillments():
    return render_template('OrdersFullfillments.html')#this is for the farmes if they receive any order that this will show them what they need to place in their pickup bags


@app.route('/delivery')
@login_required_farmers
def delivery():
    return render_template('delivery.html')


@app.route('/ContactGlhFarmers', methods=['GET', 'POST']) # Added GET and POST
@login_required_farmers
def ContactGlhFarmers():
    username = session.get('username') 
    if request.method == 'POST':
        # 1. Grab data from the form
        user_name = request.form.get('name')
        user_email = request.form.get('email')
        user_type = request.form.get('user-type')
        user_message = request.form.get('message')

        # 2. Folder logic
        folder_name = "farmers_need_support"
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)

        # 3. Save the file
        # Use a fallback if user_name is somehow missing to avoid errors
        safe_name = user_name.replace(' ', '_') if user_name else "anonymous"
        file_path = os.path.join(folder_name, f"{safe_name}.txt")

        with open(file_path, "w", encoding="utf-8") as file:
            file.write(f"Name: {user_name}\nEmail: {user_email}\nType: {user_type}\nMessage: {user_message}")

     

    # If it's a GET request (just visiting the page), just show the form
    return render_template('ContactGlhFarmers.html', success="Message saved!" , username= username)

@app.route('/Responsepage')
def Responsepage():
    # Check if the user is an admin (based on your login logic)
    is_admin = session.get('is_admin', False) 
    
    folder_list = []
    if is_admin:
        base_path = os.path.dirname(os.path.abspath(__file__)) 
        
        all_items = os.listdir(base_path)
        folder_list = [f for f in all_items if f in ['farmers_need_support', 'needed_support']]

    return render_template('Responsepage.html', is_admin=is_admin, folders=folder_list)#this is the glh resposnse page to all the sign up request and all the new users log in 

@app.route('/Logistics')
def Logistics():
    return render_template('Logistics.html')#this is for the glh staff that have to deal with their customers information and the farmers as well

@app.route('/farmersReviews')
@login_required_farmers
def farmersReviews():
    return render_template('farmersReviews.html') #this is for the glh stuff who reed the farmers reviews

@app.route('/inventory')
@login_required_farmers
def inventory():

    db = get_db()
    cursor = db.execute('SELECT * FROM foods WHERE farmer_id = ?', (session.get('user_id'),))
    rows = cursor.fetchall()

    html = "<h1>My Stock Management</h1>"
    html += "<table border='1'><tr><th>Image</th><th>Product</th><th>Stock</th><th>Price</th></tr>"

    for row in rows:
        # Use a fallback if filename is missing
        img_name = row['image_filename'] if row['image_filename'] else 'default.jpg'
        
        # Color coding for low stock
        stock_color = "red" if row['quantity'] < 5 else "black"

        html += f"""
        <tr>
            <td><img src='/static/uploads/{img_name}' width='50'></td>
            <td>{row['food_name']}</td>
            <td style='color: {stock_color}'>{row['quantity']}</td>
            <td>${row['price']}</td>
        </tr>
        """
    html += "</table>"
    html += "<br><a href='/famerAddProduct'>+ Add New Product</a>"
    return html

    return render_template('inventory.html')

@app.route('/DataRequirementsGuide')
def DataRequirementsGuide():
    return render_template('DataRequirementsGuide.html')

@app.route('/FarmersOnBoarding', methods=['GET', 'POST'])
def FarmersOnBoarding():
    if request.method == 'POST':
        #  DEFINE DB FIRST
        db = get_db()
        
        username = request.form.get('username')
        password = request.form.get('password')
        fname = request.form.get('firstname')
        sname = request.form.get('secondname')
        farm = request.form.get('farm_name')  
        phone = request.form.get('phone_number') 
        email = request.form.get('email')
        dob = request.form.get('dob')

        #  CHECK THE ADMIN TABLE
        # Use Admin_username to match your admins table schema
        existing_admin = db.execute("SELECT 1 FROM admins WHERE Admin_username = ?", (username,)).fetchone()
        if existing_admin:
            flash("This username is reserved for administrative use.")
            return render_template("FarmersOnBoarding.html") # Stay on the same page

        try:
            hashed_pw = generate_password_hash(password)
            
            #  INSERT THE USER
            cursor = db.execute('''
                INSERT INTO users (username, password, firstname, secondname, farm_name, phone, email, dob) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (username, hashed_pw, fname, sname, farm, phone, email, dob))
            db.commit()

            #  SET SESSION
            session['user_id'] = cursor.lastrowid 
            session['username'] = username
            session['farm_name'] = farm
            session['is_farmer'] = True 
        

            return redirect(url_for('legalusersvarification'))
        except sqlite3.IntegrityError:
            flash("Error: That username or email is already taken.")
            return render_template("FarmersOnBoarding.html")
        except Exception as e:
            print(f"Error: {e}")
            return f"An unexpected error occurred: {e}"

    return render_template('FarmersOnBoarding.html')


import requests
from flask import render_template, request, session, jsonify

@app.route('/physical-address', methods=['GET', 'POST'])
@login_required_farmers
def physical_address():
    if request.method == 'POST':
        postcode = request.form.get('postcode')
        city = request.form.get('city')
        county = request.form.get('county')
        username = session.get('user_onboarding')

        if username:
            db = get_db()
            db.execute('''
                UPDATE users 
                SET postcode = ?, city = ?, county = ? 
                WHERE username = ?
            ''', (postcode, city, county, username))
            db.commit()
            
            return render_template('legalusersvarification.html')
        else:
            # You should replace this with a proper flash message or error redirect
            return "Session expired. Please start again.", 401

    return render_template('phyicaladress.html')

@app.route('/api/lookup/<postcode>')
def lookup_postcode(postcode):
    # Clean spaces from postcode
    clean_pc = postcode.replace(" ", "")
    
    url = f"https://postcodes.io{clean_pc}"
    
    try:
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            data = response.json().get('result', {})
            return jsonify({
                "status": "success",
                "city": data.get("admin_district"),
                "county": data.get("admin_county") or data.get("region")
            })
    except Exception as e:
        print(f"Connection Error: {e}")

    return jsonify({"status": "error", "message": "Postcode not found"}), 404


@app.route('/legalusersvarification', methods=['GET', 'POST'])
def legalusersvarification():
    if request.method == 'POST':
       
        crn = request.form.get('customer_reference_number') 
        businesstype = request.form.get('business_type')
        username = session.get('user_onboarding')

        if username:
            db = get_db()
            db.execute('''
                UPDATE users 
                SET crn = ?, Businesstype = ? 
                WHERE username = ?
            ''', (crn, businesstype, username))
            db.commit()
            
            # Use redirect after a POST to prevent double-submissions
            return redirect(url_for('/payfarmers')) 
        else:
            # flash() is a great way to show errors on the login/start page
            flash("Session expired. Please start again.")
            

    return render_template('legalusersvarification.html')

@app.route('/payfarmers', methods=['GET', 'POST'])
def payfarmers():
   if request.method == 'POST':
        # Get data from the form
        acc_name = request.form.get('account_name')
        sort = request.form.get('sort_code')
        acc_num = request.form.get('account_number')
        tax = request.form.get('tax_id')
        username = session.get('user_onboarding') or session.get('username')

        if username:
            # Create a simple string of the farmer's details
            farmer_data = (
                f"Username: {username}\n"
                f"Account Name: {acc_name}\n"
                f"Sort Code: {sort}\n"
                f"Account Number: {acc_num}\n"
                f"Tax ID: {tax}\n"
                f"{'-'*20}\n"
            )

            # Append the details to a local text file
            try:
                with open('farmer_details.txt', 'a') as f:
                    f.write(farmer_data)
                print(f"Details for {username} saved to file.")
                return redirect(url_for('Dashboard'))
            except Exception as e:
                print(f"Error saving to file: {e}")
        else:
            print("No username in session. Please log in again.")

   return render_template('payfarmers.html')


@app.route('/famerAddProduct', methods=['GET', 'POST'])
@login_required_farmers
def famerAddProduct():
    if request.method == 'POST':
        farm_name = session.get('farm_name') 
        user_id = session.get('user_id')

        # Get the new text data
        name = request.form.get('food_name')
        qty = request.form.get('quantity')
        price = request.form.get('price')
        description = request.form.get('description') 

        #  Handle the Image File
        file = request.files.get('food_image') 
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(UPLOAD_FOLDER, filename))
        else:
            filename = "default.jpg" # Fallback if no image is uploaded

        #  Update the SQL query to include the 2 new columns
        db = get_db()
        db.execute('''
            INSERT INTO foods (farmer_id, farm_name, food_name, quantity, price, description, image_filename) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, farm_name, name, qty, price, description, filename)) 
        
        db.commit()

        flash(f"{name} added successfully!")
        return redirect(url_for('famerAddProduct'))

    return render_template('famerAddProduct.html')


# This function checks if a file has one of the allowed extensions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/certifications', methods=['GET', 'POST'])
@login_required_farmers
def certifications():

    if request.method == 'POST':
        # Grab files from the HTML form
        insurance_file = request.files.get('insurance')
        academic_file = request.files.get('academic')

        db = get_db()
        user_id = session['user_id']

        # Save Insurance
        if insurance_file and allowed_file(insurance_file.filename):
            filename = secure_filename(f"user_{user_id}_ins_" + insurance_file.filename)
            insurance_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            db.execute('UPDATE users SET insurance_path = ? WHERE id = ?', (filename, user_id))

        # Save Academic
        if academic_file and allowed_file(academic_file.filename):
            filename = secure_filename(f"user_{user_id}_acad_" + academic_file.filename)
            academic_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            db.execute('UPDATE users SET academic_path = ? WHERE id = ?', (filename, user_id))

        db.commit()
        flash("Documents uploaded!")
        return redirect(url_for('Dashboard'))

    return render_template('certifications.html')



if __name__ =='__main__':
    app.run(debug=True)