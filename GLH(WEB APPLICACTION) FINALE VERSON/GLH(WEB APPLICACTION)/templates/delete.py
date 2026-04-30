import sqlite3
import os  # Standard library, no install needed
from flask import Flask, render_template, url_for, redirect, g, session, jsonify, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename # This helps save files safely
from functools import wraps
import http.client
import requests

app = Flask(__name__)
app.secret_key = 'some_random_secret_string'
app.config["SECRET_KEY"] = "supersecretkey" # This encrypts your session cookie
DATABASE = "db.sqlite"
UPLOAD_FOLDER = 'static/uploads/certs' # this is for the certicates to be uploaded 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)#this creates a folder if its not already there

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'} #these are the type of files that are allowed 
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
    try:
        db.execute('ALTER TABLE foods ADD COLUMN farm_name TEXT')
        db.commit()
    except:
        pass
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

    #Foods Table 
    db.execute('''
        CREATE TABLE IF NOT EXISTS foods (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            farmer_id INTEGER,
            farm_name TEXT NOT NULL,          
            food_name TEXT NOT NULL,
            quantity TEXT,
            price REAL,
            FOREIGN KEY (farmer_id) REFERENCES users (id)
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

        try:
            hashed_pw = generate_password_hash(password, method="pbkdf2:sha256")
            db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
            db.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return render_template("register", error="Username already taken!")
    
    return render_template("register.html")

def login_required_farmers(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If there is no user_id in the session, kick them out
        if 'user_id' not in session:
            flash("Please log in to access this page.")
            return redirect(url_for('FarmersOnBoarding')) # Change this to  login route name
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
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and check_password_hash(user['password'], password):
            # 1. Basic Login Session Data
            session['user_id'] = user['id']
            session['username'] = user['username']
            
            # 2. ADD THESE: Identify if they are a farmer
            if user['farm_name']:
                session['farm_name'] = user['farm_name']
                session['is_farmer'] = True  # This unlocks @login_required_farmers
                flash(f"Welcome back to {user['farm_name']}!")
                return redirect(url_for('Dashboard')) # Send farmers straight to work
            else:
                # If they don't have a farm name, they might be a regular customer
                session['is_farmer'] = False
                return redirect(url_for('home'))
        
        flash("Invalid username or password")
        return render_template("login.html")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear() # Clears the login cookie
    return redirect(url_for("home"))


@app.route('/Dashboard')
@login_required_farmers
def Dashboard():
    user_id = session.get('user_id')
    db = get_db()

    # 1. Double-check the database for this specific user's farm_name
    user = db.execute('SELECT farm_name FROM users WHERE id = ?', (user_id,)).fetchone()

    # 2. If the user doesn't have a farm_name in the DB, they shouldn't be here
    if not user or not user['farm_name']:
        flash("You need to register a farm name before accessing the dashboard.")
        # Send them back to onboarding or a profile completion page
        return redirect(url_for('FarmersOnBoarding'))

    # 3. If they passed the check, get their foods
    farm_name = user['farm_name']
    cur = db.execute('SELECT * FROM foods WHERE farm_name = ?', (farm_name,))
    my_foods = cur.fetchall()

    return render_template('Dashboard.html', farm_name=farm_name, foods=my_foods)



@app.route('/')
def links():
   return render_template('links.html')#i use this page to help me navigate through the site a bit easier 

@app.route('/home')
def home():
    # 1. Check if they are logged in as a Farmer
    if session.get('is_farmer'):
        # Send them straight to their dashboard
        return redirect(url_for('Dashboard')) 
    
    # 2. Otherwise, treat them as a normal user/guest
    username = session.get('username') 
    return render_template('home.html', username=username)


@app.route('/supportcontact')
def supportcontact():
    return render_template('supportcontact.html') #this will take you to the support and contact page 

@app.route('/MeetTheMaker')
def MeetTheMaker():
    return render_template('MeetTheMaker.html')#this will take you the the meet the maker page 




@app.route('/about')
def about():
    return render_template('about.html')#this will take you to the about page

@app.route('/ProductCatalog')
def ProductCatalog():
    return render_template('ProductCatalog.html')#where customers and browsetrugh the the products the farmers offer 

@app.route('/ShoppingCart')
@login_required
def ShoppingCart():
    return render_template('ShoppingCart.html')# when they are purchaseing this is where their items are stored 

@app.route('/QrScanAndGo')
@login_required
def QrScanAndGo():
    return render_template('QrScanAndGo.html') #this is for the pick up for  when the customer wants to pick something up form 

@app.route('/PurchaseHistory')
@login_required
def PurchaseHistory():
    return render_template('PurchaseHistory.html')#this is where customers see their previouse sales if any at all 


@app.route('/StockManagement')
@login_required_farmers
def StockManagement():
    return render_template('StockManagement.html') #this is a page whenre ther famers can add or remove things form the online shop 

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


@app.route('/ContactGlhFarmers')
@login_required_farmers
def ContactGlhFarmers():
    return render_template('ContactGlhFarmers.html')#this is a quick link for the farmers to get incontact with the glh staff

@app.route('/Responsepage')
def Responsepage():
    return render_template('Responsepage.html')#this is the glh resposnse page to all the sign up request and all the new users log in 

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
    return render_template('inventory.html')#this is for the glh staff when loking over all the farmers 

@app.route('/DataRequirementsGuide')
def DataRequirementsGuide():
    return render_template('DataRequirementsGuide.html')

@app.route('/FarmersOnBoarding', methods=['GET', 'POST'])
def FarmersOnBoarding():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        fname = request.form.get('firstname')
        sname = request.form.get('secondname')
        farm = request.form.get('farm_name')  
        phone = request.form.get('phone_number') 
        email = request.form.get('email')
        dob = request.form.get('dob')
        farm = request.form.get('farm_name')  
        
        db = get_db()
        try:
            hashed_pw = generate_password_hash(password)
            
            # 1. Insert the user
            cursor = db.execute('''
                INSERT INTO users (username, password, firstname, secondname, farm_name, phone, email, dob) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (username, hashed_pw, fname, sname, farm, phone, email, dob))
            db.commit()

            # this helps configure if the person is a farmer or notwhich helps with page  permisions
            session['user_id'] = cursor.lastrowid 
            session['username'] = username
            session['farm_name'] = farm
            session['is_farmer'] = True  # This tells the app they are a farmer
            
            
            # 3. Redirect to the next step
            return render_template('legalusersvarification.html')

        except sqlite3.IntegrityError:
            return "Error: That username or email is already taken."
        except Exception as e:
            return f"Error: {e}"

    return render_template('FarmersOnBoarding.html')

#@app.route('/phyicaladress', methods=['GET', 'POST'])
#@login_required_farmers
#def phyicaladress():
    #this is after the farmer/user has finished making an acount they need to make compleete this page if they need any dilivery or any want to finish the farmers on boarding 
 #   if request.method == 'POST':
   #     postcode = request.form.get('postcode')
  ##      city = request.form.get('city')
  #      county = request.form.get('county')
 #       username = session.get('user_onboarding')
 #       if username:
 #           db = get_db()
 #          db.execute('''
  #              UPDATE users 
  #              SET postcode = ?, city = ?, county = ? 
  #              WHERE username = ?
  #          ''', (postcode, city, county, username))
  #          db.commit()
            
   #         return render_template('/legalusersvarification.html')#it should be taking to this page after it obtainns the users info but 
 #       else:
 #           return "Session expired. Please start again."# another error page needs to be placed here 

  #  return render_template('phyicaladress.html')

#@app.route('/api/lookup/<postcode>')
#def lookup_postcode(postcode):
    #  Clean the postcode remove spaces so it's safe for the URL for other users
   # clean_pc = postcode.replace(" ", "")
    #that stands for clean post code
    
   
  #  url = f"https://postcodes.io{clean_pc}"
    
 #   headers = {'Accept': 'application/json'}

  #  try:
 #       response = requests.get(url, headers=headers)
        
     #   if response.status_code == 200:
    #        data = response.json()['result']
     #       return jsonify({
        #        "status": "success",
       #         "city": data.get("admin_district"),
       #         "county": data.get("admin_county") or data.get("region")
      #      })
   # except Exception as e:
   #     print(f"Connection Error: {e}")# another error page

 #   return jsonify({"status": "error", "message": "Postcode not found"}), 404

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
            return redirect(url_for('/Dashboard')) 
        else:
            # flash() is a great way to show errors on the login/start page
            flash("Session expired. Please start again.")
            

    return render_template('legalusersvarification.html')

@app.route('/payfarmers', methods=['GET', 'POST'])
def payfarmers():
    if request.method == 'POST':
        #  Grab the info from your HTML form 'name' attributes
        acc_name = request.form.get('account_name')
        sort = request.form.get('sort_code')
        acc_num = request.form.get('account_number')
        tax = request.form.get('tax_id')
        username = session.get('user_onboarding')

        if username:
            db = get_db()
            db.execute('''
                UPDATE users 
                SET account_name = ?, sort_code = ?, account_number = ?, tax_id = ? 
                WHERE username = ?
            ''', (acc_name, sort, acc_num, tax, username))
            db.commit()
            
            # Take them to a proffesinal storefront
            return redirect(url_for('Dashboard')) 
        else:
            return redirect(url_for('login')) 
       




    return render_template('payfarmers.html')

@app.route('/famerAddProduct', methods=['GET', 'POST'])
@login_required_farmers
def famerAddProduct():
    if request.method == 'POST':
        # 1. Get identifiers from the session
        farm_name = session.get('farm_name') 
        user_id = session.get('user_id')

        # 2. Get the food data from the form
        name = request.form.get('food_name')
        qty = request.form.get('quantity')
        price = request.form.get('price')

        # 3. Save to database using the variables defined above
        db = get_db()
        db.execute('''
            INSERT INTO foods (farmer_id, farm_name, food_name, quantity, price) 
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, farm_name, name, qty, price)) # Fixed variable names here
        db.commit()

        flash(f"{name} added for {farm_name}!")
        return redirect(url_for('Dashboard'))

    return render_template('famerAddProduct.html')


# This function checks if a file has one of the allowed extensions
def allowed_file(filename):
    # Ensure there is a '.' in the filename and the extension is in our list
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

@app.route("/delete/<int:item_id>", methods=["POST"])
def delete_item(item_id): # This name MUST match 'delete_item'
    # your logic to delete from SQL
    db.execute("DELETE FROM foods WHERE id = ?", item_id)
    return redirect("/")



if __name__ =='__main__':
    app.run(debug=True)