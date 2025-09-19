import os
import json
import sqlite3
import qrcode
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for, session,
    flash
)
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import requests
from werkzeug.security import generate_password_hash, check_password_hash

# Load env
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Admin@123")
UPI_VPA = os.getenv("UPI_VPA", "rahultawarakhed-1@okicici")
UPI_PAYEE_NAME = os.getenv("UPI_PAYEE_NAME", "Rahul S Tawarakhed")
CURRENCY_SYMBOL = os.getenv("CURRENCY_SYMBOL", "₹")
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "rahultawarakhed@gmail.com")          # change if needed
APP_PASSWORD = os.getenv("APP_PASSWORD", "dkjunpfweyseyezd")             # change if needed
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "malipatilprema@gmail.com")               # admin email to receive OTP

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "shop.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
QRCODE_DIR = os.path.join(BASE_DIR, "static", "qrcodes")
ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "webp", "gif"}

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(QRCODE_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = SECRET_KEY

# --------- DB Helpers ---------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Create tables if they don't exist and ensure necessary columns exist.
    This function is safe to run repeatedly.
    """
    conn = get_db()
    cur = conn.cursor()

    # Products table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            image_filename TEXT,
            stock INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
    """)

    # Users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT,
            password TEXT NOT NULL,   -- hashed password
            address_line1 TEXT,
            address_line2 TEXT,
            city TEXT,
            state TEXT,
            pincode TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Orders table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            items_json TEXT NOT NULL,
            total REAL NOT NULL,
            status TEXT DEFAULT 'pending',
            txn_id TEXT,
            buyer_name TEXT,
            buyer_phone TEXT,
            address_line1 TEXT,
            address_line2 TEXT,
            city TEXT,
            state TEXT,
            pincode TEXT,
            buyer_address TEXT,  -- ✅ Added field
            user_id INTEGER,
            created_at TEXT
        );
    """)

    # ✅ Ensure 'address' column exists in users
    user_cols = [r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
    if "address" not in user_cols:
        try:
            conn.execute("ALTER TABLE users ADD COLUMN address TEXT")
        except Exception:
            pass

    # ✅ Ensure 'buyer_address' column exists in orders
    order_cols = [r["name"] for r in conn.execute("PRAGMA table_info(orders)").fetchall()]
    if "buyer_address" not in order_cols:
        try:
            conn.execute("ALTER TABLE orders ADD COLUMN buyer_address TEXT")
        except Exception:
            pass

    conn.commit()
    conn.close()

def send_email_otp(to_email, otp):
    subject = "Your Admin OTP Code"
    body = f"Your OTP for admin login is: {otp}\n\nThis OTP is valid for 5 minutes."

    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print("Error sending email:", e)
        return False

@app.before_request
def ensure_db():
    if not os.path.exists(DB_PATH):
        init_db()

# --------- Utils ---------
def allowed_image(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXT

def format_currency(x):
    try:
        return f"{CURRENCY_SYMBOL}{x:,.2f}"
    except Exception:
        return f"{x:.2f}"

app.jinja_env.globals.update(format_currency=format_currency)

# --------- Payment + QR Helpers ---------
def build_upi_url(UPI_VPA , UPI_PAYEE_NAME, amount, note):
    from urllib.parse import quote
    amt_str = f"{amount:.2f}"
    return f"upi://pay?pa={quote(UPI_VPA )}&pn={quote(UPI_PAYEE_NAME)}&am={quote(amt_str)}&cu=INR&tn={quote(note)}"

def generate_qr(data, save_path):
    img = qrcode.make(data)
    img.save(save_path)

# --------- Public Routes ---------
@app.route("/")
def index():
    conn = get_db()
    products = conn.execute("SELECT * FROM products ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("index.html", products=products)

@app.route("/product/<int:pid>")
def product_detail(pid):
    conn = get_db()
    product = conn.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    products = conn.execute("SELECT * FROM products ORDER BY id DESC").fetchall()
    conn.close()
    if not product:
        return redirect(url_for('index'))
    return render_template("product.html", product=product, products=products)

# Signup route
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").lower().strip()
        password = request.form.get("password", "").strip()
        phone = request.form.get("phone", "").strip()

        address_line1 = request.form.get("address_line1", "").strip()
        address_line2 = request.form.get("address_line2", "").strip()
        pincode = request.form.get("pincode", "").strip()
        city = request.form.get("city", "").strip()
        state = request.form.get("state", "").strip()

        # Verify city/state using backend if missing
        if len(pincode) == 6 and (not city or not state):
            try:
                res = requests.get(f"https://api.postalpincode.in/pincode/{pincode}", timeout=5)
                data = res.json()
                if data[0]["Status"] == "Success":
                    post_office = data[0]["PostOffice"][0]
                    city = post_office["District"]
                    state = post_office["State"]
                else:
                    flash("Invalid Pincode. Please check again.", "error")
                    return redirect(url_for("signup"))
            except Exception as e:
                print("Error fetching city/state:", e)
                flash("Error fetching city/state. Try again.", "error")
                return redirect(url_for("signup"))

        # Combine full address
        address = f"{address_line1}, {address_line2}, {city}, {state} - {pincode}"

        # Validate required fields
        if not name or not email or not password:
            flash("Please fill required fields", "error")
            return redirect(url_for("signup"))

        # Save to DB
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email=?", (email,))
        if cur.fetchone():
            flash("Email already registered. Please login.", "error")
            conn.close()
            return redirect(url_for("login"))

        hashed_pw = generate_password_hash(password)
        cur.execute(
            "INSERT INTO users (name, email, phone, address, password, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (name, email, phone, address, hashed_pw, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
        flash("Signup successful! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")
@app.route("/get_location/<pincode>")
def get_location(pincode):
    try:
        res = requests.get(f"https://api.postalpincode.in/pincode/{pincode}", timeout=5)
        data = res.json()
        if data[0]["Status"] == "Success":
            post_office = data[0]["PostOffice"][0]
            return {
                "city": post_office["District"],
                "state": post_office["State"]
            }
        else:
            return {"city": "", "state": ""}
    except Exception as e:
        print("Error fetching city/state:", e)
        return {"city": "", "state": ""}


# ---------------- Login (supports 'next' redirect) ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    next_url = request.args.get("next") or request.form.get("next") or url_for("index")
    if request.method == "POST":
        email = request.form.get("email", "").lower().strip()
        password = request.form.get("password", "").strip()

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            flash("Welcome back, " + user["name"], "success")
            # redirect to next if safe (we assume internal)
            return redirect(next_url)
        else:
            flash("Invalid credentials", "error")
            return redirect(url_for("login", next=next_url))

    # GET
    return render_template("login.html", next=next_url)

# ---------------- Logout ----------------
@app.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("user_name", None)
    flash("Logged out successfully", "info")
    return redirect(url_for("index"))

# ---------------- Profile (view & update) ----------------
@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        flash("Please login to access your profile.", "error")
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

    if request.method == "POST":
        phone = request.form.get("phone")
        address_line1 = request.form.get("address_line1")
        address_line2 = request.form.get("address_line2")
        city = request.form.get("city")
        state = request.form.get("state")
        pincode = request.form.get("pincode")

        cur.execute("""
            UPDATE users SET phone=?, address_line1=?, address_line2=?, city=?, state=?, pincode=? WHERE id=?
        """, (phone, address_line1, address_line2, city, state, pincode, session["user_id"]))
        conn.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for("profile"))

    conn.close()
    return render_template("profile.html", user=user)
# ---------------- My Orders (customer) ----------------
@app.route("/my-orders")
def my_orders():
    if "user_id" not in session:
        flash("Please login to view your orders.", "error")
        return redirect(url_for("login", next=url_for("my_orders")))

    conn = get_db()
    rows = conn.execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC", (session["user_id"],)).fetchall()
    conn.close()

    orders = []
    for r in rows:
        orders.append({
            "id": r["id"],
            "total": r["total"],
            "status": r["status"],
            "created_at": r["created_at"],
            "items": json.loads(r["items_json"]) if r["items_json"] else []
        })

    return render_template("my_orders.html", orders=orders)

# ---------------- Cart ----------------
@app.route("/add-to-cart/<int:pid>", methods=["POST"])
def add_to_cart(pid):
    try:
        qty = int(request.form.get("qty", 1))
    except:
        qty = 1
    conn = get_db()
    product = conn.execute("SELECT id, name, price, stock FROM products WHERE id=?", (pid,)).fetchone()
    conn.close()
    if not product:
        flash("Product not found", "error")
        return redirect(url_for('index'))
    if qty < 1:
        qty = 1
    if qty > product["stock"]:
        flash("Requested quantity exceeds stock", "error")
        return redirect(url_for('product_detail', pid=pid))

    cart = session.get("cart", {})
    cur_qty = cart.get(str(pid), 0)
    new_qty = min(cur_qty + qty, product["stock"])
    cart[str(pid)] = new_qty
    session["cart"] = cart
    flash("Added to cart", "success")
    return redirect(url_for('cart_view'))

@app.route("/cart")
def cart_view():
    cart = session.get("cart", {})
    if not cart:
        return render_template("cart.html", items=[], total=0.0)

    pids = [int(pid) for pid in cart.keys()]
    placeholders = ",".join("?" for _ in pids)
    conn = get_db()
    products = conn.execute(
        f"SELECT id, name, price, stock, image_filename FROM products WHERE id IN ({placeholders})", pids
    ).fetchall()
    conn.close()

    items = []
    total = 0.0
    for p in products:
        qty = cart.get(str(p["id"]), 0)
        subtotal = p["price"] * qty
        total += subtotal
        items.append({
            "id": p["id"],
            "name": p["name"],
            "price": p["price"],
            "qty": qty,
            "subtotal": subtotal,
            "image_filename": p["image_filename"],
            "stock": p["stock"],
        })
    return render_template("cart.html", items=items, total=total)

@app.route("/cart/update", methods=["POST"])
def cart_update():
    cart = session.get("cart", {})
    for key, value in request.form.items():
        if key.startswith("qty_"):
            pid = key.split("_", 1)[1]
            try:
                qty = max(0, int(value))
            except:
                qty = 0
            if qty == 0:
                cart.pop(pid, None)
            else:
                cart[pid] = qty
    session["cart"] = cart
    flash("Cart updated", "success")
    return redirect(url_for('cart_view'))

# ---- Checkout (requires login; uses stored address automatically) ----
@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    # require login before allowing checkout
    if "user_id" not in session:
        flash("Please login to place an order.", "error")
        return redirect(url_for("login", next=url_for("checkout")))

    cart = session.get("cart", {})
    if not cart:
        flash("Cart is empty", "error")
        return redirect(url_for('index'))

    # fetch products and build items
    pids = [int(pid) for pid in cart.keys()]
    placeholders = ",".join("?" for _ in pids)
    conn = get_db()
    products = conn.execute(
        f"SELECT id, name, price, stock FROM products WHERE id IN ({placeholders})", pids
    ).fetchall()

    items, total = [], 0.0
    for p in products:
        qty = cart.get(str(p["id"]), 0)
        if qty > p["stock"]:
            conn.close()
            flash(f"Not enough stock for {p['name']}", "error")
            return redirect(url_for('cart_view'))
        subtotal = p["price"] * qty
        total += subtotal
        items.append({
            "id": p["id"],
            "name": p["name"],
            "price": p["price"],
            "qty": qty,
            "subtotal": subtotal
        })

    # get logged-in user's contact info
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

    # GET -> show checkout summary (use saved address)
    if request.method == "GET":
        conn.close()
        return render_template(
            "checkout.html",
            items=items,
            total=total,
            upi_vpa=UPI_VPA,
            payee=UPI_PAYEE_NAME,
            user=user
        )

    # POST -> create order using saved user details
    buyer_name = user["name"]
    buyer_phone = user["phone"]
    buyer_address = user["address"]   # ✅ FIXED — use single address column

    if not buyer_name or not buyer_phone or not buyer_address:
        conn.close()
        flash("Please complete your profile with full address details before ordering.", "error")
        return redirect(url_for("profile"))

    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO orders 
        (items_json, total, status, txn_id, buyer_name, buyer_phone, buyer_address, user_id, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            json.dumps(items),
            total,
            "pending",
            None,
            buyer_name,
            buyer_phone,
            buyer_address,
            session["user_id"],
            datetime.now().isoformat(timespec="seconds")
        )
    )
    order_id = cur.lastrowid

    # reduce stock
    for it in items:
        cur.execute("UPDATE products SET stock = stock - ? WHERE id = ?", (it["qty"], it["id"]))

    conn.commit()
    conn.close()

    # Generate UPI QR for this order total
    upi_url = build_upi_url(UPI_VPA, UPI_PAYEE_NAME, total, f"ORDER{order_id}")
    qr_path = os.path.join(QRCODE_DIR, f"order_{order_id}.png")
    generate_qr(upi_url, qr_path)

    session["cart"] = {}
    flash("Order created. Scan the QR to pay. After payment you can add the transaction ID on the order page.", "success")
    return redirect(url_for("order_summary", order_id=order_id))

# ---- Order summary page (show QR + allow customer to submit txn id) ----
@app.route("/order/<int:order_id>")
def order_summary(order_id):
    conn = get_db()
    order = conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    conn.close()
    if not order:
        flash("Order not found", "error")
        return redirect(url_for("index"))
    items = json.loads(order["items_json"])
    qr_rel = f"static/qrcodes/order_{order_id}.png"
    return render_template("order_summary.html", order=order, items=items, qr_path=qr_rel)

# ---- Customer submits UPI txn id after paying ----
# ---- Customer submits UPI txn id after paying ----
@app.route("/order/<int:order_id>/confirm", methods=["POST"])
def confirm_order(order_id):
    txn = request.form.get("txn_id", "").strip()
    if not txn:
        flash("Please enter transaction id (UTR).", "error")
        return redirect(url_for("order_summary", order_id=order_id))

    conn = get_db()
    order = conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    if not order:
        conn.close()
        flash("Order not found", "error")
        return redirect(url_for("index"))

    # ✅ Update order
    conn.execute("UPDATE orders SET txn_id=?, status=? WHERE id=?", (txn, "Pending Verification", order_id))
    conn.commit()
    conn.close()

    # ✅ Prepare email for admin
    items = json.loads(order["items_json"]) if order["items_json"] else []
    item_lines = "\n".join([f"- {it['name']} × {it['qty']} = {CURRENCY_SYMBOL}{it['subtotal']}" for it in items])

    subject = f"🛒 New Order #{order_id} Placed"
    body = f"""
    Dear Admin,

    A customer has placed a new order.

    📌 Order ID: {order_id}
    👤 Customer: {order['buyer_name']} ({order['buyer_phone']})
    🏠 Address: {order['buyer_address']}
    💰 Total: {CURRENCY_SYMBOL}{order['total']}
    🔑 Transaction ID (UTR): {txn}

    🛍️ Items:
    {item_lines}

    Please verify the payment manually.

    Regards,
    Your Shop System
    """

    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = ADMIN_EMAIL
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.sendmail(SENDER_EMAIL, ADMIN_EMAIL, msg.as_string())
        server.quit()
        print("✅ Order email sent to admin")
    except Exception as e:
        print("❌ Error sending order email:", e)

    flash("Transaction ID received. Admin notified. Awaiting verification.", "success")
    return redirect(url_for("order_summary", order_id=order_id))
# --------- Admin (unchanged behavior, email OTP) ---------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password", "").strip()

        if password == ADMIN_PASSWORD:
            otp = str(random.randint(100000, 999999))
            session["pending_admin"] = True
            session["otp"] = otp

            if send_email_otp(ADMIN_EMAIL, otp):
                flash("OTP sent to admin email", "info")
                return redirect(url_for("admin_verify_otp"))
            else:
                flash("Failed to send OTP. Try again.", "error")
                return redirect(url_for("admin_login"))
        else:
            flash("Invalid password", "error")

    return render_template("admin_login.html")

@app.route("/admin/verify-otp", methods=["GET", "POST"])
def admin_verify_otp():
    if "pending_admin" not in session:
        return redirect(url_for("admin_login"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        if otp == session.get("otp"):
            session.pop("pending_admin")
            session.pop("otp")
            session["is_admin"] = True
            flash("Login successful", "success")
            return redirect(url_for("admin_home"))
        else:
            flash("Invalid OTP", "error")

    return render_template("admin_verify_otp.html")

@app.route("/admin/home")
def admin_home():
    if not admin_required():
        return redirect(url_for("admin_login"))
    return render_template("admin_home.html")

@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("index"))

def admin_required():
    return session.get("is_admin")

@app.route("/admin/dashboard")
def admin_dashboard():
    if not admin_required():
        return redirect(url_for("admin_login"))
    conn = get_db()
    products = conn.execute("SELECT * FROM products ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("admin_dashboard.html", products=products)

@app.route("/admin/orders")
def admin_orders():
    if not admin_required():
        return redirect(url_for('admin_login'))

    conn = get_db()
    rows = conn.execute("""
        SELECT o.*, u.email as user_email 
        FROM orders o
        LEFT JOIN users u ON o.user_id = u.id
        ORDER BY o.id DESC
    """).fetchall()
    conn.close()

    orders = []
    for r in rows:
        orders.append({
            "id": r["id"],
            "total": r["total"],
            "status": r["status"],
            "txn_id": r["txn_id"],
            "buyer_name": r["buyer_name"],
            "buyer_phone": r["buyer_phone"],
            "buyer_address": r["buyer_address"],
            "created_at": r["created_at"],
            "items": json.loads(r["items_json"]) if r["items_json"] else [],
            "user_email": r["user_email"] or "Guest"
        })

    return render_template("admin_orders.html", orders=orders)

@app.route("/admin/orders/<int:oid>/status", methods=["POST"])
def admin_update_order_status(oid):
    if not admin_required():
        return redirect(url_for('admin_login'))
    status = request.form.get("status", "pending")
    txn_id = request.form.get("txn_id", "").strip()
    conn = get_db()
    conn.execute("UPDATE orders SET status=?, txn_id=? WHERE id=?", (status, txn_id, oid))
    conn.commit()
    conn.close()
    flash("Order updated", "success")
    return redirect(url_for("admin_orders"))

# ---------------- Admin: product CRUD (unchanged) ----------------
@app.route("/admin/products/new", methods=["GET", "POST"])
def admin_add_product():
    if not admin_required():
        return redirect(url_for('admin_login'))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        desc = request.form.get("description", "").strip()
        try:
            price = float(request.form.get("price", "0") or 0)
        except:
            price = 0.0
        try:
            stock = int(request.form.get("stock", "0") or 0)
        except:
            stock = 0
        file = request.files.get("image")

        image_filename = None
        if file and allowed_image(file.filename):
            fname = secure_filename(file.filename)
            base, ext = os.path.splitext(fname)
            fname = f"{base}_{int(datetime.now().timestamp())}{ext}"
            file.save(os.path.join(UPLOAD_DIR, fname))
            image_filename = fname

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO products (name, description, price, image_filename, stock, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (name, desc, price, image_filename, stock, datetime.now().isoformat(timespec="seconds"))
        )
        conn.commit()
        conn.close()
        flash("Product added", "success")
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_add_product.html")

@app.route("/admin/products/<int:pid>/edit", methods=["GET", "POST"])
def admin_edit_product(pid):
    if not admin_required():
        return redirect(url_for('admin_login'))

    conn = get_db()
    product = conn.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()

    if not product:
        conn.close()
        flash("Product not found", "error")
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        desc = request.form.get("description", "").strip()
        try:
            price = float(request.form.get("price", "0") or 0)
        except:
            price = 0.0
        try:
            stock = int(request.form.get("stock", "0") or 0)
        except:
            stock = 0
        file = request.files.get("image")

        image_filename = product["image_filename"]
        if file and allowed_image(file.filename):
            fname = secure_filename(file.filename)
            base, ext = os.path.splitext(fname)
            fname = f"{base}_{int(datetime.now().timestamp())}{ext}"
            file.save(os.path.join(UPLOAD_DIR, fname))
            image_filename = fname

        cur = conn.cursor()
        cur.execute(
            "UPDATE products SET name=?, description=?, price=?, image_filename=?, stock=? WHERE id=?",
            (name, desc, price, image_filename, stock, pid)
        )
        conn.commit()
        conn.close()
        flash("Product updated successfully", "success")
        return redirect(url_for("admin_dashboard"))

    conn.close()
    return render_template("admin_edit_product.html", product=product)

@app.route("/admin/products/<int:pid>/delete", methods=["POST"])
def admin_delete_product(pid):
    if not admin_required():
        return redirect(url_for("admin_login"))

    conn = get_db()
    conn.execute("DELETE FROM products WHERE id=?", (pid,))
    conn.commit()
    conn.close()
    flash("Product deleted successfully", "success")
    return redirect(url_for("admin_dashboard"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
