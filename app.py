import os
import secrets
from functools import wraps

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash


db = SQLAlchemy()


def create_app():
    app = Flask(__name__)

    # Prefer env var; fallback to a strong random key for local/dev use.
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///inventory.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    app.jinja_env.filters["inr"] = format_inr

    with app.app_context():
        db.create_all()
        seed_db()

    @app.route("/")
    def index():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Ghosting the login form? Fill it out first.", "error")
            return redirect(url_for("login"))

        user = User.query.filter_by(username=username).first()
        if not user:
            flash("Who? We don't know them. Create an account, bestie.", "error")
            return redirect(url_for("login"))
        if not check_password_hash(user.password_hash, password):
            flash("Oof, that's a miss. Check your password and try again.", "error")
            return redirect(url_for("login"))

        session["user_id"] = user.id
        session["role"] = user.role
        session["username"] = user.username
        session["viewed_sessions"] = session.get("viewed_sessions", 0) + 1
        flash("Welcome back.", "success")
        return redirect(url_for("welcome"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "GET":
            return render_template("register.html")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "staff").strip().lower()

        if not username or not password:
            flash("Username and password are required.", "error")
            return redirect(url_for("register"))

        if role not in {"admin", "staff"}:
            flash("Role must be either admin or staff.", "error")
            return redirect(url_for("register"))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already taken.", "error")
            return redirect(url_for("register"))

        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            role=role,
        )
        db.session.add(user)
        db.session.commit()

        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for("login"))

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        products = Product.query.all()
        metrics = build_report_metrics(products)
        return render_template("dashboard.html", products=products, **metrics)

    @app.route("/reports")
    @login_required
    def reports():
        products = Product.query.order_by(Product.id.asc()).all()
        metrics = build_report_metrics(products)
        stock_counts = {
            "in_stock": sum(1 for product in products if product.quantity > 15),
            "low_stock": sum(1 for product in products if 0 < product.quantity <= 15),
            "out_of_stock": sum(1 for product in products if product.quantity == 0),
        }

        prefix_labels = {
            "EL": "Electronics",
            "HW": "Hardware",
            "SG": "Safety Gear",
            "ST": "Stationery",
            "FU": "Furniture",
        }
        category_values = {}
        for product in products:
            prefix = product.sku.split("-")[0]
            label = prefix_labels.get(prefix, prefix)
            category_values[label] = category_values.get(label, 0) + float(product.price) * product.quantity

        top_items = sorted(products, key=lambda item: float(item.price), reverse=True)[:5]
        top_items_payload = [
            {
                "name": item.name,
                "price": float(item.price),
                "quantity": item.quantity,
            }
            for item in top_items
        ]

        return render_template(
            "reports.html",
            products=products,
            stock_counts=stock_counts,
            category_values=category_values,
            top_items=top_items_payload,
            **metrics,
        )

    @app.route("/welcome")
    @login_required
    def welcome():
        return render_template("welcome.html")

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        user = User.query.get(session.get("user_id"))
        if not user:
            session.clear()
            flash("Session expired. Please log in again.", "error")
            return redirect(url_for("login"))

        if request.method == "POST":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not current_password or not new_password or not confirm_password:
                flash("All password fields are required.", "error")
                return redirect(url_for("profile"))

            if not check_password_hash(user.password_hash, current_password):
                flash("Current password is incorrect.", "error")
                return redirect(url_for("profile"))

            if new_password != confirm_password:
                flash("New passwords do not match.", "error")
                return redirect(url_for("profile"))

            user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash("Password updated successfully.", "success")
            return redirect(url_for("profile"))

        total_products = Product.query.count()
        viewed_sessions = session.get("viewed_sessions", 0)
        return render_template(
            "profile.html",
            user=user,
            total_products=total_products,
            viewed_sessions=viewed_sessions,
        )

    @app.route("/admin")
    @admin_required
    def admin():
        return "Admin access granted"

    @app.route("/product/add", methods=["POST"])
    @admin_required
    def add_product():
        sku = request.form.get("sku", "").strip()
        name = request.form.get("name", "").strip()
        quantity = request.form.get("quantity", "0").strip()
        price = request.form.get("price", "0").strip()

        if not sku or not name:
            return "SKU and name are required", 400

        existing = Product.query.filter_by(sku=sku).first()
        if existing:
            return "SKU already exists", 400

        try:
            quantity_value = int(quantity)
            price_value = float(price)
        except ValueError:
            return "Quantity must be an integer and price must be a number", 400

        product = Product(
            sku=sku,
            name=name,
            quantity=quantity_value,
            price=price_value,
        )
        db.session.add(product)
        db.session.commit()

        return redirect(url_for("dashboard"))

    @app.route("/product/update/<int:id>", methods=["POST"])
    @admin_required
    def update_product(id):
        product = Product.query.get_or_404(id)

        quantity = request.form.get("quantity")
        price = request.form.get("price")
        wants_json = request.accept_mimetypes.best == "application/json"

        if quantity is None and price is None:
            if wants_json:
                return jsonify({"error": "No fields to update"}), 400
            return "No fields to update", 400

        if quantity is not None:
            try:
                quantity_value = int(quantity)
                if quantity_value < 0:
                    raise ValueError("Quantity cannot be negative")
                product.quantity = quantity_value
            except ValueError:
                if wants_json:
                    return jsonify({"error": "Quantity must be a non-negative integer"}), 400
                return "Quantity must be a non-negative integer", 400

        if price is not None:
            try:
                price_value = float(price)
                if price_value < 0:
                    raise ValueError("Price cannot be negative")
                product.price = price_value
            except ValueError:
                if wants_json:
                    return jsonify({"error": "Price must be a non-negative number"}), 400
                return "Price must be a non-negative number", 400

        db.session.commit()
        if wants_json:
            badge_class = "green"
            badge_label = "ok"
            if product.quantity < 5:
                badge_class = "red"
                badge_label = "low"
            elif product.quantity < 20:
                badge_class = "orange"
                badge_label = "watch"
            return jsonify(
                {
                    "id": product.id,
                    "quantity": product.quantity,
                    "badge_class": badge_class,
                    "badge_label": badge_label,
                }
            )

        return redirect(url_for("dashboard"))

    @app.route("/product/delete/<int:id>", methods=["POST"])
    @admin_required
    def delete_product(id):
        product = Product.query.get_or_404(id)
        db.session.delete(product)
        db.session.commit()
        return redirect(url_for("dashboard"))

    return app


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapper


def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            flash("L + Ratio. You don't have the permissions for this.", "error")
            abort(403)
        return view_func(*args, **kwargs)

    return wrapper


def build_report_metrics(products):
    total_units = sum(product.quantity for product in products)
    total_inventory_value = sum(float(product.price) * product.quantity for product in products)
    critical_items = [product for product in products if product.quantity < 5]
    return {
        "total_units": total_units,
        "total_inventory_value": total_inventory_value,
        "critical_items": critical_items,
    }


def seed_massive_data():
    print("Seeding database...")
    products = [
        {"sku": "EL-001", "name": "Dell PowerEdge R740 Server", "quantity": 2, "price": 145000.00},
        {"sku": "EL-002", "name": "HP ProBook 450 G10 Laptop", "quantity": 4, "price": 82000.00},
        {"sku": "EL-003", "name": "Lenovo ThinkPad X1 Carbon", "quantity": 1, "price": 150000.00},
        {"sku": "EL-004", "name": "APC 10kVA Online UPS", "quantity": 3, "price": 98000.00},
        {"sku": "HW-001", "name": "Diesel Power Generator 10kVA", "quantity": 2, "price": 120000.00},
        {"sku": "EL-005", "name": "Synology NAS 8-Bay", "quantity": 2, "price": 90000.00},
        {"sku": "EL-006", "name": "Cisco Catalyst 9300 Switch", "quantity": 3, "price": 115000.00},
        {"sku": "EL-007", "name": "Epson 4K Projector", "quantity": 2, "price": 88000.00},
        {"sku": "HW-002", "name": "Industrial Air Compressor", "quantity": 2, "price": 95000.00},
        {"sku": "EL-008", "name": "Hikvision 32-Channel NVR", "quantity": 4, "price": 52000.00},
        {"sku": "EL-009", "name": "24-inch IPS Monitor", "quantity": 12, "price": 12500.00},
        {"sku": "EL-010", "name": "27-inch QHD Monitor", "quantity": 8, "price": 22000.00},
        {"sku": "FU-001", "name": "Steelcase Leap V2 Chair", "quantity": 10, "price": 38000.00},
        {"sku": "FU-002", "name": "Ergonomic Standing Desk", "quantity": 7, "price": 45000.00},
        {"sku": "SG-001", "name": "Fire Extinguisher 4kg", "quantity": 12, "price": 2800.00},
        {"sku": "SG-002", "name": "First Aid Cabinet", "quantity": 9, "price": 5600.00},
        {"sku": "EL-011", "name": "Dual-Band Wi-Fi Router", "quantity": 14, "price": 6900.00},
        {"sku": "HW-003", "name": "Cordless Drill Kit", "quantity": 6, "price": 8200.00},
        {"sku": "HW-004", "name": "Angle Grinder 4-inch", "quantity": 11, "price": 3600.00},
        {"sku": "FU-003", "name": "Modular Storage Cabinet", "quantity": 5, "price": 19500.00},
        {"sku": "FU-004", "name": "Conference Table 8-Seater", "quantity": 6, "price": 52000.00},
        {"sku": "SG-003", "name": "Safety Harness Kit", "quantity": 10, "price": 7400.00},
        {"sku": "ST-001", "name": "A4 Paper Reams", "quantity": 180, "price": 320.00},
        {"sku": "ST-002", "name": "Ballpoint Pens", "quantity": 240, "price": 20.00},
        {"sku": "ST-003", "name": "Sticky Notes Pack", "quantity": 150, "price": 45.00},
        {"sku": "ST-004", "name": "Highlighter Set", "quantity": 120, "price": 95.00},
        {"sku": "ST-005", "name": "Printer Paper A3", "quantity": 90, "price": 520.00},
        {"sku": "ST-006", "name": "Whiteboard Markers", "quantity": 140, "price": 60.00},
        {"sku": "ST-007", "name": "Paper Clips Box", "quantity": 200, "price": 55.00},
        {"sku": "ST-008", "name": "Stapler Pins 24/6", "quantity": 160, "price": 50.00},
        {"sku": "ST-009", "name": "File Folders", "quantity": 130, "price": 75.00},
        {"sku": "ST-010", "name": "Desk Planner", "quantity": 12, "price": 180.00},
        {"sku": "SG-004", "name": "Disposable Face Masks (50 pcs)", "quantity": 110, "price": 250.00},
        {"sku": "SG-005", "name": "Nitrile Gloves (100 pcs)", "quantity": 95, "price": 420.00},
        {"sku": "SG-006", "name": "Safety Helmets", "quantity": 65, "price": 520.00},
        {"sku": "SG-007", "name": "Reflective Safety Vests", "quantity": 85, "price": 350.00},
        {"sku": "HW-005", "name": "LED Work Lamp", "quantity": 75, "price": 950.00},
        {"sku": "HW-006", "name": "Adjustable Wrench Set", "quantity": 90, "price": 680.00},
        {"sku": "HW-007", "name": "Hammer 16oz", "quantity": 120, "price": 320.00},
        {"sku": "HW-008", "name": "Cat6 Ethernet Cable 10m", "quantity": 150, "price": 210.00},
        {"sku": "HW-009", "name": "Cable Ties Pack", "quantity": 200, "price": 50.00},
        {"sku": "HW-010", "name": "Packaging Tape Roll", "quantity": 130, "price": 70.00},
        {"sku": "EL-012", "name": "USB-C Docking Station", "quantity": 30, "price": 7800.00},
        {"sku": "EL-013", "name": "Bluetooth Headsets", "quantity": 40, "price": 3200.00},
        {"sku": "EL-014", "name": "Webcam 1080p", "quantity": 55, "price": 2500.00},
        {"sku": "FU-005", "name": "Visitor Chair", "quantity": 60, "price": 4200.00},
        {"sku": "FU-006", "name": "Office Desk 4ft", "quantity": 45, "price": 8500.00},
        {"sku": "SG-008", "name": "Emergency Exit Sign", "quantity": 25, "price": 1400.00},
        {"sku": "EL-015", "name": "Laser Printer", "quantity": 6, "price": 18500.00},
        {"sku": "SG-009", "name": "Fire Blanket", "quantity": 15, "price": 1200.00},
    ]
    db.session.bulk_insert_mappings(Product, products)
    db.session.commit()
    print(f"Successfully added {Product.query.count()} products.")


def format_inr(value):
    amount = float(value)
    sign = "-" if amount < 0 else ""
    amount = abs(amount)

    integer_part = int(amount)
    decimal_str = f"{amount:.2f}".split(".")[1]

    digits = str(integer_part)
    if len(digits) > 3:
        head = digits[:-3]
        tail = digits[-3:]
        groups = []
        while head:
            groups.insert(0, head[-2:])
            head = head[:-2]
        digits = ",".join(groups + [tail])

    return f"₹{sign}{digits}.{decimal_str}"


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sku = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=0)
    price = db.Column(db.Numeric(10, 2), nullable=False, default=0.00)


def seed_db():
    if not User.query.filter_by(username="admin").first():
        db.session.add(
            User(
                username="admin",
                password_hash=generate_password_hash("admin123"),
                role="admin",
            )
        )

    if not User.query.filter_by(username="staff").first():
        db.session.add(
            User(
                username="staff",
                password_hash=generate_password_hash("staff123"),
                role="staff",
            )
        )

    if Product.query.count() == 0:
        seed_massive_data()

    db.session.commit()


# Create app instance at module level for Vercel
app = create_app()

if __name__ == "__main__":
    with app.app_context():
        db.drop_all()
        db.create_all()
        seed_db()
    app.run(debug=True)
