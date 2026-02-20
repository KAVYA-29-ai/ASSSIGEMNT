from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import os

app = Flask(__name__)

# Fix for Render's PostgreSQL URL format
database_url = os.environ.get("DATABASE_URL", "sqlite:///database.db")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
app.secret_key = os.environ.get("SECRET_KEY", 'secret_key')

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100), nullable = False)
    email = db.Column(db.String(100), unique = True)
    password = db.Column(db.String(100))
    
    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))

with app.app_context():
    db.create_all()
    
    
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        # Validate empty fields
        if not name or not email or not password:
            return render_template('register.html', error='All fields are required')
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return render_template('register.html', error='Email already registered')
        
        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')
    
    return render_template("register.html")

@app.route("/login", methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        # Validate empty fields
        if not email or not password:
            return render_template('login.html', error='All fields are required')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            session['email'] = user.email
            return redirect('/dashboard')
        else:
            return render_template('login.html', error='Invalid email or password')
        
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        return render_template("dashboard.html", user=user)
    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('email',None)
    return redirect('/login') 



if __name__ == '__main__':
    app.run(debug=True)
