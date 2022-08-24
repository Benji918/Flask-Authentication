from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_wtf.csrf import CSRFProtect
import os


app = Flask(__name__)

csrf = CSRFProtect(app)
csrf.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# user to gert the id of the currently logged in user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


app.config['SECRET_KEY'] = os.urandom(25)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


# Line below only required once, when creating DB.
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        new_user = User(
            name=request.form.get('name'),
            email=request.form.get('email'),
            password=generate_password_hash(password=request.form.get('password'), method='pbkdf2:sha256',
                                            salt_length=16)
        )
        db.session.add(new_user)
        db.session.commit()

        # Log in and authenticate user after adding details to database.
        login_user(new_user)
        return render_template("secrets.html", user=new_user.name)
    return render_template("register.html")


@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == 'POST':
        # login code goes here
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        # check if the user actually exists
        # take the user-supplied password, hash it, and compare it to the hashed password in the database
        if not user:
            flash('Email does not exist!', 'error')
            return redirect(url_for('login'))  # if the user doesn't exist or password is wrong, reload the page
        elif not check_password_hash(user.password, password):
            flash('Password is incorrect. Try again!', 'error')
            return redirect(url_for('login'))  # if the user doesn't exist or password is wrong, reload the page
        login_user(user)
        return render_template('secrets.html', user=user.name)
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    if current_user.is_authenticated:
        return send_from_directory('static/files', 'cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
