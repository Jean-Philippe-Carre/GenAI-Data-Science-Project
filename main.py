from flask import Flask, render_template, url_for, redirect, request, jsonify, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField
from wtforms.validators import DataRequired, Email, EqualTo
import os
# import psycopg2

app = Flask(__name__)

# just a dummy secret key for the purpose of the project
app.config["SECRET_KEY"] = "secretkey"

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://neondb_owner:0WIlP3LywShn@ep-jolly-water-a5ljxiuc.us-east-2.aws.neon.tech/neondb?sslmode=require"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

UPLOAD_FOLDER = 'Images/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


class Users(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    email = db.Column(db.String)
    password = db.Column(db.String)


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[
                        DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Confirm Password', validators=[
                              DataRequired(), EqualTo('password', message='Passwords must match')])


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])


with app.app_context():
    db.create_all()


@app.route('/')
@app.route('/home')
def index():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        hashed_password = generate_password_hash(password)

        existing_user = Users.query.filter_by(email=email).first()
        if existing_user:
            form.email.errors.append("Email is already registered!")
            return render_template("register.html", form=form)

        new_user = Users(username=username, email=email,
                         password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return render_template("eda.html")

    # Render the form with validation errors (if any)
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = Users.query.filter_by(email=email).first()

        if not user:
            form.email.errors.append("Invalid email!")
            return render_template("login.html", form=form)

        if not check_password_hash(user.password, password):
            form.password.errors.append("Invalid password!")
            return render_template("login.html", form=form)

         # Create a session for the logged-in user
        session['logged_in'] = True
        session['user_id'] = user.user_id  # Store the user's ID in the session
        # Optionally store the username for display
        session['username'] = user.username

        return redirect(url_for("eda"))

    return render_template("login.html", form=form)


@app.route('/eda')
def eda():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('eda.html')


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)

    return redirect(url_for('index'))


if __name__ == "__main__":
    app.run(debug=True)
