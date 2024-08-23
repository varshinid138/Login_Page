from flask import Flask, render_template, redirect, request, url_for, flash
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_required, login_user, current_user, logout_user
from wtforms import StringField, PasswordField, BooleanField, SubmitField,SelectField
from wtforms.validators import InputRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash

import os

dbdir = "sqlite:///" + os.path.abspath(os.getcwd()) + "/database1.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = "SomeSecret"
app.config["SQLALCHEMY_DATABASE_URI"] = dbdir
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"



class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    usertype = db.Column(db.String(50), nullable=False)
    

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=5, max=50)])
    email = StringField("Email", validators=[InputRequired(), Length(min=5, max=50)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=6, max=80)])
    usertype = SelectField("User Type", 
                           choices=[('superuser', 'Superuser'), 
                                    ('admin', 'Admin'), 
                                    ('user', 'User')],
                           validators=[InputRequired()])
    submit = SubmitField("Sign Up")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=5, max=50)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=6, max=80)])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Log In")

@app.route("/")

def index():
    return render_template("index.html")


@app.route("/login" , methods=["GET", "POST"])
def login():
    form=LoginForm()

    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()

        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember)

            username=user.username
             
            if user.usertype=="superuser":
                return render_template("superuser.html",username=username)
            
            elif user.usertype=="admin":
                return render_template("admin.html",username=username)
            else:
                return render_template("user.html",username=username)
            
        return "Your credentials are invalid."
    return render_template("login.html", form=form)

@app.route("/user_signup", methods=["GET", "POST"])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        new_user = Users(username=form.username.data, email=form.email.data, password=hashed_pw, usertype=form.usertype.data)
        db.session.add(new_user)
        db.session.commit()
        flash("You've been registered successfully, now you can log in.")
        return redirect(url_for("login"))
    return render_template("signup.html", form=form)

@app.route("/create_adm",methods=["GET","POST"])
def create_adm():
    form=RegisterForm()
    if form.validate_on_submit():
        existing_user=Users.query.filter_by(email=form.email.data).first()
        hashed_pw=generate_password_hash(form.password.data)
        new_user=Users(username=form.username.data,email=form.email.data, password=hashed_pw, usertype=form.usertype.data,)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))
    return render_template("adminform.html",form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You were logged out. See you soon!")
    return redirect(url_for("login"))

if __name__ == "__main__":
    
    with app.app_context():
        db.create_all()
        app.run(debug=True)