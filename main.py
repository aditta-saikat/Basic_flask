from flask import Flask, render_template, flash, url_for,redirect, session, request
from forms import LoginForm, ResetPasswordRequestForm, ResetPasswordForm
from flask_sqlalchemy import SQLAlchemy  
from sqlalchemy import select
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms.validators import ValidationError, InputRequired, DataRequired, Email
from wtforms import StringField , PasswordField, BooleanField, SubmitField
from flask_bcrypt import Bcrypt 
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_bootstrap import Bootstrap
#from email import send_password_reset_email
import jwt
from time import time


app = Flask(__name__)
app.config['SECRET_KEY'] = 'abc'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['ADMINS'] = ['adittasaikat007@gmail.com']


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
mail = Mail(app)
bootstrap = Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def send_email(subject, sender, recipients, text_body, html_body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    mail.send(msg)


def send_password_reset_email(user):
    token = user.get_reset_password_token()
    send_email('[Microblog] Reset Your Password',
               sender=app.config['ADMINS'][0],
               recipients=[user],
               text_body=render_template('email/reset_password.txt',
                                         user=user, token=token),
               html_body=render_template('email/reset_password.html',
                                         user=user, token=token))

class User(db.Model , UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    email = db.Column(db.String(100))
    password = db.Column(db.String(100))

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return db.session.get(User, id)

class RegisterForm(FlaskForm):
    username = StringField('Username' , validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Register')

    def validate_username(self, username):
        ex_username = User.query.filter_by(username=username.data).first()
        if ex_username:
            raise ValidationError("The username already exists!")
        

@app.route('/view')
@login_required
def view():
    return render_template("view.html" , values =  User.query.all())

@app.route('/logout' , methods=['GET' , 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@app.route('/index')
def index():
    user = {'username': 'Saikat'}
    posts = [
        {
            'author': {'username': 'John'},
            'body': 'Beautiful day in Portland!'
        },
        {
            'author': {'username': 'Susan'},
            'body': 'The Avengers movie was so cool!'
        }
    ]
    return render_template('index.html', title='Home', user=user, posts=posts)



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember_me.data)
                
                flash(f"Logged in successfully as {form.username.data}.")
                return redirect(url_for('view'))  
            else:
                flash("Incorrect password. Please try again.", 'error')
        else:
            flash("User not found. Please check your username.", 'error')

    return render_template('login.html', title='Sign In', form=form)
    
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
       
        data = User(username,email, hashed_password)
            
        db.session.add(data)
        db.session.commit()
        
        flash(f"The data for {username}  has been submitted.")
        return render_template('view.html' , values =  User.query.all())
    return render_template('signup.html', title='Sign Up', form=form)

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html',
                           title='Reset Password', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)


if __name__ == "__main__":
    app.run(debug=True)