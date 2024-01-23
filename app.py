from flask import Flask, render_template, url_for, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, DecimalField
from wtforms.validators import InputRequired, Length, ValidationError, Regexp
from flask_bcrypt import Bcrypt
from os import urandom
from Crypto.Cipher import AES
import pyotp
from time import sleep
#import sqlite3

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = b"\xf7'J\xf3\x99a\xa8\xd9\xf0\xe2\x0b\xae\x14\xbd\xed\xc9\x9e|\x9f\x8a[\x85h\xa5"
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

TOTP_encryption_key = b"\x88\x95\x10\xee\x8dG!\xf9\x18\x1f\x860B\xabg'"
TOTP_iv=b'\x06\x17\xca=G\x97g95\x00\x95P\t\x85\xdb\x87'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    email = db.Column(db.String(256), nullable=False)
    salt = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    TOTP_secret = db.Column(db.String(160), nullable=False)
    
    
    


with app.app_context():
    db.create_all()
    

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(),
                           Length(min=3, max=30)],
                           render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(),
                             Length(min=3, max=30)],
                             render_kw={"placeholder": "Password"})
    
    email = EmailField(validators=[InputRequired(),
                             Length(max=256)],
                             render_kw={"placeholder": "Email"})

    submit = SubmitField('Rejestracja')
    
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                f'Nazwa użytkownika {username.data} jest już zajęta!')
    
    def validate_email(self, email):
        existing_user_email = User.query.filter_by( email=email.data).first()
        if existing_user_email:
            raise ValidationError( "email already in use")
        
           
       
            
class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=1, max=30)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=1, max=30)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

class AuthenticationForm(FlaskForm):
    code = StringField(validators=[
                           InputRequired(), Regexp('^[0-9]{1,6}$', message='Niepoprawny kod')], render_kw={"placeholder": "Code"})
    
    submit = SubmitField('Login')




@app.route('/')
def home():
    if current_user.is_authenticated:
        return render_template('home_logged_user.html', name = current_user.username)
    else:
        return render_template('home.html')
    
  

@app.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            print('użtykownik istnieje')
            salt = user.salt
            if bcrypt.check_password_hash(user.password, salt + bytes( form.password.data.encode())):
                session['potential_user_id'] = user.id
                print('poprawne hslo')

                
                return redirect(url_for('authenticate'))
        return render_template('login.html', form = form, msg="Błędny login lub hasło")
    
    return render_template('login.html', form = form)

@app.route('/login/authenticate', methods=['GET', 'POST'])
def authenticate():
    if 'potential_user_id' not in session:
        return redirect(url_for('login'))

    form = AuthenticationForm()
    user = User.query.get(int(session.get('potential_user_id', None)))
    msg =''
    if form.validate_on_submit():
        cipher = AES.new(TOTP_encryption_key, AES.MODE_CBC, TOTP_iv)
        user_totp_secret = cipher.decrypt(user.TOTP_secret)
        
        print(user_totp_secret)
        totp = pyotp.TOTP(user_totp_secret)
        print(totp.now())
        if totp.verify(form.code.data):
            login_user(user)
            session.pop('potential_user_id', None)
            
            return redirect(url_for('home'))
        msg='Niepoprawny kod'
    
    return render_template('authenticate.html',  form = form, msg = msg)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        salt = urandom(32)
        salted_password = salt + bytes( form.password.data.encode())
        hashed_password = bcrypt.generate_password_hash(salted_password,10)
        
        cipher = AES.new(TOTP_encryption_key, AES.MODE_CBC, TOTP_iv)
        totp_secret = bytes( pyotp.random_base32().encode())
        
        new_user = User(username=form.username.data,
                        email=form.email.data,
                        salt=salt,
                        password=hashed_password,
                        TOTP_secret = cipher.encrypt(totp_secret)
                        )
        
        db.session.add(new_user)
        db.session.commit()
        
        uri = pyotp.TOTP(totp_secret).provisioning_uri(name=form.username.data,
                                                            issuer_name="Bezpieczne notatki")
        
        return render_template('register_totp.html', uri=uri)
    
    return render_template('register.html', form = form)


@app.route('/my_notes')
@login_required
def my_notes():
    return render_template('my_notes.html', name = current_user.username)




if __name__=='__main__':
    app.run()