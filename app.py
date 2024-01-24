from flask import Flask, render_template, url_for, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, TextAreaField
from wtforms.validators import InputRequired, Length, ValidationError, Regexp
from flask_bcrypt import Bcrypt
from os import urandom
from Crypto.Cipher import AES
import pyotp
import markdown
from html import escape
from time import sleep
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = b"\xf7'J\xf3\x99a\xa8\xd9\xf0\xe2\x0b\xae\x14\xbd\xed\xc9\x9e|\x9f\x8a[\x85h\xa5"
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

TOTP_encryption_key = b"\x88\x95\x10\xee\x8dG!\xf9\x18\x1f\x860B\xabg'"
TOTP_iv=b'\x06\x17\xca=G\x97g95\x00\x95P\t\x85\xdb\x87'
note_encryption_iv = b'\xbd\xd6\xbfb\xc3\xe3\x98s\x86\xb7:\xdb\x90\x06/\xcc'

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
    
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    note = db.Column(db.Text, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_encrypted = db.Column(db.Boolean, nullable=False)
    is_public = db.Column(db.Boolean, nullable=False)
    
class Note_share(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    

with app.app_context():
    db.create_all()
   
    

class RegisterForm(FlaskForm):
    username = StringField( validators=[InputRequired(), Length(min=3, max=30)],
                            render_kw={"placeholder": "Nazwa użytkownika"})
    
    password = PasswordField(   validators=[InputRequired(), Length(min=3, max=30)],
                                render_kw={"placeholder": "Hasło", "oninput":"passwordStrength(this.value)"})
    
    email = EmailField( validators=[InputRequired(), Length(max=256)],
                        render_kw={"placeholder": "Email"})
    
    submit = SubmitField('Rejestracja')
    
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError(f"Wybrana nazwa użtykownika jest już zajęta")
    
    def validate_email(self, email):
        existing_user_email = User.query.filter_by( email=email.data).first()
        if existing_user_email:
            raise ValidationError( f"Wybrany adres email jest już zajęty")
        
           
       
            
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=1, max=30)],
                           render_kw={"placeholder": "Nazwa użytkownika"})

    password = PasswordField(validators=[InputRequired(), Length(min=1, max=30)],
                             render_kw={"placeholder": "Hasło"})

    submit = SubmitField('Login')
    


class AuthenticationForm(FlaskForm):
    code = StringField(validators=[InputRequired(), Regexp('^[0-9]{1,6}$')],
                       render_kw={"placeholder": "6-cyfrowy kod"})
    
    submit = SubmitField('Login')
    

class NoteCreateForm(FlaskForm):
    name = StringField(validators=[InputRequired()], render_kw={"placeholder": "Nazwa twojej notatki"})
    content = TextAreaField(render_kw={"placeholder": "Tu napisz swoją notatkę", "rows":"30", "cols":"100"})
    password = PasswordField(validators=[Length(max=30)],render_kw={"placeholder": "Hasło"})
    submit = SubmitField('Zapisz')
    
class NoteDecryptForm(FlaskForm):
    password = PasswordField(validators=[Length(max=30)],render_kw={"placeholder": "Hasło"})
    submit = SubmitField('Kontynuuj')




@app.route('/')
def home():
    if current_user.is_authenticated:
        return render_template('home_logged_user.html', name = escape(current_user.username))
    else:
        return render_template('home.html')
    
  

@app.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm()
    
    if form.validate_on_submit():
        sleep(1)
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
        
        return render_template('register_totp.html', uri=uri, totp_key = totp_secret.decode("utf-8"))
    
    
    msg = []
    for field, err_msg in form.errors.items():
        msg.append(err_msg[0])
    return render_template('register.html', form = form, msg = list(form.errors.values()))


@app.route('/my_notes')
@login_required
def my_notes():
    notes = Note.query.with_entities(Note.id, Note.name, Note.is_encrypted).filter_by(owner_id=current_user.id).all()
    
    
    return render_template('my_notes.html', name = escape(current_user.username), notes = notes)


@app.route('/my_notes/creator', methods=['GET', 'POST'])
@login_required
def note_create():
    form = NoteCreateForm()
    
    if form.validate_on_submit():
        rendered = markdown.markdown(form.content.data)
        encrypted = False
        
        if len(form.password.data) > 0:
            encrypted = True
            h = SHA256.new()
            h.update(bytes(form.password.data.encode()))
            pass_hash = h.digest()
            cipher = AES.new(pass_hash, AES.MODE_CBC, note_encryption_iv)
            #print(rendered)
            rendered = cipher.encrypt( pad(bytes(rendered.encode()), AES.block_size) )
            #print(rendered)
            #print(rendered.hex())
        
        note = Note(name = escape(form.name.data),
                    note = rendered,
                    owner_id = current_user.id,
                    is_encrypted = encrypted,
                    is_public = False)
        
        db.session.add(note)
        db.session.commit()
        return redirect(url_for('my_notes'))
    
    return render_template('note_create.html', form=form)

@app.route('/my_notes/render/<note_id>')
@login_required
def my_note_render(note_id):
    note = Note.query.filter_by(id=note_id).first()
    
    if note is None:
        return 'Notatka nie istnieje', 404
    
    if note.owner_id != current_user.id:
        return 'Brak dostępu do notatki', 403
    
    if note.is_encrypted:
        if 'decrypted_note_password' in session:
            sleep(1)
            password = session['decrypted_note_password']
            session.pop('decrypted_note_password', None)
            h = SHA256.new()
            h.update(password)
            pass_hash = h.digest()
            try:
                cipher = AES.new(pass_hash, AES.MODE_CBC, note_encryption_iv)
                decrypted = cipher.decrypt( bytes(note.note))
                decrypted = unpad(decrypted, AES.block_size)
            except ValueError:
                return 'Błędne hasło', 403
            
            return render_template('my_notes_render.html', name=note.name, content=decrypted.decode("utf-8") )
            
        return redirect ('/my_notes/decrypt/' + note_id)
    
    return render_template('my_notes_render.html', name=note.name, content=note.note)

@app.route('/my_notes/decrypt/<note_id>', methods=['GET', 'POST'])
@login_required
def note_decrypt(note_id):
    note = Note.query.filter_by(id=note_id).first()
    
    if note is None:
        return 'Notatka nie istnieje', 404
    
    if note.owner_id != current_user.id:
        return 'Brak dostępu do notatki', 403
    
    if not note.is_encrypted:
        return redirect (url_for('my_note_render'), note_id=note_id)
    
    form = NoteDecryptForm()
    
    if form.validate_on_submit():
        session['decrypted_note_password'] = bytes(form.password.data.encode())
        return redirect ('/my_notes/render/' + note_id)       
    
    return render_template('note_decrypt.html', form=form)

if __name__=='__main__':
    app.run()