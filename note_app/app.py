from flask import Flask, render_template, url_for, redirect, session, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func, desc
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
from datetime import timedelta, datetime

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
    
class Login_log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.DateTime, default=func.now())
    was_successful = db.Column(db.Boolean, nullable=False)
    info = db.Column(db.String(200), nullable=False)
    
def log(user_id, was_successful, info):
    login = Login_log(  user_id = user_id,
                        was_successful = was_successful,
                        info = info)
    db.session.add(login)
    db.session.commit()
    

with app.app_context():
    db.create_all()
   
    

class RegisterForm(FlaskForm):
    username = StringField( validators=[InputRequired(), Regexp('^[a-zA-ZąćęłńóśźżĄĆĘŁŃÓŚŹŻ0-9_-]{2,30}$', message="Nazwa użytkownika zawiera niedozwolone symbole"), Length(min=3, max=30)],render_kw={"placeholder": "Nazwa użytkownika"})
    password = PasswordField( validators=[InputRequired(), Length(min=3, max=30)], render_kw={"placeholder": "Hasło", "oninput":"passwordStrength(this.value)"})
    email = EmailField( validators=[InputRequired(), Length(max=256)],render_kw={"placeholder": "Email"})
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
    username = StringField(validators=[InputRequired(), Length(min=1, max=30)], render_kw={"placeholder": "Nazwa użytkownika"})
    password = PasswordField(validators=[InputRequired(), Length(min=1, max=30)], render_kw={"placeholder": "Hasło"})
    submit = SubmitField('Login')
    

class AuthenticationForm(FlaskForm):
    code = StringField(validators=[InputRequired(), Regexp('^[0-9]{6,6}$')],render_kw={"placeholder": "6-cyfrowy kod"})
    submit = SubmitField('Login')
    

class NoteCreateForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(max=30),  Regexp('^[a-zA-ZąćęłńóśźżĄĆĘŁŃÓŚŹŻ0-9_\- ]{1,30}$', message="Nazwa notatki zawiera niedozwolone symbole") ], render_kw={"placeholder": "Nazwa twojej notatki"})
    content = TextAreaField(render_kw={"placeholder": "Tu napisz swoją notatkę", "rows":"30", "cols":"100"})
    password = PasswordField(validators=[Length(max=30)],render_kw={"placeholder": "Hasło"})
    submit = SubmitField('Zapisz')
    
class NoteDecryptForm(FlaskForm):
    password = PasswordField(validators=[Length(max=30)],render_kw={"placeholder": "Hasło"})
    submit = SubmitField('Kontynuuj')

class ShareNoteForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(max=30)], render_kw={"placeholder": "Nazwa użytkownika"})
    submit = SubmitField('Udostępnij')
    
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if not existing_user_username:
            raise ValidationError(f"Wybrany użytkownik nie istnieje")




@app.route('/')
def home():
    public_notes = db.session.query(Note.id, Note.name, User.username).join(User, User.id == Note.owner_id).filter(Note.is_public == True).all()
    #print(public_notes)
    
    if current_user.is_authenticated:
        return render_template('home.html', notes = public_notes, logged = True, username = escape(current_user.username))
    else:
        return render_template('home.html', notes = public_notes)
    
    
    
@app.route('/render/<note_id>')
def render_public(note_id):
    note = Note.query.filter_by(id=note_id).first()

    if note is None:
        return 'Notatka nie istnieje', 404
    
    if not note.is_public:
        return 'Brak dostępu do notatki', 403
    
    if current_user.is_authenticated:
        return render_template('public_notes_render.html', name = note.name, content = note.note, logged = True, username = escape(current_user.username) )
    else:
        return render_template('public_notes_render.html', name = note.name, content = note.note)
    
    
  

@app.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm()
    
    if form.validate_on_submit():
        sleep(1)
        user = User.query.filter_by(username=form.username.data).first()
        if user:

            # if more then 5 unsuccessful login atempts in the last 2 minutes
            two_minutes_ago = datetime.utcnow() - timedelta(minutes=2)
            locked = Login_log.query.filter(Login_log.user_id == user.id, Login_log.was_successful == False, Login_log.date > two_minutes_ago).count() > 5
            if locked:
                return render_template('login.html', form = form, msg="Zbyt dużo nieudanych prób logowania. Spróbuj ponownie za jakiś czas")
            
            salt = user.salt
            if bcrypt.check_password_hash(user.password, salt + bytes( form.password.data.encode())):
                
                session['potential_user_id'] = user.id
                return redirect(url_for('authenticate'))
            
            log(user.id, False, request.remote_addr)
                        
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
        totp = pyotp.TOTP(user_totp_secret)
        
        if totp.verify(form.code.data):
            login_user(user)
            log(user.id, True, request.remote_addr)
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
        
        uri = pyotp.TOTP(totp_secret).provisioning_uri(name=form.username.data, issuer_name="Bezpieczne notatki")
        
        return render_template('register_totp.html', uri=uri, totp_key = totp_secret.decode("utf-8"))
    
    return render_template('register.html', form = form, msg = list(form.errors.values()))



@app.route('/my_notes')
@login_required
def my_notes():
    my_notes = Note.query.with_entities(Note.id, Note.name, Note.is_encrypted, Note.is_public).filter_by(owner_id=current_user.id).all()
    notes_shared_to_me = db.session.query( User.username, Note.id, Note.name).join(User, User.id == Note.owner_id).join(Note_share, Note_share.note_id == Note.id).filter(Note_share.user_id == current_user.id).all()
    login_log = db.session.query(Login_log.date, Login_log.was_successful, Login_log.info).filter(Login_log.user_id == current_user.id).order_by(desc(Login_log.date)).limit(20).all()
    
    return render_template('my_notes.html',
                           name = current_user.username,
                           notes = my_notes,
                           shared_notes = notes_shared_to_me,
                           login_log = login_log)



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
            rendered = cipher.encrypt( pad(bytes(rendered.encode()), AES.block_size) )
        
        note = Note(name = escape(form.name.data),
                    note = rendered,
                    owner_id = current_user.id,
                    is_encrypted = encrypted,
                    is_public = False)
        
        db.session.add(note)
        db.session.commit()
        return redirect(url_for('my_notes'))
    
    return render_template('note_create.html', form=form, msg =  list(form.errors.values()))



@app.route('/my_notes/render/<note_id>', methods=['GET', 'POST'])
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
                note.note = decrypted.decode("utf-8")
            except ValueError:
                return 'Błędne hasło', 403
            
            return render_template('my_notes_render.html',
                                   note=note,
                                   username = escape(current_user.username))
            
        return redirect ('/my_notes/decrypt/' + note_id)
    
    form = ShareNoteForm()
    if form.validate_on_submit():
        target_user = User.query.filter_by(username=form.username.data).first()
        new_note_share = Note_share(note_id = note_id,
                                    user_id = target_user.id)
        
        db.session.add(new_note_share)
        db.session.commit()
    
    shared_users = db.session.query(User.username).join(Note_share, User.id == Note_share.user_id).filter(Note_share.note_id == note_id).all()
    return render_template('my_notes_render.html',
                           note = note,
                           username = escape(current_user.username),
                           shareable = True,
                           shared_users = shared_users,
                           msg=list(form.errors.values()),
                           form=form)



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



@app.route('/my_notes/make_public/<note_id>', methods=['GET', 'POST'])
@login_required
def make_note_public(note_id):
    note = Note.query.filter_by(id=note_id).first()

    if note is None:
        return 'Notatka nie istnieje', 404
    
    if note.owner_id != current_user.id:
        return 'Brak dostępu do notatki', 403
    
    if note.is_encrypted:
        return 'Nie można upublicznić zaszyfrowanej notatki', 405
    
    note.is_public = True
    db.session.commit()
    return redirect(url_for('my_notes'))



@app.route('/my_notes/make_private/<note_id>', methods=['GET', 'POST'])
@login_required
def make_note_private(note_id):
    note = Note.query.filter_by(id=note_id).first()

    if note is None:
        return 'Notatka nie istnieje', 404
    
    if note.owner_id != current_user.id:
        return 'Brak dostępu do notatki', 403
    
    note.is_public = False
    db.session.commit()
    return redirect(url_for('my_notes'))



@app.route('/my_notes/shared/render/<note_id>', methods=['GET', 'POST'])
@login_required
def render_shared_note(note_id):
    note = Note.query.filter_by(id=note_id).first()
    is_shared = Note_share.query.filter_by(note_id=note_id, user_id=current_user.id).first() is not None

    if note is None:
        return 'Notatka nie istnieje', 404
    
    if not is_shared:
        return 'Brak dostępu do notatki', 403
    
    return render_template('my_notes_render.html',
                                   note=note,
                                   username = escape(current_user.username))
    
    
    
@app.route('/my_notes/remove_share/<note_id>', methods=['GET', 'POST'])
@login_required
def remove_share(note_id):
    note = Note.query.filter_by(id=note_id).first()
    is_shared = Note_share.query.filter_by(note_id=note_id, user_id=current_user.id).first() is not None

    if note is None:
        return 'Notatka nie istnieje', 404
    
    if note.owner_id != current_user.id:
        return 'Brak dostępu do notatki', 403
    
    shares = Note_share.query.filter_by(note_id=note_id).all()
    for share in shares:
        db.session.delete(share)
    db.session.commit()
    return redirect ('/my_notes/render/' + note_id)


    
if __name__=='__main__':
    app.run()