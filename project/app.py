from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__)
app.secret_key = "your_secret_key"

# Configure the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database model for users
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Translation and audio data
translations = {
    "hello": {"bemba": "muli shani", "tonga": "mwali biiha", "nyanja": "muli bwanji"},
    "thank you": {"bemba": "natotela", "tonga": "twalumba", "nyanja": "zikomo"},
    "good morning": {"bemba": "mwashibukeni", "tonga": "mwabukabuuti", "nyanja": "mwauka bwanji"},
}
audio_files = {
    "hello": {
        "bemba": "static/audio/hello_bemba.aac",
        "tonga": "static/audio/hello_tonga.aac",
        "nyanja": "static/audio/hello_nyanja.aac"
    },
    "thank you": {
        "bemba": "static/audio/thank_you_bemba.aac",
        "tonga": "static/audio/thank_you_tonga.aac",
        "nyanja": "static/audio/thank_you_nyanja.aac"
    },
    "good morning": {
        "bemba": "static/audio/good_morning_bemba.aac",
        "tonga": "static/audio/good_morning_tonga.aac",
        "nyanja": "static/audio/good_morning_nyanja.aac"
    },
}

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Check if the user exists in the database
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('translate'))
        else:
            flash('Invalid credentials! Please try again.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Check if the username is already registered
        if User.query.filter_by(username=username).first():
            flash('Username already exists! Please choose another.', 'warning')
            return redirect(url_for('register'))
        try:
            # Save the user in the database with a hashed password
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('An error occurred during registration. Please try again.', 'danger')
    return render_template('register.html')

@app.route('/translate', methods=['GET', 'POST'])
def translate():
    if 'user_id' not in session:
        flash('Please log in to access the translation feature.', 'warning')
        return redirect(url_for('login'))

    translation = None
    audio_path = None

    if request.method == 'POST':
        phrase = request.form['phrase'].lower()
        language = request.form['language'].lower()
        translation = translations.get(phrase, {}).get(language, "Translation not found.")
        audio_path = audio_files.get(phrase, {}).get(language)

    return render_template('translate.html', translation=translation, audio_path=audio_path)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# Initialize the database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
