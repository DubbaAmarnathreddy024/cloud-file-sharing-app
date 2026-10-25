"""Cloud File-Sharing App: Flask, SQLite, Fernet-encrypted local storage."""
from __future__ import annotations
import hashlib, hmac, os, secrets, sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from functools import wraps

from cryptography.fernet import Fernet, InvalidToken
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_file, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from io import BytesIO

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = Path(os.environ.get('CLOUDSHARE_INSTANCE_DIR', BASE_DIR / 'instance')).resolve()
STORAGE_DIR = Path(os.environ.get('CLOUDSHARE_STORAGE_DIR', BASE_DIR / 'storage')).resolve()
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.environ.get('CLOUDSHARE_DB_PATH', INSTANCE_DIR / 'cloudshare.sqlite3')).resolve()
KEY_PATH = INSTANCE_DIR / 'fernet.key'


def load_fernet() -> Fernet:
    env_key = os.environ.get('FERNET_KEY')
    if env_key:
        key = env_key.encode()
    elif KEY_PATH.exists():
        key = KEY_PATH.read_bytes().strip()
    else:
        key = Fernet.generate_key()
        KEY_PATH.write_bytes(key + b'\n')
        try: KEY_PATH.chmod(0o600)
        except OSError: pass
    return Fernet(key)

fernet = load_fernet()
app = Flask(__name__, instance_path=str(INSTANCE_DIR))
# A stable local fallback keeps sessions valid across Gunicorn workers/restarts.
def load_app_secret() -> str:
    configured = os.environ.get('FLASK_SECRET_KEY')
    if configured:
        return configured
    secret_file = INSTANCE_DIR / 'flask_secret.key'
    if secret_file.exists():
        return secret_file.read_text(encoding='utf-8').strip()
    value = secrets.token_hex(32)
    secret_file.write_text(value, encoding='utf-8')
    try: secret_file.chmod(0o600)
    except OSError: pass
    return value

app.config.update(
    SECRET_KEY=load_app_secret(),
    MAX_CONTENT_LENGTH=int(os.environ.get('MAX_UPLOAD_MB', '25')) * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE', '0') == '1',
)
ALLOWED_EXTENSIONS = {x.strip().lower().lstrip('.') for x in os.environ.get('ALLOWED_EXTENSIONS', '').split(',') if x.strip()}


def utcnow():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=20)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys=ON')
        g.db.execute('PRAGMA journal_mode=WAL')
    return g.db

@app.teardown_appcontext
def close_db(_error=None):
    conn = g.pop('db', None)
    if conn is not None: conn.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('PRAGMA foreign_keys=ON')
    conn.executescript('''
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL COLLATE NOCASE UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS files (
      id TEXT PRIMARY KEY,
      owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      original_name TEXT NOT NULL,
      storage_name TEXT NOT NULL UNIQUE,
      sha256 TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      uploaded_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS shares (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
      owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL,
      UNIQUE(file_id, recipient_id)
    );
    CREATE TABLE IF NOT EXISTS share_links (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
      owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TEXT,
      revoked INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id);
    CREATE INDEX IF NOT EXISTS idx_shares_recipient ON shares(recipient_id);
    ''')
    # Import old starter-project users/files metadata if the old database is present.
    old_db = BASE_DIR / 'secure_storage.db'
    if old_db.exists():
        try:
            old = sqlite3.connect(old_db); old.row_factory = sqlite3.Row
            names = {r['name'] for r in old.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if 'users' in names:
                for row in old.execute('SELECT username,password FROM users'):
                    conn.execute('INSERT OR IGNORE INTO users(username,password_hash,created_at) VALUES(?,?,?)',
                                 (row['username'], row['password'] if str(row['password']).startswith(('scrypt:', 'pbkdf2:')) else generate_password_hash(str(row['password'])), utcnow()))
            conn.commit(); old.close()
        except Exception:
            pass
    conn.commit(); conn.close()

init_db()

@app.before_request
def csrf_guard():
    if request.method == 'POST':
        submitted = request.form.get('_csrf_token', '')
        expected = session.get('_csrf_token', '')
        if not expected or not hmac.compare_digest(submitted, expected):
            abort(400, description='Invalid or missing CSRF token. Refresh the page and try again.')

@app.context_processor
def inject_globals():
    if '_csrf_token' not in session: session['_csrf_token'] = secrets.token_urlsafe(32)
    return {'csrf_token': session['_csrf_token'], 'current_user': session.get('username')}

@app.errorhandler(413)
def too_large(_error):
    flash(f'File is too large. Maximum upload size is {app.config["MAX_CONTENT_LENGTH"] // (1024*1024)} MB.', 'error')
    return redirect(url_for('upload'))

@app.errorhandler(400)
def bad_request(error):
    return render_template('error.html', code=400, message=getattr(error, 'description', 'Bad request')), 400

@app.errorhandler(404)
def not_found(_error):
    return render_template('error.html', code=404, message='The requested page or file was not found.'), 404


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please log in to continue.', 'error')
            return redirect(url_for('login', next=request.path))
        return fn(*args, **kwargs)
    return wrapper


def owned_or_shared(file_id, user_id):
    return db().execute('''SELECT f.*,u.username AS owner_name FROM files f JOIN users u ON u.id=f.owner_id
      WHERE f.id=? AND (f.owner_id=? OR EXISTS (SELECT 1 FROM shares s WHERE s.file_id=f.id AND s.recipient_id=?))''',
      (file_id, user_id, user_id)).fetchone()


def storage_path(storage_name):
    path = (STORAGE_DIR / storage_name).resolve()
    if path.parent != STORAGE_DIR.resolve(): abort(404)
    return path

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        if not 3 <= len(username) <= 32 or not all(c.isalnum() or c in '._-' for c in username):
            flash('Username must be 3–32 characters using letters, numbers, dot, underscore or hyphen.', 'error')
        elif len(password) < 10:
            flash('Use a password with at least 10 characters.', 'error')
        else:
            try:
                cur = db().execute('INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)',
                                   (username, generate_password_hash(password), utcnow()))
                db().commit()
                flash('Account created. Please log in.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('That username is already taken.', 'error')
    return render_template('signup.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        user = db().execute('SELECT * FROM users WHERE username=? COLLATE NOCASE', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session.clear(); session['user_id'] = user['id']; session['username'] = user['username']; session['_csrf_token'] = secrets.token_urlsafe(32)
            target = request.args.get('next', '')
            if not target.startswith('/') or target.startswith('//'): target = url_for('dashboard')
            return redirect(target)
        flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.post('/logout')
def logout():
    session.clear(); flash('You have been logged out.', 'success'); return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = db(); uid = session['user_id']
    my_files = conn.execute('SELECT * FROM files WHERE owner_id=? ORDER BY uploaded_at DESC', (uid,)).fetchall()
    shared_files = conn.execute('''SELECT f.*,u.username AS owner_name,s.created_at AS shared_at FROM shares s JOIN files f ON f.id=s.file_id JOIN users u ON u.id=s.owner_id WHERE s.recipient_id=? ORDER BY s.created_at DESC''', (uid,)).fetchall()
    links = conn.execute('''SELECT sl.id,sl.file_id,sl.expires_at,sl.revoked,sl.created_at,f.original_name FROM share_links sl JOIN files f ON f.id=sl.file_id WHERE sl.owner_id=? ORDER BY sl.created_at DESC''', (uid,)).fetchall()
    return render_template('dashboard.html', files=my_files, shared_files=shared_files, links=links)

@app.route('/upload', methods=['GET','POST'])
@login_required
def upload():
    if request.method == 'POST':
        uploaded = request.files.get('file')
        if not uploaded or not uploaded.filename:
            flash('Choose a file first.', 'error'); return redirect(url_for('upload'))
        original_name = secure_filename(uploaded.filename)
        if not original_name:
            flash('That filename is not supported. Rename the file and try again.', 'error'); return redirect(url_for('upload'))
        if ALLOWED_EXTENSIONS and Path(original_name).suffix.lower().lstrip('.') not in ALLOWED_EXTENSIONS:
            flash('That file type is not allowed by server configuration.', 'error'); return redirect(url_for('upload'))
        data = uploaded.read(app.config['MAX_CONTENT_LENGTH'] + 1)
        if len(data) > app.config['MAX_CONTENT_LENGTH']:
            flash('File exceeds the maximum upload size.', 'error'); return redirect(url_for('upload'))
        file_id = secrets.token_hex(16); storage_name = secrets.token_hex(24) + '.enc'
        encrypted = fernet.encrypt(data)
        path = storage_path(storage_name)
        try:
            path.write_bytes(encrypted)
            db().execute('INSERT INTO files(id,owner_id,original_name,storage_name,sha256,size_bytes,uploaded_at) VALUES(?,?,?,?,?,?,?)',
                         (file_id, session['user_id'], original_name, storage_name, hashlib.sha256(data).hexdigest(), len(data), utcnow()))
            db().commit()
        except Exception:
            path.unlink(missing_ok=True); raise
        flash('File uploaded and encrypted successfully.', 'success'); return redirect(url_for('dashboard'))
    return render_template('upload.html')

@app.get('/download/<file_id>')
@login_required
def download(file_id):
    item = owned_or_shared(file_id, session['user_id'])
    if not item: abort(404)
    path = storage_path(item['storage_name'])
    try: data = fernet.decrypt(path.read_bytes())
    except (InvalidToken, OSError):
        flash('File decryption failed. Check that the original encryption key is available.', 'error'); return redirect(url_for('dashboard'))
    return send_file(BytesIO(data), as_attachment=True, download_name=item['original_name'], mimetype='application/octet-stream')

@app.post('/delete/<file_id>')
@login_required
def delete_file(file_id):
    item = db().execute('SELECT * FROM files WHERE id=? AND owner_id=?', (file_id, session['user_id'])).fetchone()
    if not item: abort(404)
    storage_path(item['storage_name']).unlink(missing_ok=True)
    db().execute('DELETE FROM files WHERE id=?', (file_id,)); db().commit()
    flash('File deleted. Any shares and links to it have also been removed.', 'success'); return redirect(url_for('dashboard'))

@app.get('/verify/<file_id>')
@login_required
def verify_file(file_id):
    item = owned_or_shared(file_id, session['user_id'])
    if not item: abort(404)
    try: data = fernet.decrypt(storage_path(item['storage_name']).read_bytes())
    except (InvalidToken, OSError):
        flash('Integrity check failed: the stored file could not be decrypted.', 'error'); return redirect(url_for('dashboard'))
    if hmac.compare_digest(hashlib.sha256(data).hexdigest(), item['sha256']): flash(f'Integrity verified for {item["original_name"]}.', 'success')
    else: flash(f'Integrity check FAILED for {item["original_name"]}.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/share/<file_id>', methods=['GET','POST'])
@login_required
def share_file(file_id):
    item = db().execute('SELECT * FROM files WHERE id=? AND owner_id=?', (file_id, session['user_id'])).fetchone()
    if not item: abort(404)
    if request.method == 'POST':
        recipient_name = request.form.get('username','').strip()
        recipient = db().execute('SELECT id,username FROM users WHERE username=? COLLATE NOCASE', (recipient_name,)).fetchone()
        if not recipient: flash('No registered user found with that username.', 'error')
        elif recipient['id'] == session['user_id']: flash('You already own this file.', 'error')
        else:
            db().execute('INSERT OR IGNORE INTO shares(file_id,owner_id,recipient_id,created_at) VALUES(?,?,?,?)', (file_id,session['user_id'],recipient['id'],utcnow())); db().commit()
            flash(f'Shared with {recipient["username"]}.', 'success'); return redirect(url_for('dashboard'))
    recipients = db().execute('SELECT s.id,u.username,s.created_at FROM shares s JOIN users u ON u.id=s.recipient_id WHERE s.file_id=? AND s.owner_id=? ORDER BY u.username', (file_id,session['user_id'])).fetchall()
    return render_template('share.html', item=item, recipients=recipients)

@app.post('/unshare/<int:share_id>')
@login_required
def unshare(share_id):
    cur = db().execute('DELETE FROM shares WHERE id=? AND owner_id=?', (share_id,session['user_id'])); db().commit()
    flash('Access removed.' if cur.rowcount else 'Share not found.', 'success' if cur.rowcount else 'error')
    return redirect(url_for('dashboard'))

@app.post('/share-link/<file_id>')
@login_required
def create_share_link(file_id):
    item = db().execute('SELECT id FROM files WHERE id=? AND owner_id=?', (file_id,session['user_id'])).fetchone()
    if not item: abort(404)
    token = secrets.token_urlsafe(32); token_hash = hashlib.sha256(token.encode()).hexdigest()
    expiry = (datetime.now(timezone.utc) + timedelta(days=7)).replace(microsecond=0).isoformat()
    db().execute('INSERT INTO share_links(file_id,owner_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)', (file_id,session['user_id'],token_hash,expiry,utcnow())); db().commit()
    share_url = url_for('public_share', token=token, _external=True)
    return render_template('link_created.html', share_url=share_url, item=db().execute('SELECT * FROM files WHERE id=?',(file_id,)).fetchone())

@app.get('/s/<token>')
def public_share(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    link = db().execute('''SELECT sl.*,f.original_name,f.storage_name,f.sha256 FROM share_links sl JOIN files f ON f.id=sl.file_id WHERE sl.token_hash=? AND sl.revoked=0''', (token_hash,)).fetchone()
    if not link or (link['expires_at'] and link['expires_at'] < utcnow()): abort(404)
    return render_template('public_share.html', link=link, token=token)

@app.post('/s/<token>/download')
def public_share_download(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    link = db().execute('''SELECT sl.*,f.original_name,f.storage_name FROM share_links sl JOIN files f ON f.id=sl.file_id WHERE sl.token_hash=? AND sl.revoked=0''', (token_hash,)).fetchone()
    if not link or (link['expires_at'] and link['expires_at'] < utcnow()): abort(404)
    try: data = fernet.decrypt(storage_path(link['storage_name']).read_bytes())
    except (InvalidToken, OSError): abort(404)
    return send_file(BytesIO(data), as_attachment=True, download_name=link['original_name'], mimetype='application/octet-stream')

@app.post('/revoke-link/<int:link_id>')
@login_required
def revoke_link(link_id):
    cur = db().execute('UPDATE share_links SET revoked=1 WHERE id=? AND owner_id=?', (link_id,session['user_id'])); db().commit()
    flash('Sharing link revoked.' if cur.rowcount else 'Link not found.', 'success' if cur.rowcount else 'error')
    return redirect(url_for('dashboard'))

@app.get('/health')
def health():
    db().execute('SELECT 1').fetchone()
    return {'status':'ok','service':'cloud-file-sharing-app'}, 200

if __name__ == '__main__':
    # For local development. For VM deployment use Gunicorn (see README).
    app.run(host=os.environ.get('HOST', '127.0.0.1'), port=int(os.environ.get('PORT','5000')), debug=False)
