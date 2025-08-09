from datetime import datetime
from flask import render_template, flash, redirect, request, session, url_for
from urllib.parse import urlparse
from config import Config
from FlaskWebProject import app, db
from FlaskWebProject.forms import LoginForm, PostForm
from flask_login import current_user, login_user, logout_user, login_required
from FlaskWebProject.models import User, Post
import msal
import uuid
import logging
import sys

# ---------- Logging setup (to stdout so it shows in Azure Log Stream) ----------
logger = logging.getLogger("app")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)  # مهم: يرسل للـ Log Stream
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

imageSourceUrl = 'https://' + app.config["BLOB_ACCOUNT"] + '.blob.core.windows.net/' + app.config["BLOB_CONTAINER"] + '/'

@app.route('/')
@app.route('/index')
@login_required
def index():
    posts = Post.query.all()
    return render_template('index.html', title='Home Page', posts=posts)

@app.route('/login', methods=['GET'])
def login():
    session["state"] = str(uuid.uuid4())
    logger.info("AUTH: Begin login, state=%s", session["state"])
    auth_url = _build_auth_url(scopes=Config.SCOPE, state=session["state"])
    return redirect(auth_url)

@app.route(Config.REDIRECT_PATH)
def authorized():
    # 1) STATE check
    if request.args.get('state') != session.get("state"):
        logger.warning("LOGIN FAILED: state mismatch (possible CSRF). got=%s expected=%s",
                       request.args.get('state'), session.get('state'))
        flash("Login failed (state mismatch).", "warning")
        return redirect(url_for("index"))

    # 2) Provider error
    if "error" in request.args:
        desc = request.args.get("error_description")
        logger.warning("LOGIN FAILED: provider returned error: %s", desc)
        flash("Login failed (provider error).", "danger")
        return redirect(url_for("index"))

    # 3) Authorization code exchange
    if request.args.get('code'):
        logger.info("AUTH: Received authorization code")
        cache = _load_cache()
        try:
            result = _build_msal_app(cache=cache).acquire_token_by_authorization_code(
                request.args['code'],
                scopes=Config.SCOPE,
                redirect_uri=url_for('authorized', _external=True)
            )
        except Exception as e:
            logger.exception("LOGIN FAILED: exception during token exchange: %s", e)
            flash("Login failed (token exchange error).", "danger")
            return redirect(url_for("index"))

        # MSAL returns error in 'error' keys when it fails
        if not result or ("access_token" not in result and "id_token" not in result and "id_token_claims" not in result):
            logger.warning("LOGIN FAILED: token exchange failed - result=%s", result)
            flash("Login failed (no token).", "danger")
            return redirect(url_for("index"))

        # Success path
        session["user"] = result.get("id_token_claims", {})
        _save_cache(cache)

        # Extract identity details (best-effort)
        oid = session["user"].get("oid") or session["user"].get("sub") or str(uuid.uuid4())
        name = session["user"].get("name") or "Unknown"
        email = session["user"].get("preferred_username") or session["user"].get("upn") or ""

        # Optional: persist/create user if your model supports it (best-effort, no crash if schema differs)
        try:
            # إذا جدولك يدعم هذي الحقول
            user = User(id=oid) if not hasattr(User, 'query') else User.query.get(oid) or User(id=oid)
            if hasattr(user, "name"):
                user.name = name
            if hasattr(user, "email"):
                user.email = email
            if hasattr(user, "username") and not getattr(user, "username", None):
                user.username = email or name  # للسكيمات القديمة
            # خزّن إذا كان عندك DB فعّال
            try:
                if hasattr(db, "session"):
                    db.session.merge(user)
                    db.session.commit()
            except Exception:
                # تجاهل مشاكل السكيمة/الجداول
                pass

            login_user(user)  # يفعّل Flask-Login session
            logger.info("LOGIN SUCCESS: %s", email or name)
            flash("Logged in successfully.", "success")
        except Exception as e:
            logger.exception("LOGIN FAILED: could not finalize user login: %s", e)
            flash("Login failed (finalize login).", "danger")
            return redirect(url_for("index"))

    return redirect(url_for("index"))

@app.route('/logout')
def logout():
    session.clear()
    logger.info("AUTH: User logged out")
    return redirect(
        Config.AUTHORITY + "/oauth2/v2.0/logout"
        + "?post_logout_redirect_uri=" + url_for("index", _external=True)
    )

@app.route('/post', methods=['GET', 'POST'])
@login_required
def post():
    form = PostForm()
    if form.validate_on_submit():
        filename = None
        if form.image.data:
            image_file = form.image.data
            filename = image_file.filename
            image_file.save(filename)
            _upload_image_to_blob(filename)
        post = Post(title=form.title.data, content=form.content.data,
                    author=getattr(current_user, "name", "admin"), image=filename)
        db.session.add(post)
        db.session.commit()
        flash('Post successfully created!')
        return redirect(url_for('index'))
    return render_template('post.html', title='Create Post', form=form)

# ------------------ MSAL Helper Functions ------------------

def _load_cache():
    cache = msal.SerializableTokenCache()
    if session.get("token_cache"):
        cache.deserialize(session["token_cache"])
    return cache

def _save_cache(cache):
    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()

def _build_msal_app(cache=None, authority=None):
    return msal.ConfidentialClientApplication(
        Config.CLIENT_ID,
        authority=authority or Config.AUTHORITY,
        client_credential=Config.CLIENT_SECRET,
        token_cache=cache
    )

def _build_auth_url(authority=None, scopes=None, state=None):
    return _build_msal_app(authority=authority).get_authorization_request_url(
        scopes or [],
        state=state or str(uuid.uuid4()),
        redirect_uri=url_for('authorized', _external=True)
    )

def _upload_image_to_blob(filename):
    from azure.storage.blob import BlockBlobService
    blob_service = BlockBlobService(
        account_name=app.config["BLOB_ACCOUNT"],
        account_key=app.config["BLOB_STORAGE_KEY"]
    )
    blob_service.create_blob_from_path(app.config["BLOB_CONTAINER"], filename, filename)
