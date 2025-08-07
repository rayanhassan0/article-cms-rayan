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

# إعداد اللوق إذا لم يكن مفعلاً
if not app.debug:
    logging.basicConfig(filename='app.log', level=logging.INFO)

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
    auth_url = _build_auth_url(scopes=Config.SCOPE, state=session["state"])
    return redirect(auth_url)

@app.route(Config.REDIRECT_PATH)
def authorized():
    if request.args.get('state') != session.get("state"):
        return redirect(url_for("index"))  # حالة غير متطابقة

    if "error" in request.args:
        app.logger.warning("Invalid login attempt: %s", request.args.get("error_description"))
        return redirect(url_for("index"))

    if request.args.get('code'):
        cache = _load_cache()
        result = _build_msal_app(cache=cache).acquire_token_by_authorization_code(
            request.args['code'],
            scopes=Config.SCOPE,
            redirect_uri=url_for('authorized', _external=True))
        if "id_token_claims" in result:
            session["user"] = result["id_token_claims"]
            _save_cache(cache)

            # ✅ تسجيل الدخول الناجح
            username = session["user"].get("preferred_username", "Unknown user")
            app.logger.info("Admin logged in successfully: %s", username)

        else:
            # ❌ تسجيل الدخول الفاشل
            app.logger.warning("Invalid login attempt: Token not found")
    return redirect(url_for("index"))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(  # إعادة التوجيه لتسجيل الخروج من مايكروسوفت
        Config.AUTHORITY + "/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + url_for("index", _external=True))

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
        post = Post(title=form.title.data, content=form.content.data, author=current_user.name, image=filename)
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
        Config.CLIENT_ID, authority=authority or Config.AUTHORITY,
        client_credential=Config.CLIENT_SECRET, token_cache=cache)

def _build_auth_url(authority=None, scopes=None, state=None):
    return _build_msal_app(authority=authority).get_authorization_request_url(
        scopes or [],
        state=state or str(uuid.uuid4()),
        redirect_uri=url_for('authorized', _external=True))

def _upload_image_to_blob(filename):
    from azure.storage.blob import BlockBlobService
    blob_service = BlockBlobService(account_name=app.config["BLOB_ACCOUNT"], account_key=app.config["BLOB_STORAGE_KEY"])
    blob_service.create_blob_from_path(app.config["BLOB_CONTAINER"], filename, filename)