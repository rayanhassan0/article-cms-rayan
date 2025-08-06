"""
Routes and views for the flask application.
"""

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
import os

imageSourceUrl = 'https://' + app.config['BLOB_ACCOUNT'] + '.blob.core.windows.net/' + app.config['BLOB_CONTAINER'] + '/'


@app.route('/')
@app.route('/home')
@login_required
def home():
    user = User.query.filter_by(username=current_user.username).first_or_404()
    posts = Post.query.all()
    return render_template(
        'index.html',
        title='Home Page',
        posts=posts
    )


@app.route('/new_post', methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm(request.form)
    if form.validate_on_submit():
        post = Post()
        post.save_changes(form, request.files['image_path'], current_user.id, new=True)
        return redirect(url_for('home'))
    return render_template(
        'post.html',
        title='Create Post',
        imageSource=imageSourceUrl,
        form=form
    )


@app.route('/post/<int:id>', methods=['GET', 'POST'])
@login_required
def post(id):
    post = Post.query.get(int(id))
    form = PostForm(formdata=request.form, obj=post)
    if form.validate_on_submit():
        post.save_changes(form, request.files['image_path'], current_user.id)
        return redirect(url_for('home'))
    return render_template(
        'post.html',
        title='Edit Post',
        imageSource=imageSourceUrl,
        form=form
    )


# ✅ تم تعديلها لإظهار session و state
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    print("🔁 [LOGIN] Opening /login")
    print("🔁 [LOGIN] Session before setting state:", dict(session))

    if "user" in session:
        user = User.query.filter_by(username="admin").first()
        if user:
            login_user(user)
            print("✅ [LOGIN] Logged in from existing session")
            return redirect(url_for("home"))

    form = LoginForm()
    session["state"] = str(uuid.uuid4())
    auth_url = _build_auth_url(scopes=Config.SCOPE, state=session["state"])

    print("➡️ [LOGIN] Redirecting to Microsoft with state:", session["state"])
    return render_template('login.html', title='Sign In', form=form, auth_url=auth_url)


# ✅ تم تعديلها لإظهار المشاكل بالتفصيل
@app.route(Config.REDIRECT_PATH)
def authorized():
    print("🔄 [AUTHORIZED] Called with request.args:", dict(request.args))
    print("🔄 [AUTHORIZED] Current session:", dict(session))

    if request.args.get('state') != session.get("state"):
        print("⚠️ [AUTHORIZED] State mismatch! Expected:", session.get("state"), "Got:", request.args.get("state"))
        return redirect(url_for("login"))

    if "error" in request.args:
        print("❌ [AUTHORIZED] Error from Microsoft:", request.args)
        return render_template("auth_error.html", result=request.args)

    if request.args.get('code'):
        print("✅ [AUTHORIZED] Code received, requesting token...")
        cache = _load_cache()
        msal_app = _build_msal_app(cache=cache)
        result = msal_app.acquire_token_by_authorization_code(
            request.args['code'],
            scopes=Config.SCOPE,
            redirect_uri=url_for('authorized', _external=True))

        if "error" in result:
            print("❌ [AUTHORIZED] Token error:", result)
            return render_template("auth_error.html", result=result)

        session["user"] = result.get("id_token_claims")
        print("🔐 [AUTHORIZED] Logged in user:", session["user"])

        user = User.query.filter_by(username="admin").first()
        if user:
            login_user(user)
        _save_cache(cache)
        return redirect(url_for('home'))

    print("⚠️ [AUTHORIZED] No code or error in request")
    return redirect(url_for("login"))


@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    return redirect(
        Config.AUTHORITY + "/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + url_for("goodbye", _external=True)
    )


@app.route('/goodbye')
def goodbye():
    return render_template("goodbye.html", title="Logged Out")


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


@app.route("/debug-env")
def debug_env():
    return {
        "SQL_SERVER": os.environ.get("SQL_SERVER"),
        "SQL_USER_NAME": os.environ.get("SQL_USER_NAME"),
        "SQL_PASSWORD": os.environ.get("SQL_PASSWORD"),
        "SQL_DATABASE": os.environ.get("SQL_DATABASE")
    }