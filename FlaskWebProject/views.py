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

# ---------- Logging: إلى stdout عشان يظهر في Azure Log Stream ----------
logger = logging.getLogger("app")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

imageSourceUrl = 'https://' + app.config["BLOB_ACCOUNT"] + '.blob.core.windows.net/' + app.config["BLOB_CONTAINER"] + '/'

@app.route('/')
@app.route('/index')
@login_required
def index():
    posts = Post.query.order_by(Post.timestamp.desc()).all()
    return render_template('index.html', title='Home Page', posts=posts)

@app.route('/login', methods=['GET'])
def login():
    # بداية عملية تسجيل الدخول
    session["state"] = str(uuid.uuid4())
    logger.info("AUTH: Begin login, state=%s", session["state"])
    auth_url = _build_auth_url(scopes=Config.SCOPE, state=session["state"])
    return redirect(auth_url)

@app.route(Config.REDIRECT_PATH)
def authorized():
    # 1) تحقق من STATE
    if request.args.get('state') != session.get("state"):
        logger.warning("LOGIN FAILED: state mismatch (possible CSRF). got=%s expected=%s",
                       request.args.get('state'), session.get('state'))
        flash("Login failed (state mismatch).", "warning")
        return redirect(url_for("index"))

    # 2) خطأ من المزوّد
    if "error" in request.args:
        desc = request.args.get("error_description")
        logger.warning("LOGIN FAILED: provider returned error: %s", desc)
        flash("Login failed (provider error).", "danger")
        return redirect(url_for("index"))

    # 3) تبادل كود التفويض
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

        # فشل التبادل
        if not result or ("access_token" not in result and "id_token" not in result and "id_token_claims" not in result):
            logger.warning("LOGIN FAILED: token exchange failed - result=%s", result)
            flash("Login failed (no token).", "danger")
            return redirect(url_for("index"))

        # نجاح: استخراج الهوية
        session["user"] = result.get("id_token_claims", {})
        _save_cache(cache)

        email = session["user"].get("preferred_username") or session["user"].get("upn") or ""
        name  = session["user"].get("name") or (email.split("@")[0] if email else "Unknown")
        username = email or name  # سنخزن هذا في users.username

        # جلب/إنشاء المستخدم باليوزرنيم فقط (id int أوتوماتيك)
        try:
            user = User.query.filter_by(username=username).first()
            if not user:
                user = User(username=username)
                # عيّن كلمة مرور عشوائية مُشفّرة حتى لا يكون password_hash = NULL
                random_password = uuid.uuid4().hex
                user.set_password(random_password)  # يحفظ hash داخل password_hash
                db.session.add(user)
                db.session.commit()  # الآن له id صحيح (int)

            login_user(user)
            logger.info("LOGIN SUCCESS: %s", username)
            flash("Logged in successfully.", "success")
        except Exception as e:
            logger.exception("LOGIN FAILED: could not finalize user login (db/user): %s", e)
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

        # موديل Post: title, author (String), body, image_path
        # لو الفورم عندك يستخدم content بدل body، ناخذ الموجود
        body_value = ""
        if hasattr(form, "body"):
            body_value = form.body.data
        elif hasattr(form, "content"):
            body_value = form.content.data

        p = Post(
            title=form.title.data,
            author=getattr(current_user, "username", "admin"),
            body=body_value,
            image_path=filename
        )
        db.session.add(p)
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
    # ملاحظة: BlockBlobService قديمة لكن نبقيها كما هي لتوافق مشروعك
    from azure.storage.blob import BlockBlobService
    blob_service = BlockBlobService(
        account_name=app.config["BLOB_ACCOUNT"],
        account_key=app.config["BLOB_STORAGE_KEY"]
    )
    blob_service.create_blob_from_path(app.config["BLOB_CONTAINER"], filename, filename)