import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default-secret-key')

    BLOB_ACCOUNT = os.environ.get('BLOB_ACCOUNT', 'imagesrayan123')
    BLOB_STORAGE_KEY = os.environ.get('BLOB_STORAGE_KEY')
    BLOB_CONTAINER = os.environ.get('BLOB_CONTAINER', 'images')

    SQL_SERVER = os.environ.get('SQL_SERVER', 'cms-server123.database.windows.net')
    SQL_DATABASE = os.environ.get('SQL_DATABASE', 'cms')
    SQL_USER_NAME = os.environ.get('SQL_USER_NAME', 'cmsadmin')
    SQL_PASSWORD = os.environ.get('SQL_PASSWORD')

    SQLALCHEMY_DATABASE_URI = (
        f"mssql+pyodbc://{SQL_USER_NAME}:{SQL_PASSWORD}@{SQL_SERVER}:1433/{SQL_DATABASE}"
        "?driver=ODBC+Driver+18+for+SQL+Server"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
    AUTHORITY = "https://login.microsoftonline.com/common"
    CLIENT_ID = os.environ.get("CLIENT_ID")
    REDIRECT_PATH = "/getAToken"
    SCOPE = ["User.Read"]
    SESSION_TYPE = "filesystem"
