from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# Инициализируем, но не привязываем к приложению (это сделаем в app.py)
db = SQLAlchemy()
login_manager = LoginManager()