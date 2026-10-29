
from flask import Flask

from app.database import init_db


def create_app():
    app = Flask(__name__)

    app.config["SECRET_KEY"] = "dev-only-change-this-key"

    init_db()

    from app.routes import register_routes
    register_routes(app)

    return app
