from flask import Flask
from .config import Config
from .db import init_db, seed_training_run, seed_default_admin
from .routes import main_bp
from .auth import auth_bp

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)

    with app.app_context():
        init_db()
        seed_default_admin()
        seed_training_run()

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)

    @app.context_processor
    def inject_globals():
        from .model_service import get_metrics
        return {
            "brand_name": "PhishGuard",
            "model_metrics": get_metrics(),
        }

    return app
