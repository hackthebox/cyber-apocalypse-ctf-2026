"""Patched application factory used by the author solution."""

import os

from flask import Flask, render_template
from werkzeug.middleware.proxy_fix import ProxyFix

from . import db, models, staff
from .routes import gate_bp
from .pages import pages_bp


def _render_fault(code: int, heading: str, message: str):
    return render_template("error.html", code=code, heading=heading, message=message), code


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("GATE_SESSION_KEY", "dev-salt-gate-session-key")

    # The application perimeter is the only trusted proxy hop.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    app.register_blueprint(gate_bp)
    app.register_blueprint(pages_bp)

    @app.context_processor
    def inject_seal_count():
        return {
            "sealed": models.count_decrees(),
            "current_staff": staff.current_user(),
        }

    @app.errorhandler(403)
    def forbidden(_error):
        return _render_fault(403, "No business here",
                             "The inner desk is for the Watch's own runners. "
                             "A courier on the road is turned away.")

    @app.errorhandler(404)
    def not_found(_error):
        return _render_fault(404, "Nothing on record",
                             "The gate keeps no record of what you asked for.")

    @app.errorhandler(500)
    def gate_fault(_error):
        return _render_fault(500, "The gate is shut",
                             "Something fouled at the checkpoint. The Watch has been roused.")

    db.init_db()

    return app


app = create_app()
