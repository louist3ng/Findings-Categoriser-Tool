"""Flask web server — serves the results UI and JSON API."""

import json
import os
import threading
import webbrowser
from flask import Flask, render_template, jsonify


def create_app(results_path):
    """Create and configure the Flask application."""
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    )
    app.config["RESULTS_PATH"] = results_path

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/data")
    def api_data():
        results_file = app.config["RESULTS_PATH"]
        try:
            with open(results_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return jsonify(data)
        except FileNotFoundError:
            return jsonify({"error": "Results file not found"}), 404

    return app


def launch_server(results_path, port=5000, open_browser=True):
    """Start the Flask server and optionally open the browser."""
    app = create_app(results_path)
    url = f"http://localhost:{port}"
    print(f"Results available at {url} — press Ctrl+C to exit")

    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    app.run(host="0.0.0.0", port=port, debug=False)
