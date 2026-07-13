from flask import Flask, jsonify
import requests
import numpy
import yaml
import cryptography

app = Flask(__name__)

@app.route("/")
def home():
    return "SBOM Drift Detection Demo Application"

@app.route("/status")
def status():
    return jsonify({
        "status": "Running",
        "application": "SBOM Drift Detection Demo",
        "version": "1.0"
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
