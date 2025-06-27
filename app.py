from flask import Flask, request, jsonify
from flask_cors import CORS
from api import DomainInfoAPI
import sys
import os

app = Flask(__name__)
CORS(app)
api = DomainInfoAPI()

@app.route('/domain-info', methods=['GET'])
def get_domain_info():
    # Get API key from environment variable
    API_KEY = os.getenv("API_KEY")
    
    # Check API key
    provided_key = request.headers.get('X-API-KEY')
    if not provided_key or provided_key != API_KEY:
        return jsonify({"error": "Invalid API key"}), 401

    try:
        # Get domain from query parameter
        domain = request.args.get('domain')
        if not domain:
            return jsonify({"error": "No domain provided"}), 400

        # Get domain information
        info = api.get_domain_info(domain)

        return jsonify(info), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    host = '0.0.0.0'
    print(f"Starting Flask application on port {port}...")
    app.run(host=host, port=port, debug=False)  # Disable debug mode in production
