from flask import Flask, request, jsonify
from flask_cors import CORS
from api import DomainInfoAPI
import sys

app = Flask(__name__)
CORS(app)
api = DomainInfoAPI()

@app.route('/domain-info', methods=['GET'])
def get_domain_info():
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
    print("Starting Flask application...")
    app.run(debug=True)
