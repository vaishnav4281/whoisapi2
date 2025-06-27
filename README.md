# Domain Information API

This project provides a simple Flask-based API to retrieve comprehensive information about a given domain, including WHOIS details, IP address, geolocation data, and an abuse confidence score. It's designed to be robust, with a fallback mechanism for WHOIS lookups if the primary API fails.

## Features

- **WHOIS Lookup**: Fetches domain registration details (creation date, expiry date, registrar, registrant information, domain status).
  - **Primary**: Uses WhoisXMLAPI for detailed WHOIS data.
  - **Fallback**: Automatically falls back to the `python-whois` library if WhoisXMLAPI fails (e.g., due to invalid API key, rate limits, or service issues).
- **IP Address Resolution**: Resolves the domain name to its corresponding IP address.
- **IP Geolocation**: Provides geographical information (country, city, latitude, longitude, ISP, organization) for the resolved IP address.
- **Abuse Confidence Score**: Integrates with AbuseIPDB to provide a confidence score indicating potential malicious activity associated with the IP address.
- **Structured JSON Output**: All information is aggregated and returned in a clean, easy-to-parse JSON format.
- **Error Handling**: Gracefully handles errors from external APIs and provides informative error messages within the JSON response, ensuring the API always returns a consistent structure.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.x**: (Recommended Python 3.8+)
- **pip**: Python package installer (usually comes with Python).

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/whois-api-main.git # Replace with your actual repo URL
    cd whois-api-main
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Configuration (API Keys)

This API relies on external services for some data. You'll need to obtain API keys for these services and configure them.

1.  **Create a `.env` file:**
    In the root directory of your project (`whois-api-main`), create a new file named `.env`.

2.  **Add your API keys to `.env`:**
   Open the `.env` file and add your actual API keys. You can use the `.env.example` file as a template.
   
   ```ini
   # .env
   WHOISXML_API_KEY="YOUR_WHOISXMLAPI_KEY_HERE"
   ABUSEIPDB_API_KEY="YOUR_ABUSEIPDB_API_KEY_HERE"
   ```
   
   -   **`WHOISXML_API_KEY`**: Obtain this from WhoisXMLAPI. This is used for the primary WHOIS lookup. If this key is invalid or missing, the API will automatically fall back to the `python-whois` library.
   -   **`ABUSEIPDB_API_KEY`**: Obtain this from AbuseIPDB. This is used to get the abuse confidence score for the IP address. If this key is invalid or missing, the `abuse_score` will be `null` and an error message will be included.
   
   **Important**: Do not commit your `.env` file to version control (e.g., Git). It contains sensitive information. A `.gitignore` entry for `.env` is recommended.
   
   ## Running the Application
   
   To start the Flask API server:
   
   ```bash
   python app.py
   ```
   
   You should see output similar to this, indicating the server is running:
   
   ```
   Starting Flask application...
    * Serving Flask app 'app'
    * Debug mode: on
   WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
    * Running on http://127.0.0.1:5000
   Press CTRL+C to quit
   ```
   
   ## API Usage
   
   The API exposes a single endpoint to get domain information.
   
   ### `GET /domain-info`
   
   Retrieves comprehensive information for a specified domain.
   
   -   **URL**: `http://localhost:5000/domain-info`
   -   **Method**: `GET`
   -   **Query Parameters**:
       -   `domain` (string, **required**): The domain name you want to query (e.g., `google.com`, `facebook.com`).
   
   ### Example Request
   
   Using `curl` in your terminal:
   
   ```bash
   curl "http://localhost:5000/domain-info?domain=facebook.com"
   ```
   
   ### Example Response
   
   A successful response will return a JSON object containing various details. If an external API fails (e.g., AbuseIPDB due to an invalid key), the relevant fields will be `null` or `Unknown`, and the `error` field will provide details.
   
   ```json
   {
     "abuse_score": null,
     "age": "28 years, 2 months, 29 days",
     "as": "AS32934 Facebook, Inc.",
     "city": "Chennai",
     "country": "India",
     "countryCode": "IN",
     "creation_date": "1997-03-29T05:00:00+00:00",
     "domain": "facebook.com",
     "domain_status": "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited, clientTransferProhibited https://icann.org/epp#clientTransferProhibited, clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited, serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited, serverTransferProhibited https://icann.org/epp#serverTransferProhibited, serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited, clientDeleteProhibited https://www.icann.org/epp#clientDeleteProhibited, clientTransferProhibited https://www.icann.org/epp#clientTransferProhibited, clientUpdateProhibited https://www.icann.org/epp#clientUpdateProhibited, serverDeleteProhibited https://www.icann.org/epp#serverDeleteProhibited, serverTransferProhibited https://www.icann.org/epp#serverTransferProhibited, serverUpdateProhibited https://www.icann.org/epp#serverUpdateProhibited",
     "error": "AbuseIPDB error: AbuseIPDB lookup failed: 401 Client Error: Unauthorized for url: https://api.abuseipdb.com/api/v2/check?ipAddress=57.144.156.1&maxAgeInDays=90",
     "expiry_date": "2034-03-30T04:00:00",
     "ip_address": "57.144.156.1",
     "isp": "Facebook, Inc.",
     "lat": 13.0895,
     "lon": 80.2739,
     "org": "Meta Platforms Ireland Limited",
     "query": "57.144.156.1",
     "region": "TN",
     "regionName": "Tamil Nadu",
     "registrant_email": "Unknown",
     "registrant_name": "Domain Admin",
     "registrant_phone": "Unknown",
     "registrar": "RegistrarSafe, LLC",
     "status": "error",
     "timezone": "Asia/Kolkata",
     "zip": "600001"
   }
   ```
   
   *Note: In the example above, the `error` field indicates that the AbuseIPDB API key was invalid, leading to `abuse_score: null`. If you provide a valid key, this error will disappear and the `abuse_score` will be populated.*
   
   ## Project Structure
   
   -   `app.py`: The main Flask application file. It defines the API endpoint and handles incoming requests.
   -   `api.py`: Contains the `DomainInfoAPI` class, which encapsulates the logic for fetching WHOIS, IP, and abuse information from various sources.
   -   `requirements.txt`: Lists all Python dependencies required for the project.
   -   `.env.example`: A template file for environment variables (API keys).
   -   `.env`: (You create this) Stores your actual API keys, which should not be committed to version control.
   
   ## Future Enhancements
   
   -   **Caching**: Implement caching for frequently requested domains to reduce external API calls and improve response times.
   -   **Asynchronous Calls**: Use `asyncio` or similar for concurrent external API calls to further speed up responses.
   -   **More Robust Error Handling**: Implement specific error codes and messages for different types of failures (e.g., domain not found, API rate limits).
   -   **Dockerization**: Provide a `Dockerfile` for easy deployment in containerized environments.
   -   **Unit Tests**: Add comprehensive unit tests for the `DomainInfoAPI` class and API endpoints.
   -   **Logging**: Implement more detailed logging for debugging and monitoring.
   
   ## License
   
   This project is open-source and available under the MIT License.
