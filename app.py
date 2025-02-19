import os
import requests
import configparser
from flask import Flask, request, render_template, send_file
import re
from werkzeug.utils import secure_filename
from email.parser import BytesParser
from email.policy import default

# Initialize Flask app
app = Flask(__name__, static_folder='static')

# Read configuration file for API Keys
config = configparser.ConfigParser()
config.read('config.ini')

# Load API key once at the start
VIRUSTOTAL_API_KEY = config['settings'].get('virustotal_api_key', None)
if not VIRUSTOTAL_API_KEY:
    raise ValueError("API key is missing in config.ini")

# Set upload folder and allowed file extensions
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'eml', 'txt'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max file size: 16MB

# API URL
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"

# Utility function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    """Route for the home page."""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Route to handle file upload and processing."""
    if 'file' not in request.files:
        return render_template('error.html', message="No file part")

    file = request.files['file']
    if file.filename == '':
        return render_template('error.html', message="No selected file")

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        try:
            file.save(file_path)
            return process_email(file_path)
        except Exception as e:
            return render_template('error.html', message=f"Error during upload: {str(e)}")
    else:
        return render_template('error.html', message="File type not allowed. Please upload an '.eml' or '.txt' file.")

@app.route('/results', methods=['GET', 'POST'])
def results():
    """Route to display results (after email is processed)."""
    return render_template('results.html')

@app.route('/export/csv')
def export_csv():
    """Generate CSV file and send as download."""
    csv_file = "static/results.csv"
    try:
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["IOC", "Malicious", "Suspicious", "Harmless", "Geolocation"])
            for ioc, result in results.items():
                writer.writerow([ioc, result.get("malicious", 0), result.get("suspicious", 0), 
                                 result.get("harmless", 0), result.get("geolocation", "N/A")])
        return send_file(csv_file, as_attachment=True, download_name="results.csv")
    except Exception as e:
        return f"Error generating CSV: {str(e)}"

# Process the uploaded email file
def process_email(file_path):
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=default).parse(f)
        
        if not msg:
            raise ValueError("Email is malformed or missing content.")
        
        headers = parse_email_headers(msg)
        body = extract_email_body(msg)
        iocs = extract_iocs(body)
        
        spf_record = extract_spf(msg)
        dkim_record = extract_dkim(msg)
        dmarc_record = extract_dmarc(msg)
        
        results = scan_iocs(iocs)
        logs_data = collect_logs(iocs, results, spf_record, dmarc_record, dkim_record)
        
        return render_template('results.html', headers=headers, iocs=iocs, results=results, 
                               spf_record=spf_record, dkim_record=dkim_record, dmarc_record=dmarc_record, 
                               logs=logs_data)
    except Exception as e:
        return render_template('error.html', message=f"Error processing the email: {str(e)}")

# Extract SPF, DKIM, and DMARC from the email headers
def extract_spf(msg):
    return msg.get('Received-SPF', "SPF record not found in the email headers.")

def extract_dkim(msg):
    return msg.get('DKIM-Signature', "DKIM signature not found in the email headers.")

def extract_dmarc(msg):
    auth_results_header = msg.get('Authentication-Results', None)
    if auth_results_header:
        match = re.search(r'dmarc=(\S+)', auth_results_header)
        if match:
            return f"DMARC result: {match.group(1)}"
    return "DMARC record not found in the email headers."

# Extract email headers
def parse_email_headers(msg):
    headers = {}
    for header in ['From', 'To', 'Reply-To', 'Subject', 'Date']:
        headers[header] = msg[header] if msg[header] else "Not available"
    return headers

# Extract email body
def extract_email_body(msg):
    if msg.is_multipart():
        for part in msg.iter_parts():
            if part.get_content_type() == 'text/plain':
                return part.get_payload(decode=True).decode('utf-8', errors='ignore')
    return msg.get_payload(decode=True).decode('utf-8', errors='ignore')

# Generic IOC extraction function
def extract_iocs(body):
    patterns = {
        "urls": r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
        "ips": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        "domains": r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
        "file_hashes": r'\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b',
        "emails": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    }
    return {key: re.findall(pattern, body) for key, pattern in patterns.items()}

# Scan IOCs via VirusTotal
def scan_iocs(iocs):
    results = {}
    for ioc in iocs.get("ips", []) + iocs.get("urls", []) + iocs.get("domains", []) + iocs.get("file_hashes", []):
        results[ioc] = scan_with_virustotal(ioc)
    return results

# VirusTotal scan function
def scan_with_virustotal(ioc):
    url = f"{VIRUSTOTAL_API_URL}/{determine_ioc_type(ioc)}/{ioc}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        return parse_virustotal_response(response, ioc)
    except Exception as e:
        return {"ioc": ioc, "error": str(e)}

# Parse VirusTotal response
def parse_virustotal_response(response, ioc):
    if response.status_code != 200:
        return {"ioc": ioc, "malicious": 0, "suspicious": 0, "harmless": 0, "geolocation": "N/A"}
    
    response_json = response.json()
    if 'data' in response_json:
        result = response_json['data']
        formatted_result = {
            "ioc": ioc,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "geolocation": "N/A"
        }
        
        if "attributes" in result:
            attributes = result["attributes"]
            if "last_analysis_stats" in attributes:
                stats = attributes["last_analysis_stats"]
                formatted_result["malicious"] = stats.get("malicious", 0)
                formatted_result["suspicious"] = stats.get("suspicious", 0)
                formatted_result["harmless"] = stats.get("harmless", 0)
            if "country" in attributes:
                formatted_result["geolocation"] = attributes["country"]
        
        return formatted_result
    return {"ioc": ioc, "malicious": 0, "suspicious": 0, "harmless": 0, "geolocation": "N/A"}

# Function to determine IOC type for VirusTotal API request
def determine_ioc_type(ioc):
    if re.match(r'http[s]?://', ioc):
        return 'urls'
    elif re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ioc):
        return 'ips'
    elif re.match(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', ioc):
        return 'domains'
    elif re.match(r'\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b', ioc):
        return 'files'
    return 'unknown'

# Function to collect logs data
def collect_logs(iocs, results, spf_record, dmarc_record, dkim_record):
    logs_data = {
        "iocs": {
            "urls": iocs.get("urls", []),
            "ips": iocs.get("ips", []),
            "domains": iocs.get("domains", []),
            "file_hashes": iocs.get("file_hashes", []),
            "emails": iocs.get("emails", [])
        },
        "virus_total_results": results,
        "spf_record": spf_record,
        "dkim_record": dkim_record,
        "dmarc_record": dmarc_record
    }
    return logs_data

if __name__ == '__main__':
    app.run(debug=False)
