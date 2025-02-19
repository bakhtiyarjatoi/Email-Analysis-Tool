import email
from email import policy
from email.parser import BytesParser
import re
import base64
import requests
import configparser
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB

# Read the configuration file to get the API key
config = configparser.ConfigParser()
config.read('config.ini')

# Get the VirusTotal API key from the config file
API_KEY = config['settings']['api_key']
BASE_URL = "https://www.virustotal.com/api/v3/urls/"

# Function to parse raw email content
def parse_email(raw_email):
    """Parse the raw email content."""
    msg = BytesParser(policy=policy.default).parsebytes(raw_email)
    
    # Extract subject and body
    subject = msg['subject']
    body = msg.get_body(preferencelist=('plain', 'html')).get_content()

    # Extract attachments
    attachments = []
    for attachment in msg.iter_attachments():
        attachments.append({
            "filename": attachment.get_filename(),
            "content": attachment.get_payload(decode=True)
        })
    
    return subject, body, attachments

# Function to extract URLs from email text
def extract_urls(text):
    """Extract URLs from the text (plain or HTML)."""
    url_pattern = r'https?://[^\s]+'
    urls = re.findall(url_pattern, text)
    return urls

# Function to check the URL reputation using VirusTotal
def check_url_reputation(url):
    """Check the reputation of a URL using VirusTotal API."""
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": API_KEY}
    response = requests.get(f"{BASE_URL}{url_id}", headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        if 'data' in data:
            reputation = data['data']['attributes']['last_analysis_stats']
            return reputation
    return None

# Function to detect phishing keywords in the email body and subject
def detect_phishing_keywords(subject, body):
    """Detect common phishing keywords in the subject and body."""
    phishing_keywords = ["urgent", "account locked", "immediate action", "suspend", "free gift", "verify your account"]
    
    # Check if any phishing keyword is in the subject or body
    for keyword in phishing_keywords:
        if keyword.lower() in subject.lower() or keyword.lower() in body.lower():
            return True
    return False

# Function to check for dangerous attachments
def check_attachments(attachments):
    """Check for dangerous attachments."""
    dangerous_extensions = ['.exe', '.scr', '.js', '.vbs', '.bat']
    for attachment in attachments:
        filename = attachment['filename'].lower()
        for ext in dangerous_extensions:
            if filename.endswith(ext):
                return True
    return False

# Machine Learning: Simple Naive Bayes Classifier for phishing detection
def train_phishing_classifier(emails, labels):
    """Train a simple classifier to detect phishing emails."""
    vectorizer = CountVectorizer()
    X = vectorizer.fit_transform(emails)
    y = labels
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    
    model = MultinomialNB()
    model.fit(X_train, y_train)
    
    return model, vectorizer

# Predict phishing status using the classifier
def predict_phishing(subject, body, model, vectorizer):
    """Predict whether an email is phishing using the trained model."""
    email_content = [subject + " " + body]
    vectorized_email = vectorizer.transform(email_content)
    prediction = model.predict(vectorized_email)
    return prediction[0] == 1  # 1 means phishing

# Function to generate an alert for phishing detection
def generate_alert(subject, body, urls, attachments, phishing_detected, reputation):
    """Generate an alert with detailed phishing detection results."""
    alert = f"Phishing Alert: {subject}\n"
    alert += f"Body: {body}\n"
    alert += f"URLs: {urls}\n"
    alert += f"Attachments: {[attachment['filename'] for attachment in attachments]}\n"
    
    if phishing_detected:
        alert += "Phishing keywords detected in the email.\n"
    
    if reputation:
        alert += f"URL Reputation: {reputation}\n"
    
    if check_attachments(attachments):
        alert += "Suspicious attachment detected.\n"
    
    return alert

# Function to process raw email and check for phishing
def process_email(raw_email, model=None, vectorizer=None):
    subject, body, attachments = parse_email(raw_email)
    urls = extract_urls(body)

    # Check URLs reputation
    url_reputations = [check_url_reputation(url) for url in urls]
    
    # Detect phishing keywords in subject and body
    phishing_detected = detect_phishing_keywords(subject, body)
    
    # Check for dangerous attachments
    attachments_flagged = check_attachments(attachments)
    
    # If ML model is provided, predict phishing status
    if model and vectorizer:
        is_phishing = predict_phishing(subject, body, model, vectorizer)
    else:
        is_phishing = phishing_detected
    
    # Generate alert
    alert = generate_alert(subject, body, urls, attachments, is_phishing, url_reputations)
    return alert
