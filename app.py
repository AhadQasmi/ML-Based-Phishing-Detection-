from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import requests
import whois
import dns.resolver
import socket
from urllib.parse import urlparse
import tldextract
from datetime import datetime
import time
import pandas as pd
import os

# Initialize the Flask application
app = Flask(__name__)
CORS(app)   

# Load the trained model and the feature names
model = joblib.load('Model/random_forest_model.pkl')
top_20_feature_names = joblib.load('Model/feature_names.pkl')

def extract_features(url):
    features = []

    # Feature1 directory_length 
    try:
        parsed_url = urlparse(url)
        url_path = parsed_url.path.rsplit('/', 1)[0]
        features.append(len(url_path) if url_path else 0)
    except:
        features.append(0)

    # Feature2 time_domain_activation
    try:
        domain_info = whois.whois(url)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        features.append((datetime.now() - creation_date).days)
    except:
        features.append(-1) 

    # Feature3 asn_ip
    try:
        ip = socket.gethostbyname(urlparse(url).netloc)
        asn = requests.get(f"https://ipapi.co/{ip}/asn/").text.strip()
        features.append(asn.strip('AS')) if asn else features.append(0)
    except:
        features.append(0)

    # Feature4 time_response
    try:
        start = time.time()
        response = requests.get(url, timeout=5)
        end = time.time()
        features.append(end - start)
    except:
        features.append(0.207)

    # Feature5 length_url
    try:
        features.append(len(url))
    except:
        features.append(0)

    # Feature6 ttl_hostname
    try:
        domain = tldextract.extract(url).registered_domain
        ttl = dns.resolver.resolve(domain, 'NS').rrset.ttl
        features.append(ttl)
    except:
        features.append(0)

    # Feature7 qty_dot_domain
    try:
        domain = urlparse(url).netloc
        features.append(domain.count('.') if '.' in domain else 0)
    except:
        features.append(0)

    # Feature8 time_domain_expiration
    try:
        expiration_date = whois.whois(url).expiration_date
        today = datetime.now()
        features.append((expiration_date - today).days)
    except:
        features.append(-1)

    # Feature9 qty_nameservers
    try:
        domain = tldextract.extract(url).registered_domain
        ns_list = dns.resolver.resolve(domain, 'NS')
        features.append(len(ns_list))
    except:
        features.append(0)

    # Feature10 domain_length
    try:
        domain = urlparse(url).netloc
        features.append(len(domain) if domain else 0)
    except:
        features.append(0)

    # Feature11 qty_slash_url
    try:
        features.append(url.count('/') if '/' in url else 0)
    except:
        features.append(0)

    # Feature12 qty_mx_servers
    try:
        domain = tldextract.extract(url).registered_domain
        mx_list = dns.resolver.resolve(domain, 'MX')
        features.append(len(mx_list))
    except:
        features.append(0)

    # Features13 qty_hyphen_directory
    try:
        parsed_url = urlparse(url)
        url_path = parsed_url.path.rsplit('/', 1)[0]
        features.append(url_path.count('-') if '-' in url_path else 0)
    except:
        features.append(0)

    # Feature14 qty_vowels_domain
    try:
        domain = urlparse(url).netloc
        vowels = set(['a', 'e', 'i', 'o', 'u', 'A','E','I','O','U'])
        qty_vowels = sum(1 for c in domain if c in vowels)
        features.append(qty_vowels)
    except:
        features.append(0)

    # Feature15 qty_ip_resolved
    try:
        ip_list = socket.getaddrinfo(urlparse(url).netloc, None)
        features.append(len(ip_list))
    except:
        features.append(-1)

    # Feature16 file_length
    try:
        file_name = os.path.basename(urlparse(url).path)
        features.append(len(file_name) if file_name else 0)
    except:
        features.append(0)

    # Feature17 qty_redirects
    try:
        response = requests.get(url)
        features.append(len(response.history))
    except:
        features.append(-1)

    # Feature18 qty_slash_directory
    try:
        parsed_url = urlparse(url)
        url_path = parsed_url.path.rsplit('/', 1)[0]
        features.append(url_path.count('/') if '/' in url_path else 0)
    except:
        features.append(0)

    # Feature19 qty_dot_url
    try:
        features.append(url.count('.') if '.' in url else 0)
    except:
        features.append(0)

    # Feature 20: qty_dot_file
    try:
        file_name = os.path.basename(urlparse(url).path)
        features.append(file_name.count('.') if '.' in file_name else 0)
    except:
        features.append(0)

    return features

@app.route('/check_url', methods=['POST'])
def check_url():
    data = request.get_json()  
    url = data['url']  
    features = extract_features(url)  
    if features is not None:
        features_df = pd.DataFrame([features], columns=top_20_feature_names)  
        prediction = model.predict(features_df)  
        result = 'phishing' if prediction[0] == 1 else 'legitimate' 
    else:
        result = 'error'  
    return jsonify({'result': result})  

if __name__ == '__main__':
    app.run(debug=True)  # Run the Flask in debug mode

