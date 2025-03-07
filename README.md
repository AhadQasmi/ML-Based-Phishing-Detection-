# PhishEagle - Machine Learning-Based Phishing Detection System
## Overview
Phishing has emerged as a significant cybersecurity threat, affecting both individuals and organizations. Phishing URLs are deceptively crafted to appear legitimate, but they redirect users to malicious sites aimed at stealing sensitive information.

The **PhishEagle** system was developed to combat these phishing attacks by leveraging advanced machine learning techniques. Utilizing a **Random Forest** model trained on a comprehensive Mendeley dataset from 2020, PhishEagle excels in identifying recent phishing attempts with remarkable accuracy.

### Key Features
- **High Accuracy**: Achieved an impressive classification accuracy of **99.40%**, effectively distinguishing between phishing and legitimate URLs.
- **User-Friendly Browser Extension**: Integrated as a browser extension, allowing users to easily input URLs for immediate classification.

This project is a vital step toward enhancing online security and empowering users to avoid phishing risks.

## Getting Started

### Prerequisites
- Ensure you have Python installed on your machine.
- Install Flask to create the local server:
   ```bash
   pip install flask

### Installation and Setup
 - Clone the Repository:
 - To clone the repository, use the following command:
   ```bash
   git clone https://github.com/AhadQasmi/ML-Based-Phishing-Detection-.git

-Configure the Local Server:
  - Navigate to the project directory and run the Flask application to set up the 
    local server
     ```bash
     python app.py


Load the Browser Extension:
Open Chrome and navigate to chrome://extensions/.
Enable Developer Mode.
Click on Load unpacked and select the extension directory.

### Usage
After loading the extension, you can enter a URL in the input field. The system will classify the URL as either phishing or legitimate based on its training.

### Technical Specifications
Programming Language: Python
Data Processing Libraries: Utilizes various Python libraries for feature extraction and data cleaning.
User Interface: Built with HTML, CSS, and JavaScript, complemented by a Flask API for communication between the extension and the backend

  



