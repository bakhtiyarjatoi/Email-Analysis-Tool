# 📧 Email Analysis Tool

## 🚀 Overview
The **Email Analysis Tool** is a powerful web application designed to analyze email headers, extract Indicators of Compromise (IOCs), and check their reputation using **VirusTotal API**. It helps security analysts and SOC teams detect phishing attempts and malicious email sources.

## 🔥 Features
- 📜 **Email Header Analysis**: Extracts key metadata from raw email headers.
- 🔍 **IOC Extraction**: Identifies IPs, domains, and hashes from email headers.
- 🛡 **VirusTotal Integration**: Automatically scans extracted IOCs using VirusTotal API.
- 📂 **File Upload Support**: Accepts `.eml` and `.txt` files for analysis.
- 🎨 **Interactive UI**: Built with Flask, JavaScript, and Bootstrap for a smooth experience.

## 🛠 Installation
1. **Clone the Repository**
   ```bash
   git clone https://github.com/bakhtiyarjatoi/Email-Analysis-Tool.git
   cd Email-Analysis-Tool
   ```

2. **Create a Virtual Environment (Optional but Recommended)**
   ```bash
   python -m venv venv
   source venv/bin/activate   # On macOS/Linux
   venv\Scripts\activate      # On Windows
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set Up VirusTotal API Key**
   - Get your API key from [VirusTotal](https://www.virustotal.com/gui/join-us)
   - Create a `.env` file in the root directory and add:
     ```
     VIRUSTOTAL_API_KEY=your_api_key_here
     ```

5. **Run the Application**
   ```bash
   python app.py
   ```
   The tool will be available at: **http://127.0.0.1:5000**

## 📜 Usage
1. Upload an `.eml` or `.txt` file containing email headers.
2. Click "Analyze Email" to extract metadata and IOCs.
3. Click "Check Email Headers" to display parsed headers.
4. Click "Scan with VirusTotal" to check extracted IOCs.

