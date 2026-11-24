# 🛡️ CyberShield AI

**AI-Based Cybersecurity Threat Detection and Monitoring System**

CyberShield AI is a web-based cybersecurity platform developed as a **BCA Final-Year Project**. It combines **Machine Learning, network traffic analysis, dataset-based threat detection, and live packet monitoring** to identify suspicious and malicious network activity.

## 🚀 Key Features

- 🔐 User registration, login and secure authentication
- 🤖 AI/ML-based network threat detection
- 📊 CIC-IDS2017 dataset analysis
- 🌐 Live network packet monitoring using Scapy
- 🚨 Automated security alerts
- ⚠️ Threat severity and risk assessment
- 📈 Security dashboard and analytics
- 📄 Security reports
- 🗄️ SQLite database for users, analyses and alerts
- 🛡️ CSRF protection and password hashing

## 🧠 Machine Learning

CyberShield AI uses a trained model compatible with **77 CIC-IDS2017 network traffic features**.

**Detection flow:**

`Network Traffic → Flow Features → ML Model → BENIGN / ATTACK → Severity → Alert`

The trained model is stored in:

```text
models/cybershield_model.joblib
```

## 🌐 Live Monitoring

Live monitoring uses:

- **Scapy** for packet capture
- **Npcap** for Windows packet access
- Flow aggregation
- ML-based traffic classification
- Automated alert generation

Raw packets are **not directly passed** to the CIC-IDS2017 model. They are first converted into the required flow-level features.

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Backend & ML |
| Flask | Web framework |
| Flask-SQLAlchemy | Database |
| Flask-Login | Authentication |
| Scapy | Network monitoring |
| Scikit-learn | Machine Learning |
| Pandas / NumPy | Data processing |
| SQLite | Database |
| HTML / CSS / JavaScript | Frontend |
| Npcap | Packet capture |

## 📁 Project Structure

```text
CyberShield-AI/
├── app.py
├── extensions.py
├── requirements.txt
├── models/
│   └── cybershield_model.joblib
├── templates/
├── static/
├── datasets/
└── README.md
```

## ▶️ Run locally (Windows)

1. Install **Python 3.11 or later** and Git. Clone the repository (you must have access to this private repository):

   ```powershell
   git clone https://github.com/Yugank587/Cyber-shield-ai.git
   cd Cyber-shield-ai
   ```

2. Create a virtual environment and install the dependencies:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   ```

   If PowerShell blocks activation, use the virtual environment's Python directly:

   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

3. Create your local settings file:

   ```powershell
   Copy-Item .env.example .env
   ```

   For anything beyond local testing, replace `SECRET_KEY` in `.env` with a random value. You can generate one with:

   ```powershell
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

4. Start the app:

   ```powershell
   python app.py
   ```

   If you skipped activation, run `.\.venv\Scripts\python.exe app.py` instead.

5. Open **http://127.0.0.1:5000** in your browser and register an account.

The app creates its local SQLite database automatically. The trained model is included. For live packet monitoring on Windows, install **Npcap** with **WinPcap API-compatible Mode** and run the app with the permissions required to capture traffic (typically from an elevated terminal). On the Live Monitor page, select the network adapter that is actually carrying the traffic (for example, Wi-Fi rather than disconnected Ethernet). If capture stops, the monitor displays the capture error; check that Npcap is running and that the app has capture permissions. The CIC-IDS2017 CSV files are not included; add them to `datasets/` if you want to train the model or use the dataset utility scripts.

## 🎓 Project Purpose

CyberShield AI demonstrates how **Artificial Intelligence and Network Security** can be combined to build a practical cybersecurity monitoring system capable of detecting and managing potential network threats.

## 🔮 Future Enhancements

- Advanced threat intelligence
- Improved real-time ML detection
- Automated incident response
- Advanced network analytics
- Audit logging
- User profile and system settings
- Dark/Light theme
- Advanced security reports
