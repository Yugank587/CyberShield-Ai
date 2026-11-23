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
├── dataset/
└── README.md
```

## ▶️ Installation

```bash
git clone https://github.com/your-username/cybershield-ai.git
cd cybershield-ai

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt
```

Install **Npcap** on Windows for live packet monitoring.

Then start the application:

```bash
python app.py
```

Open the Flask application in your browser.

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
