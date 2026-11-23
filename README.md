# 🛡️ CyberShield AI

## AI-Based Cybersecurity Threat Detection and Monitoring System

CyberShield AI is an AI-powered cybersecurity threat detection and monitoring platform developed as a **BCA Final-Year Project**. The system combines **machine learning, network traffic analysis, dataset-based threat detection, and live packet monitoring** to identify potential cybersecurity threats and present them through a centralized web-based security interface.

The project is designed to provide a simplified **Security Operations Center (SOC)-style environment** where users can analyze network traffic, monitor live network activity, investigate detected threats, manage security alerts, and generate security reports.

---

## 📌 Project Overview

Modern computer networks generate large volumes of traffic, making manual identification of malicious activity difficult and time-consuming. CyberShield AI addresses this problem by applying machine learning techniques to network traffic data and integrating the detection pipeline with a web-based monitoring system.

The system supports two primary detection approaches:

- **Dataset-Based Threat Detection** using network traffic datasets such as CIC-IDS2017.
- **Live Network Monitoring** using Scapy and Npcap to capture network packets and process network activity for threat detection.

Detected activity is classified by the machine learning system as:

- `BENIGN`
- `ATTACK`

Attack events can then be converted into security alerts with severity levels and stored in the application's database for investigation and management.

---

# 🎯 Objectives

The main objectives of CyberShield AI are:

- Detect malicious network activity using machine learning.
- Analyze cybersecurity network traffic datasets.
- Monitor network traffic in real time.
- Integrate packet capture with machine-learning-based detection.
- Identify potential attacks and generate security alerts.
- Classify detected events according to severity.
- Maintain a history of security analyses.
- Provide a centralized cybersecurity monitoring dashboard.
- Allow users to investigate and resolve detected alerts.
- Generate security reports from collected analysis data.
- Provide a foundation for future real-time threat intelligence and SOC capabilities.

---

# 🏗️ System Architecture

The overall CyberShield AI architecture follows this workflow:

```text
                         CYBERSHIELD AI
                              │
                ┌─────────────┴─────────────┐
                │                           │
        Dataset Analysis              Live Monitoring
                │                           │
        CSV / Network Dataset             Scapy
                │                           │
                └─────────────┬─────────────┘
                              │
                       Data Processing
                              │
                              ▼
                    Feature Extraction
                              │
                              ▼
                     77 ML Features
                              │
                              ▼
                  Machine Learning Model
                              │
                     ┌────────┴────────┐
                     │                 │
                  BENIGN             ATTACK
                     │                 │
                     │                 ▼
                     │          Severity / Risk
                     │                 │
                     └────────┬────────┘
                              ▼
                       Security Alert
                              │
              ┌───────────────┼───────────────┐
              │               │               │
          Dashboard         Alerts          Reports
```

---

# 🚀 Key Features

## 1. User Authentication

CyberShield AI includes a secure authentication system using Flask-Login.

Features include:

- User registration
- User login
- User logout
- Protected application routes
- Password hashing
- User-specific analysis and alert records
- CSRF protection

---

## 2. AI-Based Threat Detection

The core detection engine uses a trained machine learning model to classify network traffic.

The current model supports:

```text
BENIGN
ATTACK
```

The trained model is stored using Joblib and uses **77 CIC-IDS2017-compatible features**.

The model package contains:

```text
model
feature_columns
target_mapping
```

This allows the application to maintain consistency between the feature-processing pipeline and the trained model.

---

# 🤖 Machine Learning Pipeline

The ML detection pipeline follows:

```text
Network Traffic
      │
      ▼
Data Preprocessing
      │
      ▼
Feature Selection
      │
      ▼
77 CIC-IDS2017 Features
      │
      ▼
Trained ML Model
      │
      ▼
Prediction
      │
      ├── BENIGN
      │
      └── ATTACK
              │
              ▼
       Threat Classification
              │
              ▼
         Security Alert
```

The system is designed to use the same feature structure expected by the trained model rather than sending arbitrary raw packet data directly to the classifier.

---

# 📊 CIC-IDS2017 Dataset

CyberShield AI uses the **CIC-IDS2017 dataset** as a major source of cybersecurity network traffic data.

The dataset contains both benign network activity and various types of malicious traffic.

The dataset is used for:

- Machine learning development
- Model evaluation
- Threat classification
- Feature analysis
- Network traffic analysis

The application supports processing network traffic CSV files through its analysis pipeline.

---

# 📁 Dataset Analysis

Users can upload supported CSV network traffic datasets.

The analysis workflow is:

```text
CSV Dataset
    │
    ▼
Upload
    │
    ▼
Validation
    │
    ▼
Data Processing
    │
    ▼
Feature Extraction
    │
    ▼
Machine Learning Prediction
    │
    ▼
BENIGN / ATTACK
    │
    ▼
Threat Statistics
    │
    ▼
Analysis Record
```

The system records information such as:

- Dataset filename
- Number of records
- Number of detected threats
- Analysis status
- Analysis timestamp
- Associated user

---

# 🌐 Live Network Monitoring

CyberShield AI includes a live network monitoring component using **Scapy** and **Npcap**.

The monitor captures network traffic from an available network interface and collects packet-level metadata.

The intended processing architecture is:

```text
Network Interface
       │
       ▼
Scapy Packet Capture
       │
       ▼
Packet Metadata
       │
       ▼
Flow Aggregation
       │
       ▼
Feature Generation
       │
       ▼
77 CIC-IDS2017-Compatible Features
       │
       ▼
Machine Learning Model
       │
       ▼
BENIGN / ATTACK
       │
       ▼
Risk / Severity
       │
       ▼
CyberShield Alert
```
