# CyberShield AI

CyberShield AI is a Flask application for analyzing network-traffic CSV files and monitoring traffic with a machine-learning model.

## Requirements

- Python 3.10 or later
- The saved model at `models/cybershield_model.joblib` (included)

## Run locally

From the project directory, create and activate a virtual environment, then install the dependencies:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Create a local environment file and start the application:

```powershell
Copy-Item .env.example .env
flask --app app init-db
flask --app app run
```

Open the local URL printed by Flask. Set a unique `SECRET_KEY` in `.env` before using the app beyond local development.

## Training data

The CIC-IDS2017 CSV files are not included in this repository because the full dataset is large and several files exceed GitHub's 100 MB per-file limit. Obtain the dataset from its official source and put the CSV files in `datasets/` to train the model or run the included dataset utilities.

Train a model with:

```powershell
python ml\train_model.py
```

The training script writes the model to `models/cybershield_model.joblib`.

## Notes

- Local databases, uploads, environment files, virtual environments, and generated reports are excluded from Git.
- Live packet monitoring may require appropriate operating-system permissions and a supported network-capture interface.
