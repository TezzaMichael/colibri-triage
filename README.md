# Colibrì Triage

Colibrì Triage is an AI-powered triage and automation interface designed for Security Operations Center (SOC) analysts. It helps streamline the analysis of alerts from SIEMs and EDRs (like SentinelOne and Cortex XDR) by providing intelligent context gathering, ECS standardization, and interactive LLM-based reasoning.

🔗 **Repository:** [https://github.com/TezzaMichael/colibri-triage](https://github.com/TezzaMichael/colibri-triage)

## Prerequisites

Before you begin, ensure you have the following installed on your system:
* **Python 3.14** (Required for the backend)
* **Node.js & npm** (Required for the frontend)

## ⚙️ Configuration & Environment Variables

1. Locate the `.env.example` file in the root directory.
2. Rename it to `.env`:
   ```bash
   mv .env.example .env
   ```
3. Open the `.env` file and populate it with your specific API keys, endpoints, and data.

> **💡 Note on "IOC" (Password Manager):**  
> In the source code, you might notice references to **IOC**. This is our custom, internal password manager. If you are deploying this externally, you can safely remove or replace the IOC implementation to use your own secret manager, or simply store your SIEM URLs and credentials directly inside the `.env` file and read them via standard environment variables.

---

## 🚀 Getting Started

### 1. Backend Setup

The backend requires **Python 3.14**. It is highly recommended to use a virtual environment to manage dependencies.

**Create and activate the virtual environment:**

* **Windows:**
  ```cmd
  python -m venv venv
  .\venv\Scripts\activate
  ```

* **Linux / macOS:**
  ```bash
  python3.14 -m venv venv
  source venv/bin/activate
  ```

**Install dependencies and run the server:**
Once the virtual environment is active, install the required packages and start the API server:

```bash
pip install -r requirements.txt
python apicall.py
```
*The backend API should now be running (typically on `localhost:8001`).*

---

### 2. Frontend Setup

Open a new terminal window (keep the backend running) and navigate to the frontend directory to start the React UI.

```bash
cd frontend
npm install
npm run dev
```
*The frontend should now be accessible in your browser (typically at `http://localhost:5173`).*

---

### 3. Colibrì Core Setup

This project acts as the triage logic and user interface for the Colibrì LLM. To run the actual AI model and core services, you need to set up the main Colibrì repository.

Please refer to the official repository for installation and running instructions:
👉 **[https://github.com/JustVugg/colibri.git](https://github.com/JustVugg/colibri.git)**

---

## License
Distributed under the Apache 2.0 License. See LICENSE file for more information.