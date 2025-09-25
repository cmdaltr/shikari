# 🏹 Archer: Threat Hunting Python Service

Archer is a modular Python package/service designed for automated threat hunting, integrating VECTR, MITRE ATT&CK techniques, and workflow automation with n8n. It provides a FastAPI microservice that outputs structured hunt queries in YAML format, ready for correlation and enrichment.

---
<br>

## 1️⃣ Prerequisites

- **Docker & Docker Compose** (for containerized setup)  
- **Python 3.11+** (for local setup)  

---
<br>

## 2️⃣ Clone the repository

```bash
git clone https://github.com/cmdshiftd/archer.git
cd archer
```

---
<br>

## 3️⃣ Setup Options

### Option A: Run with Docker (Recommended)

1. Build and start the service using Docker Compose:

```bash
docker-compose up --build
```

2. The FastAPI service will be available at `http://localhost:8000`.

3. To stop the service, press `Ctrl+C` and then run:

```bash
docker-compose down
```

---
<br>

### Option B: Run Locally with Python

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the FastAPI service:

```bash
uvicorn archer.main:app --reload
```

The service will be available at `http://localhost:8000`.

---
<br>

### Option C: Use as a Console Script

Archer can also be used as a standalone console script for quick queries without running the full service.

1. Install Archer as a package (if published) or install locally:

```bash
pip install .
```

2. Run the console script:

```bash
archer --help
```

3. Example usage:

```bash
archer hunt --technique T1059 --output yaml
```

---
<br>

## ⚙️ Using Archer with n8n

Archer integrates seamlessly with [n8n](https://n8n.io/) for workflow automation.

### Example: Trigger Archer Hunt via HTTP Request Node

1. Add an HTTP Request node in n8n.

2. Configure it to make a POST request to Archer's endpoint:

```
POST http://localhost:8000/hunt
Content-Type: application/json

{
  "techniques": ["T1059", "T1086"],
  "filters": {
    "platform": "windows"
  }
}
```

3. The response will contain the hunt queries in YAML format, which can be parsed and used in subsequent workflow nodes.

---
<br>

### Tips for n8n Integration

- Use the **Function** node to parse YAML responses into JSON for easier manipulation.

- Chain multiple Archer calls to build complex threat hunting workflows.

- Combine Archer outputs with enrichment services (e.g., VirusTotal, MISP) within n8n.

---
<br>

## 📚 References & Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)  
- [VECTR Platform](https://vectr.io/)  
- [FastAPI Documentation](https://fastapi.tiangolo.com/)  
- [n8n Workflow Automation](https://n8n.io/)  
- [Docker Documentation](https://docs.docker.com/)  

---
<br>

## 🤝 Contributing

Feel free to open issues or submit pull requests to improve Archer.

---
<br>

## 📝 License

This project is licensed under the MIT License. See the LICENSE file for details.