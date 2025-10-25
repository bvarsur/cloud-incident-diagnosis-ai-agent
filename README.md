# 🚨 Cloud Infrastructure Incident Diagnosis AI Agent

A comprehensive AI-powered system for analyzing cloud infrastructure logs, detecting incidents, and providing actionable insights. Built with Python, Streamlit, and local LLM integration.

## 🌟 Features

### 📊 Dashboard
- **Incident Statistics**: Total incidents, severity distribution, affected services
- **Interactive Charts**: Timeline analysis, severity pie charts, trend visualization
- **Real-time Metrics**: Resolution times, incident frequency, service health

### 📁 Log Processing
- **Multi-Cloud Support**: AWS CloudWatch, Azure Monitor, GCP Logging
- **Smart Parsing**: Automatic log format detection and normalization
- **Canonical Schema**: Unified log structure across all cloud providers

### 🤖 AI-Powered Analysis
- **Local LLM Integration**: Ollama and Transformers support
- **Incident Detection**: Pattern recognition and anomaly detection
- **Root Cause Analysis**: AI-generated diagnostic reports
- **Remediation Suggestions**: Actionable recommendations

### 💬 Chat Assistant
- **Natural Language Queries**: Ask questions about incidents in plain English
- **Time-based Queries**: "What happened at 14:00?"
- **Service-specific Analysis**: "Show me database issues"
- **Solution Recommendations**: "How to fix connection timeouts?"

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Streamlit     │    │   Log Parser    │    │  Local LLM      │
│   Frontend      │◄──►│   & Analyzer     │◄──►│  Integration    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   SQLite        │    │   Chat System   │    │   Dashboard     │
│   Database      │    │   & Queries     │    │   Visualizations│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- 8GB+ RAM (for local LLM)
- Git

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd incident-ai-agent
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Set up local LLM (Optional)**
```bash
# For Ollama (recommended)
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama2

# For Transformers (alternative)
# Models will be downloaded automatically on first use
```

4. **Run the application**
```bash
# Option 1: Direct command
streamlit run app.py

# Option 2: Using Python module
python -m streamlit run app.py

# Option 3: Use the provided scripts
# Windows Batch:
run_app.bat

# Windows PowerShell:
.\run_app.ps1
```

5. **Open your browser**
Navigate to `http://localhost:8501`

## 📖 Usage Guide

### 1. Upload Logs
- **Upload File**: Drag and drop log files (JSON, TXT, LOG)
- **Paste Text**: Copy-paste raw log data
- **Paste JSON**: Structured JSON logs

### 2. Analyze Incidents
- Automatic incident detection and severity assessment
- Root cause analysis with confidence levels
- Actionable remediation recommendations

### 3. Chat with AI
- **Time Queries**: "What happened at 14:30?"
- **Service Queries**: "Show me API gateway issues"
- **Severity Queries**: "What are the critical incidents?"
- **Solution Queries**: "How to fix database timeouts?"

### 4. Dashboard Analysis
- View incident trends and patterns
- Filter by severity, service, or time range
- Export reports and insights

## 🔧 Configuration

### Local LLM Setup

#### Option 1: Ollama (Recommended)
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model
ollama pull llama2
ollama pull mistral

# Update app.py to use Ollama
llm = LocalLLM(model_type="ollama", model_name="llama2")
```

#### Option 2: Transformers
```python
# Update app.py to use Transformers
llm = LocalLLM(model_type="transformers", model_name="microsoft/DialoGPT-medium")
```

### Database Configuration
The system uses SQLite by default. To use a different database:

```python
# In app.py
db_manager = DatabaseManager(db_path="custom_incidents.db")
```

## 📁 Project Structure

```
incident-ai-agent/
├── app.py                 # Main Streamlit application
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── src/                  # Source code modules
│   ├── __init__.py
│   ├── log_parser.py     # Log parsing and normalization
│   ├── incident_analyzer.py # Incident detection logic
│   ├── database.py       # Database operations
│   ├── chat_system.py    # Chat interface
│   └── local_llm.py      # Local LLM integration
├── sample_data/          # Sample log files
│   ├── cloudwatch_logs.json
│   ├── azure_logs.json
│   └── gcp_logs.json
└── incidents.db          # SQLite database (created automatically)
```

## 🎯 Example Use Cases

### 1. AWS CloudWatch Analysis
```json
{
  "timestamp": "2024-01-15T14:30:15Z",
  "service": "api-gateway",
  "severity": "ERROR",
  "message": "HTTP 500 Internal Server Error - Database connection timeout"
}
```

**AI Analysis**: Detects database connectivity issues, suggests connection pool optimization.

### 2. Azure Monitor Integration
```json
{
  "timestamp": "2024-01-15T15:45:10Z",
  "service": "web-app",
  "severity": "ERROR",
  "message": "Application Insights: Exception in user controller - NullReferenceException"
}
```

**AI Analysis**: Identifies application-level exceptions, recommends code review and null checks.

### 3. GCP Cloud Run Issues
```json
{
  "timestamp": "2024-01-15T16:20:05Z",
  "service": "cloud-run",
  "severity": "ERROR",
  "message": "Cloud Run: Container failed to start - Out of memory"
}
```

**AI Analysis**: Detects memory issues, suggests resource allocation adjustments.

## 🔍 Advanced Features

### Custom Log Parsers
Extend the system for custom log formats:

```python
class CustomLogParser(LogParser):
    def parse_custom_format(self, logs):
        # Your custom parsing logic
        pass
```

### Custom Incident Detection
Add domain-specific incident patterns:

```python
class CustomIncidentAnalyzer(IncidentAnalyzer):
    def detect_custom_patterns(self, logs):
        # Your custom detection logic
        pass
```

### API Integration
The system can be extended with REST APIs:

```python
# Example API endpoint
@app.route('/api/incidents', methods=['GET'])
def get_incidents():
    return db_manager.get_all_incidents()
```

## 🛠️ Troubleshooting

### Common Issues

1. **LLM Not Working**
   - Ensure Ollama is running: `ollama serve`
   - Check model availability: `ollama list`
   - Verify model name in configuration

2. **Database Errors**
   - Check file permissions for SQLite database
   - Ensure sufficient disk space
   - Verify database schema initialization

3. **Memory Issues**
   - Reduce batch size for large log files
   - Use smaller LLM models
   - Increase system RAM

### Performance Optimization

1. **Large Log Files**
   - Process logs in batches
   - Use streaming for real-time analysis
   - Implement log rotation

2. **LLM Performance**
   - Use quantized models
   - Implement caching for repeated queries
   - Consider GPU acceleration

## 📊 Sample Data

The `sample_data/` directory contains example logs from:
- **AWS CloudWatch**: API Gateway and database errors
- **Azure Monitor**: Application Insights exceptions
- **GCP Logging**: Cloud Run container failures

Use these files to test the system functionality.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section
2. Review existing GitHub issues
3. Create a new issue with detailed information

## 🔮 Roadmap

- [ ] Real-time log streaming
- [ ] Advanced ML models for anomaly detection
- [ ] Multi-tenant support
- [ ] REST API endpoints
- [ ] Docker containerization
- [ ] Kubernetes deployment
- [ ] Grafana integration
- [ ] Slack/Teams notifications

---

