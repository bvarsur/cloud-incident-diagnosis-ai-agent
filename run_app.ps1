# Cloud Infrastructure Incident Diagnosis AI Agent Launcher
Write-Host "🚨 Starting Cloud Infrastructure Incident Diagnosis AI Agent..." -ForegroundColor Green
Write-Host ""

Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt

Write-Host ""
Write-Host "🚀 Starting Streamlit application..." -ForegroundColor Green
Write-Host "🌐 Open your browser to http://localhost:8501" -ForegroundColor Cyan
Write-Host ""

streamlit run app.py
