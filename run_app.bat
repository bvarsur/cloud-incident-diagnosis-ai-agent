@echo off
echo Starting Cloud Infrastructure Incident Diagnosis AI Agent...
echo.
echo Installing dependencies...
pip install -r requirements.txt
echo.
echo Starting Streamlit application...
echo Open your browser to http://localhost:8501
echo.
streamlit run app.py
pause
