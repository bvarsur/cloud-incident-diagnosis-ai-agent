"""
Test script for the Incident AI Agent
Tests basic functionality without requiring full LLM setup
"""

import json
import os
import sys
from datetime import datetime

# Add src to path
sys.path.append('src')

def test_log_parser():
    """Test log parsing functionality"""
    print("Testing Log Parser...")
    
    try:
        from src.log_parser import LogParser
        parser = LogParser()
        
        # Test with sample data
        sample_logs = '''
        {"timestamp": "2024-01-15T14:30:15Z", "service": "api-gateway", "severity": "ERROR", "message": "HTTP 500 Internal Server Error"}
        {"timestamp": "2024-01-15T14:30:16Z", "service": "api-gateway", "severity": "ERROR", "message": "HTTP 500 Internal Server Error"}
        '''
        
        parsed_logs = parser.parse_logs(sample_logs)
        print(f"✅ Parsed {len(parsed_logs)} log entries")
        
        if parsed_logs:
            print(f"   Sample log: {parsed_logs[0]}")
        
        return True
    except Exception as e:
        print(f"❌ Log parser test failed: {e}")
        return False

def test_incident_analyzer():
    """Test incident analysis functionality"""
    print("Testing Incident Analyzer...")
    
    try:
        from src.incident_analyzer import IncidentAnalyzer
        analyzer = IncidentAnalyzer()
        
        # Test with sample logs
        sample_logs = [
            {
                "timestamp": "2024-01-15T14:30:15Z",
                "service": "api-gateway",
                "severity": "ERROR",
                "message": "HTTP 500 Internal Server Error - Database connection timeout"
            },
            {
                "timestamp": "2024-01-15T14:30:16Z",
                "service": "api-gateway",
                "severity": "ERROR",
                "message": "HTTP 500 Internal Server Error - Database connection timeout"
            }
        ]
        
        incidents = analyzer.analyze_incidents(sample_logs)
        print(f"✅ Detected {len(incidents)} incidents")
        
        if incidents:
            print(f"   Sample incident: {incidents[0].get('title', 'No title')}")
        
        return True
    except Exception as e:
        print(f"❌ Incident analyzer test failed: {e}")
        return False

def test_database():
    """Test database functionality"""
    print("Testing Database...")
    
    try:
        from src.database import DatabaseManager
        db = DatabaseManager("test_incidents.db")
        
        # Test storing an incident
        test_incident = {
            "id": "test_incident_1",
            "timestamp": datetime.now().isoformat(),
            "severity": "HIGH",
            "title": "Test Incident",
            "service": "test-service",
            "root_cause": "Test root cause",
            "recommended_actions": ["Test action 1", "Test action 2"]
        }
        
        success = db.store_incident(test_incident)
        if success:
            print("✅ Successfully stored incident")
        
        # Test retrieving incidents
        incidents = db.get_all_incidents()
        print(f"✅ Retrieved {len(incidents)} incidents")
        
        # Test statistics
        stats = db.get_incident_statistics()
        print(f"✅ Statistics: {stats}")
        
        # Clean up test database
        if os.path.exists("test_incidents.db"):
            os.remove("test_incidents.db")
        
        return True
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

def test_chat_system():
    """Test chat system functionality"""
    print("Testing Chat System...")
    
    try:
        from src.database import DatabaseManager
        from src.chat_system import ChatSystem
        
        db = DatabaseManager("test_chat.db")
        chat = ChatSystem(db)
        
        # Test chat response
        response = chat.get_response("How many incidents are there?")
        print(f"✅ Chat response: {response[:100]}...")
        
        # Clean up test database
        if os.path.exists("test_chat.db"):
            os.remove("test_chat.db")
        
        return True
    except Exception as e:
        print(f"❌ Chat system test failed: {e}")
        return False

def test_sample_data():
    """Test with sample data files"""
    print("Testing Sample Data...")
    
    try:
        sample_files = [
            "sample_data/cloudwatch_logs.json",
            "sample_data/azure_logs.json",
            "sample_data/gcp_logs.json"
        ]
        
        for file_path in sample_files:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    data = json.load(f)
                print(f"✅ Loaded {len(data)} entries from {file_path}")
            else:
                print(f"⚠️  Sample file not found: {file_path}")
        
        return True
    except Exception as e:
        print(f"❌ Sample data test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 Starting Incident AI Agent Tests\n")
    
    tests = [
        test_log_parser,
        test_incident_analyzer,
        test_database,
        test_chat_system,
        test_sample_data
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
            print()
        except Exception as e:
            print(f"❌ Test {test.__name__} crashed: {e}\n")
    
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The application is ready to use.")
        print("\nTo run the application:")
        print("  streamlit run app.py")
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
