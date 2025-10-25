#!/usr/bin/env python3
"""
Test script to verify enhanced chat system provides accurate, database-driven responses
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.database import DatabaseManager
from src.chat_system import ChatSystem
from src.incident_analyzer import IncidentAnalyzer
from datetime import datetime

def setup_test_data():
    """Set up test incidents in database"""
    db_manager = DatabaseManager()
    analyzer = IncidentAnalyzer()
    
    # Create sample logs for testing
    sample_logs = [
        {
            'timestamp': '2025-09-28T09:25:33Z',
            'service': 'EC2',
            'severity': 'ERROR',
            'message': 'MetricReport - CPU 95.50% MEM 57.96% for instance i-060543E',
            'title': 'ERROR - MetricReport - CPU 95.50% MEM 57.96% for instance i-060543E'
        },
        {
            'timestamp': '2025-09-28T09:25:34Z',
            'service': 'EC2',
            'severity': 'ERROR', 
            'message': 'High CPU utilization detected on instance i-060543E',
            'title': 'High CPU utilization alert'
        },
        {
            'timestamp': '2025-09-28T09:25:35Z',
            'service': 'CloudFront',
            'severity': 'WARN',
            'message': 'CloudFront distribution experiencing high latency',
            'title': 'CloudFront latency warning'
        }
    ]
    
    # Analyze and store incidents
    incidents = analyzer.analyze_incidents(sample_logs)
    
    for incident in incidents:
        # Store incident in database
        db_manager.store_incident(incident)
        
        # Store associated logs
        for log in sample_logs:
            if log.get('service') == incident.get('service'):
                db_manager.store_log_entry(
                    incident_id=incident.get('id'),
                    timestamp=log.get('timestamp'),
                    service=log.get('service'),
                    severity=log.get('severity'),
                    message=log.get('message'),
                    metadata={'title': log.get('title')}
                )
    
    return db_manager, incidents

def test_chat_responses():
    """Test various chat queries for structured responses"""
    
    print("Setting up test data...")
    db_manager, test_incidents = setup_test_data()
    
    # Initialize chat system
    chat_system = ChatSystem(db_manager)
    
    # Test queries
    test_queries = [
        "what are the recommended actions for incident INC-3189?",
        "incident INC-3189",
        "why did this incident happen?",
        "how to fix the CPU issue?",
        "what incidents do we have?",
        "show me CloudFront issues"
    ]
    
    print(f"\nTesting {len(test_queries)} chat queries...\n")
    
    for i, query in enumerate(test_queries, 1):
        print(f"=== Test Query {i}: '{query}' ===")
        
        try:
            response = chat_system.get_response(query)
            print(f"Response:\n{response}\n")
            
            # Check if response is structured
            if "## " in response and "### " in response:
                print("✅ Response is properly structured")
            else:
                print("⚠️  Response may not be fully structured")
                
            # Check if response mentions database evidence
            if "database" in response.lower() or "evidence" in response.lower():
                print("✅ Response includes database evidence")
            else:
                print("⚠️  Response may lack database evidence")
                
        except Exception as e:
            print(f"❌ Error: {e}")
        
        print("-" * 80)
    
    # Test specific incident ID query
    if test_incidents:
        incident_id = test_incidents[0].get('id')
        print(f"\n=== Testing Specific Incident ID: {incident_id} ===")
        
        specific_query = f"what are the recommended actions for incident {incident_id}?"
        response = chat_system.get_response(specific_query)
        print(f"Query: {specific_query}")
        print(f"Response:\n{response}")
        
        # Verify incident-specific data
        if incident_id in response:
            print("✅ Response includes specific incident ID")
        if "recommended actions" in response.lower():
            print("✅ Response includes recommended actions")

def test_error_handling():
    """Test error handling and missing data scenarios"""
    
    print("\n=== Testing Error Handling ===")
    
    # Test with empty database
    empty_db = DatabaseManager(":memory:")  # In-memory database
    chat_system = ChatSystem(empty_db)
    
    queries = [
        "what incidents do we have?",
        "incident INC-999",
        "why did this happen?"
    ]
    
    for query in queries:
        print(f"\nQuery (empty DB): '{query}'")
        response = chat_system.get_response(query)
        print(f"Response: {response[:200]}...")
        
        if "no incidents" in response.lower() or "not found" in response.lower():
            print("✅ Properly handles missing data")

if __name__ == "__main__":
    print("Testing Enhanced Chat System with Database-Driven Responses")
    print("=" * 70)
    
    test_chat_responses()
    test_error_handling()
    
    print("\n" + "=" * 70)
    print("Chat system testing completed!")
