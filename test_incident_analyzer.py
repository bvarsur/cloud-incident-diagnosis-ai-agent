#!/usr/bin/env python3
"""
Test script to verify incident analyzer is generating recommendations properly
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.incident_analyzer import IncidentAnalyzer
from datetime import datetime
import json

def test_cpu_memory_incident():
    """Test incident analyzer with CPU and memory logs"""
    
    # Create sample logs similar to what's shown in the screenshot
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
            'service': 'EC2',
            'severity': 'WARN',
            'message': 'Memory usage approaching threshold on instance i-060543E',
            'title': 'Memory threshold warning'
        },
        {
            'timestamp': '2025-09-28T09:25:36Z',
            'service': 'EC2',
            'severity': 'ERROR',
            'message': 'Performance degradation detected due to resource constraints',
            'title': 'Performance alert'
        },
        {
            'timestamp': '2025-09-28T09:25:37Z',
            'service': 'CloudWatch',
            'severity': 'INFO',
            'message': 'Metrics collected for EC2 instance monitoring',
            'title': 'Metrics collection'
        }
    ]
    
    # Initialize analyzer
    analyzer = IncidentAnalyzer()
    
    # Analyze incidents
    print("Analyzing sample logs...")
    incidents = analyzer.analyze_incidents(sample_logs)
    
    print(f"\nFound {len(incidents)} incidents")
    
    for i, incident in enumerate(incidents, 1):
        print(f"\n--- Incident {i} ---")
        print(f"ID: {incident.get('id')}")
        print(f"Title: {incident.get('title')}")
        print(f"Severity: {incident.get('severity')}")
        print(f"Service: {incident.get('service')}")
        print(f"Root Cause: {incident.get('root_cause')}")
        print(f"Log Count: {incident.get('log_count')}")
        
        # Check error counts
        error_counts = incident.get('error_counts', {})
        print(f"\nError Counts:")
        for error_type, count in error_counts.items():
            print(f"  - {error_type}: {count}")
        
        # Check recommended actions
        recommended_actions = incident.get('recommended_actions', [])
        print(f"\nRecommended Actions ({len(recommended_actions)} found):")
        if recommended_actions:
            for j, action in enumerate(recommended_actions, 1):
                print(f"  {j}. {action}")
        else:
            print("  No recommended actions found!")
        
        # Check diagnostic report
        diagnostic_report = incident.get('diagnostic_report', {})
        print(f"\nDiagnostic Report:")
        if isinstance(diagnostic_report, dict):
            if 'recommended_actions' in diagnostic_report:
                dr_actions = diagnostic_report['recommended_actions']
                print(f"  - Actions in diagnostic report: {len(dr_actions)}")
                for j, action in enumerate(dr_actions[:3], 1):
                    print(f"    {j}. {action}")
            
            if 'summary' in diagnostic_report:
                summary = diagnostic_report['summary']
                print(f"  - Severity Score: {summary.get('severity_score', 'N/A')}")
                print(f"  - Error Rate: {summary.get('error_rate', 'N/A')}")
            
            if 'technical_details' in diagnostic_report:
                tech_details = diagnostic_report['technical_details']
                print(f"  - Technical Error Rate: {tech_details.get('error_rate', 'N/A')}")
        
        print("\n" + "="*60)

if __name__ == "__main__":
    test_cpu_memory_incident()
