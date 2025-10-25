"""
Cloud Infrastructure Incident Diagnosis AI Agent
Main Streamlit application
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import sqlite3
from typing import List, Dict, Any
import os
import tornado.websocket
import traceback

from src.log_parser import LogParser
from src.incident_analyzer import IncidentAnalyzer
from src.database import DatabaseManager
from src.chat_system import ChatSystem

# Configure Streamlit page
st.set_page_config(
    page_title="Incident AI Agent",
    page_icon="🚨",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Handle WebSocket errors gracefully
def handle_websocket_error():
    try:
        yield
    except tornado.websocket.WebSocketClosedError:
        st.warning("WebSocket connection closed. Please refresh the page if you experience issues.")
        # Prevent cascading errors by catching the exception
        return None
    except tornado.iostream.StreamClosedError:
        st.warning("Stream connection closed. Please refresh the page to reconnect.")
        return None
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")
        traceback.print_exc()
        return None

# Initialize session state
if 'incidents' not in st.session_state:
    st.session_state.incidents = []
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

def main():
    st.title("🚨 Cloud Infrastructure Incident Diagnosis AI Agent")
    st.markdown("Upload logs from AWS, Azure, or GCP to diagnose incidents and get actionable insights")
    
    # Initialize components
    db_manager = DatabaseManager()
    log_parser = LogParser()
    incident_analyzer = IncidentAnalyzer()
    chat_system = ChatSystem(db_manager)
    
    # Create tabs for navigation
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "📁 Upload Logs", "💬 Chat Assistant", "🔍 Incident Diagnosis"])
    
    with tab1:
        show_dashboard(db_manager)
    
    with tab2:
        show_upload_page(log_parser, incident_analyzer, db_manager)
    
    with tab3:
        show_chat_interface(chat_system)
    
    with tab4:
        show_incident_diagnosis(db_manager)

def show_dashboard(db_manager: DatabaseManager):
    """Enhanced dashboard with mature information and detailed analytics"""
    st.header("📊 Advanced Incident Dashboard")
    
    # Add database management options
    with st.expander("⚙️ Database Management", expanded=False):
        st.warning("⚠️ Warning: These actions cannot be undone!")
        if st.button("🗑️ Clean Database", help="Remove all incidents, logs, and chat history from the database"):
            if db_manager.clean_database():
                st.success("✅ Database cleaned successfully! Refresh the page to see the changes.")
                # Clear session state to reflect the changes
                if 'incidents' in st.session_state:
                    st.session_state.incidents = []
                if 'chat_history' in st.session_state:
                    st.session_state.chat_history = []
            else:
                st.error("❌ Failed to clean the database. Please check the logs for details.")
    
    # Get incident statistics
    stats = db_manager.get_incident_statistics()
    
    if not stats or stats.get('total_incidents', 0) == 0:
        st.info("📈 No incidents found. Upload some logs to see the dashboard.")
        st.markdown("""
        ### Getting Started
        1. Go to the **📁 Upload Logs** tab
        2. Choose **Use Sample Data** option
        3. Select a sample log file (AWS, Azure, or GCP)
        4. Click **🔍 Analyze Logs** to process the data
        5. Return to this dashboard to see the results
        """)
        return
    
    # Advanced Key metrics
    st.subheader("📈 Executive Summary")
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric(
            label="Total Incidents", 
            value=stats.get('total_incidents', 0),
            delta=f"+{stats.get('total_incidents', 0)} total"
        )
    
    with col2:
        st.metric(
            label="Critical Issues", 
            value=stats.get('high_severity', 0),
            delta=f"{stats.get('high_severity', 0)} high priority"
        )
    
    with col3:
        st.metric(
            label="Services Affected", 
            value=stats.get('unique_services', 0),
            delta="active services"
        )
    
    with col4:
        st.metric(
            label="Avg Resolution", 
            value=f"{stats.get('avg_resolution_time', 0):.1f}h",
            delta="mean time to resolve"
        )
    
    with col5:
        # Calculate incident rate
        incident_rate = stats.get('total_incidents', 0) / max(stats.get('unique_services', 1), 1)
        st.metric(
            label="Incident Rate", 
            value=f"{incident_rate:.1f}",
            delta="incidents per service"
        )
    
    st.divider()
    
    # Advanced Analytics Section
    st.subheader("📊 Advanced Analytics")
    
    # Get all incidents for detailed analysis
    all_incidents = db_manager.get_all_incidents()
    
    if all_incidents:
        # Create comprehensive analytics
        df_incidents = pd.DataFrame(all_incidents)
        
        # Convert timestamp to datetime
        df_incidents['timestamp'] = pd.to_datetime(df_incidents['timestamp'], errors='coerce')
        
        # Create multiple chart rows
        row1_col1, row1_col2 = st.columns(2)
        
        with row1_col1:
            # Severity distribution with enhanced colors
            severity_data = db_manager.get_severity_distribution()
            if severity_data:
                color_map = {
                    'CRITICAL': '#DC2626',
                    'HIGH': '#EA580C', 
                    'MEDIUM': '#D97706',
                    'LOW': '#059669'
                }
                colors = [color_map.get(severity, '#6B7280') for severity in severity_data.keys()]
                
                fig = px.pie(
                    values=list(severity_data.values()),
                    names=list(severity_data.keys()),
                    title="🚨 Severity Distribution",
                    color_discrete_sequence=colors
                )
                fig.update_traces(textposition='inside', textinfo='percent+label+value')
                fig.update_layout(showlegend=True, legend=dict(orientation="v", yanchor="top", y=1, xanchor="left", x=1.01))
                st.plotly_chart(fig, use_container_width=True)
        
        with row1_col2:
            # Service distribution
            service_counts = df_incidents['service'].value_counts()
            fig = px.bar(
                x=service_counts.index,
                y=service_counts.values,
                title="🔧 Incidents by Service",
                labels={'x': 'Service', 'y': 'Incident Count'},
                color=service_counts.values,
                color_continuous_scale='Viridis'
            )
            fig.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
        
        # Second row of charts
        row2_col1, row2_col2 = st.columns(2)
        
        with row2_col1:
            # Timeline with trend analysis
            timeline_data = db_manager.get_incident_timeline(days=14)  # Show last 14 days
            if timeline_data:
                df_timeline = pd.DataFrame(timeline_data)
                df_timeline['timestamp'] = pd.to_datetime(df_timeline['timestamp'])
                
                # Fill in missing dates with zero counts
                if len(df_timeline) > 0:
                    date_range = pd.date_range(
                        start=df_timeline['timestamp'].min() - pd.Timedelta(days=1),
                        end=df_timeline['timestamp'].max() + pd.Timedelta(days=1)
                    )
                    df_complete = pd.DataFrame({'timestamp': date_range})
                    df_timeline = pd.merge(df_complete, df_timeline, on='timestamp', how='left')
                    df_timeline['count'] = df_timeline['count'].fillna(0)
                
                fig = px.line(
                    df_timeline, 
                    x='timestamp', 
                    y='count',
                    title="📈 Incident Trends Over Time",
                    markers=True,
                    line_shape='spline'
                )
                fig.update_layout(
                    xaxis_title="Date",
                    yaxis_title="Incident Count",
                    hovermode='x unified'
                )
                st.plotly_chart(fig, use_container_width=True)
        
        with row2_col2:
            # Error type analysis - unique types only
            all_errors = []
            for incident in all_incidents:
                error_counts = incident.get('error_counts', {})
                for error_type, count in error_counts.items():
                    all_errors.extend([error_type] * count)
            
            if all_errors:
                error_series = pd.Series(all_errors)
                error_counts = error_series.value_counts().head(10)
                
                # Clean up error type names for better readability
                cleaned_error_types = {}
                for error_type, count in error_counts.items():
                    # Clean up regex patterns and technical names
                    clean_name = error_type.replace('\\d{2}', 'XX').replace('\\', '').replace('|', ' or ')
                    if clean_name.startswith('5'):
                        clean_name = '5XX Server Errors'
                    elif clean_name.startswith('4'):
                        clean_name = '4XX Client Errors'
                    elif 'timeout' in clean_name.lower():
                        clean_name = 'Timeout Errors'
                    elif 'error' in clean_name.lower():
                        clean_name = 'General Errors'
                    elif 'exception' in clean_name.lower():
                        clean_name = 'Exceptions'
                    
                    cleaned_error_types[clean_name] = count
                
                if cleaned_error_types:
                    fig = px.bar(
                        x=list(cleaned_error_types.values()),
                        y=list(cleaned_error_types.keys()),
                        orientation='h',
                        title="🔍 Top Error Types",
                        labels={'x': 'Count', 'y': 'Error Type'},
                        color=list(cleaned_error_types.values()),
                        color_continuous_scale='Reds'
                    )
                    fig.update_layout(yaxis={'categoryorder':'total ascending'})
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No error type data available")
            else:
                st.info("No error type data available")
    
    st.divider()
    
    # Enhanced Recent incidents with sorting and filtering
    st.subheader("🔍 Recent Incidents Analysis")
    
    # Add filters
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        severity_filter = st.selectbox(
            "Filter by Severity",
            ["All"] + list(set(incident.get('severity', 'Unknown') for incident in all_incidents)),
            key="dashboard_severity_filter"
        )
    
    with col2:
        service_filter = st.selectbox(
            "Filter by Service",
            ["All"] + list(set(incident.get('service', 'Unknown') for incident in all_incidents)),
            key="dashboard_service_filter"
        )
    
    with col3:
        time_filter = st.selectbox(
            "Time Period",
            ["All Time", "Today", "Yesterday", "Past 2 Days", "Past 7 Days", "Past 30 Days"],
            key="dashboard_time_filter"
        )
    
    with col4:
        sort_by = st.selectbox(
            "Sort by",
            ["Timestamp (Newest)", "Timestamp (Oldest)", "Severity", "Service", "Title"],
            key="dashboard_sort_by"
        )
    
    # Apply filters
    filtered_incidents = all_incidents.copy()
    
    if severity_filter != "All":
        filtered_incidents = [i for i in filtered_incidents if i.get('severity') == severity_filter]
    
    if service_filter != "All":
        filtered_incidents = [i for i in filtered_incidents if i.get('service') == service_filter]
    
    # Time period filter
    if time_filter != "All Time":
        now = pd.Timestamp.now()
        if time_filter == "Today":
            cutoff = now - pd.Timedelta(days=1)
        elif time_filter == "Yesterday":
            start = now - pd.Timedelta(days=2)
            end = now - pd.Timedelta(days=1)
            filtered_incidents = [
                i for i in filtered_incidents 
                if i.get('timestamp') and 
                pd.to_datetime(i.get('timestamp', ''), errors='coerce') >= start and
                pd.to_datetime(i.get('timestamp', ''), errors='coerce') < end
            ]
        elif time_filter == "Past 2 Days":
            cutoff = now - pd.Timedelta(days=2)
        elif time_filter == "Past 7 Days":
            cutoff = now - pd.Timedelta(days=7)
        elif time_filter == "Past 30 Days":
            cutoff = now - pd.Timedelta(days=30)
        else:
            cutoff = None
        
        if cutoff and time_filter != "Yesterday":
            filtered_incidents = [
                i for i in filtered_incidents 
                if i.get('timestamp') and 
                pd.to_datetime(i.get('timestamp', ''), errors='coerce') >= cutoff
            ]
    
    # Apply sorting
    if sort_by == "Timestamp (Newest)":
        filtered_incidents.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    elif sort_by == "Timestamp (Oldest)":
        filtered_incidents.sort(key=lambda x: x.get('timestamp', ''))
    elif sort_by == "Severity":
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        filtered_incidents.sort(key=lambda x: severity_order.get(x.get('severity', 'LOW'), 4))
    elif sort_by == "Service":
        filtered_incidents.sort(key=lambda x: x.get('service', ''))
    elif sort_by == "Title":
        filtered_incidents.sort(key=lambda x: x.get('title', ''))
    
    # Display filtered results
    if filtered_incidents:
        st.write(f"**Showing {len(filtered_incidents)} incidents**")
        
        # Create enhanced dataframe with human-readable time
        display_data = []
        for incident in filtered_incidents[:20]:  # Limit to 20 for performance
            # Convert timestamp to human-readable format
            timestamp = incident.get('timestamp', 'Unknown')
            if timestamp != 'Unknown':
                try:
                    dt = pd.to_datetime(timestamp)
                    human_time = dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    human_time = timestamp[:16]  # Fallback to original format
            else:
                human_time = 'Unknown'
            
            # Get full root cause text
            root_cause = incident.get('root_cause', 'Unknown')
            
            # Get region if available
            region = incident.get('region', 'N/A')
            
            # Get error counts if available
            error_counts = incident.get('error_counts', {})
            error_summary = ", ".join([f"{k}: {v}" for k, v in error_counts.items()][:3])
            if len(error_counts) > 3:
                error_summary += f" (+{len(error_counts) - 3} more)"
            
            display_data.append({
                "🕒 Time": human_time,
                "🚨 Severity": incident.get('severity', 'Unknown'),
                "🔧 Service": incident.get('service', 'Unknown'),
                "📝 Title": incident.get('title', 'No title'),
                "🌎 Region": region,
                "🎯 Root Cause": root_cause[:100] + ("..." if len(root_cause) > 100 else ""),
                "⚠️ Errors": error_summary if error_summary else "N/A",
                "📊 Count": incident.get('log_count', 0)
            })
        
        if display_data:
            df = pd.DataFrame(display_data)
            
            # Enhanced color coding
            def color_severity(val):
                if val == 'CRITICAL':
                    return 'background-color: #DC2626; color: white; font-weight: bold'
                elif val == 'HIGH':
                    return 'background-color: #EA580C; color: white; font-weight: bold'
                elif val == 'MEDIUM':
                    return 'background-color: #D97706; color: white; font-weight: bold'
                elif val == 'LOW':
                    return 'background-color: #059669; color: white; font-weight: bold'
                return ''
            
            styled_df = df.style.applymap(color_severity, subset=['🚨 Severity'])
            st.dataframe(styled_df, use_container_width=True, height=500)
        else:
            st.info("No data to display")
    else:
        st.info("No incidents match the selected filters.")
    
    # Add refresh button
    if st.button("🔄 Refresh Dashboard", type="primary"):
        st.rerun()

def show_upload_page(log_parser: LogParser, incident_analyzer: IncidentAnalyzer, db_manager: DatabaseManager):
    """Enhanced log upload and processing with detailed diagnostic reports"""
    st.header("📁 Log Upload & Analysis")
    
    # Upload options with sample data option
    upload_method = st.radio(
        "Choose upload method:",
        ["Upload File", "Paste Text/JSON", "Use Sample Data"]
    )
    
    logs_data = None
    
    if upload_method == "Upload File":
        uploaded_file = st.file_uploader(
            "Choose a log file",
            type=['txt', 'json', 'log'],
            help="Upload CloudWatch, Azure Monitor, or GCP logs"
        )
        if uploaded_file:
            logs_data = uploaded_file.read().decode('utf-8')
    
    elif upload_method == "Paste Text/JSON":
        logs_data = st.text_area(
            "Paste your logs here (Text or JSON format)",
            height=300,
            help="Paste raw log data or structured JSON logs from any cloud provider"
        )
    
    else:  # Use Sample Data
        sample_options = {
            "AWS Incident Logs": "aws_incident_logs.json",
            "Azure Incident Logs": "azure_incident_logs.json",
            "GCP Incident Logs": "gcp_incident_logs.json"
        }
        
        selected_sample = st.selectbox(
            "Select sample log file:",
            list(sample_options.keys())
        )
        
        sample_file = sample_options[selected_sample]
        sample_path = os.path.join("sample_data", sample_file)
        
        if os.path.exists(sample_path):
            with open(sample_path, 'r') as f:
                logs_data = f.read()
            st.success(f"✅ Loaded sample data: {selected_sample}")
        else:
            st.error(f"❌ Sample file not found: {sample_path}")
    
    analyze_button = st.button("🔍 Analyze Logs", type="primary", use_container_width=True)
    
    if logs_data and analyze_button:
        with st.spinner("🔍 Processing logs and generating diagnostic reports..."):
            try:
                # Parse logs
                parsed_logs = log_parser.parse_logs(logs_data)
                
                if not parsed_logs:
                    st.error("❌ No valid logs found in the provided data. Please check the format.")
                    return
                
                # Analyze incidents
                incidents = incident_analyzer.analyze_incidents(parsed_logs)
                
                if not incidents:
                    st.warning("⚠️ No incidents detected in the logs. The system may need additional pattern matching rules.")
                    # Try to display raw logs as a fallback
                    st.subheader("📋 Raw Log Entries")
                    log_df = pd.DataFrame(parsed_logs[:20])  # Show first 20 logs
                    st.dataframe(log_df, use_container_width=True)
                    return
                
                # Store in database
                for incident in incidents:
                    db_manager.store_incident(incident)
                
                # Show success message with more details
                st.success(f"✅ Successfully analyzed logs and diagnosed {len(incidents)} incidents from {len(parsed_logs)} log entries. The incidents have been stored in the database.")
                
                # Display detailed diagnostic reports
                if incidents:
                    st.markdown("---")
                    st.header("📊 Detailed Diagnostic Report")
                    
                    # Summary metrics
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Total Incidents", len(incidents))
                    with col2:
                        critical_count = len([i for i in incidents if i.get('severity') in ['CRITICAL', 'HIGH']])
                        st.metric("Critical/High", critical_count)
                    with col3:
                        services = len(set(i.get('service', 'Unknown') for i in incidents))
                        st.metric("Services Affected", services)
                    with col4:
                        avg_errors = sum(i.get('log_count', 0) for i in incidents) / len(incidents) if incidents else 0
                        st.metric("Avg Errors/Incident", f"{avg_errors:.1f}")
                    
                    # Detailed incident analysis
                    for i, incident in enumerate(incidents):
                        with st.expander(f"🚨 Incident {i+1}: {incident.get('severity', 'Unknown')} - {incident.get('title', 'No title')}", expanded=True):
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.subheader("📋 Incident Details")
                                st.write(f"**ID:** {incident.get('id', 'N/A')}")
                                st.write(f"**Timestamp:** {incident.get('timestamp', 'N/A')}")
                                st.write(f"**Service:** {incident.get('service', 'N/A')}")
                                st.write(f"**Severity:** {incident.get('severity', 'N/A')}")
                                st.write(f"**Log Count:** {incident.get('log_count', 0)}")
                                
                                # Error breakdown
                                error_counts = incident.get('error_counts', {})
                                if error_counts:
                                    st.subheader("📈 Error Breakdown")
                                    for error_type, count in error_counts.items():
                                        st.write(f"• {error_type}: {count}")
                            
                            with col2:
                                st.subheader("🔍 Root Cause Analysis")
                                st.write(f"**Primary Cause:** {incident.get('root_cause', 'Not specified')}")
                                
                                # Contributing factors
                                if 'diagnostic_report' in incident:
                                    report = incident['diagnostic_report']
                                    if isinstance(report, dict):
                                        if 'contributing_factors' in report:
                                            st.write("**Contributing Factors:**")
                                            for factor in report['contributing_factors']:
                                                st.write(f"• {factor}")
                                
                                st.subheader("💡 Recommended Actions")
                                actions = incident.get('recommended_actions', [])
                                for j, action in enumerate(actions, 1):
                                    st.write(f"{j}. {action}")
                    
                    # Pattern analysis
                    st.markdown("---")
                    st.header("🔍 Pattern Analysis")
                    
                    # Create pattern analysis
                    all_services = [i.get('service', 'Unknown') for i in incidents]
                    service_counts = pd.Series(all_services).value_counts()
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        # Service distribution
                        fig_service = px.bar(
                            x=service_counts.index,
                            y=service_counts.values,
                            title="Incidents by Service",
                            labels={'x': 'Service', 'y': 'Incident Count'}
                        )
                        st.plotly_chart(fig_service, use_container_width=True)
                    
                    with col2:
                        # Severity distribution
                        severity_counts = pd.Series([i.get('severity', 'Unknown') for i in incidents]).value_counts()
                        fig_severity = px.pie(
                            values=severity_counts.values,
                            names=severity_counts.index,
                            title="Severity Distribution"
                        )
                        st.plotly_chart(fig_severity, use_container_width=True)
                
                st.rerun()
                
            except Exception as e:
                st.error(f"❌ Error processing logs: {str(e)}")
                st.exception(e)

def show_chat_interface(chat_system: ChatSystem):
    """Display enhanced chat interface like a modern chatting app"""
    st.header("💬 AI Chat Assistant")
    
    # Chat header with info
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        st.markdown("🤖 **AI-Powered Incident Analysis** - Ask questions about your incidents and get intelligent insights")
    with col2:
        if st.button("🔄 Refresh", help="Refresh chat data"):
            st.rerun()
    with col3:
        if st.button("🗑️ Clear Chat", help="Clear chat history"):
            st.session_state.chat_history = []
            st.rerun()
    
    st.divider()
    
    # Simplified welcome message
    if not st.session_state.chat_history:
        st.markdown("""
        <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    border-radius: 15px; margin: 20px 0; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">
            <h3 style="color: white; margin-bottom: 15px; font-size: 24px;">👋 Welcome to AI Chat Assistant!</h3>
            <p style="color: #f0f0f0; font-size: 16px;">Ask me anything about your incidents and get intelligent insights</p>
            <p style="color: #f0f0f0; font-size: 14px; margin-top: 10px;">I'm trained on your incident data to provide accurate responses</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Display chat messages with better styling
    if st.session_state.chat_history:
        for i, message in enumerate(st.session_state.chat_history):
            if message["role"] == "user":
                with st.chat_message("user", avatar="👤"):
                    st.markdown(f"""
                    <div style="background-color: #e3f2fd; padding: 12px; border-radius: 10px; border-left: 4px solid #2196f3; color: #1565c0; font-weight: 500;">
                        {message["content"]}
                    </div>
                    """, unsafe_allow_html=True)
            else:
                with st.chat_message("assistant", avatar="🤖"):
                        # Enhanced AI response formatting with better contrast
                        response_content = message["content"]
                        
                        # Clean HTML tags and markdown from response
                        import re
                        # Remove HTML tags
                        clean_response = re.sub(r'<[^>]*>', '', response_content)
                        # Remove markdown formatting
                        clean_response = re.sub(r'\*\*(.*?)\*\*', r'\1', clean_response)  # Remove **bold**
                        clean_response = re.sub(r'\*(.*?)\*', r'\1', clean_response)      # Remove *italic*
                        clean_response = re.sub(r'`(.*?)`', r'\1', clean_response)        # Remove `code`
                        # Clean up any remaining HTML entities
                        clean_response = clean_response.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
                        # Remove any trailing HTML tags that might have been missed
                        clean_response = clean_response.strip()
                        
                        # Check if response contains structured data
                        if "Found" in clean_response and "incidents" in clean_response:
                            st.markdown(f"""
                            <div style="background-color: #e8f5e8; padding: 12px; border-radius: 10px; border-left: 4px solid #4caf50; color: #1b5e20; font-weight: 500;">
                                ✅ {clean_response}
                            </div>
                            """, unsafe_allow_html=True)
                        elif "No incidents found" in clean_response:
                            st.markdown(f"""
                            <div style="background-color: #fff3e0; padding: 12px; border-radius: 10px; border-left: 4px solid #ff9800; color: #e65100; font-weight: 500;">
                                ⚠️ {clean_response}
                            </div>
                            """, unsafe_allow_html=True)
                        elif "Error" in clean_response or "failed" in clean_response.lower():
                            st.markdown(f"""
                            <div style="background-color: #ffebee; padding: 12px; border-radius: 10px; border-left: 4px solid #f44336; color: #c62828; font-weight: 500;">
                                ❌ {clean_response}
                            </div>
                            """, unsafe_allow_html=True)
                        else:
                            st.markdown(f"""
                            <div style="background-color: #f8f9fa; padding: 12px; border-radius: 10px; border-left: 4px solid #6c757d; color: #212529; font-weight: 500;">
                                🤖 {clean_response}
                            </div>
                            """, unsafe_allow_html=True)
                        
                        # Add helpful action buttons for AI responses with improved feedback messages
                        if i == len(st.session_state.chat_history) - 1:  # Only for latest response
                            col1, col2 = st.columns(2)
                            with col1:
                                if st.button("👍 Helpful", key=f"helpful_{i}"):
                                    st.success("Thanks for the feedback! This helps improve future responses.")
                            with col2:
                                if st.button("👎 Not Helpful", key=f"not_helpful_{i}"):
                                    st.warning("We'll improve our responses based on your feedback.")
    
    # Compact quick questions section
    st.markdown("**💡 Quick Questions:**")
    
    # Inline quick action buttons with improved spinner messages
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("📊 Total Incidents", help="Ask about total incident count", use_container_width=True):
            st.session_state.chat_history.append({"role": "user", "content": "How many total incidents are there?"})
            with st.spinner("Analyzing incident data..."):
                response = chat_system.get_response("How many total incidents are there?")
                st.session_state.chat_history.append({"role": "assistant", "content": response})
            st.rerun()
    
    with col2:
        if st.button("🚨 Critical Issues", help="Ask about critical incidents", use_container_width=True):
            st.session_state.chat_history.append({"role": "user", "content": "What are the critical incidents?"})
            with st.spinner("Analyzing critical incidents..."):
                response = chat_system.get_response("What are the critical incidents?")
                st.session_state.chat_history.append({"role": "assistant", "content": response})
            st.rerun()
    
    with col3:
        if st.button("🔧 Service Issues", help="Ask about service problems", use_container_width=True):
            st.session_state.chat_history.append({"role": "user", "content": "Show me service issues"})
            with st.spinner("Analyzing service issues..."):
                response = chat_system.get_response("Show me service issues")
                st.session_state.chat_history.append({"role": "assistant", "content": response})
            st.rerun()
    
    with col4:
        if st.button("💡 Solutions", help="Ask for solutions", use_container_width=True):
            st.session_state.chat_history.append({"role": "user", "content": "What are the recommended solutions?"})
            with st.spinner("Finding recommended solutions..."):
                response = chat_system.get_response("What are the recommended solutions?")
                st.session_state.chat_history.append({"role": "assistant", "content": response})
            st.rerun()
    
    st.divider()
    
    # Prominent chat input with enhanced styling and additional context
    st.markdown("""
    <div style="background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); padding: 15px; border-radius: 10px; margin: 15px 0;">
        <h4 style="color: white; margin: 0; text-align: center;">💬 Chat with AI Assistant</h4>
        <p style="color: #f0f0f0; font-size: 12px; text-align: center; margin-top: 5px;">
            Trained on your incident data for accurate responses
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Enhanced chat input with better visibility
    user_input = st.chat_input(
        "Ask about incidents, solutions, or patterns... (Press Enter to send)",
        key="chat_input"
    )
    
    if user_input:
        # Add user message to chat history
        st.session_state.chat_history.append({"role": "user", "content": user_input})
        
        # Get AI response with enhanced spinner
        with st.spinner("🤖 AI is analyzing your request..."):
            response = chat_system.get_response(user_input)
            st.session_state.chat_history.append({"role": "assistant", "content": response})
        
        st.rerun()

def show_incident_diagnosis(db_manager: DatabaseManager):
    """Enhanced incident diagnosis with streamlined filtering and sorting"""
    st.header("🔍 Advanced Incident Analysis")
    
    # Get all incidents
    incidents = db_manager.get_all_incidents()
    
    if not incidents:
        st.info("No incidents found. Upload some logs first.")
        st.markdown("""
        ### Getting Started
        1. Go to the **📁 Upload Logs** tab
        2. Choose **Use Sample Data** option
        3. Select a sample log file (AWS, Azure, or GCP)
        4. Click **🔍 Analyze Logs** to process the data
        """)
        return
    
    # Advanced filtering section
    st.subheader("🔍 Advanced Filters & Sorting")
    
    # Create filter columns in a more compact layout
    filter_col1, filter_col2, filter_col3 = st.columns(3)
    
    with filter_col1:
        # Severity filter with color indicators
        severity_options = ["All"] + sorted(list(set(incident.get('severity', 'Unknown') for incident in incidents)))
        severity_filter = st.selectbox(
            "Filter by Severity",
            severity_options,
            key="analysis_severity_filter"
        )
    
    with filter_col2:
        # Service filter with counts
        service_counts = {}
        for incident in incidents:
            service = incident.get('service', 'Unknown')
            service_counts[service] = service_counts.get(service, 0) + 1
        
        service_options = ["All"] + [f"{s} ({service_counts[s]})" for s in sorted(service_counts.keys())]
        service_filter = st.selectbox(
            "Filter by Service",
            service_options,
            key="analysis_service_filter"
        )
        # Extract just the service name without count
        if service_filter != "All":
            service_filter = service_filter.split(" (")[0]
    
    with filter_col3:
        # Sort options
        sort_by = st.selectbox(
            "Sort by",
            ["Timestamp (Newest)", "Timestamp (Oldest)", "Severity", "Service", "Title", "Error Count"],
            key="analysis_sort_by"
        )
        
        sort_order = st.selectbox(
            "Sort Order",
            ["Descending", "Ascending"],
            key="analysis_sort_order"
        )
    
    # Time period filtering in a more compact layout
    with st.expander("Time Period", expanded=False):
        time_col1, time_col2 = st.columns(2)
        
        with time_col1:
            # Time-based filtering
            time_filter = st.selectbox(
                "Time Period",
                ["All Time", "Today", "Yesterday", "Past 2 Days", "Past 7 Days", "Past 30 Days"],
                key="analysis_time_filter"
            )
        
        with time_col2:
            # Additional sorting options
            additional_sort = st.selectbox(
                "Additional Sort",
                ["None", "By Time", "By Service"],
                key="analysis_additional_sort"
            )
    
    # Apply filters
    filtered_incidents = incidents.copy()
    
    # Severity filter
    if severity_filter != "All":
        filtered_incidents = [i for i in filtered_incidents if i.get('severity') == severity_filter]
    
    # Service filter
    if service_filter != "All":
        filtered_incidents = [i for i in filtered_incidents if i.get('service') == service_filter]
    
    # Time period filter
    if time_filter != "All Time":
        now = pd.Timestamp.now()
        if time_filter == "Today":
            cutoff = now - pd.Timedelta(days=1)
        elif time_filter == "Yesterday":
            start = now - pd.Timedelta(days=2)
            end = now - pd.Timedelta(days=1)
            filtered_incidents = [
                i for i in filtered_incidents 
                if i.get('timestamp') and 
                pd.to_datetime(i.get('timestamp', ''), errors='coerce') >= start and
                pd.to_datetime(i.get('timestamp', ''), errors='coerce') < end
            ]
        elif time_filter == "Past 2 Days":
            cutoff = now - pd.Timedelta(days=2)
        elif time_filter == "Past 7 Days":
            cutoff = now - pd.Timedelta(days=7)
        elif time_filter == "Past 30 Days":
            cutoff = now - pd.Timedelta(days=30)
        else:
            cutoff = None
        
        if cutoff and time_filter != "Yesterday":
            filtered_incidents = [
                i for i in filtered_incidents 
                if i.get('timestamp') and 
                pd.to_datetime(i.get('timestamp', ''), errors='coerce') >= cutoff
            ]
    
    # Apply sorting
    if sort_by == "Timestamp (Newest)":
        filtered_incidents.sort(key=lambda x: x.get('timestamp', ''), reverse=(sort_order == "Descending"))
    elif sort_by == "Timestamp (Oldest)":
        filtered_incidents.sort(key=lambda x: x.get('timestamp', ''), reverse=(sort_order == "Ascending"))
    elif sort_by == "Severity":
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        filtered_incidents.sort(
            key=lambda x: severity_order.get(x.get('severity', 'LOW'), 4),
            reverse=(sort_order == "Descending")
        )
    elif sort_by == "Service":
        filtered_incidents.sort(key=lambda x: x.get('service', ''), reverse=(sort_order == "Descending"))
    elif sort_by == "Title":
        filtered_incidents.sort(key=lambda x: x.get('title', ''), reverse=(sort_order == "Descending"))
    elif sort_by == "Error Count":
        filtered_incidents.sort(key=lambda x: x.get('log_count', 0), reverse=(sort_order == "Descending"))
    
    # Display results
    st.subheader(f"📊 Diagnosis Results ({len(filtered_incidents)} incidents found)")
    
    if filtered_incidents:
        # Summary statistics in a more visually appealing format
        st.markdown("""
        <style>
        .metric-container {
            background-color: #f0f2f6;
            border-radius: 10px;
            padding: 10px;
            margin-bottom: 10px;
        }
        </style>
        """, unsafe_allow_html=True)
        
        with st.container():
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Incidents", len(filtered_incidents))
            
            with col2:
                critical_count = len([i for i in filtered_incidents if i.get('severity') in ['CRITICAL', 'HIGH']])
                st.metric("Critical/High", critical_count)
            
            with col3:
                services = len(set(i.get('service', 'Unknown') for i in filtered_incidents))
                st.metric("Services Affected", services)
            
            with col4:
                total_errors = sum(i.get('log_count', 0) for i in filtered_incidents)
                st.metric("Total Errors", total_errors)
        
        st.divider()
        
        # Detailed incident display with improved visual hierarchy
        for i, incident in enumerate(filtered_incidents):
            # Color-code severity for better visual identification
            severity = incident.get('severity', 'Unknown')
            severity_color = {
                'CRITICAL': '#DC2626',  # Red
                'HIGH': '#EA580C',      # Orange
                'MEDIUM': '#D97706',    # Amber
                'LOW': '#059669'        # Green
            }.get(severity, '#6B7280')  # Gray default
            
            # Format timestamp for better readability
            timestamp = incident.get('timestamp', 'N/A')
            if timestamp != 'N/A':
                try:
                    dt = pd.to_datetime(timestamp)
                    formatted_time = dt.strftime('%b %d, %Y %H:%M:%S')
                except:
                    formatted_time = timestamp
            else:
                formatted_time = 'N/A'
            
            # Create a more visually distinct incident card
            with st.expander(f"🚨 {severity} - {incident.get('title', 'No title')}", expanded=False):
                st.markdown(f"<div style='border-left: 4px solid {severity_color}; padding-left: 10px;'>", unsafe_allow_html=True)
                
                # Header with key information
                st.markdown(f"**Service:** {incident.get('service', 'N/A')} | **Time:** {formatted_time} | **ID:** {incident.get('id', 'N/A')}")
                
                col1, col2 = st.columns([3, 2])
                
                with col1:
                    st.subheader("📋 Incident Summary")
                    
                    # Create a more structured summary
                    summary_data = {
                        "Affected Service": incident.get('service', 'N/A'),
                        "Error Count": incident.get('log_count', 0),
                        "Root Cause": incident.get('root_cause', 'Not identified')
                    }
                    
                    # Add affected services if available
                    if 'affected_services' in incident and len(incident['affected_services']) > 1:
                        summary_data["Affected Services"] = ", ".join(incident['affected_services'])
                    
                    # Display summary as a clean table
                    summary_df = pd.DataFrame([summary_data])
                    st.dataframe(summary_df.T, use_container_width=True, hide_index=False)
                    
                    # Error breakdown with visual indicators
                    error_counts = incident.get('error_counts', {})
                    if error_counts:
                        st.subheader("📈 Error Analysis")
                        
                        # Convert to dataframe for better display
                        error_items = [(k, v) for k, v in error_counts.items()]
                        if error_items:
                            error_df = pd.DataFrame(error_items, columns=['Error Type', 'Count'])
                            st.dataframe(error_df, use_container_width=True, hide_index=True)
                
                with col2:
                    st.subheader("🔍 Diagnosis")
                    st.markdown(f"**Primary Issue:** {incident.get('root_cause', 'Not identified')}")
                    
                    # Contributing factors with better formatting
                    if 'diagnostic_report' in incident:
                        report = incident['diagnostic_report']
                        if isinstance(report, dict) and 'contributing_factors' in report:
                            st.markdown("**Contributing Factors:**")
                            for factor in report['contributing_factors']:
                                st.markdown(f"• {factor}")
                    
                    st.subheader("💡 Recommended Actions")
                    actions = incident.get('recommended_actions', [])
                    for j, action in enumerate(actions, 1):
                        st.markdown(f"{j}. {action}")
                
                st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.info("No incidents match the selected filters.")
    
    # Export functionality
    if filtered_incidents:
        st.divider()
        st.subheader("📤 Export Options")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📊 Export to CSV", use_container_width=True):
                df = pd.DataFrame(filtered_incidents)
                csv = df.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=f"incidents_analysis_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
        with col2:
            if st.button("📋 Export Summary", use_container_width=True):
                summary = {
                    "total_incidents": len(filtered_incidents),
                    "critical_count": len([i for i in filtered_incidents if i.get('severity') in ['CRITICAL', 'HIGH']]),
                    "services_affected": len(set(i.get('service', 'Unknown') for i in filtered_incidents)),
                    "total_errors": sum(i.get('log_count', 0) for i in filtered_incidents)
                }
                st.json(summary)
        
        with col3:
            if st.button("🔄 Refresh Analysis", use_container_width=True):
                st.rerun()

if __name__ == "__main__":
    main()
