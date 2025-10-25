"""
Database Manager for Incident Storage
Handles SQLite database operations for incidents and chat history
"""

import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
import logging

class DatabaseManager:
    """Manage SQLite database for incidents and chat history"""
    
    def __init__(self, db_path: str = "incidents.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self._init_database()
    
    def _init_database(self):
        """Initialize database tables"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create incidents table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS incidents (
                        id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        end_time TEXT,
                        severity TEXT NOT NULL,
                        title TEXT NOT NULL,
                        service TEXT NOT NULL,
                        affected_services TEXT,
                        error_counts TEXT,
                        log_count INTEGER,
                        root_cause TEXT,
                        recommended_actions TEXT,
                        diagnostic_report TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create chat_history table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS chat_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        user_message TEXT NOT NULL,
                        ai_response TEXT NOT NULL,
                        incident_context TEXT
                    )
                ''')
                
                # Create log_entries table for storing parsed logs
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS log_entries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        service TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        message TEXT NOT NULL,
                        metadata TEXT,
                        incident_id TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (incident_id) REFERENCES incidents (id)
                    )
                ''')
                
                conn.commit()
                self.logger.info("Database initialized successfully")
                
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
            raise
    
    def store_incident(self, incident: Dict[str, Any]) -> bool:
        """Store an incident in the database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO incidents (
                        id, timestamp, end_time, severity, title, service,
                        affected_services, error_counts, log_count, root_cause,
                        recommended_actions, diagnostic_report
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    incident.get('id'),
                    incident.get('timestamp'),
                    incident.get('end_time'),
                    incident.get('severity'),
                    incident.get('title'),
                    incident.get('service'),
                    json.dumps(incident.get('affected_services', [])),
                    json.dumps(incident.get('error_counts', {})),
                    incident.get('log_count', 0),
                    incident.get('root_cause'),
                    json.dumps(incident.get('recommended_actions', [])),
                    json.dumps(incident.get('diagnostic_report', {}))
                ))
                
                conn.commit()
                self.logger.info(f"Stored incident: {incident.get('id')}")
                return True
                
        except Exception as e:
            self.logger.error(f"Error storing incident: {e}")
            return False
    
    def store_log_entries(self, log_entries: List[Dict[str, Any]], incident_id: Optional[str] = None) -> bool:
        """Store log entries in the database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for log_entry in log_entries:
                    cursor.execute('''
                        INSERT INTO log_entries (
                            timestamp, service, severity, message, metadata, incident_id
                        ) VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        log_entry.get('timestamp'),
                        log_entry.get('service'),
                        log_entry.get('severity'),
                        log_entry.get('message'),
                        json.dumps(log_entry.get('metadata', {})),
                        incident_id
                    ))
                
                conn.commit()
                self.logger.info(f"Stored {len(log_entries)} log entries")
                return True
                
        except Exception as e:
            self.logger.error(f"Error storing log entries: {e}")
            return False
    
    def store_chat_message(self, user_message: str, ai_response: str, incident_context: Optional[str] = None) -> bool:
        """Store a chat message and response"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO chat_history (timestamp, user_message, ai_response, incident_context)
                    VALUES (?, ?, ?, ?)
                ''', (
                    datetime.now().isoformat(),
                    user_message,
                    ai_response,
                    incident_context
                ))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Error storing chat message: {e}")
            return False
    
    def get_all_incidents(self) -> List[Dict[str, Any]]:
        """Get all incidents from the database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM incidents ORDER BY timestamp DESC
                ''')
                
                rows = cursor.fetchall()
                incidents = []
                
                for row in rows:
                    incident = dict(row)
                    # Parse JSON fields
                    incident['affected_services'] = json.loads(incident.get('affected_services', '[]'))
                    incident['error_counts'] = json.loads(incident.get('error_counts', '{}'))
                    incident['recommended_actions'] = json.loads(incident.get('recommended_actions', '[]'))
                    incident['diagnostic_report'] = json.loads(incident.get('diagnostic_report', '{}'))
                    incidents.append(incident)
                
                return incidents
                
        except Exception as e:
            self.logger.error(f"Error getting incidents: {e}")
            return []
    
    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific incident by ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM incidents WHERE id = ?
                ''', (incident_id,))
                
                row = cursor.fetchone()
                if row:
                    incident = dict(row)
                    # Parse JSON fields
                    incident['affected_services'] = json.loads(incident.get('affected_services', '[]'))
                    incident['error_counts'] = json.loads(incident.get('error_counts', '{}'))
                    incident['recommended_actions'] = json.loads(incident.get('recommended_actions', '[]'))
                    incident['diagnostic_report'] = json.loads(incident.get('diagnostic_report', '{}'))
                    return incident
                
                return None
                
        except Exception as e:
            self.logger.error(f"Error getting incident by ID: {e}")
            return None
    
    def get_recent_incidents(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent incidents"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM incidents ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
                
                rows = cursor.fetchall()
                incidents = []
                
                for row in rows:
                    incident = dict(row)
                    # Parse JSON fields
                    incident['affected_services'] = json.loads(incident.get('affected_services', '[]'))
                    incident['error_counts'] = json.loads(incident.get('error_counts', '{}'))
                    incident['recommended_actions'] = json.loads(incident.get('recommended_actions', '[]'))
                    incidents.append(incident)
                
                return incidents
                
        except Exception as e:
            self.logger.error(f"Error getting recent incidents: {e}")
            return []
    
    def get_incidents_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """Get incidents by severity level"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM incidents WHERE severity = ? ORDER BY timestamp DESC
                ''', (severity,))
                
                rows = cursor.fetchall()
                incidents = []
                
                for row in rows:
                    incident = dict(row)
                    incident['affected_services'] = json.loads(incident.get('affected_services', '[]'))
                    incident['error_counts'] = json.loads(incident.get('error_counts', '{}'))
                    incident['recommended_actions'] = json.loads(incident.get('recommended_actions', '[]'))
                    incidents.append(incident)
                
                return incidents
                
        except Exception as e:
            self.logger.error(f"Error getting incidents by severity: {e}")
            return []
    
    def get_incidents_by_service(self, service: str) -> List[Dict[str, Any]]:
        """Get incidents by service"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM incidents WHERE service = ? ORDER BY timestamp DESC
                ''', (service,))
                
                rows = cursor.fetchall()
                incidents = []
                
                for row in rows:
                    incident = dict(row)
                    incident['affected_services'] = json.loads(incident.get('affected_services', '[]'))
                    incident['error_counts'] = json.loads(incident.get('error_counts', '{}'))
                    incident['recommended_actions'] = json.loads(incident.get('recommended_actions', '[]'))
                    incidents.append(incident)
                
                return incidents
                
        except Exception as e:
            self.logger.error(f"Error getting incidents by service: {e}")
            return []
    
    def get_incident_statistics(self) -> Dict[str, Any]:
        """Get incident statistics for dashboard"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total incidents
                cursor.execute('SELECT COUNT(*) FROM incidents')
                total_incidents = cursor.fetchone()[0]
                
                # High severity incidents
                cursor.execute('SELECT COUNT(*) FROM incidents WHERE severity IN ("CRITICAL", "HIGH")')
                high_severity = cursor.fetchone()[0]
                
                # Unique services
                cursor.execute('SELECT COUNT(DISTINCT service) FROM incidents')
                unique_services = cursor.fetchone()[0]
                
                # Average resolution time (simplified)
                cursor.execute('''
                    SELECT AVG(
                        CASE 
                            WHEN end_time IS NOT NULL AND timestamp IS NOT NULL 
                            THEN (julianday(end_time) - julianday(timestamp)) * 24
                            ELSE 0
                        END
                    ) FROM incidents
                ''')
                avg_resolution_time = cursor.fetchone()[0] or 0
                
                return {
                    'total_incidents': total_incidents,
                    'high_severity': high_severity,
                    'unique_services': unique_services,
                    'avg_resolution_time': avg_resolution_time
                }
                
        except Exception as e:
            self.logger.error(f"Error getting incident statistics: {e}")
            return {}
    
    def get_severity_distribution(self) -> Dict[str, int]:
        """Get severity distribution for charts"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT severity, COUNT(*) FROM incidents GROUP BY severity
                ''')
                
                rows = cursor.fetchall()
                return dict(rows)
                
        except Exception as e:
            self.logger.error(f"Error getting severity distribution: {e}")
            return {}
    
    def get_incident_timeline(self, days: int = 7) -> List[Dict[str, Any]]:
        """Get incident timeline data for charts"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT DATE(timestamp) as date, COUNT(*) as count
                    FROM incidents 
                    WHERE timestamp >= datetime('now', '-{} days')
                    GROUP BY DATE(timestamp)
                    ORDER BY date
                '''.format(days))
                
                rows = cursor.fetchall()
                return [{'timestamp': row[0], 'count': row[1]} for row in rows]
                
        except Exception as e:
            self.logger.error(f"Error getting incident timeline: {e}")
            return []
    
    def search_incidents(self, query: str) -> List[Dict[str, Any]]:
        """Search incidents by title, service, or root cause"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM incidents 
                    WHERE title LIKE ? OR service LIKE ? OR root_cause LIKE ?
                    ORDER BY timestamp DESC
                ''', (f'%{query}%', f'%{query}%', f'%{query}%'))
                
                rows = cursor.fetchall()
                incidents = []
                
                for row in rows:
                    incident = dict(row)
                    incident['affected_services'] = json.loads(incident.get('affected_services', '[]'))
                    incident['error_counts'] = json.loads(incident.get('error_counts', '{}'))
                    incident['recommended_actions'] = json.loads(incident.get('recommended_actions', '[]'))
                    incidents.append(incident)
                
                return incidents
                
        except Exception as e:
            self.logger.error(f"Error searching incidents: {e}")
            return []
    
    def get_chat_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get chat history"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM chat_history ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
                
        except Exception as e:
            self.logger.error(f"Error getting chat history: {e}")
            return []
    
    def clear_old_data(self, days: int = 30) -> bool:
        """Clear old data to keep database size manageable"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Clear old incidents
                cursor.execute('''
                    DELETE FROM incidents 
                    WHERE created_at < datetime('now', '-{} days')
                '''.format(days))
                
                # Clear old chat history
                cursor.execute('''
                    DELETE FROM chat_history 
                    WHERE timestamp < datetime('now', '-{} days')
                '''.format(days))
                
                # Clear old log entries
                cursor.execute('''
                    DELETE FROM log_entries 
                    WHERE created_at < datetime('now', '-{} days')
                '''.format(days))
                
                conn.commit()
                self.logger.info(f"Cleared data older than {days} days")
                return True
                
        except Exception as e:
            self.logger.error(f"Error clearing old data: {e}")
            return False
    
    def clean_database(self) -> bool:
        """Clean all data from the database (remove all incidents, logs, and chat history)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Clear all log entries first (due to foreign key constraint)
                cursor.execute('DELETE FROM log_entries')
                
                # Clear all incidents
                cursor.execute('DELETE FROM incidents')
                
                # Clear all chat history
                cursor.execute('DELETE FROM chat_history')
                
                conn.commit()
                self.logger.info("Database cleaned successfully - all data removed")
                return True
                
        except Exception as e:
            self.logger.error(f"Error cleaning database: {e}")
            return False
