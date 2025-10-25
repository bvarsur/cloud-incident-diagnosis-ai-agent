"""
Log Parser for Cloud Infrastructure Logs
Supports AWS CloudWatch, Azure Monitor, and GCP logs
"""

import json
import re
from datetime import datetime
from typing import List, Dict, Any, Optional
import logging

class LogParser:
    """Parse and normalize logs from different cloud providers"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Common log patterns
        self.patterns = {
            'timestamp': [
                r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',
                r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',
                r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}'
            ],
            'severity': [
                r'(ERROR|CRITICAL|FATAL)',
                r'(WARN|WARNING)',
                r'(INFO|INFORMATION)',
                r'(DEBUG|TRACE)'
            ],
            'http_status': [
                r'HTTP/\d\.\d" (\d{3})',
                r'status[=:]\s*(\d{3})',
                r'"status":\s*(\d{3})'
            ]
        }
        
        # Sensitive data patterns for masking
        self.sensitive_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'api_key': r'[A-Za-z0-9]{20,}',
            'password': r'(?i)(password|pwd|pass)\s*[=:]\s*[^\s]+',
            'token': r'(?i)(token|bearer|auth)\s*[=:]\s*[^\s]+',
            'secret': r'(?i)(secret|key)\s*[=:]\s*[^\s]+'
        }
    
    def parse_logs(self, raw_logs: str) -> List[Dict[str, Any]]:
        """
        Parse raw logs and return normalized log entries with data cleaning and masking
        
        Args:
            raw_logs: Raw log data as string
            
        Returns:
            List of normalized log entries
        """
        try:
            # Clean and mask sensitive data first
            cleaned_logs = self._clean_and_mask_sensitive_data(raw_logs)
            
            # Try to parse as JSON first
            if self._is_json(cleaned_logs):
                return self._parse_json_logs(cleaned_logs)
            else:
                return self._parse_text_logs(cleaned_logs)
        except Exception as e:
            self.logger.error(f"Error parsing logs: {e}")
            return []
    
    def _clean_and_mask_sensitive_data(self, raw_logs: str) -> str:
        """
        Clean and mask sensitive data from logs
        
        Args:
            raw_logs: Raw log data
            
        Returns:
            Cleaned log data with sensitive information masked
        """
        cleaned_logs = raw_logs
        
        # Track if any sensitive data was found
        sensitive_data_found = False
        
        for data_type, pattern in self.sensitive_patterns.items():
            matches = re.findall(pattern, cleaned_logs)
            if matches:
                sensitive_data_found = True
                self.logger.warning(f"Found {len(matches)} {data_type} patterns in logs - masking for security")
                
                # Replace with masked version
                if data_type == 'email':
                    cleaned_logs = re.sub(pattern, r'***@***.***', cleaned_logs)
                elif data_type == 'phone':
                    cleaned_logs = re.sub(pattern, r'***-***-****', cleaned_logs)
                elif data_type == 'ssn':
                    cleaned_logs = re.sub(pattern, r'***-**-****', cleaned_logs)
                elif data_type == 'credit_card':
                    cleaned_logs = re.sub(pattern, r'****-****-****-****', cleaned_logs)
                elif data_type == 'ip_address':
                    cleaned_logs = re.sub(pattern, r'***.***.***.***', cleaned_logs)
                elif data_type in ['api_key', 'password', 'token', 'secret']:
                    cleaned_logs = re.sub(pattern, r'***MASKED***', cleaned_logs)
        
        if sensitive_data_found:
            self.logger.info("Sensitive data has been masked for security compliance")
        
        return cleaned_logs
    
    def _detect_sensitive_data(self, log_entry: Dict[str, Any]) -> List[str]:
        """
        Detect sensitive data types in a log entry
        
        Args:
            log_entry: Log entry dictionary
            
        Returns:
            List of detected sensitive data types
        """
        detected_types = []
        log_text = str(log_entry)
        
        for data_type, pattern in self.sensitive_patterns.items():
            if re.search(pattern, log_text):
                detected_types.append(data_type)
        
        return detected_types
    
    def _is_json(self, text: str) -> bool:
        """Check if text is valid JSON"""
        try:
            json.loads(text)
            return True
        except (json.JSONDecodeError, ValueError):
            return False
    
    def _parse_json_logs(self, json_logs: str) -> List[Dict[str, Any]]:
        """Parse JSON format logs"""
        try:
            data = json.loads(json_logs)
            
            # Handle different JSON structures
            if isinstance(data, list):
                # Array of log entries
                normalized_logs = []
                for entry in data:
                    if isinstance(entry, dict):
                        # Check if this is an incident log format (has incident_id)
                        if 'incident_id' in entry:
                            # Add severity mapping if log_level exists
                            if 'log_level' in entry and 'severity' not in entry:
                                entry['severity'] = entry['log_level']
                            # Add message as title if title doesn't exist
                            if 'message' in entry and 'title' not in entry:
                                entry['title'] = entry['message']
                        normalized_logs.append(self._normalize_log_entry(entry))
                return normalized_logs
            elif isinstance(data, dict):
                # Handle single log entry or nested structure
                if 'logs' in data or 'events' in data or 'records' in data:
                    logs_key = next(key for key in ['logs', 'events', 'records'] if key in data)
                    return [self._normalize_log_entry(entry) for entry in data[logs_key]]
                else:
                    return [self._normalize_log_entry(data)]
            else:
                return []
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse JSON: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Error parsing JSON logs: {e}")
            return []
    
    def _parse_text_logs(self, text_logs: str) -> List[Dict[str, Any]]:
        """Parse plain text logs"""
        lines = text_logs.strip().split('\n')
        parsed_logs = []
        
        for line in lines:
            if line.strip():
                parsed_logs.append(self._parse_single_text_log(line))
        
        return parsed_logs
    
    def _parse_single_text_log(self, line: str) -> Dict[str, Any]:
        """Parse a single text log line"""
        entry = {
            'timestamp': self._extract_timestamp(line),
            'service': self._extract_service(line),
            'severity': self._extract_severity(line),
            'message': line.strip(),
            'metadata': self._extract_metadata(line)
        }
        
        return entry
    
    def _normalize_log_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a log entry to canonical schema"""
        normalized = {
            'timestamp': self._extract_timestamp_from_dict(entry),
            'service': self._extract_service_from_dict(entry),
            'severity': self._extract_severity_from_dict(entry),
            'message': self._extract_message_from_dict(entry),
            'metadata': self._extract_metadata_from_dict(entry)
        }
        
        # Preserve incident_id if present in the original entry
        if 'incident_id' in entry:
            normalized['incident_id'] = entry['incident_id']
            
        # Preserve title if present
        if 'title' in entry:
            normalized['title'] = entry['title']
            
        # Preserve region if present (for AWS logs)
        if 'region' in entry:
            normalized['region'] = entry['region']
            
        # If log_level exists but severity doesn't, use log_level as severity
        if not normalized.get('severity') and 'log_level' in entry:
            normalized['severity'] = entry['log_level']
            
        return normalized
    
    def _extract_timestamp(self, line: str) -> Optional[str]:
        """Extract timestamp from log line"""
        for pattern in self.patterns['timestamp']:
            match = re.search(pattern, line)
            if match:
                return match.group(0)
        return None
    
    def _extract_timestamp_from_dict(self, entry: Dict[str, Any]) -> Optional[str]:
        """Extract timestamp from dictionary entry"""
        # Common timestamp field names
        timestamp_fields = ['timestamp', 'time', 'datetime', '@timestamp', 'log_time']
        
        for field in timestamp_fields:
            if field in entry:
                return str(entry[field])
        
        # Try to find timestamp in message
        if 'message' in entry:
            return self._extract_timestamp(entry['message'])
        
        return None
    
    def _extract_service(self, line: str) -> str:
        """Extract service name from log line"""
        # Common service patterns
        service_patterns = [
            r'\[(\w+)\]',
            r'(\w+):\s',
            r'service[=:]\s*(\w+)',
            r'component[=:]\s*(\w+)'
        ]
        
        for pattern in service_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return 'unknown'
    
    def _extract_service_from_dict(self, entry: Dict[str, Any]) -> str:
        """Extract service from dictionary entry"""
        service_fields = ['service', 'component', 'source', 'app', 'application']
        
        for field in service_fields:
            if field in entry:
                return str(entry[field])
        
        return 'unknown'
    
    def _extract_severity(self, line: str) -> str:
        """Extract severity level from log line"""
        line_upper = line.upper()
        
        if any(level in line_upper for level in ['ERROR', 'CRITICAL', 'FATAL', 'FAIL']):
            return 'ERROR'
        elif any(level in line_upper for level in ['WARN', 'WARNING']):
            return 'WARN'
        elif any(level in line_upper for level in ['INFO', 'INFORMATION']):
            return 'INFO'
        elif any(level in line_upper for level in ['DEBUG', 'TRACE']):
            return 'DEBUG'
        else:
            return 'INFO'
    
    def _extract_severity_from_dict(self, entry: Dict[str, Any]) -> str:
        """Extract severity from dictionary entry"""
        severity_fields = ['severity', 'level', 'log_level', 'priority']
        
        for field in severity_fields:
            if field in entry:
                severity = str(entry[field]).upper()
                if severity in ['ERROR', 'CRITICAL', 'FATAL']:
                    return 'ERROR'
                elif severity in ['WARN', 'WARNING']:
                    return 'WARN'
                elif severity in ['INFO', 'INFORMATION']:
                    return 'INFO'
                elif severity in ['DEBUG', 'TRACE']:
                    return 'DEBUG'
        
        # Try to extract from message
        if 'message' in entry:
            return self._extract_severity(entry['message'])
        
        return 'INFO'
    
    def _extract_message_from_dict(self, entry: Dict[str, Any]) -> str:
        """Extract message from dictionary entry"""
        message_fields = ['message', 'msg', 'text', 'content', 'description']
        
        for field in message_fields:
            if field in entry:
                return str(entry[field])
        
        # If no message field, convert entire entry to string
        return json.dumps(entry)
    
    def _extract_metadata(self, line: str) -> Dict[str, Any]:
        """Extract metadata from log line"""
        metadata = {}
        
        # Extract HTTP status codes
        for pattern in self.patterns['http_status']:
            match = re.search(pattern, line)
            if match:
                metadata['http_status'] = int(match.group(1))
                break
        
        # Extract other common patterns
        patterns = {
            'user_id': r'user[=:]\s*(\w+)',
            'request_id': r'request[_-]?id[=:]\s*(\w+)',
            'session_id': r'session[_-]?id[=:]\s*(\w+)',
            'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                metadata[key] = match.group(1)
        
        return metadata
    
    def _extract_metadata_from_dict(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Extract metadata from dictionary entry"""
        metadata = {}
        
        # Common metadata fields
        metadata_fields = [
            'user_id', 'request_id', 'session_id', 'ip_address',
            'http_status', 'status_code', 'response_time', 'duration',
            'source_ip', 'user_agent', 'endpoint', 'method'
        ]
        
        for field in metadata_fields:
            if field in entry:
                metadata[field] = entry[field]
        
        return metadata
