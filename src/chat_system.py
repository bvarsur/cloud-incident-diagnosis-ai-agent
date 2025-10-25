"""
Chat System for Incident Queries
Provides AI-powered chat interface for querying incidents and solutions
"""

import json
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import Counter
import logging

class ChatSystem:
    """Handle chat interactions and provide AI responses about incidents"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.logger = logging.getLogger(__name__)
        
        # Initialize local LLM for enhanced responses
        try:
            from src.local_llm import LocalLLM
            self.llm = LocalLLM()
            self.use_llm = True
            self.logger.info("Local LLM initialized successfully")
        except Exception as e:
            self.logger.warning(f"Could not initialize Local LLM: {e}")
            self.use_llm = False
        
        # Enhanced query patterns with more comprehensive matching
        self.query_patterns = {
            'time_based': [
                r'what happened at (\d{1,2}:\d{2})',
                r'what happened around (\d{1,2}:\d{2})',
                r'incidents at (\d{1,2}:\d{2})',
                r'problems at (\d{1,2}:\d{2})',
                r'between (\d{1,2}:\d{2}) and (\d{1,2}:\d{2})',
                r'during (\d{1,2}:\d{2})'
            ],
            'severity_based': [
                r'critical incidents',
                r'high severity',
                r'severe problems',
                r'worst incidents',
                r'emergency incidents',
                r'urgent issues',
                r'major outages'
            ],
            'service_based': [
                r'problems with (\w+)',
                r'issues in (\w+)',
                r'(\w+) service problems',
                r'(\w+) errors',
                r'(\w+) outage',
                r'(\w+) downtime',
                r'(\w+) failures'
            ],
            'solution_based': [
                r'how to fix',
                r'what to do about',
                r'solutions for',
                r'recommendations for',
                r'resolve',
                r'remediate',
                r'troubleshoot'
            ],
            'analysis_based': [
                r'root cause',
                r'why did',
                r'what caused',
                r'analyze',
                r'diagnosis',
                r'investigation'
            ],
            'trend_based': [
                r'trending',
                r'pattern',
                r'frequency',
                r'recurring',
                r'common issues',
                r'statistics'
            ]
        }
        
        # Context memory for conversation continuity
        self.conversation_context = []
        self.max_context_length = 10
        
    def get_response(self, user_input: str) -> str:
        """
        Generate AI response to user query with enhanced LLM capabilities and context awareness
        
        Args:
            user_input: User's question or query
            
        Returns:
            AI response string
        """
        try:
            # Add user input to conversation context
            self._add_to_context(user_input, 'user')
            
            # Preprocess user input for better understanding
            processed_input = self._preprocess_input(user_input)
            
            # Get relevant incidents with enhanced filtering
            incidents = self._get_relevant_incidents(processed_input)
            
            # Check for follow-up questions using context
            if self._is_followup_question(user_input):
                response = self._handle_followup_query(user_input, incidents)
            else:
                # Use LLM for enhanced responses if available
                if self.use_llm and incidents:
                    try:
                        # Include conversation context for better responses
                        context_aware_input = self._build_context_aware_input(user_input)
                        llm_response = self.llm.chat_with_incidents(context_aware_input, incidents)
                        if llm_response and len(llm_response) > 20:  # Basic validation
                            response = llm_response
                        else:
                            response = self._get_rule_based_response(processed_input, incidents)
                    except Exception as e:
                        self.logger.error(f"LLM error: {e}, falling back to rule-based response")
                        response = self._get_rule_based_response(processed_input, incidents)
                else:
                    response = self._get_rule_based_response(processed_input, incidents)
            
            # Add response to context
            self._add_to_context(response, 'assistant')
            
            return response
                
        except Exception as e:
            self.logger.error(f"Error generating response: {e}")
            # Provide more specific error information for debugging
            return f"Error processing request: {str(e)}. Please check the logs for more details."
            
    def _get_relevant_incidents(self, user_input: str) -> List[Dict[str, Any]]:
        """Get incidents relevant to the user query"""
        user_input_lower = user_input.lower()
        
        # Check if user is asking about a specific incident ID
        incident_id_match = re.search(r'(inc-?\d+|incident\s+\w+)', user_input_lower)
        if incident_id_match:
            incident_id = incident_id_match.group(1).upper().replace('INCIDENT ', 'INC-')
            if not incident_id.startswith('INC-'):
                incident_id = 'INC-' + incident_id.replace('INC', '')
            
            # Try to get specific incident by ID
            specific_incident = self.db_manager.get_incident_by_id(incident_id)
            if specific_incident:
                return [specific_incident]
        
        # Get all incidents from database
        all_incidents = self.db_manager.get_all_incidents()
        
        if not all_incidents:
            return []
            
        # Extract key terms from user input
        query_terms = self._extract_query_terms(user_input)
        
        # Score incidents by relevance to query
        scored_incidents = []
        for incident in all_incidents:
            score = self._calculate_relevance_score(incident, query_terms, user_input)
            scored_incidents.append((score, incident))
        
        # Sort by relevance score (descending) using explicit key to avoid dict comparison on ties
        scored_incidents.sort(key=lambda x: x[0], reverse=True)
        
        # Return top 10 most relevant incidents
        return [incident for _, incident in scored_incidents[:10]]
        
    def _extract_query_terms(self, query: str) -> List[str]:
        """Extract key terms from user query"""
        # Convert to lowercase
        query = query.lower()
        
        # Remove common stop words
        stop_words = {'a', 'an', 'the', 'and', 'or', 'but', 'is', 'are', 'was', 'were', 
                     'in', 'on', 'at', 'to', 'for', 'with', 'by', 'about', 'like', 
                     'through', 'over', 'before', 'after', 'between', 'under'}
        
        # Extract words, removing punctuation
        words = re.findall(r'\b\w+\b', query)
        
        # Filter out stop words and short words
        terms = [word for word in words if word not in stop_words and len(word) > 2]
        
        return terms
        
    def _calculate_relevance_score(self, incident: Dict[str, Any], query_terms: List[str], 
                                  original_query: str) -> float:
        """
        Calculate relevance score of incident to query terms
        
        Args:
            incident: Incident dictionary
            query_terms: List of key terms from user query
            original_query: Original user query string
            
        Returns:
            Relevance score (higher is more relevant)
        """
        score = 0.0
        
        # Check for direct matches in incident fields
        incident_text = json.dumps(incident).lower()
        
        # Score based on term matches
        for term in query_terms:
            if term in incident_text:
                score += 1.0
                
                # Bonus for matches in important fields
                if term in str(incident.get('title', '')).lower():
                    score += 2.0
                if term in str(incident.get('service', '')).lower():
                    score += 1.5
                if term in str(incident.get('severity', '')).lower():
                    score += 1.5
                if term in str(incident.get('root_cause', '')).lower():
                    score += 2.0
        
        # Check for time-based queries
        time_match = re.search(r'(\d{1,2}):(\d{2})', original_query)
        if time_match and incident.get('timestamp'):
            try:
                query_hour = int(time_match.group(1))
                query_minute = int(time_match.group(2))
                
                # Parse incident timestamp
                timestamp = incident.get('timestamp')
                if timestamp:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    
                    # Calculate time difference in minutes
                    incident_hour = dt.hour
                    incident_minute = dt.minute
                    
                    hour_diff = abs(query_hour - incident_hour)
                    minute_diff = abs(query_minute - incident_minute)
                    
                    # Convert to total minutes difference
                    total_diff_minutes = hour_diff * 60 + minute_diff
                    
                    # Score based on time proximity (closer is better)
                    if total_diff_minutes < 30:  # Within 30 minutes
                        time_score = 5.0 * (1 - total_diff_minutes / 30)
                        score += time_score
            except (ValueError, TypeError):
                pass
        
        # Check for service-specific queries
        service_match = re.search(r'(aws|azure|gcp|database|api|web|app|server)', original_query, re.IGNORECASE)
        if service_match and incident.get('service'):
            service_term = service_match.group(1).lower()
            incident_service = incident.get('service', '').lower()
            
            if service_term in incident_service:
                score += 3.0
        
        # Check for severity-specific queries
        severity_match = re.search(r'(critical|high|medium|low|error|warning)', original_query, re.IGNORECASE)
        if severity_match and incident.get('severity'):
            severity_term = severity_match.group(1).lower()
            incident_severity = incident.get('severity', '').lower()
            
            if severity_term in incident_severity:
                score += 3.0
                
        # Recency bonus (newer incidents get higher score)
        if incident.get('timestamp'):
            try:
                timestamp = incident.get('timestamp')
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                
                # Calculate days since incident
                days_old = (datetime.now().astimezone() - dt.astimezone()).days
                
                # Newer incidents get higher score (max 2.0 bonus for today's incidents)
                recency_score = max(0, 2.0 - (days_old * 0.1))
                score += recency_score
            except (ValueError, TypeError):
                pass
        
        return score
    
    def _analyze_query_type(self, user_input: str) -> str:
        """Analyze the type of query to determine appropriate response"""
        user_input_lower = user_input.lower()
        
        # Check for time-based queries
        for pattern in self.query_patterns['time_based']:
            if re.search(pattern, user_input_lower):
                return 'time_based'
        
        # Check for severity-based queries
        for pattern in self.query_patterns['severity_based']:
            if re.search(pattern, user_input_lower):
                return 'severity_based'
        
        # Check for service-based queries
        for pattern in self.query_patterns['service_based']:
            if re.search(pattern, user_input_lower):
                return 'service_based'
        
        # Check for solution-based queries
        for pattern in self.query_patterns['solution_based']:
            if re.search(pattern, user_input_lower):
                return 'solution_based'
        
        # Check for analysis-based queries
        if 'analysis_based' in self.query_patterns:
            for pattern in self.query_patterns['analysis_based']:
                if re.search(pattern, user_input_lower):
                    return 'analysis_based'
        
        # Check for trend-based queries
        if 'trend_based' in self.query_patterns:
            for pattern in self.query_patterns['trend_based']:
                if re.search(pattern, user_input_lower):
                    return 'trend_based'
        
        return 'general'
    
    def _handle_time_based_query(self, user_input: str) -> str:
        """Handle queries about incidents at specific times"""
        # Extract time from query
        time_match = re.search(r'(\d{1,2}:\d{2})', user_input)
        if not time_match:
            return "I couldn't find a specific time in your query. Please specify a time like '14:00' or '2:30 PM'."
        
        query_time = time_match.group(1)
        
        # Get all incidents
        incidents = self.db_manager.get_all_incidents()
        
        # Filter incidents by time
        relevant_incidents = []
        for incident in incidents:
            incident_time = self._extract_time_from_timestamp(incident.get('timestamp'))
            if incident_time and self._is_time_match(incident_time, query_time):
                relevant_incidents.append(incident)
        
        if not relevant_incidents:
            return f"I didn't find any incidents around {query_time}. You can check the dashboard for a broader time range."
        
        # Generate response
        response = f"Here's what happened around {query_time}:\n\n"
        
        for i, incident in enumerate(relevant_incidents[:3], 1):  # Limit to 3 incidents
            response += f"{i}. {incident.get('severity', 'Unknown')} - {incident.get('title', 'No title')}\n"
            response += f"   Service: {incident.get('service', 'Unknown')}\n"
            response += f"   Root Cause: {incident.get('root_cause', 'Not specified')}\n\n"
        
        if len(relevant_incidents) > 3:
            response += f"... and {len(relevant_incidents) - 3} more incidents. Check the dashboard for details."
        
        return response
    
    def _handle_severity_based_query(self, user_input: str) -> str:
        """Handle queries about high-severity incidents"""
        if "critical" in user_input.lower():
            return self._get_critical_incidents()
        
        # Get high-severity incidents
        critical_incidents = self.db_manager.get_incidents_by_severity('CRITICAL')
        high_incidents = self.db_manager.get_incidents_by_severity('HIGH')
        
        all_high_severity = critical_incidents + high_incidents
        
        if not all_high_severity:
            return "No high-severity incidents found."
        
        # Sort by timestamp (most recent first)
        all_high_severity.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        response = f"{len(all_high_severity)} high-severity incidents:\n"
        
        for i, incident in enumerate(all_high_severity[:5], 1):  # Limit to 5
            response += f"{i}. {incident.get('id', 'Unknown')} - {incident.get('severity', 'Unknown')} ({incident.get('service', 'Unknown')})\n"
        
        return response.strip()
    
    def _handle_service_based_query(self, user_input: str) -> str:
        """Handle queries about specific services"""
        # Extract service name from query
        service_match = re.search(r'(\w+)', user_input.lower())
        if not service_match:
            return "I couldn't identify a specific service in your query. Please mention the service name."
        
        service_name = service_match.group(1)
        
        # Get incidents for this service
        service_incidents = self.db_manager.get_incidents_by_service(service_name)
        
        if not service_incidents:
            return f"No incidents found for service '{service_name}'. This service appears to be running smoothly!"
        
        # Sort by timestamp (most recent first)
        service_incidents.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        response = f"Found {len(service_incidents)} incidents for service '{service_name}':\n\n"
        
        for i, incident in enumerate(service_incidents[:5], 1):  # Limit to 5
            response += f"{i}. {incident.get('severity', 'Unknown')} - {incident.get('title', 'No title')}\n"
            response += f"   Time: {self._format_timestamp(incident.get('timestamp'))}\n"
            response += f"   Root Cause: {incident.get('root_cause', 'Not specified')}\n"
            
            # Add recommended actions if available
            actions = incident.get('recommended_actions', [])
            if actions:
                response += f"   Recommended Actions: {', '.join(actions[:2])}\n"
            
            response += "\n"
        
        if len(service_incidents) > 5:
            response += f"... and {len(service_incidents) - 5} more incidents for this service."
        
        return response
    
    def _handle_solution_based_query(self, user_input: str) -> str:
        """Handle queries about solutions and recommendations"""
        return self._get_recommended_solutions()
    
    def _handle_general_query(self, user_input: str) -> str:
        """Handle general queries about incidents with exact, precise responses"""
        try:
            user_lower = user_input.lower()
            
            # Get incident statistics from database
            stats = self.db_manager.get_incident_statistics()
            
            if not stats or stats.get('total_incidents', 0) == 0:
                return "0 incidents found in the database."
            
            total = stats.get('total_incidents', 0)
            high_severity = stats.get('high_severity', 0)
            services = stats.get('unique_services', 0)
            
            # Handle specific count questions
            if "how many total" in user_lower or "total incidents" in user_lower:
                return f"{total} total incidents"
            
            # Handle recommended solutions questions
            if "recommended solutions" in user_lower or "solutions" in user_lower:
                return self._get_recommended_solutions()
            
            # Handle critical incidents questions
            if "critical incidents" in user_lower:
                return self._get_critical_incidents()
            
            # Handle service issues questions
            if "service issues" in user_lower or "service problems" in user_lower:
                return self._get_service_issues()
            
            # Default response with key stats
            return f"{total} incidents across {services} services ({high_severity} high severity)"
            
        except Exception as e:
            self.logger.error(f"Error in general query handler: {e}")
            return f"Database error: {str(e)}"
        
    def _handle_date_based_query(self, date_str: str, incidents: List[Dict[str, Any]]) -> str:
        """Handle queries about incidents on specific dates"""
        # Extract date components from the query
        month_match = re.search(r'(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*', date_str, re.IGNORECASE)
        day_match = re.search(r'\b(\d{1,2})(?:st|nd|rd|th)?\b', date_str)
        year_match = re.search(r'\b(\d{4})\b', date_str)
        
        if not (month_match and day_match):
            return "I couldn't parse the date in your query. Please specify a date like 'March 30' or 'March 30, 2024'."
        
        month_str = month_match.group(1).lower()
        day = int(day_match.group(1))
        year = int(year_match.group(1)) if year_match else datetime.now().year
        
        month_map = {'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6, 
                    'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12}
        month = month_map.get(month_str[:3], 1)
        
        # Filter incidents by date
        date_incidents = []
        for incident in incidents:
            timestamp = incident.get('timestamp')
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    if dt.month == month and dt.day == day and dt.year == year:
                        date_incidents.append(incident)
                except (ValueError, TypeError):
                    pass
        
        if not date_incidents:
            return f"I didn't find any incidents on {month_str.capitalize()} {day}, {year}. You can check the dashboard for incidents on other dates."
        
        # Generate response
        formatted_date = f"{month_str.capitalize()} {day}, {year}"
        response = f"Here are the incidents from {formatted_date}:\n\n"
        
        for i, incident in enumerate(date_incidents[:5], 1):
            response += f"{i}. {incident.get('severity', 'Unknown')} - {incident.get('title', 'No title')}\n"
            response += f"   Service: {incident.get('service', 'Unknown')}\n"
            response += f"   Time: {self._extract_time_from_timestamp(incident.get('timestamp', ''))}\n"
            response += f"   Root Cause: {incident.get('root_cause', 'Not specified')}\n\n"
        
        if len(date_incidents) > 5:
            response += f"... and {len(date_incidents) - 5} more incidents on this date. Check the dashboard for details."
        
        return response
        
    def _handle_yes_no_query(self, user_input: str, incidents: List[Dict[str, Any]]) -> str:
        """Handle yes/no questions about incidents"""
        user_input_lower = user_input.lower()
        
        # Check for common yes/no question patterns
        if "any incident" in user_input_lower or "any issue" in user_input_lower:
            if incidents:
                return f"Yes, I found {len(incidents)} incidents that might be relevant to your query."
            else:
                return "No, I don't see any incidents matching your criteria."
                
        # Check for date-specific questions
        date_match = re.search(r'(?:on|at|during)\s+(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\s+\d{1,2}(?:st|nd|rd|th)?(?:\s*,?\s*\d{4})?', user_input_lower, re.IGNORECASE)
        if date_match:
            date_str = date_match.group(0)
            
            # Extract date components
            month_match = re.search(r'(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*', date_str, re.IGNORECASE)
            day_match = re.search(r'\b(\d{1,2})(?:st|nd|rd|th)?\b', date_str)
            year_match = re.search(r'\b(\d{4})\b', date_str)
            
            if month_match and day_match:
                month_str = month_match.group(1).lower()
                day = int(day_match.group(1))
                year = int(year_match.group(1)) if year_match else datetime.now().year
                
                month_map = {'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6, 
                            'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12}
                month = month_map.get(month_str[:3], 1)
                
                # Count incidents on this date
                date_incidents = 0
                for incident in incidents:
                    timestamp = incident.get('timestamp')
                    if timestamp:
                        try:
                            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                            if dt.month == month and dt.day == day and dt.year == year:
                                date_incidents += 1
                        except (ValueError, TypeError):
                            pass
                
                formatted_date = f"{month_str.capitalize()} {day}, {year}"
                if date_incidents > 0:
                    return f"Yes, there {'was' if date_incidents == 1 else 'were'} {date_incidents} incident{'s' if date_incidents != 1 else ''} on {formatted_date}."
                else:
                    return f"No, I don't see any incidents on {formatted_date}."
        
        # Default response for other yes/no questions
        return self._handle_general_query(user_input)
    
    def _extract_time_from_timestamp(self, timestamp: str) -> Optional[str]:
        """Extract time from timestamp string"""
        if not timestamp:
            return None
        
        try:
            # Try to parse timestamp and extract time
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return dt.strftime('%H:%M')
        except:
            # Try to extract time pattern from string
            time_match = re.search(r'(\d{1,2}:\d{2})', timestamp)
            return time_match.group(1) if time_match else None
    
    def _is_time_match(self, incident_time: str, query_time: str) -> bool:
        """Check if incident time matches query time (within 30 minutes)"""
        try:
            # Parse times
            incident_dt = datetime.strptime(incident_time, '%H:%M')
            query_dt = datetime.strptime(query_time, '%H:%M')
            
            # Calculate time difference
            time_diff = abs((incident_dt - query_dt).total_seconds())
            
            # Consider it a match if within 30 minutes
            return time_diff <= 1800  # 30 minutes in seconds
        except:
            return False
    
    def _format_timestamp(self, timestamp: str) -> str:
        """Format timestamp for display"""
        if not timestamp:
            return "Unknown time"
        
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return timestamp
    
    def get_incident_summary(self, incident_id: str) -> str:
        """Get a summary of a specific incident"""
        incident = self.db_manager.get_incident_by_id(incident_id)
        
        if not incident:
            return "Incident not found."
        
        summary = f"Incident Summary:\n\n"
        summary += f"Severity: {incident.get('severity', 'Unknown')}\n"
        summary += f"Title: {incident.get('title', 'No title')}\n"
        summary += f"Service: {incident.get('service', 'Unknown')}\n"
        summary += f"Time: {self._format_timestamp(incident.get('timestamp'))}\n"
        summary += f"Root Cause: {incident.get('root_cause', 'Not specified')}\n\n"
        
        # Add recommended actions
        actions = incident.get('recommended_actions', [])
        if actions:
            summary += "Recommended Actions:\n"
            for i, action in enumerate(actions, 1):
                summary += f"{i}. {action}\n"
        
        return summary
    
    def search_incidents_by_keywords(self, keywords: List[str]) -> str:
        """Search incidents by keywords"""
        # Join keywords into search query
        query = ' '.join(keywords)
        
        # Search incidents
        incidents = self.db_manager.search_incidents(query)
        
        if not incidents:
            return f"No incidents found matching keywords: {', '.join(keywords)}"
        
        response = f"Found {len(incidents)} incidents matching your search:\n\n"
        
        for i, incident in enumerate(incidents[:5], 1):  # Limit to 5
            response += f"{i}. {incident.get('severity', 'Unknown')} - {incident.get('title', 'No title')}\n"
            response += f"   Service: {incident.get('service', 'Unknown')}\n"
            response += f"   Time: {self._format_timestamp(incident.get('timestamp'))}\n"
            response += f"   Root Cause: {incident.get('root_cause', 'Not specified')}\n\n"
        
        if len(incidents) > 5:
            response += f"... and {len(incidents) - 5} more matching incidents."
        
        return response
    
    def _format_structured_response(self, incident_summary: str, evidence: str, 
                                  recommended_actions: List[str], confidence_level: str, 
                                  explanation: str) -> str:
        """Format response in structured format as requested"""
        response = f"""## 📊 Incident Analysis Response

### Incident Summary
{incident_summary}

### 🔍 Evidence (Database Query Results)
{evidence}

### 💡 Recommended Actions
"""
        for i, action in enumerate(recommended_actions, 1):
            response += f"{i}. {action}\n"
        
        response += f"""
### 🎯 Confidence Level
{confidence_level}

### 📝 Explanation
{explanation}
"""
        return response
    
    def _preprocess_input(self, user_input: str) -> str:
        """Preprocess user input for better understanding"""
        processed = user_input.lower().strip()
        
        # Expand common abbreviations
        abbreviations = {
            'db': 'database', 'api': 'api service', 'ui': 'user interface',
            'cpu': 'processor', 'mem': 'memory', 'net': 'network', 'auth': 'authentication'
        }
        
        for abbr, full in abbreviations.items():
            processed = re.sub(r'\b' + abbr + r'\b', full, processed)
        
        return processed
    
    def _add_to_context(self, message: str, role: str):
        """Add message to conversation context"""
        self.conversation_context.append({
            'role': role, 'message': message, 'timestamp': datetime.now().isoformat()
        })
        
        if len(self.conversation_context) > self.max_context_length:
            self.conversation_context = self.conversation_context[-self.max_context_length:]
    
    def _is_followup_question(self, user_input: str) -> bool:
        """Check if this is a follow-up question"""
        followup_indicators = [
            'what about', 'and', 'also', 'tell me more', 'more details', 'elaborate',
            'why', 'how', 'when did', 'where'
        ]
        return any(indicator in user_input.lower() for indicator in followup_indicators)
    
    def _build_context_aware_input(self, user_input: str) -> str:
        """Build context-aware input including conversation history"""
        if not self.conversation_context:
            return user_input
        
        recent_context = self.conversation_context[-6:]
        context_str = "Previous conversation:\n"
        for ctx in recent_context:
            role = "User" if ctx['role'] == 'user' else "Assistant"
            context_str += f"{role}: {ctx['message'][:100]}...\n"
        
        return f"{context_str}\nCurrent question: {user_input}"
    
    def _handle_followup_query(self, user_input: str, incidents: List[Dict[str, Any]]) -> str:
        """Handle follow-up questions using conversation context"""
        user_lower = user_input.lower()
        
        if any(word in user_lower for word in ['why', 'cause', 'reason']):
            return self._handle_why_question(incidents)
        elif any(word in user_lower for word in ['how', 'fix', 'resolve', 'solution']):
            return self._handle_how_question(incidents)
        elif any(word in user_lower for word in ['when', 'time', 'occurred']):
            return self._handle_when_question(incidents)
        elif any(word in user_lower for word in ['more', 'details', 'elaborate']):
            return self._handle_details_question(incidents)
        else:
            return self._get_rule_based_response(user_input, incidents)
    
    def _handle_why_question(self, incidents: List[Dict[str, Any]]) -> str:
        """Handle 'why' questions about incidents"""
        if not incidents:
            return "I need more context about which incident you're asking about."
        
        incident = incidents[0]
        incident_id = incident.get('id', 'Unknown')
        root_cause = incident.get('root_cause', 'Unknown')
        
        if root_cause and root_cause != 'Unknown':
            return f"Incident {incident_id}: {root_cause}"
        else:
            return f"The root cause for incident {incident_id} hasn't been determined yet."
    
    def _handle_how_question(self, incidents: List[Dict[str, Any]]) -> str:
        """Handle 'how to fix' questions"""
        if not incidents:
            return "I need more context about which incident you want to fix."
        
        incident = incidents[0]
        incident_id = incident.get('id', 'Unknown')
        
        # Get recommendations from database
        diagnostic_report = incident.get('diagnostic_report', {})
        if isinstance(diagnostic_report, dict):
            recommendations = diagnostic_report.get('recommended_actions', [])
        else:
            recommendations = incident.get('recommended_actions', [])
        
        if recommendations:
            response = f"To fix incident {incident_id}:\n"
            for i, action in enumerate(recommendations[:3], 1):
                response += f"{i}. {action}\n"
            return response
        else:
            return f"No specific fix recommendations found for incident {incident_id}. Check the service logs and configuration."
    
    def _handle_when_question(self, incidents: List[Dict[str, Any]]) -> str:
        """Handle 'when' questions about incidents"""
        if not incidents:
            return "I need more context about which incident you're asking about."
        
        incident = incidents[0]
        timestamp = incident.get('timestamp')
        
        if timestamp:
            formatted_time = self._format_timestamp(timestamp)
            response = f"This incident occurred at: {formatted_time}\n\n"
            
            log_count = incident.get('log_count', 0)
            if log_count:
                response += f"Total log entries: {log_count}\n"
        else:
            response = "The exact time of this incident is not available."
        
        return response
    
    def _handle_details_question(self, incidents: List[Dict[str, Any]]) -> str:
        """Handle requests for more details"""
        if not incidents:
            return "I need more context about which incident you want details for."
        
        incident = incidents[0]
        response = f"**Detailed Incident Information:**\n\n"
        response += f"**ID:** {incident.get('id', 'Unknown')}\n"
        response += f"**Title:** {incident.get('title', 'No title')}\n"
        response += f"**Severity:** {incident.get('severity', 'Unknown')}\n"
        response += f"**Service:** {incident.get('service', 'Unknown')}\n"
        response += f"**Time:** {self._format_timestamp(incident.get('timestamp'))}\n\n"
        
        error_counts = incident.get('error_counts', {})
        if error_counts:
            response += "**Error Breakdown:**\n"
            for error_type, count in error_counts.items():
                response += f"• {error_type.replace('_', ' ').title()}: {count}\n"
        
        return response
    
    def _get_rule_based_response(self, user_input: str, incidents: List[Dict[str, Any]]) -> str:
        """Get rule-based response as fallback"""
        query_type = self._analyze_query_type(user_input)
        
        if query_type == 'time_based':
            return self._handle_time_based_query(user_input)
        elif query_type == 'severity_based':
            return self._handle_severity_based_query(user_input)
        elif query_type == 'service_based':
            return self._handle_service_based_query(user_input)
        elif query_type == 'solution_based':
            return self._handle_solution_based_query(user_input)
        elif query_type == 'analysis_based':
            return self._handle_analysis_query(user_input, incidents)
        elif query_type == 'trend_based':
            return self._handle_trend_query(user_input, incidents)
        else:
            if re.search(r'\b(is|are|was|were|has|have|had|can|could|will|would|should)\b', user_input.lower()):
                return self._handle_yes_no_query(user_input, incidents)
            return self._handle_general_query(user_input)
    
    def _handle_analysis_query(self, user_input: str, incidents: List[Dict[str, Any]]) -> str:
        """Handle analysis-related queries"""
        if not incidents:
            return "No incidents available for analysis. Upload some logs first."
        
        incident = incidents[0]
        root_cause = incident.get('root_cause', 'Unknown')
        
        response = f"Analysis for {incident.get('id', 'incident')}: {root_cause}\n"
        
        diagnostic_report = incident.get('diagnostic_report', {})
        if isinstance(diagnostic_report, dict):
            error_patterns = diagnostic_report.get('error_patterns', {})
            if error_patterns:
                response += "\nError patterns:\n"
                for pattern, count in list(error_patterns.items())[:3]:
                    response += f"• {pattern.replace('_', ' ').title()}: {count}x\n"
        
        return response
    
    def _get_recommended_solutions(self) -> str:
        """Get recommended solutions from recent incidents"""
        recent_incidents = self.db_manager.get_recent_incidents(limit=10)
        
        if not recent_incidents:
            return "No incidents found. Upload logs to get recommendations."
        
        # Extract all recommendations
        all_recommendations = []
        for incident in recent_incidents:
            actions = incident.get('recommended_actions', [])
            all_recommendations.extend(actions)
        
        if not all_recommendations:
            return "No specific recommendations available."
        
        # Get unique recommendations
        unique_recommendations = list(dict.fromkeys(all_recommendations))  # Preserve order
        
        response = "Recommended solutions:\n"
        for i, recommendation in enumerate(unique_recommendations[:5], 1):
            response += f"{i}. {recommendation}\n"
        
        return response.strip()
    
    def _get_critical_incidents(self) -> str:
        """Get critical incidents from database"""
        critical_incidents = self.db_manager.get_incidents_by_severity('CRITICAL')
        
        if not critical_incidents:
            return "No critical incidents found."
        
        response = f"{len(critical_incidents)} critical incidents:\n"
        for i, incident in enumerate(critical_incidents[:5], 1):
            response += f"{i}. {incident.get('id', 'Unknown')} - {incident.get('service', 'Unknown')}\n"
        
        return response.strip()
    
    def _get_service_issues(self) -> str:
        """Get service issues from database"""
        all_incidents = self.db_manager.get_all_incidents()
        
        if not all_incidents:
            return "No service issues found."
        
        # Group by service
        service_counts = Counter(incident.get('service', 'Unknown') for incident in all_incidents)
        
        response = "Service issues:\n"
        for i, (service, count) in enumerate(service_counts.most_common(5), 1):
            response += f"{i}. {service}: {count} incidents\n"
        
        return response.strip()
    
    def _handle_trend_query(self, user_input: str, incidents: List[Dict[str, Any]]) -> str:
        """Handle trend and pattern queries"""
        if not incidents:
            return "No incidents available for trend analysis. Upload some logs first."
        
        severity_counts = Counter(incident.get('severity', 'Unknown') for incident in incidents)
        service_counts = Counter(incident.get('service', 'Unknown') for incident in incidents)
        
        response = f"Trends from {len(incidents)} incidents:\n\n"
        
        response += "By severity:\n"
        for severity, count in severity_counts.most_common():
            response += f"• {severity}: {count}\n"
        
        response += "\nBy service:\n"
        for service, count in service_counts.most_common(3):
            response += f"• {service}: {count}\n"
        
        return response
