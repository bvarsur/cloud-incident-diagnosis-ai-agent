"""
Local LLM Integration for Advanced Incident Analysis
Supports Ollama and Transformers for local AI processing
"""

import json
import logging
from typing import List, Dict, Any, Optional
import re
from datetime import datetime

class LocalLLM:
    """Local LLM integration for incident analysis"""
    
    def __init__(self, model_type: str = "ollama", model_name: str = "llama2"):
        self.model_type = model_type
        self.model_name = model_name
        self.logger = logging.getLogger(__name__)
        
        # Initialize based on model type
        if model_type == "ollama":
            self._init_ollama()
        elif model_type == "transformers":
            self._init_transformers()
        else:
            self.logger.warning(f"Unknown model type: {model_type}. Using fallback analysis.")
            self.model = None
    
    def _init_ollama(self):
        """Initialize Ollama client"""
        try:
            import ollama
            self.ollama_client = ollama
            self.logger.info("Ollama client initialized")
        except ImportError:
            self.logger.warning("Ollama not available. Install with: pip install ollama")
            self.ollama_client = None
    
    def _init_transformers(self):
        """Initialize Transformers model"""
        try:
            from transformers import pipeline
            self.pipeline = pipeline(
                "text-generation",
                model=self.model_name,
                device_map="auto"
            )
            self.logger.info(f"Transformers model {self.model_name} initialized")
        except ImportError:
            self.logger.warning("Transformers not available. Install with: pip install transformers torch")
            self.pipeline = None
    
    def analyze_incident_patterns(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Use local LLM to analyze incident patterns and generate insights
        
        Args:
            logs: List of log entries
            
        Returns:
            Analysis results with patterns and insights
        """
        if not logs:
            return {"patterns": [], "insights": [], "confidence": 0.0}
        
        # Prepare context for LLM
        context = self._prepare_log_context(logs)
        
        # Generate analysis prompt
        prompt = self._create_analysis_prompt(context)
        
        # Get LLM response
        if self.model_type == "ollama" and self.ollama_client:
            response = self._query_ollama(prompt)
        elif self.model_type == "transformers" and self.pipeline:
            response = self._query_transformers(prompt)
        else:
            # Fallback to rule-based analysis
            response = self._fallback_analysis(logs)
        
        # Parse and structure the response
        return self._parse_analysis_response(response, logs)
    
    def generate_incident_report(self, incident: Dict[str, Any], logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate comprehensive incident report using LLM
        
        Args:
            incident: Incident details
            logs: Related log entries
            
        Returns:
            Structured incident report
        """
        context = {
            "incident": incident,
            "logs": logs[:50]  # Limit to 50 most relevant logs
        }
        
        prompt = self._create_report_prompt(context)
        
        if self.model_type == "ollama" and self.ollama_client:
            response = self._query_ollama(prompt)
        elif self.model_type == "transformers" and self.pipeline:
            response = self._query_transformers(prompt)
        else:
            response = self._fallback_report(incident, logs)
        
        return self._parse_report_response(response)
    
    def suggest_remediation_actions(self, incident: Dict[str, Any], logs: List[Dict[str, Any]]) -> List[str]:
        """
        Generate remediation suggestions using LLM
        
        Args:
            incident: Incident details
            logs: Related log entries
            
        Returns:
            List of suggested remediation actions
        """
        context = {
            "incident": incident,
            "logs": logs[:30]  # Limit context
        }
        
        prompt = self._create_remediation_prompt(context)
        
        if self.model_type == "ollama" and self.ollama_client:
            response = self._query_ollama(prompt)
        elif self.model_type == "transformers" and self.pipeline:
            response = self._query_transformers(prompt)
        else:
            response = self._fallback_remediation(incident, logs)
        
        return self._parse_remediation_response(response)
    
    def _prepare_log_context(self, logs: List[Dict[str, Any]]) -> str:
        """Prepare log context for LLM analysis"""
        context_lines = []
        
        for log in logs[:100]:  # Limit to 100 logs for context
            timestamp = log.get('timestamp', 'Unknown')
            service = log.get('service', 'Unknown')
            severity = log.get('severity', 'INFO')
            message = log.get('message', '')[:200]  # Truncate long messages
            
            context_lines.append(f"[{timestamp}] {service} {severity}: {message}")
        
        return "\n".join(context_lines)
    
    def _create_analysis_prompt(self, context: str) -> str:
        """Create prompt for pattern analysis"""
        return f"""
Analyze the following log entries and identify patterns, anomalies, and potential incidents:

{context}

Please provide:
1. Key patterns observed
2. Anomalies or unusual behavior
3. Potential root causes
4. Severity assessment
5. Confidence level (0-100)

Format your response as JSON with the following structure:
{{
    "patterns": ["pattern1", "pattern2"],
    "anomalies": ["anomaly1", "anomaly2"],
    "root_causes": ["cause1", "cause2"],
    "severity": "LOW|MEDIUM|HIGH|CRITICAL",
    "confidence": 85
}}
"""
    
    def _create_report_prompt(self, context: Dict[str, Any]) -> str:
        """Create prompt for incident report generation"""
        incident = context["incident"]
        logs_summary = self._prepare_log_context(context["logs"])
        
        return f"""
Generate a comprehensive incident report for the following:

Incident Details:
- ID: {incident.get('id', 'Unknown')}
- Severity: {incident.get('severity', 'Unknown')}
- Service: {incident.get('service', 'Unknown')}
- Title: {incident.get('title', 'Unknown')}

Related Logs:
{logs_summary}

Please provide a structured report including:
1. Executive Summary
2. Technical Details
3. Impact Assessment
4. Root Cause Analysis
5. Recommended Actions
6. Prevention Measures

Format as JSON:
{{
    "executive_summary": "Brief overview",
    "technical_details": "Technical analysis",
    "impact_assessment": "Business impact",
    "root_cause_analysis": "Detailed root cause",
    "recommended_actions": ["action1", "action2"],
    "prevention_measures": ["measure1", "measure2"]
}}
"""
    
    def _create_remediation_prompt(self, context: Dict[str, Any]) -> str:
        """Create prompt for remediation suggestions"""
        incident = context["incident"]
        
        return f"""
Based on this incident, suggest specific remediation actions:

Incident: {incident.get('title', 'Unknown')}
Severity: {incident.get('severity', 'Unknown')}
Service: {incident.get('service', 'Unknown')}
Root Cause: {incident.get('root_cause', 'Unknown')}

Provide 5-7 specific, actionable remediation steps. Focus on:
1. Immediate fixes
2. Short-term improvements
3. Long-term prevention

Format as a JSON array of strings:
["action1", "action2", "action3"]
"""
    
    def _query_ollama(self, prompt: str) -> str:
        """Query Ollama model"""
        try:
            response = self.ollama_client.generate(
                model=self.model_name,
                prompt=prompt,
                options={
                    "temperature": 0.3,
                    "top_p": 0.9,
                    "max_tokens": 1000
                }
            )
            return response['response']
        except Exception as e:
            self.logger.error(f"Ollama query failed: {e}")
            return ""
    
    def _query_transformers(self, prompt: str) -> str:
        """Query Transformers model"""
        try:
            response = self.pipeline(
                prompt,
                max_length=500,
                num_return_sequences=1,
                temperature=0.3,
                do_sample=True
            )
            return response[0]['generated_text']
        except Exception as e:
            self.logger.error(f"Transformers query failed: {e}")
            return ""
    
    def _fallback_analysis(self, logs: List[Dict[str, Any]]) -> str:
        """Fallback analysis when LLM is not available"""
        error_count = sum(1 for log in logs if log.get('severity') in ['ERROR', 'CRITICAL'])
        warning_count = sum(1 for log in logs if log.get('severity') == 'WARN')
        
        patterns = []
        if error_count > 5:
            patterns.append("High error rate detected")
        if warning_count > 10:
            patterns.append("Multiple warnings observed")
        
        severity = "HIGH" if error_count > 10 else "MEDIUM" if error_count > 5 else "LOW"
        
        return json.dumps({
            "patterns": patterns,
            "anomalies": ["Error spike detected"] if error_count > 5 else [],
            "root_causes": ["Service degradation"] if error_count > 5 else [],
            "severity": severity,
            "confidence": 70
        })
    
    def _fallback_report(self, incident: Dict[str, Any], logs: List[Dict[str, Any]]) -> str:
        """Fallback report generation"""
        return json.dumps({
            "executive_summary": f"Incident {incident.get('id', 'Unknown')} occurred in {incident.get('service', 'Unknown')} service",
            "technical_details": f"Severity: {incident.get('severity', 'Unknown')}, Root cause: {incident.get('root_cause', 'Unknown')}",
            "impact_assessment": "Service degradation detected",
            "root_cause_analysis": incident.get('root_cause', 'Unknown'),
            "recommended_actions": incident.get('recommended_actions', []),
            "prevention_measures": ["Implement monitoring", "Set up alerting"]
        })
    
    def _fallback_remediation(self, incident: Dict[str, Any], logs: List[Dict[str, Any]]) -> str:
        """Fallback remediation suggestions"""
        actions = [
            "Check service health status",
            "Review recent configuration changes",
            "Monitor resource utilization",
            "Check dependencies and integrations",
            "Implement additional monitoring"
        ]
        return json.dumps(actions)
    
    def _parse_analysis_response(self, response: str, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Parse LLM analysis response"""
        try:
            # Try to extract JSON from response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                # Fallback parsing
                return self._fallback_analysis(logs)
        except json.JSONDecodeError:
            return self._fallback_analysis(logs)
    
    def _parse_report_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM report response"""
        try:
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                return self._fallback_report({}, [])
        except json.JSONDecodeError:
            return self._fallback_report({}, [])
    
    def _parse_remediation_response(self, response: str) -> List[str]:
        """Parse LLM remediation response"""
        try:
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                return self._fallback_remediation({}, [])
        except json.JSONDecodeError:
            return self._fallback_remediation({}, [])
    
    def chat_with_incidents(self, user_query: str, incidents: List[Dict[str, Any]]) -> str:
        """
        Chat interface for querying incidents using LLM
        
        Args:
            user_query: User's question
            incidents: List of incidents to query
            
        Returns:
            LLM response about incidents
        """
        if not incidents:
            return "No incidents found to analyze."
        
        # Prepare incident context with more detailed information
        incident_details = []
        for incident in incidents[:10]:  # Limit to 10 incidents
            # Create a more detailed context for each incident
            details = f"""Incident ID: {incident.get('id', 'Unknown')}
Title: {incident.get('title', 'No title')}
Severity: {incident.get('severity', 'Unknown')}
Service: {incident.get('service', 'Unknown')}
Timestamp: {incident.get('timestamp', 'Unknown')}
Log Count: {incident.get('log_count', 0)}
Root Cause: {incident.get('root_cause', 'Unknown')}"""
            
            # Add region if available
            if incident.get('region'):
                details += f"\nRegion: {incident.get('region')}"
                
            # Add error counts if available
            if incident.get('error_counts'):
                error_counts = incident.get('error_counts', {})
                error_str = ", ".join([f"{k}: {v}" for k, v in error_counts.items()])
                details += f"\nError Counts: {error_str}"
                
            # Add diagnostic report if available
            if incident.get('diagnostic_report'):
                report = incident.get('diagnostic_report', {})
                if report.get('recommended_actions'):
                    actions = "\n- " + "\n- ".join(report.get('recommended_actions', []))
                    details += f"\nRecommended Actions: {actions}"
                
            incident_details.append(details)
        
        context = "\n\n".join(incident_details)
        
        prompt = f"""
Based on the following incident data, answer the user's question accurately and helpfully:

INCIDENT DATA:
{context}

USER QUESTION: {user_query}

Provide a detailed, accurate response based on the incident data. Include specific details from the incidents when relevant.
If the question asks about recommendations or solutions, focus on the 'Recommended Actions' and 'Root Cause' fields.
If the question is about specific services or regions, highlight information from those specific incidents.
If you cannot find relevant information in the provided data, clearly state that limitation.
"""
        
        if self.model_type == "ollama" and self.ollama_client:
            response = self._query_ollama(prompt)
        elif self.model_type == "transformers" and self.pipeline:
            response = self._query_transformers(prompt)
        else:
            # Fallback response
            response = self._fallback_chat_response(user_query, incidents)
        
        return response.strip()
    
    def _fallback_chat_response(self, user_query: str, incidents: List[Dict[str, Any]]) -> str:
        """Fallback chat response when LLM is not available"""
        query_lower = user_query.lower()
        
        if "total" in query_lower and "incident" in query_lower:
            return f"There are {len(incidents)} total incidents in the database."
        elif "severity" in query_lower or "critical" in query_lower:
            high_severity = [i for i in incidents if i.get('severity') in ['HIGH', 'CRITICAL']]
            return f"Found {len(high_severity)} high-severity incidents."
        elif "service" in query_lower:
            services = list(set(i.get('service', 'Unknown') for i in incidents))
            return f"Incidents affect {len(services)} services: {', '.join(services[:5])}"
        else:
            return "I can help you analyze incidents. Try asking about total incidents, severity levels, or specific services."
