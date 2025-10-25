from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import re
import json


class IncidentAnalyzer:
    def _detect_incidents_from_patterns(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect incidents from logs using pattern matching when no incident_id is available

        Args:
            logs: List of normalized log entries

        Returns:
            List of detected incidents
        """
        incidents = []

        # Group logs by service
        service_groups = defaultdict(list)
        for log in logs:
            service = log.get('service', 'unknown')
            service_groups[service].append(log)

        # Analyze each service group
        for service, service_logs in service_groups.items():
            # Group by severity
            severity_groups = defaultdict(list)
            for log in service_logs:
                severity = log.get('severity', 'UNKNOWN').upper()
                severity_groups[severity].append(log)

            # Create incidents for each severity group
            for severity, severity_logs in severity_groups.items():
                if severity in ['CRITICAL', 'ERROR', 'HIGH', 'WARN', 'WARNING']:
                    incident_id = f"{service}_{severity}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                    incident = self._create_incident_from_group(incident_id, severity_logs)
                    if incident:
                        incidents.append(incident)

        return incidents

    def analyze_incidents(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze logs to detect incidents

        Args:
            logs: List of normalized log entries

        Returns:
            List of detected incidents
        """
        incidents = []

        # Group logs by incident_id if available
        incident_groups = defaultdict(list)

        # First pass - group logs by incident_id if available
        for log in logs:
            incident_id = log.get('incident_id')
            if incident_id:
                incident_groups[incident_id].append(log)
            else:
                # For logs without incident_id, group by service and time window (5 minutes)
                service = log.get('service', 'unknown')
                timestamp = log.get('timestamp', datetime.now().isoformat())
                
                # Create time-based grouping key (group logs within 5-minute windows)
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    # Round to 5-minute intervals
                    rounded_minute = (dt.minute // 5) * 5
                    time_key = dt.replace(minute=rounded_minute, second=0, microsecond=0)
                    key = f"{service}_{time_key.isoformat()}"
                except:
                    # Fallback to original behavior if timestamp parsing fails
                    key = f"{service}_{timestamp}"
                
                incident_groups[key].append(log)

        # Second pass - analyze each group
        for incident_id, group_logs in incident_groups.items():
            # Create incident from group
            incident = self._create_incident_from_group(incident_id, group_logs)
            if incident:
                incidents.append(incident)

        # If no incidents were created from groups, fall back to error pattern detection
        if not incidents:
            incidents = self._detect_incidents_from_patterns(logs)

        return incidents

    def _create_incident_from_group(self, incident_id: str, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Create an incident from a group of logs with the same incident_id

        Args:
            incident_id: Incident ID or group key
            logs: List of logs in this group

        Returns:
            Incident dictionary or None if no incident detected
        """
        if not logs:
            return None

        # Get the most severe log in the group
        severity_order = {'CRITICAL': 0, 'ERROR': 1, 'WARN': 2, 'WARNING': 2, 'INFO': 3, 'DEBUG': 4}
        logs_with_severity = [log for log in logs if log.get('severity')]

        if logs_with_severity:
            # Sort by severity (most severe first)
            most_severe_log = sorted(
                logs_with_severity,
                key=lambda x: severity_order.get(x.get('severity', '').upper(), 5)
            )[0]
        else:
            most_severe_log = logs[0]

        # Generate diagnostic report first to get recommendations
        diagnostic_report = self._generate_diagnostic_report(logs)
        
        # Create incident
        incident = {
            'id': incident_id,
            'timestamp': most_severe_log.get('timestamp', datetime.now().isoformat()),
            'service': most_severe_log.get('service', 'unknown'),
            'severity': most_severe_log.get('severity', 'MEDIUM').upper(),
            'title': most_severe_log.get('title', most_severe_log.get('message', 'Incident detected')),
            'log_count': len(logs),
            'root_cause': self._determine_root_cause(logs),
            'error_counts': self._count_errors_by_type(logs),
            'diagnostic_report': diagnostic_report,
            'recommended_actions': diagnostic_report.get('recommended_actions', []) if isinstance(diagnostic_report, dict) else []
        }

        # Add region if available
        if 'region' in most_severe_log:
            incident['region'] = most_severe_log['region']

        return incident

    def _determine_root_cause(self, logs: List[Dict[str, Any]]) -> str:
        """
        Analyze logs to determine the most likely root cause
        
        Args:
            logs: List of log entries for analysis
            
        Returns:
            Root cause description
        """
        if not logs:
            return "Insufficient data for root cause analysis"
        
        # Analyze error patterns
        error_patterns = self._analyze_error_patterns(logs)
        
        # Check for common failure scenarios (prioritize performance and cloud issues)
        root_causes = []
        
        # Performance/Resource issues (high priority for cloud environments)
        performance_errors = [log for log in logs if self._is_performance_error(log)]
        if performance_errors:
            # Analyze specific performance issues
            cpu_issues = [log for log in performance_errors if 'cpu' in log.get('message', '').lower() or 'cpu' in log.get('title', '').lower()]
            memory_issues = [log for log in performance_errors if 'memory' in log.get('message', '').lower() or 'mem' in log.get('title', '').lower()]
            
            if cpu_issues:
                root_causes.append(f"High CPU utilization affecting performance ({len(cpu_issues)} occurrences)")
            if memory_issues:
                root_causes.append(f"Memory resource exhaustion ({len(memory_issues)} occurrences)")
            if not cpu_issues and not memory_issues:
                root_causes.append(f"Performance degradation and resource constraints ({len(performance_errors)} occurrences)")
        
        # Cloud Infrastructure issues
        cloud_errors = [log for log in logs if self._is_cloud_infrastructure_error(log)]
        if cloud_errors:
            root_causes.append(f"Cloud infrastructure issues ({len(cloud_errors)} occurrences)")
        
        # Database connection issues
        db_errors = [log for log in logs if self._is_database_error(log)]
        if db_errors:
            root_causes.append(f"Database connectivity issues ({len(db_errors)} occurrences)")
        
        # Memory/Resource issues (traditional)
        memory_errors = [log for log in logs if self._is_memory_error(log)]
        if memory_errors:
            root_causes.append(f"Memory/Resource exhaustion ({len(memory_errors)} occurrences)")
        
        # Network/Timeout issues
        network_errors = [log for log in logs if self._is_network_error(log)]
        if network_errors:
            root_causes.append(f"Network connectivity/timeout issues ({len(network_errors)} occurrences)")
        
        # Authentication/Authorization issues
        auth_errors = [log for log in logs if self._is_auth_error(log)]
        if auth_errors:
            root_causes.append(f"Authentication/Authorization failures ({len(auth_errors)} occurrences)")
        
        # Configuration issues
        config_errors = [log for log in logs if self._is_config_error(log)]
        if config_errors:
            root_causes.append(f"Configuration errors ({len(config_errors)} occurrences)")
        
        # API/Service dependency issues
        api_errors = [log for log in logs if self._is_api_error(log)]
        if api_errors:
            root_causes.append(f"External API/Service failures ({len(api_errors)} occurrences)")
        
        # If no specific patterns found, analyze by frequency
        if not root_causes:
            error_messages = [log.get('message', '') for log in logs if log.get('severity') in ['ERROR', 'CRITICAL']]
            if error_messages:
                most_common = Counter(error_messages).most_common(1)[0]
                root_causes.append(f"Recurring error pattern: {most_common[0][:100]}... ({most_common[1]} occurrences)")
        
        return "; ".join(root_causes) if root_causes else "Unable to determine specific root cause from available logs"
    
    def _analyze_error_patterns(self, logs: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze patterns in error messages"""
        patterns = defaultdict(int)
        
        for log in logs:
            message = log.get('message', '').lower()
            severity = log.get('severity', '').upper()
            
            if severity in ['ERROR', 'CRITICAL', 'FATAL']:
                # Common error patterns
                if 'timeout' in message or 'timed out' in message:
                    patterns['timeout_errors'] += 1
                elif 'connection' in message and ('refused' in message or 'failed' in message):
                    patterns['connection_errors'] += 1
                elif 'memory' in message or 'out of memory' in message or 'oom' in message:
                    patterns['memory_errors'] += 1
                elif 'permission' in message or 'unauthorized' in message or 'forbidden' in message:
                    patterns['permission_errors'] += 1
                elif 'not found' in message or '404' in message:
                    patterns['not_found_errors'] += 1
                elif 'internal server error' in message or '500' in message:
                    patterns['server_errors'] += 1
        
        return dict(patterns)
    
    def _is_database_error(self, log: Dict[str, Any]) -> bool:
        """Check if log indicates database-related error"""
        message = log.get('message', '').lower()
        db_keywords = ['database', 'sql', 'connection pool', 'deadlock', 'transaction', 'mysql', 'postgresql', 'mongodb', 'redis']
        error_keywords = ['error', 'failed', 'timeout', 'refused', 'unavailable']
        
        return any(db_word in message for db_word in db_keywords) and any(err_word in message for err_word in error_keywords)
    
    def _is_memory_error(self, log: Dict[str, Any]) -> bool:
        """Check if log indicates memory-related error"""
        message = log.get('message', '').lower()
        memory_keywords = ['out of memory', 'oom', 'memory leak', 'heap space', 'gc overhead', 'memory exhausted']
        
        return any(keyword in message for keyword in memory_keywords)
    
    def _is_network_error(self, log: Dict[str, Any]) -> bool:
        """Check if log indicates network-related error"""
        message = log.get('message', '').lower()
        network_keywords = ['connection timeout', 'network', 'socket', 'dns', 'host unreachable', 'connection refused']
        
        return any(keyword in message for keyword in network_keywords)
    
    def _is_auth_error(self, log: Dict[str, Any]) -> bool:
        """Check if log indicates authentication/authorization error"""
        message = log.get('message', '').lower()
        auth_keywords = ['unauthorized', 'forbidden', 'authentication', 'authorization', 'access denied', 'invalid token', 'expired token']
        
        return any(keyword in message for keyword in auth_keywords)
    
    def _is_config_error(self, log: Dict[str, Any]) -> bool:
        """Check if log indicates configuration error"""
        message = log.get('message', '').lower()
        config_keywords = ['configuration', 'config', 'property not found', 'missing parameter', 'invalid setting']
        
        return any(keyword in message for keyword in config_keywords)
    
    def _is_api_error(self, log: Dict[str, Any]) -> bool:
        """Check if log indicates API/external service error"""
        message = log.get('message', '').lower()
        api_keywords = ['api', 'rest', 'http', 'service unavailable', 'external service', 'third party']
        error_indicators = ['error', 'failed', '4xx', '5xx', 'timeout']
        
        return any(api_word in message for api_word in api_keywords) and any(err_word in message for err_word in error_indicators)
    
    def _is_performance_error(self, log: Dict[str, Any]) -> bool:
        """Check if log indicates performance/resource error"""
        message = log.get('message', '').lower()
        title = log.get('title', '').lower()
        
        performance_keywords = [
            'cpu', 'memory', 'disk', 'performance', 'slow', 'high utilization',
            'resource', 'threshold', 'limit exceeded', 'overload', 'bottleneck',
            'response time', 'latency', 'throughput'
        ]
        
        return any(keyword in message or keyword in title for keyword in performance_keywords)
    
    def _is_cloud_infrastructure_error(self, log: Dict[str, Any]) -> bool:
        """Check if log indicates cloud infrastructure error"""
        message = log.get('message', '').lower()
        title = log.get('title', '').lower()
        service = log.get('service', '').lower()
        
        cloud_keywords = [
            'aws', 'azure', 'gcp', 'ec2', 'instance', 'container', 'kubernetes',
            'docker', 'pod', 'node', 'cluster', 'load balancer', 'auto scaling',
            'cloudwatch', 'monitoring', 'metrics'
        ]
        
        return any(keyword in message or keyword in title or keyword in service for keyword in cloud_keywords)

    def _count_errors_by_type(self, logs: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Count different types of errors in the logs
        
        Args:
            logs: List of log entries
            
        Returns:
            Dictionary with error type counts
        """
        error_counts = defaultdict(int)
        
        for log in logs:
            severity = log.get('severity', '').upper()
            message = log.get('message', '').lower()
            
            # Count by severity
            if severity in ['CRITICAL', 'ERROR', 'WARN', 'WARNING', 'INFO', 'DEBUG']:
                error_counts[f"{severity.lower()}_count"] += 1
            
            # Count by error type (including performance and cloud errors)
            if severity in ['ERROR', 'CRITICAL', 'WARN', 'WARNING']:
                if self._is_database_error(log):
                    error_counts['database_errors'] += 1
                elif self._is_memory_error(log):
                    error_counts['memory_errors'] += 1
                elif self._is_network_error(log):
                    error_counts['network_errors'] += 1
                elif self._is_auth_error(log):
                    error_counts['auth_errors'] += 1
                elif self._is_config_error(log):
                    error_counts['config_errors'] += 1
                elif self._is_api_error(log):
                    error_counts['api_errors'] += 1
                elif self._is_performance_error(log):
                    error_counts['performance_errors'] += 1
                elif self._is_cloud_infrastructure_error(log):
                    error_counts['cloud_infrastructure_errors'] += 1
                else:
                    error_counts['other_errors'] += 1
        
        return dict(error_counts)

    def _generate_diagnostic_report(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate comprehensive diagnostic report
        
        Args:
            logs: List of log entries
            
        Returns:
            Diagnostic report dictionary
        """
        if not logs:
            return {"status": "No logs available for analysis"}
        
        # Basic statistics
        total_logs = len(logs)
        error_logs = [log for log in logs if log.get('severity') in ['ERROR', 'CRITICAL']]
        warning_logs = [log for log in logs if log.get('severity') in ['WARN', 'WARNING']]
        
        # Time analysis
        timestamps = [log.get('timestamp') for log in logs if log.get('timestamp')]
        time_analysis = self._analyze_time_patterns(timestamps)
        
        # Service analysis
        services = [log.get('service') for log in logs if log.get('service')]
        service_analysis = Counter(services).most_common(5)
        
        # Error pattern analysis
        error_patterns = self._analyze_error_patterns(logs)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(logs, error_patterns)
        
        # Calculate severity score
        severity_score = self._calculate_severity_score(logs)
        
        report = {
            "summary": {
                "total_logs": total_logs,
                "error_count": len(error_logs),
                "warning_count": len(warning_logs),
                "severity_score": severity_score,
                "analysis_timestamp": datetime.now().isoformat()
            },
            "time_analysis": time_analysis,
            "service_analysis": {
                "affected_services": len(set(services)),
                "top_services": service_analysis
            },
            "error_patterns": error_patterns,
            "recommended_actions": recommendations,
            "technical_details": {
                "log_sources": list(set(log.get('service', 'unknown') for log in logs)),
                "severity_distribution": dict(Counter(log.get('severity', 'unknown') for log in logs)),
                "error_rate": round(len(error_logs) / total_logs, 3) if total_logs > 0 else 0
            }
        }
        
        return report
    
    def _analyze_time_patterns(self, timestamps: List[str]) -> Dict[str, Any]:
        """Analyze temporal patterns in logs"""
        if not timestamps:
            return {"status": "No timestamps available"}
        
        try:
            # Parse timestamps
            parsed_times = []
            for ts in timestamps:
                if ts:
                    try:
                        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                        parsed_times.append(dt)
                    except:
                        continue
            
            if not parsed_times:
                return {"status": "Unable to parse timestamps"}
            
            # Sort times
            parsed_times.sort()
            
            # Calculate duration
            duration = (parsed_times[-1] - parsed_times[0]).total_seconds() / 60  # minutes
            
            # Calculate rate
            rate = len(parsed_times) / max(duration, 1)  # logs per minute
            
            return {
                "start_time": parsed_times[0].isoformat(),
                "end_time": parsed_times[-1].isoformat(),
                "duration_minutes": round(duration, 2),
                "log_rate_per_minute": round(rate, 2),
                "total_events": len(parsed_times)
            }
        except Exception as e:
            return {"status": f"Time analysis failed: {str(e)}"}
    
    def _generate_recommendations(self, logs: List[Dict[str, Any]], error_patterns: Dict[str, int]) -> List[str]:
        """Generate actionable recommendations based on log analysis"""
        recommendations = []
        
        # Performance/Resource-related recommendations (prioritize for cloud incidents)
        performance_errors = sum(1 for log in logs if self._is_performance_error(log))
        if performance_errors > 0:
            recommendations.append("Scale up instance resources (CPU/Memory) or implement auto-scaling")
            recommendations.append("Optimize application performance and resource usage")
            recommendations.append("Set up CloudWatch alarms for CPU and memory thresholds")
            recommendations.append("Review and tune application configuration for better resource efficiency")
        
        # Cloud Infrastructure recommendations
        cloud_errors = sum(1 for log in logs if self._is_cloud_infrastructure_error(log))
        if cloud_errors > 0:
            recommendations.append("Check cloud service health and regional status")
            recommendations.append("Review instance types and right-size infrastructure")
            recommendations.append("Implement multi-AZ deployment for high availability")
            recommendations.append("Set up comprehensive cloud monitoring and alerting")
        
        # Database-related recommendations
        db_errors = sum(1 for log in logs if self._is_database_error(log))
        if db_errors > 0:
            recommendations.append("Check database connection pool settings and increase timeout values")
            recommendations.append("Monitor database performance and optimize slow queries")
        
        # Memory-related recommendations
        memory_errors = sum(1 for log in logs if self._is_memory_error(log))
        if memory_errors > 0:
            recommendations.append("Increase memory allocation and implement memory monitoring")
            recommendations.append("Review application for memory leaks and optimize garbage collection")
        
        # Network-related recommendations
        network_errors = sum(1 for log in logs if self._is_network_error(log))
        if network_errors > 0:
            recommendations.append("Check network connectivity and DNS resolution")
            recommendations.append("Implement retry mechanisms with exponential backoff")
        
        # Authentication recommendations
        auth_errors = sum(1 for log in logs if self._is_auth_error(log))
        if auth_errors > 0:
            recommendations.append("Review authentication configuration and token management")
            recommendations.append("Implement proper session management and security policies")
        
        # Configuration recommendations
        config_errors = sum(1 for log in logs if self._is_config_error(log))
        if config_errors > 0:
            recommendations.append("Validate configuration files and environment variables")
            recommendations.append("Implement configuration management and version control")
        
        # API/Service recommendations
        api_errors = sum(1 for log in logs if self._is_api_error(log))
        if api_errors > 0:
            recommendations.append("Check external API service status and implement circuit breakers")
            recommendations.append("Add retry logic with exponential backoff for API calls")
        
        # High error rate recommendations
        error_rate = len([log for log in logs if log.get('severity') in ['ERROR', 'CRITICAL']]) / len(logs) if logs else 0
        if error_rate > 0.1:  # More than 10% errors
            recommendations.append("Implement comprehensive error handling and logging")
            recommendations.append("Set up real-time monitoring and alerting for error spikes")
        
        # Specific recommendations based on log content analysis
        cpu_issues = any('cpu' in log.get('message', '').lower() or 'cpu' in log.get('title', '').lower() for log in logs)
        memory_issues = any('memory' in log.get('message', '').lower() or 'mem' in log.get('title', '').lower() for log in logs)
        
        if cpu_issues:
            recommendations.append("Investigate high CPU usage and optimize CPU-intensive processes")
            recommendations.append("Consider upgrading to higher CPU instance types")
        
        if memory_issues:
            recommendations.append("Investigate memory usage patterns and optimize memory allocation")
            recommendations.append("Consider upgrading to higher memory instance types")
        
        # General recommendations if no specific patterns found
        if not recommendations:
            recommendations.extend([
                "Implement comprehensive monitoring and alerting",
                "Review application logs for recurring patterns", 
                "Set up automated health checks and diagnostics",
                "Establish incident response procedures"
            ])
        
        return recommendations[:10]  # Limit to 10 recommendations
    
    def _calculate_severity_score(self, logs: List[Dict[str, Any]]) -> float:
        """Calculate overall severity score (0-100)"""
        if not logs:
            return 0.0
        
        severity_weights = {
            'CRITICAL': 10,
            'ERROR': 7,
            'WARN': 4,
            'WARNING': 4,
            'INFO': 1,
            'DEBUG': 0.5
        }
        
        total_weight = 0
        for log in logs:
            severity = log.get('severity', '').upper()
            total_weight += severity_weights.get(severity, 1)
        
        # Normalize to 0-100 scale
        max_possible = len(logs) * 10  # All critical
        score = (total_weight / max_possible) * 100 if max_possible > 0 else 0
        
        return min(100, round(score, 1))
