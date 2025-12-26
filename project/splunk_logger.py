import json
import time
import logging
from datetime import datetime
from flask import current_app, request, session
from flask_login import current_user
import requests

class SplunkLogger:
    """Splunk integration for security logging"""
    
    def __init__(self, app=None):
        self.app = app
        self.service = None
        self.hec_url = None
        self.enabled = False
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize Splunk connection"""
        self.app = app
        
        # HTTP Event Collector URL - always try this first
        splunk_host = app.config.get('SPLUNK_HOST', 'splunk')
        splunk_port = app.config.get('SPLUNK_PORT', '8088')
        self.hec_url = f"http://{splunk_host}:{splunk_port}/services/collector"
        
        app.logger.info(f"Splunk HEC URL: {self.hec_url}")
        
        # Check if we have the required HEC token
        if app.config.get('SPLUNK_HEC_TOKEN'):
            self.enabled = True
            app.logger.info("Splunk HEC logging enabled")
        else:
            app.logger.warning("No SPLUNK_HEC_TOKEN found - logging disabled")
            self.enabled = False
    
    def log_security_event(self, event_type, data=None, severity="INFO"):
        """Log security events to Splunk"""
        print(f"DEBUG: log_security_event called - enabled: {self.enabled}")  # Debug print
        
        if not self.enabled:
            print("DEBUG: Logging not enabled")  # Debug print
            return True  # Fail silently
            
        if not current_app.config.get('SPLUNK_HEC_TOKEN'):
            print("DEBUG: No HEC token")  # Debug print
            return False
        
        try:
            event_data = {
                "time": int(time.time()),
                "event": {
                    "event_type": event_type,
                    "severity": severity,
                    "timestamp": datetime.utcnow().isoformat(),
                    "source_ip": request.remote_addr if request else None,
                    "user_agent": request.headers.get('User-Agent') if request else None,
                    "session_id": session.get('session_id') if session else None,
                    "user_id": current_user.user_id if current_user and current_user.is_authenticated else None,
                    "username": current_user.username if current_user and current_user.is_authenticated else None,
                    "data": data or {}
                },
                "sourcetype": "app_security_event",
                "index": current_app.config.get('SPLUNK_INDEX', 'main')
            }
            
            print(f"DEBUG: Sending event data: {json.dumps(event_data, indent=2)}")  # Debug print
            
            return self._send_to_hec(event_data)
        except Exception as e:
            print(f"DEBUG: Exception in log_security_event: {e}")  # Debug print
            if current_app:
                current_app.logger.error(f"Failed to log security event: {e}")
            return False
    
    def log_login_attempt(self, username, success, failure_reason=None):
        """Log login attempts for behavioral analysis"""
        try:
            data = {
                "username": username,
                "success": success,
                "failure_reason": failure_reason,
                "ip_address": request.remote_addr if request else None,
                "user_agent": request.headers.get('User-Agent') if request else None
            }
            
            event_type = "login_success" if success else "login_failure"
            severity = "INFO" if success else "WARNING"
            
            return self.log_security_event(event_type, data, severity)
        except Exception as e:
            if current_app:
                current_app.logger.error(f"Failed to log login attempt: {e}")
            return False
    
    def log_access_violation(self, resource, action, reason):
        """Log unauthorized access attempts"""
        try:
            data = {
                "resource": resource,
                "action": action,
                "reason": reason,
                "referrer": request.referrer if request else None
            }
            
            return self.log_security_event("access_violation", data, "HIGH")
        except Exception as e:
            if current_app:
                current_app.logger.error(f"Failed to log access violation: {e}")
            return False
    
    def _send_to_hec(self, event_data):
        """Send event to Splunk HTTP Event Collector"""
        if not self.enabled:
            print("DEBUG: HEC not enabled")  # Debug print
            return True
            
        try:
            headers = {
                'Authorization': f"Splunk {current_app.config['SPLUNK_HEC_TOKEN']}",
                'Content-Type': 'application/json'
            }
            
            print(f"DEBUG: Sending to {self.hec_url}")  # Debug print
            print(f"DEBUG: Headers: {headers}")  # Debug print
            
            response = requests.post(
                self.hec_url,
                headers=headers,
                data=json.dumps(event_data),
                verify=current_app.config.get('SPLUNK_VERIFY_SSL', False),
                timeout=5
            )
            
            print(f"DEBUG: Response status: {response.status_code}")  # Debug print
            print(f"DEBUG: Response text: {response.text}")  # Debug print
            
            return response.status_code == 200
        
        except Exception as e:
            print(f"DEBUG: Exception in _send_to_hec: {e}")  # Debug print
            if current_app:
                current_app.logger.error(f"Failed to send to Splunk HEC: {e}")
            return False

# Global instance
splunk_logger = SplunkLogger()