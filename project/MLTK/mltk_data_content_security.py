"""
Generate test content security data for Splunk MLTK
This script creates realistic PII detection patterns for anomaly detection

Use Cases:
- Detect users repeatedly posting sensitive information
- Identify unusual spikes in PII detections
- Flag accounts that consistently trigger high-severity PII warnings
- Detect coordinated data exfiltration attempts
"""

import json
import time
import random
import requests
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class MLTKContentSecurityDataGenerator:
    def __init__(self):
        self.hec_url = f"http://{os.getenv('SPLUNK_HOST', 'localhost')}:{os.getenv('SPLUNK_PORT', '8088')}/services/collector"
        #self.hec_token = '5c6ddb02-e1aa-4dee-baf5-f09d51ca1870'
        self.index = "main"
        
        # Define user behavior profiles for content security
        self.user_profiles = {
            'normal_user_1': {
                'description': 'Careful user - rarely posts PII',
                'total_events': 100,
                'pii_rate': 0.02,  # 2% of posts contain PII
                'severity_distribution': {'LOW': 0.8, 'MEDIUM': 0.15, 'HIGH': 0.05}
            },
            'normal_user_2': {
                'description': 'Average user - occasional PII',
                'total_events': 120,
                'pii_rate': 0.05,  # 5% of posts contain PII
                'severity_distribution': {'LOW': 0.7, 'MEDIUM': 0.25, 'HIGH': 0.05}
            },
            'careless_user': {
                'description': 'Careless user - moderate PII posting',
                'total_events': 150,
                'pii_rate': 0.12,  # 12% of posts contain PII
                'severity_distribution': {'LOW': 0.5, 'MEDIUM': 0.35, 'HIGH': 0.15}
            },
            'business_user': {
                'description': 'Business user - posts contact info',
                'total_events': 80,
                'pii_rate': 0.08,
                'severity_distribution': {'LOW': 0.85, 'MEDIUM': 0.10, 'HIGH': 0.05}  # Mostly emails/phone
            }
        }
        
        # PII types by severity
        self.pii_types = {
            'HIGH': ['nric', 'credit_card', 'ssn', 'passport', 'api_key'],
            'MEDIUM': ['singapore_phone', 'bank_account', 'driving_license_sg', 'mac_address', 'bitcoin_address'],
            'LOW': ['email', 'postal_code_sg', 'ip_address']
        }
        
        # Content types where PII can appear
        self.content_types = ['post', 'username', 'signup']
    
    def generate_timestamp(self, days_ago):
        """Generate a timestamp for specified days ago"""
        base_date = datetime.now() - timedelta(days=days_ago)
        hour = random.randint(8, 23)  # Active hours
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        
        return datetime(
            base_date.year,
            base_date.month,
            base_date.day,
            hour,
            minute,
            second
        )
    
    def generate_normal_events(self, username, profile):
        """Generate normal PII detection events for a user"""
        events = []
        total_events = profile['total_events']
        pii_rate = profile['pii_rate']
        severity_dist = profile['severity_distribution']
        
        # Calculate how many events should trigger PII
        pii_events_count = int(total_events * pii_rate)
        
        # Distribute events over last 14 days
        days_range = 14
        
        for i in range(pii_events_count):
            # Random day within range
            days_ago = random.randint(0, days_range - 1)
            timestamp = self.generate_timestamp(days_ago)
            
            # Select severity based on distribution
            severity = random.choices(
                list(severity_dist.keys()),
                weights=list(severity_dist.values()),
                k=1
            )[0]
            
            # Select PII types for this severity
            pii_types = random.sample(
                self.pii_types[severity],
                k=random.randint(1, 2)  # 1-2 PII types per event
            )
            
            # Calculate risk score (LOW: 10-30, MEDIUM: 31-60, HIGH: 61-100)
            if severity == 'LOW':
                risk_score = random.randint(10, 30)
            elif severity == 'MEDIUM':
                risk_score = random.randint(31, 60)
            else:
                risk_score = random.randint(61, 100)
            
            # Select content type
            content_type = random.choice(self.content_types)
            
            event = {
                'timestamp': timestamp,
                'username': username,
                'event_type': 'pii_detected',
                'content_type': content_type,
                'severity': severity,
                'risk_score': risk_score,
                'match_count': len(pii_types),
                'pii_types': pii_types,
                'safe_for_storage': severity == 'LOW',
                'anomaly_type': 'normal'
            }
            
            events.append(event)
        
        # Sort by timestamp
        events.sort(key=lambda x: x['timestamp'])
        return events
    
    def generate_anomalous_events(self, username):
        """Generate anomalous PII detection events"""
        anomalies = []
        
        # Anomaly Type 1: Sudden spike in PII detections (7 events in 1 hour)
        spike_day = random.randint(1, 5)
        spike_hour = random.randint(10, 20)
        base_time = datetime.now() - timedelta(days=spike_day, hours=24-spike_hour)
        
        for i in range(7):
            anomalies.append({
                'timestamp': base_time + timedelta(minutes=i * 8),
                'username': username,
                'event_type': 'pii_detected',
                'content_type': 'post',
                'severity': 'HIGH',
                'risk_score': random.randint(70, 95),
                'match_count': random.randint(2, 4),
                'pii_types': random.sample(self.pii_types['HIGH'], k=random.randint(2, 3)),
                'safe_for_storage': False,
                'anomaly_type': 'spike_high_severity'
            })
        
        # Anomaly Type 2: Multiple HIGH severity detections in short time (3 incidents)
        for incident in range(3):
            day_offset = incident + 1
            incident_time = self.generate_timestamp(day_offset)
            
            for j in range(3):
                anomalies.append({
                    'timestamp': incident_time + timedelta(minutes=j * 5),
                    'username': username,
                    'event_type': 'pii_detected',
                    'content_type': random.choice(['post', 'username']),
                    'severity': 'HIGH',
                    'risk_score': random.randint(75, 100),
                    'match_count': random.randint(3, 5),
                    'pii_types': random.sample(self.pii_types['HIGH'], k=3),
                    'safe_for_storage': False,
                    'anomaly_type': 'repeated_high_severity'
                })
        
        # Anomaly Type 3: Unusual PII types combination (credit card + NRIC + passport)
        for i in range(4):
            anomalies.append({
                'timestamp': self.generate_timestamp(random.randint(1, 7)),
                'username': username,
                'event_type': 'pii_detected',
                'content_type': 'post',
                'severity': 'HIGH',
                'risk_score': random.randint(80, 100),
                'match_count': 3,
                'pii_types': ['credit_card', 'nric', 'passport'],  # Suspicious combination
                'safe_for_storage': False,
                'anomaly_type': 'suspicious_combination'
            })
        
        # Anomaly Type 4: Off-hours PII posting (2-5 AM)
        for i in range(5):
            night_time = datetime.now() - timedelta(days=random.randint(1, 7))
            night_time = night_time.replace(hour=random.randint(2, 5), minute=random.randint(0, 59))
            
            anomalies.append({
                'timestamp': night_time,
                'username': username,
                'event_type': 'pii_detected',
                'content_type': 'post',
                'severity': random.choice(['MEDIUM', 'HIGH']),
                'risk_score': random.randint(50, 90),
                'match_count': random.randint(2, 4),
                'pii_types': random.sample(self.pii_types['HIGH'], k=2),
                'safe_for_storage': False,
                'anomaly_type': 'unusual_hour'
            })
        
        return anomalies
    
    def send_to_splunk(self, event, dry_run=False):
        """Send event to Splunk HEC"""
        if dry_run:
            print(f"[DRY RUN] Would send: {event['timestamp']} - {event['username']} - {event['severity']} - {event['anomaly_type']}")
            return True
        
        event_data = {
            "time": int(event['timestamp'].timestamp()),
            "event": {
                "event_type": event['event_type'],
                "severity": event['severity'],
                "timestamp": event['timestamp'].isoformat(),
                "source_ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "user_id": hash(event['username']) % 10000,
                "username": event['username'],
                "data": {
                    "content_type": event['content_type'],
                    "risk_score": event['risk_score'],
                    "match_count": event['match_count'],
                    "pii_types": event['pii_types'],
                    "safe_for_storage": event['safe_for_storage'],
                    "anomaly_type": event.get('anomaly_type', 'normal')
                }
            },
            "sourcetype": "app_security_event",
            "index": self.index
        }
        
        try:
            headers = {
                'Authorization': f"Splunk {self.hec_token}",
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                self.hec_url,
                headers=headers,
                data=json.dumps(event_data),
                verify=False,
                timeout=5
            )
            
            if response.status_code == 200:
                return True
            else:
                print(f"Error sending event: {response.status_code} - {response.text}")
                return False
        
        except Exception as e:
            print(f"Exception sending event: {e}")
            return False
    
    def generate_all_data(self, dry_run=False, include_anomalies=True):
        """Generate all test data"""
        print("=" * 80)
        print("MLTK Content Security Test Data Generator")
        print("=" * 80)
        print(f"\nMode: {'DRY RUN' if dry_run else 'LIVE'}")
        print(f"Target: {self.hec_url}")
        print(f"Index: {self.index}\n")
        
        total_events = 0
        total_anomalies = 0
        
        for username, profile in self.user_profiles.items():
            print(f"\nGenerating events for {username} ({profile['description']})...")
            print(f"  Target: ~{int(profile['total_events'] * profile['pii_rate'])} PII detection events")
            
            # Generate normal events
            events = self.generate_normal_events(username, profile)
            
            # Send to Splunk
            success_count = 0
            for event in events:
                if self.send_to_splunk(event, dry_run):
                    success_count += 1
                    if not dry_run and success_count % 10 == 0:
                        time.sleep(0.1)  # Small delay
            
            print(f"  ✓ Sent {success_count} normal PII detection events")
            total_events += success_count
            
            # Generate anomalies for some users
            if include_anomalies and username in ['careless_user', 'normal_user_1']:
                anomalies = self.generate_anomalous_events(username)
                anomaly_count = 0
                for anomaly in anomalies:
                    if self.send_to_splunk(anomaly, dry_run):
                        anomaly_count += 1
                
                print(f"  ✓ Sent {anomaly_count} anomalous PII events")
                total_anomalies += anomaly_count
        
        print("\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"Total users: {len(self.user_profiles)}")
        print(f"Total normal PII events: {total_events}")
        print(f"Total anomalous PII events: {total_anomalies}")
        print(f"Grand total: {total_events + total_anomalies}")
        print("\nNext steps for MLTK:")
        print("1. Wait 2-3 minutes for Splunk to index the data")
        print("2. Verify data in Splunk:")
        print("   index=main event_type=\"pii_detected\" | stats count by username, severity")
        print("\n3. MLTK Anomaly Detection Queries:")
        print("\n   A) Detect unusual PII posting frequency:")
        print("   index=main event_type=\"pii_detected\"")
        print("   | bucket _time span=1h")
        print("   | stats count as pii_count by _time, username")
        print("   | fit DensityFunction pii_count by username into pii_frequency_model")
        print("\n   B) Detect unusual risk score patterns:")
        print("   index=main event_type=\"pii_detected\"")
        print("   | stats avg(data.risk_score) as avg_risk by username, _time")
        print("   | fit DensityFunction avg_risk by username into risk_pattern_model")
        print("\n   C) Detect unusual PII type combinations:")
        print("   index=main event_type=\"pii_detected\"")
        print("   | eval pii_combo=mvjoin('data.pii_types', \",\")")
        print("   | rare pii_combo by username")
        print("\n   D) Time-based anomaly detection (off-hours posting):")
        print("   index=main event_type=\"pii_detected\"")
        print("   | eval hour=tonumber(strftime(_time, \"%H\"))")
        print("   | fit DensityFunction hour by username severity")
        print("   | search IsOutlier(DensityFunction)=\"True\"")
        print("=" * 80)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate MLTK content security test data')
    parser.add_argument('--dry-run', action='store_true', help='Print events without sending to Splunk')
    parser.add_argument('--no-anomalies', action='store_true', help='Skip generating anomalous events')
    
    args = parser.parse_args()
    
    generator = MLTKContentSecurityDataGenerator()
    generator.generate_all_data(
        dry_run=args.dry_run,
        include_anomalies=not args.no_anomalies
    )


if __name__ == '__main__':
    main()
