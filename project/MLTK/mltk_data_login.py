"""
Generate test login data for Splunk MLTK anomalous login detection
This script creates realistic login patterns for multiple user types
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

class MLTKTestDataGenerator:
    def __init__(self):
        self.hec_url = f"http://{os.getenv('SPLUNK_HOST', 'localhost')}:{os.getenv('SPLUNK_PORT', '8088')}/services/collector"
        #self.hec_token = '5c6ddb02-e1aa-4dee-baf5-f09d51ca1870'
        self.index = "main"
        # Define user profiles with normal behavior patterns
        self.user_profiles = {
            'user': {
                'description': 'Regular office worker (9-5)',
                'total_events': 120,
                'patterns': [
                    {'weight': 0.70, 'hours': range(9, 18), 'days': range(0, 5), 'ip': '192.168.1.100'},  # Weekday work
                    {'weight': 0.15, 'hours': range(18, 22), 'days': range(0, 5), 'ip': '192.168.1.100'},  # Weekday evening
                    {'weight': 0.10, 'hours': range(10, 15), 'days': range(5, 7), 'ip': '192.168.1.100'},  # Weekend
                    {'weight': 0.05, 'hours': range(9, 18), 'days': range(0, 5), 'ip': '10.0.10.50'},     # From office
                ]
            },
            'user2': {
                'description': 'Night shift worker',
                'total_events': 120,
                'patterns': [
                    {'weight': 0.75, 'hours': list(range(22, 24)) + list(range(0, 7)), 'days': range(0, 5), 'ip': '10.0.0.50'},  # Night shift
                    {'weight': 0.15, 'hours': list(range(23, 24)) + list(range(0, 6)), 'days': range(5, 7), 'ip': '10.0.0.50'},  # Weekend nights
                    {'weight': 0.10, 'hours': range(14, 18), 'days': range(0, 7), 'ip': '10.0.0.50'},  # Afternoon (rare)
                ]
            },
            'user3': {
                'description': 'Freelancer with irregular schedule',
                'total_events': 120,
                'patterns': [
                    {'weight': 0.40, 'hours': range(10, 18), 'days': range(0, 7), 'ip': '172.16.0.100'},  # Home
                    {'weight': 0.30, 'hours': range(19, 23), 'days': range(0, 7), 'ip': '172.16.0.100'},  # Evening
                    {'weight': 0.20, 'hours': range(10, 18), 'days': range(0, 7), 'ip': '192.168.50.25'}, # Coworking
                    {'weight': 0.10, 'hours': range(8, 20), 'days': range(0, 7), 'ip': '203.0.113.42'},   # Coffee shop
                ]
            },
            'user4': {
                'description': 'Executive with travel',
                'total_events': 100,
                'patterns': [
                    {'weight': 0.60, 'hours': range(8, 20), 'days': range(0, 5), 'ip': '10.20.30.40'},    # Office
                    {'weight': 0.20, 'hours': range(7, 23), 'days': range(0, 5), 'ip': '192.168.1.200'},  # Home
                    {'weight': 0.15, 'hours': range(6, 23), 'days': range(0, 7), 'ip': '185.125.190.36'}, # Hotel (travel)
                    {'weight': 0.05, 'hours': range(10, 18), 'days': range(5, 7), 'ip': '192.168.1.200'}, # Weekend
                ]
            },
            'admin': {
                'description': 'Admin with irregular hours',
                'total_events': 100,
                'patterns': [
                    {'weight': 0.35, 'hours': range(14, 20), 'days': range(0, 5), 'ip': '172.20.10.5'},   # Afternoon/evening
                    {'weight': 0.30, 'hours': range(20, 24), 'days': range(0, 7), 'ip': '172.20.10.5'},   # Late night
                    {'weight': 0.20, 'hours': range(10, 16), 'days': range(5, 7), 'ip': '172.20.10.5'},   # Weekend
                    {'weight': 0.15, 'hours': range(9, 17), 'days': range(0, 5), 'ip': '10.100.50.25'},   # Office
                ]
            }
        }
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
        ]
    
    def generate_timestamp(self, days_ago, hour):
        """Generate a timestamp for specified days ago and hour"""
        base_date = datetime.now() - timedelta(days=days_ago)
        # Add some randomness to minutes
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
    
    def select_pattern(self, patterns):
        """Select a pattern based on weights"""
        total_weight = sum(p['weight'] for p in patterns)
        normalized_weights = [p['weight'] / total_weight for p in patterns]
        return random.choices(patterns, weights=normalized_weights, k=1)[0]
    
    def generate_events_for_user(self, username, profile):
        """Generate login events for a specific user"""
        events = []
        total_events = profile['total_events']
        patterns = profile['patterns']
        
        # Distribute events over last 14 days
        days_range = 14
        
        for i in range(total_events):
            # Select pattern based on weights
            pattern = self.select_pattern(patterns)
            
            # Random day within range
            days_ago = random.randint(0, days_range - 1)
            
            # Check if day of week matches pattern
            target_date = datetime.now() - timedelta(days=days_ago)
            day_of_week = target_date.weekday()
            
            # If day doesn't match pattern, adjust
            if day_of_week not in pattern['days']:
                valid_day = random.choice(pattern['days'])
                days_ago = days_ago + (valid_day - day_of_week)
            
            # Select hour from pattern
            hour = random.choice(pattern['hours'])
            
            # Generate timestamp
            event_time = self.generate_timestamp(days_ago, hour)
            
            # Create event
            event = {
                'timestamp': event_time,
                'username': username,
                'source_ip': pattern['ip'],
                'user_agent': random.choice(self.user_agents),
                'success': True,
                'event_type': 'login_success'
            }
            
            events.append(event)
        
        # Sort by timestamp
        events.sort(key=lambda x: x['timestamp'])
        return events
    
    def generate_anomalous_events(self, username):
        """Generate anomalous events for testing detection - MLTK-optimized"""
        anomalies = []
        
        # Define unusual hours based on user profile
        unusual_hours_map = {
            'user': [2, 3, 4, 23],  # Office worker shouldn't login at 2-4 AM
            'user2': [10, 11, 12, 13],  # Night shift shouldn't login midday
            'user3': [1, 2, 3, 4],  # Even freelancer rarely at 1-4 AM
            'user4': [0, 1, 2, 3, 4],  # Executive unusual at very early morning
            'admin': [0, 1, 2, 3, 4, 5]  # Admin unusual at very early morning
        }
        
        unusual_hours = unusual_hours_map.get(username, [2, 3, 4])
        
        # Anomaly Set 1: Logins at unusual hours (spread over 7 days)
        for day_offset in range(1, 8):
            unusual_hour = random.choice(unusual_hours)
            anomalies.append({
                'timestamp': self.generate_timestamp(day_offset, unusual_hour),
                'username': username,
                'source_ip': '192.168.1.100',  # Same familiar IP
                'user_agent': self.user_agents[0],
                'success': True,
                'event_type': 'login_success',
                'anomaly_type': 'unusual_hour'
            })
        
        # Anomaly Set 2: Logins from completely new IPs (spread over 5 days)
        unusual_ips = [
            '45.76.123.89',  # Different region
            '203.0.113.100',  # Another unusual IP
            '185.220.101.50',  # Suspicious IP range
            '91.215.85.20',  # Foreign IP
            '37.48.65.148'  # Another foreign IP
        ]
        for day_offset in [1, 2, 3, 4, 5]:
            hour = random.choice([9, 10, 14, 15, 20])  # Normal hours but unusual IP
            anomalies.append({
                'timestamp': self.generate_timestamp(day_offset, hour),
                'username': username,
                'source_ip': unusual_ips[day_offset - 1],
                'user_agent': self.user_agents[0],
                'success': True,
                'event_type': 'login_success',
                'anomaly_type': 'unusual_ip'
            })
        
        # Anomaly Set 3: Rapid succession logins (credential stuffing - 3 separate incidents)
        for incident in range(3):
            day_offset = incident + 1
            base_hour = random.choice([3, 4, 14, 15, 21])  # Various times
            base_time = self.generate_timestamp(day_offset, base_hour)
            
            for j in range(7):  # 7 rapid logins in short succession
                anomalies.append({
                    'timestamp': base_time + timedelta(minutes=j * 2),
                    'username': username,
                    'source_ip': f'103.{random.randint(50, 200)}.{random.randint(1, 255)}.{random.randint(1, 255)}',
                    'user_agent': self.user_agents[0],
                    'success': True,
                    'event_type': 'login_success',
                    'anomaly_type': 'rapid_succession'
                })
        
        # Anomaly Set 4: Weekend activity for weekday users
        if username in ['user', 'user2']:  # These users rarely login on weekends
            for weekend_day in [5, 6]:  # Saturday, Sunday
                unusual_hour = random.choice([2, 3, 22, 23])
                timestamp = datetime.now() - timedelta(days=weekend_day)
                timestamp = timestamp.replace(hour=unusual_hour, minute=random.randint(0, 59))
                anomalies.append({
                    'timestamp': timestamp,
                    'username': username,
                    'source_ip': '198.51.100.75',  # Yet another unusual IP
                    'user_agent': self.user_agents[1],  # Different user agent too
                    'success': True,
                    'event_type': 'login_success',
                    'anomaly_type': 'unusual_day_and_hour'
                })
        
        return anomalies
    
    def send_to_splunk(self, event, dry_run=False):
        """Send event to Splunk HEC"""
        if dry_run:
            print(f"[DRY RUN] Would send: {event['timestamp']} - {event['username']} from {event['source_ip']}")
            return True
        
        event_data = {
            "time": int(event['timestamp'].timestamp()),
            "event": {
                "event_type": event['event_type'],
                "severity": "INFO",
                "timestamp": event['timestamp'].isoformat(),
                "source_ip": event['source_ip'],
                "user_agent": event['user_agent'],
                "user_id": hash(event['username']) % 10000,  # Dummy user ID
                "username": event['username'],
                "data": {
                    "success": event['success'],
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
        print("MLTK Test Data Generator")
        print("=" * 80)
        print(f"\nMode: {'DRY RUN' if dry_run else 'LIVE'}")
        print(f"Target: {self.hec_url}")
        print(f"Index: {self.index}\n")
        
        total_events = 0
        total_anomalies = 0
        
        for username, profile in self.user_profiles.items():
            print(f"\nGenerating events for {username} ({profile['description']})...")
            print(f"  Target: {profile['total_events']} events")
            
            # Generate normal events
            events = self.generate_events_for_user(username, profile)
            
            # Send to Splunk
            success_count = 0
            for event in events:
                if self.send_to_splunk(event, dry_run):
                    success_count += 1
                    if not dry_run and success_count % 10 == 0:
                        print(f"  Sent {success_count}/{len(events)} events...")
                        time.sleep(0.1)  # Small delay to avoid overwhelming HEC
            
            print(f"  ✓ Sent {success_count} normal events")
            total_events += success_count
            
            # Generate anomalies if requested
            if include_anomalies:
                anomalies = self.generate_anomalous_events(username)
                anomaly_count = 0
                for anomaly in anomalies:
                    if self.send_to_splunk(anomaly, dry_run):
                        anomaly_count += 1
                
                print(f"  ✓ Sent {anomaly_count} anomalous events")
                total_anomalies += anomaly_count
        
        print("\n" + "=" * 80)
        print(f"SUMMARY")
        print("=" * 80)
        print(f"Total users: {len(self.user_profiles)}")
        print(f"Total normal events: {total_events}")
        print(f"Total anomalous events: {total_anomalies}")
        print(f"Grand total: {total_events + total_anomalies}")
        print("\nNext steps:")
        print("1. Wait 2-3 minutes for Splunk to index the data")
        print("2. Verify data in Splunk:")
        print("   index=main sourcetype=app_security_event | stats count by username")
        print("3. Run MLTK detection query:")
        print("   index=main sourcetype=app_security_event event_type=\"login_success\"")
        print("   | eval hour=tonumber(strftime(_time, \"%H\"))")
        print("   | fit DensityFunction hour by username")
        print("   | search IsOutlier(DensityFunction)=\"True\"")
        print("=" * 80)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate MLTK test data')
    parser.add_argument('--dry-run', action='store_true', help='Print events without sending to Splunk')
    parser.add_argument('--no-anomalies', action='store_true', help='Skip generating anomalous events')
    
    args = parser.parse_args()
    
    generator = MLTKTestDataGenerator()
    generator.generate_all_data(
        dry_run=args.dry_run,
        include_anomalies=not args.no_anomalies
    )


if __name__ == '__main__':
    main()
