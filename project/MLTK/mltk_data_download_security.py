"""
Generate test download security data for Splunk MLTK
This script creates realistic post download patterns for anomaly detection

Use Cases:
- Detect data exfiltration (mass downloading)
- Identify automated scraping behavior
- Flag account compromise via unusual download patterns
- Detect insider threats (pre-deletion mass downloads)
- Monitor unusual geographic or time-based access
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

class MLTKDownloadSecurityDataGenerator:
    def __init__(self):
        self.hec_url = f"http://{os.getenv('SPLUNK_HOST', 'localhost')}:{os.getenv('SPLUNK_PORT', '8088')}/services/collector"
        # Update this with your actual HEC token from Splunk settings
        self.hec_token = '5c6ddb02-e1aa-4dee-baf5-f09d51ca1870'
        self.index = "main"
        
        # Define user behavior profiles for download patterns
        self.user_profiles = {
            'casual_downloader': {
                'description': 'Casual user - downloads own posts occasionally',
                'total_downloads': 30,
                'own_post_ratio': 0.85,  # 85% own posts
                'downloads_per_session': (1, 3),  # 1-3 downloads per session
                'session_frequency': 0.4,  # 40% of days active
                'active_hours': range(10, 22),
                'primary_ip': '192.168.1.100',
                'file_size_range': (100000, 2000000)  # 100KB - 2MB
            },
            'active_user': {
                'description': 'Active user - moderate downloading',
                'total_downloads': 80,
                'own_post_ratio': 0.60,  # 60% own posts
                'downloads_per_session': (2, 6),
                'session_frequency': 0.7,  # 70% of days active
                'active_hours': range(8, 23),
                'primary_ip': '192.168.1.150',
                'file_size_range': (200000, 3000000)  # 200KB - 3MB
            },
            'content_creator': {
                'description': 'Content creator - frequently downloads own work',
                'total_downloads': 120,
                'own_post_ratio': 0.90,  # 90% own posts
                'downloads_per_session': (3, 8),
                'session_frequency': 0.85,  # 85% of days active
                'active_hours': range(9, 20),
                'primary_ip': '192.168.1.200',
                'file_size_range': (500000, 5000000)  # 500KB - 5MB
            },
            'researcher': {
                'description': 'Researcher - downloads others posts for analysis',
                'total_downloads': 100,
                'own_post_ratio': 0.20,  # 20% own posts
                'downloads_per_session': (5, 12),
                'session_frequency': 0.6,  # 60% of days active
                'active_hours': range(9, 18),
                'primary_ip': '10.0.10.50',
                'file_size_range': (300000, 2500000)  # 300KB - 2.5MB
            },
            'business_user': {
                'description': 'Business user - regular scheduled downloads',
                'total_downloads': 60,
                'own_post_ratio': 0.50,  # 50% own posts
                'downloads_per_session': (3, 7),
                'session_frequency': 0.5,  # 50% of days active (weekdays mostly)
                'active_hours': range(9, 17),  # Business hours
                'primary_ip': '10.20.30.40',
                'file_size_range': (400000, 3500000)  # 400KB - 3.5MB
            }
        }
        
        # Post owner usernames for simulation
        self.post_owners = [
            'alice_photos', 'bob_art', 'charlie_design', 'diana_portfolio',
            'evan_graphics', 'fiona_images', 'george_pics', 'hannah_shots',
            'ian_creative', 'julia_media'
        ]
        
        # User agents for variety
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
        ]
    
    def generate_timestamp(self, days_ago, hour=None, minute=None):
        """Generate a timestamp for specified days ago"""
        base_date = datetime.now() - timedelta(days=days_ago)
        
        if hour is None:
            hour = random.randint(8, 22)
        if minute is None:
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
    
    def generate_normal_downloads(self, username, profile):
        """Generate normal download events for a user"""
        events = []
        total_downloads = profile['total_downloads']
        own_post_ratio = profile['own_post_ratio']
        session_frequency = profile['session_frequency']
        downloads_per_session = profile['downloads_per_session']
        active_hours = profile['active_hours']
        primary_ip = profile['primary_ip']
        file_size_range = profile['file_size_range']
        
        # Distribute downloads over last 14 days
        days_range = 14
        downloads_generated = 0
        
        for day_offset in range(days_range):
            # Check if user is active this day
            if random.random() > session_frequency:
                continue
            
            # Determine number of downloads for this session
            session_downloads = random.randint(*downloads_per_session)
            
            # Generate session start time
            session_hour = random.choice(active_hours)
            session_start = self.generate_timestamp(day_offset, session_hour)
            
            for i in range(session_downloads):
                if downloads_generated >= total_downloads:
                    break
                
                # Calculate download time (spread within 1-2 hours)
                download_time = session_start + timedelta(minutes=random.randint(0, 120))
                
                # Determine if downloading own post or others'
                is_own_post = random.random() < own_post_ratio
                
                if is_own_post:
                    post_owner = username
                else:
                    post_owner = random.choice(self.post_owners)
                
                # Generate realistic file details
                post_id = random.randint(1000, 9999)
                filename = f"image_{post_id}_{random.randint(100, 999)}.jpg"
                file_size = random.randint(*file_size_range)
                
                # User ID simulation
                downloader_id = hash(username) % 10000
                owner_id = hash(post_owner) % 10000
                
                event = {
                    'timestamp': download_time,
                    'post_id': post_id,
                    'post_owner_id': owner_id,
                    'post_owner_username': post_owner,
                    'downloader_id': downloader_id,
                    'downloader_username': username,
                    'filename': filename,
                    'file_size_bytes': file_size,
                    'is_own_post': is_own_post,
                    'source_ip': primary_ip,
                    'user_agent': random.choice(self.user_agents),
                    'anomaly_type': 'normal'
                }
                
                events.append(event)
                downloads_generated += 1
            
            if downloads_generated >= total_downloads:
                break
        
        # Sort by timestamp
        events.sort(key=lambda x: x['timestamp'])
        return events
    
    def generate_anomalous_events(self, username):
        """Generate anomalous download events for testing detection"""
        anomalies = []
        
        # Anomaly Type 1: Mass Download Spike (Data Exfiltration)
        # 25 downloads in 15 minutes
        spike_day = random.randint(1, 5)
        spike_hour = random.choice([2, 3, 14, 15, 22])
        spike_start = self.generate_timestamp(spike_day, spike_hour, 0)
        
        print(f"  → Generating mass download spike (25 downloads in 15 min)")
        for i in range(25):
            download_time = spike_start + timedelta(minutes=random.uniform(0, 15))
            post_owner = random.choice(self.post_owners)
            
            anomalies.append({
                'timestamp': download_time,
                'post_id': random.randint(1000, 9999),
                'post_owner_id': hash(post_owner) % 10000,
                'post_owner_username': post_owner,
                'downloader_id': hash(username) % 10000,
                'downloader_username': username,
                'filename': f"image_{random.randint(1000, 9999)}.jpg",
                'file_size_bytes': random.randint(500000, 3000000),
                'is_own_post': False,  # Downloading others' content
                'source_ip': '192.168.1.100',
                'user_agent': self.user_agents[0],
                'anomaly_type': 'mass_download_spike'
            })
        
        # Anomaly Type 2: Automated Scraping Pattern
        # Consistent 3-second intervals, 15 downloads
        scraping_day = random.randint(2, 6)
        scraping_start = self.generate_timestamp(scraping_day, 14, 30)
        
        print(f"  → Generating automated scraping pattern (15 downloads, 3s intervals)")
        for i in range(15):
            download_time = scraping_start + timedelta(seconds=i * 3)  # Exactly 3 seconds apart
            
            anomalies.append({
                'timestamp': download_time,
                'post_id': 5000 + i,  # Sequential post IDs
                'post_owner_id': hash(self.post_owners[i % len(self.post_owners)]) % 10000,
                'post_owner_username': self.post_owners[i % len(self.post_owners)],
                'downloader_id': hash(username) % 10000,
                'downloader_username': username,
                'filename': f"image_{5000 + i}.jpg",
                'file_size_bytes': random.randint(1000000, 2000000),
                'is_own_post': False,
                'source_ip': '45.76.123.89',  # Different IP
                'user_agent': 'Python-urllib/3.10',  # Bot user agent
                'anomaly_type': 'automated_scraping'
            })
        
        # Anomaly Type 3: Off-Hours Downloads (2-5 AM)
        # 8 downloads during suspicious hours
        print(f"  → Generating off-hours downloads (8 downloads, 2-5 AM)")
        for i in range(8):
            night_day = random.randint(1, 7)
            night_hour = random.randint(2, 5)
            night_time = self.generate_timestamp(night_day, night_hour)
            
            anomalies.append({
                'timestamp': night_time,
                'post_id': random.randint(1000, 9999),
                'post_owner_id': hash(random.choice(self.post_owners)) % 10000,
                'post_owner_username': random.choice(self.post_owners),
                'downloader_id': hash(username) % 10000,
                'downloader_username': username,
                'filename': f"image_{random.randint(1000, 9999)}.jpg",
                'file_size_bytes': random.randint(500000, 2500000),
                'is_own_post': False,
                'source_ip': '192.168.1.100',
                'user_agent': random.choice(self.user_agents),
                'anomaly_type': 'off_hours_access'
            })
        
        # Anomaly Type 4: Geographic Anomaly (Multiple Countries)
        # 12 downloads from different geographic locations
        foreign_ips = [
            ('185.125.190.36', 'Germany'),
            ('91.215.85.20', 'Russia'),
            ('37.48.65.148', 'Ukraine'),
            ('45.142.120.10', 'Netherlands'),
            ('203.0.113.100', 'Singapore'),
            ('198.51.100.75', 'USA')
        ]
        
        print(f"  → Generating geographic anomalies (12 downloads from 6 countries)")
        for i in range(12):
            geo_day = random.randint(1, 6)
            geo_hour = random.randint(10, 20)
            geo_time = self.generate_timestamp(geo_day, geo_hour)
            
            foreign_ip, country = foreign_ips[i % len(foreign_ips)]
            
            anomalies.append({
                'timestamp': geo_time,
                'post_id': random.randint(1000, 9999),
                'post_owner_id': hash(random.choice(self.post_owners)) % 10000,
                'post_owner_username': random.choice(self.post_owners),
                'downloader_id': hash(username) % 10000,
                'downloader_username': username,
                'filename': f"image_{random.randint(1000, 9999)}.jpg",
                'file_size_bytes': random.randint(400000, 2000000),
                'is_own_post': False,
                'source_ip': foreign_ip,
                'user_agent': random.choice(self.user_agents),
                'anomaly_type': f'geographic_anomaly_{country}'
            })
        
        # Anomaly Type 5: High Bandwidth Usage
        # Large files downloaded rapidly
        print(f"  → Generating high bandwidth usage (10 large files)")
        bandwidth_day = random.randint(1, 5)
        bandwidth_start = self.generate_timestamp(bandwidth_day, 16, 0)
        
        for i in range(10):
            download_time = bandwidth_start + timedelta(minutes=i * 3)
            
            anomalies.append({
                'timestamp': download_time,
                'post_id': random.randint(1000, 9999),
                'post_owner_id': hash(random.choice(self.post_owners)) % 10000,
                'post_owner_username': random.choice(self.post_owners),
                'downloader_id': hash(username) % 10000,
                'downloader_username': username,
                'filename': f"large_image_{random.randint(1000, 9999)}.jpg",
                'file_size_bytes': random.randint(8000000, 15000000),  # 8-15 MB files
                'is_own_post': False,
                'source_ip': '192.168.1.100',
                'user_agent': random.choice(self.user_agents),
                'anomaly_type': 'high_bandwidth_usage'
            })
        
        # Anomaly Type 6: Downloading from Multiple Unique Sources
        # 20 downloads from 15 different post owners (suspicious pattern)
        print(f"  → Generating multiple sources pattern (20 downloads, 15 owners)")
        sources_day = random.randint(1, 5)
        sources_start = self.generate_timestamp(sources_day, 11, 0)
        
        # Create extended list of post owners
        extended_owners = self.post_owners + [f'user_{i}' for i in range(10)]
        
        for i in range(20):
            download_time = sources_start + timedelta(minutes=i * 4)
            post_owner = extended_owners[i % 15]  # 15 different owners
            
            anomalies.append({
                'timestamp': download_time,
                'post_id': random.randint(1000, 9999),
                'post_owner_id': hash(post_owner) % 10000,
                'post_owner_username': post_owner,
                'downloader_id': hash(username) % 10000,
                'downloader_username': username,
                'filename': f"image_{random.randint(1000, 9999)}.jpg",
                'file_size_bytes': random.randint(500000, 2500000),
                'is_own_post': False,
                'source_ip': '192.168.1.100',
                'user_agent': random.choice(self.user_agents),
                'anomaly_type': 'multiple_unique_sources'
            })
        
        return anomalies
    
    def send_to_splunk(self, event, dry_run=False):
        """Send event to Splunk HEC"""
        if dry_run:
            own_indicator = "OWN" if event['is_own_post'] else "OTHER"
            print(f"[DRY RUN] {event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} - "
                  f"{event['downloader_username']} downloaded {own_indicator} post "
                  f"from {event['post_owner_username']} ({event['file_size_bytes']} bytes) "
                  f"[{event['anomaly_type']}]")
            return True
        
        event_data = {
            "time": int(event['timestamp'].timestamp()),
            "event": {
                "event_type": "post_download",
                "severity": "INFO",
                "timestamp": event['timestamp'].isoformat(),
                "source_ip": event['source_ip'],
                "user_agent": event['user_agent'],
                "user_id": event['downloader_id'],
                "username": event['downloader_username'],
                "data": {
                    "post_id": event['post_id'],
                    "post_owner_id": event['post_owner_id'],
                    "post_owner_username": event['post_owner_username'],
                    "downloader_id": event['downloader_id'],
                    "downloader_username": event['downloader_username'],
                    "filename": event['filename'],
                    "file_size_bytes": event['file_size_bytes'],
                    "download_time": event['timestamp'].isoformat(),
                    "is_own_post": event['is_own_post'],
                    "anomaly_type": event.get('anomaly_type', 'normal')
                }
            },
            "sourcetype": "app_security_event",
            "index": self.index
        }
        
        try:
            headers = {
                'Authorization': f'Splunk {self.hec_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                self.hec_url,
                headers=headers,
                data=json.dumps(event_data),
                verify=False,
                timeout=5
            )
            
            return response.status_code == 200
        
        except Exception as e:
            print(f"Error sending to Splunk: {e}")
            return False
    
    def generate_all_data(self, dry_run=False, include_anomalies=True):
        """Generate complete dataset"""
        print("=" * 80)
        print("MLTK Download Security Data Generator")
        print("=" * 80)
        
        if dry_run:
            print("\n*** DRY RUN MODE - No data will be sent to Splunk ***\n")
        
        total_events = 0
        total_normal = 0
        total_anomalies = 0
        
        # Generate normal downloads for each user profile
        print("\n[1] Generating Normal Download Patterns")
        print("-" * 80)
        
        for username, profile in self.user_profiles.items():
            print(f"\nUser: {username} ({profile['description']})")
            print(f"  Expected downloads: {profile['total_downloads']}")
            print(f"  Own post ratio: {profile['own_post_ratio'] * 100:.0f}%")
            
            events = self.generate_normal_downloads(username, profile)
            
            print(f"  Generated: {len(events)} events")
            
            for event in events:
                if self.send_to_splunk(event, dry_run):
                    total_normal += 1
                    total_events += 1
                
                if not dry_run:
                    time.sleep(0.01)  # Rate limiting
        
        # Generate anomalous patterns
        if include_anomalies:
            print("\n\n[2] Generating Anomalous Download Patterns")
            print("-" * 80)
            
            # Select users to flag with anomalies
            flagged_users = ['active_user', 'researcher']
            
            for username in flagged_users:
                print(f"\nGenerating anomalies for: {username}")
                anomalies = self.generate_anomalous_events(username)
                
                print(f"  Total anomalies: {len(anomalies)}")
                
                for event in anomalies:
                    if self.send_to_splunk(event, dry_run):
                        total_anomalies += 1
                        total_events += 1
                    
                    if not dry_run:
                        time.sleep(0.01)
        
        # Summary
        print("\n" + "=" * 80)
        print("GENERATION COMPLETE")
        print("=" * 80)
        print(f"Total events generated: {total_events}")
        print(f"  Normal downloads: {total_normal}")
        print(f"  Anomalous downloads: {total_anomalies}")
        
        if not dry_run:
            print(f"\nData sent to: {self.hec_url}")
            print(f"Index: {self.index}")
            print("\nWait 2-3 minutes for Splunk to index the data.")
        
        print("\n" + "=" * 80)
        print("VERIFICATION QUERIES")
        print("=" * 80)
        print("\n1. View all download events:")
        print("   index=main event_type=\"post_download\" | stats count by data.downloader_username")
        
        print("\n2. Check anomaly distribution:")
        print("   index=main event_type=\"post_download\"")
        print("   | stats count by data.anomaly_type")
        
        print("\n3. Detect mass downloads:")
        print("   index=main event_type=\"post_download\"")
        print("   | bucket _time span=10m")
        print("   | stats count as downloads by _time, data.downloader_username")
        print("   | where downloads > 15")
        
        print("\n4. Find automated scraping patterns:")
        print("   index=main event_type=\"post_download\"")
        print("   | streamstats current=f last(_time) as prev_time by data.downloader_username")
        print("   | eval time_diff=_time-prev_time") 
        print("   | where time_diff <= 5")
        print("   | stats count by data.downloader_username")
        
        print("\n5. Geographic anomalies:")
        print("   index=main event_type=\"post_download\"")
        print("   | iplocation data.source_ip")
        print("   | stats dc(Country) as countries by data.downloader_username")
        print("   | where countries > 1")
        
        print("\n" + "=" * 80)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate download security training data for Splunk MLTK')
    parser.add_argument('--dry-run', action='store_true', help='Preview data without sending to Splunk')
    parser.add_argument('--no-anomalies', action='store_true', help='Generate only normal baseline data')
    
    args = parser.parse_args()
    
    generator = MLTKDownloadSecurityDataGenerator()
    generator.generate_all_data(
        dry_run=args.dry_run,
        include_anomalies=not args.no_anomalies
    )


if __name__ == '__main__':
    main()
