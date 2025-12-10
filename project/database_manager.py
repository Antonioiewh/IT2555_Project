import requests
from functools import wraps
from flask import current_app
from sqlalchemy import text
from datetime import datetime
import logging

class DatabaseHA:
    """High Availability Database Manager"""
    
    def __init__(self, orchestrator_url="http://orchestrator:3000"):
        self.orchestrator_url = orchestrator_url
        self.logger = logging.getLogger(__name__)
        
    def get_master_host(self, cluster_alias="main"):
        """Get current master from orchestrator"""
        try:
            response = requests.get(f"{self.orchestrator_url}/api/cluster-info/{cluster_alias}")
            if response.status_code == 200:
                data = response.json()
                for instance in data:
                    if instance.get('IsMaster', False):
                        hostname = instance.get('Key', {}).get('Hostname', 'mysql')
                        self.logger.info(f"Current master: {hostname}")
                        return hostname
            self.logger.warning("No master found, using fallback")
            return 'mysql'  # fallback
        except Exception as e:
            self.logger.error(f"Error getting master host: {e}")
            return 'mysql'  # fallback
    
    def get_replica_hosts(self, cluster_alias="main"):
        """Get available replicas from orchestrator"""
        try:
            response = requests.get(f"{self.orchestrator_url}/api/cluster-info/{cluster_alias}")
            if response.status_code == 200:
                data = response.json()
                replicas = []
                for instance in data:
                    if not instance.get('IsMaster', False) and instance.get('IsLastCheckValid', False):
                        hostname = instance.get('Key', {}).get('Hostname')
                        if hostname:
                            replicas.append(hostname)
                self.logger.info(f"Available replicas: {replicas}")
                return replicas
            return []
        except Exception as e:
            self.logger.error(f"Error getting replica hosts: {e}")
            return []
    
    def trigger_topology_check(self, hostname=None):
        """Trigger orchestrator to check topology"""
        try:
            if not hostname:
                hostname = self.get_master_host()
            
            response = requests.post(f"{self.orchestrator_url}/api/discover/mysql/{hostname}/3306")
            if response.status_code == 200:
                self.logger.info(f"Triggered topology check for {hostname}")
                return True
            else:
                self.logger.warning(f"Topology check failed: {response.status_code}")
                return False
        except Exception as e:
            self.logger.error(f"Error triggering topology check: {e}")
            return False
    
    def update_database_uri(self, app, new_master_host):
        """Update the database URI to point to new master"""
        try:
            old_uri = app.config['SQLALCHEMY_DATABASE_URI']
            # Replace the hostname in the URI
            # Example: mysql+pymysql://user:pass@mysql/db -> mysql+pymysql://user:pass@new_master/db
            new_uri = old_uri.replace('@mysql/', f'@{new_master_host}/')
            app.config['SQLALCHEMY_DATABASE_URI'] = new_uri
            self.logger.info(f"Updated database URI from {old_uri} to {new_uri}")
            return True
        except Exception as e:
            self.logger.error(f"Error updating database URI: {e}")
            return False

    def test_connection(self, db_session):
        """Test database connection"""
        try:
            result = db_session.execute(text('SELECT 1')).scalar()
            return result == 1
        except Exception as e:
            self.logger.error(f"Database connection test failed: {e}")
            return False

def with_db_failover(db_ha_instance):
    """Decorator factory for database failover"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_msg = str(e).lower()
                if any(keyword in error_msg for keyword in ["lost connection", "can't connect", "server has gone away"]):
                    current_app.logger.warning(f"Database connection lost: {e}")
                    
                    # Trigger orchestrator to check topology
                    db_ha_instance.trigger_topology_check()
                    
                    # Get new master and update configuration
                    new_master = db_ha_instance.get_master_host()
                    if new_master != 'mysql':
                        db_ha_instance.update_database_uri(current_app, new_master)
                        
                        # Attempt to recreate database session
                        try:
                            from models import db
                            db.session.remove()
                            db.create_all()
                            current_app.logger.info("Database session recreated")
                        except Exception as recreate_error:
                            current_app.logger.error(f"Error recreating database session: {recreate_error}")
                    
                    # Retry the operation once
                    try:
                        return func(*args, **kwargs)
                    except Exception as retry_error:
                        current_app.logger.error(f"Retry failed: {retry_error}")
                        raise retry_error
                else:
                    # Re-raise non-connection errors
                    raise e
        return wrapper
    return decorator

def create_health_endpoints(app, db_ha_instance):
    """Create health check endpoints"""
    from flask import jsonify
    from models import db
    
    @app.route('/api/health')
    @with_db_failover(db_ha_instance)
    def health_check():
        """Health check endpoint with HA support"""
        try:
            # Test database connection
            if not db_ha_instance.test_connection(db.session):
                raise Exception("Database connection test failed")
                
            master_host = db_ha_instance.get_master_host()
            replicas = db_ha_instance.get_replica_hosts()
            
            return jsonify({
                'status': 'healthy',
                'database': {
                    'master': master_host,
                    'replicas': replicas,
                    'connection': 'ok'
                },
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            return jsonify({
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }), 500

    @app.route('/api/db-health')
    def db_health():
        """Database health check endpoint"""
        try:
            from models import db
            result = db.session.execute(text('SELECT 1')).scalar()
            if result == 1:
                return jsonify({
                    'status': 'healthy',
                    'database': 'mysql',
                    'connection': 'ok',
                    'timestamp': datetime.now().isoformat()
                })
            else:
                raise Exception('Unexpected result from health check query')
        except Exception as e:
            return jsonify({
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }), 500

    @app.route('/api/system-health')
    def system_health():
        """Complete system health check"""
        health_status = {
            'database': 'unknown',
            'redis': 'unknown',
            'overall': 'unknown'
        }
        
        try:
            # Check database
            from models import db
            db.session.execute(text('SELECT 1')).scalar()
            health_status['database'] = 'healthy'
        except:
            health_status['database'] = 'unhealthy'
        
        try:
            # Check Redis if you're using it
            import redis
            r = redis.Redis(host='redis', port=6379, db=0)
            r.ping()
            health_status['redis'] = 'healthy'
        except:
            health_status['redis'] = 'unhealthy'
        
        # Determine overall health
        if health_status['database'] == 'healthy' and health_status['redis'] == 'healthy':
            health_status['overall'] = 'healthy'
            status_code = 200
        else:
            health_status['overall'] = 'degraded'
            status_code = 503
        
        health_status['timestamp'] = datetime.now().isoformat()
        return jsonify(health_status), status_code