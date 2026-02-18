import clamd
from flask import Blueprint, request, jsonify, current_app
from io import BytesIO

scanner_bp = Blueprint('scanner', __name__)

class VirusScanner:
    def __init__(self, host='clamav', port=3310):
        self.host = host
        self.port = port
        self.cd = None

    def _connect(self):
        """Lazy connection to ClamAV container"""
        try:
            # We use clamd (network socket) to talk to the Docker container
            self.cd = clamd.ClamdNetworkSocket(host=self.host, port=self.port)
            return True
        except Exception as e:
            print(f"⚠️ Virus Scanner Error: Could not connect to ClamAV at {self.host}:{self.port}. {e}")
            return False

    def scan_stream(self, file_obj):
        """
        Scans a file object (like from request.files).
        Returns: (is_safe: bool, message: str)
        """
        if not self.cd:
            if not self._connect():
                # Fail Safe: If scanner is down, do we block upload? 
                # Security best practice says YES, block it.
                return False, "Scanner unavailable"

        try:
            # clamd.instream streams the data chunks directly to the engine
            # This is memory efficient (doesn't load huge files into RAM)
            result = self.cd.instream(file_obj)
            
            # Result format: {'stream': ('FOUND', 'Win.Test.EICAR')} OR {'stream': ('OK', None)}
            if result and 'stream' in result:
                status, virus_name = result['stream']
                if status == 'FOUND':
                    return False, f"Malware Detected: {virus_name}"
                return True, "Clean"
            
            return True, "Clean"
        except Exception as e:
            # Re-connect next time
            self.cd = None 
            return False, f"Scan Error: {str(e)}"
        
av_scanner = VirusScanner(host='clamav', port=3310)

# ==========================================
# PUBLIC API ROUTES (For External Use)
# ==========================================

@scanner_bp.route('/api/v1/scan', methods=['POST'])
def public_scan_endpoint():
    """
    External API: POST a file to receive a JSON safety report.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # 1. Scan the file
    is_safe, message = av_scanner.scan_stream(file)
    
    # 2. Reset file pointer (good practice)
    file.seek(0)

    response = {
        'filename': file.filename,
        'safe': is_safe,
        'status': message
    }

    # Return 200 if safe, 406 (Not Acceptable) if malware
    status_code = 200 if is_safe else 406
    return jsonify(response), status_code