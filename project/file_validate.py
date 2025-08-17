import os
import re
import hashlib
import io
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from PIL import Image
from werkzeug.utils import secure_filename

def validate_file_security(file_path: str = None, file_data: bytes = None, filename: str = None, 
                          max_size: int = 10*1024*1024) -> Dict:
    """
    Simplified file security validation focusing on polyglot detection
    
    Process:
    1. Identify expected file type from extension
    2. Scan entire file for signatures of OTHER file types
    3. Flag if multiple different signatures found
    
    Returns:
        Dict with validation results
    """
    result = {
        'is_safe': True,
        'risk_level': 'low',
        'threats': [],
        'warnings': [],
        'file_info': {}
    }
    
    try:
        # Get file data if not provided
        if file_data is None and file_path:
            with open(file_path, 'rb') as f:
                file_data = f.read()
        elif file_data is None:
            result['threats'].append("No file data provided")
            result['is_safe'] = False
            return result
        
        # Get filename
        if filename is None and file_path:
            filename = os.path.basename(file_path)
        elif filename is None:
            filename = "unknown_file"
        
        # Basic file info
        file_size = len(file_data)
        result['file_info'] = {
            'filename': filename,
            'size': file_size,
            'md5_hash': hashlib.md5(file_data).hexdigest()
        }
        
        # 1. Basic checks
        if file_size > max_size:
            result['threats'].append(f"File too large: {file_size} bytes")
            result['is_safe'] = False
            result['risk_level'] = 'medium'
            return result
        
        if file_size == 0:
            result['threats'].append("Empty file")
            result['is_safe'] = False
            return result
        
        # 2. Get expected file type from extension
        expected_type = _get_file_type_from_extension(filename)
        if not expected_type:
            result['warnings'].append("Unknown or missing file extension")
        
        # 3. Scan for ALL file signatures in the entire file
        detected_signatures = _scan_all_signatures(file_data)
        
        # 4. Polyglot detection logic
        polyglot_result = _detect_polyglot(expected_type, detected_signatures, filename)
        
        if polyglot_result['is_polyglot']:
            result['threats'].extend(polyglot_result['threats'])
            result['is_safe'] = False
            result['risk_level'] = polyglot_result['risk_level']
        
        # 5. Only check for CRITICAL malicious patterns (reduce false positives)
        critical_threats = _check_critical_patterns(file_data)
        if critical_threats:
            result['threats'].extend(critical_threats)
            result['is_safe'] = False
            result['risk_level'] = 'critical'
        
        # Add detection info
        result['detection_info'] = {
            'expected_type': expected_type,
            'detected_signatures': detected_signatures,
            'is_polyglot': polyglot_result['is_polyglot']
        }
        
    except Exception as e:
        result['threats'].append(f"Validation error: {str(e)}")
        result['is_safe'] = False
        result['risk_level'] = 'high'
    
    return result

def _get_file_type_from_extension(filename: str) -> str:
    """Get expected file type from extension"""
    if '.' not in filename:
        return None
    
    ext = filename.rsplit('.', 1)[1].lower()
    
    # Map extensions to file types (FIXED: jpg and jpeg both map to 'image')
    extension_map = {
        'jpg': 'image', 'jpeg': 'image',  # Both treated as same type
        'png': 'image',  # Also treat as generic image
        'gif': 'image',  # Also treat as generic image
        'webp': 'image', 'bmp': 'image', 'tiff': 'image', 'tif': 'image',
        'pdf': 'pdf',
        'txt': 'text',
        'doc': 'document', 'docx': 'document',
        'xls': 'document', 'xlsx': 'document',
        'ppt': 'document', 'pptx': 'document',
        'zip': 'archive',
        'rar': 'archive',
        '7z': 'archive',
        'tar': 'archive', 'gz': 'archive',
        'exe': 'executable',
        'html': 'web', 'htm': 'web',
        'js': 'script',
        'php': 'script',
        'asp': 'script', 'aspx': 'script',
        'mp4': 'video', 'avi': 'video', 'mov': 'video',
        'mp3': 'audio', 'wav': 'audio', 'flac': 'audio'
    }
    
    return extension_map.get(ext)

def _scan_all_signatures(file_data: bytes) -> List[str]:
    """Scan entire file for known file format signatures - IMPROVED"""
    detected = []
    
    # IMPROVED: More precise signatures and better logic
    signatures = {
        'image': [
            # JPEG signatures - more specific to reduce false positives
            b'\xFF\xD8\xFF\xE0',  # JPEG with JFIF
            b'\xFF\xD8\xFF\xE1',  # JPEG with EXIF
            b'\xFF\xD8\xFF\xE2',  # JPEG with ICC profile
            # PNG signature - exact match
            b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A',
            # GIF signatures
            b'GIF87a', b'GIF89a',
            # WEBP
            b'RIFF', # Note: This might be too broad, but let's see
        ],
        'pdf': [b'%PDF-'],
        'archive': [
            b'PK\x03\x04',  # ZIP
            b'PK\x05\x06',  # ZIP (empty archive)
            b'Rar!\x1A\x07',  # RAR (more specific)
            b'7z\xBC\xAF\x27\x1C',  # 7Z
        ],
        'executable': [
            b'MZ',  # PE executable (but only at start of file)
            b'\x7FELF',  # ELF executable (but only at start of file)
        ],
        'web': [
            b'<!DOCTYPE html',
            b'<html',
            b'<HTML',
        ],
        'script': [
            b'<?php',
            b'<%@',
            b'<script',
        ],
    }
    
    # Check each signature with POSITION AWARENESS
    for file_type, sigs in signatures.items():
        for sig in sigs:
            # CRITICAL FIX: Check position for executable signatures
            if file_type == 'executable':
                # Only flag as executable if signature is at the very beginning
                if file_data.startswith(sig):
                    if file_type not in detected:
                        detected.append(file_type)
                    break
            else:
                # For other types, search the entire file but avoid false positives
                if sig in file_data:
                    # Additional check for RIFF (WEBP) - make sure it's actually WEBP
                    if sig == b'RIFF':
                        if b'WEBP' in file_data[:20]:  # WEBP identifier should be near start
                            if file_type not in detected:
                                detected.append(file_type)
                    else:
                        if file_type not in detected:
                            detected.append(file_type)
                    break
    
    return detected

def _detect_polyglot(expected_type: str, detected_signatures: List[str], filename: str) -> Dict:
    """Detect if file is a polyglot based on expected vs detected signatures - FIXED"""
    result = {
        'is_polyglot': False,
        'threats': [],
        'risk_level': 'low'
    }
    
    if not detected_signatures:
        # No signatures detected - could be text file or corrupted
        if expected_type in ['text', 'script', 'web']:
            # These file types might not have binary signatures
            return result
        else:
            result['warnings'] = ["No recognizable file signatures detected"]  # Changed to warning
            return result
    
    # If only one signature detected
    if len(detected_signatures) == 1:
        detected_type = detected_signatures[0]
        
        # Check if detected matches expected
        if expected_type and detected_type != expected_type:
            # EXPANDED acceptable mismatches
            acceptable_mismatches = {
                'document': ['archive'],  # DOCX/XLSX files are ZIP archives
                'image': ['image'],       # Any image type is fine for image extensions
            }
            
            if expected_type in acceptable_mismatches:
                if detected_type in acceptable_mismatches[expected_type]:
                    return result  # Acceptable mismatch
            
            # Only flag as threat if it's a significant mismatch
            if detected_type == 'executable':
                result['threats'].append(f"CRITICAL: File with '{expected_type}' extension contains executable code")
                result['is_polyglot'] = True
                result['risk_level'] = 'critical'
            elif detected_type == 'script':
                result['threats'].append(f"CRITICAL: File with '{expected_type}' extension contains script code")
                result['is_polyglot'] = True
                result['risk_level'] = 'critical'
            else:
                result['warnings'] = [f"File type mismatch: extension suggests '{expected_type}' but content appears to be '{detected_type}'"]
                result['risk_level'] = 'medium'
        
        return result
    
    # Multiple signatures detected - this is a polyglot!
    if len(detected_signatures) > 1:
        result['is_polyglot'] = True
        result['threats'].append(f"Polyglot file detected with multiple signatures: {', '.join(detected_signatures)}")
        
        # Determine risk level based on what's detected
        critical_types = ['executable', 'script']
        
        if any(d_type in critical_types for d_type in detected_signatures):
            result['risk_level'] = 'critical'
            result['threats'].append("CRITICAL: Executable or script code detected alongside other file types")
        else:
            result['risk_level'] = 'high'
    
    return result

def _check_critical_patterns(file_data: bytes) -> List[str]:
    """Check for only the most critical malicious patterns - VERY RESTRICTIVE"""
    threats = []
    
    # VERY restrictive patterns - only the most obvious threats
    critical_patterns = [
        (b'<?php echo', "PHP code execution detected"),
        (b'<?php system', "PHP system command detected"),
        (b'<%@page', "JSP server page detected"),
        (b'eval(atob(', "JavaScript eval with base64 detected"),
        (b'document.write(', "JavaScript document.write detected"),
        (b'<script>eval(', "JavaScript eval in script tag detected"),
        (b'cmd.exe /c', "Windows command execution detected"),
        (b'/bin/sh -c', "Shell command execution detected"),
        (b'powershell.exe', "PowerShell execution detected"),
    ]
    
    # Only check the first 1KB and last 1KB to reduce false positives in large files
    check_data = file_data[:1024] + file_data[-1024:] if len(file_data) > 2048 else file_data
    data_lower = check_data.lower()
    
    for pattern, message in critical_patterns:
        if pattern in data_lower:
            threats.append(message)
    
    return threats


# Example usage and testing
if __name__ == "__main__":    
    # Test function
    def test_file(filename, description=""):
        print(f"\n--- Testing: {filename} {description} ---")
        try:
            with open(filename, 'rb') as f:
                data = f.read()
            
            result = validate_file_security(file_data=data, filename=filename)
            print(f"Safe: {result['is_safe']}")
            print(f"Risk Level: {result['risk_level']}")
            
            if 'detection_info' in result:
                info = result['detection_info']
                print(f"Expected Type: {info['expected_type']}")
                print(f"Detected Signatures: {info['detected_signatures']}")
                print(f"Is Polyglot: {info['is_polyglot']}")
            
            if result['threats']:
                print("Threats:")
                for threat in result['threats']:
                    print(f"  - {threat}")
            
            if result['warnings']:
                print("Warnings:")
                for warning in result['warnings']:
                    print(f"  - {warning}")
        
        except FileNotFoundError:
            print(f"File not found: {filename}")