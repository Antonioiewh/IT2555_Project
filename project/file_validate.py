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

# =============================================================================
# NEW: SPECIALIZED VALIDATION FUNCTIONS FOR DIFFERENT UPLOAD TYPES
# =============================================================================

def validate_profile_image(file_obj, user_id: int, upload_folder: str) -> Dict:
    """
    Complete validation and processing for profile pictures
    Returns: {'success': bool, 'filename': str, 'error': str, 'filepath': str}
    """
    result = {'success': False, 'filename': None, 'error': None, 'filepath': None}
    
    try:
        # Read file data
        file_obj.seek(0)
        file_data = file_obj.read()
        file_obj.seek(0)
        
        # Security validation
        validation = validate_file_security(
            file_data=file_data,
            filename=file_obj.filename,
            max_size=2*1024*1024  # 2MB for profile pics
        )
        
        if not validation['is_safe']:
            threats = '; '.join(validation['threats'])
            result['error'] = f'Security validation failed: {threats}'
            return result
        
        # Check for high-risk files
        if validation['risk_level'] in ['high', 'critical']:
            warnings = '; '.join(validation['warnings'])
            result['error'] = f'High-risk file detected: {warnings}'
            return result
        
        # Validate image format
        if not _validate_image_format(file_data):
            result['error'] = 'Invalid image format. Only JPEG, PNG, GIF, and WEBP are supported.'
            return result
        
        # Generate filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"profile_{user_id}_{timestamp}.jpg"
        
        # Process and save image
        processed_path = _process_and_save_image(
            file_data, 
            os.path.join(upload_folder, filename),
            target_size=(300, 300),
            quality=90
        )
        
        if processed_path:
            result.update({
                'success': True,
                'filename': filename,
                'filepath': processed_path
            })
        else:
            result['error'] = 'Failed to process image'
            
    except Exception as e:
        result['error'] = f'Processing error: {str(e)}'
    
    return result

def validate_banner_image(file_obj, user_id: int, upload_folder: str) -> Dict:
    """
    Complete validation and processing for banner images
    Returns: {'success': bool, 'filename': str, 'error': str, 'filepath': str}
    """
    result = {'success': False, 'filename': None, 'error': None, 'filepath': None}
    
    try:
        # Read file data
        file_obj.seek(0)
        file_data = file_obj.read()
        file_obj.seek(0)
        
        # Security validation
        validation = validate_file_security(
            file_data=file_data,
            filename=file_obj.filename,
            max_size=5*1024*1024  # 5MB for banners
        )
        
        if not validation['is_safe']:
            threats = '; '.join(validation['threats'])
            result['error'] = f'Security validation failed: {threats}'
            return result
        
        if validation['risk_level'] in ['high', 'critical']:
            warnings = '; '.join(validation['warnings'])
            result['error'] = f'High-risk file detected: {warnings}'
            return result
        
        # Validate file extension
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
        if '.' not in file_obj.filename or file_obj.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
            result['error'] = 'Invalid file type. Only PNG, JPG, JPEG, GIF, and WEBP are allowed.'
            return result
        
        # Validate image format
        if not _validate_image_format(file_data):
            result['error'] = 'Invalid image format.'
            return result
        
        # Generate filename
        import uuid
        file_extension = file_obj.filename.rsplit('.', 1)[1].lower()
        filename = f"banner_{user_id}_{uuid.uuid4().hex}.{file_extension}"
        
        # Process and save image
        processed_path = _process_and_save_image(
            file_data,
            os.path.join(upload_folder, filename),
            target_size=(1920, 1080),
            quality=85
        )
        
        if processed_path:
            result.update({
                'success': True,
                'filename': filename,
                'filepath': processed_path
            })
        else:
            result['error'] = 'Failed to process image'
            
    except Exception as e:
        result['error'] = f'Processing error: {str(e)}'
    
    return result

def validate_post_images(file_list, post_id: int, upload_folder: str) -> Dict:
    """
    Validate and process multiple post images
    Returns: {'success': bool, 'processed_files': list, 'errors': list, 'warnings': list}
    """
    result = {
        'success': True,
        'processed_files': [],
        'errors': [],
        'warnings': []
    }
    
    for i, file_obj in enumerate(file_list):
        if not file_obj or not file_obj.filename:
            continue
        
        try:
            # Read file data
            file_obj.seek(0)
            file_data = file_obj.read()
            file_obj.seek(0)
            
            # Security validation
            validation = validate_file_security(
                file_data=file_data,
                filename=file_obj.filename,
                max_size=10*1024*1024  # 10MB for post images
            )
            
            if not validation['is_safe']:
                threats = '; '.join(validation['threats'])
                result['errors'].append(f'File {file_obj.filename}: {threats}')
                continue
            
            if validation['risk_level'] in ['high', 'critical']:
                warnings = '; '.join(validation['warnings'])
                result['warnings'].append(f'File {file_obj.filename}: {warnings}')
                continue
            
            # Validate file extension
            allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
            if '.' not in file_obj.filename or file_obj.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
                result['errors'].append(f'Invalid file type: {file_obj.filename}')
                continue
            
            # Validate image format
            if not _validate_image_format(file_data):
                result['errors'].append(f'Invalid image format: {file_obj.filename}')
                continue
            
            # Generate filename
            import random
            import string
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
            filename = f"{post_id}_{timestamp}_{random_suffix}_{secure_filename(file_obj.filename)}"
            
            # Process and save image
            processed_path = _process_and_save_image(
                file_data,
                os.path.join(upload_folder, filename),
                target_size=(1200, 1200),
                quality=85
            )
            
            if processed_path:
                result['processed_files'].append({
                    'filename': filename,
                    'original_name': file_obj.filename,
                    'filepath': processed_path,
                    'url': f"uploads/{filename}"
                })
            else:
                result['errors'].append(f'Failed to process: {file_obj.filename}')
                
        except Exception as e:
            result['errors'].append(f'Error processing {file_obj.filename}: {str(e)}')
    
    # Set overall success status
    result['success'] = len(result['processed_files']) > 0 or len(result['errors']) == 0
    
    return result

def validate_cropped_image_data(image_data_b64: str, user_id: int, upload_folder: str) -> Dict:
    """
    Validate and process base64 cropped image data
    Returns: {'success': bool, 'filename': str, 'error': str, 'filepath': str}
    """
    result = {'success': False, 'filename': None, 'error': None, 'filepath': None}
    
    try:
        # Decode base64 data
        import base64
        if ',' in image_data_b64:
            image_data_b64 = image_data_b64.split(',')[1]
        
        image_binary = base64.b64decode(image_data_b64)
        
        # Security validation
        validation = validate_file_security(
            file_data=image_binary,
            filename="cropped_image.jpg",
            max_size=2*1024*1024  # 2MB limit
        )
        
        if not validation['is_safe']:
            threats = '; '.join(validation['threats'])
            result['error'] = f'Security validation failed: {threats}'
            return result
        
        if validation['risk_level'] in ['high', 'critical']:
            warnings = '; '.join(validation['warnings'])
            result['error'] = f'High-risk content detected: {warnings}'
            return result
        
        # Validate image format
        if not _validate_image_format(image_binary):
            result['error'] = 'Invalid image data'
            return result
        
        # Generate filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"profile_{user_id}_{timestamp}.jpg"
        
        # Process and save
        processed_path = _process_and_save_image(
            image_binary,
            os.path.join(upload_folder, filename),
            target_size=(300, 300),
            quality=90
        )
        
        if processed_path:
            result.update({
                'success': True,
                'filename': filename,
                'filepath': processed_path
            })
        else:
            result['error'] = 'Failed to process image'
            
    except Exception as e:
        result['error'] = f'Processing error: {str(e)}'
    
    return result

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _validate_image_format(file_data: bytes) -> bool:
    """Validate that file data is a legitimate image"""
    try:
        with Image.open(io.BytesIO(file_data)) as img:
            # Verify it's a standard image format
            if img.format not in ['JPEG', 'PNG', 'GIF', 'WEBP']:
                return False
            # Try to load the image to verify it's not corrupted
            img.load()
            return True
    except Exception:
        return False

def _process_and_save_image(file_data: bytes, output_path: str, target_size: tuple = None, quality: int = 85) -> str:
    """Process and save image with optimization"""
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with Image.open(io.BytesIO(file_data)) as img:
            # Convert to RGB if necessary
            if img.mode in ('RGBA', 'P'):
                img = img.convert('RGB')
            
            # Resize if target size specified
            if target_size:
                if target_size == (300, 300):  # Profile picture - crop to square
                    img = img.resize(target_size, Image.Resampling.LANCZOS)
                else:  # Banner or post image - maintain aspect ratio
                    img.thumbnail(target_size, Image.Resampling.LANCZOS)
            
            # Save optimized image
            img.save(output_path, 'JPEG', quality=quality, optimize=True)
            
        return output_path
        
    except Exception as e:
        print(f"Error processing image: {e}")
        return None

def clean_old_file(upload_folder: str, old_filename: str) -> bool:
    """Safely remove old file"""
    if not old_filename:
        return True
    
    try:
        old_path = os.path.join(upload_folder, old_filename)
        if os.path.exists(old_path):
            os.remove(old_path)
        return True
    except Exception:
        return False

# Convenience functions remain the same
def quick_polyglot_check(file_data: bytes, filename: str) -> Tuple[bool, str]:
    """
    Quick check if file is a polyglot
    Returns: (is_polyglot, reason)
    """
    expected_type = _get_file_type_from_extension(filename)
    detected_signatures = _scan_all_signatures(file_data)
    polyglot_result = _detect_polyglot(expected_type, detected_signatures, filename)
    
    if polyglot_result['is_polyglot']:
        return True, "; ".join(polyglot_result['threats'])
    return False, "File appears to be a valid single-format file"

def scan_upload(file_data: bytes, filename: str, max_size: int = 10*1024*1024) -> Tuple[bool, List[str]]:
    """Scan uploaded file - returns (is_safe, issues_list)"""
    result = validate_file_security(file_data=file_data, filename=filename, max_size=max_size)
    issues = result['threats'] + result['warnings']
    return result['is_safe'], issues

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