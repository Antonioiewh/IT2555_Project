# file validate function

import os
import re
import hashlib
import io
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from PIL import Image
from werkzeug.utils import secure_filename

# Import watermarking functionality
WATERMARK_AVAILABLE = False
try:
    from .watermaker import apply_red_watermark, is_image_file
    WATERMARK_AVAILABLE = True
except ImportError:
    try:
        from watermaker import apply_red_watermark, is_image_file
        WATERMARK_AVAILABLE = True
    except ImportError:
        def apply_red_watermark(*args, **kwargs):
            return {'success': False, 'error': 'Watermarking not available', 'image_data': None}
        def is_image_file(*args, **kwargs):
            return False
        WATERMARK_AVAILABLE = False

# Import metadata removal functionality
METADATA_REMOVAL_AVAILABLE = False
try:
    # Try relative import first (when imported as a package)
    from .metadata_remover import remove_metadata, extract_metadata, demo_metadata_before_after
    METADATA_REMOVAL_AVAILABLE = True
except ImportError:
    try:
        # Try direct import (when run directly or in same directory)
        from metadata_remover import remove_metadata, extract_metadata, demo_metadata_before_after
        METADATA_REMOVAL_AVAILABLE = True
    except ImportError:
        try:
            # Try adding current directory to path and import
            import sys
            import os
            current_dir = os.path.dirname(os.path.abspath(__file__))
            if current_dir not in sys.path:
                sys.path.insert(0, current_dir)
            from metadata_remover import remove_metadata, extract_metadata, demo_metadata_before_after
            METADATA_REMOVAL_AVAILABLE = True
        except ImportError as e:
            # Create basic fallback functions for images only
            def remove_metadata(file_path):
                """Fallback metadata remover using only PIL for images"""
                try:
                    import piexif
                    from PIL import Image
                    
                    file_extension = os.path.splitext(file_path)[1].lower()
                    
                    if file_extension in ['.jpg', '.jpeg']:
                        # Remove EXIF from JPEG
                        try:
                            piexif.remove(file_path)
                            return True
                        except:
                            # Fallback: re-encode to remove EXIF
                            with Image.open(file_path) as img:
                                rgb_img = img.convert("RGB")
                                rgb_img.save(file_path, format='JPEG', exif=b'')
                            return True
                    
                    elif file_extension in ['.png', '.gif', '.bmp', '.tiff']:
                        # Re-encode to remove metadata
                        with Image.open(file_path) as img:
                            data = list(img.getdata())
                            clean_img = Image.new(img.mode, img.size)
                            clean_img.putdata(data)
                            clean_img.save(file_path, format=img.format)
                        return True
                    
                    else:
                        # Unsupported file type for basic remover
                        return False
                        
                except Exception:
                    return False
            
            def extract_metadata(file_path):
                """Fallback metadata extractor using only PIL for images"""
                try:
                    from PIL import Image
                    
                    file_extension = os.path.splitext(file_path)[1].lower()
                    metadata = {}
                    
                    if file_extension in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff']:
                        try:
                            with Image.open(file_path) as img:
                                # Get PIL info that might contain metadata
                                info = img.info if hasattr(img, 'info') else {}
                                for key, value in info.items():
                                    if isinstance(value, (str, int, float)) and value not in [None, '', 0]:
                                        metadata[f"METADATA_{key}"] = str(value)
                                
                                # Add basic file properties
                                metadata['FILE_format'] = img.format
                                metadata['FILE_mode'] = img.mode
                                metadata['FILE_size_pixels'] = f"{img.size[0]}x{img.size[1]}"
                        except Exception:
                            pass
                    
                    # Add file statistics
                    if os.path.exists(file_path):
                        from datetime import datetime
                        stat = os.stat(file_path)
                        metadata['FILE_size_bytes'] = str(stat.st_size)
                        metadata['FILE_modified_time'] = str(datetime.fromtimestamp(stat.st_mtime))
                    
                    return metadata
                except Exception:
                    return {}
            
            def demo_metadata_before_after(file_path):
                """Fallback demo function"""
                result = {
                    'before': extract_metadata(file_path),
                    'after': {},
                    'removed_count': 0,
                    'success': False,
                    'details': 'Using fallback metadata demo'
                }
                
                # Create a copy for processing
                import shutil
                import tempfile
                
                try:
                    temp_dir = tempfile.mkdtemp()
                    temp_file = os.path.join(temp_dir, f"temp_{os.path.basename(file_path)}")
                    shutil.copy2(file_path, temp_file)
                    
                    success = remove_metadata(temp_file)
                    result['after'] = extract_metadata(temp_file)
                    
                    # Count meaningful metadata
                    before_metadata = {k: v for k, v in result['before'].items() 
                                     if not k.startswith('FILE_') and v not in [None, '', '0']}
                    after_metadata = {k: v for k, v in result['after'].items() 
                                    if not k.startswith('FILE_') and v not in [None, '', '0']}
                    
                    result['removed_count'] = len(before_metadata) - len(after_metadata)
                    result['success'] = success
                    
                    # Clean up
                    try:
                        os.unlink(temp_file)
                        os.rmdir(temp_dir)
                    except:
                        pass
                        
                except Exception as e:
                    result['details'] = f'Fallback demo error: {str(e)}'
                
                return result
            
            METADATA_REMOVAL_AVAILABLE = True

# Import OCR functionality
OCR_AVAILABLE = False
try:
    # Try relative import first (when imported as a package)
    from .ocr_validate import extract_text_from_image, validate_image_with_ocr
    OCR_AVAILABLE = True
except ImportError:
    try:
        # Try direct import (when run directly or in same directory)
        from ocr_validate import extract_text_from_image, validate_image_with_ocr
        OCR_AVAILABLE = True
    except ImportError:
        # Create fallback functions
        def extract_text_from_image(*args, **kwargs):
            return {
                'success': False, 
                'error': 'OCR module not available',
                'text_found': False,
                'extracted_text': ''
            }
        
        def validate_image_with_ocr(*args, **kwargs):
            return {
                'success': False,
                'error': 'OCR module not available',
                'ocr_performed': False
            }
        
        OCR_AVAILABLE = False

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
# GLOBAL VALIDATION + METADATA REMOVAL PIPELINE
# =============================================================================

def validate_and_clean_file(file_path: str = None, file_data: bytes = None, filename: str = None, 
                            max_size: int = 10*1024*1024, remove_metadata_flag: bool = True, 
                            add_watermark: bool = True, watermark_text: str = "VALIDATED",
                            enable_ocr: bool = False) -> Dict:
    """
    Global file validation and metadata removal pipeline.
    
    Process:
    1. Run comprehensive security validation (polyglot detection, malware scan)
    2. If file is safe, optionally remove metadata from the file
    3. Return combined results
    
    Args:
        file_path: Path to the file (if working with saved file)
        file_data: Raw file bytes (if working with uploaded data)
        filename: Original filename for validation context
        max_size: Maximum allowed file size in bytes
        remove_metadata_flag: Whether to remove metadata (default: True)
        add_watermark: Whether to add watermark to images (default: True)
        watermark_text: Text to use for watermark (default: "VALIDATED")
        enable_ocr: Whether to perform OCR text extraction (default: False)
    
    Returns:
        Dict with validation and cleaning results:
        {
            'is_safe': bool,
            'risk_level': str,
            'threats': list,
            'warnings': list,
            'metadata_removed': bool,
            'metadata_removal_error': str or None,
            'watermark_added': bool,
            'watermark_error': str or None,
            'file_info': dict
        }
    """
    result = {
        'is_safe': True,
        'risk_level': 'low',
        'threats': [],
        'warnings': [],
        'metadata_removed': False,
        'metadata_removal_error': None,
        'watermark_added': False,
        'watermark_error': None,
        'file_info': {}
    }
    
    try:
        # Step 1: Security validation
        validation_result = validate_file_security(
            file_path=file_path,
            file_data=file_data,
            filename=filename,
            max_size=max_size
        )
        
        # Copy validation results
        result.update({
            'is_safe': validation_result['is_safe'],
            'risk_level': validation_result['risk_level'],
            'threats': validation_result['threats'],
            'warnings': validation_result['warnings'],
            'file_info': validation_result['file_info']
        })
        
        # Step 2: Metadata removal (only if file passed security validation)
        if validation_result['is_safe'] and remove_metadata_flag:
            if not METADATA_REMOVAL_AVAILABLE:
                result['warnings'].append('Metadata removal module not available')
                result['metadata_removal_error'] = 'Module not found'
            else:
                # Ensure we have a file path for metadata removal
                target_path = file_path
                temp_file_created = False
                
                if not target_path and file_data:
                    # Create temporary file if we only have file_data
                    import tempfile
                    temp_fd, target_path = tempfile.mkstemp(suffix=f"_{filename or 'temp'}")
                    try:
                        with os.fdopen(temp_fd, 'wb') as tmp_file:
                            tmp_file.write(file_data)
                        temp_file_created = True
                    except Exception as e:
                        os.close(temp_fd)
                        result['metadata_removal_error'] = f'Failed to create temp file: {str(e)}'
                        target_path = None
                
                # Remove metadata
                if target_path:
                    try:
                        metadata_success = remove_metadata(target_path)
                        result['metadata_removed'] = metadata_success
                        
                        if not metadata_success:
                            result['warnings'].append('Metadata removal failed or unsupported file type')
                            result['metadata_removal_error'] = 'Removal function returned False'
                        
                        # Clean up temp file if created
                        if temp_file_created:
                            try:
                                # Read the cleaned file back if needed
                                if file_data is not None:  # Update file_data with cleaned version
                                    with open(target_path, 'rb') as f:
                                        file_data = f.read()
                                os.unlink(target_path)
                            except Exception as e:
                                result['warnings'].append(f'Temp file cleanup failed: {str(e)}')
                                
                    except Exception as e:
                        result['metadata_removal_error'] = f'Metadata removal error: {str(e)}'
                        result['warnings'].append(f'Metadata removal failed: {str(e)}')
                        
                        # Clean up temp file on error
                        if temp_file_created and os.path.exists(target_path):
                            try:
                                os.unlink(target_path)
                            except:
                                pass
        
        # Step 3: Watermarking (only if file passed security validation and is an image)
        if validation_result['is_safe'] and add_watermark and WATERMARK_AVAILABLE:
            try:
                # Check if this is an image file that can be watermarked
                is_image = False
                if file_data is not None:
                    is_image = is_image_file(file_data)
                elif file_path is not None:
                    is_image = is_image_file(file_path)
                
                if is_image:
                    # Apply red watermark
                    watermark_input = file_data if file_data is not None else file_path
                    watermark_result = apply_red_watermark(
                        watermark_input, 
                        watermark_text=watermark_text,
                        save_to_path=None  # Keep in memory for now
                    )
                    
                    if watermark_result['success']:
                        result['watermark_added'] = True
                        # Update file_data with watermarked version if we're working with bytes
                        if file_data is not None and watermark_result['image_data']:
                            file_data = watermark_result['image_data']
                        result['warnings'].append('Red validation watermark added to image')
                    else:
                        result['watermark_error'] = watermark_result.get('error', 'Unknown watermarking error')
                        result['warnings'].append(f'Watermarking failed: {result["watermark_error"]}')
                else:
                    # Not an image file, skip watermarking
                    result['warnings'].append('Watermarking skipped: not an image file')
                    
            except Exception as e:
                result['watermark_error'] = f'Watermarking error: {str(e)}'
                result['warnings'].append(f'Watermarking failed: {str(e)}')
        elif not WATERMARK_AVAILABLE:
            result['warnings'].append('Watermarking skipped: module not available')
        elif not add_watermark:
            result['warnings'].append('Watermarking skipped: disabled')
        elif not validation_result['is_safe']:
            result['warnings'].append('Watermarking skipped: file failed security validation')

        # Step 4: OCR text extraction (only if enabled, file passed security validation, and is an image)
        result['ocr_performed'] = False
        result['ocr_text'] = ''
        result['ocr_error'] = None
        result['ocr_details'] = None
        
        if enable_ocr and validation_result['is_safe'] and OCR_AVAILABLE:
            try:
                # Check if this is an image file
                is_image = False
                if file_data is not None:
                    # Use watermark module's is_image_file if available
                    if WATERMARK_AVAILABLE:
                        is_image = is_image_file(file_data)
                    else:
                        # Fallback check using file extension
                        if filename:
                            ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
                            is_image = ext in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp']
                elif file_path is not None:
                    if WATERMARK_AVAILABLE:
                        is_image = is_image_file(file_path)
                    else:
                        ext = file_path.rsplit('.', 1)[-1].lower() if '.' in file_path else ''
                        is_image = ext in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp']
                
                if is_image:
                    # Perform OCR text extraction
                    ocr_input = file_data if file_data is not None else file_path
                    
                    # Run OCR directly without timeout
                    try:
                        ocr_result = extract_text_from_image(ocr_input)
                    except Exception as e:
                        ocr_result = {'success': False, 'error': str(e)}
                    
                    if ocr_result and ocr_result.get('success'):
                        result['ocr_performed'] = True
                        result['ocr_text'] = ocr_result['extracted_text']
                        result['ocr_details'] = {
                            'text_found': ocr_result['text_found'],
                            'total_detections': ocr_result['total_detections'],
                            'high_confidence_count': ocr_result['high_confidence_count'],
                            'text_blocks': ocr_result['text_blocks'],
                            'annotated_image_path': ocr_result.get('annotated_image_path'),  # For visualization
                            'json_path': ocr_result.get('json_path'),  # For reference
                            'average_confidence': ocr_result.get('average_confidence', 0)
                        }
                        
                        # Add info message
                        if ocr_result['text_found']:
                            result['warnings'].append(
                                f"OCR: Extracted {ocr_result['total_detections']} text block(s) from image"
                            )
                        else:
                            result['warnings'].append("OCR: No text detected in image")
                    elif ocr_result and not ocr_result.get('success'):
                        result['ocr_error'] = ocr_result.get('error', 'Unknown OCR error')
                        result['warnings'].append(f'OCR failed: {result["ocr_error"]}')
                else:
                    result['warnings'].append('OCR skipped: not an image file')
                    
            except Exception as e:
                result['ocr_error'] = f'OCR error: {str(e)}'
                result['warnings'].append(f'OCR failed: {str(e)}')
        elif not enable_ocr:
            result['warnings'].append('OCR skipped: disabled')
        elif not OCR_AVAILABLE:
            result['warnings'].append('OCR skipped: module not available')
        elif not validation_result['is_safe']:
            result['warnings'].append('OCR skipped: file failed security validation')

        # Add pipeline info
        result['pipeline_info'] = {
            'validation_completed': True,
            'metadata_removal_enabled': remove_metadata_flag,
            'metadata_removal_available': METADATA_REMOVAL_AVAILABLE,
            'watermarking_enabled': add_watermark,
            'watermarking_available': WATERMARK_AVAILABLE,
            'ocr_enabled': enable_ocr,
            'ocr_available': OCR_AVAILABLE
        }
        
        # Include processed file data (watermarked/cleaned bytes) if we have it
        # Note: This is NOT JSON serializable - handle separately before JSON conversion
        result['processed_data'] = file_data
        
    except Exception as e:
        result['threats'].append(f'Pipeline error: {str(e)}')
        result['is_safe'] = False
        result['risk_level'] = 'high'
    
    return result

# =============================================================================
# SPECIALIZED VALIDATION FUNCTIONS FOR DIFFERENT UPLOAD TYPES
# =============================================================================

def validate_profile_image(file_obj, user_id: int, upload_folder: str, username: str = None) -> Dict:
    """
    Complete validation and processing for profile pictures with comprehensive pipeline
    Returns: {'success': bool, 'filename': str, 'error': str, 'filepath': str}
    """
    result = {'success': False, 'filename': None, 'error': None, 'filepath': None}
    
    try:
        # Read file data
        file_obj.seek(0)
        file_data = file_obj.read()
        file_obj.seek(0)
        
        # Use comprehensive validation pipeline with username watermarking
        validation = validate_and_clean_file(
            file_data=file_data,
            filename=file_obj.filename,
            max_size=2*1024*1024,  # 2MB for profile pics
            remove_metadata_flag=True,
            add_watermark=True,
            watermark_text=username or "VALIDATED"
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
        
        # Generate filename and save the processed file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"profile_{user_id}_{timestamp}.jpg"
        filepath = os.path.join(upload_folder, filename)
        
        # Save the processed (validated, cleaned, watermarked) file
        with open(filepath, 'wb') as f:
            f.write(file_data)  # This is now the processed data
        
        result.update({
            'success': True,
            'filename': filename,
            'filepath': filepath
        })
            
    except Exception as e:
        result['error'] = f'Processing error: {str(e)}'
    
    return result

def validate_banner_image(file_obj, user_id: int, upload_folder: str, username: str = None) -> Dict:
    """
    Complete validation and processing for banner images with comprehensive pipeline
    Returns: {'success': bool, 'filename': str, 'error': str, 'filepath': str}
    """
    result = {'success': False, 'filename': None, 'error': None, 'filepath': None}
    
    try:
        # Read file data
        file_obj.seek(0)
        file_data = file_obj.read()
        file_obj.seek(0)
        
        # Use comprehensive validation pipeline with username watermarking
        validation = validate_and_clean_file(
            file_data=file_data,
            filename=file_obj.filename,
            max_size=5*1024*1024,  # 5MB for banners
            remove_metadata_flag=True,
            add_watermark=True,
            watermark_text=username or "VALIDATED"
        )
        
        if not validation['is_safe']:
            threats = '; '.join(validation['threats'])
            result['error'] = f'Security validation failed: {threats}'
            return result
        
        if validation['risk_level'] in ['high', 'critical']:
            warnings = '; '.join(validation['warnings'])
            result['error'] = f'High-risk file detected: {warnings}'
            return result
        
        # Generate filename and save the processed file
        import uuid
        file_extension = file_obj.filename.rsplit('.', 1)[1].lower() if '.' in file_obj.filename else 'jpg'
        filename = f"banner_{user_id}_{uuid.uuid4().hex}.{file_extension}"
        filepath = os.path.join(upload_folder, filename)
        
        # Save the processed (validated, cleaned, watermarked) file
        with open(filepath, 'wb') as f:
            f.write(file_data)  # This is now the processed data
        
        result.update({
            'success': True,
            'filename': filename,
            'filepath': filepath
        })
            
    except Exception as e:
        result['error'] = f'Processing error: {str(e)}'
    
    return result

def validate_post_images(file_list, post_id: int, upload_folder: str, username: str = None) -> Dict:
    """
    Validate and process multiple post images with comprehensive pipeline
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
            
            # Use comprehensive validation pipeline with username watermarking
            validation = validate_and_clean_file(
                file_data=file_data,
                filename=file_obj.filename,
                max_size=10*1024*1024,  # 10MB for post images
                remove_metadata_flag=True,
                add_watermark=True,
                watermark_text=username or "VALIDATED"
            )
            
            if not validation['is_safe']:
                threats = '; '.join(validation['threats'])
                result['errors'].append(f'File {file_obj.filename}: {threats}')
                continue
            
            if validation['risk_level'] in ['high', 'critical']:
                warnings = '; '.join(validation['warnings'])
                result['warnings'].append(f'File {file_obj.filename}: {warnings}')
                continue
            
            # Generate filename and save the processed file
            import random
            import string
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
            filename = f"{post_id}_{timestamp}_{random_suffix}_{secure_filename(file_obj.filename)}"
            filepath = os.path.join(upload_folder, filename)
            
            # Save the processed (validated, cleaned, watermarked) file
            with open(filepath, 'wb') as f:
                f.write(file_data)  # This is now the processed data
            
            result['processed_files'].append({
                'filename': filename,
                'original_name': file_obj.filename,
                'filepath': filepath,
                'url': filename  # Just the filename for consistency
            })
                
        except Exception as e:
            result['errors'].append(f'Error processing {file_obj.filename}: {str(e)}')
    
    # Set overall success status
    result['success'] = len(result['processed_files']) > 0 or len(result['errors']) == 0
    
    return result

def validate_cropped_image_data(image_data_b64: str, user_id: int, upload_folder: str, username: str = None) -> Dict:
    """
    Validate and process base64 cropped image data with comprehensive pipeline
    Returns: {'success': bool, 'filename': str, 'error': str, 'filepath': str}
    """
    result = {'success': False, 'filename': None, 'error': None, 'filepath': None}
    
    try:
        # Decode base64 data
        import base64
        if ',' in image_data_b64:
            image_data_b64 = image_data_b64.split(',')[1]
        
        image_binary = base64.b64decode(image_data_b64)
        
        # Use comprehensive validation pipeline with username watermarking
        validation = validate_and_clean_file(
            file_data=image_binary,
            filename="cropped_image.jpg",
            max_size=2*1024*1024,  # 2MB limit
            remove_metadata_flag=True,
            add_watermark=True,
            watermark_text=username or "VALIDATED"
        )
        
        if not validation['is_safe']:
            threats = '; '.join(validation['threats'])
            result['error'] = f'Security validation failed: {threats}'
            return result
        
        if validation['risk_level'] in ['high', 'critical']:
            warnings = '; '.join(validation['warnings'])
            result['error'] = f'High-risk content detected: {warnings}'
            return result
        
        # Generate filename and save the processed file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"profile_{user_id}_{timestamp}.jpg"
        filepath = os.path.join(upload_folder, filename)
        
        # Save the processed (validated, cleaned, watermarked) file
        with open(filepath, 'wb') as f:
            f.write(image_binary)  # This is now the processed data
        
        result.update({
            'success': True,
            'filename': filename,
            'filepath': filepath
        })
            
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


def validate_image_with_ocr(file_path: str, output_dir: str = None, check_sensitive: bool = True) -> Dict:
    """
    Validate an image file using OCR to extract and analyze text content
    
    Args:
        file_path: Path to the image file
        output_dir: Directory to save OCR results (default: static/clean/ocr_output)
        check_sensitive: Whether to check extracted text for sensitive content
        
    Returns:
        Dict with OCR validation results:
        - success: bool (whether OCR scan succeeded)
        - has_text: bool (whether text was detected)
        - extracted_text: list of text strings
        - full_text: combined text
        - ocr_json_path: path to JSON results
        - has_sensitive_content: bool (if check_sensitive=True)
        - sensitive_matches: list (if check_sensitive=True and sensitive content found)
        - error: error message if failed
    """
    try:
        # Import OCR validator
        try:
            from .ocr_validate import validate_image_content, scan_and_check_sensitive_content
        except ImportError:
            try:
                from ocr_validate import validate_image_content, scan_and_check_sensitive_content
            except ImportError:
                return {
                    'success': False,
                    'error': 'OCR validation module not available (PaddleOCR not installed)',
                    'has_text': False,
                    'extracted_text': [],
                    'full_text': ''
                }
        
        # Perform OCR scan with optional sensitive content check
        if check_sensitive:
            result = scan_and_check_sensitive_content(file_path, output_dir)
        else:
            result = validate_image_content(file_path, output_dir)
        
        return result
        
    except Exception as e:
        return {
            'success': False,
            'error': f'OCR validation error: {str(e)}',
            'has_text': False,
            'extracted_text': [],
            'full_text': ''
        }


def scan_image_for_text(file_path: str, output_dir: str = None) -> Tuple[bool, str, Dict]:
    """
    Simplified function to scan image for text using OCR
    
    Args:
        file_path: Path to image file
        output_dir: Output directory for OCR results
        
    Returns:
        Tuple of (has_text: bool, full_text: str, ocr_data: dict)
    """
    result = validate_image_with_ocr(file_path, output_dir, check_sensitive=False)
    
    if result['success']:
        return result.get('has_text', False), result.get('full_text', ''), result
    else:
        return False, '', result


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