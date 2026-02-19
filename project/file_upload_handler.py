# file_upload_handler.py - Unified file upload handling with S3 support

import os
import io
from typing import Dict, Optional, Tuple
from werkzeug.utils import secure_filename
from s3_service import s3_service
import logging

logger = logging.getLogger(__name__)


class FileUploadHandler:
    """Handles file uploads with local and S3 storage options"""
    
    def __init__(self, local_upload_dir: str = None, use_s3: bool = True):
        """
        Initialize file upload handler
        
        Args:
            local_upload_dir: Directory for local backup (e.g., static/uploads)
            use_s3: Whether to use S3 storage (default: True)
        """
        self.local_upload_dir = local_upload_dir
        self.use_s3 = use_s3 and s3_service.enabled
        
    def save_file(self, file_obj, file_path: str, content_type: str = 'application/octet-stream', 
                  save_local: bool = True) -> Dict:
        """
        Save file to S3 and optionally to local storage
        
        Args:
            file_obj: File object from request.files
            file_path: Relative path in S3 (e.g., 'banners/user_123.jpg')
            content_type: MIME type
            save_local: Whether to also save locally for backup
            
        Returns:
            Dict with keys:
            - success (bool): Upload success
            - s3_key (str): Path in S3 (if S3 enabled)
            - local_path (str): Local file path (if saved locally)
            - url (str): URL to access the file
            - error (str): Error message if failed
        """
        result = {
            'success': False,
            's3_key': None,
            'local_path': None,
            'url': None,
            'error': None
        }
        
        try:
            # Clean filename
            if hasattr(file_obj, 'filename'):
                filename = secure_filename(file_obj.filename)
                # Use secure filename in S3 path
                file_path = os.path.dirname(file_path) + '/' + filename if '/' in file_path else filename
            
            file_content = file_obj.read()
            file_obj.seek(0)
            
            # Upload to S3 if enabled
            if self.use_s3:
                s3_success, s3_key, s3_error = s3_service.upload_bytes_to_s3(
                    file_content, file_path, content_type
                )
                
                if s3_success:
                    result['s3_key'] = s3_key
                    result['url'] = s3_service.get_s3_url(s3_key)
                    logger.info(f"File uploaded to S3: {s3_key}")
                else:
                    logger.warning(f"S3 upload failed: {s3_error}")
                    result['error'] = s3_error
            
            # Save locally as backup
            if save_local and self.local_upload_dir:
                local_path = self._save_local(file_content, file_path)
                if local_path:
                    result['local_path'] = local_path
                    # Use local URL as fallback if S3 failed
                    if not result['url']:
                        result['url'] = f"/static/{local_path}"
            
            # Mark as success if at least one storage succeeded
            if result['s3_key'] or result['local_path']:
                result['success'] = True
            else:
                result['error'] = 'Failed to save file to any storage'
            
            return result
            
        except Exception as e:
            logger.error(f"File upload error: {str(e)}")
            result['error'] = str(e)
            return result
    
    def _save_local(self, file_content: bytes, file_path: str) -> Optional[str]:
        """
        Save file to local directory
        
        Args:
            file_content: File bytes
            file_path: Relative path
            
        Returns:
            Relative path if successful, None otherwise
        """
        try:
            # Create directory structure
            full_dir = os.path.join(self.local_upload_dir, os.path.dirname(file_path))
            os.makedirs(full_dir, exist_ok=True)
            
            # Save file
            full_path = os.path.join(self.local_upload_dir, file_path)
            with open(full_path, 'wb') as f:
                f.write(file_content)
            
            logger.info(f"File saved locally: {file_path}")
            return file_path
            
        except Exception as e:
            logger.error(f"Local save error: {str(e)}")
            return None
    
    def delete_file(self, file_path: str, delete_s3: bool = True, delete_local: bool = True) -> Dict:
        """
        Delete file from S3 and/or local storage
        
        Args:
            file_path: Path of the file
            delete_s3: Delete from S3
            delete_local: Delete from local storage
            
        Returns:
            Dict with deletion results
        """
        result = {
            'success': False,
            's3_deleted': False,
            'local_deleted': False,
            'error': None
        }
        
        try:
            # Delete from S3
            if delete_s3 and self.use_s3:
                s3_success, s3_error = s3_service.delete_file_from_s3(file_path)
                result['s3_deleted'] = s3_success
                if not s3_success:
                    logger.warning(f"S3 deletion failed: {s3_error}")
            
            # Delete from local storage
            if delete_local and self.local_upload_dir:
                local_path = os.path.join(self.local_upload_dir, file_path)
                if os.path.exists(local_path):
                    try:
                        os.remove(local_path)
                        result['local_deleted'] = True
                        logger.info(f"File deleted locally: {file_path}")
                    except Exception as e:
                        logger.warning(f"Local deletion failed: {str(e)}")
            
            result['success'] = result['s3_deleted'] or result['local_deleted']
            return result
            
        except Exception as e:
            logger.error(f"File deletion error: {str(e)}")
            result['error'] = str(e)
            return result


# Create default handler instance
def create_upload_handler(app) -> FileUploadHandler:
    """Create upload handler with Flask app config"""
    upload_dir = os.path.join(app.root_path, app.config.get('UPLOAD_FOLDER', 'static/uploads'))
    use_s3 = os.getenv('USE_S3_STORAGE', 'true').lower() == 'true'
    return FileUploadHandler(
        local_upload_dir=upload_dir,
        use_s3=use_s3
    )
