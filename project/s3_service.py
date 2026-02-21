# s3_service.py - AWS S3 integration for file uploads

import os
import boto3
import logging
from botocore.exceptions import ClientError, NoCredentialsError
from werkzeug.utils import secure_filename
from datetime import datetime
from typing import Dict, Tuple, Optional

logger = logging.getLogger(__name__)


class S3Service:
    """Handles all S3 operations for file uploads and backups"""
    
    def __init__(self):
        """Initialize S3 client with credentials from environment variables"""
        try:
            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
                region_name=os.getenv('AWS_REGION', 'Asia Pacific (Singapore) ap-southeast-1')
            )
            self.bucket_name = os.getenv('AWS_S3_BUCKET_NAME')
            
            if not self.bucket_name:
                raise ValueError("AWS_S3_BUCKET_NAME environment variable not set")
            
            self.enabled = True
            logger.info(f"S3 service initialized with bucket: {self.bucket_name}")
            
        except NoCredentialsError:
            self.enabled = False
            logger.warning("AWS credentials not found. S3 uploads disabled.")
        except Exception as e:
            self.enabled = False
            logger.error(f"Failed to initialize S3 service: {str(e)}")
    
    def upload_file_to_s3(self, file_obj, file_path: str, content_type: str = 'application/octet-stream') -> Tuple[bool, str, Optional[str]]:
        """
        Upload a file to S3
        
        Args:
            file_obj: File object from request.files
            file_path: Path structure (e.g., 'users/123/banner.jpg' or 'posts/456/image.png')
            content_type: MIME type of the file
            
        Returns:
            Tuple of (success: bool, s3_key: str, error: Optional[str])
        """
        if not self.enabled:
            return False, "", "S3 service is not enabled"
        
        try:
            # Ensure file_path doesn't start with /
            file_path = file_path.lstrip('/')
            
            # Read file content
            file_content = file_obj.read()
            file_obj.seek(0)  # Reset file pointer for fallback local save
            
            # Upload to S3
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=file_path,
                Body=file_content,
                ContentType=content_type,
                Metadata={
                    'uploaded_at': datetime.utcnow().isoformat(),
                    'source': 'app'
                }
            )
            
            logger.info(f"Successfully uploaded {file_path} to S3")
            return True, file_path, None
            
        except ClientError as e:
            error_msg = f"S3 upload error: {str(e)}"
            logger.error(error_msg)
            return False, "", error_msg
        except Exception as e:
            error_msg = f"Unexpected error uploading to S3: {str(e)}"
            logger.error(error_msg)
            return False, "", error_msg
    
    def upload_bytes_to_s3(self, file_bytes: bytes, file_path: str, content_type: str = 'application/octet-stream') -> Tuple[bool, str, Optional[str]]:
        """
        Upload raw bytes to S3
        
        Args:
            file_bytes: Raw file bytes
            file_path: Path structure in S3
            content_type: MIME type
            
        Returns:
            Tuple of (success: bool, s3_key: str, error: Optional[str])
        """
        if not self.enabled:
            return False, "", "S3 service is not enabled"
        
        try:
            file_path = file_path.lstrip('/')
            
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=file_path,
                Body=file_bytes,
                ContentType=content_type,
                Metadata={
                    'uploaded_at': datetime.utcnow().isoformat()
                }
            )
            
            logger.info(f"Successfully uploaded {file_path} to S3 (bytes)")
            return True, file_path, None
            
        except Exception as e:
            error_msg = f"Error uploading bytes to S3: {str(e)}"
            logger.error(error_msg)
            return False, "", error_msg
    
    def delete_file_from_s3(self, file_path: str) -> Tuple[bool, Optional[str]]:
        """
        Delete a file from S3
        
        Args:
            file_path: Path of file in S3
            
        Returns:
            Tuple of (success: bool, error: Optional[str])
        """
        if not self.enabled:
            return False, "S3 service is not enabled"
        
        try:
            file_path = file_path.lstrip('/')
            
            self.s3_client.delete_object(
                Bucket=self.bucket_name,
                Key=file_path
            )
            
            logger.info(f"Successfully deleted {file_path} from S3")
            return True, None
            
        except Exception as e:
            error_msg = f"Error deleting from S3: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def get_presigned_url(self, file_path: str, expiration: int = 3600) -> Tuple[bool, str, Optional[str]]:
        """
        Generate a presigned URL for accessing a file in S3
        
        Args:
            file_path: Path of file in S3
            expiration: URL expiration time in seconds (default: 1 hour)
            
        Returns:
            Tuple of (success: bool, url: str, error: Optional[str])
        """
        if not self.enabled:
            return False, "", "S3 service is not enabled"
        
        try:
            file_path = file_path.lstrip('/')
            
            url = self.s3_client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': self.bucket_name,
                    'Key': file_path
                },
                ExpiresIn=expiration
            )
            
            return True, url, None
            
        except Exception as e:
            error_msg = f"Error generating presigned URL: {str(e)}"
            logger.error(error_msg)
            return False, "", error_msg
    
    def get_s3_url(self, file_path: str) -> str:
        """
        Get the standard S3 URL for a file (for public buckets)
        
        Args:
            file_path: Path of file in S3
            
        Returns:
            Full S3 URL
        """
        file_path = file_path.lstrip('/')
        region = os.getenv('AWS_REGION', 'Asia Pacific (Singapore) ap-southeast-1')
        return f"https://{self.bucket_name}.s3.{region}.amazonaws.com/{file_path}"
    
    def list_files_in_s3(self, prefix: str = '') -> Tuple[bool, list, Optional[str]]:
        """
        List files in S3 with optional prefix
        
        Args:
            prefix: Prefix to filter files (e.g., 'users/123/')
            
        Returns:
            Tuple of (success: bool, files: list, error: Optional[str])
        """
        if not self.enabled:
            return False, [], "S3 service is not enabled"
        
        try:
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=prefix
            )
            
            files = [obj['Key'] for obj in response.get('Contents', [])]
            return True, files, None
            
        except Exception as e:
            error_msg = f"Error listing S3 files: {str(e)}"
            logger.error(error_msg)
            return False, [], error_msg
    
    def list_files_with_metadata(self, prefix: str = '', max_keys: int = 1000) -> Tuple[bool, list, Optional[str]]:
        """
        List files in S3 with detailed metadata
        
        Args:
            prefix: Prefix to filter files (e.g., 'users/', 'posts/')
            max_keys: Maximum number of files to return
            
        Returns:
            Tuple of (success: bool, files_metadata: list[dict], error: Optional[str])
            Each dict contains: Key, Size, LastModified, StorageClass, ETag, URL
        """
        if not self.enabled:
            return False, [], "S3 service is not enabled"
        
        try:
            all_files = []
            continuation_token = None
            
            while True:
                # Build request parameters
                params = {
                    'Bucket': self.bucket_name,
                    'Prefix': prefix,
                    'MaxKeys': min(max_keys - len(all_files), 1000)
                }
                
                if continuation_token:
                    params['ContinuationToken'] = continuation_token
                
                response = self.s3_client.list_objects_v2(**params)
                
                # Process each object
                for obj in response.get('Contents', []):
                    file_info = {
                        'Key': obj['Key'],
                        'Size': obj['Size'],
                        'SizeFormatted': self._format_file_size(obj['Size']),
                        'LastModified': obj['LastModified'].isoformat(),
                        'StorageClass': obj.get('StorageClass', 'STANDARD'),
                        'ETag': obj['ETag'].strip('"'),
                        'URL': self.get_s3_url(obj['Key']),
                        'FileName': obj['Key'].split('/')[-1],
                        'Folder': '/'.join(obj['Key'].split('/')[:-1]) if '/' in obj['Key'] else ''
                    }
                    all_files.append(file_info)
                
                # Check if there are more files
                if not response.get('IsTruncated', False) or len(all_files) >= max_keys:
                    break
                
                continuation_token = response.get('NextContinuationToken')
            
            logger.info(f"Listed {len(all_files)} files from S3 with prefix '{prefix}'")
            return True, all_files, None
            
        except Exception as e:
            error_msg = f"Error listing S3 files with metadata: {str(e)}"
            logger.error(error_msg)
            return False, [], error_msg
    
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
    
    def delete_multiple_files(self, file_paths: list) -> Tuple[bool, Dict, Optional[str]]:
        """
        Delete multiple files from S3 in a batch operation
        
        Args:
            file_paths: List of file paths to delete
            
        Returns:
            Tuple of (success: bool, results: dict, error: Optional[str])
            results contains: deleted (list), errors (list)
        """
        if not self.enabled:
            return False, {'deleted': [], 'errors': []}, "S3 service is not enabled"
        
        if not file_paths:
            return True, {'deleted': [], 'errors': []}, None
        
        try:
            # Prepare objects for deletion
            objects_to_delete = [{'Key': path.lstrip('/')} for path in file_paths]
            
            response = self.s3_client.delete_objects(
                Bucket=self.bucket_name,
                Delete={'Objects': objects_to_delete}
            )
            
            deleted = [obj['Key'] for obj in response.get('Deleted', [])]
            errors = [
                {'Key': obj['Key'], 'Message': obj.get('Message', 'Unknown error')}
                for obj in response.get('Errors', [])
            ]
            
            logger.info(f"Deleted {len(deleted)} files from S3. {len(errors)} errors.")
            
            return True, {'deleted': deleted, 'errors': errors}, None
            
        except Exception as e:
            error_msg = f"Error deleting multiple files from S3: {str(e)}"
            logger.error(error_msg)
            return False, {'deleted': [], 'errors': []}, error_msg
    
    def get_bucket_stats(self) -> Tuple[bool, Dict, Optional[str]]:
        """
        Get statistics about the S3 bucket
        
        Returns:
            Tuple of (success: bool, stats: dict, error: Optional[str])
            stats contains: total_files, total_size, folders
        """
        if not self.enabled:
            return False, {}, "S3 service is not enabled"
        
        try:
            total_files = 0
            total_size = 0
            folders = set()
            
            paginator = self.s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=self.bucket_name)
            
            for page in pages:
                for obj in page.get('Contents', []):
                    total_files += 1
                    total_size += obj['Size']
                    
                    # Extract folder from key
                    if '/' in obj['Key']:
                        folder = obj['Key'].split('/')[0]
                        folders.add(folder)
            
            stats = {
                'total_files': total_files,
                'total_size': total_size,
                'total_size_formatted': self._format_file_size(total_size),
                'folders': sorted(list(folders)),
                'folder_count': len(folders)
            }
            
            logger.info(f"Bucket stats: {total_files} files, {stats['total_size_formatted']}")
            return True, stats, None
            
        except Exception as e:
            error_msg = f"Error getting bucket stats: {str(e)}"
            logger.error(error_msg)
            return False, {}, error_msg


# Initialize S3 service
s3_service = S3Service()
