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


# Initialize S3 service
s3_service = S3Service()
