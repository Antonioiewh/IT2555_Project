#!/usr/bin/env python3
"""
test_s3_integration.py - Test S3 integration without starting the Flask app

Usage:
    python test_s3_integration.py
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_credentials():
    """Test if AWS credentials are loaded"""
    print("\n" + "="*50)
    print("Testing AWS Credentials")
    print("="*50)
    
    access_key = os.getenv('AWS_ACCESS_KEY_ID')
    secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    region = os.getenv('AWS_REGION', 'Asia Pacific (Singapore) ap-southeast-1')
    bucket = os.getenv('AWS_S3_BUCKET_NAME')
    
    if not access_key:
        print("❌ AWS_ACCESS_KEY_ID not set")
        return False
    print(f"✓ AWS_ACCESS_KEY_ID: {access_key[:10]}...")
    
    if not secret_key:
        print("❌ AWS_SECRET_ACCESS_KEY not set")
        return False
    print(f"✓ AWS_SECRET_ACCESS_KEY: {secret_key[:10]}...")
    
    print(f"✓ AWS_REGION: {region}")
    
    if not bucket:
        print("❌ AWS_S3_BUCKET_NAME not set")
        return False
    print(f"✓ AWS_S3_BUCKET_NAME: {bucket}")
    
    return True


def test_boto3():
    """Test boto3 installation"""
    print("\n" + "="*50)
    print("Testing boto3 Installation")
    print("="*50)
    
    try:
        import boto3
        print(f"✓ boto3 version: {boto3.__version__}")
        return True
    except ImportError:
        print("❌ boto3 not installed. Run: pip install boto3")
        return False


def test_s3_connection():
    """Test S3 connection"""
    print("\n" + "="*50)
    print("Testing S3 Connection")
    print("="*50)
    
    try:
        from s3_service import s3_service
        
        if not s3_service.enabled:
            print("❌ S3 service is not enabled")
            return False
        
        print("✓ S3 service initialized successfully")
        
        # Try to list buckets
        try:
            response = s3_service.s3_client.list_buckets()
            buckets = [b['Name'] for b in response.get('Buckets', [])]
            print(f"✓ Found {len(buckets)} S3 buckets")
            
            bucket_name = os.getenv('AWS_S3_BUCKET_NAME')
            if bucket_name in buckets:
                print(f"✓ Your bucket '{bucket_name}' exists")
                return True
            else:
                print(f"❌ Bucket '{bucket_name}' not found in your account")
                print(f"   Available buckets: {buckets}")
                return False
                
        except Exception as e:
            print(f"❌ Error listing buckets: {str(e)}")
            return False
            
    except Exception as e:
        print(f"❌ Failed to initialize S3 service: {str(e)}")
        return False


def test_upload_and_delete():
    """Test uploading and deleting a file"""
    print("\n" + "="*50)
    print("Testing Upload & Delete")
    print("="*50)
    
    try:
        from s3_service import s3_service
        
        # Upload test file
        test_content = b"This is a test file for S3 integration"
        test_path = "test/test_file.txt"
        
        print(f"Uploading test file to: {test_path}")
        success, key, error = s3_service.upload_bytes_to_s3(
            test_content,
            test_path,
            content_type='text/plain'
        )
        
        if not success:
            print(f"❌ Upload failed: {error}")
            return False
        
        print(f"✓ File uploaded successfully")
        print(f"  S3 Key: {key}")
        
        # Get URL
        url = s3_service.get_s3_url(key)
        print(f"  S3 URL: {url}")
        
        # Delete test file
        print(f"Deleting test file...")
        del_success, del_error = s3_service.delete_file_from_s3(key)
        
        if not del_success:
            print(f"⚠ Deletion failed: {del_error}")
            print("  (File may still exist in S3)")
            return False
        
        print(f"✓ File deleted successfully")
        return True
        
    except Exception as e:
        print(f"❌ Error during upload/delete test: {str(e)}")
        return False


def test_image_upload():
    """Test uploading an actual image file"""
    print("\n" + "="*50)
    print("Testing Image Upload")
    print("="*50)
    
    try:
        from s3_service import s3_service
        
        # Create a simple test image
        test_image_path = Path("test_image.jpg")
        
        # Create a minimal JPEG (1x1 pixel)
        jpeg_bytes = bytes([
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
            0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
            0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
            0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
            0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
            0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
            0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
            0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01,
            0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00,
            0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0xFF, 0xC4, 0x00, 0xB5, 0x10, 0x00, 0x02, 0x01, 0x03,
            0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7D,
            0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06,
            0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08,
            0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72,
            0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28,
            0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45,
            0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
            0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75,
            0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
            0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3,
            0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6,
            0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9,
            0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2,
            0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4,
            0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01,
            0x00, 0x00, 0x3F, 0x00, 0xFB, 0xD3, 0xFF, 0xD9
        ])
        
        test_path = "test/test_image.jpg"
        
        print(f"Uploading test image to: {test_path}")
        success, key, error = s3_service.upload_bytes_to_s3(
            jpeg_bytes,
            test_path,
            content_type='image/jpeg'
        )
        
        if not success:
            print(f"❌ Image upload failed: {error}")
            return False
        
        print(f"✓ Image uploaded successfully")
        print(f"  Size: {len(jpeg_bytes)} bytes")
        
        # Delete test image
        del_success, _ = s3_service.delete_file_from_s3(key)
        if del_success:
            print(f"✓ Image deleted successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Error during image upload test: {str(e)}")
        return False


def main():
    """Run all tests"""
    print("\n")
    print("┌" + "="*48 + "┐")
    print("│  AWS S3 Integration Test Suite               │")
    print("└" + "="*48 + "┘")
    
    tests = [
        ("Credentials", test_credentials),
        ("boto3 Library", test_boto3),
        ("S3 Connection", test_s3_connection),
        ("Upload & Delete", test_upload_and_delete),
        ("Image Upload", test_image_upload),
    ]
    
    results = {}
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"❌ Test failed with error: {str(e)}")
            results[test_name] = False
    
    # Summary
    print("\n" + "="*50)
    print("Test Summary")
    print("="*50)
    
    for test_name, passed in results.items():
        status = "✓ PASS" if passed else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    passed_count = sum(1 for v in results.values() if v)
    total_count = len(results)
    
    print(f"\nResult: {passed_count}/{total_count} tests passed")
    
    if all(results.values()):
        print("\n✓ All tests passed! S3 integration is working.")
        return 0
    else:
        print("\n❌ Some tests failed. Check the messages above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
