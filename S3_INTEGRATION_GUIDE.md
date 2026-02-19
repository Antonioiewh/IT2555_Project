# AWS S3 Integration Setup Guide

## Overview
Your Flask application is now configured to upload files to AWS S3 with local backup. Files are uploaded to S3 first, with automatic fallback to local storage if S3 is unavailable.

## Quick Setup (5 steps)

### Step 1: Create AWS S3 Bucket
1. Go to [AWS Console](https://console.aws.amazon.com/)
2. Navigate to **S3** service
3. Click **Create bucket**
4. Name it something like: `appname-uploads-prod` (must be globally unique)
5. Choose region closest to your users (e.g., `us-east-1`)
6. **⚠️ IMPORTANT:** For now, keep it **private** (don't make it public unless needed)
7. Create the bucket

### Step 2: Create IAM User for S3 Access
1. Go to **IAM** service in AWS Console
2. Click **Users** → **Create user**
3. Name it: `app-s3-user` (or similar)
4. Click **Next**
5. Click **Attach policies directly**
6. Search for and select: `AmazonS3FullAccess` (for development)
   - **For production**, create a custom policy with only your bucket
7. Create the user

### Step 3: Generate Access Keys
1. Click the user you just created
2. Go to **Security credentials** tab
3. Click **Create access key**
4. Choose **Command Line Interface (CLI)**
5. Accept the warning, click **Next**
6. Copy your credentials:
   - **Access Key ID**
   - **Secret Access Key** (⚠️ Save this safely, you won't see it again!)

### Step 4: Configure Environment Variables
Create a `.env` file in your project root:

```bash
# AWS S3 Configuration
AWS_ACCESS_KEY_ID=your_access_key_from_step_3
AWS_SECRET_ACCESS_KEY=your_secret_key_from_step_3
AWS_REGION=us-east-1
AWS_S3_BUCKET_NAME=appname-uploads-prod

# Enable S3 storage
USE_S3_STORAGE=true
```

**⚠️ IMPORTANT:** 
- Never commit `.env` file to Git!
- It's already in `.gitignore` (hopefully)
- For Docker, pass these as environment variables: `docker run -e AWS_ACCESS_KEY_ID=... -e AWS_SECRET_ACCESS_KEY=...`

### Step 5: Install Dependencies
```bash
pip install -r requirements.txt
```

This installs:
- `boto3` - AWS SDK for Python
- `python-dotenv` - Load environment variables

## Testing the Integration

### Option A: Using Python
```python
from s3_service import s3_service

# Test upload
success, key, error = s3_service.upload_bytes_to_s3(
    b"test content",
    "test/test_file.txt",
    "text/plain"
)
print(f"Upload success: {success}")
if success:
    print(f"S3 Key: {key}")
    print(f"URL: {s3_service.get_s3_url(key)}")
else:
    print(f"Error: {error}")
```

### Option B: Upload through your app
1. Start your Flask app
2. Go to your banner upload page
3. Upload an image
4. Check your S3 bucket in AWS Console to verify the file appears

### Option C: Check logs
```bash
# Your app logs will show:
# "Successfully uploaded banners/user_1_photo.jpg to S3"
```

## File Organization in S3

Your uploaded files will be organized as:
```
s3://your-bucket-name/
├── banners/
│   ├── user_1_banner.jpg
│   ├── user_2_banner.png
│   └── ...
├── posts/
│   ├── post_1/
│   │   ├── image_1.jpg
│   │   └── image_2.jpg
│   └── post_2/
├── attachments/
│   ├── user_1/
│   │   ├── document.pdf
│   │   └── image.jpg
│   └── user_2/
└── ...
```

## Accessing Files

### Public bucket (if you make it public):
```python
url = s3_service.get_s3_url("banners/user_1_banner.jpg")
# Returns: https://bucket-name.s3.us-east-1.amazonaws.com/banners/user_1_banner.jpg
```

### Private bucket (recommended):
Use presigned URLs that expire after 1 hour:
```python
success, url, error = s3_service.get_presigned_url("banners/user_1_banner.jpg")
# URL is valid for 1 hour, then expires
```

## Production Best Practices

### 1. Restrict IAM User Permissions
Instead of `AmazonS3FullAccess`, create a custom policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject"
            ],
            "Resource": "arn:aws:s3:::your-bucket-name/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": "arn:aws:s3:::your-bucket-name"
        }
    ]
}
```

### 2. Enable S3 Bucket Versioning
```bash
aws s3api put-bucket-versioning \
    --bucket appname-uploads-prod \
    --versioning-configuration Status=Enabled
```

### 3. Enable Server-Side Encryption
1. Go to bucket properties
2. Enable **Default encryption** with **AES-256** or **KMS**

### 4. Set Bucket Lifecycle Policy
Delete old files automatically after 90 days:
```json
{
    "Rules": [
        {
            "Id": "DeleteOldFiles",
            "Status": "Enabled",
            "ExpirationInDays": 90,
            "NoncurrentVersionExpirationInDays": 30
        }
    ]
}
```

### 5. Block Public Access
In bucket settings, enable **Block all public access**

### 6. Enable CloudTrail Logging
Track all S3 access for security audits

## Fallback Behavior

If S3 is unavailable:
- Files still upload to `static/uploads/` (local)
- Your app continues to work
- Check logs for S3 errors:
```
WARNING - S3 upload failed: Connection timeout
```

## Monitoring S3 Usage

### View costs
- AWS Console → **Billing** → **S3**

### View storage usage
```bash
aws s3 ls s3://appname-uploads-prod --recursive --human-readable --summarize
```

### Delete specific user's files
```bash
aws s3 rm s3://appname-uploads-prod/banners/user_123/ --recursive
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "NoCredentialsError" | Check `.env` file has AWS credentials set correctly |
| "InvalidBucketName" | Bucket name must be globally unique, check spelling |
| "AccessDenied" | Check IAM user has S3 permissions |
| Files not appearing | Wait a few seconds (S3 eventual consistency), then refresh |
| High AWS costs | Check for duplicate uploads, enable lifecycle policies |

## Cost Estimation

For typical usage ($0.023 per GB storage/month):
- 1 GB uploads: ~$0.023/month
- 1 TB uploads: ~$23/month
- Data transfer: Varies by location

Monitor your usage in AWS Billing console!

## Next Steps

1. ✅ Create S3 bucket
2. ✅ Create IAM user
3. ✅ Set up `.env`
4. ✅ Test uploads
5. Consider enabling CloudFront for faster file delivery
6. Set up automated backups in S3
7. Monitor costs in AWS Billing

## API Reference

See [S3Service documentation](s3_service.py) for full API:
- `upload_file_to_s3()` - Upload from file object
- `upload_bytes_to_s3()` - Upload raw bytes
- `delete_file_from_s3()` - Remove files
- `get_presigned_url()` - Generate temporary URLs
- `list_files_in_s3()` - List bucket contents
