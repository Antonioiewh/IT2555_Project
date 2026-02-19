# watermaker.py - Image Watermarking Module for File Pipeline

import os
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont
import logging

def apply_red_watermark(image_data_or_path, watermark_text="VALIDATED", save_to_path=None):
    """
    Apply a red watermark to the bottom-right corner of an image.
    Enhanced version with red color and larger font for pipeline use.
    
    Args:
        image_data_or_path: Either bytes data or path to the image file
        watermark_text: Text to display as watermark (default: "VALIDATED")
        save_to_path: If provided, save the watermarked image to this path
    
    Returns:
        Dict containing:
        {
            'success': bool,
            'image_data': bytes or None,  # Watermarked image as bytes
            'error': str or None,
            'details': str
        }
    """
    result = {
        'success': False,
        'image_data': None,
        'error': None,
        'details': ''
    }
    
    try:
        # Handle input - either bytes or file path
        if isinstance(image_data_or_path, bytes):
            # Input is bytes data
            if len(image_data_or_path) == 0:
                result['error'] = "Empty image data provided"
                return result
            img = Image.open(BytesIO(image_data_or_path))
            input_source = "bytes data"
        elif isinstance(image_data_or_path, str) and os.path.exists(image_data_or_path):
            # Input is file path - check if file is readable
            try:
                # Verify file exists and is readable
                if os.path.getsize(image_data_or_path) == 0:
                    result['error'] = f"File is empty: {image_data_or_path}"
                    return result
                    
                img = Image.open(image_data_or_path)
                input_source = f"file: {os.path.basename(image_data_or_path)}"
            except (IOError, OSError) as file_error:
                result['error'] = f"Cannot read image file: {str(file_error)}"
                return result
        else:
            if isinstance(image_data_or_path, str):
                result['error'] = f"File does not exist: {image_data_or_path}"
            else:
                result['error'] = "Invalid input: must be bytes data or valid file path"
            return result
        
        # Check if it's actually an image
        if not _is_valid_image(img):
            result['error'] = "Input is not a valid image format"
            return result
        
        # Convert to RGBA for proper alpha compositing
        if img.mode != 'RGBA':
            img = img.convert('RGBA')
        
        # Create a copy to avoid modifying original
        img = img.copy()
        width, height = img.size
        
        # Create overlay layer for watermark
        overlay = Image.new('RGBA', img.size, (255, 255, 255, 0))  # Transparent overlay
        draw = ImageDraw.Draw(overlay)
        
        # Calculate enhanced font size (larger than original)
        # Using 10.5% of height for better clarity without being too large
        base_font_size = max(int(height * 0.105), 28)  # 10.5% of image height, minimum 28px
        
        # Try to load a nice font, fallback to default if unavailable
        font = _get_best_font(base_font_size)
        
        # Get text bounding box to know its size
        bbox = draw.textbbox((0, 0), watermark_text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        
        # Calculate position (bottom-right with padding)
        padding = max(int(width * 0.03), 15)  # 3% of image width, minimum 15px
        x = width - text_width - padding
        y = height - text_height - padding
        
        # Draw watermark with RED color and good opacity for clarity
        # Red color with full opacity for crisp text
        watermark_color = (220, 20, 20, 255)  # Bright red, full opacity for sharpness
        
        # Add very subtle shadow for contrast without blurriness
        shadow_offset = 1
        shadow_color = (0, 0, 0, 80)  # Much lighter shadow
        draw.text((x + shadow_offset, y + shadow_offset), watermark_text, 
                 font=font, fill=shadow_color)
        
        # Draw main watermark text with full opacity for crisp rendering
        draw.text((x, y), watermark_text, font=font, fill=watermark_color)
        
        # Composite the overlay onto the image
        img = Image.alpha_composite(img, overlay)
        
        # Convert to RGB for saving (most common format)
        img_rgb = img.convert('RGB')
        
        # Save to specified path if provided
        if save_to_path:
            try:
                # Ensure directory exists
                save_dir = os.path.dirname(save_to_path)
                if save_dir:  # Only create directory if path has a directory component
                    os.makedirs(save_dir, exist_ok=True)
                
                # Save with error handling
                img_rgb.save(save_to_path, format='JPEG', quality=92, optimize=True)
                
                # Verify the file was actually saved
                if os.path.exists(save_to_path) and os.path.getsize(save_to_path) > 0:
                    result['details'] += f" Saved to: {save_to_path}"
                else:
                    result['error'] = f"File was not saved properly to: {save_to_path}"
                    return result
                    
            except Exception as save_error:
                result['error'] = f"Failed to save watermarked image to {save_to_path}: {str(save_error)}"
                logging.error(f"Save error: {str(save_error)}")
                return result
        
        # Convert to bytes for return
        buf = BytesIO()
        img_rgb.save(buf, format='JPEG', quality=92, optimize=True)
        buf.seek(0)
        result['image_data'] = buf.getvalue()
        
        result['success'] = True
        result['details'] = f"Successfully applied red watermark '{watermark_text}' to {input_source}. " + result['details']
        
        # Log success
        logging.info(f"Watermark applied successfully to image from {input_source}")
        
    except Exception as e:
        error_msg = str(e) if str(e) else "Unknown watermarking error occurred"
        result['error'] = f"Error applying watermark: {error_msg}"
        logging.error(f"Watermarking error: {error_msg}")
        logging.debug(f"Full watermarking exception: {repr(e)}")
    
    return result

def _get_best_font(font_size):
    """
    Try to get the best available font for watermarking
    """
    font_paths = [
        # Windows fonts
        "C:\\Windows\\Fonts\\arial.ttf",
        "C:\\Windows\\Fonts\\calibri.ttf", 
        "C:\\Windows\\Fonts\\segoeui.ttf",
        # Linux fonts
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        # macOS fonts
        "/System/Library/Fonts/Arial.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
        # Fallback system names
        "arial.ttf",
        "Arial",
        "helvetica",
        "DejaVu Sans"
    ]
    
    for font_path in font_paths:
        try:
            return ImageFont.truetype(font_path, font_size)
        except (OSError, IOError):
            continue
    
    # Ultimate fallback to default font
    try:
        return ImageFont.load_default()
    except:
        # If even default fails, create a minimal font
        return None

def _is_valid_image(img):
    """
    Check if PIL image object is valid and supported for watermarking
    """
    try:
        # Get original image info before verify
        original_mode = img.mode
        original_size = img.size
        original_format = img.format
        
        # Check basic properties first
        width, height = original_size
        if width <= 0 or height <= 0:
            return False
        
        # Check if format is supported (if available)
        if original_format and original_format not in ['JPEG', 'PNG', 'GIF', 'BMP', 'TIFF', 'WEBP']:
            return False
        
        # Try to access pixel data to verify image integrity
        # This is safer than verify() which can only be called once
        img.load()
        
        return True
        
    except Exception as e:
        logging.debug(f"Image validation failed: {str(e)}")
        return False

def apply_watermark_to_file(file_path, watermark_text="VALIDATED", output_path=None):
    """
    Convenience function to watermark a file and optionally save it
    
    Args:
        file_path: Path to the input image file
        watermark_text: Text to use as watermark
        output_path: Path to save watermarked image (if None, overwrites original)
    
    Returns:
        Dict with success status and details
    """
    if not os.path.exists(file_path):
        return {
            'success': False,
            'error': f"File not found: {file_path}",
            'details': ''
        }
    
    # Use input file path as output if not specified
    if output_path is None:
        output_path = file_path
    
    return apply_red_watermark(file_path, watermark_text, output_path)

def is_image_file(file_path_or_data):
    """
    Check if a file or data is a valid image that can be watermarked
    
    Args:
        file_path_or_data: Either file path (str) or image bytes data
    
    Returns:
        bool: True if it's a valid image file
    """
    try:
        if isinstance(file_path_or_data, bytes):
            img = Image.open(BytesIO(file_path_or_data))
        elif isinstance(file_path_or_data, str):
            img = Image.open(file_path_or_data)
        else:
            return False
            
        return _is_valid_image(img)
        
    except Exception:
        return False

# Example usage and testing
if __name__ == "__main__":
    # Test function
    def test_watermark():
        print("Testing watermarking functionality...")
        
        # This would be used in actual testing
        test_image_path = "test_image.jpg"  # Would need an actual test image
        if os.path.exists(test_image_path):
            result = apply_watermark_to_file(test_image_path, "TEST VALIDATED", "test_watermarked.jpg")
            print(f"Watermark test result: {result}")
        else:
            print("No test image found for watermarking test")
    
    # Uncomment to run test
    # test_watermark()
