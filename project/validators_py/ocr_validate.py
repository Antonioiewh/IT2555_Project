# ocr_validate.py - PaddleOCR integration for text extraction from images

import os
import json
import logging
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from paddleocr import PaddleOCR

logger = logging.getLogger(__name__)

# Global OCR instance (initialized once for performance)
_ocr_instance = None


def get_ocr_instance():
    """Get or create PaddleOCR instance (singleton pattern for performance)"""
    global _ocr_instance
    
    if _ocr_instance is None:
        try:
            _ocr_instance = PaddleOCR(
                lang="en",  # Specify English recognition model
                use_doc_orientation_classify=False,  # Disable document orientation classification
                use_doc_unwarping=False,  # Disable text image unwarping
                use_textline_orientation=False  # Disable text line orientation classification
            )
            logger.info("PaddleOCR instance initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize PaddleOCR: {str(e)}")
            raise
    
    return _ocr_instance


def scan_image_with_ocr(image_path: str, output_dir: str = None) -> Tuple[bool, Dict, Optional[str]]:
    """
    Scan an image with PaddleOCR and save results to JSON
    
    Args:
        image_path: Path to the image file to scan
        output_dir: Directory to save OCR results (default: static/clean/ocr_output)
        
    Returns:
        Tuple of (success: bool, results: dict, error: Optional[str])
        results contains:
        - extracted_text: List of text strings
        - full_text: Combined text as single string
        - confidence_scores: List of confidence scores (0-1)
        - json_path: Path to saved JSON file
        - annotated_image_path: Path to annotated image
        - scan_timestamp: ISO timestamp
    """
    try:
        # Validate input file exists
        if not os.path.exists(image_path):
            return False, {}, f"Image file not found: {image_path}"
        
        # Set default output directory
        if output_dir is None:
            output_dir = os.path.join('static', 'clean', 'ocr_output')
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Get OCR instance
        ocr = get_ocr_instance()
        
        # Perform OCR prediction using PaddleOCR's predict API
        logger.info(f"Starting OCR scan on: {image_path}")
        result = ocr.predict(image_path)
        
        # Process each result and use built-in save methods
        for res in result:
            # Print result to logs
            res.print()
            
            # Save using PaddleOCR's built-in methods
            res.save_to_img(output_dir)
            res.save_to_json(output_dir)
        
        # Find the generated JSON and image files (most recent ones)
        output_files = os.listdir(output_dir)
        json_files = [f for f in output_files if f.endswith('.json')]
        img_files = [f for f in output_files if f.endswith('.jpg') or f.endswith('.png')]
        
        # Sort by modification time to get most recent
        json_files_with_time = [(f, os.path.getmtime(os.path.join(output_dir, f))) for f in json_files]
        img_files_with_time = [(f, os.path.getmtime(os.path.join(output_dir, f))) for f in img_files]
        
        # Get most recent files
        json_path = os.path.join(output_dir, sorted(json_files_with_time, key=lambda x: x[1])[-1][0]) if json_files_with_time else None
        annotated_image_path = os.path.join(output_dir, sorted(img_files_with_time, key=lambda x: x[1])[-1][0]) if img_files_with_time else None
        
        logger.info(f"JSON output saved to: {json_path}")
        logger.info(f"Annotated image saved to: {annotated_image_path}")
        
        # Extract text and scores from the saved JSON file
        extracted_texts = []
        confidence_scores = []
        
        if json_path and os.path.exists(json_path):
            # Read the JSON file to get OCR results
            with open(json_path, 'r', encoding='utf-8') as f:
                json_data = json.load(f)
            
            # Extract text and scores from JSON
            rec_texts = json_data.get('rec_texts', [])
            rec_scores = json_data.get('rec_scores', [])
            
            logger.info(f"JSON contains {len(rec_texts)} text segments")
            
            # Filter texts by confidence (> 0.5)
            for i, text in enumerate(rec_texts):
                score = rec_scores[i] if i < len(rec_scores) else 0.0
                if text and text.strip() and score > 0.5:
                    extracted_texts.append(text.strip())
                    confidence_scores.append(float(score))
            
            logger.info(f"Extracted {len(extracted_texts)} text segments after filtering (confidence > 0.5)")
        else:
            logger.warning("JSON file not found, no text extracted")
        
        # Prepare return results
        results = {
            'extracted_text': extracted_texts,
            'full_text': ' '.join(extracted_texts),
            'confidence_scores': confidence_scores,
            'json_path': json_path,
            'annotated_image_path': annotated_image_path,
            'scan_timestamp': datetime.utcnow().isoformat(),
            'total_detections': len(extracted_texts),
            'average_confidence': sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
        }
        
        logger.info(f"OCR scan completed: {len(extracted_texts)} text segments detected")
        logger.info(f"JSON output: {json_path}")
        logger.info(f"Annotated image: {annotated_image_path}")
        
        return True, results, None
        
    except Exception as e:
        error_msg = f"OCR scan error: {str(e)}"
        logger.error(error_msg)
        import traceback
        logger.error(traceback.format_exc())
        return False, {}, error_msg


def parse_ocr_json(json_file_path: str, min_confidence: float = 0.5) -> Tuple[bool, List[str], Optional[str]]:
    """
    Parse OCR JSON output and extract text with confidence filtering
    
    Args:
        json_file_path: Path to the OCR JSON file
        min_confidence: Minimum confidence score (0-1) to include text
        
    Returns:
        Tuple of (success: bool, extracted_texts: list, error: Optional[str])
    """
    try:
        with open(json_file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
        
        # Extract text from rec_texts field
        rec_texts = data.get('rec_texts', [])
        rec_scores = data.get('rec_scores', [])
        
        # Filter out empty text and low confidence results
        extracted_text = []
        for i, text in enumerate(rec_texts):
            score = rec_scores[i] if i < len(rec_scores) else 0
            if text.strip() and score >= min_confidence:
                extracted_text.append(text.strip())
        
        logger.info(f"Parsed {len(extracted_text)} text segments from JSON")
        return True, extracted_text, None
    
    except FileNotFoundError:
        error = f"JSON file not found: {json_file_path}"
        logger.error(error)
        return False, [], error
    except json.JSONDecodeError:
        error = f"Invalid JSON format: {json_file_path}"
        logger.error(error)
        return False, [], error
    except Exception as e:
        error = f"Error parsing OCR JSON: {str(e)}"
        logger.error(error)
        return False, [], error


def validate_image_content(image_path: str, output_dir: str = None) -> Dict:
    """
    High-level function to scan an image and validate its text content
    
    Args:
        image_path: Path to image file
        output_dir: Optional output directory for OCR results
        
    Returns:
        Dict with validation results:
        - success: bool
        - has_text: bool (whether text was detected)
        - extracted_text: list of text strings
        - full_text: combined text
        - json_path: path to JSON results
        - error: error message if failed
    """
    # Perform OCR scan
    success, ocr_results, error = scan_image_with_ocr(image_path, output_dir)
    
    if not success:
        return {
            'success': False,
            'has_text': False,
            'extracted_text': [],
            'full_text': '',
            'json_path': None,
            'error': error
        }
    
    # Check if text was detected
    has_text = len(ocr_results.get('extracted_text', [])) > 0
    
    return {
        'success': True,
        'has_text': has_text,
        'extracted_text': ocr_results.get('extracted_text', []),
        'full_text': ocr_results.get('full_text', ''),
        'confidence_scores': ocr_results.get('confidence_scores', []),
        'average_confidence': ocr_results.get('average_confidence', 0),
        'total_detections': ocr_results.get('total_detections', 0),
        'json_path': ocr_results.get('json_path'),
        'annotated_image_path': ocr_results.get('annotated_image_path'),
        'scan_timestamp': ocr_results.get('scan_timestamp'),
        'error': None
    }


def scan_and_check_sensitive_content(image_path: str, output_dir: str = None) -> Dict:
    """
    Scan image with OCR and check extracted text for sensitive content
    
    Args:
        image_path: Path to image file
        output_dir: Optional output directory
        
    Returns:
        Dict with OCR results and sensitive content detection
    """
    # First, scan the image
    validation_result = validate_image_content(image_path, output_dir)
    
    if not validation_result['success']:
        return validation_result
    
    # Initialize sensitive content fields with defaults
    validation_result['has_sensitive_content'] = False
    validation_result['severity'] = 'NONE'
    validation_result['sensitive_content_check'] = None
    
    # If text was found, check for sensitive content
    if validation_result['has_text']:
        try:
            from validators_py.content_validate import check_sensitive_content
            
            full_text = validation_result['full_text']
            sensitive_check = check_sensitive_content(full_text)
            
            # Add sensitive content results
            validation_result['sensitive_content_check'] = sensitive_check
            validation_result['has_sensitive_content'] = sensitive_check.get('has_sensitive_content', False)
            validation_result['severity'] = sensitive_check.get('severity', 'NONE')
            
        except ImportError:
            logger.warning("Content validator not available, skipping sensitive content check")
        except Exception as e:
            logger.error(f"Error checking sensitive content: {str(e)}")
    
    return validation_result


def scan_image_for_text(file_path: str, output_dir: str = None) -> Tuple[bool, str, Dict]:
    """
    Simplified function to scan image for text using OCR
    
    Args:
        file_path: Path to image file
        output_dir: Output directory for OCR results
        
    Returns:
        Tuple of (has_text: bool, full_text: str, ocr_data: dict)
    """
    result = validate_image_content(file_path, output_dir)
    
    has_text = result.get('has_text', False)
    full_text = result.get('full_text', '')
    
    return has_text, full_text, result


# CLI test function (for standalone testing)
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python ocr_validate.py <image_path> [output_dir]")
        sys.exit(1)
    
    image_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None
    
    print(f"Scanning image: {image_path}")
    print("-" * 60)
    
    result = validate_image_content(image_path, output_dir)
    
    if result['success']:
        print(f"✓ OCR scan successful")
        print(f"  Text detected: {result['has_text']}")
        print(f"  Total detections: {result['total_detections']}")
        print(f"  Average confidence: {result['average_confidence']:.2%}")
        print(f"  JSON saved to: {result['json_path']}")
        print(f"  Annotated image: {result['annotated_image_path']}")
        
        if result['has_text']:
            print(f"\nExtracted text:")
            print("-" * 60)
            for i, text in enumerate(result['extracted_text'], 1):
                confidence = result['confidence_scores'][i-1] if i-1 < len(result['confidence_scores']) else 0
                print(f"  {i}. [{confidence:.2%}] {text}")
            print("-" * 60)
            print(f"\nFull text:\n{result['full_text']}")
    else:
        print(f"✗ OCR scan failed: {result['error']}")
    
    print("-" * 60)
