import re
import math
from typing import Dict, List, Tuple, Optional
from datetime import datetime

# y2gx: Enhanced sensitive content checker with validation, false positive reduction, and context awareness
class SensitiveContentChecker:
    """
    A comprehensive content checker that uses regex patterns to detect sensitive information
    such as NRIC, credit card numbers, phone numbers, emails, and other PII.
    """
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
        self.severity_levels = {
            'HIGH': ['nric', 'credit_card', 'ssn', 'passport', 'api_key'],
            'MEDIUM': ['phone', 'bank_account', 'driving_license', 'mac_address', 'bitcoin_address'],
            'LOW': ['email', 'postal_code', 'ip_address']
        }
        
        # Pre-compile regex patterns for performance
        self._compiled_patterns = {}
        self._compile_patterns()
        
        # False positive patterns to exclude
        self.false_positive_patterns = [
            r'\b0{4}[-\s]?0{4}[-\s]?0{4}[-\s]?0{4}\b',  # Test card 0000-0000-0000-0000
            r'\b1{4}[-\s]?1{4}[-\s]?1{4}[-\s]?1{4}\b',  # Sequential 1111-1111-1111-1111
            r'\b1234[-\s]?5678[-\s]?9012[-\s]?3456\b',  # Example card
            r'\b4111[-\s]?1111[-\s]?1111[-\s]?1111\b',  # Visa test card
            r'\b5555[-\s]?5555[-\s]?5555[-\s]?4444\b',  # MC test card
        ]
        
        # Compile false positive patterns
        self._compiled_fp_patterns = [re.compile(p, re.IGNORECASE) for p in self.false_positive_patterns]
        
        # Context indicators for test/code detection
        self.test_context_keywords = {'test', 'example', 'sample', 'demo', 'placeholder', 'dummy', 'fake'}
        self.code_context_keywords = {'const', 'var', 'let', 'function', 'def', 'class', '//', '/*', '*/'}
    
    def _initialize_patterns(self) -> Dict[str, Dict]:
        """Initialize all regex patterns for sensitive content detection"""
        return {
            'nric': {
                'pattern': r'\b[STFG]\d{7}[A-Z]\b',
                'description': 'Singapore NRIC/FIN',
                'examples': ['S1234567A', 'T9876543Z'],
                'severity': 'HIGH'
            },
            'credit_card': {
                'pattern': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
                'description': 'Credit Card Numbers (Visa, MasterCard, Amex, Discover)',
                'examples': ['4111111111111111', '5555555555554444'],
                'severity': 'HIGH'
            },
            'ssn': {
                'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
                'description': 'US Social Security Number',
                'examples': ['123-45-6789'],
                'severity': 'HIGH'
            },
            'singapore_phone': {
                'pattern': r'\b(?:\+65\s?)?[689]\d{7}\b',
                'description': 'Singapore Phone Numbers',
                'examples': ['+65 91234567', '81234567', '65551234'],
                'severity': 'MEDIUM'
            },
            'email': {
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'description': 'Email Addresses',
                'examples': ['user@example.com', 'test.email+tag@domain.org'],
                'severity': 'LOW'
            },
            'bank_account': {
                'pattern': r'\b\d{10,12}\b(?=.*(?:account|acc|bank|dbs|ocbc|uob))',
                'description': 'Bank Account Numbers',
                'examples': ['1234567890 (with context: bank account)'],
                'severity': 'MEDIUM'
            },
            'passport': {
                'pattern': r'\b[A-Z]{1,2}\d{6,9}\b',
                'description': 'Passport Numbers',
                'examples': ['A1234567', 'AB1234567'],
                'severity': 'HIGH'
            },
            'driving_license_sg': {
                'pattern': r'\b[A-Z]\d{7}[A-Z]\b(?=.*(?:license|licence|driving))',
                'description': 'Singapore Driving License',
                'examples': ['S1234567A (with context: driving license)'],
                'severity': 'MEDIUM'
            },
            'postal_code_sg': {
                'pattern': r'\b\d{6}\b(?=.*(?:postal|zip|singapore|sg))',
                'description': 'Singapore Postal Code',
                'examples': ['123456 (with context: postal code)'],
                'severity': 'LOW'
            },
            'ip_address': {
                'pattern': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                'description': 'IP Addresses',
                'examples': ['192.168.1.1', '10.0.0.1'],
                'severity': 'LOW'
            },
            'mac_address': {
                'pattern': r'\b[0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}\b',
                'description': 'MAC Addresses',
                'examples': ['00:1B:44:11:3A:B7', '00-1B-44-11-3A-B7'],
                'severity': 'MEDIUM'
            },
            'api_key': {
                'pattern': r'\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)["\'\s]*[:=]["\'\s]*[A-Za-z0-9+/=]{20,}\b',
                'description': 'API Keys and Secrets',
                'examples': ['api_key="abcdef123456789"'],
                'severity': 'HIGH'
            },
            'bitcoin_address': {
                'pattern': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-z0-9]{39,59}\b',
                'description': 'Bitcoin Addresses',
                'examples': ['1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'],
                'severity': 'MEDIUM'
            },
            # Composite patterns for cloud provider tokens
            'aws_access_key': {
                'pattern': r'\bAKIA[0-9A-Z]{16}\b',
                'description': 'AWS Access Key ID',
                'examples': ['AKIAIOSFODNN7EXAMPLE'],
                'severity': 'HIGH'
            },
            'github_token': {
                'pattern': r'\bghp_[a-zA-Z0-9]{36}\b',
                'description': 'GitHub Personal Access Token',
                'examples': ['ghp_abcdefghijklmnopqrstuvwxyz123456'],
                'severity': 'HIGH'
            },
            'slack_token': {
                'pattern': r'\bxox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}\b',
                'description': 'Slack Token',
                'examples': ['xoxb-123456789012-123456789012-abc123def456ghi789'],
                'severity': 'HIGH'
            }
        }
    
    def _compile_patterns(self):
        """Pre-compile all regex patterns for better performance"""
        for name, info in self.patterns.items():
            self._compiled_patterns[name] = re.compile(
                info['pattern'],
                re.IGNORECASE | re.MULTILINE
            )
    
    def check_content(self, text: str, strict_mode: bool = False) -> Dict:
        """
        Check text for sensitive content and return detailed results
        
        Args:
            text (str): Text content to check
            strict_mode (bool): If True, apply stricter validation and context checks
            
        Returns:
            Dict: Results containing matches, severity, and recommendations
        """
        if not text or not isinstance(text, str):
            return {
                'status': 'error',
                'message': 'Invalid input text',
                'matches': [],
                'severity': 'NONE',
                'risk_score': 0
            }
        
        matches = []
        highest_severity = 'NONE'
        risk_score = 0
        
        # Check each pattern using pre-compiled regexes
        for pattern_name, pattern_info in self.patterns.items():
            regex = self._compiled_patterns[pattern_name]
            found_matches = regex.finditer(text)
            
            for match in found_matches:
                matched_text = match.group()
                
                # Skip false positives
                if self._is_false_positive(matched_text, pattern_name):
                    continue
                
                # Validate specific patterns
                if not self._validate_pattern(matched_text, pattern_name):
                    continue
                
                # Check context in strict mode
                context_info = None
                if strict_mode:
                    context_info = self._analyze_context(text, match.start(), match.end())
                    if context_info['type'] in ['test', 'code'] and context_info['confidence'] == 'high':
                        continue  # Skip likely false positives
                
                match_info = {
                    'type': pattern_name,
                    'description': pattern_info['description'],
                    'matched_text': self._mask_sensitive_data(match.group()),
                    'original_text': match.group(),
                    'position': {
                        'start': match.start(),
                        'end': match.end()
                    },
                    'severity': pattern_info['severity'],
                    'context': self._extract_context(text, match.start(), match.end()),
                    'validated': True,  # Passed validation checks
                    'context_analysis': context_info if strict_mode else None
                }
                matches.append(match_info)
                
                # Update severity and risk score
                severity = pattern_info['severity']
                if self._is_higher_severity(severity, highest_severity):
                    highest_severity = severity
                
                risk_score += self._get_severity_score(severity)
        
        # Calculate final risk score (0-100)
        risk_score = min(risk_score * 10, 100)
        
        return {
            'status': 'success',
            'text_length': len(text),
            'matches': matches,
            'match_count': len(matches),
            'severity': highest_severity,
            'risk_score': risk_score,
            'recommendations': self._get_recommendations(matches),
            'timestamp': datetime.utcnow().isoformat(),
            'safe_for_storage': len(matches) == 0 or highest_severity == 'LOW'
        }
    
    def _mask_sensitive_data(self, text: str) -> str:
        """Mask sensitive data for safe display"""
        if len(text) <= 4:
            return '*' * len(text)
        
        # Show first 2 and last 2 characters
        return text[:2] + '*' * (len(text) - 4) + text[-2:]
    
    def _extract_context(self, text: str, start: int, end: int, window: int = 30) -> str:
        """Extract context around the matched text"""
        context_start = max(0, start - window)
        context_end = min(len(text), end + window)
        
        context = text[context_start:context_end]
        
        # Mask the sensitive part in the context
        relative_start = start - context_start
        relative_end = end - context_start
        
        masked_context = (
            context[:relative_start] + 
            '[REDACTED]' + 
            context[relative_end:]
        )
        
        return masked_context.strip()
    
    def _is_higher_severity(self, severity1: str, severity2: str) -> bool:
        """Check if severity1 is higher than severity2"""
        severity_order = {'NONE': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}
        return severity_order.get(severity1, 0) > severity_order.get(severity2, 0)
    
    def _get_severity_score(self, severity: str) -> int:
        """Get numeric score for severity level"""
        scores = {'LOW': 1, 'MEDIUM': 3, 'HIGH': 5}
        return scores.get(severity, 0)
    
    def _get_recommendations(self, matches: List[Dict]) -> List[str]:
        """Generate recommendations based on found matches"""
        recommendations = []
        
        if not matches:
            recommendations.append("✅ No sensitive content detected. Content appears safe for storage.")
            return recommendations
        
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for match in matches:
            severity_counts[match['severity']] += 1
        
        if severity_counts['HIGH'] > 0:
            recommendations.append(f"🚨 HIGH RISK: {severity_counts['HIGH']} highly sensitive items detected (NRIC, Credit Cards, etc.)")
            recommendations.append("❌ DO NOT store or transmit this content without proper encryption and authorization")
            recommendations.append("🔒 Implement data masking/tokenization before storage")
        
        if severity_counts['MEDIUM'] > 0:
            recommendations.append(f"⚠️ MEDIUM RISK: {severity_counts['MEDIUM']} moderately sensitive items detected")
            recommendations.append("🛡️ Consider additional security measures and access controls")
        
        if severity_counts['LOW'] > 0:
            recommendations.append(f"ℹ️ LOW RISK: {severity_counts['LOW']} potentially sensitive items detected")
            recommendations.append("📝 Review and consider if this information is necessary")
        
        recommendations.append("🔍 Manual review recommended before processing")
        
        return recommendations
    
    def get_pattern_info(self) -> Dict:
        """Get information about all available patterns"""
        pattern_info = {}
        for name, info in self.patterns.items():
            pattern_info[name] = {
                'description': info['description'],
                'severity': info['severity'],
                'examples': info.get('examples', [])
            }
        return pattern_info
    
    def validate_luhn(self, card_number: str) -> bool:
        """Validate credit card number using Luhn algorithm"""
        def luhn_checksum(card_num):
            def digits_of(n):
                return [int(d) for d in str(n)]
            digits = digits_of(card_num)
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(digits_of(d*2))
            return checksum % 10
        
        return luhn_checksum(card_number.replace(' ', '').replace('-', '')) == 0
    
    def _validate_nric_checksum(self, nric: str) -> bool:
        """Validate Singapore NRIC/FIN using checksum algorithm"""
        if len(nric) != 9:
            return False
        
        try:
            weights = [2, 7, 6, 5, 4, 3, 2]
            prefix = nric[0].upper()
            digits = [int(d) for d in nric[1:8]]
            checksum = nric[8].upper()
            
            # ST checksums (for Singapore Citizens/PRs born before 2000)
            st_checks = ['J', 'Z', 'I', 'H', 'G', 'F', 'E', 'D', 'C', 'B', 'A']
            # FG checksums (for Foreigners and new format)
            fg_checks = ['X', 'W', 'U', 'T', 'R', 'Q', 'P', 'N', 'M', 'L', 'K']
            # M checksums (for 21st century births)
            m_checks = ['K', 'L', 'J', 'N', 'P', 'Q', 'R', 'T', 'U', 'W', 'X']
            
            total = sum(w * d for w, d in zip(weights, digits))
            
            if prefix in ['S', 'T']:
                return checksum == st_checks[total % 11]
            elif prefix in ['F', 'G']:
                total += 4
                return checksum == fg_checks[total % 11]
            elif prefix == 'M':
                total += 3
                return checksum == m_checks[total % 11]
            
            return False
        except (ValueError, IndexError):
            return False
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy to detect high-entropy strings (API keys, tokens)"""
        if not text:
            return 0
        
        # Count character frequencies
        frequencies = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        length = len(text)
        for count in frequencies.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _is_false_positive(self, text: str, pattern_type: str) -> bool:
        """Check if match is likely a false positive"""
        # Check against known false positive patterns
        for fp_pattern in self._compiled_fp_patterns:
            if fp_pattern.search(text):
                return True
        
        # Pattern-specific checks
        if pattern_type == 'credit_card':
            # Exclude cards with all same digits
            clean_num = text.replace(' ', '').replace('-', '')
            if len(set(clean_num)) == 1:
                return True
            
            # Exclude sequential patterns (123456789, 987654321)
            sequential_count = 0
            for i in range(len(clean_num) - 1):
                if clean_num[i].isdigit() and clean_num[i+1].isdigit():
                    if abs(int(clean_num[i+1]) - int(clean_num[i])) == 1:
                        sequential_count += 1
            if sequential_count > len(clean_num) * 0.6:  # >60% sequential
                return True
        
        if pattern_type == 'ssn':
            # Exclude obviously fake SSNs
            parts = text.split('-')
            if parts[0] == '000' or parts[0] == '666' or int(parts[0]) >= 900:
                return True
            if parts[1] == '00' or parts[2] == '0000':
                return True
        
        if pattern_type == 'ip_address':
            # Validate IP address ranges
            try:
                octets = [int(x) for x in text.split('.')]
                if any(octet > 255 for octet in octets):
                    return True
            except ValueError:
                return True
        
        return False
    
    def _validate_pattern(self, text: str, pattern_type: str) -> bool:
        """Validate matched pattern using algorithm-specific checks"""
        if pattern_type == 'credit_card':
            # Use Luhn algorithm
            return self.validate_luhn(text)
        
        if pattern_type == 'nric':
            # Use NRIC checksum validation
            return self._validate_nric_checksum(text)
        
        if pattern_type in ['api_key', 'aws_access_key', 'github_token']:
            # Check entropy for high-randomness tokens
            entropy = self._calculate_entropy(text)
            return entropy > 4.0  # High entropy indicates real token
        
        # Default: accept the match
        return True
    
    def _analyze_context(self, text: str, start: int, end: int) -> Dict:
        """Analyze surrounding context to reduce false positives"""
        # Get words before and after the match
        context_window = 100
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        
        words_before = text[context_start:start].lower().split()[-10:]
        words_after = text[end:context_end].lower().split()[:10]
        
        all_context = words_before + words_after
        
        # Check for test/example context
        test_indicators = sum(1 for word in all_context if word in self.test_context_keywords)
        if test_indicators >= 2:
            return {'type': 'test', 'confidence': 'high'}
        elif test_indicators == 1:
            return {'type': 'test', 'confidence': 'medium'}
        
        # Check for code context
        code_indicators = sum(1 for word in all_context if word in self.code_context_keywords)
        if code_indicators >= 2:
            return {'type': 'code', 'confidence': 'high'}
        elif code_indicators == 1:
            return {'type': 'code', 'confidence': 'medium'}
        
        return {'type': 'real', 'confidence': 'high'}

def create_content_scanning_middleware():
    """Create middleware function for automatic content scanning"""
    
    def scan_user_content(content_type, content_text, user_id=None, additional_context=None):
        """
        Scan user-generated content and return safety assessment
        
        Args:
            content_type (str): Type of content ('ticket', 'message', 'post', etc.)
            content_text (str): The text content to scan
            user_id (int): Optional user ID for logging
            additional_context (dict): Additional context for classification
            
        Returns:
            dict: Safety assessment with recommendations
        """
        try:
            checker = SensitiveContentChecker()
            results = checker.check_content(content_text)
            
            # Add content-specific logic
            assessment = {
                'safe_to_process': True,
                'requires_review': False,
                'block_content': False,
                'classification_required': 'public',
                'warnings': [],
                'redacted_content': content_text,
                'original_results': results
            }
            
            if results['match_count'] > 0:
                if results['severity'] == 'HIGH':
                    assessment['safe_to_process'] = False
                    assessment['requires_review'] = True
                    assessment['block_content'] = True  # Block high-risk content
                    assessment['classification_required'] = 'secret'
                    assessment['warnings'].append(f"HIGH RISK: Contains {results['match_count']} highly sensitive items")
                    
                elif results['severity'] == 'MEDIUM':
                    assessment['requires_review'] = True
                    assessment['classification_required'] = 'confidential'
                    assessment['warnings'].append(f"MEDIUM RISK: Contains {results['match_count']} moderately sensitive items")
                    
                elif results['severity'] == 'LOW':
                    assessment['classification_required'] = 'internal'
                    assessment['warnings'].append(f"LOW RISK: Contains {results['match_count']} potentially sensitive items")
                
                # Create redacted version for logs
                redacted_text = content_text
                for match in results['matches']:
                    redacted_text = redacted_text.replace(
                        match['original_text'], 
                        '[REDACTED]'
                    )
                assessment['redacted_content'] = redacted_text
            
            return assessment
            
        except Exception as e:
            # On error, err on the side of caution
            return {
                'safe_to_process': False,
                'requires_review': True,
                'block_content': False,
                'classification_required': 'internal',
                'warnings': [f'Content scan failed: {str(e)}'],
                'redacted_content': '[CONTENT SCAN FAILED]',
                'original_results': {'status': 'error', 'message': str(e)}
            }
    
    return scan_user_content

# Convenience function for quick checks
def check_sensitive_content(text: str) -> Dict:
    """Quick function to check for sensitive content"""
    checker = SensitiveContentChecker()
    return checker.check_content(text)

# Create the middleware instance
content_scanner = create_content_scanning_middleware()

# Export for use in other modules
__all__ = ['SensitiveContentChecker', 'check_sensitive_content', 'content_scanner', 'create_content_scanning_middleware']