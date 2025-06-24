"""
TTP Extractor Module for identifying MITRE ATT&CK techniques in threat intelligence reports.
"""

import re
import json
import logging
from typing import Dict, List, Optional, Tuple, Set
from pathlib import Path
from datetime import datetime
import requests


class TTPExtractor:
    """Extractor for MITRE ATT&CK Tactics, Techniques, and Procedures."""
    
    def __init__(self, config):
        """Initialize the TTP extractor."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Load MITRE ATT&CK framework data
        self.attack_data = self._load_attack_data()
        
        # Compile regex patterns for efficient matching
        self._compile_patterns()
        
    def _load_attack_data(self) -> Dict:
        """Load MITRE ATT&CK framework data."""
        data_file = Path(self.config.ATTACK_DATA_FILE)
        
        if not data_file.exists():
            self.logger.warning(f"ATT&CK data file not found: {data_file}")
            self.logger.info("Downloading latest ATT&CK data...")
            if self.download_attack_data():
                # Reload after successful download
                with open(data_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                return self._get_default_attack_data()
        
        try:
            with open(data_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load ATT&CK data: {e}")
            return self._get_default_attack_data()

    def download_attack_data(self) -> bool:
        """
        Download MITRE ATT&CK data from official source.
        
        Returns:
            bool: True if download was successful, False otherwise
        """
        try:
            self.logger.info("Downloading MITRE ATT&CK data...")
            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            # Save for future use
            data_file = Path(self.config.ATTACK_DATA_FILE)
            data_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
                
            self.logger.info(f"ATT&CK data downloaded and saved to: {data_file}")
            
            # Update internal data and recompile patterns
            self.attack_data = data
            self._compile_patterns()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to download ATT&CK data: {e}")
            return False
            
    def _get_default_attack_data(self) -> Dict:
        """Get default ATT&CK data with common techniques."""
        return {
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--01df3350-ce05-4bdf-bdf8-0a919a66d4a8",
                    "external_references": [{"external_id": "T1566.001", "source_name": "mitre-attack"}],
                    "name": "Spearphishing Attachment",
                    "description": "Spearphishing attachment is a specific variant of spearphishing.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]
                },
                {
                    "type": "attack-pattern", 
                    "id": "attack-pattern--dfd7cc1d-e1d8-4394-a198-97c4cab8aa67",
                    "external_references": [{"external_id": "T1055", "source_name": "mitre-attack"}],
                    "name": "Process Injection",
                    "description": "Process injection is a method of executing arbitrary code.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "privilege-escalation"}]
                }
            ]
        }
        
    def _compile_patterns(self):
        """Compile regex patterns for TTP extraction."""
        # Extract techniques from ATT&CK data
        self.techniques = {}
        self.technique_patterns = []
        
        for obj in self.attack_data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                # Get technique ID
                technique_id = None
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        technique_id = ref.get("external_id")
                        break
                        
                if technique_id:
                    name = obj.get("name", "")
                    description = obj.get("description", "")
                    
                    # Get tactic
                    tactic = "unknown"
                    kill_chain_phases = obj.get("kill_chain_phases", [])
                    if kill_chain_phases:
                        tactic = kill_chain_phases[0].get("phase_name", "unknown")
                    
                    self.techniques[technique_id] = {
                        "name": name,
                        "description": description,
                        "tactic": tactic
                    }
                    
                    # Create patterns for matching
                    patterns = self._create_technique_patterns(technique_id, name)
                    self.technique_patterns.extend(patterns)
                    
        self.logger.info(f"Loaded {len(self.techniques)} ATT&CK techniques")
        
    def _create_technique_patterns(self, technique_id: str, name: str) -> List[Tuple[str, str, float]]:
        """Create regex patterns for matching a technique."""
        patterns = []
        
        # Pattern for exact technique ID (highest confidence)
        id_pattern = rf'\b{re.escape(technique_id)}\b'
        patterns.append((id_pattern, technique_id, 1.0))
        
        if name:
            # Exact name match (high confidence)
            escaped_name = re.escape(name)
            exact_name_pattern = rf'\b{escaped_name}\b'
            patterns.append((exact_name_pattern, technique_id, 0.9))
            
            # Case-insensitive exact match
            case_insensitive_pattern = rf'(?i)\b{escaped_name}\b'
            patterns.append((case_insensitive_pattern, technique_id, 0.8))
            
            # Split name into words for partial matching (only for longer names)
            words = re.findall(r'\b\w+\b', name.lower())
            if len(words) >= 2:
                # Match 3+ consecutive words from the name
                for i in range(len(words) - 2):
                    partial_words = words[i:i+3]
                    if all(len(word) > 2 for word in partial_words):  # Avoid very short words
                        partial_pattern = r'\b' + r'\s+'.join(re.escape(word) for word in partial_words) + r'\b'
                        patterns.append((f'(?i){partial_pattern}', technique_id, 0.6))
        
        return patterns
        
    def extract_ttps(self, report_data: Dict) -> List[Dict]:
        """
        Extract TTPs from a parsed report with improved accuracy.
        
        Args:
            report_data: Parsed report data from ReportParser
            
        Returns:
            List of extracted TTP dictionaries
        """
        content = report_data.get('content', '')
        
        # Check if content is empty or too short
        if not content or len(content.strip()) < 50:
            self.logger.warning(f"Report content is empty or too short: {report_data.get('source', 'unknown')}")
            return []
        
        extracted_ttps = []
        matched_techniques = {}  # Track matches per technique with best confidence
        
        # Pre-process content for better matching
        processed_content = self._preprocess_content(content)
        
        # Search for techniques using compiled patterns
        for pattern, technique_id, base_confidence in self.technique_patterns:
            try:
                matches = list(re.finditer(pattern, processed_content, re.IGNORECASE))
                
                if matches:
                    # Find the best match for this technique
                    best_match = max(matches, key=lambda m: len(m.group()))
                    
                    # Calculate context-aware confidence
                    context_confidence = self._calculate_context_confidence(
                        best_match, processed_content, technique_id
                    )
                    final_confidence = min(base_confidence * context_confidence, 1.0)
                    
                    # Only keep if confidence is above threshold
                    if final_confidence >= self.config.MIN_CONFIDENCE_THRESHOLD:
                        # Keep the highest confidence match for this technique
                        if (technique_id not in matched_techniques or 
                            final_confidence > matched_techniques[technique_id]['confidence']):
                            
                            technique_info = self.techniques.get(technique_id, {})
                            
                            matched_techniques[technique_id] = {
                                'technique_id': technique_id,
                                'technique_name': technique_info.get('name', ''),
                                'tactic': technique_info.get('tactic', 'unknown'),
                                'description': technique_info.get('description', ''),
                                'matched_text': best_match.group(),
                                'match_position': best_match.start(),
                                'confidence': final_confidence,
                                'source': report_data.get('source', ''),
                                'report_title': report_data.get('title', ''),
                                'date': self._parse_date(report_data.get('publication_date')),
                                'extracted_at': datetime.utcnow().isoformat(),
                                'match_count': len(matches),
                                'extraction_method': 'pattern'
                            }
                            
            except re.error as e:
                self.logger.warning(f"Regex error with pattern for {technique_id}: {e}")
                continue
        
        # Convert matched techniques to list
        extracted_ttps = list(matched_techniques.values())
        
        # Additional validation and filtering
        extracted_ttps = self._validate_and_filter_ttps(extracted_ttps, processed_content)
        
        # Sort by confidence (highest first)
        extracted_ttps.sort(key=lambda x: x.get('confidence', 0), reverse=True)
        
        self.logger.info(f"Extracted {len(extracted_ttps)} unique TTPs from report")
        if len(extracted_ttps) == 0:
            self.logger.warning(f"No TTPs extracted from: {report_data.get('source', 'unknown')}")
        
        return extracted_ttps
    
    def _preprocess_content(self, content: str) -> str:
        """Preprocess content for better matching."""
        # Normalize whitespace
        content = re.sub(r'\s+', ' ', content)
        
        # Remove certain formatting that might interfere with matching
        content = re.sub(r'[^\w\s.,;:!()\-]', ' ', content)
        
        # Normalize common variations
        content = re.sub(r'\bT(\d{4})\.(\d{3})\b', r'T\1.\2', content)  # Normalize technique IDs
        
        return content.strip()
    
    def _calculate_context_confidence(self, match, content: str, technique_id: str) -> float:
        """Calculate confidence based on context around the match."""
        confidence = 1.0
        
        match_text = match.group().lower()
        match_start = match.start()
        match_end = match.end()
        
        # Get context around the match (100 characters before and after)
        context_start = max(0, match_start - 100)
        context_end = min(len(content), match_end + 100)
        context = content[context_start:context_end].lower()
        
        # Boost confidence for security-related context
        security_indicators = [
            'attack', 'malware', 'threat', 'vulnerability', 'exploit', 'mitre',
            'technique', 'tactic', 'apt', 'campaign', 'adversary', 'attacker',
            'compromise', 'intrusion', 'infiltration', 'breach', 'incident'
        ]
        
        security_score = sum(1 for indicator in security_indicators if indicator in context)
        if security_score > 0:
            confidence += min(security_score * 0.1, 0.3)
        
        # Reduce confidence for very short matches (likely false positives)
        if len(match_text) < 4:
            confidence *= 0.5
        
        # Reduce confidence if match appears to be part of a URL or filename
        if re.search(r'[/\\.]', context[max(0, match_start - context_start - 10):
                                        min(len(context), match_end - context_start + 10)]):
            confidence *= 0.3
        
        # Boost confidence for technique ID matches
        if re.match(r'^T\d{4}', match_text):
            confidence += 0.2
        
        # Check if it's a common word that might be a false positive
        common_words = ['access', 'data', 'file', 'service', 'process', 'network', 'system']
        if match_text in common_words and security_score == 0:
            confidence *= 0.4
        
        return min(confidence, 1.0)
    
    def _validate_and_filter_ttps(self, ttps: List[Dict], content: str) -> List[Dict]:
        """Validate and filter TTPs to reduce false positives."""
        validated_ttps = []
        
        for ttp in ttps:
            # Skip if confidence is too low
            if ttp['confidence'] < self.config.MIN_CONFIDENCE_THRESHOLD:
                continue
            
            # Additional validation checks
            if self._is_valid_ttp_match(ttp, content):
                validated_ttps.append(ttp)
            else:
                self.logger.debug(f"Filtered out low-quality match: {ttp['technique_id']} - {ttp['matched_text']}")
        
        return validated_ttps
    
    def _is_valid_ttp_match(self, ttp: Dict, content: str) -> bool:
        """Validate if a TTP match is likely to be genuine."""
        matched_text = ttp['matched_text'].lower()
        technique_name = ttp['technique_name'].lower()
        
        # If it's a technique ID match, it's likely valid
        if re.match(r'^t\d{4}', matched_text):
            return True
        
        # If the matched text is exactly the technique name, it's likely valid
        if matched_text == technique_name:
            return True
        
        # Check for context clues around the match
        match_pos = ttp['match_position']
        context_window = 50
        start_pos = max(0, match_pos - context_window)
        end_pos = min(len(content), match_pos + len(matched_text) + context_window)
        context = content[start_pos:end_pos].lower()
        
        # Look for security-related terms in context
        security_terms = [
            'mitre', 'att&ck', 'attack', 'technique', 'tactic', 'ttp',
            'adversary', 'threat', 'malware', 'campaign'
        ]
        
        has_security_context = any(term in context for term in security_terms)
        
        # Require security context for short or common words
        if len(matched_text) < 6 or matched_text in ['data', 'file', 'access', 'service']:
            return has_security_context
        
        return True
        
    def _parse_date(self, date_str: Optional[str]) -> Optional[str]:
        """Parse date string into ISO format with improved validation."""
        if not date_str:
            return None
            
        # Clean up the date string
        date_str = date_str.strip()
        
        # Skip obviously invalid dates
        if len(date_str) < 4:
            return None
        
        # Skip malformed dates like '925-11-11' or '2-16-16'
        if re.match(r'^\d{1,3}-\d{1,2}-\d{1,2}', date_str):
            self.logger.debug(f"Skipping invalid date format: '{date_str}'")
            return None
        
        # Try to parse various date formats
        date_formats = [
            '%Y-%m-%d',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%SZ',
            '%m/%d/%Y',
            '%d/%m/%Y', 
            '%m-%d-%Y',
            '%d-%m-%Y',
            '%B %d, %Y',
            '%d %B %Y',
            '%b %d %Y',
            '%b %d, %Y',
            '%Y/%m/%d',
            '%d.%m.%Y',
            '%m.%d.%Y'
        ]
        
        for fmt in date_formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                # Validate the parsed date is reasonable (between 2000 and 2030)
                if 2000 <= dt.year <= 2030:
                    return dt.date().isoformat()
            except ValueError:
                continue
        
        # If no standard format matches, try to extract a valid date from the string
        # Look for patterns like "February 20, 2025" or "20 Feb 2025"
        date_pattern = r'(\d{1,2})\s+(January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{4})'
        match = re.search(date_pattern, date_str, re.IGNORECASE)
        if match:
            day, month, year = match.groups()
            try:
                # Convert month name to number
                month_names = {
                    'january': 1, 'february': 2, 'march': 3, 'april': 4, 'may': 5, 'june': 6,
                    'july': 7, 'august': 8, 'september': 9, 'october': 10, 'november': 11, 'december': 12,
                    'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
                    'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12
                }
                month_num = month_names.get(month.lower())
                if month_num:
                    dt = datetime(int(year), month_num, int(day))
                    if 2000 <= dt.year <= 2030:
                        return dt.date().isoformat()
            except (ValueError, TypeError):
                pass
        
        self.logger.debug(f"Could not parse date: '{date_str}'")
        return None
        
    def get_technique_info(self, technique_id: str) -> Optional[Dict]:
        """Get information about a specific technique."""
        return self.techniques.get(technique_id)
        
    def get_all_techniques(self) -> Dict:
        """Get all loaded techniques."""
        return self.techniques.copy()
        
    def get_techniques_by_tactic(self, tactic: str) -> Dict:
        """Get all techniques for a specific tactic."""
        return {
            tid: info for tid, info in self.techniques.items()
            if info.get('tactic') == tactic
        }
