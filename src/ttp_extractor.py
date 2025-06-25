"""
TTP Extractor Module for identifying MITRE ATT&CK techniques in threat intelligence reports.
"""

import re
import json
import logging
from typing import Dict, List, Optional, Tuple
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
        """Download MITRE ATT&CK data from official source."""
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
                    
                    # Create strict patterns for matching
                    patterns = self._create_strict_patterns(technique_id, name)
                    self.technique_patterns.extend(patterns)
                    
        self.logger.info(f"Loaded {len(self.techniques)} ATT&CK techniques")
        
    def _create_strict_patterns(self, technique_id: str, name: str) -> List[Tuple[str, str, float]]:
        """Create strict regex patterns for matching a technique."""
        patterns = []
        
        # Pattern for exact technique ID (highest confidence)
        id_pattern = rf'\b{re.escape(technique_id)}\b'
        patterns.append((id_pattern, technique_id, 0.95))
        
        # Only include technique names that are distinctive enough
        if name and len(name) > 8:  # Only longer, more specific names
            # Exact name match (case insensitive) - but only for distinctive names
            distinctive_names = [
                'spearphishing', 'powershell', 'credential dumping', 'process injection',
                'lateral movement', 'command and control', 'data exfiltration', 'privilege escalation',
                'persistence mechanism', 'defense evasion', 'discovery', 'collection'
            ]
            
            name_lower = name.lower()
            is_distinctive = any(distinctive in name_lower for distinctive in distinctive_names) or \
                           len(name.split()) >= 3  # Multi-word names are usually more distinctive
            
            if is_distinctive:
                # Exact name match
                escaped_name = re.escape(name)
                exact_pattern = rf'(?i)\b{escaped_name}\b'
                patterns.append((exact_pattern, technique_id, 0.85))
                
                # Also match if name appears in a MITRE context
                mitre_context_pattern = rf'(?i)(?:mitre|att&?ck|technique).*?\b{escaped_name}\b'
                patterns.append((mitre_context_pattern, technique_id, 0.90))
        
        return patterns
        
    def extract_ttps(self, report_data: Dict) -> List[Dict]:
        """Extract TTPs from a parsed report with very strict matching."""
        content = report_data.get('content', '')
        
        # Check if content is empty or too short
        if not content or len(content.strip()) < 100:
            self.logger.warning(f"Report content is empty or too short: {report_data.get('source', 'unknown')}")
            return []
        
        extracted_ttps = []
        matched_techniques = set()  # Avoid duplicates
        
        # Pre-process content to normalize technique IDs
        processed_content = self._preprocess_content(content)
        
        # Search for techniques using compiled patterns
        for pattern, technique_id, base_confidence in self.technique_patterns:
            if technique_id in matched_techniques:
                continue  # Skip if already matched
                
            try:
                matches = list(re.finditer(pattern, processed_content, re.IGNORECASE))
                
                if matches:
                    # Use the best match for this technique
                    best_match = max(matches, key=lambda m: len(m.group()))
                    
                    # Calculate context-aware confidence
                    final_confidence = self._calculate_confidence(
                        best_match, processed_content, technique_id, base_confidence
                    )
                    
                    # Very strict threshold - only high confidence matches
                    if final_confidence >= self.config.MIN_CONFIDENCE_THRESHOLD:
                        technique_info = self.techniques.get(technique_id, {})
                        
                        ttp = {
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
                            'match_count': len(matches)
                        }
                        
                        extracted_ttps.append(ttp)
                        matched_techniques.add(technique_id)
                        
            except re.error as e:
                self.logger.warning(f"Regex error with pattern for {technique_id}: {e}")
                continue
        
        # Additional filtering for quality
        extracted_ttps = self._filter_low_quality_matches(extracted_ttps, processed_content)
        
        # Sort by confidence (highest first)
        extracted_ttps.sort(key=lambda x: x.get('confidence', 0), reverse=True)
        
        self.logger.info(f"Extracted {len(extracted_ttps)} unique TTPs from report")
        return extracted_ttps
    
    def _preprocess_content(self, content: str) -> str:
        """Preprocess content for better matching."""
        # Normalize whitespace
        content = re.sub(r'\s+', ' ', content)
        
        # Normalize technique ID formats
        content = re.sub(r'T(\d{4})\.(\d{3})', r'T\1.\2', content)  # T1234.001
        content = re.sub(r'T(\d{4})', r'T\1', content)  # T1234
        
        return content.strip()
    
    def _calculate_confidence(self, match, content: str, technique_id: str, base_confidence: float) -> float:
        """Calculate confidence based on context and match quality."""
        confidence = base_confidence
        
        match_text = match.group().lower()
        match_start = match.start()
        match_end = match.end()
        
        # Get context around the match
        context_start = max(0, match_start - 100)
        context_end = min(len(content), match_end + 100)
        context = content[context_start:context_end].lower()
        
        # Boost for security/MITRE context
        security_indicators = [
            'mitre', 'att&ck', 'attack', 'technique', 'tactic', 'ttp', 'threat',
            'adversary', 'malware', 'campaign', 'apt', 'intrusion', 'compromise'
        ]
        
        security_context_count = sum(1 for indicator in security_indicators if indicator in context)
        if security_context_count > 0:
            confidence += min(security_context_count * 0.05, 0.15)
        
        # Penalty for very common words without security context
        common_words = ['data', 'file', 'access', 'service', 'process', 'network', 'system', 'user']
        if match_text in common_words and security_context_count == 0:
            confidence *= 0.3
        
        # Boost for technique ID matches
        if re.match(r'^t\d{4}', match_text):
            confidence += 0.1
        
        # Penalty for matches that appear to be in URLs or code
        surrounding_text = content[max(0, match_start - 20):min(len(content), match_end + 20)]
        if re.search(r'[/\\.]', surrounding_text) or 'http' in surrounding_text.lower():
            confidence *= 0.4
        
        # Penalty for very short matches
        if len(match_text) < 4:
            confidence *= 0.5
        
        return min(confidence, 1.0)
    
    def _filter_low_quality_matches(self, ttps: List[Dict], content: str) -> List[Dict]:
        """Filter out low quality matches."""
        filtered_ttps = []
        
        for ttp in ttps:
            # Skip very low confidence matches
            if ttp['confidence'] < 0.6:
                continue
            
            matched_text = ttp['matched_text'].lower()
            
            # Skip single character matches
            if len(matched_text) < 2:
                continue
            
            # Skip matches that are just numbers
            if matched_text.isdigit():
                continue
            
            # Keep technique ID matches and high-confidence name matches
            if re.match(r'^t\d{4}', matched_text) or ttp['confidence'] > 0.8:
                filtered_ttps.append(ttp)
                continue
            
            # For other matches, require security context
            match_pos = ttp['match_position']
            context_window = 200
            start_pos = max(0, match_pos - context_window)
            end_pos = min(len(content), match_pos + len(matched_text) + context_window)
            surrounding_context = content[start_pos:end_pos].lower()
            
            security_terms = [
                'mitre', 'att&ck', 'attack', 'technique', 'tactic', 'threat',
                'adversary', 'malware', 'campaign', 'apt', 'cyber'
            ]
            
            has_security_context = any(term in surrounding_context for term in security_terms)
            if has_security_context:
                filtered_ttps.append(ttp)
        
        return filtered_ttps
        
    def _parse_date(self, date_str: Optional[str]) -> Optional[str]:
        """Parse date string into ISO format with validation."""
        if not date_str:
            return None
            
        date_str = date_str.strip()
        
        # Skip obviously invalid dates
        if len(date_str) < 4:
            return None
        
        # Skip malformed dates like '925-11-11'
        if re.match(r'^\d{1,3}-\d{1,2}-\d{1,2}'
        , date_str):
            return None
        
        # Try to parse various date formats
        date_formats = [
            '%Y-%m-%d',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%m/%d/%Y',
            '%d/%m/%Y', 
            '%m-%d-%Y',
            '%d-%m-%Y',
            '%B %d, %Y',
            '%d %B %Y',
            '%b %d, %Y',
            '%b %d %Y',
            '%Y/%m/%d',
            '%d.%m.%Y',
            '%m.%d.%Y'
        ]
        
        for fmt in date_formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                # Validate the parsed date is reasonable
                if 2000 <= dt.year <= 2030:
                    return dt.date().isoformat()
            except ValueError:
                continue
        
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
