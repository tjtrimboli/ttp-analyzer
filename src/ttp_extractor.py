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
            return self._download_attack_data()
        
        try:
            with open(data_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load ATT&CK data: {e}")
            return self._get_default_attack_data()
            
    def _download_attack_data(self) -> Dict:
        """Download MITRE ATT&CK data from official source."""
        try:
            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            # Save for future use
            data_file = Path(self.config.ATTACK_DATA_FILE)
            data_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
                
            self.logger.info("ATT&CK data downloaded successfully")
            return data
            
        except Exception as e:
            self.logger.error(f"Failed to download ATT&CK data: {e}")
            return self._get_default_attack_data()
            
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
                # Add more default techniques as needed
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
        
    def _create_technique_patterns(self, technique_id: str, name: str) -> List[Tuple[str, str]]:
        """Create regex patterns for matching a technique."""
        patterns = []
        
        # Pattern for technique ID (e.g., T1566.001)
        id_pattern = rf'\b{re.escape(technique_id)}\b'
        patterns.append((id_pattern, technique_id))
        
        # Pattern for technique name (case insensitive)
        if name:
            # Split name into words and create flexible pattern
            words = re.findall(r'\b\w+\b', name.lower())
            if words:
                # Exact name match
                name_pattern = rf'\b{re.escape(name.lower())}\b'
                patterns.append((name_pattern, technique_id))
                
                # Partial name matches for longer names
                if len(words) > 1:
                    # Match any 2+ consecutive words
                    for i in range(len(words) - 1):
                        partial = ' '.join(words[i:i+2])
                        partial_pattern = rf'\b{re.escape(partial)}\b'
                        patterns.append((partial_pattern, technique_id))
        
        return patterns
        
    def extract_ttps(self, report_data: Dict) -> List[Dict]:
        """
        Extract TTPs from a parsed report.
        
        Args:
            report_data: Parsed report data from ReportParser
            
        Returns:
            List of extracted TTP dictionaries
        """
        content = report_data.get('content', '')
        content_lower = content.lower()
        
        extracted_ttps = []
        matched_techniques = set()  # Avoid duplicates
        
        # Search for techniques using compiled patterns
        for pattern, technique_id in self.technique_patterns:
            matches = re.finditer(pattern, content_lower, re.IGNORECASE)
            
            for match in matches:
                if technique_id not in matched_techniques:
                    technique_info = self.techniques.get(technique_id, {})
                    
                    ttp = {
                        'technique_id': technique_id,
                        'technique_name': technique_info.get('name', ''),
                        'tactic': technique_info.get('tactic', 'unknown'),
                        'description': technique_info.get('description', ''),
                        'matched_text': match.group(),
                        'match_position': match.start(),
                        'confidence': self._calculate_confidence(match.group(), technique_info),
                        'source': report_data.get('source', ''),
                        'report_title': report_data.get('title', ''),
                        'date': self._parse_date(report_data.get('publication_date')),
                        'extracted_at': datetime.utcnow().isoformat()
                    }
                    
                    extracted_ttps.append(ttp)
                    matched_techniques.add(technique_id)
        
        # Additional heuristic-based extraction
        heuristic_ttps = self._extract_heuristic_ttps(report_data)
        extracted_ttps.extend(heuristic_ttps)
        
        self.logger.info(f"Extracted {len(extracted_ttps)} TTPs from report")
        return extracted_ttps
        
    def _extract_heuristic_ttps(self, report_data: Dict) -> List[Dict]:
        """Extract TTPs using heuristic patterns for common attack behaviors."""
        content = report_data.get('content', '').lower()
        heuristic_ttps = []
        
        # Define heuristic patterns for common attack behaviors
        heuristic_patterns = {
            'T1059': [  # Command and Scripting Interpreter
                r'\b(powershell|cmd\.exe|command line|shell|bash|script)\b',
                r'\b(execute|run|invoke).{0,20}(command|script|powershell|cmd)\b'
            ],
            'T1105': [  # Ingress Tool Transfer
                r'\b(download|upload|transfer|retrieve).{0,20}(tool|payload|file)\b',
                r'\b(wget|curl|certutil|bitsadmin)\b'
            ],
            'T1083': [  # File and Directory Discovery
                r'\b(enumerate|list|discover).{0,20}(file|director|folder)\b',
                r'\b(dir|ls|find|search).{0,20}command\b'
            ],
            'T1070': [  # Indicator Removal on Host
                r'\b(delete|remove|clear|wipe).{0,20}(log|trace|evidence|artifact)\b',
                r'\b(anti-forensic|cover.{0,10}track)\b'
            ],
            'T1027': [  # Obfuscated Files or Information
                r'\b(obfuscat|encrypt|encod|pack|hide).{0,20}(payload|code|file)\b',
                r'\b(base64|xor|cipher|steganograph)\b'
            ]
        }
        
        for technique_id, patterns in heuristic_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                
                for match in matches:
                    technique_info = self.techniques.get(technique_id, {})
                    
                    # Only add if we haven't already matched this technique
                    if not any(ttp['technique_id'] == technique_id for ttp in heuristic_ttps):
                        ttp = {
                            'technique_id': technique_id,
                            'technique_name': technique_info.get('name', f'Technique {technique_id}'),
                            'tactic': technique_info.get('tactic', 'unknown'),
                            'description': technique_info.get('description', ''),
                            'matched_text': match.group(),
                            'match_position': match.start(),
                            'confidence': 0.6,  # Lower confidence for heuristic matches
                            'source': report_data.get('source', ''),
                            'report_title': report_data.get('title', ''),
                            'date': self._parse_date(report_data.get('publication_date')),
                            'extracted_at': datetime.utcnow().isoformat(),
                            'extraction_method': 'heuristic'
                        }
                        
                        heuristic_ttps.append(ttp)
                        break  # Only match once per technique per report
        
        return heuristic_ttps
        
    def _calculate_confidence(self, matched_text: str, technique_info: Dict) -> float:
        """Calculate confidence score for a TTP match."""
        confidence = 0.5  # Base confidence
        
        # Increase confidence for exact ID matches
        if re.match(r'T\d{4}', matched_text):
            confidence += 0.4
        
        # Increase confidence for exact name matches
        technique_name = technique_info.get('name', '').lower()
        if technique_name and matched_text.lower() == technique_name:
            confidence += 0.3
        
        # Decrease confidence for very short matches
        if len(matched_text) < 5:
            confidence -= 0.2
        
        # Ensure confidence is between 0 and 1
        return max(0.0, min(1.0, confidence))
        
    def _parse_date(self, date_str: Optional[str]) -> Optional[str]:
        """Parse date string into ISO format."""
        if not date_str:
            return None
            
        # Try to parse various date formats
        date_formats = [
            '%Y-%m-%d',
            '%m/%d/%Y',
            '%d/%m/%Y',
            '%B %d, %Y',
            '%d %B %Y',
            '%b %d %Y'
        ]
        
        for fmt in date_formats:
            try:
                dt = datetime.strptime(date_str.strip(), fmt)
                return dt.date().isoformat()
            except ValueError:
                continue
                
        # If no format matches, return the original string
        return date_str
        
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
