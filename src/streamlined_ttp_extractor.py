"""
Streamlined TTP Extractor - Performance-focused version
Simple regex-based extraction with MITRE ATT&CK data cross-reference.
"""

import re
import json
import logging
from typing import Dict, List, Optional, Set
from pathlib import Path
from datetime import datetime
import requests


class StreamlinedTTPExtractor:
    """Fast, efficient TTP extractor using simple regex matching."""
    
    def __init__(self, config):
        """Initialize the streamlined extractor."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Load MITRE ATT&CK data once at initialization
        self.attack_data = self._load_attack_data()
        self.techniques = self._build_technique_lookup()
        
        # Precompile regex patterns for performance
        self.technique_id_pattern = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
        
        self.logger.info(f"Loaded {len(self.techniques)} MITRE ATT&CK techniques")
    
    def _load_attack_data(self) -> Dict:
        """Load MITRE ATT&CK data from file."""
        data_file = Path(self.config.ATTACK_DATA_FILE)
        
        if not data_file.exists():
            self.logger.warning(f"ATT&CK data not found: {data_file}")
            return {"objects": []}
        
        try:
            with open(data_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load ATT&CK data: {e}")
            return {"objects": []}
    
    def _build_technique_lookup(self) -> Dict[str, Dict]:
        """Build fast lookup table for techniques."""
        techniques = {}
        
        for obj in self.attack_data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            
            # Extract technique ID
            technique_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break
            
            if not technique_id or not technique_id.startswith('T'):
                continue
            
            # Extract tactic
            tactic = "unknown"
            kill_chain_phases = obj.get("kill_chain_phases", [])
            if kill_chain_phases:
                tactic = kill_chain_phases[0].get("phase_name", "unknown")
            
            techniques[technique_id] = {
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "tactic": tactic
            }
        
        return techniques
    
    def extract_ttps(self, report_data: Dict) -> List[Dict]:
        """Extract TTPs using simple, fast regex matching."""
        content = report_data.get('content', '')
        
        if not content or len(content.strip()) < 20:
            return []
        
        # Find all technique IDs using precompiled regex
        matches = self.technique_id_pattern.finditer(content)
        
        extracted_ttps = []
        seen_techniques = set()
        
        for match in matches:
            technique_id = match.group()
            
            # Skip duplicates
            if technique_id in seen_techniques:
                continue
            
            # Cross-reference with MITRE data
            technique_info = self.techniques.get(technique_id)
            if not technique_info:
                self.logger.debug(f"Unknown technique ID: {technique_id}")
                continue
            
            # Simple confidence scoring
            confidence = self._calculate_simple_confidence(match, content)
            
            # Only include if meets minimum confidence
            if confidence < self.config.MIN_CONFIDENCE_THRESHOLD:
                continue
            
            ttp = {
                'technique_id': technique_id,
                'technique_name': technique_info['name'],
                'tactic': technique_info['tactic'],
                'description': technique_info['description'],
                'matched_text': technique_id,
                'match_position': match.start(),
                'confidence': confidence,
                'source': report_data.get('source', ''),
                'report_title': report_data.get('title', ''),
                'date': self._parse_date(report_data.get('publication_date')),
                'extracted_at': datetime.utcnow().isoformat(),
                'match_type': 'regex_id'
            }
            
            extracted_ttps.append(ttp)
            seen_techniques.add(technique_id)
        
        self.logger.debug(f"Extracted {len(extracted_ttps)} TTPs from {len(content)} chars")
        return extracted_ttps
    
    def _calculate_simple_confidence(self, match, content: str) -> float:
        """Simple confidence calculation based on context."""
        # Get context around the match
        start = max(0, match.start() - 100)
        end = min(len(content), match.end() + 100)
        context = content[start:end].lower()
        
        # Base confidence for regex ID match
        confidence = 0.8
        
        # Boost for MITRE context
        mitre_indicators = ['mitre', 'att&ck', 'attack', 'technique', 'tactic']
        for indicator in mitre_indicators:
            if indicator in context:
                confidence = min(1.0, confidence + 0.1)
                break
        
        # Boost for threat context
        threat_indicators = ['threat', 'adversary', 'attacker', 'campaign']
        for indicator in threat_indicators:
            if indicator in context:
                confidence = min(1.0, confidence + 0.05)
                break
        
        return confidence
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[str]:
        """Simple date parsing."""
        if not date_str:
            return None
        
        # Try to parse ISO format
        try:
            dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            return dt.date().isoformat()
        except:
            pass
        
        # Try common formats
        formats = ['%Y-%m-%d', '%m/%d/%Y', '%d/%m/%Y']
        for fmt in formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                if 1990 <= dt.year <= 2030:
                    return dt.date().isoformat()
            except:
                continue
        
        return None
    
    def download_attack_data(self) -> bool:
        """Download MITRE ATT&CK data."""
        try:
            self.logger.info("Downloading MITRE ATT&CK data...")
            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            # Save data
            data_file = Path(self.config.ATTACK_DATA_FILE)
            data_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            # Update internal data
            self.attack_data = data
            self.techniques = self._build_technique_lookup()
            
            self.logger.info(f"Downloaded {len(self.techniques)} techniques")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to download ATT&CK data: {e}")
            return False
    
    def get_all_techniques(self) -> Dict:
        """Get all loaded techniques."""
        return self.techniques.copy()
    
    def get_technique_info(self, technique_id: str) -> Optional[Dict]:
        """Get info for specific technique."""
        return self.techniques.get(technique_id)
