"""
Unified Streamlined TTP Extractor
Combines all optimizations into a single, clean component.
"""

import re
import json
import logging
import requests
import time
from typing import Dict, List, Optional, Set
from pathlib import Path
from datetime import datetime

class StreamlinedTTPExtractor:
    """
    Unified high-performance TTP extractor with optimized MITRE data loading.
    
    Combines:
    - Fast local JSON data loading
    - Precompiled regex patterns
    - Simple confidence scoring
    - Minimal overhead processing
    """
    
    def __init__(self, config):
        """Initialize with optimized data loading."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Performance tracking
        start_time = time.time()
        
        # Load MITRE data efficiently
        self.techniques = {}
        self.technique_ids = set()
        self._load_mitre_data()
        
        # Precompile regex for maximum speed
        self.technique_id_pattern = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
        
        load_time = time.time() - start_time
        self.logger.info(f"Loaded {len(self.techniques)} techniques in {load_time:.3f}s")
    
    def _load_mitre_data(self):
        """Load MITRE ATT&CK data with optimized parsing."""
        data_file = Path(self.config.ATTACK_DATA_FILE)
        
        if not data_file.exists():
            self.logger.warning(f"ATT&CK data not found: {data_file}")
            self.logger.warning("Run --update-attack-data to download")
            return
        
        try:
            # Fast JSON loading
            with open(data_file, 'r', encoding='utf-8') as f:
                raw_data = json.load(f)
            
            # Optimized technique extraction
            techniques = {}
            technique_ids = set()
            
            for obj in raw_data.get("objects", []):
                if obj.get("type") != "attack-pattern":
                    continue
                
                # Extract technique ID efficiently
                technique_id = self._extract_technique_id(obj)
                if not technique_id:
                    continue
                
                # Store minimal required data
                techniques[technique_id] = {
                    "name": obj.get("name", ""),
                    "tactic": self._extract_primary_tactic(obj),
                    "description": obj.get("description", "")[:150]  # Truncate for memory
                }
                
                technique_ids.add(technique_id)
            
            # Atomic update
            self.techniques = techniques
            self.technique_ids = technique_ids
            
        except Exception as e:
            self.logger.error(f"Failed to load ATT&CK data: {e}")
    
    def _extract_technique_id(self, obj: Dict) -> Optional[str]:
        """Fast technique ID extraction."""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                if technique_id and technique_id.startswith('T'):
                    return technique_id
        return None
    
    def _extract_primary_tactic(self, obj: Dict) -> str:
        """Extract primary tactic efficiently."""
        phases = obj.get("kill_chain_phases", [])
        if phases:
            return phases[0].get("phase_name", "unknown")
        return "unknown"
    
    def extract_ttps(self, report_data: Dict) -> List[Dict]:
        """Extract TTPs using optimized regex matching and MITRE lookup."""
        content = report_data.get('content', '')
        
        if not content or len(content.strip()) < 20:
            self.logger.debug("Content too short for extraction")
            return []
        
        # Find all technique IDs using precompiled regex
        matches = list(self.technique_id_pattern.finditer(content))
        
        if not matches:
            self.logger.debug("No technique ID patterns found")
            return []
        
        self.logger.debug(f"Found {len(matches)} potential technique IDs")
        
        extracted_ttps = []
        seen_techniques = set()
        
        for match in matches:
            technique_id = match.group()
            
            # Skip duplicates
            if technique_id in seen_techniques:
                continue
            
            # Fast lookup in technique database
            technique_info = self.techniques.get(technique_id)
            if not technique_info:
                self.logger.debug(f"Unknown technique ID: {technique_id}")
                continue
            
            # Simple confidence scoring
            confidence = self._calculate_confidence(match, content)
            
            # Apply confidence threshold
            if confidence < self.config.MIN_CONFIDENCE_THRESHOLD:
                self.logger.debug(f"Low confidence for {technique_id}: {confidence:.2f}")
                continue
            
            # Create TTP record
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
                'match_type': 'regex_id_unified'
            }
            
            extracted_ttps.append(ttp)
            seen_techniques.add(technique_id)
            
            self.logger.debug(f"Extracted {technique_id}: {technique_info['name']} (conf: {confidence:.2f})")
        
        self.logger.debug(f"Final extraction: {len(extracted_ttps)} TTPs from {len(content)} chars")
        return extracted_ttps
    
    def _calculate_confidence(self, match, content: str) -> float:
        """Fast confidence calculation based on context."""
        # Get context around match
        start = max(0, match.start() - 100)
        end = min(len(content), match.end() + 100)
        context = content[start:end].lower()
        
        # Base confidence for regex ID match
        confidence = 0.8
        
        # Context boosts
        mitre_indicators = ['mitre', 'att&ck', 'attack', 'technique', 'tactic']
        if any(indicator in context for indicator in mitre_indicators):
            confidence += 0.1
        
        threat_indicators = ['threat', 'adversary', 'attacker', 'campaign']
        if any(indicator in context for indicator in threat_indicators):
            confidence += 0.05
        
        analysis_indicators = ['analysis', 'observed', 'employed', 'used']
        if any(indicator in context for indicator in analysis_indicators):
            confidence += 0.03
        
        return min(1.0, confidence)
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[str]:
        """Simple date parsing."""
        if not date_str:
            return None
        
        # Try ISO format first
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
        """Download fresh MITRE ATT&CK data."""
        try:
            self.logger.info("Downloading MITRE ATT&CK data...")
            
            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            
            start_time = time.time()
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            download_time = time.time() - start_time
            
            # Validate data
            data = response.json()
            if not self._validate_data(data):
                return False
            
            # Save atomically
            data_file = Path(self.config.ATTACK_DATA_FILE)
            data_file.parent.mkdir(parents=True, exist_ok=True)
            
            temp_file = data_file.with_suffix('.tmp')
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            temp_file.replace(data_file)
            
            # Reload data
            old_count = len(self.techniques)
            self._load_mitre_data()
            new_count = len(self.techniques)
            
            self.logger.info(f"Updated: {old_count} → {new_count} techniques "
                           f"(downloaded in {download_time:.1f}s)")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to download ATT&CK data: {e}")
            return False
    
    def _validate_data(self, data: Dict) -> bool:
        """Basic validation of downloaded data."""
        if not isinstance(data, dict):
            return False
        
        objects = data.get("objects", [])
        if not isinstance(objects, list):
            return False
        
        # Check for reasonable number of attack patterns
        attack_patterns = [obj for obj in objects if obj.get("type") == "attack-pattern"]
        if len(attack_patterns) < 100:
            self.logger.warning(f"Suspiciously few attack patterns: {len(attack_patterns)}")
            return False
        
        return True
    
    # Compatibility methods for existing code
    def get_all_techniques(self) -> Dict:
        """Get all loaded techniques."""
        return self.techniques.copy()
    
    def get_technique_info(self, technique_id: str) -> Optional[Dict]:
        """Get info for specific technique."""
        return self.techniques.get(technique_id)
    
    def technique_exists(self, technique_id: str) -> bool:
        """Check if technique exists."""
        return technique_id in self.technique_ids
    
    def get_techniques_by_tactic(self, tactic: str) -> Dict:
        """Get techniques filtered by tactic."""
        return {
            tid: info for tid, info in self.techniques.items()
            if info.get('tactic') == tactic
        }
    
    def get_performance_stats(self) -> Dict:
        """Get performance statistics."""
        return {
            'techniques_loaded': len(self.techniques),
            'technique_ids_available': len(self.technique_ids),
            'memory_estimate_mb': (len(self.techniques) * 100) / (1024 * 1024),  # Rough estimate
            'extraction_method': 'regex_id_unified',
            'data_source': 'local_json_optimized'
        }
