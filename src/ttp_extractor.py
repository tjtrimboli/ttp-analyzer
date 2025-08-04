"""
TTP Extractor - Combines the best of enhanced and streamlined approaches
Configurable performance modes: fast, balanced, comprehensive
"""

import re
import json
import logging
import requests
import time
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter


class TTPExtractor:
    """
    TTP extractor with configurable performance modes.
    
    Modes:
    - fast: Streamlined regex-only approach (highest performance)
    - balanced: Fast regex + selective name matching (recommended)
    - comprehensive: Full enhanced extraction (highest accuracy)
    """
    
    def __init__(self, config):
        """Initialize with performance mode from config."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Determine performance mode
        self.performance_mode = getattr(config, 'PERFORMANCE_MODE', 'balanced').lower()
        if self.performance_mode not in ['fast', 'balanced', 'comprehensive']:
            self.logger.warning(f"Invalid performance mode '{self.performance_mode}', using 'balanced'")
            self.performance_mode = 'balanced'
        
        self.logger.info(f"Initializing TTP extractor in '{self.performance_mode}' mode")
        
        # Performance tracking
        start_time = time.time()
        
        # Load MITRE data efficiently
        self.techniques = {}
        self.technique_ids = set()
        self._load_mitre_data()
        
        # Compile patterns based on performance mode
        self._compile_patterns()
        
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
            with open(data_file, 'r', encoding='utf-8') as f:
                raw_data = json.load(f)
            
            techniques = {}
            technique_ids = set()
            
            for obj in raw_data.get("objects", []):
                if obj.get("type") != "attack-pattern":
                    continue
                
                technique_id = self._extract_technique_id(obj)
                if not technique_id:
                    continue
                
                # Store data with appropriate detail level based on mode
                if self.performance_mode == 'fast':
                    # Minimal data for speed
                    techniques[technique_id] = {
                        "name": obj.get("name", ""),
                        "tactic": self._extract_primary_tactic(obj)
                    }
                else:
                    # More complete data for enhanced modes
                    techniques[technique_id] = {
                        "name": obj.get("name", ""),
                        "tactic": self._extract_primary_tactic(obj),
                        "description": obj.get("description", "")[:200]  # Truncate for memory
                    }
                
                technique_ids.add(technique_id)
            
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
    
    def _compile_patterns(self):
        """Compile patterns based on performance mode."""
        # Always compile basic ID patterns (used in all modes)
        self.technique_id_pattern = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
        
        # Compile name patterns for balanced/comprehensive modes
        self.technique_name_patterns = []
        if self.performance_mode in ['balanced', 'comprehensive']:
            self._compile_name_patterns()
        
        # Compile heuristic patterns for comprehensive mode
        self.heuristic_patterns = {}
        if self.performance_mode == 'comprehensive':
            self._compile_heuristic_patterns()
    
    def _compile_name_patterns(self):
        """Compile technique name patterns for enhanced matching."""
        # Filter technique names to avoid ambiguous ones
        name_frequency = Counter(info['name'].lower() for info in self.techniques.values())
        
        for technique_id, info in self.techniques.items():
            name = info.get('name', '')
            if not name or len(name) < 4:
                continue
            
            # Skip ambiguous names in balanced mode, allow in comprehensive
            if self.performance_mode == 'balanced' and name_frequency[name.lower()] > 1:
                continue
            
            # Apply smart filtering
            if self._should_include_technique_name(name):
                pattern = self._create_context_pattern(name, technique_id)
                if pattern:
                    self.technique_name_patterns.append((pattern, technique_id, name))
    
    def _should_include_technique_name(self, name: str) -> bool:
        """Smart filtering for technique names."""
        name_lower = name.lower().strip()
        
        # Skip very short names
        if len(name) < 4:
            return False
        
        # In balanced mode, be more selective
        if self.performance_mode == 'balanced':
            # Skip single generic words
            words = name_lower.split()
            if len(words) == 1:
                generic_single = {'data', 'file', 'user', 'access', 'network', 'system'}
                return words[0] not in generic_single
            
            # Skip very generic combinations
            very_generic = {'data file', 'user access', 'file access'}
            return name_lower not in very_generic
        
        # Comprehensive mode is more permissive
        return True
    
    def _create_context_pattern(self, technique_name: str, technique_id: str) -> Optional[str]:
        """Create context-aware pattern for technique names."""
        escaped_name = re.escape(technique_name)
        
        if self.performance_mode == 'balanced':
            # Simpler patterns for balanced mode
            patterns = [
                rf'(?:MITRE|ATT&CK|T\d{{4}}).{{0,50}}?{escaped_name}',
                rf'{escaped_name}.{{0,50}}?(?:MITRE|ATT&CK|T\d{{4}})',
                rf'(?:technique|tactic|adversar|threat).{{0,50}}?{escaped_name}',
            ]
        else:
            # More comprehensive patterns for comprehensive mode
            patterns = [
                rf'(?:MITRE\s+ATT&CK|attack\.mitre\.org).{{0,75}}?{escaped_name}',
                rf'(?:T\d{{4}}(?:\.\d{{3}})?.{{0,50}}?{escaped_name}|{escaped_name}.{{0,50}}?T\d{{4}})',
                rf'(?:technique|tactic|TTP|adversar|attacker|threat\s+actor).{{0,75}}?{escaped_name}',
                rf'(?:observed|detected|employed|used|utilized).{{0,50}}?{escaped_name}',
            ]
        
        return '|'.join(f'(?:{pattern})' for pattern in patterns)
    
    def _compile_heuristic_patterns(self):
        """Compile heuristic patterns for comprehensive mode."""
        self.heuristic_patterns = {
            'T1059': [  # Command and Scripting Interpreter
                r'(?:adversar|attacker|threat\s+actor|malicious).{0,50}(?:powershell|command.line|script|cmd\.exe)',
                r'(?:execute|execution|run|invoke).{0,30}(?:malicious|suspicious).{0,30}(?:command|script)',
            ],
            'T1105': [  # Ingress Tool Transfer
                r'(?:adversar|attacker|threat\s+actor).{0,50}(?:download|upload|transfer|deploy).{0,30}(?:tool|payload|malware)',
                r'(?:malicious|suspicious).{0,30}(?:file\s+transfer|tool\s+download)',
            ],
            'T1566': [  # Phishing
                r'(?:adversar|attacker|threat\s+actor).{0,50}(?:phishing|spear.?phishing|malicious\s+email)',
                r'(?:campaign|operation|attack).{0,50}(?:phishing\s+email|malicious\s+attachment)',
            ]
        }
    
    def extract_ttps(self, report_data: Dict) -> List[Dict]:
        """Extract TTPs using the configured performance mode."""
        content = report_data.get('content', '')
        
        if not content or len(content.strip()) < 20:
            self.logger.debug("Content too short for extraction")
            return []
        
        extracted_ttps = []
        matched_techniques = set()
        
        # Phase 1: Always do fast ID extraction (core of all modes)
        id_matches = self._extract_technique_ids(content, report_data, matched_techniques)
        extracted_ttps.extend(id_matches)
        
        # Phase 2: Name extraction for balanced/comprehensive modes
        if self.performance_mode in ['balanced', 'comprehensive']:
            name_matches = self._extract_technique_names(content, report_data, matched_techniques)
            extracted_ttps.extend(name_matches)
        
        # Phase 3: Heuristic extraction for comprehensive mode only
        if self.performance_mode == 'comprehensive' and self.config.ENABLE_HEURISTIC_EXTRACTION:
            heuristic_matches = self._extract_heuristics(content, report_data, matched_techniques)
            extracted_ttps.extend(heuristic_matches)
        
        # Apply appropriate validation
        validated_ttps = self._validate_extractions(extracted_ttps)
        
        # Sort by confidence
        validated_ttps.sort(key=lambda x: x.get('confidence', 0), reverse=True)
        
        self.logger.debug(f"Extracted {len(validated_ttps)} TTPs in {self.performance_mode} mode")
        return validated_ttps
    
    def _extract_technique_ids(self, content: str, report_data: Dict, matched_techniques: Set[str]) -> List[Dict]:
        """Fast technique ID extraction (used in all modes)."""
        ttps = []
        matches = list(self.technique_id_pattern.finditer(content))
        
        if not matches:
            return ttps
        
        for match in matches:
            technique_id = match.group()
            
            if technique_id in matched_techniques:
                continue
            
            technique_info = self.techniques.get(technique_id)
            if not technique_info:
                continue
            
            # Fast confidence calculation
            confidence = self._calculate_confidence(match, content, 'id')
            
            if confidence < self.config.MIN_CONFIDENCE_THRESHOLD:
                continue
            
            ttp = {
                'technique_id': technique_id,
                'technique_name': technique_info['name'],
                'tactic': technique_info['tactic'],
                'description': technique_info.get('description', ''),
                'matched_text': technique_id,
                'match_position': match.start(),
                'confidence': confidence,
                'source': report_data.get('source', ''),
                'report_title': report_data.get('title', ''),
                'date': self._parse_date(report_data.get('publication_date')),
                'extracted_at': datetime.utcnow().isoformat(),
                'match_type': 'regex_id',
                'extraction_mode': self.performance_mode
            }
            
            ttps.append(ttp)
            matched_techniques.add(technique_id)
        
        return ttps
    
    def _extract_technique_names(self, content: str, report_data: Dict, matched_techniques: Set[str]) -> List[Dict]:
        """Name-based extraction for balanced/comprehensive modes."""
        ttps = []
        
        for pattern, technique_id, technique_name in self.technique_name_patterns:
            if technique_id in matched_techniques:
                continue
            
            matches = list(re.finditer(pattern, content, re.IGNORECASE | re.DOTALL))
            if not matches:
                continue
            
            match = matches[0]  # Take first match
            
            # Find the actual technique name within the match
            name_match = re.search(re.escape(technique_name), match.group(), re.IGNORECASE)
            if not name_match:
                continue
            
            confidence = self._calculate_confidence(match, content, 'name')
            
            if confidence < self.config.MIN_CONFIDENCE_THRESHOLD:
                continue
            
            technique_info = self.techniques[technique_id]
            
            ttp = {
                'technique_id': technique_id,
                'technique_name': technique_info['name'],
                'tactic': technique_info['tactic'],
                'description': technique_info.get('description', ''),
                'matched_text': name_match.group(),
                'match_position': match.start() + name_match.start(),
                'confidence': confidence,
                'source': report_data.get('source', ''),
                'report_title': report_data.get('title', ''),
                'date': self._parse_date(report_data.get('publication_date')),
                'extracted_at': datetime.utcnow().isoformat(),
                'match_type': 'name_context',
                'extraction_mode': self.performance_mode
            }
            
            ttps.append(ttp)
            matched_techniques.add(technique_id)
            break
        
        return ttps
    
    def _extract_heuristics(self, content: str, report_data: Dict, matched_techniques: Set[str]) -> List[Dict]:
        """Heuristic extraction for comprehensive mode."""
        ttps = []
        content_lower = content.lower()
        
        for technique_id, patterns in self.heuristic_patterns.items():
            if technique_id in matched_techniques or technique_id not in self.techniques:
                continue
            
            for pattern in patterns:
                matches = list(re.finditer(pattern, content_lower, re.IGNORECASE | re.DOTALL))
                if not matches:
                    continue
                
                match = matches[0]
                
                # Require security context for heuristic matches
                context = self._get_match_context(content, match.start(), match.end())
                if not self._has_security_context(context):
                    continue
                
                technique_info = self.techniques[technique_id]
                
                ttp = {
                    'technique_id': technique_id,
                    'technique_name': technique_info['name'],
                    'tactic': technique_info['tactic'],
                    'description': technique_info.get('description', ''),
                    'matched_text': match.group()[:50],
                    'match_position': match.start(),
                    'confidence': 0.35,  # Lower confidence for heuristics
                    'source': report_data.get('source', ''),
                    'report_title': report_data.get('title', ''),
                    'date': self._parse_date(report_data.get('publication_date')),
                    'extracted_at': datetime.utcnow().isoformat(),
                    'match_type': 'heuristic',
                    'extraction_mode': self.performance_mode
                }
                
                ttps.append(ttp)
                matched_techniques.add(technique_id)
                break
        
        return ttps
    
    def _calculate_confidence(self, match, content: str, match_type: str) -> float:
        """Smart confidence calculation based on performance mode."""
        # Base confidence by match type
        if match_type == 'id':
            confidence = 0.85
        elif match_type == 'name':
            confidence = 0.6 if self.performance_mode == 'balanced' else 0.55
        else:  # heuristic
            confidence = 0.35
        
        # Fast context analysis
        if self.performance_mode in ['balanced', 'comprehensive']:
            context = self._get_match_context(content, match.start(), match.end(), 100)
            context_lower = context.lower()
            
            # Boost for MITRE context
            if any(indicator in context_lower for indicator in ['mitre', 'att&ck', 'attack.mitre.org']):
                confidence += 0.1
            
            # Boost for technique IDs in context
            if re.search(r'\bT\d{4}(?:\.\d{3})?\b', context):
                confidence += 0.05
            
            # Boost for threat context
            threat_keywords = ['threat actor', 'adversary', 'campaign', 'technique', 'tactic']
            if any(keyword in context_lower for keyword in threat_keywords):
                confidence += 0.03
        
        return min(1.0, confidence)
    
    def _get_match_context(self, content: str, start: int, end: int, window: int = 100) -> str:
        """Get surrounding context for a match."""
        context_start = max(0, start - window)
        context_end = min(len(content), end + window)
        return content[context_start:context_end]
    
    def _has_security_context(self, context: str) -> bool:
        """Check if context has security/threat indicators."""
        context_lower = context.lower()
        security_indicators = [
            'threat', 'adversary', 'attacker', 'malicious', 'attack', 'campaign',
            'cybersecurity', 'security', 'intrusion', 'compromise', 'intelligence'
        ]
        return any(indicator in context_lower for indicator in security_indicators)
    
    def _validate_extractions(self, ttps: List[Dict]) -> List[Dict]:
        """Apply validation based on performance mode."""
        if self.performance_mode == 'fast':
            # Minimal validation for speed
            return [ttp for ttp in ttps if ttp.get('confidence', 0) >= self.config.MIN_CONFIDENCE_THRESHOLD]
        
        # More thorough validation for balanced/comprehensive modes
        validated = []
        for ttp in ttps:
            if ttp.get('confidence', 0) < self.config.MIN_CONFIDENCE_THRESHOLD:
                continue
            
            # Additional validation for comprehensive mode
            if self.performance_mode == 'comprehensive':
                if not self._validate_comprehensive(ttp):
                    continue
            
            validated.append(ttp)
        
        return validated
    
    def _validate_comprehensive(self, ttp: Dict) -> bool:
        """Comprehensive validation for highest accuracy mode."""
        # Check for negative contexts
        matched_text = ttp.get('matched_text', '').lower()
        
        negative_patterns = [
            'should not', 'avoid', 'not a valid', 'false positive',
            'incorrectly identified', 'example of what not'
        ]
        
        for pattern in negative_patterns:
            if pattern in matched_text:
                return False
        
        return True
    
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
            if not self._validate_attack_data(data):
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
            self._compile_patterns()
            new_count = len(self.techniques)
            
            self.logger.info(f"Updated: {old_count} → {new_count} techniques "
                           f"(downloaded in {download_time:.1f}s)")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to download ATT&CK data: {e}")
            return False
    
    def _validate_attack_data(self, data: Dict) -> bool:
        """Basic validation of downloaded data."""
        if not isinstance(data, dict) or "objects" not in data:
            return False
        
        attack_patterns = [obj for obj in data["objects"] if obj.get("type") == "attack-pattern"]
        return len(attack_patterns) >= 100
    
    # Compatibility methods
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
        stats = {
            'performance_mode': self.performance_mode,
            'techniques_loaded': len(self.techniques),
            'technique_ids_available': len(self.technique_ids),
            'extraction_methods': ['regex_id']
        }
        
        if self.performance_mode in ['balanced', 'comprehensive']:
            stats['extraction_methods'].append('name_context')
            stats['name_patterns_compiled'] = len(self.technique_name_patterns)
        
        if self.performance_mode == 'comprehensive':
            stats['extraction_methods'].append('heuristic')
            stats['heuristic_patterns_compiled'] = len(self.heuristic_patterns)
        
        return stats
