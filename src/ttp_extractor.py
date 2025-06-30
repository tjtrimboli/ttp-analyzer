"""
Enhanced TTP Extractor Module with improved accuracy and reduced false positives.
"""

import re
import json
import logging
from typing import Dict, List, Optional, Tuple, Set
from pathlib import Path
from datetime import datetime
import requests
from collections import defaultdict


class TTPExtractor:
    """Enhanced extractor for MITRE ATT&CK Tactics, Techniques, and Procedures."""
    
    def __init__(self, config):
        """Initialize the TTP extractor."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Load MITRE ATT&CK framework data
        self.attack_data = self._load_attack_data()
        
        # Compile regex patterns for efficient matching
        self.techniques = {}
        self.technique_id_patterns = []
        self.technique_name_patterns = []
        self._compile_patterns()
        
    def _load_attack_data(self) -> Dict:
        """Load MITRE ATT&CK framework data."""
        data_file = Path(self.config.ATTACK_DATA_FILE)
        
        if not data_file.exists():
            self.logger.error(f"ATT&CK data file not found: {data_file}")
            self.logger.error("Please run: python ttp_analyzer.py --update-attack-data")
            return self._get_default_attack_data()
        
        try:
            with open(data_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.logger.info(f"Loaded ATT&CK data from {data_file}")
                return data
        except Exception as e:
            self.logger.error(f"Failed to load ATT&CK data: {e}")
            self.logger.error("Try running: python ttp_analyzer.py --update-attack-data")
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
                },
                {
                    "type": "attack-pattern", 
                    "id": "attack-pattern--dfd7cc1d-e1d8-4394-a198-97c4cab8aa67",
                    "external_references": [{"external_id": "T1055", "source_name": "mitre-attack"}],
                    "name": "Process Injection",
                    "description": "Process injection is a method of executing arbitrary code.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "privilege-escalation"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--7bc57495-ea59-4380-be31-a64af124ef18",
                    "external_references": [{"external_id": "T1059", "source_name": "mitre-attack"}],
                    "name": "Command and Scripting Interpreter",
                    "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add",
                    "external_references": [{"external_id": "T1105", "source_name": "mitre-attack"}],
                    "name": "Ingress Tool Transfer",
                    "description": "Adversaries may transfer tools or other files from an external system into a compromised environment.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--7bc57495-ea59-4380-be31-a64af124ef19",
                    "external_references": [{"external_id": "T1083", "source_name": "mitre-attack"}],
                    "name": "File and Directory Discovery",
                    "description": "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "discovery"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--799ace7f-e227-4411-baa0-8868704f2a69",
                    "external_references": [{"external_id": "T1070", "source_name": "mitre-attack"}],
                    "name": "Indicator Removal",
                    "description": "Adversaries may delete or alter generated artifacts on a host system, including logs or captured files such as quarantined malware.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--b3d682b6-98f2-4fb0-aa3b-b4df007ca70a",
                    "external_references": [{"external_id": "T1027", "source_name": "mitre-attack"}],
                    "name": "Obfuscated Files or Information",
                    "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81",
                    "external_references": [{"external_id": "T1078", "source_name": "mitre-attack"}],
                    "name": "Valid Accounts",
                    "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--2b742742-28c3-4e1b-bab7-8350d6300fa7",
                    "external_references": [{"external_id": "T1566", "source_name": "mitre-attack"}],
                    "name": "Phishing",
                    "description": "Adversaries may send phishing messages to gain access to victim systems.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]
                }
            ]
        }
        
    def _compile_patterns(self):
        """Compile enhanced regex patterns for TTP extraction."""
        # Clear existing patterns
        self.techniques = {}
        self.technique_id_patterns = []
        self.technique_name_patterns = []
        
        # Track technique names to avoid duplicates and overly generic terms
        name_to_techniques = defaultdict(list)
        
        for obj in self.attack_data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                # Get technique ID
                technique_id = None
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        technique_id = ref.get("external_id")
                        break
                        
                if technique_id and technique_id.startswith('T'):
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
                    
                    # Create ID pattern (always high confidence)
                    id_pattern = rf'\b{re.escape(technique_id)}\b'
                    self.technique_id_patterns.append((id_pattern, technique_id, 'id'))
                    
                    # Track name for careful handling
                    if name:
                        name_to_techniques[name.lower()].append(technique_id)
        
        # Create enhanced name patterns with context requirements
        for name_lower, technique_ids in name_to_techniques.items():
            # Skip overly generic or ambiguous technique names
            if self._is_generic_name(name_lower):
                self.logger.debug(f"Skipping generic technique name: {name_lower}")
                continue
            
            if len(technique_ids) == 1:
                # Unique name - create context-aware pattern
                technique_id = technique_ids[0]
                context_pattern = self._create_context_aware_pattern(name_lower)
                if context_pattern:
                    self.technique_name_patterns.append((context_pattern, technique_id, 'name'))
            else:
                # Duplicate name - skip to avoid confusion
                self.logger.debug(f"Skipping duplicate technique name: {name_lower} -> {technique_ids}")
        
        self.logger.info(f"Compiled {len(self.technique_id_patterns)} ID patterns and "
                        f"{len(self.technique_name_patterns)} context-aware name patterns")
    
    def _is_generic_name(self, name: str) -> bool:
        """Check if a technique name is too generic and likely to cause false positives."""
        # Allow well-known MITRE technique names even if they contain generic words
        known_technique_names = {
            'process injection', 'valid accounts', 'remote services', 'web services',
            'command and scripting interpreter', 'file and directory discovery',
            'network discovery', 'system discovery', 'account discovery',
            'remote access software', 'data staged', 'data collection',
            'credential access', 'defense evasion', 'privilege escalation'
        }
        
        name_lower = name.lower()
        
        # Don't filter known technique names
        if name_lower in known_technique_names:
            return False
        
        # Check for overly generic single words or very common phrases
        overly_generic = {
            'data', 'file', 'files', 'user', 'users', 'network', 'system', 'systems',
            'access', 'remote', 'local', 'server', 'client', 'application', 'software',
            'tool', 'tools', 'script', 'scripts', 'command', 'commands',
            'registry', 'library', 'api', 'protocol', 'connection', 'communication',
            'information', 'service', 'services'
        }
        
        words = name_lower.split()
        
        # Filter out single generic words
        if len(words) == 1 and words[0] in overly_generic:
            return True
        
        # Filter out very generic two-word combinations
        if len(words) == 2:
            # Both words are overly generic
            if all(word in overly_generic for word in words):
                return True
            # Very common generic phrases
            generic_phrases = {
                'web service', 'data file', 'user account', 'network access',
                'system tool', 'remote connection', 'local service'
            }
            if name_lower in generic_phrases:
                return True
        
        # Check for very short names (but allow some short legitimate ones)
        if len(name) < 6:
            return True
        
        return False
    
    def _create_context_aware_pattern(self, technique_name: str) -> Optional[str]:
        """Create a context-aware pattern that requires MITRE ATT&CK context."""
        # Escape the technique name for regex
        escaped_name = re.escape(technique_name)
        
        # Create more flexible pattern that requires MITRE context within reasonable distance
        # Look for technique name near MITRE references, technique IDs, or threat intelligence context
        context_pattern = (
            rf'(?:'
            # MITRE context before technique name (within 50 characters)
            rf'(?:MITRE\s+ATT&CK|mitre\s+att&ck|ATT&CK|attack\.mitre\.org|technique|tactic|TTP).{{0,50}}?{escaped_name}'
            rf'|'
            # Technique name before MITRE context (within 50 characters)  
            rf'{escaped_name}.{{0,50}}?(?:MITRE\s+ATT&CK|mitre\s+att&ck|ATT&CK|attack\.mitre\.org|technique|tactic|TTP)'
            rf'|'
            # Technique ID near technique name
            rf'(?:T\d{{4}}(?:\.\d{{3}})?.{{0,30}}?{escaped_name}|{escaped_name}.{{0,30}}?T\d{{4}}(?:\.\d{{3}})?)'
            rf'|'
            # Technique name in brackets or parentheses (common in reports)
            rf'(?:\[.{{0,20}}?{escaped_name}.{{0,20}}?\]|\(.{{0,20}}?{escaped_name}.{{0,20}}?\))'
            rf'|'
            # Threat intelligence context
            rf'(?:adversar|attacker|threat\s+actor|malicious|campaign).{{0,50}}?{escaped_name}'
            rf'|'
            rf'{escaped_name}.{{0,50}}?(?:adversar|attacker|threat\s+actor|malicious|campaign)'
            rf')'
        )
        
        return context_pattern
    
    def extract_ttps(self, report_data: Dict) -> List[Dict]:
        """
        Extract TTPs from a parsed report with enhanced accuracy.
        
        Args:
            report_data: Parsed report data from ReportParser
            
        Returns:
            List of extracted TTP dictionaries
        """
        content = report_data.get('content', '')
        
        # Check if content is empty or too short
        if not content or len(content.strip()) < 30:
            self.logger.warning(f"Report content is empty or too short: {report_data.get('source', 'unknown')}")
            return []
        
        self.logger.debug(f"Extracting TTPs from {len(content)} characters of content")
        
        extracted_ttps = []
        matched_techniques = set()  # Avoid duplicates within this report
        
        # Phase 1: Search for technique IDs (highest confidence)
        id_matches = self._extract_by_technique_ids(content, report_data, matched_techniques)
        extracted_ttps.extend(id_matches)
        
        # Phase 2: Search for technique names with context validation (medium confidence)
        name_matches = self._extract_by_technique_names(content, report_data, matched_techniques)
        extracted_ttps.extend(name_matches)
        
        # Phase 3: Heuristic extraction (lower confidence, if enabled)
        if self.config.ENABLE_HEURISTIC_EXTRACTION:
            heuristic_matches = self._extract_heuristic_ttps(report_data, matched_techniques)
            extracted_ttps.extend(heuristic_matches)
        
        # Filter by confidence threshold and validate
        validated_ttps = self._validate_and_filter_ttps(extracted_ttps)
        
        # Sort by confidence (highest first)
        validated_ttps.sort(key=lambda x: x.get('confidence', 0), reverse=True)
        
        self.logger.info(f"Extracted {len(validated_ttps)} validated TTPs from report")
        
        if len(validated_ttps) == 0:
            self.logger.warning(f"No TTPs extracted from: {report_data.get('source', 'unknown')}")
            # Log a sample for debugging
            sample = content[:300] + "..." if len(content) > 300 else content
            self.logger.debug(f"Content sample: {sample}")
        
        return validated_ttps
    
    def _extract_by_technique_ids(self, content: str, report_data: Dict, matched_techniques: Set[str]) -> List[Dict]:
        """Extract TTPs by technique IDs with high confidence."""
        ttps = []
        content_lower = content.lower()
        
        for pattern, technique_id, match_type in self.technique_id_patterns:
            if technique_id in matched_techniques:
                continue
            
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            
            if matches:
                # Validate that this is actually a MITRE reference
                match = matches[0]
                context = self._get_match_context(content, match.start(), match.end())
                
                if self._validate_mitre_context(context, technique_id):
                    technique_info = self.techniques.get(technique_id, {})
                    
                    ttp = {
                        'technique_id': technique_id,
                        'technique_name': technique_info.get('name', ''),
                        'tactic': technique_info.get('tactic', 'unknown'),
                        'description': technique_info.get('description', ''),
                        'matched_text': match.group(),
                        'match_position': match.start(),
                        'confidence': self._calculate_confidence(match.group(), technique_info, match_type, context),
                        'source': report_data.get('source', ''),
                        'report_title': report_data.get('title', ''),
                        'date': self._parse_date(report_data.get('publication_date')),
                        'extracted_at': datetime.utcnow().isoformat(),
                        'match_type': match_type,
                        'match_count': len(matches),
                        'context': context[:100]  # Store context for validation
                    }
                    
                    ttps.append(ttp)
                    matched_techniques.add(technique_id)
                    self.logger.debug(f"Found technique ID: {technique_id} ({match.group()}) in context: {context[:50]}...")
                else:
                    self.logger.debug(f"Rejected technique ID {technique_id} due to invalid context: {context[:100]}...")
        
        return ttps
    
    def _extract_by_technique_names(self, content: str, report_data: Dict, matched_techniques: Set[str]) -> List[Dict]:
        """Extract TTPs by technique names with context validation."""
        ttps = []
        
        for pattern, technique_id, match_type in self.technique_name_patterns:
            if technique_id in matched_techniques:
                continue
            
            matches = list(re.finditer(pattern, content, re.IGNORECASE | re.DOTALL))
            
            if matches:
                match = matches[0]
                full_match = match.group()
                
                # Extract just the technique name from the context match
                technique_name = self.techniques[technique_id]['name']
                name_match = re.search(re.escape(technique_name), full_match, re.IGNORECASE)
                
                if name_match:
                    # Get broader context for validation
                    context = self._get_match_context(content, match.start(), match.end())
                    
                    # Additional validation for name matches
                    if self._validate_technique_name_match(context, technique_name, technique_id):
                        technique_info = self.techniques.get(technique_id, {})
                        
                        ttp = {
                            'technique_id': technique_id,
                            'technique_name': technique_info.get('name', ''),
                            'tactic': technique_info.get('tactic', 'unknown'),
                            'description': technique_info.get('description', ''),
                            'matched_text': name_match.group(),
                            'match_position': match.start() + name_match.start(),
                            'confidence': self._calculate_confidence(name_match.group(), technique_info, match_type, context),
                            'source': report_data.get('source', ''),
                            'report_title': report_data.get('title', ''),
                            'date': self._parse_date(report_data.get('publication_date')),
                            'extracted_at': datetime.utcnow().isoformat(),
                            'match_type': match_type,
                            'match_count': len(matches),
                            'context': context[:100]
                        }
                        
                        ttps.append(ttp)
                        matched_techniques.add(technique_id)
                        self.logger.debug(f"Found technique name: {technique_id} ({name_match.group()})")
        
        return ttps
    
    def _get_match_context(self, content: str, start: int, end: int, window: int = 300) -> str:
        """Get surrounding context for a match."""
        context_start = max(0, start - window)
        context_end = min(len(content), end + window)
        return content[context_start:context_end]
    
    def _validate_mitre_context(self, context: str, technique_id: str) -> bool:
        """Validate that a match is in proper MITRE ATT&CK context."""
        context_lower = context.lower()
        
        # Check for negative contexts that should reject the match
        negative_indicators = [
            'should not trigger', 'should not match', 'should not extract',
            'not a valid', 'example of', 'for example', 'such as',
            'should not be', 'avoid matching', 'prevent', 'exclude',
            'false positive', 'incorrectly identified', 'mistakenly'
        ]
        
        # Reject if in negative context
        if any(indicator in context_lower for indicator in negative_indicators):
            self.logger.debug(f"Rejecting {technique_id} due to negative context: {context_lower[:100]}")
            return False
        
        # Look for MITRE/ATT&CK indicators in context
        mitre_indicators = [
            'mitre', 'att&ck', 'attack.mitre.org', 'technique', 'tactic', 'ttp',
            'adversary', 'threat', 'cybersecurity', 'malware', 'ransomware'
        ]
        
        # Check for technique ID patterns in context
        technique_pattern = r'\bT\d{4}(?:\.\d{3})?\b'
        has_technique_ids = bool(re.search(technique_pattern, context))
        
        # Check for MITRE indicators
        has_mitre_context = any(indicator in context_lower for indicator in mitre_indicators)
        
        # Higher confidence if both conditions are met
        return has_technique_ids or has_mitre_context
    
    def _validate_technique_name_match(self, context: str, technique_name: str, technique_id: str) -> bool:
        """Additional validation for technique name matches."""
        context_lower = context.lower()
        
        # Reject matches in clearly non-MITRE contexts
        negative_indicators = [
            'product', 'company', 'brand', 'service provider', 'vendor',
            'advertisement', 'marketing', 'commercial', 'purchase', 'buy',
            'about us', 'contact us', 'privacy policy', 'terms of service',
            'should not trigger', 'should not match', 'should not extract',
            'not a valid', 'example of', 'for example', 'such as'
        ]
        
        if any(indicator in context_lower for indicator in negative_indicators):
            self.logger.debug(f"Rejecting {technique_name} due to negative context indicators")
            return False
        
        # For name matches, we already have context awareness built into the pattern,
        # so if the pattern matched, we can be more confident it's legitimate
        
        # Require some form of security/threat context for name matches
        security_indicators = [
            'mitre', 'att&ck', 'attack.mitre.org', 'technique', 'tactic', 'ttp',
            'adversary', 'attacker', 'threat actor', 'malicious', 'campaign',
            'cybersecurity', 'security', 'threat', 'analysis', 'intelligence',
            'observed', 'detected', 'employed', 'used', 'utilized', 'leveraged'
        ]
        
        has_security_context = any(indicator in context_lower for indicator in security_indicators)
        
        # Check for technique ID near the name (additional confidence)
        id_pattern = r'\bT\d{4}(?:\.\d{3})?\b'
        nearby_ids = re.findall(id_pattern, context)
        
        # Accept if we have security context OR nearby technique IDs
        return has_security_context or len(nearby_ids) > 0
    
    def _extract_heuristic_ttps(self, report_data: Dict, already_matched: Set[str]) -> List[Dict]:
        """Extract TTPs using conservative heuristic patterns."""
        content = report_data.get('content', '').lower()
        heuristic_ttps = []
        
        # More conservative heuristic patterns with better context
        heuristic_patterns = {
            'T1059': [  # Command and Scripting Interpreter
                r'(?:adversar|attacker|threat actor).*?(?:powershell|command.?line|script)',
                r'(?:malicious|suspicious).*?(?:powershell|cmd\.exe|script execution)',
                r'(?:execute|run|invoke).{0,30}(?:malicious|suspicious|adversar).*?(?:command|script)'
            ],
            'T1105': [  # Ingress Tool Transfer
                r'(?:adversar|attacker).*?(?:download|upload|transfer).{0,30}(?:tool|payload|malware)',
                r'(?:malicious|suspicious).*?(?:file transfer|tool download|payload delivery)',
                r'(?:threat actor|adversar).*?(?:wget|curl|certutil|bitsadmin)'
            ],
            'T1083': [  # File and Directory Discovery
                r'(?:adversar|attacker).*?(?:enumerate|discover|search).{0,30}(?:file|director)',
                r'(?:reconnaissance|discovery).*?(?:file system|director|folder)',
                r'(?:threat actor|malicious).*?(?:file discovery|system reconnaissance)'
            ]
        }
        
        for technique_id, patterns in heuristic_patterns.items():
            # Skip if already matched or technique doesn't exist
            if technique_id in already_matched or technique_id not in self.techniques:
                continue
            
            for pattern in patterns:
                matches = list(re.finditer(pattern, content, re.IGNORECASE | re.DOTALL))
                
                if matches:
                    match = matches[0]
                    context = self._get_match_context(report_data.get('content', ''), match.start(), match.end())
                    
                    # Additional validation for heuristic matches
                    if self._validate_heuristic_match(context, technique_id):
                        technique_info = self.techniques.get(technique_id, {})
                        
                        ttp = {
                            'technique_id': technique_id,
                            'technique_name': technique_info.get('name', f'Technique {technique_id}'),
                            'tactic': technique_info.get('tactic', 'unknown'),
                            'description': technique_info.get('description', ''),
                            'matched_text': match.group()[:50],  # Limit length
                            'match_position': match.start(),
                            'confidence': 0.4,  # Lower confidence for heuristic matches
                            'source': report_data.get('source', ''),
                            'report_title': report_data.get('title', ''),
                            'date': self._parse_date(report_data.get('publication_date')),
                            'extracted_at': datetime.utcnow().isoformat(),
                            'match_type': 'heuristic',
                            'match_count': len(matches),
                            'context': context[:100]
                        }
                        
                        heuristic_ttps.append(ttp)
                        already_matched.add(technique_id)
                        self.logger.debug(f"Found heuristic match: {technique_id}")
                        break  # Only match once per technique per report
        
        return heuristic_ttps
    
    def _validate_heuristic_match(self, context: str, technique_id: str) -> bool:
        """Validate heuristic matches more strictly."""
        context_lower = context.lower()
        
        # Require threat intelligence context for heuristic matches
        required_indicators = [
            'threat', 'adversary', 'attacker', 'malicious', 'attack', 'campaign',
            'threat actor', 'cybersecurity', 'security', 'intrusion', 'compromise'
        ]
        
        return any(indicator in context_lower for indicator in required_indicators)
    
    def _validate_and_filter_ttps(self, ttps: List[Dict]) -> List[Dict]:
        """Validate and filter TTPs to ensure quality."""
        validated_ttps = []
        
        for ttp in ttps:
            # Check confidence threshold
            if ttp.get('confidence', 0) < self.config.MIN_CONFIDENCE_THRESHOLD:
                continue
            
            # Additional validation based on match type
            if ttp.get('match_type') == 'name':
                # Stricter validation for name matches
                if not self._final_name_validation(ttp):
                    self.logger.debug(f"Rejected name match for {ttp['technique_id']}: failed final validation")
                    continue
            
            validated_ttps.append(ttp)
        
        return validated_ttps
    
    def _final_name_validation(self, ttp: Dict) -> bool:
        """Final validation for technique name matches."""
        context = ttp.get('context', '').lower()
        technique_name = ttp.get('technique_name', '').lower()
        
        # Ensure the match isn't in a clearly inappropriate context
        inappropriate_contexts = [
            'about us', 'contact', 'privacy', 'terms', 'legal', 'copyright',
            'advertisement', 'sponsor', 'product description', 'service offering'
        ]
        
        return not any(ctx in context for ctx in inappropriate_contexts)
    
    def _calculate_confidence(self, matched_text: str, technique_info: Dict, match_type: str, context: str = "") -> float:
        """Calculate enhanced confidence score for a TTP match."""
        # Base confidence by match type
        if match_type == 'id':
            confidence = 0.9  # High confidence for ID matches
        elif match_type == 'name':
            confidence = 0.6  # Lower base confidence for name matches
        else:  # heuristic
            confidence = 0.4  # Lower confidence for heuristic matches
        
        # Adjust based on context quality
        context_lower = context.lower()
        
        # Boost confidence for strong MITRE context
        if any(indicator in context_lower for indicator in ['mitre', 'att&ck', 'attack.mitre.org']):
            confidence += 0.1
        
        # Boost confidence for technique ID references in context
        if re.search(r'\bT\d{4}(?:\.\d{3})?\b', context):
            confidence += 0.05
        
        # Boost confidence for threat intelligence context
        if any(indicator in context_lower for indicator in ['threat actor', 'adversary', 'campaign', 'ttp']):
            confidence += 0.05
        
        # Reduce confidence for very short matches
        if len(matched_text) < 4:
            confidence -= 0.1
        
        # Reduce confidence for matches in potentially inappropriate contexts
        if any(indicator in context_lower for indicator in ['advertisement', 'product', 'service']):
            confidence -= 0.2
        
        # Ensure confidence is between 0 and 1
        return max(0.0, min(1.0, confidence))
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[str]:
        """Parse date string into ISO format."""
        if not date_str:
            return None
        
        date_str = date_str.strip()
        
        # Skip obviously invalid dates
        if re.match(r'^\d{3}-\d{1,2}-\d{1,2}$', date_str):
            return None
        
        # Try to parse various date formats
        date_formats = [
            '%Y-%m-%d', '%m/%d/%Y', '%d/%m/%Y', '%m-%d-%Y', '%d-%m-%Y',
            '%B %d, %Y', '%d %B %Y', '%b %d %Y', '%b %d, %Y',
            '%Y/%m/%d', '%d.%m.%Y', '%m.%d.%Y'
        ]
        
        for fmt in date_formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                if 1900 <= dt.year <= 2030:
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
