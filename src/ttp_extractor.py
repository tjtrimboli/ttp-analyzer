"""
Enhanced TTP Extractor Module with improved accuracy and reduced false negatives.
This version addresses the core issues preventing accurate TTP extraction.
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
        """Initialize the enhanced TTP extractor."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Load MITRE ATT&CK framework data
        self.attack_data = self._load_attack_data()
        
        # Compile enhanced regex patterns
        self.techniques = {}
        self.technique_id_patterns = []
        self.technique_name_patterns = []
        self.sub_technique_patterns = []
        self._compile_enhanced_patterns()
        
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
            self._compile_enhanced_patterns()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to download ATT&CK data: {e}")
            return False

    def _get_default_attack_data(self) -> Dict:
        """Get comprehensive default ATT&CK data with common techniques."""
        return {
            "objects": [
                # Initial Access
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--2b742742-28c3-4e1b-bab7-8350d6300fa7",
                    "external_references": [{"external_id": "T1566", "source_name": "mitre-attack"}],
                    "name": "Phishing",
                    "description": "Adversaries may send phishing messages to gain access to victim systems.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]
                },
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
                    "id": "attack-pattern--b91c2e8d-8e75-4fcf-aed6-9cbd13e06acd",
                    "external_references": [{"external_id": "T1566.002", "source_name": "mitre-attack"}],
                    "name": "Spearphishing Link",
                    "description": "Adversaries may send spearphishing emails with a malicious link.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--54b4c251-1f0e-4eba-ba6b-dbc7a6f6f06b",
                    "external_references": [{"external_id": "T1566.004", "source_name": "mitre-attack"}],
                    "name": "Spearphishing Voice",
                    "description": "Adversaries may use voice communications to ultimately gain access to victim systems.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c",
                    "external_references": [{"external_id": "T1190", "source_name": "mitre-attack"}],
                    "name": "Exploit Public-Facing Application",
                    "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]
                },
                
                # Execution
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--7bc57495-ea59-4380-be31-a64af124ef18",
                    "external_references": [{"external_id": "T1059", "source_name": "mitre-attack"}],
                    "name": "Command and Scripting Interpreter",
                    "description": "Adversaries may abuse command and script interpreters to execute commands.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--970a3432-3053-4124-a2d8-3c245b4d3298",
                    "external_references": [{"external_id": "T1059.001", "source_name": "mitre-attack"}],
                    "name": "PowerShell",
                    "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]
                },
                
                # Persistence
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81",
                    "external_references": [{"external_id": "T1078", "source_name": "mitre-attack"}],
                    "name": "Valid Accounts",
                    "description": "Adversaries may obtain and abuse credentials of existing accounts.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "persistence"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--65f2d882-3f41-4d48-8a06-29af77ec9f90",
                    "external_references": [{"external_id": "T1136", "source_name": "mitre-attack"}],
                    "name": "Create Account",
                    "description": "Adversaries may create an account to maintain access to victim systems.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "persistence"}]
                },
                
                # Privilege Escalation  
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--dfd7cc1d-e1d8-4394-a198-97c4cab8aa67",
                    "external_references": [{"external_id": "T1055", "source_name": "mitre-attack"}],
                    "name": "Process Injection",
                    "description": "Adversaries may inject code into processes in order to evade process-based defenses.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "privilege-escalation"}]
                },
                
                # Defense Evasion
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--b3d682b6-98f2-4fb0-aa3b-b4df007ca70a",
                    "external_references": [{"external_id": "T1027", "source_name": "mitre-attack"}],
                    "name": "Obfuscated Files or Information",
                    "description": "Adversaries may attempt to make an executable or file difficult to discover.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--799ace7f-e227-4411-baa0-8868704f2a69",
                    "external_references": [{"external_id": "T1070", "source_name": "mitre-attack"}],
                    "name": "Indicator Removal",
                    "description": "Adversaries may delete or alter generated artifacts on a host system.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}]
                },
                
                # Credential Access
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--0a3ead4e-6d47-4ccb-854c-41091bf0c72c",
                    "external_references": [{"external_id": "T1003", "source_name": "mitre-attack"}],
                    "name": "OS Credential Dumping",
                    "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}]
                },
                
                # Discovery
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--7bc57495-ea59-4380-be31-a64af124ef19",
                    "external_references": [{"external_id": "T1083", "source_name": "mitre-attack"}],
                    "name": "File and Directory Discovery",
                    "description": "Adversaries may enumerate files and directories or search in specific locations.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "discovery"}]
                },
                
                # Lateral Movement
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--54a649ff-439a-41a4-9856-8d144a2551ba",
                    "external_references": [{"external_id": "T1021", "source_name": "mitre-attack"}],
                    "name": "Remote Services",
                    "description": "Adversaries may use valid accounts to log into a service specifically designed to accept remote connections.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "lateral-movement"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--01327cde-66c4-4123-bf34-5f258d59457b",
                    "external_references": [{"external_id": "T1021.001", "source_name": "mitre-attack"}],
                    "name": "Remote Desktop Protocol",
                    "description": "Adversaries may use Remote Desktop Protocol (RDP) to move laterally within a network.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "lateral-movement"}]
                },
                
                # Command and Control
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add",
                    "external_references": [{"external_id": "T1105", "source_name": "mitre-attack"}],
                    "name": "Ingress Tool Transfer",
                    "description": "Adversaries may transfer tools or other files from an external system.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--bf90d72c-c00b-45e3-b3aa-68560560d4c5",
                    "external_references": [{"external_id": "T1219", "source_name": "mitre-attack"}],
                    "name": "Remote Access Software",
                    "description": "Adversaries may use legitimate desktop support and remote access software.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}]
                },
                
                # Resource Development (newer tactics)
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--cd25c1b8-d298-4b62-9c72-d0bb1e3ef64c",
                    "external_references": [{"external_id": "T1588.006", "source_name": "mitre-attack"}],
                    "name": "Web Services",
                    "description": "Adversaries may register for web services that can be used during targeting.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "resource-development"}]
                },
                
                # Modify Authentication Process
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--f4c1826f-a322-41cd-9557-562100848c84",
                    "external_references": [{"external_id": "T1556.006", "source_name": "mitre-attack"}],
                    "name": "Multi-Factor Authentication",
                    "description": "Adversaries may disable or modify multi-factor authentication (MFA) mechanisms.",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}]
                }
            ]
        }
        
    def _compile_enhanced_patterns(self):
        """Compile enhanced regex patterns for more accurate TTP extraction."""
        # Clear existing patterns
        self.techniques = {}
        self.technique_id_patterns = []
        self.technique_name_patterns = []
        self.sub_technique_patterns = []
        
        # Track technique names for better handling
        name_frequency = defaultdict(int)
        
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
                    
                    name_frequency[name.lower()] += 1
        
        # Create enhanced patterns
        self._create_enhanced_id_patterns()
        self._create_enhanced_name_patterns(name_frequency)
        
        self.logger.info(f"Compiled {len(self.technique_id_patterns)} enhanced ID patterns and "
                        f"{len(self.technique_name_patterns)} enhanced name patterns")
    
    def _create_enhanced_id_patterns(self):
        """Create enhanced ID patterns that handle various formats better."""
        for technique_id in self.techniques.keys():
            # Create multiple pattern variations for better matching
            escaped_id = re.escape(technique_id)
            
            # Basic ID pattern (most reliable)
            basic_pattern = rf'\b{escaped_id}\b'
            self.technique_id_patterns.append((basic_pattern, technique_id, 'id_basic'))
            
            # ID in brackets/parentheses
            bracket_pattern = rf'[\[\(]{escaped_id}[\]\)]'
            self.technique_id_patterns.append((bracket_pattern, technique_id, 'id_bracket'))
            
            # ID with spaces (sometimes happens in documents)
            if '.' in technique_id:
                spaced_id = technique_id.replace('.', r'\s*\.\s*')
                spaced_pattern = rf'\b{spaced_id}\b'
                self.technique_id_patterns.append((spaced_pattern, technique_id, 'id_spaced'))
    
    def _create_enhanced_name_patterns(self, name_frequency):
        """Create enhanced name patterns with better context awareness."""
        for technique_id, info in self.techniques.items():
            name = info.get('name', '')
            if not name or len(name) < 4:
                continue
                
            # Skip if name appears multiple times (ambiguous)
            if name_frequency[name.lower()] > 1:
                self.logger.debug(f"Skipping ambiguous technique name: {name}")
                continue
                
            # Apply improved filtering
            if self._should_include_technique_name(name):
                # Create context-aware pattern
                pattern = self._create_enhanced_context_pattern(name)
                if pattern:
                    self.technique_name_patterns.append((pattern, technique_id, 'name_context'))
    
    def _should_include_technique_name(self, name: str) -> bool:
        """Improved filtering that allows more legitimate MITRE technique names."""
        name_lower = name.lower().strip()
        
        # Allow all technique names that are clearly legitimate MITRE techniques
        # This is much less restrictive than the original version
        
        # Skip only obviously problematic cases
        if len(name) < 4:
            return False
            
        # Skip single generic words only
        words = name_lower.split()
        if len(words) == 1:
            # Only filter very generic single words
            very_generic = {'data', 'file', 'user', 'access', 'network', 'system', 'tool', 'service'}
            return words[0] not in very_generic
        
        # Allow most multi-word technique names - MITRE techniques often contain common words
        # Only filter if ALL words are extremely generic
        if len(words) >= 2:
            extremely_generic_combinations = {
                'data file', 'user access', 'network service', 'system tool',
                'file access', 'data access', 'system access'
            }
            return name_lower not in extremely_generic_combinations
        
        return True
    
    def _create_enhanced_context_pattern(self, technique_name: str) -> Optional[str]:
        """Create enhanced context-aware pattern for technique names."""
        escaped_name = re.escape(technique_name)
        
        # More flexible context pattern that's less restrictive
        # Look for the technique name in various contexts that indicate MITRE references
        
        patterns = [
            # Explicit MITRE context (highest confidence)
            rf'(?:MITRE\s+ATT&CK|mitre\s+att&ck|ATT&CK|attack\.mitre\.org).{{0,100}}?{escaped_name}',
            rf'{escaped_name}.{{0,100}}?(?:MITRE\s+ATT&CK|mitre\s+att&ck|ATT&CK|attack\.mitre\.org)',
            
            # Technique ID nearby (high confidence)
            rf'(?:T\d{{4}}(?:\.\d{{3}})?.{{0,50}}?{escaped_name}|{escaped_name}.{{0,50}}?T\d{{4}}(?:\.\d{{3}})?)',
            
            # In brackets or parentheses (medium confidence)
            rf'[\[\(].{{0,30}}?{escaped_name}.{{0,30}}?[\]\)]',
            
            # Threat intelligence context (medium confidence)
            rf'(?:technique|tactic|TTP|adversar|attacker|threat\s+actor|campaign|malicious).{{0,75}}?{escaped_name}',
            rf'{escaped_name}.{{0,75}}?(?:technique|tactic|TTP|adversar|attacker|threat\s+actor|campaign|malicious)',
            
            # Security analysis context (lower confidence but still valid)
            rf'(?:observed|detected|employed|used|utilized|leveraged|implements?).{{0,50}}?{escaped_name}',
            rf'{escaped_name}.{{0,50}}?(?:was\s+observed|was\s+detected|was\s+employed|was\s+used|was\s+utilized)',
            
            # List or enumeration context
            rf'(?:includes?|such\s+as|like|including).{{0,30}}?{escaped_name}',
            rf'{escaped_name}.{{0,30}}?(?:among|and\s+other|including)',

            # Execution context (lower confidence)
            rf'(?:adversar|attacker|threat\s+actor).{{0,30}}?(?:employed|used|utilized).{{0,30}}?{escaped_name}',
            rf'{escaped_name}.{{0,30}}?(?:execution|during).{{0,30}}?(?:campaign|purposes?)'
        ]
        
        # Combine all patterns with OR
        combined_pattern = '|'.join(f'(?:{pattern})' for pattern in patterns)
        return f'(?:{combined_pattern})'

    def extract_ttps(self, report_data: Dict) -> List[Dict]:
        """Enhanced TTP extraction with improved accuracy."""
        content = report_data.get('content', '')
        
        if not content or len(content.strip()) < 20:
            self.logger.warning(f"Report content too short: {report_data.get('source', 'unknown')}")
            return []
        
        self.logger.debug(f"Extracting TTPs from {len(content)} characters of content")
        
        extracted_ttps = []
        matched_techniques = set()
        
        # Phase 1: Enhanced ID extraction
        id_matches = self._extract_enhanced_ids(content, report_data, matched_techniques)
        extracted_ttps.extend(id_matches)
        
        # Phase 2: Enhanced name extraction  
        name_matches = self._extract_enhanced_names(content, report_data, matched_techniques)
        extracted_ttps.extend(name_matches)
        
        # Phase 3: Improved heuristic extraction
        if self.config.ENABLE_HEURISTIC_EXTRACTION:
            heuristic_matches = self._extract_enhanced_heuristics(content, report_data, matched_techniques)
            extracted_ttps.extend(heuristic_matches)
        
        # Filter with improved validation
        validated_ttps = self._enhanced_validation(extracted_ttps)
        
        # Sort by confidence
        validated_ttps.sort(key=lambda x: x.get('confidence', 0), reverse=True)
        
        self.logger.info(f"Extracted {len(validated_ttps)} validated TTPs from report")
        return validated_ttps
    
    def _extract_enhanced_ids(self, content: str, report_data: Dict, matched_techniques: Set[str]) -> List[Dict]:
        """Enhanced ID extraction with better validation."""
        ttps = []
        
        for pattern, technique_id, match_type in self.technique_id_patterns:
            if technique_id in matched_techniques:
                continue
            
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            
            if matches:
                match = matches[0]  # Take first match
                context = self._get_match_context(content, match.start(), match.end())
                
                # Less restrictive validation for IDs
                if self._validate_id_match(context, technique_id):
                    technique_info = self.techniques.get(technique_id, {})
                    
                    ttp = {
                        'technique_id': technique_id,
                        'technique_name': technique_info.get('name', ''),
                        'tactic': technique_info.get('tactic', 'unknown'),
                        'description': technique_info.get('description', ''),
                        'matched_text': match.group(),
                        'match_position': match.start(),
                        'confidence': self._calculate_enhanced_confidence(match.group(), technique_info, match_type, context),
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
                    self.logger.debug(f"Found technique ID: {technique_id} via {match_type}")
        
        return ttps
    
    def _extract_enhanced_names(self, content: str, report_data: Dict, matched_techniques: Set[str]) -> List[Dict]:
        """Enhanced name extraction with improved patterns."""
        ttps = []
        
        for pattern, technique_id, match_type in self.technique_name_patterns:
            if technique_id in matched_techniques:
                continue
            
            matches = list(re.finditer(pattern, content, re.IGNORECASE | re.DOTALL))
            
            if matches:
                match = matches[0]
                technique_name = self.techniques[technique_id]['name']
                
                # Find the actual technique name within the match
                name_match = re.search(re.escape(technique_name), match.group(), re.IGNORECASE)
                
                if name_match:
                    context = self._get_match_context(content, match.start(), match.end())
                    
                    # Since we already have context in the pattern, validation is simpler
                    if self._validate_name_match(context, technique_name):
                        technique_info = self.techniques.get(technique_id, {})
                        
                        ttp = {
                            'technique_id': technique_id,
                            'technique_name': technique_info.get('name', ''),
                            'tactic': technique_info.get('tactic', 'unknown'),
                            'description': technique_info.get('description', ''),
                            'matched_text': name_match.group(),
                            'match_position': match.start() + name_match.start(),
                            'confidence': self._calculate_enhanced_confidence(name_match.group(), technique_info, match_type, context),
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
                        self.logger.debug(f"Found technique name: {technique_id} ({technique_name})")
        
        return ttps
    
    def _extract_enhanced_heuristics(self, content: str, report_data: Dict, matched_techniques: Set[str]) -> List[Dict]:
        """Enhanced heuristic extraction with better patterns."""
        ttps = []
        content_lower = content.lower()
        
        # Improved heuristic patterns with more specific context
        heuristic_patterns = {
            'T1059': [  # Command and Scripting Interpreter
                r'(?:adversar|attacker|threat\s+actor|malicious).{0,50}(?:powershell|command.line|script|cmd\.exe)',
                r'(?:execute|execution|run|invoke).{0,30}(?:malicious|suspicious).{0,30}(?:command|script|powershell)',
                r'(?:threat\s+intelligence|security\s+analysis).{0,50}(?:command.line|script\s+execution)'
            ],
            'T1105': [  # Ingress Tool Transfer
                r'(?:adversar|attacker|threat\s+actor).{0,50}(?:download|upload|transfer|deploy).{0,30}(?:tool|payload|malware|binary)',
                r'(?:malicious|suspicious).{0,30}(?:file\s+transfer|tool\s+download|payload\s+delivery)',
                r'(?:campaign|operation).{0,50}(?:wget|curl|certutil|bitsadmin)'
            ],
            'T1083': [  # File and Directory Discovery
                r'(?:adversar|attacker|threat\s+actor).{0,50}(?:enumerate|discover|search|reconnaissance).{0,30}(?:file|director|folder)',
                r'(?:reconnaissance|discovery\s+phase).{0,50}(?:file\s+system|director|folder\s+structure)',
                r'(?:threat\s+actor|campaign).{0,50}(?:file\s+discovery|system\s+reconnaissance)'
            ],
            'T1566': [  # Phishing
                r'(?:adversar|attacker|threat\s+actor).{0,50}(?:phishing|spear.?phishing|malicious\s+email)',
                r'(?:campaign|operation|attack).{0,50}(?:phishing\s+email|malicious\s+attachment|email\s+attack)',
                r'(?:initial\s+access|attack\s+vector).{0,50}(?:phishing|email.based\s+attack)'
            ]
        }
        
        for technique_id, patterns in heuristic_patterns.items():
            if technique_id in matched_techniques or technique_id not in self.techniques:
                continue
            
            for pattern in patterns:
                matches = list(re.finditer(pattern, content_lower, re.IGNORECASE | re.DOTALL))
                
                if matches:
                    match = matches[0]
                    context = self._get_match_context(content, match.start(), match.end())
                    
                    # Validate heuristic match
                    if self._validate_heuristic_match(context, technique_id):
                        technique_info = self.techniques.get(technique_id, {})
                        
                        ttp = {
                            'technique_id': technique_id,
                            'technique_name': technique_info.get('name', ''),
                            'tactic': technique_info.get('tactic', 'unknown'),
                            'description': technique_info.get('description', ''),
                            'matched_text': match.group()[:50],
                            'match_position': match.start(),
                            'confidence': 0.35,  # Lower confidence for heuristics
                            'source': report_data.get('source', ''),
                            'report_title': report_data.get('title', ''),
                            'date': self._parse_date(report_data.get('publication_date')),
                            'extracted_at': datetime.utcnow().isoformat(),
                            'match_type': 'heuristic',
                            'match_count': len(matches),
                            'context': context[:100]
                        }
                        
                        ttps.append(ttp)
                        matched_techniques.add(technique_id)
                        self.logger.debug(f"Found heuristic match: {technique_id}")
                        break
        
        return ttps
    
    def _validate_id_match(self, context: str, technique_id: str) -> bool:
        """Less restrictive validation for ID matches."""
        context_lower = context.lower()
        
        # Reject only clear negative contexts
        negative_patterns = [
            r'should\s+not\s+(?:trigger|match|extract|be)',
            r'avoid\s+(?:matching|extracting)',
            r'not\s+a\s+(?:valid|real)',
            r'false\s+positive',
            r'incorrectly\s+identified',
            r'example\s+of\s+(?:what\s+)?not\s+to'
        ]
        
        for pattern in negative_patterns:
            if re.search(pattern, context_lower):
                return False
        
        # For ID matches, we're less strict - if it looks like a MITRE ID, it probably is
        return True
    
    def _validate_name_match(self, context: str, technique_name: str) -> bool:
        """Validation for name matches - less restrictive than before."""
        context_lower = context.lower()
        
        # Reject obvious negative contexts
        negative_indicators = [
            'product', 'company', 'brand', 'vendor', 'advertisement', 'marketing',
            'about us', 'contact us', 'privacy policy', 'terms of service',
            'should not trigger', 'should not match', 'example of what not'
        ]
        
        # Only reject if clearly in wrong context
        for indicator in negative_indicators:
            if indicator in context_lower:
                return False
        
        return True
    
    def _validate_heuristic_match(self, context: str, technique_id: str) -> bool:
        """Validation for heuristic matches."""
        context_lower = context.lower()
        
        # Require security/threat context for heuristic matches
        required_indicators = [
            'threat', 'adversary', 'attacker', 'malicious', 'attack', 'campaign',
            'threat actor', 'cybersecurity', 'security', 'intrusion', 'compromise',
            'intelligence', 'analysis', 'operation', 'observed', 'detected'
        ]
        
        return any(indicator in context_lower for indicator in required_indicators)
    
    def _calculate_enhanced_confidence(self, matched_text: str, technique_info: Dict, match_type: str, context: str = "") -> float:
        """Enhanced confidence calculation with better scoring."""
        # Base confidence by match type
        if match_type.startswith('id_'):
            confidence = 0.85  # High confidence for ID matches
        elif match_type.startswith('name_'):
            confidence = 0.55  # Medium confidence for name matches  
        else:  # heuristic
            confidence = 0.35
        
        context_lower = context.lower()
        
        # Boost for strong MITRE context
        if any(indicator in context_lower for indicator in ['mitre', 'att&ck', 'attack.mitre.org']):
            confidence += 0.1
        
        # Boost for technique IDs in context
        if re.search(r'\bT\d{4}(?:\.\d{3})?\b', context):
            confidence += 0.05
        
        # Boost for threat intelligence keywords
        threat_keywords = ['threat actor', 'adversary', 'campaign', 'ttp', 'technique', 'tactic']
        if any(keyword in context_lower for keyword in threat_keywords):
            confidence += 0.05
        
        # Boost for security analysis context
        analysis_keywords = ['observed', 'detected', 'employed', 'used', 'utilized', 'analysis', 'intelligence']
        if any(keyword in context_lower for keyword in analysis_keywords):
            confidence += 0.03
        
        # Penalty for very short matches (but less harsh)
        if len(matched_text) < 4:
            confidence -= 0.05
        
        # Ensure confidence bounds
        return max(0.0, min(1.0, confidence))
    
    def _enhanced_validation(self, ttps: List[Dict]) -> List[Dict]:
        """Enhanced validation with more lenient filtering."""
        validated_ttps = []
        
        # Use a lower threshold for better recall
        confidence_threshold = max(0.25, self.config.MIN_CONFIDENCE_THRESHOLD * 0.7)
        
        for ttp in ttps:
            # Check confidence threshold
            if ttp.get('confidence', 0) >= confidence_threshold:
                validated_ttps.append(ttp)
            else:
                self.logger.debug(f"Filtered out {ttp['technique_id']} due to low confidence: {ttp.get('confidence', 0):.2f}")
        
        return validated_ttps
    
    def _get_match_context(self, content: str, start: int, end: int, window: int = 200) -> str:
        """Get surrounding context for a match."""
        context_start = max(0, start - window)
        context_end = min(len(content), end + window)
        return content[context_start:context_end]
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[str]:
        """Parse date string into ISO format."""
        if not date_str:
            return None
        
        date_str = date_str.strip()
        
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
