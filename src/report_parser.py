"""
Report Parser - Combines fast and comprehensive parsing approaches
Configurable performance modes: fast, balanced, comprehensive
"""

import requests
import logging
from typing import Dict, Optional, Union, List
from pathlib import Path
from urllib.parse import urlparse
import re
from datetime import datetime
import time

try:
    import PyPDF2
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False

try:
    from bs4 import BeautifulSoup, Comment
    BS4_SUPPORT = True
except ImportError:
    BS4_SUPPORT = False


class ReportParser:
    """
    report parser with configurable performance modes.
    
    Modes:
    - fast: Quick text extraction with minimal overhead
    - balanced: Smart content preservation with reasonable speed
    - comprehensive: Full content preservation with enhanced parsing
    """
    
    def __init__(self, config):
        """Initialize the parser."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        
        # Determine performance mode
        self.performance_mode = getattr(config, 'PERFORMANCE_MODE', 'balanced').lower()
        if self.performance_mode not in ['fast', 'balanced', 'comprehensive']:
            self.performance_mode = 'balanced'
        
        self.logger.info(f"Initializing report parser in '{self.performance_mode}' mode")
        
        # Configure session based on performance mode
        if self.performance_mode == 'fast':
            # Minimal headers for speed
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (compatible; TTP-Analyzer)',
                'Accept': 'text/html,*/*;q=0.9'
            })
        else:
            # More complete headers for compatibility
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'DNT': '1',
                'Connection': 'keep-alive'
            })
        
        self.last_request_time = 0
        
        # TTP-relevant keywords for content preservation (used in balanced/comprehensive modes)
        if self.performance_mode != 'fast':
            self.ttp_keywords = {
                'mitre', 'att&ck', 'attack', 'technique', 'tactic', 'ttp', 'adversary', 'attacker',
                'threat actor', 'campaign', 'malicious', 'security', 'cybersecurity', 'intelligence',
                'observed', 'detected', 'employed', 'used', 'utilized', 'leveraged', 'implements',
                'phishing', 'spearphishing', 'powershell', 'command', 'script', 'injection',
                'credential', 'dumping', 'discovery', 'reconnaissance', 'exfiltration', 'persistence'
            }
        
    def parse_report(self, source: Union[str, Path]) -> Optional[Dict]:
        """Parse a report with mode-appropriate processing."""
        self.logger.debug(f"Parsing report from: {source}")
        
        try:
            if isinstance(source, (str, Path)) and self._is_url(str(source)):
                return self._parse_web_report(str(source))
            elif isinstance(source, (str, Path)) and self._is_file_path(str(source)):
                return self._parse_file_report(Path(source))
            else:
                return self._parse_raw_content(str(source))
                
        except Exception as e:
            self.logger.error(f"Failed to parse report from {source}: {e}")
            return None
    
    def _is_url(self, source: str) -> bool:
        """Check if source is a URL."""
        return source.startswith(('http://', 'https://'))
    
    def _is_file_path(self, source: str) -> bool:
        """Check if source is a file path."""
        return Path(source).exists()
    
    def _parse_web_report(self, url: str) -> Dict:
        """Parse a web report with mode-appropriate handling."""
        self._rate_limit()
        
        try:
            response = self.session.get(url, timeout=self.config.REQUEST_TIMEOUT)
            response.raise_for_status()
            
            content_type = response.headers.get('content-type', '').lower()
            
            if 'pdf' in content_type:
                return self._parse_pdf_content(response.content, url)
            else:
                return self._parse_html_content(response.text, url)
                
        except requests.RequestException as e:
            self.logger.error(f"Failed to fetch URL {url}: {e}")
            raise
    
    def _parse_file_report(self, file_path: Path) -> Dict:
        """Parse a local file report."""
        if file_path.suffix.lower() == '.pdf':
            with open(file_path, 'rb') as f:
                return self._parse_pdf_content(f.read(), str(file_path))
        else:
            with open(file_path, 'r', encoding='utf-8') as f:
                return self._parse_raw_content(f.read(), str(file_path))
    
    def _parse_html_content(self, html_content: str, source: str) -> Dict:
        """Parse HTML content with mode-appropriate processing."""
        if not BS4_SUPPORT:
            self.logger.warning("BeautifulSoup not available, using basic text extraction")
            return self._parse_raw_content(html_content, source)
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Apply mode-appropriate element removal
            if self.performance_mode == 'fast':
                self._fast_element_removal(soup)
            elif self.performance_mode == 'balanced':
                self._balanced_element_removal(soup)
            else:  # comprehensive
                self._comprehensive_element_removal(soup)
            
            # Extract title with appropriate strategy
            title = self._extract_title(soup)
            
            # Extract content with mode-appropriate strategy
            content = self._extract_content(soup)
            
            # Apply mode-appropriate content cleaning
            cleaned_content = self._clean_content(content)
            
            # Extract publication date (comprehensive mode only for speed)
            pub_date = None
            if self.performance_mode == 'comprehensive':
                pub_date = self._extract_date_comprehensive(html_content, soup)
            else:
                pub_date = self._extract_date_simple(html_content)
            
            result = {
                'source': source,
                'title': title,
                'content': cleaned_content,
                'publication_date': pub_date,
                'content_type': 'html',
                'content_length': len(cleaned_content),
                'parsed_at': datetime.utcnow().isoformat(),
                'parser_mode': self.performance_mode
            }
            
            self.logger.debug(f"Extracted {len(cleaned_content)} characters from HTML in {self.performance_mode} mode")
            return result
            
        except Exception as e:
            self.logger.error(f"Error parsing HTML content from {source}: {e}")
            return self._parse_raw_content(html_content, source)
    
    def _fast_element_removal(self, soup: BeautifulSoup):
        """Fast element removal for speed."""
        # Remove only the most problematic elements
        for tag in soup(['script', 'style', 'nav', 'footer']):
            tag.decompose()
    
    def _balanced_element_removal(self, soup: BeautifulSoup):
        """Balanced element removal - preserve TTP content while removing clutter."""
        # Remove obviously unwanted elements
        remove_tags = ["script", "style", "iframe", "embed", "object"]
        for tag in soup(remove_tags):
            tag.decompose()
        
        # Smart removal of navigation elements
        potential_remove = ["nav", "header", "footer", "sidebar"]
        for tag_name in potential_remove:
            for tag in soup.find_all(tag_name):
                tag_text = tag.get_text().lower()
                # Keep if contains TTP-relevant keywords
                if not any(keyword in tag_text for keyword in self.ttp_keywords):
                    tag.decompose()
        
        # Remove comments
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment.extract()
    
    def _comprehensive_element_removal(self, soup: BeautifulSoup):
        """Comprehensive element removal with maximum content preservation."""
        # Same as balanced but with additional intelligence
        self._balanced_element_removal(soup)
        
        # Additional cleanup for comprehensive mode
        # Remove elements with specific classes that are typically non-content
        unwanted_classes = ['advertisement', 'ad-banner', 'social-share', 'related-articles']
        for class_name in unwanted_classes:
            for element in soup.find_all(class_=lambda x: x and class_name in ' '.join(x).lower()):
                element_text = element.get_text().lower()
                if not any(keyword in element_text for keyword in self.ttp_keywords):
                    element.decompose()
    
    def _extract_title(self, soup: BeautifulSoup) -> str:
        """Extract title with mode-appropriate complexity."""
        title_candidates = []
        
        # Strategy 1: HTML title tag (all modes)
        if soup.title and soup.title.string:
            title_candidates.append(soup.title.string.strip())
        
        # Strategy 2: Headings (all modes)
        for heading_tag in ['h1', 'h2']:
            headings = soup.find_all(heading_tag)
            for heading in headings[:2]:  # Limit for speed
                text = heading.get_text().strip()
                if 10 < len(text) < 200:
                    title_candidates.append(text)
        
        # Strategy 3: Meta tags (balanced/comprehensive modes)
        if self.performance_mode != 'fast':
            meta_selectors = [
                ('meta', {'property': 'og:title'}),
                ('meta', {'name': 'title'}),
                ('meta', {'property': 'twitter:title'})
            ]
            
            for tag_name, attrs in meta_selectors:
                element = soup.find(tag_name, attrs)
                if element and element.get('content'):
                    title_candidates.append(element['content'].strip())
        
        # Choose best title
        if title_candidates:
            # Prefer titles with TTP-relevant keywords if in balanced/comprehensive mode
            if self.performance_mode != 'fast':
                for candidate in title_candidates:
                    candidate_lower = candidate.lower()
                    if any(keyword in candidate_lower for keyword in self.ttp_keywords):
                        return candidate[:200]
            
            return title_candidates[0][:200]
        
        return ""
    
    def _extract_content(self, soup: BeautifulSoup) -> str:
        """Extract content with mode-appropriate strategy."""
        if self.performance_mode == 'fast':
            # Fast extraction - just get all text
            return soup.get_text()
        
        elif self.performance_mode == 'balanced':
            # Balanced extraction - smart content selection
            content_strategies = [
                self._extract_semantic_content,
                self._extract_class_based_content,
                self._extract_paragraph_content
            ]
            
            for strategy in content_strategies:
                try:
                    content = strategy(soup)
                    if content and len(content.strip()) > 200:
                        # Quick TTP relevance check
                        content_lower = content.lower()
                        ttp_score = sum(1 for keyword in self.ttp_keywords if keyword in content_lower)
                        if ttp_score >= 2:
                            return content
                except Exception:
                    continue
            
            # Fallback to all text
            return soup.get_text()
        
        else:  # comprehensive
            # Comprehensive extraction - detailed content analysis
            return self._extract_comprehensive_content(soup)
    
    def _extract_semantic_content(self, soup: BeautifulSoup) -> str:
        """Extract from semantic HTML tags."""
        content_parts = []
        semantic_tags = ['article', 'main', 'section', 'div']
        
        for tag in semantic_tags:
            elements = soup.find_all(tag)[:5]  # Limit for performance
            for element in elements:
                text = element.get_text()
                if len(text.strip()) > 100:
                    content_parts.append(text)
        
        return '\n'.join(content_parts)
    
    def _extract_class_based_content(self, soup: BeautifulSoup) -> str:
        """Extract based on content-related CSS classes."""
        content_selectors = [
            '.content', '.main-content', '.post-content', '.article-content',
            '.entry-content', '.blog-content', '.analysis', '.intelligence',
            '.security-content', '.threat-content', '[role="main"]'
        ]
        
        content_parts = []
        for selector in content_selectors:
            elements = soup.select(selector)[:3]  # Limit for performance
            for element in elements:
                text = element.get_text()
                if len(text.strip()) > 100:
                    content_parts.append(text)
        
        return '\n'.join(content_parts)
    
    def _extract_paragraph_content(self, soup: BeautifulSoup) -> str:
        """Extract from paragraphs and relevant elements."""
        content_parts = []
        
        # Extract paragraphs
        for p in soup.find_all('p')[:50]:  # Limit for performance
            text = p.get_text().strip()
            if len(text) > 20:
                content_parts.append(text)
        
        # Extract list items
        for li in soup.find_all('li')[:30]:
            text = li.get_text().strip()
            if len(text) > 30:
                content_parts.append(text)
        
        return '\n'.join(content_parts)
    
    def _extract_comprehensive_content(self, soup: BeautifulSoup) -> str:
        """Comprehensive content extraction with all strategies."""
        # Try multiple strategies and combine results
        strategies = [
            self._extract_semantic_content,
            self._extract_class_based_content,
            self._extract_paragraph_content,
            self._extract_intelligence_content
        ]
        
        all_content = []
        for strategy in strategies:
            try:
                content = strategy(soup)
                if content and len(content.strip()) > 100:
                    all_content.append(content)
            except Exception:
                continue
        
        if all_content:
            # Combine and deduplicate
            combined = '\n'.join(all_content)
            return self._deduplicate_content(combined)
        
        return soup.get_text()
    
    def _extract_intelligence_content(self, soup: BeautifulSoup) -> str:
        """Extract content specifically relevant to threat intelligence."""
        intelligence_selectors = [
            '[class*="threat"]', '[class*="security"]', '[class*="analysis"]',
            '[class*="intelligence"]', '[class*="attack"]', '[class*="mitre"]',
            '[id*="threat"]', '[id*="security"]', '[id*="analysis"]'
        ]
        
        content_parts = []
        for selector in intelligence_selectors:
            elements = soup.select(selector)
            for element in elements:
                text = element.get_text().strip()
                if len(text) > 50:
                    content_parts.append(text)
        
        return '\n'.join(content_parts)
    
    def _deduplicate_content(self, content: str) -> str:
        """Remove duplicate content while preserving structure."""
        lines = content.split('\n')
        seen_lines = set()
        unique_lines = []
        
        for line in lines:
            line_clean = line.strip()
            if line_clean and line_clean not in seen_lines:
                unique_lines.append(line)
                seen_lines.add(line_clean)
        
        return '\n'.join(unique_lines)
    
    def _clean_content(self, content: str) -> str:
        """Clean content with mode-appropriate thoroughness."""
        if not content:
            return ""
        
        if self.performance_mode == 'fast':
            # Minimal cleaning for speed
            content = re.sub(r'\s+', ' ', content).strip()
            return content
        
        elif self.performance_mode == 'balanced':
            # Balanced cleaning
            # Normalize whitespace
            content = re.sub(r'\r\n', '\n', content)
            content = re.sub(r'\r', '\n', content)
            content = re.sub(r'\n{3,}', '\n\n', content)
            content = re.sub(r'[ \t]+', ' ', content)
            
            # Remove some unwanted artifacts
            unwanted_patterns = [
                r'Cookie\s+Policy(?!\s+(?:analysis|security))',
                r'Privacy\s+Policy(?!\s+(?:analysis|security))',
                r'Follow\s+us\s+on\s+(?:Twitter|LinkedIn)',
                r'Subscribe\s+to\s+newsletter'
            ]
            
            for pattern in unwanted_patterns:
                content = re.sub(pattern, '', content, flags=re.IGNORECASE)
            
            return content.strip()
        
        else:  # comprehensive
            # Comprehensive cleaning with maximum preservation
            return self._comprehensive_content_cleaning(content)
    
    def _comprehensive_content_cleaning(self, content: str) -> str:
        """Comprehensive content cleaning that preserves TTP context."""
        # Normalize whitespace but preserve structure
        content = re.sub(r'\r\n', '\n', content)
        content = re.sub(r'\r', '\n', content)
        content = re.sub(r'\n{3,}', '\n\n', content)
        content = re.sub(r'[ \t]+', ' ', content)
        
        # Remove excessive repetition but preserve TTP patterns
        lines = content.split('\n')
        cleaned_lines = []
        prev_line = ""
        
        for line in lines:
            line = line.strip()
            if not line:
                if prev_line:
                    cleaned_lines.append("")
                continue
            
            # Don't remove lines with TTP-relevant content
            line_lower = line.lower()
            has_ttp_content = any(keyword in line_lower for keyword in self.ttp_keywords)
            has_technique_id = bool(re.search(r'\bT\d{4}(?:\.\d{3})?\b', line))
            
            if has_ttp_content or has_technique_id or line != prev_line:
                cleaned_lines.append(line)
            
            prev_line = line
        
        cleaned_content = '\n'.join(cleaned_lines)
        
        # Remove unwanted artifacts but preserve security-related content
        artifacts_to_remove = [
            r'Cookie\s+Policy(?!\s+(?:analysis|security|threat))',
            r'Privacy\s+Policy(?!\s+(?:analysis|security|threat))',
            r'Terms\s+of\s+Service(?!\s+(?:analysis|security|threat))',
            r'Follow\s+us\s+on\s+(?:Twitter|LinkedIn|Facebook)',
            r'Subscribe\s+to\s+(?:our\s+)?newsletter',
            r'Advertisement(?!\s+(?:analysis|vector|campaign))',
            r'Sponsored\s+Content(?!\s+(?:analysis|by\s+security))'
        ]
        
        for artifact_pattern in artifacts_to_remove:
            cleaned_content = re.sub(artifact_pattern, '', cleaned_content, flags=re.IGNORECASE)
        
        # Clean URLs but preserve security-related ones
        security_domains = ['mitre.org', 'cisa.gov', 'nist.gov', 'attack.mitre.org', 'cve.mitre.org']
        
        def url_replacer(match):
            url = match.group(0)
            if any(domain in url.lower() for domain in security_domains):
                return url
            return ''
        
        cleaned_content = re.sub(r'https?://\S+', url_replacer, cleaned_content)
        
        # Final cleanup
        cleaned_content = re.sub(r'\s+', ' ', cleaned_content)
        cleaned_content = re.sub(r'\n\s*\n', '\n', cleaned_content)
        
        return cleaned_content.strip()
    
    def _extract_date_simple(self, content: str) -> Optional[str]:
        """Simple date extraction for fast/balanced modes."""
        # Look for ISO format dates
        iso_pattern = r'\b(\d{4}-\d{1,2}-\d{1,2})\b'
        matches = re.findall(iso_pattern, content)
        
        if matches:
            for date_str in matches:
                try:
                    dt = datetime.strptime(date_str, '%Y-%m-%d')
                    if 1990 <= dt.year <= 2030:
                        return dt.date().isoformat()
                except ValueError:
                    continue
        
        return None
    
    def _extract_date_comprehensive(self, html_content: str, soup: BeautifulSoup) -> Optional[str]:
        """Comprehensive date extraction with multiple strategies."""
        # Try structured data first
        date = self._extract_structured_date(soup)
        if date:
            return date
        
        # Try meta tags
        date = self._extract_meta_date(soup)
        if date:
            return date
        
        # Try time elements
        date = self._extract_time_elements(soup)
        if date:
            return date
        
        # Fall back to text patterns
        return self._extract_date_from_text(html_content)
    
    def _extract_structured_date(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract date from JSON-LD structured data."""
        scripts = soup.find_all('script', type='application/ld+json')
        for script in scripts:
            try:
                import json
                data = json.loads(script.string)
                
                if isinstance(data, list):
                    data = data[0] if data else {}
                
                date_fields = ['datePublished', 'dateCreated', 'dateModified']
                for field in date_fields:
                    if field in data:
                        return self._parse_date_string(data[field])
            except:
                continue
        
        return None
    
    def _extract_meta_date(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract date from meta tags."""
        meta_selectors = [
            ('meta', {'property': 'article:published_time'}),
            ('meta', {'name': 'pubdate'}),
            ('meta', {'name': 'date'}),
            ('meta', {'property': 'og:published_time'})
        ]
        
        for tag_name, attrs in meta_selectors:
            element = soup.find(tag_name, attrs)
            if element and element.get('content'):
                return self._parse_date_string(element['content'])
        
        return None
    
    def _extract_time_elements(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract date from time elements."""
        time_elements = soup.find_all('time')
        for time_elem in time_elements:
            datetime_attr = time_elem.get('datetime')
            if datetime_attr:
                return self._parse_date_string(datetime_attr)
        
        return None
    
    def _extract_date_from_text(self, content: str) -> Optional[str]:
        """Extract date from text content using patterns."""
        date_patterns = [
            r'\b(\d{4}-\d{1,2}-\d{1,2})\b',
            r'\b(\d{1,2}[-/]\d{1,2}[-/]\d{4})\b',
            r'\b((?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4})\b'
        ]
        
        for pattern in date_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                for match in matches:
                    date_str = match if isinstance(match, str) else match[0]
                    parsed_date = self._parse_date_string(date_str)
                    if parsed_date:
                        return parsed_date
        
        return None
    
    def _parse_date_string(self, date_str: str) -> Optional[str]:
        """Parse various date string formats into ISO format."""
        if not date_str:
            return None
        
        date_str = date_str.strip()
        
        # Handle ISO format with timezone
        if 'T' in date_str:
            try:
                if date_str.endswith('Z'):
                    date_str = date_str[:-1]
                elif '+' in date_str:
                    date_str = date_str.split('+')[0]
                
                dt = datetime.fromisoformat(date_str)
                return dt.date().isoformat()
            except:
                pass
        
        # Try various formats
        date_formats = [
            '%Y-%m-%d', '%m/%d/%Y', '%d/%m/%Y',
            '%B %d, %Y', '%b %d, %Y', '%d %B %Y'
        ]
        
        for fmt in date_formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                if 1990 <= dt.year <= 2030:
                    return dt.date().isoformat()
            except ValueError:
                continue
        
        return None
    
    def _parse_pdf_content(self, pdf_content: bytes, source: str) -> Dict:
        """Parse PDF content with mode-appropriate processing."""
        if not PDF_SUPPORT:
            raise ImportError("PyPDF2 not available for PDF parsing")
        
        try:
            from io import BytesIO
            pdf_reader = PyPDF2.PdfReader(BytesIO(pdf_content))
            
            # Extract text from all pages
            text_content = ""
            page_count = len(pdf_reader.pages)
            
            # Limit pages in fast mode for speed
            max_pages = page_count if self.performance_mode != 'fast' else min(page_count, 20)
            
            for i, page in enumerate(pdf_reader.pages[:max_pages]):
                try:
                    page_text = page.extract_text()
                    if page_text:
                        text_content += page_text + "\n"
                except Exception as e:
                    self.logger.debug(f"Failed to extract text from PDF page {i}: {e}")
                    continue
            
            # Extract metadata
            title = ""
            creation_date = None
            
            if pdf_reader.metadata and self.performance_mode != 'fast':
                title = (pdf_reader.metadata.get('/Title') or "").strip()
                
                # Extract creation date in comprehensive mode
                if self.performance_mode == 'comprehensive':
                    creation_date_obj = pdf_reader.metadata.get('/CreationDate')
                    if creation_date_obj:
                        try:
                            date_str = str(creation_date_obj)
                            if date_str.startswith("D:"):
                                date_str = date_str[2:10]
                                if len(date_str) == 8:
                                    dt = datetime.strptime(date_str, '%Y%m%d')
                                    creation_date = dt.date().isoformat()
                        except:
                            pass
            
            # Extract title from content if not from metadata
            if not title and text_content:
                lines = [line.strip() for line in text_content.split('\n') if line.strip()]
                for line in lines[:10]:
                    if 5 < len(line) < 150:
                        title = line
                        break
            
            # Clean content based on mode
            cleaned_content = self._clean_content(text_content)
            
            result = {
                'source': source,
                'title': title,
                'content': cleaned_content,
                'publication_date': creation_date,
                'content_type': 'pdf',
                'content_length': len(cleaned_content),
                'page_count': page_count,
                'pages_processed': max_pages,
                'parsed_at': datetime.utcnow().isoformat(),
                'parser_mode': self.performance_mode
            }
            
            self.logger.debug(f"Extracted {len(cleaned_content)} characters from PDF")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to parse PDF from {source}: {e}")
            raise
    
    def _parse_raw_content(self, content: str, source: str = "raw") -> Dict:
        """Parse raw text content with mode-appropriate processing."""
        lines = [line.strip() for line in content.split('\n') if line.strip()]
        
        # Extract title from first meaningful line
        title = ""
        for line in lines[:5]:
            if 5 < len(line) < 150:
                title = line
                break
        
        # Clean content
        cleaned_content = self._clean_content(content)
        
        # Extract date only in balanced/comprehensive modes
        pub_date = None
        if self.performance_mode != 'fast':
            pub_date = self._extract_date_simple(content)
        
        result = {
            'source': source,
            'title': title,
            'content': cleaned_content,
            'publication_date': pub_date,
            'content_type': 'text',
            'content_length': len(cleaned_content),
            'parsed_at': datetime.utcnow().isoformat(),
            'parser_mode': self.performance_mode
        }
        
        return result
    
    def _rate_limit(self):
        """Rate limiting for web requests."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.config.RATE_LIMIT_DELAY:
            sleep_time = self.config.RATE_LIMIT_DELAY - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
