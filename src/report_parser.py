"""
Enhanced Report Parser Module with improved content preservation for TTP extraction.
This version is more careful about preserving TTP-relevant content during cleaning.
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
    """Enhanced parser with better content preservation for TTP extraction."""
    
    def __init__(self, config):
        """Initialize the enhanced report parser."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        
        # Enhanced headers for better compatibility
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        self.last_request_time = 0
        
        # TTP-relevant keywords to preserve during cleaning
        self.ttp_keywords = {
            'mitre', 'att&ck', 'attack', 'technique', 'tactic', 'ttp', 'adversary', 'attacker',
            'threat actor', 'campaign', 'malicious', 'security', 'cybersecurity', 'intelligence',
            'observed', 'detected', 'employed', 'used', 'utilized', 'leveraged', 'implements',
            'phishing', 'spearphishing', 'powershell', 'command', 'script', 'injection',
            'credential', 'dumping', 'discovery', 'reconnaissance', 'exfiltration', 'persistence'
        }
        
    def parse_report(self, source: Union[str, Path]) -> Optional[Dict]:
        """Parse a report with enhanced content preservation."""
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
        try:
            result = urlparse(source)
            return all([result.scheme, result.netloc])
        except:
            return False
            
    def _is_file_path(self, source: str) -> bool:
        """Check if source is a file path."""
        return Path(source).exists()
        
    def _parse_web_report(self, url: str) -> Dict:
        """Parse a web report with enhanced error handling."""
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
        """Enhanced HTML parsing with better content preservation."""
        if not BS4_SUPPORT:
            self.logger.warning("BeautifulSoup not available, using basic text extraction")
            return self._parse_raw_content(html_content, source)
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # More selective removal - preserve content that might contain TTPs
            self._selective_element_removal(soup)
            
            # Extract title with enhanced strategies
            title = self._extract_enhanced_title(soup)
            
            # Enhanced content extraction with TTP awareness
            content = self._extract_ttp_aware_content(soup)
            
            # Gentler content cleaning that preserves TTP context
            cleaned_content = self._gentle_content_cleaning(content)
            
            # Enhanced date extraction
            pub_date = self._extract_date_enhanced(html_content, soup)
            
            # Content quality validation with TTP awareness
            if len(cleaned_content.strip()) < 100:
                self.logger.warning(f"Short content from {source}: {len(cleaned_content)} chars")
                # Try alternative extraction methods
                alt_content = self._alternative_content_extraction(soup)
                if len(alt_content) > len(cleaned_content):
                    cleaned_content = self._gentle_content_cleaning(alt_content)
                    self.logger.debug(f"Used alternative extraction: {len(cleaned_content)} chars")
            
            result = {
                'source': source,
                'title': title,
                'content': cleaned_content,
                'publication_date': pub_date,
                'content_type': 'html',
                'content_length': len(cleaned_content),
                'parsed_at': datetime.utcnow().isoformat()
            }
            
            self.logger.debug(f"Extracted {len(cleaned_content)} characters from HTML")
            return result
            
        except Exception as e:
            self.logger.error(f"Error parsing HTML content from {source}: {e}")
            return self._parse_raw_content(html_content, source)
    
    def _selective_element_removal(self, soup: BeautifulSoup):
        """More selective removal that preserves TTP-relevant content."""
        # Remove obviously irrelevant elements
        remove_tags = ["script", "style", "iframe", "embed", "object"]
        
        # Be more careful with navigation, headers, footers - they might contain relevant info
        potential_remove = ["nav", "header", "footer", "sidebar", "menu"]
        
        # Remove scripts and styles completely
        for tag in soup(remove_tags):
            tag.decompose()
        
        # For potential removes, check if they contain TTP-relevant content
        for tag_name in potential_remove:
            for tag in soup.find_all(tag_name):
                tag_text = tag.get_text().lower()
                
                # If the element contains TTP-relevant keywords, keep it
                if not any(keyword in tag_text for keyword in self.ttp_keywords):
                    tag.decompose()
        
        # Remove comments
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment.extract()
    
    def _extract_enhanced_title(self, soup: BeautifulSoup) -> str:
        """Enhanced title extraction with multiple fallbacks."""
        title_candidates = []
        
        # Strategy 1: HTML title tag
        if soup.title and soup.title.string:
            title_candidates.append(soup.title.string.strip())
        
        # Strategy 2: Multiple heading levels
        for heading_tag in ['h1', 'h2', 'h3']:
            headings = soup.find_all(heading_tag)
            for heading in headings:
                text = heading.get_text().strip()
                if 10 < len(text) < 200:  # Reasonable title length
                    title_candidates.append(text)
        
        # Strategy 3: Meta tags
        meta_selectors = [
            ('meta', {'property': 'og:title'}),
            ('meta', {'name': 'title'}),
            ('meta', {'name': 'dc.title'}),
            ('meta', {'property': 'twitter:title'})
        ]
        
        for tag_name, attrs in meta_selectors:
            element = soup.find(tag_name, attrs)
            if element and element.get('content'):
                title_candidates.append(element['content'].strip())
        
        # Strategy 4: Content-based classes
        title_selectors = [
            '.article-title', '.post-title', '.entry-title', '.blog-title',
            '.page-title', '.content-title', '.report-title', '.document-title'
        ]
        
        for selector in title_selectors:
            elements = soup.select(selector)
            for element in elements:
                text = element.get_text().strip()
                if 10 < len(text) < 200:
                    title_candidates.append(text)
        
        # Choose the best title (prefer ones with security/threat keywords)
        if title_candidates:
            # Prefer titles with TTP-relevant keywords
            for candidate in title_candidates:
                candidate_lower = candidate.lower()
                if any(keyword in candidate_lower for keyword in self.ttp_keywords):
                    return candidate[:200]
            
            # Otherwise, return the first reasonable candidate
            return title_candidates[0][:200]
        
        return ""
    
    def _extract_ttp_aware_content(self, soup: BeautifulSoup) -> str:
        """Extract content with awareness of TTP-relevant information."""
        content_strategies = [
            self._extract_semantic_content,
            self._extract_class_based_content,
            self._extract_paragraph_content,
            self._extract_all_text_content
        ]
        
        for strategy in content_strategies:
            try:
                content = strategy(soup)
                if content and len(content.strip()) > 200:
                    # Check if content contains TTP-relevant information
                    content_lower = content.lower()
                    ttp_score = sum(1 for keyword in self.ttp_keywords if keyword in content_lower)
                    
                    if ttp_score >= 2:  # At least 2 TTP-relevant keywords
                        return content
                    elif len(content.strip()) > 1000:  # Long content might be worth keeping
                        return content
            except Exception as e:
                self.logger.debug(f"Content extraction strategy failed: {e}")
                continue
        
        # Fallback to all text if nothing else works
        return soup.get_text()
    
    def _extract_semantic_content(self, soup: BeautifulSoup) -> str:
        """Extract from semantic HTML tags."""
        content_parts = []
        semantic_tags = ['article', 'main', 'section', 'div']
        
        for tag in semantic_tags:
            elements = soup.find_all(tag)
            for element in elements:
                text = element.get_text()
                if len(text.strip()) > 100:
                    content_parts.append(text)
        
        return '\n'.join(content_parts)
    
    def _extract_class_based_content(self, soup: BeautifulSoup) -> str:
        """Extract based on content-related CSS classes."""
        content_selectors = [
            '.content', '.main-content', '.post-content', '.article-content',
            '.entry-content', '.blog-content', '.text-content', '.body-content',
            '.article-body', '.post-body', '.story-body', '.report-content',
            '.analysis', '.intelligence', '.security-content', '.threat-content',
            '[role="main"]', '.container', '.wrapper'
        ]
        
        content_parts = []
        for selector in content_selectors:
            elements = soup.select(selector)
            for element in elements:
                text = element.get_text()
                if len(text.strip()) > 100:
                    content_parts.append(text)
        
        return '\n'.join(content_parts)
    
    def _extract_paragraph_content(self, soup: BeautifulSoup) -> str:
        """Extract from paragraphs and relevant elements."""
        content_parts = []
        
        # Extract paragraphs
        for p in soup.find_all('p'):
            text = p.get_text().strip()
            if len(text) > 20:
                content_parts.append(text)
        
        # Extract list items
        for li in soup.find_all('li'):
            text = li.get_text().strip()
            if len(text) > 30:
                content_parts.append(text)
        
        # Extract divs with substantial text
        for div in soup.find_all('div'):
            # Get direct text content
            direct_text = ''.join(div.find_all(string=True, recursive=False)).strip()
            if len(direct_text) > 50:
                content_parts.append(direct_text)
        
        # Extract table cells (threat intel reports often use tables)
        for td in soup.find_all(['td', 'th']):
            text = td.get_text().strip()
            if len(text) > 20:
                content_parts.append(text)
        
        return '\n'.join(content_parts)
    
    def _extract_all_text_content(self, soup: BeautifulSoup) -> str:
        """Fallback to extract all text content."""
        return soup.get_text()
    
    def _alternative_content_extraction(self, soup: BeautifulSoup) -> str:
        """Alternative extraction for difficult pages."""
        # Try extracting from elements that commonly contain threat intelligence
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
        
        if content_parts:
            return '\n'.join(content_parts)
        
        # Final fallback - extract from all visible text elements
        visible_elements = soup.find_all(['p', 'div', 'span', 'li', 'td', 'th', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'])
        for elem in visible_elements:
            text = elem.get_text().strip()
            if len(text) > 15:
                content_parts.append(text)
        
        return '\n'.join(content_parts)
    
    def _gentle_content_cleaning(self, content: str) -> str:
        """Gentler content cleaning that preserves TTP context."""
        if not content:
            return ""
        
        # Normalize whitespace but preserve structure
        content = re.sub(r'\r\n', '\n', content)
        content = re.sub(r'\r', '\n', content)
        content = re.sub(r'\n{3,}', '\n\n', content)  # Max 2 consecutive newlines
        content = re.sub(r'[ \t]+', ' ', content)  # Normalize spaces
        
        # Remove excessive repetition but preserve TTP patterns
        lines = content.split('\n')
        cleaned_lines = []
        prev_line = ""
        
        for line in lines:
            line = line.strip()
            if not line:
                if prev_line:  # Only add empty line if previous line had content
                    cleaned_lines.append("")
                continue
            
            # Don't remove lines that contain TTP-relevant information
            line_lower = line.lower()
            has_ttp_content = any(keyword in line_lower for keyword in self.ttp_keywords)
            
            # Check for technique ID patterns
            has_technique_id = bool(re.search(r'\bT\d{4}(?:\.\d{3})?\b', line))
            
            if has_ttp_content or has_technique_id or line != prev_line:
                cleaned_lines.append(line)
            
            prev_line = line
        
        cleaned_content = '\n'.join(cleaned_lines)
        
        # Remove only clearly unwanted artifacts, but preserve security-related content
        artifacts_to_remove = [
            r'Cookie\s+Policy(?!\s+(?:analysis|security|threat))',  # Keep if followed by security terms
            r'Privacy\s+Policy(?!\s+(?:analysis|security|threat))',
            r'Terms\s+of\s+Service(?!\s+(?:analysis|security|threat))',
            r'Follow\s+us\s+on\s+(?:Twitter|LinkedIn|Facebook)',
            r'Subscribe\s+to\s+(?:our\s+)?newsletter',
            r'Advertisement(?!\s+(?:analysis|vector|campaign))',  # Keep if security-related
            r'Sponsored\s+Content(?!\s+(?:analysis|by\s+security))'
        ]
        
        for artifact_pattern in artifacts_to_remove:
            cleaned_content = re.sub(artifact_pattern, '', cleaned_content, flags=re.IGNORECASE)
        
        # Clean up URLs but preserve those that might be relevant
        # Keep security-related domains
        security_domains = ['mitre.org', 'cisa.gov', 'nist.gov', 'attack.mitre.org', 'cve.mitre.org']
        
        def url_replacer(match):
            url = match.group(0)
            if any(domain in url.lower() for domain in security_domains):
                return url  # Keep security-related URLs
            return ''  # Remove other URLs
        
        cleaned_content = re.sub(r'https?://\S+', url_replacer, cleaned_content)
        
        # Final cleanup
        cleaned_content = re.sub(r'\s+', ' ', cleaned_content)
        cleaned_content = re.sub(r'\n\s*\n', '\n', cleaned_content)
        
        return cleaned_content.strip()
    
    def _extract_date_enhanced(self, html_content: str, soup: BeautifulSoup) -> Optional[str]:
        """Enhanced date extraction with multiple strategies."""
        # Strategy 1: Structured data (JSON-LD)
        date = self._extract_structured_date(soup)
        if date:
            return date
        
        # Strategy 2: Meta tags
        date = self._extract_meta_date(soup)
        if date:
            return date
        
        # Strategy 3: Time elements
        date = self._extract_time_elements(soup)
        if date:
            return date
        
        # Strategy 4: Text patterns in content
        date = self._extract_date_from_text(html_content)
        if date:
            return date
        
        return None
    
    def _extract_structured_date(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract date from JSON-LD structured data."""
        scripts = soup.find_all('script', type='application/ld+json')
        for script in scripts:
            try:
                import json
                data = json.loads(script.string)
                
                # Handle both single objects and arrays
                if isinstance(data, list):
                    data = data[0] if data else {}
                
                date_fields = ['datePublished', 'dateCreated', 'dateModified', 'publishedDate']
                for field in date_fields:
                    if field in data:
                        return self._parse_date_string(data[field])
            except (json.JSONDecodeError, TypeError):
                continue
        
        return None
    
    def _extract_meta_date(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract date from meta tags."""
        meta_selectors = [
            ('meta', {'property': 'article:published_time'}),
            ('meta', {'property': 'article:modified_time'}),
            ('meta', {'name': 'pubdate'}),
            ('meta', {'name': 'date'}),
            ('meta', {'name': 'publish_date'}),
            ('meta', {'property': 'og:published_time'}),
            ('meta', {'name': 'DC.date.created'}),
            ('meta', {'name': 'dc.date'}),
            ('meta', {'name': 'citation_publication_date'}),
            ('meta', {'property': 'twitter:data1'})  # Sometimes used for dates
        ]
        
        for tag_name, attrs in meta_selectors:
            element = soup.find(tag_name, attrs)
            if element:
                date_value = element.get('content') or element.get('datetime')
                if date_value:
                    parsed_date = self._parse_date_string(date_value)
                    if parsed_date:
                        return parsed_date
        
        return None
    
    def _extract_time_elements(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract date from time elements."""
        time_elements = soup.find_all('time')
        for time_elem in time_elements:
            datetime_attr = time_elem.get('datetime')
            if datetime_attr:
                parsed_date = self._parse_date_string(datetime_attr)
                if parsed_date:
                    return parsed_date
            
            # Try parsing the text content of time elements
            time_text = time_elem.get_text().strip()
            if time_text:
                parsed_date = self._parse_date_string(time_text)
                if parsed_date:
                    return parsed_date
        
        return None
    
    def _extract_date_from_text(self, content: str) -> Optional[str]:
        """Extract date from text content using patterns."""
        # Enhanced date patterns
        date_patterns = [
            # ISO format
            r'\b(\d{4}-\d{1,2}-\d{1,2})\b',
            # US format
            r'\b(\d{1,2}[-/]\d{1,2}[-/]\d{4})\b',
            # Full month names
            r'\b((?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4})\b',
            # Abbreviated month names
            r'\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\.?\s+\d{1,2},?\s+\d{4})\b',
            # Day month year
            r'\b(\d{1,2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4})\b',
            # Published/Updated patterns
            r'(?:Published|Updated|Created|Modified)\s*:?\s*([A-Za-z]+\s+\d{1,2},?\s+\d{4})',
            r'(?:Published|Updated|Created|Modified)\s*:?\s*(\d{1,2}[-/]\d{1,2}[-/]\d{4})'
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
        
        # Handle ISO format dates with timezone
        if 'T' in date_str:
            try:
                # Remove timezone info for parsing
                if date_str.endswith('Z'):
                    date_str = date_str[:-1]
                elif '+' in date_str:
                    date_str = date_str.split('+')[0]
                elif date_str.count('-') > 2:  # Has timezone offset
                    parts = date_str.rsplit('-', 1)
                    if ':' in parts[1]:  # Likely timezone
                        date_str = parts[0]
                
                dt = datetime.fromisoformat(date_str)
                return dt.date().isoformat()
            except:
                pass
        
        # Try various date formats
        date_formats = [
            '%Y-%m-%d',
            '%m/%d/%Y', '%d/%m/%Y',
            '%m-%d-%Y', '%d-%m-%Y',
            '%B %d, %Y', '%b %d, %Y',
            '%d %B %Y', '%d %b %Y',
            '%B %d %Y', '%b %d %Y',
            '%Y/%m/%d', '%d.%m.%Y', '%m.%d.%Y',
            '%d-%b-%Y', '%d-%B-%Y'
        ]
        
        for fmt in date_formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                # Reasonable year range check
                if 1990 <= dt.year <= 2030:
                    return dt.date().isoformat()
            except ValueError:
                continue
        
        return None
    
    def _parse_pdf_content(self, pdf_content: bytes, source: str) -> Dict:
        """Enhanced PDF parsing with better text extraction."""
        if not PDF_SUPPORT:
            raise ImportError("PyPDF2 not available for PDF parsing")
        
        try:
            from io import BytesIO
            pdf_reader = PyPDF2.PdfReader(BytesIO(pdf_content))
            
            # Extract text from all pages with better handling
            text_content = ""
            page_count = len(pdf_reader.pages)
            
            for i, page in enumerate(pdf_reader.pages):
                try:
                    page_text = page.extract_text()
                    if page_text:
                        # Basic text cleaning for PDFs
                        page_text = re.sub(r'\s+', ' ', page_text)
                        text_content += page_text + "\n"
                except Exception as e:
                    self.logger.debug(f"Failed to extract text from PDF page {i}: {e}")
                    continue
            
            # Extract metadata for title and date
            title = ""
            creation_date = None
            
            if pdf_reader.metadata:
                title = (pdf_reader.metadata.get('/Title') or 
                        pdf_reader.metadata.get('/Subject') or "").strip()
                
                # Try to get creation date
                creation_date_obj = pdf_reader.metadata.get('/CreationDate')
                if creation_date_obj:
                    try:
                        # PDF dates are in D:YYYYMMDDHHmmSSOHH'mm format
                        date_str = str(creation_date_obj)
                        if date_str.startswith("D:"):
                            date_str = date_str[2:10]  # Extract YYYYMMDD
                            if len(date_str) == 8:
                                dt = datetime.strptime(date_str, '%Y%m%d')
                                creation_date = dt.date().isoformat()
                    except:
                        pass
            
            # If no title from metadata, extract from content
            if not title and text_content:
                lines = [line.strip() for line in text_content.split('\n') if line.strip()]
                for line in lines[:10]:  # Check first 10 lines
                    if 5 < len(line) < 150:  # Reasonable title length
                        title = line
                        break
            
            # Gentle cleaning for PDFs
            cleaned_content = self._gentle_content_cleaning(text_content)
            
            result = {
                'source': source,
                'title': title,
                'content': cleaned_content,
                'publication_date': creation_date,
                'content_type': 'pdf',
                'content_length': len(cleaned_content),
                'page_count': page_count,
                'parsed_at': datetime.utcnow().isoformat()
            }
            
            self.logger.debug(f"Extracted {len(cleaned_content)} characters from PDF")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to parse PDF from {source}: {e}")
            raise
    
    def _parse_raw_content(self, content: str, source: str = "raw") -> Dict:
        """Parse raw text content with enhanced cleaning."""
        lines = [line.strip() for line in content.split('\n') if line.strip()]
        
        # Extract title from first meaningful line
        title = ""
        for line in lines[:5]:
            if 5 < len(line) < 150:
                title = line
                break
        
        # Apply gentle cleaning
        cleaned_content = self._gentle_content_cleaning(content)
        
        result = {
            'source': source,
            'title': title,
            'content': cleaned_content,
            'publication_date': self._extract_date_from_text(content),
            'content_type': 'text',
            'content_length': len(cleaned_content),
            'parsed_at': datetime.utcnow().isoformat()
        }
        
        return result
    
    def _rate_limit(self):
        """Implement rate limiting for web requests."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.config.RATE_LIMIT_DELAY:
            sleep_time = self.config.RATE_LIMIT_DELAY - time_since_last
            self.logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
