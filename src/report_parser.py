"""
Report Parser Module for extracting content from various report sources.
Supports web URLs, PDFs, and local files.
"""

import requests
import logging
from typing import Dict, Optional, Union
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
    from bs4 import BeautifulSoup
    BS4_SUPPORT = True
except ImportError:
    BS4_SUPPORT = False


class ReportParser:
    """Parser for extracting content from threat intelligence reports."""
    
    def __init__(self, config):
        """Initialize the report parser."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        
        # Use multiple user agents to avoid detection
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
        ]
        self.current_ua_index = 0
        
        # Set up session headers
        self._update_headers()
        
        # Rate limiting
        self.last_request_time = 0
        
    def _update_headers(self):
        """Update session headers with current user agent."""
        self.session.headers.update({
            'User-Agent': self.user_agents[self.current_ua_index],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
    def parse_report(self, source: Union[str, Path]) -> Optional[Dict]:
        """Parse a report from various sources with retry logic."""
        self.logger.debug(f"Parsing report from: {source}")
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if isinstance(source, (str, Path)) and self._is_url(str(source)):
                    return self._parse_web_report(str(source))
                elif isinstance(source, (str, Path)) and self._is_file_path(str(source)):
                    return self._parse_file_report(Path(source))
                else:
                    return self._parse_raw_content(str(source))
                    
            except Exception as e:
                self.logger.warning(f"Attempt {attempt + 1} failed for {source}: {e}")
                if attempt < max_retries - 1:
                    # Try different user agent
                    self.current_ua_index = (self.current_ua_index + 1) % len(self.user_agents)
                    self._update_headers()
                    time.sleep(2)  # Wait before retry
                else:
                    self.logger.error(f"All attempts failed for {source}")
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
        """Parse a report from a web URL."""
        self._rate_limit()
        
        try:
            # Longer timeout but with streaming to avoid memory issues
            response = self.session.get(url, timeout=30, stream=True)
            response.raise_for_status()
            
            # Check content size
            content_length = response.headers.get('content-length')
            if content_length and int(content_length) > 50 * 1024 * 1024:  # 50MB limit
                self.logger.warning(f"Content too large: {content_length} bytes")
                return None
            
            # Get content
            content = response.text
            content_type = response.headers.get('content-type', '').lower()
            
            if 'pdf' in content_type:
                return self._parse_pdf_content(response.content, url)
            else:
                return self._parse_html_content(content, url)
                
        except requests.RequestException as e:
            self.logger.error(f"Failed to fetch URL {url}: {e}")
            raise
            
    def _parse_file_report(self, file_path: Path) -> Dict:
        """Parse a report from a local file."""
        if file_path.suffix.lower() == '.pdf':
            with open(file_path, 'rb') as f:
                return self._parse_pdf_content(f.read(), str(file_path))
        else:
            with open(file_path, 'r', encoding='utf-8') as f:
                return self._parse_raw_content(f.read(), str(file_path))
                
    def _parse_html_content(self, html_content: str, source: str) -> Dict:
        """Parse HTML content and extract relevant information."""
        if not BS4_SUPPORT:
            self.logger.warning("BeautifulSoup not available, using basic text extraction")
            return self._parse_raw_content(html_content, source)
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Remove unwanted elements
            for element in soup(["script", "style", "nav", "header", "footer", "aside", "form"]):
                element.decompose()
            
            # Extract title
            title = self._extract_title(soup)
            
            # Extract content with multiple strategies
            content = self._extract_content(soup)
            
            # Clean content
            cleaned_content = self._clean_content(content)
            
            # Extract publication date
            pub_date = self._extract_publication_date(soup, html_content)
            
            result = {
                'source': source,
                'title': title,
                'content': cleaned_content,
                'publication_date': pub_date,
                'content_type': 'html',
                'parsed_at': datetime.utcnow().isoformat()
            }
            
            self.logger.debug(f"Extracted {len(cleaned_content)} characters from HTML")
            return result
            
        except Exception as e:
            self.logger.error(f"Error parsing HTML content: {e}")
            return self._parse_raw_content(html_content, source)
    
    def _extract_title(self, soup: BeautifulSoup) -> str:
        """Extract title from HTML."""
        # Try title tag first
        if soup.title and soup.title.string:
            return soup.title.string.strip()
        
        # Try h1 tags
        h1_tags = soup.find_all('h1')
        for h1 in h1_tags:
            text = h1.get_text().strip()
            if text and len(text) > 5:
                return text
        
        # Try meta tags
        meta_title = soup.find('meta', property='og:title')
        if meta_title and meta_title.get('content'):
            return meta_title['content'].strip()
        
        return "Unknown Title"
    
    def _extract_content(self, soup: BeautifulSoup) -> str:
        """Extract main content from HTML."""
        content = ""
        
        # Try main content selectors in order of preference
        selectors = [
            'article',
            'main', 
            '[role="main"]',
            '.content',
            '.post-content',
            '.entry-content',
            '.article-content',
            '.blog-post'
        ]
        
        for selector in selectors:
            try:
                elements = soup.select(selector)
                if elements and len(elements[0].get_text().strip()) > 200:
                    content = elements[0].get_text()
                    break
            except:
                continue
        
        # Fallback: get all paragraphs
        if not content or len(content.strip()) < 200:
            paragraphs = soup.find_all('p')
            content = ' '.join([p.get_text().strip() for p in paragraphs if len(p.get_text().strip()) > 20])
        
        # Final fallback: all text
        if not content or len(content.strip()) < 100:
            content = soup.get_text()
        
        return content
        
    def _parse_pdf_content(self, pdf_content: bytes, source: str) -> Dict:
        """Parse PDF content and extract text."""
        if not PDF_SUPPORT:
            raise ImportError("PyPDF2 not available for PDF parsing")
            
        try:
            from io import BytesIO
            
            pdf_reader = PyPDF2.PdfReader(BytesIO(pdf_content))
            
            # Extract text from all pages
            text_content = ""
            for page in pdf_reader.pages:
                text_content += page.extract_text() + "\n"
                
            # Try to extract title from metadata
            title = ""
            if pdf_reader.metadata:
                title = pdf_reader.metadata.get('/Title', '')
                
            if not title and text_content:
                lines = text_content.split('\n')
                for line in lines:
                    if line.strip():
                        title = line.strip()[:100]
                        break
                        
            return {
                'source': source,
                'title': title,
                'content': self._clean_content(text_content),
                'publication_date': None,
                'content_type': 'pdf',
                'parsed_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to parse PDF: {e}")
            raise
            
    def _parse_raw_content(self, content: str, source: str = "raw") -> Dict:
        """Parse raw text content."""
        lines = content.split('\n')
        title = ""
        
        for line in lines:
            if line.strip():
                title = line.strip()[:100]
                break
                
        return {
            'source': source,
            'title': title,
            'content': self._clean_content(content),
            'publication_date': self._extract_date_from_text(content),
            'content_type': 'text',
            'parsed_at': datetime.utcnow().isoformat()
        }
        
    def _clean_content(self, content: str) -> str:
        """Clean and normalize content text."""
        # Remove excessive whitespace
        content = re.sub(r'\s+', ' ', content)
        
        # Remove special characters but keep important punctuation
        content = re.sub(r'[^\w\s.,;:!?()\-/\\&]', ' ', content)
        
        return content.strip()
    
    def _extract_publication_date(self, soup: BeautifulSoup, html_content: str) -> Optional[str]:
        """Extract publication date from HTML."""
        # Try meta tags first
        meta_selectors = [
            ('property', 'article:published_time'),
            ('property', 'og:article:published_time'),
            ('name', 'publication_date'),
            ('name', 'date'),
            ('name', 'publish_date'),
            ('name', 'DC.date.issued'),
            ('name', 'DC.Date.created')
        ]
        
        for attr, value in meta_selectors:
            meta = soup.find('meta', {attr: value})
            if meta and meta.get('content'):
                date_str = meta['content']
                parsed_date = self._parse_date_string(date_str)
                if parsed_date:
                    return parsed_date
        
        # Try time elements
        time_elements = soup.find_all('time')
        for time_elem in time_elements:
            if time_elem.get('datetime'):
                parsed_date = self._parse_date_string(time_elem['datetime'])
                if parsed_date:
                    return parsed_date
            
            # Check text content of time element
            text = time_elem.get_text().strip()
            if text:
                parsed_date = self._parse_date_string(text)
                if parsed_date:
                    return parsed_date
        
        # Look for date in specific elements
        date_classes = ['.date', '.publish-date', '.publication-date', '.post-date', '.article-date']
        for class_name in date_classes:
            elements = soup.select(class_name)
            for elem in elements:
                text = elem.get_text().strip()
                parsed_date = self._parse_date_string(text)
                if parsed_date:
                    return parsed_date
        
        # Fallback to text search
        return self._extract_date_from_text(html_content)
    
    def _extract_date_from_text(self, content: str) -> Optional[str]:
        """Extract date from text content."""
        # Look for "Last updated" or "Published" patterns
        update_patterns = [
            r'(?:last\s+updated|updated)(?:\s*on)?[\s:]*([^\n\r,;]+?)(?:\n|\r|,|;|$)',
            r'(?:published|posted|created)(?:\s*on)?[\s:]*([^\n\r,;]+?)(?:\n|\r|,|;|$)',
            r'(?:date)[\s:]*([^\n\r,;]+?)(?:\n|\r|,|;|$)'
        ]
        
        for pattern in update_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                date_text = match.group(1).strip()
                # Clean up common suffixes
                date_text = re.sub(r'\s+(by|at|in)\s+.*$', '', date_text)
                parsed_date = self._parse_date_string(date_text)
                if parsed_date:
                    return parsed_date
        
        # Look for standalone date patterns
        date_patterns = [
            r'\b(\d{4}-\d{1,2}-\d{1,2})\b',
            r'\b(\d{1,2}[-/]\d{1,2}[-/]\d{4})\b',
            r'\b((?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4})\b',
            r'\b(\d{1,2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4})\b'
        ]
        
        for pattern in date_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                parsed_date = self._parse_date_string(match)
                if parsed_date:
                    return parsed_date
                
        return None
    
    def _parse_date_string(self, date_str: str) -> Optional[str]:
        """Parse date string into ISO format."""
        if not date_str or len(date_str.strip()) < 4:
            return None
            
        date_str = date_str.strip()
        
        # Remove common prefixes/suffixes
        date_str = re.sub(r'^(on|at|the)\s+', '', date_str, flags=re.IGNORECASE)
        date_str = re.sub(r'\s+(at|by|in|•|–|-)\s+.*$', '', date_str, flags=re.IGNORECASE)
        
        # Skip obviously invalid dates
        if re.match(r'^\d{1,3}-\d{1,2}-\d{1,2}$', date_str):
            return None
        
        # Try various date formats
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
                # Validate reasonable date range
                if 2000 <= dt.year <= 2030:
                    return dt.date().isoformat()
            except ValueError:
                continue
        
        return None
        
    def _rate_limit(self):
        """Implement rate limiting for web requests."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.config.RATE_LIMIT_DELAY:
            sleep_time = self.config.RATE_LIMIT_DELAY - time_since_last
            time.sleep(sleep_time)
            
        self.last_request_time = time.time()
