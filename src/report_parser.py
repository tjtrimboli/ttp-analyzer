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
        
        # Set up session headers
        self.session.headers.update({
            'User-Agent': self.config.USER_AGENT
        })
        
        # Rate limiting
        self.last_request_time = 0
        
    def parse_report(self, source: Union[str, Path]) -> Optional[Dict]:
        """
        Parse a report from various sources.
        
        Args:
            source: URL, file path, or content string
            
        Returns:
            Dictionary containing parsed report data
        """
        self.logger.debug(f"Parsing report from: {source}")
        
        try:
            if isinstance(source, (str, Path)) and self._is_url(str(source)):
                return self._parse_web_report(str(source))
            elif isinstance(source, (str, Path)) and self._is_file_path(str(source)):
                return self._parse_file_report(Path(source))
            else:
                # Treat as raw content
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
        """Parse a report from a web URL."""
        self._rate_limit()
        
        try:
            # Use shorter timeout to avoid hanging
            response = self.session.get(url, timeout=15)
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
            for element in soup(["script", "style", "nav", "header", "footer"]):
                element.decompose()
            
            # Extract title
            title = ""
            if soup.title:
                title = soup.title.string.strip() if soup.title.string else ""
            elif soup.h1:
                title = soup.h1.get_text().strip()
            
            # Simple content extraction - try common content containers
            content = ""
            
            # Try main content areas first
            content_selectors = ['article', 'main', '.content', '.post-content', '.entry-content']
            for selector in content_selectors:
                try:
                    elements = soup.select(selector)
                    if elements:
                        content = elements[0].get_text()
                        break
                except:
                    continue
            
            # Fallback to all paragraphs
            if not content or len(content.strip()) < 200:
                paragraphs = soup.find_all('p')
                content = ' '.join([p.get_text().strip() for p in paragraphs])
            
            # Final fallback - all text
            if not content or len(content.strip()) < 100:
                content = soup.get_text()
            
            # Clean content
            cleaned_content = self._clean_content(content)
            
            # Extract publication date - simple approach
            pub_date = self._extract_simple_date(soup, html_content)
            
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
                
            # Try to extract title from metadata or first page
            title = ""
            if pdf_reader.metadata:
                title = pdf_reader.metadata.get('/Title', '')
                
            if not title and text_content:
                # Use first non-empty line as title
                lines = text_content.split('\n')
                for line in lines:
                    if line.strip():
                        title = line.strip()[:100]  # Limit title length
                        break
                        
            return {
                'source': source,
                'title': title,
                'content': self._clean_content(text_content),
                'publication_date': None,  # PDFs rarely have extractable dates
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
        
        # Try to extract title from first non-empty line
        for line in lines:
            if line.strip():
                title = line.strip()[:100]
                break
                
        return {
            'source': source,
            'title': title,
            'content': self._clean_content(content),
            'publication_date': self._extract_date(content),
            'content_type': 'text',
            'parsed_at': datetime.utcnow().isoformat()
        }
        
    def _clean_content(self, content: str) -> str:
        """Clean and normalize content text."""
        # Remove excessive whitespace
        content = re.sub(r'\s+', ' ', content)
        
        # Remove special characters but keep important punctuation
        content = re.sub(r'[^\w\s.,;:!?()\-/\\]', ' ', content)
        
        return content.strip()
        
    def _extract_simple_date(self, soup: BeautifulSoup, html_content: str) -> Optional[str]:
        """Simple date extraction focusing on common patterns."""
        
        # Try meta tags first
        meta_tags = soup.find_all('meta')
        for meta in meta_tags:
            if meta.get('name') in ['date', 'publish_date', 'publication_date'] or \
               meta.get('property') in ['article:published_time', 'og:article:published_time']:
                date_str = meta.get('content')
                if date_str:
                    parsed = self._parse_date_string(date_str)
                    if parsed:
                        return parsed
        
        # Try time elements
        time_elements = soup.find_all('time')
        for time_elem in time_elements:
            if time_elem.get('datetime'):
                parsed = self._parse_date_string(time_elem['datetime'])
                if parsed:
                    return parsed
        
        # Fallback to text search
        return self._extract_date(html_content)
        
    def _extract_date(self, content: str) -> Optional[str]:
        """Extract publication date from content using regex patterns."""
        # Look for common date patterns
        date_patterns = [
            r'\b(\d{4}-\d{1,2}-\d{1,2})\b',  # ISO format
            r'\b(\d{1,2}[-/]\d{1,2}[-/]\d{4})\b',  # US format
            r'\b((?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4})\b',
            r'\b(\d{1,2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4})\b'
        ]
        
        for pattern in date_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                parsed = self._parse_date_string(match)
                if parsed:
                    return parsed
                
        return None
    
    def _parse_date_string(self, date_str: str) -> Optional[str]:
        """Parse date string into ISO format."""
        if not date_str:
            return None
            
        date_str = date_str.strip()
        
        # Skip obviously invalid dates
        if len(date_str) < 4 or re.match(r'^\d{1,3}-\d{1,2}-\d{1,2}$', date_str):
            return None
        
        # Try common formats
        date_formats = [
            '%Y-%m-%d',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%SZ',
            '%m/%d/%Y',
            '%d/%m/%Y', 
            '%m-%d-%Y',
            '%B %d, %Y',
            '%d %B %Y',
            '%b %d, %Y'
        ]
        
        for fmt in date_formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                if 2000 <= dt.year <= 2030:
                    return dt.date().isoformat()
            except ValueError:
                continue
        
        return None
        
    def _rate_limit(self):
        """Implement basic rate limiting for web requests."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.config.RATE_LIMIT_DELAY:
            sleep_time = self.config.RATE_LIMIT_DELAY - time_since_last
            self.logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
            
        self.last_request_time = time.time()
