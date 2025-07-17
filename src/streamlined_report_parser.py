"""
Streamlined Report Parser - Performance-focused version
Simplified parsing with focus on extracting TTP-relevant content efficiently.
"""

import requests
import logging
import re
from typing import Dict, Optional
from pathlib import Path
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


class StreamlinedReportParser:
    """Fast, efficient report parser focused on extracting TTP-relevant content."""
    
    def __init__(self, config):
        """Initialize the streamlined parser."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        
        # Simple, efficient headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,*/*;q=0.9'
        })
        
        self.last_request_time = 0
        
    def parse_report(self, source: str) -> Optional[Dict]:
        """Parse a report efficiently."""
        self.logger.debug(f"Parsing: {source}")
        
        try:
            if self._is_url(source):
                return self._parse_web_report(source)
            elif Path(source).exists():
                return self._parse_file_report(Path(source))
            else:
                return self._parse_raw_content(source)
        except Exception as e:
            self.logger.error(f"Parse failed for {source}: {e}")
            return None
    
    def _is_url(self, source: str) -> bool:
        """Quick URL check."""
        return source.startswith(('http://', 'https://'))
    
    def _parse_web_report(self, url: str) -> Dict:
        """Parse web report with minimal overhead."""
        self._rate_limit()
        
        try:
            response = self.session.get(url, timeout=self.config.REQUEST_TIMEOUT)
            response.raise_for_status()
            
            content_type = response.headers.get('content-type', '').lower()
            
            if 'pdf' in content_type:
                return self._parse_pdf_content(response.content, url)
            else:
                return self._parse_html_content(response.text, url)
                
        except Exception as e:
            self.logger.error(f"Failed to fetch {url}: {e}")
            raise
    
    def _parse_file_report(self, file_path: Path) -> Dict:
        """Parse local file efficiently."""
        if file_path.suffix.lower() == '.pdf':
            with open(file_path, 'rb') as f:
                return self._parse_pdf_content(f.read(), str(file_path))
        else:
            with open(file_path, 'r', encoding='utf-8') as f:
                return self._parse_raw_content(f.read(), str(file_path))
    
    def _parse_html_content(self, html_content: str, source: str) -> Dict:
        """Streamlined HTML parsing focused on speed."""
        if not BS4_SUPPORT:
            return self._parse_raw_content(html_content, source)
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Fast removal of unwanted elements
            for tag in soup(['script', 'style', 'nav', 'footer']):
                tag.decompose()
            
            # Quick title extraction
            title = ""
            if soup.title:
                title = soup.title.get_text().strip()
            elif soup.h1:
                title = soup.h1.get_text().strip()
            
            # Efficient content extraction - get all text
            content = soup.get_text()
            
            # Basic cleaning - normalize whitespace
            content = re.sub(r'\s+', ' ', content).strip()
            
            # Simple date extraction from common patterns
            pub_date = self._extract_date_simple(html_content)
            
            return {
                'source': source,
                'title': title[:200],  # Limit title length
                'content': content,
                'publication_date': pub_date,
                'content_type': 'html',
                'content_length': len(content),
                'parsed_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"HTML parsing error: {e}")
            return self._parse_raw_content(html_content, source)
    
    def _parse_pdf_content(self, pdf_content: bytes, source: str) -> Dict:
        """Streamlined PDF parsing."""
        if not PDF_SUPPORT:
            raise ImportError("PyPDF2 not available")
        
        try:
            from io import BytesIO
            pdf_reader = PyPDF2.PdfReader(BytesIO(pdf_content))
            
            # Extract text from all pages efficiently
            text_content = ""
            for page in pdf_reader.pages:
                try:
                    page_text = page.extract_text()
                    if page_text:
                        text_content += page_text + " "
                except:
                    continue
            
            # Basic cleaning
            text_content = re.sub(r'\s+', ' ', text_content).strip()
            
            # Extract title from metadata or first line
            title = ""
            if pdf_reader.metadata and pdf_reader.metadata.get('/Title'):
                title = str(pdf_reader.metadata['/Title']).strip()
            elif text_content:
                # Use first non-empty line as title
                lines = [line.strip() for line in text_content.split('\n') if line.strip()]
                if lines:
                    title = lines[0][:200]
            
            return {
                'source': source,
                'title': title,
                'content': text_content,
                'publication_date': None,
                'content_type': 'pdf',
                'content_length': len(text_content),
                'page_count': len(pdf_reader.pages),
                'parsed_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"PDF parsing error: {e}")
            raise
    
    def _parse_raw_content(self, content: str, source: str = "raw") -> Dict:
        """Parse raw text content."""
        # Basic cleaning
        content = re.sub(r'\s+', ' ', content).strip()
        
        # Extract title from first line
        lines = [line.strip() for line in content.split('\n') if line.strip()]
        title = lines[0][:200] if lines else ""
        
        return {
            'source': source,
            'title': title,
            'content': content,
            'publication_date': self._extract_date_simple(content),
            'content_type': 'text',
            'content_length': len(content),
            'parsed_at': datetime.utcnow().isoformat()
        }
    
    def _extract_date_simple(self, content: str) -> Optional[str]:
        """Simple, fast date extraction."""
        # Look for common date patterns
        date_patterns = [
            r'\b(\d{4}-\d{1,2}-\d{1,2})\b',  # ISO format
            r'\b(\d{1,2}[-/]\d{1,2}[-/]\d{4})\b',  # US format
            r'(?:published|updated|date).*?(\d{4}-\d{1,2}-\d{1,2})',  # With keywords
        ]
        
        for pattern in date_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                date_str = matches[0]
                # Simple validation
                try:
                    datetime.strptime(date_str, '%Y-%m-%d')
                    return date_str
                except:
                    continue
        
        return None
    
    def _rate_limit(self):
        """Simple rate limiting."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.config.RATE_LIMIT_DELAY:
            sleep_time = self.config.RATE_LIMIT_DELAY - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
