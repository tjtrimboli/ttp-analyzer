"""
Enhanced Report Parser Module with improved content extraction and accuracy.
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
    """Enhanced parser for extracting content from threat intelligence reports."""
    
    def __init__(self, config):
        """Initialize the report parser."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        
        # Set up session headers to appear more like a real browser
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Rate limiting
        self.last_request_time = 0
        
    def parse_report(self, source: Union[str, Path]) -> Optional[Dict]:
        """
        Parse a report from various sources with enhanced content extraction.
        
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
        """Parse a report from a web URL with enhanced content extraction."""
        self._rate_limit()
        
        try:
            response = self.session.get(url, timeout=30)
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
        """Enhanced HTML content parsing with better extraction strategies."""
        if not BS4_SUPPORT:
            self.logger.warning("BeautifulSoup not available, using basic text extraction")
            return self._parse_raw_content(html_content, source)
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Remove unnecessary elements that don't contain useful content
            for tag in soup(["script", "style", "nav", "header", "footer", "sidebar", 
                            "menu", "advertisement", "ads", "cookie", "popup"]):
                tag.decompose()
            
            # Remove comments
            for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
                comment.extract()
            
            # Extract title with multiple fallback strategies
            title = self._extract_title(soup)
            
            # Enhanced content extraction with multiple strategies
            content = self._extract_main_content(soup)
            
            # Clean and validate content
            cleaned_content = self._clean_content(content)
            
            # Enhanced date extraction
            pub_date = self._extract_date_enhanced(html_content, soup)
            
            # Validate content quality
            if len(cleaned_content.strip()) < 100:
                self.logger.warning(f"Very short content extracted from {source}: {len(cleaned_content)} chars")
                # Try alternative extraction
                alt_content = self._extract_alternative_content(soup)
                if len(alt_content) > len(cleaned_content):
                    cleaned_content = self._clean_content(alt_content)
                    self.logger.debug(f"Used alternative extraction, new length: {len(cleaned_content)} chars")
            
            result = {
                'source': source,
                'title': title,
                'content': cleaned_content,
                'publication_date': pub_date,
                'content_type': 'html',
                'content_length': len(cleaned_content),
                'parsed_at': datetime.utcnow().isoformat()
            }
            
            self.logger.debug(f"Extracted {len(cleaned_content)} characters from HTML: {source}")
            return result
            
        except Exception as e:
            self.logger.error(f"Error parsing HTML content from {source}: {e}")
            return self._parse_raw_content(html_content, source)
    
    def _extract_title(self, soup: BeautifulSoup) -> str:
        """Extract title using multiple strategies."""
        title = ""
        
        # Strategy 1: HTML title tag
        if soup.title and soup.title.string:
            title = soup.title.string.strip()
        
        # Strategy 2: h1 tag
        if not title and soup.h1:
            title = soup.h1.get_text().strip()
        
        # Strategy 3: Open Graph title
        if not title:
            og_title = soup.find('meta', property='og:title')
            if og_title and og_title.get('content'):
                title = og_title['content'].strip()
        
        # Strategy 4: Article title class
        if not title:
            for selector in ['.article-title', '.post-title', '.entry-title', '.blog-title']:
                element = soup.select_one(selector)
                if element:
                    title = element.get_text().strip()
                    break
        
        return title[:200] if title else ""  # Limit title length
    
    def _extract_main_content(self, soup: BeautifulSoup) -> str:
        """Extract main content using multiple strategies."""
        content_strategies = [
            # Strategy 1: Look for semantic content containers
            lambda: self._extract_by_semantic_tags(soup),
            # Strategy 2: Look for content-related class names
            lambda: self._extract_by_content_classes(soup),
            # Strategy 3: Extract all paragraph content
            lambda: self._extract_paragraph_content(soup),
            # Strategy 4: Extract all text content as fallback
            lambda: soup.get_text()
        ]
        
        for strategy in content_strategies:
            try:
                content = strategy()
                if content and len(content.strip()) > 200:  # Minimum content threshold
                    return content
            except Exception as e:
                self.logger.debug(f"Content extraction strategy failed: {e}")
                continue
        
        return soup.get_text()  # Final fallback
    
    def _extract_by_semantic_tags(self, soup: BeautifulSoup) -> str:
        """Extract content using semantic HTML tags."""
        content_parts = []
        
        # Look for semantic content containers
        for tag in ['article', 'main', 'section']:
            elements = soup.find_all(tag)
            for element in elements:
                text = element.get_text()
                if len(text.strip()) > 100:  # Only include substantial content
                    content_parts.append(text)
        
        return '\n'.join(content_parts)
    
    def _extract_by_content_classes(self, soup: BeautifulSoup) -> str:
        """Extract content by looking for content-related CSS classes."""
        content_selectors = [
            '.content', '.main-content', '.post-content', '.article-content',
            '.entry-content', '.blog-content', '.text-content', '.body-content',
            '.article-body', '.post-body', '.story-body', '.report-content',
            '[role="main"]', '.container .row', '.blog-post', '.article'
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
        """Extract content from paragraphs and list items."""
        content_parts = []
        
        # Extract paragraphs
        for p in soup.find_all('p'):
            text = p.get_text().strip()
            if len(text) > 20:  # Skip very short paragraphs
                content_parts.append(text)
        
        # Extract list items that might contain substantial content
        for li in soup.find_all('li'):
            text = li.get_text().strip()
            if len(text) > 30:  # Only substantial list items
                content_parts.append(text)
        
        # Extract div elements that might contain text content
        for div in soup.find_all('div'):
            # Only get direct text, not nested elements
            direct_text = ''.join(div.find_all(string=True, recursive=False)).strip()
            if len(direct_text) > 50:
                content_parts.append(direct_text)
        
        return '\n'.join(content_parts)
    
    def _extract_alternative_content(self, soup: BeautifulSoup) -> str:
        """Alternative content extraction for difficult pages."""
        # Try extracting from all text-containing elements
        text_elements = soup.find_all(['p', 'div', 'span', 'li', 'td', 'th'])
        content_parts = []
        
        for elem in text_elements:
            text = elem.get_text().strip()
            if len(text) > 15 and text not in content_parts:  # Avoid duplicates
                content_parts.append(text)
        
        return '\n'.join(content_parts)
    
    def _extract_date_enhanced(self, html_content: str, soup: BeautifulSoup) -> Optional[str]:
        """Enhanced date extraction with multiple strategies."""
        # Strategy 1: Look for structured data
        structured_date = self._extract_structured_date(soup)
        if structured_date:
            return structured_date
        
        # Strategy 2: Look for meta tags
        meta_date = self._extract_meta_date(soup)
        if meta_date:
            return meta_date
        
        # Strategy 3: Look for date patterns in text
        text_date = self._extract_date_from_text(html_content)
        if text_date:
            return text_date
        
        return None
    
    def _extract_structured_date(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract date from structured data."""
        # Look for JSON-LD structured data
        scripts = soup.find_all('script', type='application/ld+json')
        for script in scripts:
            try:
                import json
                data = json.loads(script.string)
                for date_field in ['datePublished', 'dateCreated', 'dateModified']:
                    if date_field in data:
                        return self._parse_date_string(data[date_field])
            except:
                continue
        
        return None
    
    def _extract_meta_date(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract date from meta tags."""
        meta_selectors = [
            ('meta', {'property': 'article:published_time'}),
            ('meta', {'name': 'pubdate'}),
            ('meta', {'name': 'date'}),
            ('meta', {'property': 'og:published_time'}),
            ('meta', {'name': 'DC.date.created'}),
            ('time', {'datetime': True})
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
    
    def _extract_date_from_text(self, content: str) -> Optional[str]:
        """Extract date from text content using regex patterns."""
        date_patterns = [
            r'\b(\d{4}[-/]\d{1,2}[-/]\d{1,2})\b',
            r'\b(\d{1,2}[-/]\d{1,2}[-/]\d{4})\b',
            r'\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b',
            r'\b\d{1,2}\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}\b'
        ]
        
        for pattern in date_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                date_str = matches[0] if isinstance(matches[0], str) else ' '.join(matches[0])
                parsed_date = self._parse_date_string(date_str)
                if parsed_date:
                    return parsed_date
        
        return None
    
    def _parse_date_string(self, date_str: str) -> Optional[str]:
        """Parse various date string formats into ISO format."""
        if not date_str:
            return None
        
        date_str = date_str.strip()
        
        # Handle ISO format dates (may include timezone)
        if 'T' in date_str:
            try:
                dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                return dt.date().isoformat()
            except:
                pass
        
        # Try various date formats
        date_formats = [
            '%Y-%m-%d',
            '%m/%d/%Y',
            '%d/%m/%Y',
            '%m-%d-%Y',
            '%d-%m-%Y',
            '%B %d, %Y',
            '%d %B %Y',
            '%b %d %Y',
            '%b %d, %Y',
            '%Y/%m/%d',
            '%d.%m.%Y',
            '%m.%d.%Y'
        ]
        
        for fmt in date_formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                if 1900 <= dt.year <= 2030:
                    return dt.date().isoformat()
            except ValueError:
                continue
        
        return None
    
    def _parse_pdf_content(self, pdf_content: bytes, source: str) -> Dict:
        """Parse PDF content with enhanced text extraction."""
        if not PDF_SUPPORT:
            raise ImportError("PyPDF2 not available for PDF parsing")
        
        try:
            from io import BytesIO
            
            pdf_reader = PyPDF2.PdfReader(BytesIO(pdf_content))
            
            # Extract text from all pages
            text_content = ""
            page_count = len(pdf_reader.pages)
            
            for i, page in enumerate(pdf_reader.pages):
                try:
                    page_text = page.extract_text()
                    if page_text:
                        text_content += page_text + "\n"
                except Exception as e:
                    self.logger.debug(f"Failed to extract text from PDF page {i}: {e}")
                    continue
            
            # Extract title from metadata or first meaningful content
            title = ""
            if pdf_reader.metadata:
                title = pdf_reader.metadata.get('/Title', '') or pdf_reader.metadata.get('/Subject', '')
            
            if not title and text_content:
                # Use first substantial line as title
                lines = [line.strip() for line in text_content.split('\n') if line.strip()]
                for line in lines[:5]:  # Check first 5 lines
                    if 5 < len(line) < 100:  # Reasonable title length
                        title = line
                        break
            
            cleaned_content = self._clean_content(text_content)
            
            return {
                'source': source,
                'title': title,
                'content': cleaned_content,
                'publication_date': None,
                'content_type': 'pdf',
                'content_length': len(cleaned_content),
                'page_count': page_count,
                'parsed_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to parse PDF from {source}: {e}")
            raise
    
    def _parse_raw_content(self, content: str, source: str = "raw") -> Dict:
        """Parse raw text content with enhanced cleaning."""
        lines = [line.strip() for line in content.split('\n') if line.strip()]
        
        # Extract title from first meaningful line
        title = ""
        for line in lines[:3]:
            if 5 < len(line) < 100:
                title = line
                break
        
        cleaned_content = self._clean_content(content)
        
        return {
            'source': source,
            'title': title,
            'content': cleaned_content,
            'publication_date': self._extract_date_from_text(content),
            'content_type': 'text',
            'content_length': len(cleaned_content),
            'parsed_at': datetime.utcnow().isoformat()
        }
    
    def _clean_content(self, content: str) -> str:
        """Enhanced content cleaning and normalization."""
        if not content:
            return ""
        
        # Remove excessive whitespace and normalize line breaks
        content = re.sub(r'\s+', ' ', content)
        content = re.sub(r'\n\s*\n', '\n', content)
        
        # Remove common website artifacts
        artifacts = [
            r'Cookie\s+Policy', r'Privacy\s+Policy', r'Terms\s+of\s+Service',
            r'Subscribe\s+to\s+newsletter', r'Follow\s+us\s+on', r'Share\s+this\s+article',
            r'Related\s+Articles?', r'You\s+might\s+also\s+like', r'Advertisement',
            r'\bAd\b', r'Sponsored\s+Content', r'Click\s+here\s+to'
        ]
        
        for artifact in artifacts:
            content = re.sub(artifact, '', content, flags=re.IGNORECASE)
        
        # Remove URLs that aren't part of meaningful content
        content = re.sub(r'https?://\S+', '', content)
        
        # Remove email addresses
        content = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '', content)
        
        # Clean up remaining artifacts
        content = re.sub(r'[^\w\s.,;:!?()\[\]{}-]', ' ', content)
        content = re.sub(r'\s+', ' ', content)
        
        return content.strip()
    
    def _rate_limit(self):
        """Implement rate limiting for web requests."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.config.RATE_LIMIT_DELAY:
            sleep_time = self.config.RATE_LIMIT_DELAY - time_since_last
            self.logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
