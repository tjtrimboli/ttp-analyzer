#!/usr/bin/env python3
"""
 MITRE ATT&CK TTP Analyzer for Threat Actor Evolution
A modular application for parsing threat intelligence reports and analyzing TTPs.

This version integrates the  TTP extraction and report parsing components
for significantly improved accuracy and reduced false negatives.
"""

import argparse
import sys
import logging
from pathlib import Path
from typing import Dict, List, Optional
import json
import time

from src.config import Config

# Try to import  components, fall back to original if needed
try:
    from src.ttp_extractor import TTPExtractor as TTPExtractor
    from src.report_parser import ReportParser as ReportParser
    _MODE = True
except ImportError:
    try:
        from src.ttp_extractor import TTPExtractor
        from src.report_parser import ReportParser
        _MODE = False
    except ImportError:
        print("Error: Could not import TTP extraction components.")
        print("Please ensure the  modules are properly installed.")
        sys.exit(1)

from src.timeline_analyzer import TimelineAnalyzer
from src.visualization import Visualizer


class TTPAnalyzer:
    """ TTP Analyzer with improved extraction capabilities."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the  TTP Analyzer."""
        self.config = Config(config_path)
        self.setup_logging()
        
        # Initialize components lazily for better performance
        self.parser = None
        self.extractor = None
        self.timeline_analyzer = None
        self.visualizer = None
        
        # Track performance metrics
        self.metrics = {
            'reports_processed': 0,
            'reports_failed': 0,
            'ttps_extracted': 0,
            'processing_time': 0
        }
        
    def _ensure_components_initialized(self):
        """Lazy initialization of components that require heavy resources."""
        if self.parser is None:
            self.parser = ReportParser(self.config)
            
        if self.extractor is None:
            self.extractor = TTPExtractor(self.config)
            
        if self.timeline_analyzer is None:
            self.timeline_analyzer = TimelineAnalyzer(self.config)
            
        if self.visualizer is None:
            self.visualizer = Visualizer(self.config)
        
    def setup_logging(self):
        """Configure  logging for the application."""
        log_level = getattr(logging, self.config.LOG_LEVEL.upper())
        
        # Ensure log directory exists
        log_file_path = Path(self.config.LOG_FILE)
        log_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Configure logging with  format
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config.LOG_FILE),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        
        # Log enhancement status
        if _MODE:
            self.logger.info(" TTP extraction components loaded successfully")
        else:
            self.logger.warning("Using original TTP extraction components - consider upgrading")
        
    def validate_actor_directory(self, actor_name: str) -> Path:
        """Validate that the actor directory exists and contains reports."""
        actor_dir = Path(self.config.GROUPS_DIR) / actor_name
        
        if not actor_dir.exists():
            raise FileNotFoundError(f"Actor directory not found: {actor_dir}")
            
        if not actor_dir.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {actor_dir}")
            
        # Check for reports file
        reports_file = actor_dir / "reports.txt"
        if not reports_file.exists():
            raise FileNotFoundError(f"Reports file not found: {reports_file}")
            
        return actor_dir
        
    def load_report_links(self, actor_dir: Path) -> List[str]:
        """Load report links from the actor's reports.txt file."""
        reports_file = actor_dir / "reports.txt"
        links = []
        
        try:
            with open(reports_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):  # Skip empty lines and comments
                        # Basic URL validation
                        if line.startswith(('http://', 'https://')):
                            links.append(line)
                        else:
                            self.logger.warning(f"Invalid URL format at line {line_num}: {line}")
        except Exception as e:
            self.logger.error(f"Error reading reports file: {e}")
            raise
            
        return links
        
    def analyze_actor(self, actor_name: str) -> Dict:
        """ analysis of a specific threat actor."""
        start_time = time.time()
        self.logger.info(f"Starting  analysis for threat actor: {actor_name}")
        
        # Ensure all components are initialized for analysis
        self._ensure_components_initialized()
        
        try:
            # Validate actor directory
            actor_dir = self.validate_actor_directory(actor_name)
            
            # Load report links
            report_links = self.load_report_links(actor_dir)
            self.logger.info(f"Found {len(report_links)} reports to analyze")
            
            if not report_links:
                raise ValueError("No valid report URLs found in reports.txt")
            
            #  report parsing with better error handling
            self.logger.info(" parsing of reports...")
            parsed_reports = []
            parsing_errors = []
            
            for i, link in enumerate(report_links, 1):
                self.logger.info(f"Processing report {i}/{len(report_links)}: {link}")
                try:
                    report_data = self.parser.parse_report(link)
                    if report_data and report_data.get('content'):
                        content_length = len(report_data['content'])
                        
                        # More lenient content validation for  parser
                        min_length = getattr(self.config, 'MIN_CONTENT_LENGTH', 50)
                        if content_length >= min_length:
                            parsed_reports.append(report_data)
                            self.metrics['reports_processed'] += 1
                            self.logger.debug(f"Successfully parsed {content_length} characters")
                        else:
                            self.logger.warning(f"Report too short ({content_length} chars): {link}")
                            parsing_errors.append(f"Content too short: {link}")
                    else:
                        self.logger.warning(f"No content extracted from: {link}")
                        parsing_errors.append(f"No content extracted: {link}")
                        
                except Exception as e:
                    self.logger.error(f"Failed to parse report {link}: {e}")
                    parsing_errors.append(f"Parse error: {link} - {str(e)}")
                    self.metrics['reports_failed'] += 1
                    continue
            
            if not parsed_reports:
                raise ValueError(f"No reports were successfully parsed. Errors: {parsing_errors}")
            
            self.logger.info(f"Successfully parsed {len(parsed_reports)}/{len(report_links)} reports")
            
            #  TTP extraction
            self.logger.info(" TTP extraction from parsed reports...")
            all_ttps = []
            extraction_stats = {
                'reports_with_ttps': 0,
                'total_matches': 0,
                'high_confidence_matches': 0,
                'technique_types': {'id': 0, 'name': 0, 'heuristic': 0}
            }
            
            for report in parsed_reports:
                try:
                    ttps = self.extractor.extract_ttps(report)
                    if ttps:
                        extraction_stats['reports_with_ttps'] += 1
                        extraction_stats['total_matches'] += len(ttps)
                        
                        # Track match types and confidence
                        for ttp in ttps:
                            match_type = ttp.get('match_type', 'unknown')
                            if match_type.startswith('id'):
                                extraction_stats['technique_types']['id'] += 1
                            elif match_type.startswith('name'):
                                extraction_stats['technique_types']['name'] += 1
                            elif match_type == 'heuristic':
                                extraction_stats['technique_types']['heuristic'] += 1
                                
                            if ttp.get('confidence', 0) >= 0.7:
                                extraction_stats['high_confidence_matches'] += 1
                        
                        all_ttps.extend(ttps)
                    
                except Exception as e:
                    self.logger.error(f"Failed to extract TTPs from report {report.get('source', 'unknown')}: {e}")
                    continue
            
            self.metrics['ttps_extracted'] = len(all_ttps)
            self.logger.info(f" extraction completed: {len(all_ttps)} TTP instances found")
            self.logger.info(f"Extraction stats: {extraction_stats}")
            
            if not all_ttps:
                self.logger.warning("No TTPs were extracted from any reports")
                return self._create__empty_results(actor_name, len(parsed_reports), extraction_stats)
            
            # Analyze timeline with  data
            self.logger.info("Analyzing TTP timeline...")
            timeline_data = self.timeline_analyzer.analyze_timeline(all_ttps)
            
            # Generate  visualizations
            self.logger.info("Generating  visualizations...")
            output_dir = Path(self.config.OUTPUT_DIR) / actor_name
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Create visualizations with  error handling
            visualization_results = {}
            
            heatmap_path = output_dir / "ttp_heatmap.png"
            timeline_path = output_dir / "ttp_timeline.png"
            frequency_path = output_dir / "ttp_frequency.png"
            
            try:
                self.visualizer.create_ttp_heatmap(
                    all_ttps, heatmap_path, title=f"{actor_name} TTP Heatmap ()"
                )
                visualization_results['heatmap'] = str(heatmap_path)
                self.logger.debug("Heatmap visualization created successfully")
            except Exception as e:
                self.logger.error(f"Failed to create heatmap: {e}")
                visualization_results['heatmap'] = None
            
            try:
                self.visualizer.create_timeline_chart(
                    timeline_data, timeline_path, title=f"{actor_name} TTP Timeline ()"
                )
                visualization_results['timeline'] = str(timeline_path)
                self.logger.debug("Timeline visualization created successfully")
            except Exception as e:
                self.logger.error(f"Failed to create timeline: {e}")
                visualization_results['timeline'] = None
            
            try:
                self.visualizer.create_frequency_analysis(
                    all_ttps, frequency_path, title=f"{actor_name} TTP Frequency Analysis ()"
                )
                visualization_results['frequency'] = str(frequency_path)
                self.logger.debug("Frequency analysis visualization created successfully")
            except Exception as e:
                self.logger.error(f"Failed to create frequency analysis: {e}")
                visualization_results['frequency'] = None
            
            # Build  results
            processing_time = time.time() - start_time
            self.metrics['processing_time'] = processing_time
            
            # Calculate additional statistics
            unique_techniques = len(set(ttp['technique_id'] for ttp in all_ttps))
            unique_tactics = len(set(ttp['tactic'] for ttp in all_ttps if ttp.get('tactic')))
            
            # Confidence statistics
            confidences = [ttp.get('confidence', 0) for ttp in all_ttps]
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0
            
            # Sub-technique analysis
            sub_techniques = [ttp for ttp in all_ttps if '.' in ttp['technique_id']]
            
            results = {
                'actor_name': actor_name,
                'analysis_mode': '' if _MODE else 'standard',
                'total_reports': len(parsed_reports),
                'reports_processed': len(report_links),
                'parsing_success_rate': len(parsed_reports) / len(report_links) if report_links else 0,
                'total_ttps': len(all_ttps),
                'unique_techniques': unique_techniques,
                'unique_tactics': unique_tactics,
                'sub_techniques_count': len(sub_techniques),
                'timeline_data': timeline_data,
                'date_range': timeline_data.get('date_range', {'start': None, 'end': None, 'duration_days': 0}),
                'extraction_stats': extraction_stats,
                'confidence_stats': {
                    'average': round(avg_confidence, 3),
                    'min': round(min(confidences), 3) if confidences else 0,
                    'max': round(max(confidences), 3) if confidences else 0,
                    'high_confidence_count': len([c for c in confidences if c >= 0.7])
                },
                'processing_metrics': self.metrics,
                'processing_time_seconds': round(processing_time, 2),
                'visualizations': visualization_results,
                'parsing_errors': parsing_errors[:10],  # Keep first 10 errors for debugging
                'enhancement_info': {
                    '_mode': _MODE,
                    'version': '2.0',
                    'features': ['_extraction', 'improved_parsing', 'better_confidence']
                }
            }
            
            # Save  results
            results_file = output_dir / "analysis_results.json"
            try:
                with open(results_file, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, default=str)
                self.logger.debug(f"Results saved to {results_file}")
            except Exception as e:
                self.logger.error(f"Failed to save results: {e}")
            
            # Save detailed TTP data for further analysis
            ttps_file = output_dir / "extracted_ttps.json"
            try:
                with open(ttps_file, 'w', encoding='utf-8') as f:
                    json.dump(all_ttps, f, indent=2, default=str)
                self.logger.debug(f"Detailed TTP data saved to {ttps_file}")
            except Exception as e:
                self.logger.error(f"Failed to save TTP data: {e}")
            
            self.logger.info(f" analysis complete. Results saved to: {output_dir}")
            return results
            
        except Exception as e:
            self.logger.error(f" analysis failed for {actor_name}: {e}")
            raise
    
    def _create__empty_results(self, actor_name: str, num_reports: int, extraction_stats: Dict) -> Dict:
        """Create  results structure when no TTPs are found."""
        return {
            'actor_name': actor_name,
            'analysis_mode': '' if _MODE else 'standard',
            'total_reports': num_reports,
            'total_ttps': 0,
            'unique_techniques': 0,
            'unique_tactics': 0,
            'sub_techniques_count': 0,
            'timeline_data': {
                'total_ttps': 0,
                'dated_ttps': 0,
                'date_range': {'start': None, 'end': None, 'duration_days': 0}
            },
            'extraction_stats': extraction_stats,
            'confidence_stats': {
                'average': 0,
                'min': 0,
                'max': 0,
                'high_confidence_count': 0
            },
            'date_range': {'start': None, 'end': None, 'duration_days': 0},
            'visualizations': {
                'heatmap': None,
                'timeline': None,
                'frequency': None
            },
            'processing_metrics': self.metrics,
            'enhancement_info': {
                '_mode': _MODE,
                'version': '2.0',
                'note': 'No TTPs extracted - consider reviewing report content and extraction settings'
            }
        }
            
    def list_available_actors(self) -> List[str]:
        """List all available threat actors in the groups directory."""
        groups_dir = Path(self.config.GROUPS_DIR)
        if not groups_dir.exists():
            return []
            
        actors = []
        for item in groups_dir.iterdir():
            if item.is_dir() and (item / "reports.txt").exists():
                actors.append(item.name)
                
        return sorted(actors)

    def update_attack_data(self) -> bool:
        """Update MITRE ATT&CK framework data with  feedback."""
        self.logger.info("Updating MITRE ATT&CK framework data...")
        
        # Only initialize the extractor for this operation
        if self.extractor is None:
            self.extractor = TTPExtractor(self.config)
        
        try:
            success = self.extractor.download_attack_data()
            if success:
                self.logger.info("ATT&CK data update completed successfully")
                
                # Display  statistics about the downloaded data
                techniques = self.extractor.get_all_techniques()
                self.logger.info(f"Loaded {len(techniques)} ATT&CK techniques")
                
                # Count techniques by tactic
                tactic_counts = {}
                sub_technique_count = 0
                
                for tid, technique_info in techniques.items():
                    tactic = technique_info.get('tactic', 'unknown')
                    tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
                    
                    if '.' in tid:  # Sub-technique
                        sub_technique_count += 1
                
                self.logger.info(f"Sub-techniques loaded: {sub_technique_count}")
                self.logger.info("Techniques by tactic:")
                for tactic, count in sorted(tactic_counts.items()):
                    self.logger.info(f"  {tactic}: {count}")
                
                # Test pattern compilation
                if hasattr(self.extractor, 'technique_id_patterns'):
                    id_patterns = len(self.extractor.technique_id_patterns)
                    name_patterns = len(self.extractor.technique_name_patterns)
                    self.logger.info(f"Compiled patterns - IDs: {id_patterns}, Names: {name_patterns}")
                
                return True
            else:
                self.logger.error("Failed to update ATT&CK data")
                return False
                
        except Exception as e:
            self.logger.error(f"ATT&CK data update failed: {e}")
            return False

    def get_system_info(self) -> Dict:
        """Get information about the current system configuration."""
        self._ensure_components_initialized()
        
        info = {
            '_mode': _MODE,
            'version': '2.0' if _MODE else '1.0',
            'config': {
                'min_confidence_threshold': self.config.MIN_CONFIDENCE_THRESHOLD,
                'heuristic_extraction': self.config.ENABLE_HEURISTIC_EXTRACTION,
                'max_report_size_mb': self.config.MAX_REPORT_SIZE_MB
            }
        }
        
        if self.extractor:
            techniques = self.extractor.get_all_techniques()
            info['techniques_loaded'] = len(techniques)
            
            if hasattr(self.extractor, 'technique_id_patterns'):
                info['patterns_compiled'] = {
                    'id_patterns': len(self.extractor.technique_id_patterns),
                    'name_patterns': len(self.extractor.technique_name_patterns)
                }
        
        return info


def main():
    """ main entry point for the application."""
    parser = argparse.ArgumentParser(
        description=" MITRE ATT&CK TTP Analyzer for threat actors",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ttp_analyzer.py --actor scattered_spider
  python ttp_analyzer.py --list-actors
  python ttp_analyzer.py --update-attack-data
  python ttp_analyzer.py --system-info
        """
    )
    
    parser.add_argument(
        '--actor', '-a',
        type=str,
        help='Name of the threat actor to analyze'
    )
    
    parser.add_argument(
        '--list-actors', '-l',
        action='store_true',
        help='List all available threat actors'
    )
    
    parser.add_argument(
        '--update-attack-data', '-u',
        action='store_true',
        help='Download and update MITRE ATT&CK framework data'
    )
    
    parser.add_argument(
        '--config', '-c',
        type=str,
        help='Path to custom configuration file'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--system-info', '-s',
        action='store_true',
        help='Display system information and enhancement status'
    )
    
    args = parser.parse_args()
    
    try:
        # Initialize  analyzer
        analyzer = TTPAnalyzer(args.config)
        
        # Override log level if verbose
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
            analyzer.logger.info("Verbose logging enabled")
        
        # Display system info if requested
        if args.system_info:
            info = analyzer.get_system_info()
            print(f"\n=== TTP Analyzer System Information ===")
            print(f" Mode: {'✅ Enabled' if info['_mode'] else '❌ Standard'}")
            print(f"Version: {info['version']}")
            print(f"Techniques Loaded: {info.get('techniques_loaded', 'Unknown')}")
            if 'patterns_compiled' in info:
                patterns = info['patterns_compiled']
                print(f"ID Patterns: {patterns['id_patterns']}")
                print(f"Name Patterns: {patterns['name_patterns']}")
            print(f"Configuration:")
            for key, value in info['config'].items():
                print(f"  {key}: {value}")
            return
        
        # Update ATT&CK data if requested
        if args.update_attack_data:
            success = analyzer.update_attack_data()
            if success:
                print("✅ MITRE ATT&CK data updated successfully")
                if _MODE:
                    print("✅  extraction patterns compiled")
            else:
                print("❌ Failed to update MITRE ATT&CK data")
                sys.exit(1)
            return
        
        # List actors if requested
        if args.list_actors:
            actors = analyzer.list_available_actors()
            if actors:
                print("Available threat actors:")
                for actor in actors:
                    print(f"  - {actor}")
                print(f"\nTotal: {len(actors)} threat actors")
            else:
                print("No threat actors found in groups/ directory")
                print("Please create actor directories with reports.txt files")
            return
        
        # Validate actor argument
        if not args.actor:
            parser.error("Either --actor, --list-actors, --update-attack-data, or --system-info must be specified")
        
        # Run  analysis
        print(f"🔍 Starting  analysis for {args.actor}...")
        if _MODE:
            print("✅ Using  TTP extraction components")
        else:
            print("⚠️  Using standard components - consider upgrading for better results")
        
        results = analyzer.analyze_actor(args.actor)
        
        # Print  summary
        print(f"\n===  Analysis Summary for {results['actor_name']} ===")
        print(f"Analysis Mode: {results['analysis_mode'].title()}")
        print(f"Reports processed: {results['total_reports']}")
        print(f"Parsing success rate: {results['parsing_success_rate']:.1%}")
        print(f"TTPs extracted: {results['total_ttps']}")
        print(f"Unique techniques: {results['unique_techniques']}")
        print(f"Sub-techniques: {results['sub_techniques_count']}")
        
        #  metrics
        if 'confidence_stats' in results:
            conf_stats = results['confidence_stats']
            print(f"Average confidence: {conf_stats['average']:.2f}")
            print(f"High confidence TTPs: {conf_stats['high_confidence_count']}")
        
        if 'extraction_stats' in results:
            ext_stats = results['extraction_stats']
            print(f"Reports with TTPs: {ext_stats['reports_with_ttps']}")
            
            if ext_stats['technique_types']:
                types = ext_stats['technique_types']
                print(f"Match types - ID: {types['id']}, Name: {types['name']}, Heuristic: {types['heuristic']}")
        
        # Handle date range safely
        date_range = results['date_range']
        if date_range['start'] and date_range['end']:
            print(f"Date range: {date_range['start']} to {date_range['end']}")
        else:
            print("Date range: No valid dates found in reports")
        
        print(f"Processing time: {results.get('processing_time_seconds', 0):.1f} seconds")
        
        # Visualization status
        vis_results = results.get('visualizations', {})
        created_vis = [name for name, path in vis_results.items() if path]
        if created_vis:
            print(f"Visualizations created: {', '.join(created_vis)}")
            output_dir = Path(vis_results[created_vis[0]]).parent
            print(f"Results saved to: {output_dir}")
        
        # Show any parsing errors
        if results.get('parsing_errors'):
            error_count = len(results['parsing_errors'])
            print(f"⚠️  {error_count} parsing errors occurred (see logs for details)")
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
