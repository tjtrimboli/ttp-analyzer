#!/usr/bin/env python3
"""
MITRE ATT&CK TTP Analyzer
Combines the best of enhanced and streamlined approaches with configurable performance modes.

Performance Modes:
- fast: Maximum speed, regex-only extraction (10-30x faster)
- balanced: Good speed with enhanced accuracy (recommended)
- comprehensive: Maximum accuracy with full feature set
"""

import argparse
import sys
import logging
import json
import time
from pathlib import Path
from typing import Dict, List, Optional
from collections import Counter

# Import components
from src.config import Config
from src.timeline_analyzer import TimelineAnalyzer
from src.visualization import Visualizer

# Import the new components we just created
from src.ttp_extractor import TTPExtractor
from src.report_parser import ReportParser


class TTPAnalyzer:
    """
    TTP analyzer with configurable performance modes.
    
    This combines the best features from both the enhanced and streamlined
    approaches, allowing users to choose their preferred speed/accuracy tradeoff.
    """
    
    def __init__(self, config_path: Optional[str] = None, performance_mode: Optional[str] = None):
        """Initialize the analyzer."""
        self.config = Config(config_path)
        
        # Override performance mode if specified
        if performance_mode:
            self.config.PERFORMANCE_MODE = performance_mode
        
        # Ensure performance mode is set
        if not hasattr(self.config, 'PERFORMANCE_MODE'):
            self.config.PERFORMANCE_MODE = 'balanced'
        
        self.performance_mode = self.config.PERFORMANCE_MODE.lower()
        
        self.setup_logging()
        
        # Initialize components with approach
        self.parser = ReportParser(self.config)
        self.extractor = TTPExtractor(self.config)
        self.timeline_analyzer = TimelineAnalyzer(self.config)
        self.visualizer = Visualizer(self.config)
        
        # Performance tracking
        self.metrics = {
            'reports_processed': 0,
            'reports_failed': 0,
            'ttps_extracted': 0,
            'processing_time': 0,
            'performance_mode': self.performance_mode
        }
        
        self.logger.info(f"TTP Analyzer initialized in '{self.performance_mode}' mode")
        
    def setup_logging(self):
        """Setup logging configuration."""
        log_level = getattr(logging, self.config.LOG_LEVEL.upper())
        
        # Ensure log directory exists
        log_file_path = Path(self.config.LOG_FILE)
        log_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config.LOG_FILE),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        
    def analyze_actor(self, actor_name: str) -> Dict:
        """Analyze a threat actor with approach."""
        start_time = time.time()
        self.logger.info(f"Starting analysis for {actor_name} in {self.performance_mode} mode")
        
        try:
            # Validate actor directory
            actor_dir = self._validate_actor_directory(actor_name)
            
            # Load report links
            report_links = self._load_report_links(actor_dir)
            self.logger.info(f"Found {len(report_links)} reports to analyze")
            
            if not report_links:
                raise ValueError("No valid report URLs found in reports.txt")
            
            # Parse reports with parser
            self.logger.info("Parsing reports with parser...")
            parsed_reports = []
            parsing_errors = []
            
            for i, link in enumerate(report_links, 1):
                self.logger.info(f"Processing report {i}/{len(report_links)}: {link}")
                try:
                    report_data = self.parser.parse_report(link)
                    if report_data and report_data.get('content'):
                        content_length = len(report_data['content'])
                        
                        # Adaptive content validation based on performance mode
                        min_length = self._get_min_content_length()
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
            
            # Extract TTPs with extractor
            self.logger.info("Extracting TTPs with extractor...")
            all_ttps = []
            extraction_stats = {
                'reports_with_ttps': 0,
                'total_matches': 0,
                'high_confidence_matches': 0,
                'match_types': Counter(),
                'performance_mode': self.performance_mode
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
                            extraction_stats['match_types'][match_type] += 1
                            
                            if ttp.get('confidence', 0) >= 0.7:
                                extraction_stats['high_confidence_matches'] += 1
                        
                        all_ttps.extend(ttps)
                    
                except Exception as e:
                    self.logger.error(f"Failed to extract TTPs from report {report.get('source', 'unknown')}: {e}")
                    continue
            
            self.metrics['ttps_extracted'] = len(all_ttps)
            self.logger.info(f"TTP extraction completed: {len(all_ttps)} TTP instances found")
            self.logger.info(f"Extraction stats: {dict(extraction_stats['match_types'])}")
            
            if not all_ttps:
                self.logger.warning("No TTPs were extracted from any reports")
                return self._create_empty_results(actor_name, len(parsed_reports), extraction_stats, parsing_errors)
            
            # Analyze timeline
            self.logger.info("Analyzing TTP timeline...")
            timeline_data = self.timeline_analyzer.analyze_timeline(all_ttps)
            
            # Generate visualizations
            self.logger.info("Generating visualizations...")
            output_dir = Path(self.config.OUTPUT_DIR) / actor_name
            output_dir.mkdir(parents=True, exist_ok=True)
            
            visualization_results = self._create_visualizations(all_ttps, timeline_data, output_dir, actor_name)
            
            # Build comprehensive results
            processing_time = time.time() - start_time
            self.metrics['processing_time'] = processing_time
            
            results = self._build_results(
                actor_name, parsed_reports, all_ttps, timeline_data, 
                extraction_stats, visualization_results, output_dir, 
                processing_time, parsing_errors
            )
            
            # Save results
            self._save_results(results, all_ttps, output_dir)
            
            self.logger.info(f"analysis complete in {processing_time:.1f}s")
            return results
            
        except Exception as e:
            self.logger.error(f"analysis failed for {actor_name}: {e}")
            raise
    
    def _validate_actor_directory(self, actor_name: str) -> Path:
        """Validate actor directory exists and contains reports."""
        actor_dir = Path(self.config.GROUPS_DIR) / actor_name
        
        if not actor_dir.exists() or not actor_dir.is_dir():
            raise FileNotFoundError(f"Actor directory not found: {actor_dir}")
        
        reports_file = actor_dir / "reports.txt"
        if not reports_file.exists():
            raise FileNotFoundError(f"Reports file not found: {reports_file}")
        
        return actor_dir
        
    def _load_report_links(self, actor_dir: Path) -> List[str]:
        """Load report links from reports.txt file."""
        reports_file = actor_dir / "reports.txt"
        links = []
        
        try:
            with open(reports_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if line.startswith(('http://', 'https://')):
                            links.append(line)
                        else:
                            self.logger.warning(f"Invalid URL format at line {line_num}: {line}")
        except Exception as e:
            self.logger.error(f"Error reading reports file: {e}")
            raise
            
        return links
    
    def _get_min_content_length(self) -> int:
        """Get minimum content length based on performance mode."""
        if self.performance_mode == 'fast':
            return 50
        elif self.performance_mode == 'balanced':
            return 100
        else:  # comprehensive
            return 150
    
    def _create_visualizations(self, ttps: List[Dict], timeline_data: Dict, 
                             output_dir: Path, actor_name: str) -> Dict:
        """Create visualizations and return results."""
        visualization_results = {}
        
        try:
            # Heatmap
            heatmap_path = output_dir / "ttp_heatmap.png"
            self.visualizer.create_ttp_heatmap(
                ttps, heatmap_path, title=f"{actor_name} TTP Heatmap ({self.performance_mode.title()} Mode)"
            )
            visualization_results['heatmap'] = str(heatmap_path)
            self.logger.debug("Heatmap visualization created successfully")
        except Exception as e:
            self.logger.error(f"Failed to create heatmap: {e}")
            visualization_results['heatmap'] = None
        
        try:
            # Timeline
            timeline_path = output_dir / "ttp_timeline.png"
            self.visualizer.create_timeline_chart(
                timeline_data, timeline_path, title=f"{actor_name} TTP Timeline ({self.performance_mode.title()} Mode)"
            )
            visualization_results['timeline'] = str(timeline_path)
            self.logger.debug("Timeline visualization created successfully")
        except Exception as e:
            self.logger.error(f"Failed to create timeline: {e}")
            visualization_results['timeline'] = None
        
        try:
            # Frequency analysis
            frequency_path = output_dir / "ttp_frequency.png"
            self.visualizer.create_frequency_analysis(
                ttps, frequency_path, title=f"{actor_name} TTP Analysis ({self.performance_mode.title()} Mode)"
            )
            visualization_results['frequency'] = str(frequency_path)
            self.logger.debug("Frequency analysis visualization created successfully")
        except Exception as e:
            self.logger.error(f"Failed to create frequency analysis: {e}")
            visualization_results['frequency'] = None
        
        return visualization_results
    
    def _build_results(self, actor_name: str, reports: List[Dict], ttps: List[Dict],
                      timeline_data: Dict, extraction_stats: Dict, 
                      visualization_results: Dict, output_dir: Path,
                      processing_time: float, parsing_errors: List[str]) -> Dict:
        """Build comprehensive results structure."""
        # Calculate statistics
        unique_techniques = len(set(ttp['technique_id'] for ttp in ttps))
        unique_tactics = len(set(ttp['tactic'] for ttp in ttps if ttp.get('tactic')))
        sub_techniques = [ttp for ttp in ttps if '.' in ttp['technique_id']]
        
        # Confidence statistics
        confidences = [ttp.get('confidence', 0) for ttp in ttps]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0
        
        # Performance statistics
        extractor_stats = self.extractor.get_performance_stats()
        
        return {
            'actor_name': actor_name,
            'analysis_version': 'v1.0',
            'performance_mode': self.performance_mode,
            'total_reports': len(reports),
            'reports_processed': len(report_links := [r['source'] for r in reports]),
            'parsing_success_rate': len(reports) / len(report_links) if report_links else 0,
            'total_ttps': len(ttps),
            'unique_techniques': unique_techniques,
            'unique_tactics': unique_tactics,
            'sub_techniques_count': len(sub_techniques),
            'timeline_data': timeline_data,
            'date_range': timeline_data.get('date_range', {
                'start': None, 'end': None, 'duration_days': 0
            }),
            'extraction_stats': {
                'reports_with_ttps': extraction_stats['reports_with_ttps'],
                'total_matches': extraction_stats['total_matches'],
                'high_confidence_matches': extraction_stats['high_confidence_matches'],
                'match_types': dict(extraction_stats['match_types']),
                'performance_mode': extraction_stats['performance_mode']
            },
            'confidence_stats': {
                'average': round(avg_confidence, 3),
                'min': round(min(confidences), 3) if confidences else 0,
                'max': round(max(confidences), 3) if confidences else 0,
                'high_confidence_count': len([c for c in confidences if c >= 0.7])
            },
            'performance_metrics': {
                'processing_time_seconds': round(processing_time, 2),
                'reports_per_second': len(reports) / processing_time if processing_time > 0 else 0,
                'ttps_per_second': len(ttps) / processing_time if processing_time > 0 else 0,
                'mode_stats': extractor_stats
            },
            'visualizations': visualization_results,
            'output_directory': str(output_dir),
            'parsing_errors': parsing_errors[:10],  # Keep first 10 for debugging
            'system_info': {
                'analyzer': True,
                'performance_mode': self.performance_mode,
                'features_enabled': self._get_enabled_features(),
                'analysis_timestamp': time.time()
            }
        }
    
    def _get_enabled_features(self) -> List[str]:
        """Get list of enabled features based on performance mode."""
        features = ['regex_id_extraction']
        
        if self.performance_mode in ['balanced', 'comprehensive']:
            features.append('name_context_extraction')
        
        if self.performance_mode == 'comprehensive':
            features.extend(['heuristic_extraction', 'enhanced_validation', 'comprehensive_parsing'])
        
        return features
    
    def _create_empty_results(self, actor_name: str, num_reports: int, 
                            extraction_stats: Dict, parsing_errors: List[str]) -> Dict:
        """Create results structure when no TTPs are found."""
        return {
            'actor_name': actor_name,
            'analysis_version': 'v1.0',
            'performance_mode': self.performance_mode,
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
            'confidence_stats': {'average': 0, 'min': 0, 'max': 0, 'high_confidence_count': 0},
            'performance_metrics': self.metrics,
            'visualizations': {'heatmap': None, 'timeline': None, 'frequency': None},
            'parsing_errors': parsing_errors,
            'system_info': {
                'analyzer': True,
                'performance_mode': self.performance_mode,
                'note': 'No TTPs extracted - consider reviewing report content or trying comprehensive mode'
            }
        }
    
    def _save_results(self, results: Dict, ttps: List[Dict], output_dir: Path):
        """Save analysis results and detailed TTP data."""
        try:
            # Save main results
            results_file = output_dir / "analysis_results.json"
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
            self.logger.debug(f"Results saved to {results_file}")
            
            # Save detailed TTP data
            ttps_file = output_dir / "extracted_ttps.json"
            with open(ttps_file, 'w', encoding='utf-8') as f:
                json.dump(ttps, f, indent=2, default=str)
            self.logger.debug(f"Detailed TTP data saved to {ttps_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
    
    def list_available_actors(self) -> List[str]:
        """List all available threat actors."""
        groups_dir = Path(self.config.GROUPS_DIR)
        if not groups_dir.exists():
            return []
        
        actors = []
        for item in groups_dir.iterdir():
            if item.is_dir() and (item / "reports.txt").exists():
                actors.append(item.name)
        
        return sorted(actors)
    
    def update_attack_data(self) -> bool:
        """Update MITRE ATT&CK framework data."""
        self.logger.info("Updating MITRE ATT&CK framework data...")
        
        try:
            success = self.extractor.download_attack_data()
            if success:
                self.logger.info("ATT&CK data update completed successfully")
                
                # Display statistics about the downloaded data
                techniques = self.extractor.get_all_techniques()
                stats = self.extractor.get_performance_stats()
                
                self.logger.info(f"Loaded {len(techniques)} ATT&CK techniques")
                self.logger.info(f"Performance mode: {stats['performance_mode']}")
                self.logger.info(f"Enabled extraction methods: {stats['extraction_methods']}")
                
                return True
            else:
                self.logger.error("Failed to update ATT&CK data")
                return False
                
        except Exception as e:
            self.logger.error(f"ATT&CK data update failed: {e}")
            return False
    
    def get_system_info(self) -> Dict:
        """Get system information and performance statistics."""
        extractor_stats = self.extractor.get_performance_stats()
        
        return {
            'analyzer_version': 'v1.0',
            'performance_mode': self.performance_mode,
            'techniques_loaded': len(self.extractor.get_all_techniques()),
            'extraction_methods': extractor_stats.get('extraction_methods', []),
            'config': {
                'min_confidence_threshold': self.config.MIN_CONFIDENCE_THRESHOLD,
                'heuristic_extraction': getattr(self.config, 'ENABLE_HEURISTIC_EXTRACTION', True),
                'max_report_size_mb': getattr(self.config, 'MAX_REPORT_SIZE_MB', 50),
                'rate_limit_delay': getattr(self.config, 'RATE_LIMIT_DELAY', 1.0)
            },
            'performance_stats': extractor_stats,
            'available_modes': ['fast', 'balanced', 'comprehensive'],
            'current_mode_features': self._get_enabled_features()
        }


def main():
    """Main entry point for the TTP analyzer."""
    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK TTP Analyzer with configurable performance modes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Performance Modes:
  fast         - Maximum speed, regex-only extraction (10-30x faster)
  balanced     - Good speed with enhanced accuracy (recommended)
  comprehensive - Maximum accuracy with full feature set

Examples:
  python analyzer.py --actor scattered_spider
  python analyzer.py --actor apt1 --mode comprehensive
  python analyzer.py --list-actors
  python analyzer.py --update-attack-data
  python analyzer.py --system-info
        """
    )
    
    parser.add_argument('--actor', '-a', help='Name of the threat actor to analyze')
    parser.add_argument('--list-actors', '-l', action='store_true', help='List all available threat actors')
    parser.add_argument('--update-attack-data', '-u', action='store_true', help='Download and update MITRE ATT&CK framework data')
    parser.add_argument('--config', '-c', help='Path to custom configuration file')
    parser.add_argument('--mode', '-m', choices=['fast', 'balanced', 'comprehensive'], 
                       help='Performance mode (overrides config setting)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--system-info', '-s', action='store_true', help='Display system information')
    
    args = parser.parse_args()
    
    try:
        # Initialize analyzer
        analyzer = TTPAnalyzer(args.config, args.mode)
        
        # Override log level if verbose
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
            analyzer.logger.info("Verbose logging enabled")
        
        # Display system info if requested
        if args.system_info:
            info = analyzer.get_system_info()
            print(f"\n=== TTP Analyzer System Information ===")
            print(f"Version: {info['analyzer_version']}")
            print(f"Performance Mode: {info['performance_mode']}")
            print(f"Techniques Loaded: {info['techniques_loaded']}")
            print(f"Extraction Methods: {', '.join(info['extraction_methods'])}")
            print(f"Available Modes: {', '.join(info['available_modes'])}")
            print(f"Current Mode Features: {', '.join(info['current_mode_features'])}")
            print(f"\nConfiguration:")
            for key, value in info['config'].items():
                print(f"  {key}: {value}")
            return
        
        # Update ATT&CK data if requested
        if args.update_attack_data:
            success = analyzer.update_attack_data()
            if success:
                print("MITRE ATT&CK data updated successfully")
                print(f"extraction patterns compiled for {analyzer.performance_mode} mode")
            else:
                print("Failed to update MITRE ATT&CK data")
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
        
        # Run analysis
        print(f"Starting analysis for {args.actor}...")
        print(f"Performance mode: {analyzer.performance_mode}")
        print(f"Enabled features: {', '.join(analyzer._get_enabled_features())}")
        
        results = analyzer.analyze_actor(args.actor)
        
        # Print comprehensive summary
        print(f"\n=== Analysis Summary for {results['actor_name']} ===")
        print(f"Analysis Version: {results['analysis_version']}")
        print(f"Performance Mode: {results['performance_mode']}")
        print(f"Reports processed: {results['total_reports']}")
        print(f"Parsing success rate: {results['parsing_success_rate']:.1%}")
        print(f"TTPs extracted: {results['total_ttps']}")
        print(f"Unique techniques: {results['unique_techniques']}")
        print(f"Sub-techniques: {results['sub_techniques_count']}")
        
        # Performance metrics
        perf_metrics = results['performance_metrics']
        print(f"Processing time: {perf_metrics['processing_time_seconds']:.1f} seconds")
        print(f"Processing speed: {perf_metrics['reports_per_second']:.1f} reports/sec, {perf_metrics['ttps_per_second']:.1f} TTPs/sec")
        
        # Extraction statistics
        ext_stats = results['extraction_stats']
        print(f"Reports with TTPs: {ext_stats['reports_with_ttps']}")
        if ext_stats['match_types']:
            match_type_summary = ', '.join(f"{k}: {v}" for k, v in ext_stats['match_types'].items())
            print(f"Match types: {match_type_summary}")
        
        # Confidence statistics
        conf_stats = results['confidence_stats']
        print(f"Average confidence: {conf_stats['average']:.2f}")
        print(f"High confidence TTPs: {conf_stats['high_confidence_count']}")
        
        # Date range
        date_range = results['date_range']
        if date_range['start'] and date_range['end']:
            print(f"Date range: {date_range['start']} to {date_range['end']}")
        else:
            print("Date range: No valid dates found in reports")
        
        # Visualizations
        vis_results = results.get('visualizations', {})
        created_vis = [name for name, path in vis_results.items() if path]
        if created_vis:
            print(f"Visualizations created: {', '.join(created_vis)}")
            print(f"Results saved to: {results['output_directory']}")
        
        # Performance mode recommendations
        if results['performance_mode'] == 'fast' and results['total_ttps'] < 5:
            print(f"\n💡 Tip: Try 'balanced' or 'comprehensive' mode for potentially more TTPs")
        elif results['performance_mode'] == 'comprehensive' and perf_metrics['processing_time_seconds'] > 60:
            print(f"\n💡 Tip: Try 'balanced' mode for faster processing with similar accuracy")
        
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
