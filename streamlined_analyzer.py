#!/usr/bin/env python3
"""
Streamlined MITRE ATT&CK TTP Analyzer
Performance-focused version with simplified processing pipeline.
"""

import argparse
import sys
import logging
import json
import time
from pathlib import Path
from typing import Dict, List, Optional
from collections import Counter

from src.config import Config
from src.timeline_analyzer import TimelineAnalyzer
from src.visualization import Visualizer

# Import streamlined components
try:
    from src.streamlined_report_parser import StreamlinedReportParser
    from src.streamlined_ttp_extractor import StreamlinedTTPExtractor
    STREAMLINED_MODE = True
except ImportError:
    # Fallback to original components
    from src.report_parser import ReportParser as StreamlinedReportParser
    from src.ttp_extractor import TTPExtractor as StreamlinedTTPExtractor
    STREAMLINED_MODE = False


class StreamlinedTTPAnalyzer:
    """Fast, efficient TTP analyzer with minimal overhead."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the streamlined analyzer."""
        self.config = Config(config_path)
        self.setup_logging()
        
        # Initialize components
        self.parser = StreamlinedReportParser(self.config)
        self.extractor = StreamlinedTTPExtractor(self.config)
        self.timeline_analyzer = TimelineAnalyzer(self.config)
        self.visualizer = Visualizer(self.config)
        
        self.logger.info(f"Streamlined mode: {STREAMLINED_MODE}")
        
    def setup_logging(self):
        """Setup efficient logging."""
        log_level = getattr(logging, self.config.LOG_LEVEL.upper())
        
        # Ensure log directory exists
        log_file_path = Path(self.config.LOG_FILE)
        log_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config.LOG_FILE),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        
    def analyze_actor(self, actor_name: str) -> Dict:
        """Streamlined actor analysis."""
        start_time = time.time()
        self.logger.info(f"Analyzing {actor_name}...")
        
        try:
            # Load reports quickly
            actor_dir = self._validate_actor_directory(actor_name)
            report_links = self._load_report_links(actor_dir)
            
            if not report_links:
                raise ValueError("No valid report URLs found")
            
            self.logger.info(f"Processing {len(report_links)} reports...")
            
            # Parse reports with minimal error handling overhead
            parsed_reports = []
            for i, link in enumerate(report_links, 1):
                self.logger.debug(f"Processing {i}/{len(report_links)}: {link}")
                
                try:
                    report_data = self.parser.parse_report(link)
                    if report_data and report_data.get('content'):
                        parsed_reports.append(report_data)
                except Exception as e:
                    self.logger.warning(f"Parse failed: {link} - {e}")
                    continue
            
            if not parsed_reports:
                raise ValueError("No reports successfully parsed")
            
            self.logger.info(f"Parsed {len(parsed_reports)} reports successfully")
            
            # Extract TTPs efficiently
            all_ttps = []
            for report in parsed_reports:
                try:
                    ttps = self.extractor.extract_ttps(report)
                    all_ttps.extend(ttps)
                except Exception as e:
                    self.logger.warning(f"TTP extraction failed: {e}")
                    continue
            
            self.logger.info(f"Extracted {len(all_ttps)} TTPs")
            
            if not all_ttps:
                self.logger.warning("No TTPs extracted")
                return self._create_empty_results(actor_name, len(parsed_reports))
            
            # Quick timeline analysis
            timeline_data = self.timeline_analyzer.analyze_timeline(all_ttps)
            
            # Generate output directory
            output_dir = Path(self.config.OUTPUT_DIR) / actor_name
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Create visualizations
            self._create_visualizations(all_ttps, timeline_data, output_dir, actor_name)
            
            # Build results efficiently
            processing_time = time.time() - start_time
            results = self._build_results(
                actor_name, parsed_reports, all_ttps, timeline_data, 
                output_dir, processing_time
            )
            
            # Save results
            self._save_results(results, output_dir)
            
            self.logger.info(f"Analysis complete in {processing_time:.1f}s")
            return results
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            raise
    
    def _validate_actor_directory(self, actor_name: str) -> Path:
        """Quick actor directory validation."""
        actor_dir = Path(self.config.GROUPS_DIR) / actor_name
        
        if not actor_dir.exists() or not actor_dir.is_dir():
            raise FileNotFoundError(f"Actor directory not found: {actor_dir}")
        
        reports_file = actor_dir / "reports.txt"
        if not reports_file.exists():
            raise FileNotFoundError(f"Reports file not found: {reports_file}")
        
        return actor_dir
    
    def _load_report_links(self, actor_dir: Path) -> List[str]:
        """Fast report links loading."""
        reports_file = actor_dir / "reports.txt"
        links = []
        
        with open(reports_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and line.startswith(('http://', 'https://')):
                    links.append(line)
        
        return links
    
    def _create_visualizations(self, ttps: List[Dict], timeline_data: Dict, 
                             output_dir: Path, actor_name: str):
        """Create visualizations efficiently."""
        try:
            # Heatmap
            heatmap_path = output_dir / "ttp_heatmap.png"
            self.visualizer.create_ttp_heatmap(
                ttps, heatmap_path, title=f"{actor_name} TTP Heatmap"
            )
            
            # Timeline
            timeline_path = output_dir / "ttp_timeline.png"
            self.visualizer.create_timeline_chart(
                timeline_data, timeline_path, title=f"{actor_name} TTP Timeline"
            )
            
            # Frequency analysis
            frequency_path = output_dir / "ttp_frequency.png"
            self.visualizer.create_frequency_analysis(
                ttps, frequency_path, title=f"{actor_name} TTP Analysis"
            )
            
            self.logger.info("Visualizations created successfully")
            
        except Exception as e:
            self.logger.error(f"Visualization creation failed: {e}")
    
    def _build_results(self, actor_name: str, reports: List[Dict], ttps: List[Dict],
                      timeline_data: Dict, output_dir: Path, processing_time: float) -> Dict:
        """Build results structure efficiently."""
        # Calculate basic statistics
        unique_techniques = len(set(ttp['technique_id'] for ttp in ttps))
        unique_tactics = len(set(ttp['tactic'] for ttp in ttps if ttp.get('tactic')))
        
        # Confidence stats
        confidences = [ttp.get('confidence', 0) for ttp in ttps]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0
        
        return {
            'actor_name': actor_name,
            'streamlined_mode': STREAMLINED_MODE,
            'total_reports': len(reports),
            'total_ttps': len(ttps),
            'unique_techniques': unique_techniques,
            'unique_tactics': unique_tactics,
            'timeline_data': timeline_data,
            'date_range': timeline_data.get('date_range', {
                'start': None, 'end': None, 'duration_days': 0
            }),
            'confidence_stats': {
                'average': round(avg_confidence, 3),
                'min': round(min(confidences), 3) if confidences else 0,
                'max': round(max(confidences), 3) if confidences else 0
            },
            'processing_time_seconds': round(processing_time, 2),
            'output_directory': str(output_dir),
            'analysis_timestamp': time.time()
        }
    
    def _create_empty_results(self, actor_name: str, num_reports: int) -> Dict:
        """Create empty results when no TTPs found."""
        return {
            'actor_name': actor_name,
            'streamlined_mode': STREAMLINED_MODE,
            'total_reports': num_reports,
            'total_ttps': 0,
            'unique_techniques': 0,
            'unique_tactics': 0,
            'timeline_data': {
                'total_ttps': 0,
                'dated_ttps': 0,
                'date_range': {'start': None, 'end': None, 'duration_days': 0}
            },
            'date_range': {'start': None, 'end': None, 'duration_days': 0},
            'confidence_stats': {'average': 0, 'min': 0, 'max': 0},
            'processing_time_seconds': 0,
            'output_directory': None
        }
    
    def _save_results(self, results: Dict, output_dir: Path):
        """Save results efficiently."""
        try:
            results_file = output_dir / "analysis_results.json"
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
    
    def list_available_actors(self) -> List[str]:
        """List available actors."""
        groups_dir = Path(self.config.GROUPS_DIR)
        if not groups_dir.exists():
            return []
        
        actors = []
        for item in groups_dir.iterdir():
            if item.is_dir() and (item / "reports.txt").exists():
                actors.append(item.name)
        
        return sorted(actors)
    
    def update_attack_data(self) -> bool:
        """Update MITRE ATT&CK data."""
        return self.extractor.download_attack_data()


def main():
    """Streamlined main function."""
    parser = argparse.ArgumentParser(
        description="Streamlined MITRE ATT&CK TTP Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--actor', '-a', help='Threat actor to analyze')
    parser.add_argument('--list-actors', '-l', action='store_true', help='List available actors')
    parser.add_argument('--update-attack-data', '-u', action='store_true', help='Update MITRE data')
    parser.add_argument('--config', '-c', help='Custom config file path')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    try:
        # Initialize analyzer
        analyzer = StreamlinedTTPAnalyzer(args.config)
        
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        # Handle commands
        if args.update_attack_data:
            success = analyzer.update_attack_data()
            print("✅ MITRE data updated" if success else "❌ Update failed")
            return
        
        if args.list_actors:
            actors = analyzer.list_available_actors()
            if actors:
                print("Available actors:")
                for actor in actors:
                    print(f"  - {actor}")
                print(f"\nTotal: {len(actors)} actors")
            else:
                print("No actors found")
            return
        
        if not args.actor:
            parser.error("Specify --actor, --list-actors, or --update-attack-data")
        
        # Run analysis
        print(f"🚀 Analyzing {args.actor} (streamlined mode: {STREAMLINED_MODE})...")
        
        results = analyzer.analyze_actor(args.actor)
        
        # Print summary
        print(f"\n=== Analysis Summary ===")
        print(f"Actor: {results['actor_name']}")
        print(f"Reports: {results['total_reports']}")
        print(f"TTPs: {results['total_ttps']}")
        print(f"Unique techniques: {results['unique_techniques']}")
        print(f"Processing time: {results['processing_time_seconds']}s")
        
        # Handle date range safely
        date_range = results.get('date_range', {})
        if date_range and date_range.get('start') and date_range.get('end'):
            print(f"Date range: {date_range['start']} to {date_range['end']}")
        else:
            print("Date range: No valid dates found in reports")
        
        output_dir = results.get('output_directory')
        if output_dir:
            print(f"Results saved to: {output_dir}")
        else:
            print("No results files created (no TTPs found)")
        
        # Show advice for zero TTPs
        if results['total_ttps'] == 0:
            print("\n💡 Troubleshooting Tips:")
            print("  • Check that reports contain explicit MITRE technique IDs (T1234, T1234.001)")
            print("  • Verify reports.txt URLs are accessible and contain threat intelligence")
            print("  • Consider lowering MIN_CONFIDENCE_THRESHOLD in config if too restrictive")
            print("  • Enable verbose mode (-v) to see detailed parsing information")
        
    except KeyboardInterrupt:
        print("\nCancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
