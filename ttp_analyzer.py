#!/usr/bin/env python3
"""
MITRE ATT&CK TTP Analyzer for Threat Actor Evolution
A modular application for parsing threat intelligence reports and analyzing TTPs.
"""

import argparse
import sys
import logging
from pathlib import Path
from typing import Dict, List, Optional
import json

from src.report_parser import ReportParser
from src.ttp_extractor import TTPExtractor
from src.timeline_analyzer import TimelineAnalyzer
from src.visualization import VisualizationEngine
from src.config import Config


class TTPAnalyzer:
    """Main application class for TTP analysis."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the TTP Analyzer."""
        self.config = Config(config_path)
        self.setup_logging()
        
        # Initialize components that are always needed
        self.parser = None
        self.extractor = None
        self.timeline_analyzer = None
        self.visualizer = None
        
    def _ensure_components_initialized(self):
        """Lazy initialization of components that require heavy resources."""
        if self.parser is None:
            self.parser = ReportParser(self.config)
        if self.extractor is None:
            self.extractor = TTPExtractor(self.config)
        if self.timeline_analyzer is None:
            self.timeline_analyzer = TimelineAnalyzer(self.config)
        if self.visualizer is None:
            self.visualizer = VisualizationEngine(self.config)
        
    def setup_logging(self):
        """Configure logging for the application."""
        log_level = getattr(logging, self.config.LOG_LEVEL.upper())
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config.LOG_FILE),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
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
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):  # Skip empty lines and comments
                        links.append(line)
        except Exception as e:
            self.logger.error(f"Error reading reports file: {e}")
            raise
            
        return links
        
    def analyze_actor(self, actor_name: str) -> Dict:
        """Analyze a specific threat actor."""
        self.logger.info(f"Starting analysis for threat actor: {actor_name}")
        
        # Ensure all components are initialized for analysis
        self._ensure_components_initialized()
        
        try:
            # Validate actor directory
            actor_dir = self.validate_actor_directory(actor_name)
            
            # Load report links
            report_links = self.load_report_links(actor_dir)
            self.logger.info(f"Found {len(report_links)} reports to analyze")
            
            # Parse reports
            self.logger.info("Parsing reports...")
            parsed_reports = []
            for i, link in enumerate(report_links, 1):
                self.logger.info(f"Processing report {i}/{len(report_links)}: {link}")
                try:
                    report_data = self.parser.parse_report(link)
                    if report_data:
                        parsed_reports.append(report_data)
                except Exception as e:
                    self.logger.error(f"Failed to parse report {link}: {e}")
                    continue
            
            if not parsed_reports:
                raise ValueError("No reports were successfully parsed")
            
            # Extract TTPs
            self.logger.info("Extracting TTPs from parsed reports...")
            all_ttps = []
            for report in parsed_reports:
                ttps = self.extractor.extract_ttps(report)
                all_ttps.extend(ttps)
            
            self.logger.info(f"Extracted {len(all_ttps)} TTP instances")
            
            # Analyze timeline
            self.logger.info("Analyzing TTP timeline...")
            timeline_data = self.timeline_analyzer.analyze_timeline(all_ttps)
            
            # Generate visualizations
            self.logger.info("Generating visualizations...")
            output_dir = Path(self.config.OUTPUT_DIR) / actor_name
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Create heatmap
            heatmap_path = self.visualizer.create_ttp_heatmap(
                all_ttps, 
                output_dir / "ttp_heatmap.png",
                title=f"{actor_name} TTP Heatmap"
            )
            
            # Create timeline
            timeline_path = self.visualizer.create_timeline_chart(
                timeline_data,
                output_dir / "ttp_timeline.png",
                title=f"{actor_name} TTP Timeline"
            )
            
            # Create frequency analysis
            frequency_path = self.visualizer.create_frequency_analysis(
                all_ttps,
                output_dir / "ttp_frequency.png",
                title=f"{actor_name} TTP Frequency Analysis"
            )
            
            # Save analysis results
            timeline_data = self.timeline_analyzer.analyze_timeline(all_ttps)
            
            # Safely extract date range
            date_range = timeline_data.get('date_range', {})
            start_date = date_range.get('start')
            end_date = date_range.get('end')
            
            results = {
                'actor_name': actor_name,
                'total_reports': len(parsed_reports),
                'total_ttps': len(all_ttps),
                'timeline_data': timeline_data,
                'unique_techniques': len(set(ttp['technique_id'] for ttp in all_ttps)),
                'date_range': {
                    'start': start_date,
                    'end': end_date,
                    'duration_days': date_range.get('duration_days', 0)
                },
                'visualizations': {
                    'heatmap': str(heatmap_path),
                    'timeline': str(timeline_path),
                    'frequency': str(frequency_path)
                }
            }
            
            # Save results to JSON
            results_file = output_dir / "analysis_results.json"
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
            
            self.logger.info(f"Analysis complete. Results saved to: {output_dir}")
            return results
            
        except Exception as e:
            self.logger.error(f"Analysis failed for {actor_name}: {e}")
            raise
            
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
        """Update MITRE ATT&CK framework data."""
        self.logger.info("Updating MITRE ATT&CK framework data...")
        
        # Only initialize the extractor for this operation
        if self.extractor is None:
            self.extractor = TTPExtractor(self.config)
        
        try:
            success = self.extractor.download_attack_data()
            if success:
                self.logger.info("ATT&CK data update completed successfully")
                
                # Display statistics about the downloaded data
                techniques = self.extractor.get_all_techniques()
                self.logger.info(f"Loaded {len(techniques)} ATT&CK techniques")
                
                # Count techniques by tactic
                tactic_counts = {}
                for technique_info in techniques.values():
                    tactic = technique_info.get('tactic', 'unknown')
                    tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
                
                self.logger.info("Techniques by tactic:")
                for tactic, count in sorted(tactic_counts.items()):
                    self.logger.info(f"  {tactic}: {count}")
                
                return True
            else:
                self.logger.error("Failed to update ATT&CK data")
                return False
                
        except Exception as e:
            self.logger.error(f"ATT&CK data update failed: {e}")
            return False


def main():
    """Main entry point for the application."""
    parser = argparse.ArgumentParser(
        description="Analyze MITRE ATT&CK TTPs for threat actors",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ttp_analyzer.py --actor APT1
  python ttp_analyzer.py --list-actors
  python ttp_analyzer.py --update-attack-data
  python ttp_analyzer.py --actor scattered_spider --config custom_config.yaml
        """
    )
    
    parser.add_argument(
        '--actor', '-a',
        type=str,
        help='Name of the threat actor to analyze (must match directory name in groups/)'
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
    
    args = parser.parse_args()
    
    try:
        # Initialize analyzer
        analyzer = TTPAnalyzer(args.config)
        
        # Override log level if verbose
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        # Update ATT&CK data if requested
        if args.update_attack_data:
            success = analyzer.update_attack_data()
            if success:
                print("✓ MITRE ATT&CK data updated successfully")
            else:
                print("✗ Failed to update MITRE ATT&CK data")
                sys.exit(1)
            return
        
        # List actors if requested
        if args.list_actors:
            actors = analyzer.list_available_actors()
            if actors:
                print("Available threat actors:")
                for actor in actors:
                    print(f"  - {actor}")
            else:
                print("No threat actors found in groups/ directory")
            return
        
        # Validate actor argument
        if not args.actor:
            parser.error("Either --actor, --list-actors, or --update-attack-data must be specified")
        
        # Run analysis
        results = analyzer.analyze_actor(args.actor)
        
        # Print summary
        print(f"\n=== Analysis Summary for {results['actor_name']} ===")
        print(f"Reports analyzed: {results['total_reports']}")
        print(f"TTPs extracted: {results['total_ttps']}")
        print(f"Unique techniques: {results['unique_techniques']}")
        
        # Handle date range safely
        start_date = results['date_range']['start']
        end_date = results['date_range']['end']
        if start_date and end_date:
            print(f"Date range: {start_date} to {end_date}")
        else:
            print("Date range: No valid dates found in reports")
            
        print(f"Visualizations saved to: {Path(results['visualizations']['heatmap']).parent}")
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
