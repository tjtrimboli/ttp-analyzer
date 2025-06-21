"""
Visualization Engine Module for creating TTP analysis charts and graphs.
"""

import logging
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Optional
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime
import pandas as pd


class VisualizationEngine:
    """Engine for creating visualizations of TTP analysis results."""
    
    def __init__(self, config):
        """Initialize the visualization engine."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Set matplotlib style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        
        # Configure matplotlib for better output
        plt.rcParams['figure.figsize'] = (12, 8)
        plt.rcParams['figure.dpi'] = 300
        plt.rcParams['savefig.dpi'] = 300
        plt.rcParams['savefig.bbox'] = 'tight'
        plt.rcParams['font.size'] = 10
        
    def create_ttp_heatmap(self, ttps: List[Dict], output_path: Path, title: str = "TTP Heatmap") -> Path:
        """
        Create a heatmap showing TTP frequency by tactic and technique.
        
        Args:
            ttps: List of extracted TTP dictionaries
            output_path: Path to save the heatmap
            title: Title for the chart
            
        Returns:
            Path to the saved heatmap file
        """
        self.logger.info(f"Creating TTP heatmap with {len(ttps)} TTPs")
        
        if not ttps:
            self.logger.warning("No TTPs provided for heatmap creation")
            return self._create_empty_chart(output_path, "No TTPs Available")
        
        # Prepare data for heatmap
        ttp_counts = Counter()
        tactic_technique_map = defaultdict(list)
        
        for ttp in ttps:
            technique_id = ttp.get('technique_id', 'Unknown')
            technique_name = ttp.get('technique_name', technique_id)
            tactic = ttp.get('tactic', 'unknown').replace('-', ' ').title()
            
            # Create a combined label
            technique_label = f"{technique_id}\n{technique_name[:20]}"
            ttp_key = (tactic, technique_label)
            
            ttp_counts[ttp_key] += 1
            tactic_technique_map[tactic].append(technique_label)
        
        if not ttp_counts:
            return self._create_empty_chart(output_path, "No Valid TTPs Found")
        
        # Create DataFrame for heatmap
        tactics = sorted(set(tactic for tactic, _ in ttp_counts.keys()))
        techniques = sorted(set(technique for _, technique in ttp_counts.keys()))
        
        # Create matrix
        matrix = np.zeros((len(techniques), len(tactics)))
        
        for i, technique in enumerate(techniques):
            for j, tactic in enumerate(tactics):
                count = ttp_counts.get((tactic, technique), 0)
                matrix[i, j] = count
        
        # Create the heatmap
        fig, ax = plt.subplots(figsize=(max(12, len(tactics) * 2), max(8, len(techniques) * 0.5)))
        
        # Create heatmap with custom colormap
        heatmap = sns.heatmap(
            matrix,
            xticklabels=tactics,
            yticklabels=techniques,
            annot=True,
            fmt='g',
            cmap='YlOrRd',
            cbar_kws={'label': 'Frequency'},
            square=False,
            ax=ax
        )
        
        # Customize the plot
        ax.set_title(title, fontsize=16, fontweight='bold', pad=20)
        ax.set_xlabel('MITRE ATT&CK Tactics', fontsize=12, fontweight='bold')
        ax.set_ylabel('Techniques', fontsize=12, fontweight='bold')
        
        # Rotate labels for better readability
        plt.xticks(rotation=45, ha='right')
        plt.yticks(rotation=0)
        
        # Adjust layout and save
        plt.tight_layout()
        plt.savefig(output_path, bbox_inches='tight', dpi=300)
        plt.close()
        
        self.logger.info(f"TTP heatmap saved to: {output_path}")
        return output_path
    
    def create_timeline_chart(self, timeline_data: Dict, output_path: Path, title: str = "TTP Timeline") -> Path:
        """
        Create a timeline chart showing TTP evolution over time.
        
        Args:
            timeline_data: Timeline analysis data
            output_path: Path to save the chart
            title: Title for the chart
            
        Returns:
            Path to the saved chart file
        """
        self.logger.info("Creating TTP timeline chart")
        
        monthly_data = timeline_data.get('monthly_breakdown', {})
        
        if not monthly_data:
            return self._create_empty_chart(output_path, "No Timeline Data Available")
        
        # Prepare data
        months = sorted(monthly_data.keys())
        ttp_counts = [monthly_data[month]['total_ttps'] for month in months]
        technique_counts = [monthly_data[month]['unique_techniques'] for month in months]
        tactic_counts = [monthly_data[month]['unique_tactics'] for month in months]
        
        # Create the timeline chart
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10))
        
        # Top subplot: TTP counts over time
        ax1.plot(months, ttp_counts, marker='o', linewidth=2, markersize=6, label='Total TTPs', color='#1f77b4')
        ax1.fill_between(months, ttp_counts, alpha=0.3, color='#1f77b4')
        
        ax1.set_title(f'{title} - Activity Over Time', fontsize=14, fontweight='bold')
        ax1.set_ylabel('Number of TTPs', fontsize=12)
        ax1.grid(True, alpha=0.3)
        ax1.legend()
        
        # Rotate x-axis labels
        for tick in ax1.get_xticklabels():
            tick.set_rotation(45)
        
        # Bottom subplot: Technique and tactic diversity
        ax2.plot(months, technique_counts, marker='s', linewidth=2, markersize=5, 
                label='Unique Techniques', color='#ff7f0e')
        ax2.plot(months, tactic_counts, marker='^', linewidth=2, markersize=5, 
                label='Unique Tactics', color='#2ca02c')
        
        ax2.set_title('TTP Diversity Over Time', fontsize=14, fontweight='bold')
        ax2.set_xlabel('Time Period', fontsize=12)
        ax2.set_ylabel('Number of Unique TTPs', fontsize=12)
        ax2.grid(True, alpha=0.3)
        ax2.legend()
        
        # Rotate x-axis labels
        for tick in ax2.get_xticklabels():
            tick.set_rotation(45)
        
        plt.tight_layout()
        plt.savefig(output_path, bbox_inches='tight', dpi=300)
        plt.close()
        
        self.logger.info(f"Timeline chart saved to: {output_path}")
        return output_path
    
    def create_frequency_analysis(self, ttps: List[Dict], output_path: Path, title: str = "TTP Frequency Analysis") -> Path:
        """
        Create frequency analysis charts for TTPs.
        
        Args:
            ttps: List of extracted TTP dictionaries
            output_path: Path to save the chart
            title: Title for the chart
            
        Returns:
            Path to the saved chart file
        """
        self.logger.info("Creating TTP frequency analysis")
        
        if not ttps:
            return self._create_empty_chart(output_path, "No TTPs Available for Frequency Analysis")
        
        # Analyze frequencies
        technique_counts = Counter(ttp.get('technique_name', 'Unknown') for ttp in ttps)
        tactic_counts = Counter(ttp.get('tactic', 'unknown').replace('-', ' ').title() for ttp in ttps)
        
        # Get top techniques and tactics
        top_techniques = technique_counts.most_common(15)
        top_tactics = tactic_counts.most_common(10)
        
        # Create subplots
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        
        # Top techniques bar chart
        if top_techniques:
            techniques, counts = zip(*top_techniques)
            colors = plt.cm.Set3(np.linspace(0, 1, len(techniques)))
            
            bars1 = ax1.barh(range(len(techniques)), counts, color=colors)
            ax1.set_yticks(range(len(techniques)))
            ax1.set_yticklabels([t[:30] + '...' if len(t) > 30 else t for t in techniques])
            ax1.set_xlabel('Frequency')
            ax1.set_title('Top 15 Most Frequent Techniques', fontweight='bold')
            ax1.grid(axis='x', alpha=0.3)
            
            # Add value labels on bars
            for bar, count in zip(bars1, counts):
                ax1.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2, 
                        str(count), va='center', fontsize=9)
        
        # Top tactics pie chart
        if top_tactics:
            tactics, counts = zip(*top_tactics)
            colors = plt.cm.Set2(np.linspace(0, 1, len(tactics)))
            
            wedges, texts, autotexts = ax2.pie(counts, labels=tactics, autopct='%1.1f%%', 
                                              colors=colors, startangle=90)
            ax2.set_title('Tactic Distribution', fontweight='bold')
            
            # Improve text readability
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
        
        # Confidence distribution
        confidences = [ttp.get('confidence', 0.5) for ttp in ttps]
        ax3.hist(confidences, bins=20, color='skyblue', alpha=0.7, edgecolor='black')
        ax3.set_xlabel('Confidence Score')
        ax3.set_ylabel('Frequency')
        ax3.set_title('Confidence Score Distribution', fontweight='bold')
        ax3.grid(alpha=0.3)
        
        # TTP count by source
        source_counts = Counter(ttp.get('source', 'Unknown')[:50] for ttp in ttps)  # Truncate long URLs
        top_sources = source_counts.most_common(10)
        
        if top_sources:
            sources, counts = zip(*top_sources)
            colors = plt.cm.viridis(np.linspace(0, 1, len(sources)))
            
            bars4 = ax4.bar(range(len(sources)), counts, color=colors)
            ax4.set_xticks(range(len(sources)))
            ax4.set_xticklabels([s[:20] + '...' if len(s) > 20 else s for s in sources], 
                               rotation=45, ha='right')
            ax4.set_ylabel('Number of TTPs')
            ax4.set_title('TTPs by Source', fontweight='bold')
            ax4.grid(axis='y', alpha=0.3)
            
            # Add value labels on bars
            for bar, count in zip(bars4, counts):
                ax4.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1, 
                        str(count), ha='center', va='bottom', fontsize=9)
        
        plt.suptitle(title, fontsize=16, fontweight='bold', y=0.98)
        plt.tight_layout()
        plt.subplots_adjust(top=0.93)
        plt.savefig(output_path, bbox_inches='tight', dpi=300)
        plt.close()
        
        self.logger.info(f"Frequency analysis saved to: {output_path}")
        return output_path
    
    def create_campaign_phases_chart(self, timeline_data: Dict, output_path: Path, title: str = "Campaign Phases") -> Path:
        """
        Create a chart showing campaign phases over time.
        
        Args:
            timeline_data: Timeline analysis data containing phase information
            output_path: Path to save the chart
            title: Title for the chart
            
        Returns:
            Path to the saved chart file
        """
        self.logger.info("Creating campaign phases chart")
        
        phases = timeline_data.get('campaign_phases', [])
        
        if not phases:
            return self._create_empty_chart(output_path, "No Campaign Phases Identified")
        
        # Create timeline visualization
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10))
        
        # Phase timeline
        colors = plt.cm.tab10(np.linspace(0, 1, len(phases)))
        
        for i, phase in enumerate(phases):
            start_date = datetime.fromisoformat(phase['start_date'])
            end_date = datetime.fromisoformat(phase['end_date'])
            duration = phase['duration_days']
            
            # Create bar for phase duration
            ax1.barh(i, duration, left=start_date.toordinal(), 
                    color=colors[i], alpha=0.7, height=0.6)
            
            # Add phase label
            ax1.text(start_date.toordinal() + duration/2, i, 
                    f"Phase {phase['phase_number']}\n{phase['phase_characteristics']['phase_type']}", 
                    ha='center', va='center', fontsize=9, fontweight='bold')
        
        ax1.set_yticks(range(len(phases)))
        ax1.set_yticklabels([f"Phase {p['phase_number']}" for p in phases])
        ax1.set_xlabel('Timeline')
        ax1.set_title(f'{title} - Phase Duration', fontweight='bold')
        ax1.grid(axis='x', alpha=0.3)
        
        # Phase characteristics
        phase_types = [p['phase_characteristics']['phase_type'] for p in phases]
        intensities = [p['phase_characteristics']['intensity'] for p in phases]
        complexities = [p['phase_characteristics']['complexity'] for p in phases]
        
        x_pos = range(len(phases))
        width = 0.35
        
        bars1 = ax2.bar([x - width/2 for x in x_pos], intensities, width, 
                       label='Intensity (# TTPs)', color='lightblue', alpha=0.7)
        bars2 = ax2.bar([x + width/2 for x in x_pos], complexities, width, 
                       label='Complexity (# Techniques)', color='lightcoral', alpha=0.7)
        
        ax2.set_xlabel('Campaign Phase')
        ax2.set_ylabel('Count')
        ax2.set_title('Phase Intensity and Complexity', fontweight='bold')
        ax2.set_xticks(x_pos)
        ax2.set_xticklabels([f"Phase {i+1}" for i in range(len(phases))])
        ax2.legend()
        ax2.grid(axis='y', alpha=0.3)
        
        # Add value labels
        for bar in bars1:
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                    f'{int(height)}', ha='center', va='bottom', fontsize=9)
        
        for bar in bars2:
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                    f'{int(height)}', ha='center', va='bottom', fontsize=9)
        
        plt.tight_layout()
        plt.savefig(output_path, bbox_inches='tight', dpi=300)
        plt.close()
        
        self.logger.info(f"Campaign phases chart saved to: {output_path}")
        return output_path
    
    def _create_empty_chart(self, output_path: Path, message: str) -> Path:
        """Create an empty chart with a message when no data is available."""
        fig, ax = plt.subplots(figsize=(10, 6))
        
        ax.text(0.5, 0.5, message, transform=ax.transAxes, 
               fontsize=16, ha='center', va='center',
               bbox=dict(boxstyle="round,pad=0.3", facecolor="lightgray", alpha=0.5))
        
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis('off')
        
        plt.tight_layout()
        plt.savefig(output_path, bbox_inches='tight', dpi=300)
        plt.close()
        
        return output_path
    
    def create_summary_dashboard(self, results: Dict, output_path: Path) -> Path:
        """
        Create a comprehensive summary dashboard.
        
        Args:
            results: Analysis results dictionary
            output_path: Path to save the dashboard
            
        Returns:
            Path to the saved dashboard file
        """
        self.logger.info("Creating summary dashboard")
        
        fig = plt.figure(figsize=(20, 12))
        
        # Create a grid layout
        gs = fig.add_gridspec(3, 4, hspace=0.3, wspace=0.3)
        
        # Summary statistics (top row)
        ax1 = fig.add_subplot(gs[0, :2])
        
        # Key metrics
        metrics = [
            ('Total Reports', results.get('total_reports', 0)),
            ('Total TTPs', results.get('total_ttps', 0)),
            ('Unique Techniques', results.get('unique_techniques', 0)),
            ('Date Range', f"{results.get('date_range', {}).get('start', 'N/A')} - {results.get('date_range', {}).get('end', 'N/A')}")
        ]
        
        ax1.axis('off')
        ax1.text(0.5, 0.8, f"Analysis Summary: {results.get('actor_name', 'Unknown Actor')}", 
                transform=ax1.transAxes, fontsize=18, fontweight='bold', ha='center')
        
        for i, (metric, value) in enumerate(metrics):
            ax1.text(0.1, 0.6 - i*0.15, f"{metric}:", transform=ax1.transAxes, 
                    fontsize=12, fontweight='bold')
            ax1.text(0.5, 0.6 - i*0.15, str(value), transform=ax1.transAxes, 
                    fontsize=12)
        
        # Add timestamp
        ax1.text(0.5, 0.05, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                transform=ax1.transAxes, fontsize=10, ha='center', style='italic')
        
        plt.savefig(output_path, bbox_inches='tight', dpi=300)
        plt.close()
        
        self.logger.info(f"Summary dashboard saved to: {output_path}")
        return output_path
