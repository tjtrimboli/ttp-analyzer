"""
Enhanced Visualization Engine Module with MITRE ATT&CK Kill Chain Ordered Heatmap
Creates TTP analysis charts and graphs with proper tactical ordering.
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


class Visualizer:
    """Enhanced visualization engine with kill chain ordered heatmaps."""
    
    def __init__(self, config):
        """Initialize the enhanced visualization engine."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Define MITRE ATT&CK kill chain order
        self.kill_chain_order = [
            'reconnaissance',
            'resource-development',
            'initial-access',
            'execution',
            'persistence',
            'privilege-escalation',
            'defense-evasion',
            'credential-access',
            'discovery',
            'lateral-movement',
            'collection',
            'command-and-control',
            'exfiltration',
            'impact'
        ]
        
        # Mapping of display names for better visualization
        self.tactic_display_names = {
            'reconnaissance': 'Reconnaissance',
            'resource-development': 'Resource Development',
            'initial-access': 'Initial Access',
            'execution': 'Execution',
            'persistence': 'Persistence',  
            'privilege-escalation': 'Privilege Escalation',
            'defense-evasion': 'Defense Evasion',
            'credential-access': 'Credential Access',
            'discovery': 'Discovery',
            'lateral-movement': 'Lateral Movement',
            'collection': 'Collection',
            'command-and-control': 'Command and Control',
            'exfiltration': 'Exfiltration',
            'impact': 'Impact'
        }
        
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
        """Create a kill chain ordered heatmap showing TTP frequency by tactic and technique."""
        self.logger.info(f"Creating kill chain ordered TTP heatmap with {len(ttps)} TTPs")
        
        if not ttps:
            self.logger.warning("No TTPs provided for heatmap creation")
            return self._create_empty_chart(output_path, "No TTPs Available")
        
        # Prepare data for heatmap
        ttp_counts = Counter()
        tactic_technique_map = defaultdict(list)
        
        for ttp in ttps:
            technique_id = ttp.get('technique_id', 'Unknown')
            technique_name = ttp.get('technique_name', technique_id)
            tactic = ttp.get('tactic', 'unknown').lower()
            
            # Create a combined label (shorter for better display)
            technique_label = f"{technique_id}"
            if technique_name and len(technique_name) < 30:
                technique_label += f"\n{technique_name}"
            
            # Use display name for tactic
            tactic_display = self.tactic_display_names.get(tactic, tactic.replace('-', ' ').title())
            
            ttp_key = (tactic_display, technique_label)
            ttp_counts[ttp_key] += 1
            tactic_technique_map[tactic_display].append(technique_label)
        
        if not ttp_counts:
            return self._create_empty_chart(output_path, "No Valid TTPs Found")
        
        # Order tactics according to kill chain
        all_tactics = set(tactic for tactic, _ in ttp_counts.keys())
        ordered_tactics = self._order_tactics_by_kill_chain(all_tactics)
        
        # Get all techniques
        all_techniques = sorted(set(technique for _, technique in ttp_counts.keys()))
        
        # Limit techniques for better visualization
        if len(all_techniques) > 30:
            # Keep only top techniques by frequency
            technique_totals = defaultdict(int)
            for (tactic, technique), count in ttp_counts.items():
                technique_totals[technique] += count
            
            top_techniques = sorted(technique_totals.items(), key=lambda x: x[1], reverse=True)[:30]
            all_techniques = [t[0] for t in top_techniques]
        
        # Create matrix with proper ordering
        matrix = np.zeros((len(all_techniques), len(ordered_tactics)))
        
        for i, technique in enumerate(all_techniques):
            for j, tactic in enumerate(ordered_tactics):
                count = ttp_counts.get((tactic, technique), 0)
                matrix[i, j] = count
        
        # Create the clean heatmap with larger size
        fig, ax = plt.subplots(figsize=(max(18, len(ordered_tactics) * 1.6), max(14, len(all_techniques) * 0.5)))
        
        # Create heatmap with enhanced styling
        heatmap = sns.heatmap(
            matrix,
            xticklabels=ordered_tactics,
            yticklabels=all_techniques,
            annot=True,
            fmt='g',
            cmap='YlOrRd',
            cbar_kws={'label': 'Frequency', 'shrink': 0.8},
            square=False,
            ax=ax,
            linewidths=0.5,
            linecolor='white'
        )
        
        # Customize the plot with clean styling
        ax.set_title(title, fontsize=18, fontweight='bold', pad=25)
        ax.set_xlabel('Tactics', fontsize=14, fontweight='bold', labelpad=15)
        ax.set_ylabel('Techniques', fontsize=14, fontweight='bold', labelpad=15)
        
        # Rotate labels for better readability
        plt.xticks(rotation=45, ha='right', fontsize=11)
        plt.yticks(rotation=0, fontsize=10)
        
        # Add summary statistics in bottom left corner
        total_ttps = len(ttps)
        unique_techniques = len(all_techniques)
        unique_tactics = len(ordered_tactics)
        
        # Position stats box in bottom left, outside the plot area
        stats_text = f'Total TTPs: {total_ttps}\nUnique Techniques: {unique_techniques}\nTactics Used: {unique_tactics}'
        
        # Place stats box in the bottom left margin area
        fig.text(0.02, 0.02, stats_text, ha='left', va='bottom', fontsize=11,
                bbox=dict(boxstyle='round,pad=0.5', facecolor='white', alpha=0.9, 
                         edgecolor='gray', linewidth=1))
        
        # Adjust layout for clean appearance
        plt.tight_layout()
        plt.subplots_adjust(bottom=0.15, left=0.12)  # Make room for stats and labels
        plt.savefig(output_path, bbox_inches='tight', dpi=300, facecolor='white')
        plt.close()
        
        self.logger.info(f"Kill chain ordered TTP heatmap saved to: {output_path}")
        return output_path
    
    def _order_tactics_by_kill_chain(self, tactics: set) -> List[str]:
        """Order tactics according to MITRE ATT&CK kill chain sequence."""
        ordered_tactics = []
        
        # First, add tactics in kill chain order
        for kill_chain_tactic in self.kill_chain_order:
            display_name = self.tactic_display_names.get(kill_chain_tactic, 
                                                        kill_chain_tactic.replace('-', ' ').title())
            if display_name in tactics:
                ordered_tactics.append(display_name)
        
        # Add any remaining tactics that aren't in the standard kill chain
        remaining_tactics = tactics - set(ordered_tactics)
        if remaining_tactics:
            ordered_tactics.extend(sorted(remaining_tactics))
            self.logger.debug(f"Added non-standard tactics: {remaining_tactics}")
        
        return ordered_tactics
    
    def create_timeline_chart(self, timeline_data: Dict, output_path: Path, title: str = "TTP Timeline") -> Path:
        """Create a timeline chart showing TTP evolution over time."""
        self.logger.info("Creating TTP timeline chart")
        
        monthly_data = timeline_data.get('monthly_breakdown', {})
        
        if not monthly_data:
            return self._create_empty_chart(output_path, "No Timeline Data Available")
        
        # Prepare data with proper date handling
        months = sorted(monthly_data.keys())
        ttp_counts = [monthly_data[month]['total_ttps'] for month in months]
        technique_counts = [monthly_data[month]['unique_techniques'] for month in months]
        tactic_counts = [monthly_data[month]['unique_tactics'] for month in months]
        
        # Convert month strings to datetime objects for proper plotting
        try:
            month_dates = []
            for month in months:
                year, month_num = month.split('-')
                dt = datetime(int(year), int(month_num), 1)
                month_dates.append(dt)
        except (ValueError, IndexError):
            # Fallback to using month strings as categories
            month_dates = months
        
        # Create the timeline chart
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10))
        
        # Top subplot: TTP counts over time
        ax1.plot(month_dates, ttp_counts, marker='o', linewidth=2, markersize=6, 
                label='Total TTPs', color='#1f77b4')
        ax1.fill_between(month_dates, ttp_counts, alpha=0.3, color='#1f77b4')
        
        ax1.set_title(f'{title} - Activity Over Time', fontsize=14, fontweight='bold')
        ax1.set_ylabel('Number of TTPs', fontsize=12)
        ax1.grid(True, alpha=0.3)
        ax1.legend()
        
        # Format x-axis labels
        if isinstance(month_dates[0], datetime):
            ax1.tick_params(axis='x', rotation=45)
            # Format dates nicely
            import matplotlib.dates as mdates
            ax1.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m'))
        else:
            for tick in ax1.get_xticklabels():
                tick.set_rotation(45)
        
        # Bottom subplot: Technique and tactic diversity
        ax2.plot(month_dates, technique_counts, marker='s', linewidth=2, markersize=5, 
                label='Unique Techniques', color='#ff7f0e')
        ax2.plot(month_dates, tactic_counts, marker='^', linewidth=2, markersize=5, 
                label='Unique Tactics', color='#2ca02c')
        
        ax2.set_title('TTP Diversity Over Time', fontsize=14, fontweight='bold')
        ax2.set_xlabel('Time Period', fontsize=12)
        ax2.set_ylabel('Number of Unique TTPs', fontsize=12)
        ax2.grid(True, alpha=0.3)
        ax2.legend()
        
        # Format x-axis labels
        if isinstance(month_dates[0], datetime):
            ax2.tick_params(axis='x', rotation=45)
            ax2.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m'))
        else:
            for tick in ax2.get_xticklabels():
                tick.set_rotation(45)
        
        plt.tight_layout()
        plt.savefig(output_path, bbox_inches='tight', dpi=300)
        plt.close()
        
        self.logger.info(f"Timeline chart saved to: {output_path}")
        return output_path
    
    def create_frequency_analysis(self, ttps: List[Dict], output_path: Path, title: str = "TTP Frequency Analysis") -> Path:
        """Create frequency analysis charts for TTPs."""
        self.logger.info("Creating TTP frequency analysis")
        
        if not ttps:
            return self._create_empty_chart(output_path, "No TTPs Available for Frequency Analysis")
        
        # Analyze frequencies
        technique_counts = Counter(ttp.get('technique_name', 'Unknown') for ttp in ttps)
        tactic_counts = Counter()
        
        # Count tactics with proper display names
        for ttp in ttps:
            tactic = ttp.get('tactic', 'unknown').lower()
            display_name = self.tactic_display_names.get(tactic, tactic.replace('-', ' ').title())
            tactic_counts[display_name] += 1
        
        # Get top techniques and tactics
        top_techniques = technique_counts.most_common(15)
        
        # Order tactics by kill chain for consistent display
        all_tactic_names = set(tactic_counts.keys())
        ordered_tactic_names = self._order_tactics_by_kill_chain(all_tactic_names)
        top_tactics = [(tactic, tactic_counts[tactic]) for tactic in ordered_tactic_names if tactic_counts[tactic] > 0]
        
        # Create subplots
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        
        # Top techniques bar chart
        if top_techniques:
            techniques, counts = zip(*top_techniques)
            colors = plt.cm.Set3(np.linspace(0, 1, len(techniques)))
            
            # Truncate long technique names
            techniques_short = [t[:25] + '...' if len(t) > 25 else t for t in techniques]
            
            bars1 = ax1.barh(range(len(techniques)), counts, color=colors)
            ax1.set_yticks(range(len(techniques)))
            ax1.set_yticklabels(techniques_short)
            ax1.set_xlabel('Frequency')
            ax1.set_title('Top 15 Most Frequent Techniques', fontweight='bold')
            ax1.grid(axis='x', alpha=0.3)
            
            # Add value labels on bars
            for bar, count in zip(bars1, counts):
                ax1.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2, 
                        str(count), va='center', fontsize=9)
        
        # Tactics ordered by kill chain
        if top_tactics:
            tactics, counts = zip(*top_tactics)
            
            # Use kill chain colors for better visualization
            kill_chain_colors = plt.cm.viridis(np.linspace(0, 1, len(tactics)))
            
            bars2 = ax2.bar(range(len(tactics)), counts, color=kill_chain_colors)
            ax2.set_xticks(range(len(tactics)))
            ax2.set_xticklabels([t.replace(' ', '\n') for t in tactics], rotation=0, ha='center', fontsize=8)
            ax2.set_ylabel('Frequency')
            ax2.set_title('Tactics by Kill Chain Order', fontweight='bold')
            ax2.grid(axis='y', alpha=0.3)
            
            # Add value labels on bars
            for bar, count in zip(bars2, counts):
                ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1, 
                        str(count), ha='center', va='bottom', fontsize=9)
        
        # Confidence distribution
        confidences = [ttp.get('confidence', 0.5) for ttp in ttps]
        ax3.hist(confidences, bins=20, color='skyblue', alpha=0.7, edgecolor='black')
        ax3.set_xlabel('Confidence Score')
        ax3.set_ylabel('Frequency')
        ax3.set_title('Confidence Score Distribution', fontweight='bold')
        ax3.grid(alpha=0.3)
        
        # Add statistics
        avg_conf = np.mean(confidences)
        ax3.axvline(avg_conf, color='red', linestyle='--', linewidth=2, 
                   label=f'Average: {avg_conf:.2f}')
        ax3.legend()
        
        # TTP count by source
        source_counts = Counter()
        for ttp in ttps:
            source = ttp.get('source', 'Unknown')
            # Extract domain from URL for cleaner display
            if 'http' in source:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(source)
                    source = parsed.netloc or source
                except:
                    pass
            source_counts[source] += 1
        
        top_sources = source_counts.most_common(10)
        
        if top_sources:
            sources, counts = zip(*top_sources)
            colors = plt.cm.viridis(np.linspace(0, 1, len(sources)))
            
            # Truncate long source names
            sources_short = [s[:20] + '...' if len(s) > 20 else s for s in sources]
            
            bars4 = ax4.bar(range(len(sources)), counts, color=colors)
            ax4.set_xticks(range(len(sources)))
            ax4.set_xticklabels(sources_short, rotation=45, ha='right')
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
