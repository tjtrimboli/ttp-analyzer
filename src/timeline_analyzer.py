"""
Timeline Analyzer Module for analyzing TTP evolution over time.
"""

import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import statistics


class TimelineAnalyzer:
    """Analyzer for TTP timeline and evolution patterns."""
    
    def __init__(self, config):
        """Initialize the timeline analyzer."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def analyze_timeline(self, ttps: List[Dict]) -> Dict:
        """
        Analyze TTP timeline and evolution patterns.
        
        Args:
            ttps: List of extracted TTP dictionaries
            
        Returns:
            Dictionary containing timeline analysis results
        """
        self.logger.info(f"Analyzing timeline for {len(ttps)} TTPs")
        
        # Filter TTPs with valid dates
        dated_ttps = [ttp for ttp in ttps if ttp.get('date')]
        
        if not dated_ttps:
            self.logger.warning("No TTPs with valid dates found")
            return self._get_empty_timeline()
        
        # Sort TTPs by date
        dated_ttps.sort(key=lambda x: x['date'])
        
        # Perform various timeline analyses
        analysis = {
            'total_ttps': len(ttps),
            'dated_ttps': len(dated_ttps),
            'date_range': self._get_date_range(dated_ttps),
            'monthly_breakdown': self._analyze_monthly_breakdown(dated_ttps),
            'technique_evolution': self._analyze_technique_evolution(dated_ttps),
            'tactic_evolution': self._analyze_tactic_evolution(dated_ttps),
            'campaign_phases': self._identify_campaign_phases(dated_ttps),
            'trend_analysis': self._analyze_trends(dated_ttps),
            'technique_lifecycle': self._analyze_technique_lifecycle(dated_ttps),
            'activity_patterns': self._analyze_activity_patterns(dated_ttps)
        }
        
        return analysis
        
    def _get_empty_timeline(self) -> Dict:
        """Return empty timeline structure when no dated TTPs are available."""
        return {
            'total_ttps': 0,
            'dated_ttps': 0,
            'date_range': {'start': None, 'end': None, 'duration_days': 0},
            'monthly_breakdown': {},
            'technique_evolution': {},
            'tactic_evolution': {},
            'campaign_phases': [],
            'trend_analysis': {},
            'technique_lifecycle': {},
            'activity_patterns': {}
        }
        
    def _get_date_range(self, dated_ttps: List[Dict]) -> Dict:
        """Get the date range of TTP activity."""
        if not dated_ttps:
            return {'start': None, 'end': None, 'duration_days': 0}
        
        start_date = dated_ttps[0]['date']
        end_date = dated_ttps[-1]['date']
        
        # Calculate duration
        start_dt = datetime.fromisoformat(start_date)
        end_dt = datetime.fromisoformat(end_date)
        duration = (end_dt - start_dt).days
        
        return {
            'start': start_date,
            'end': end_date,
            'duration_days': duration
        }
        
    def _analyze_monthly_breakdown(self, dated_ttps: List[Dict]) -> Dict:
        """Analyze TTP distribution by month."""
        monthly_counts = defaultdict(lambda: {
            'total': 0,
            'techniques': set(),
            'tactics': set(),
            'reports': set()
        })
        
        for ttp in dated_ttps:
            # Group by year-month
            date_obj = datetime.fromisoformat(ttp['date'])
            month_key = f"{date_obj.year}-{date_obj.month:02d}"
            
            monthly_counts[month_key]['total'] += 1
            monthly_counts[month_key]['techniques'].add(ttp['technique_id'])
            monthly_counts[month_key]['tactics'].add(ttp['tactic'])
            monthly_counts[month_key]['reports'].add(ttp['source'])
        
        # Convert sets to counts for JSON serialization
        result = {}
        for month, data in monthly_counts.items():
            result[month] = {
                'total_ttps': data['total'],
                'unique_techniques': len(data['techniques']),
                'unique_tactics': len(data['tactics']),
                'unique_reports': len(data['reports']),
                'techniques': list(data['techniques']),
                'tactics': list(data['tactics'])
            }
        
        return result
        
    def _analyze_technique_evolution(self, dated_ttps: List[Dict]) -> Dict:
        """Analyze how individual techniques evolve over time."""
        technique_timeline = defaultdict(list)
        
        # Group TTPs by technique
        for ttp in dated_ttps:
            technique_timeline[ttp['technique_id']].append({
                'date': ttp['date'],
                'source': ttp['source'],
                'confidence': ttp.get('confidence', 0.5)
            })
        
        # Analyze each technique's timeline
        evolution = {}
        for technique_id, events in technique_timeline.items():
            events.sort(key=lambda x: x['date'])
            
            evolution[technique_id] = {
                'first_seen': events[0]['date'],
                'last_seen': events[-1]['date'],
                'frequency': len(events),
                'timeline': events,
                'activity_span_days': self._calculate_activity_span(events),
                'avg_confidence': statistics.mean([e.get('confidence', 0.5) for e in events])
            }
        
        return evolution
        
    def _analyze_tactic_evolution(self, dated_ttps: List[Dict]) -> Dict:
        """Analyze how tactics evolve over time."""
        tactic_timeline = defaultdict(list)
        
        # Group TTPs by tactic
        for ttp in dated_ttps:
            tactic_timeline[ttp['tactic']].append({
                'date': ttp['date'],
                'technique_id': ttp['technique_id'],
                'source': ttp['source']
            })
        
        # Analyze each tactic's timeline
        evolution = {}
        for tactic, events in tactic_timeline.items():
            events.sort(key=lambda x: x['date'])
            
            evolution[tactic] = {
                'first_seen': events[0]['date'],
                'last_seen': events[-1]['date'],
                'frequency': len(events),
                'unique_techniques': len(set(e['technique_id'] for e in events)),
                'techniques_used': list(set(e['technique_id'] for e in events)),
                'activity_span_days': self._calculate_activity_span(events)
            }
        
        return evolution
        
    def _identify_campaign_phases(self, dated_ttps: List[Dict]) -> List[Dict]:
        """Identify distinct campaign phases based on activity patterns."""
        if len(dated_ttps) < 3:
            return []
        
        # Group TTPs by time windows
        time_windows = self._create_time_windows(dated_ttps)
        
        phases = []
        for i, (start_date, end_date, window_ttps) in enumerate(time_windows):
            # Analyze characteristics of this phase
            techniques = [ttp['technique_id'] for ttp in window_ttps]
            tactics = [ttp['tactic'] for ttp in window_ttps]
            
            phase = {
                'phase_number': i + 1,
                'start_date': start_date,
                'end_date': end_date,
                'duration_days': (datetime.fromisoformat(end_date) - 
                                datetime.fromisoformat(start_date)).days,
                'ttp_count': len(window_ttps),
                'primary_techniques': self._get_top_items(techniques, 5),
                'primary_tactics': self._get_top_items(tactics, 3),
                'phase_characteristics': self._characterize_phase(window_ttps)
            }
            
            phases.append(phase)
        
        return phases
        
    def _analyze_trends(self, dated_ttps: List[Dict]) -> Dict:
        """Analyze trends in TTP usage over time."""
        # Create monthly aggregations
        monthly_data = defaultdict(lambda: {
            'count': 0,
            'techniques': set(),
            'tactics': set()
        })
        
        for ttp in dated_ttps:
            date_obj = datetime.fromisoformat(ttp['date'])
            month_key = f"{date_obj.year}-{date_obj.month:02d}"
            
            monthly_data[month_key]['count'] += 1
            monthly_data[month_key]['techniques'].add(ttp['technique_id'])
            monthly_data[month_key]['tactics'].add(ttp['tactic'])
        
        # Calculate trends
        months = sorted(monthly_data.keys())
        
        if len(months) < 2:
            return {'trend': 'insufficient_data'}
        
        # Activity trend
        counts = [monthly_data[month]['count'] for month in months]
        activity_trend = self._calculate_trend(counts)
        
        # Diversity trends
        technique_diversity = [len(monthly_data[month]['techniques']) for month in months]
        tactic_diversity = [len(monthly_data[month]['tactics']) for month in months]
        
        return {
            'activity_trend': activity_trend,
            'technique_diversity_trend': self._calculate_trend(technique_diversity),
            'tactic_diversity_trend': self._calculate_trend(tactic_diversity),
            'peak_activity_month': months[counts.index(max(counts))],
            'activity_volatility': statistics.stdev(counts) if len(counts) > 1 else 0
        }
        
    def _analyze_technique_lifecycle(self, dated_ttps: List[Dict]) -> Dict:
        """Analyze the lifecycle of techniques (introduction, peak, decline)."""
        technique_usage = defaultdict(list)
        
        # Group by technique and month
        for ttp in dated_ttps:
            date_obj = datetime.fromisoformat(ttp['date'])
            month_key = f"{date_obj.year}-{date_obj.month:02d}"
            technique_usage[ttp['technique_id']].append(month_key)
        
        lifecycle_analysis = {}
        for technique_id, months in technique_usage.items():
            month_counts = Counter(months)
            sorted_months = sorted(month_counts.keys())
            
            if len(sorted_months) >= 3:
                # Find peak usage
                peak_month = max(month_counts, key=month_counts.get)
                peak_index = sorted_months.index(peak_month)
                
                lifecycle_analysis[technique_id] = {
                    'introduction_phase': sorted_months[:max(1, peak_index)],
                    'peak_month': peak_month,
                    'peak_usage': month_counts[peak_month],
                    'decline_phase': sorted_months[peak_index+1:] if peak_index < len(sorted_months)-1 else [],
                    'lifecycle_stage': self._determine_lifecycle_stage(sorted_months, peak_index)
                }
        
        return lifecycle_analysis
        
    def _analyze_activity_patterns(self, dated_ttps: List[Dict]) -> Dict:
        """Analyze patterns in threat actor activity."""
        # Time-based patterns
        dates = [datetime.fromisoformat(ttp['date']) for ttp in dated_ttps]
        
        # Day of week patterns
        weekday_counts = Counter(date.weekday() for date in dates)
        weekdays = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        
        # Month patterns
        month_counts = Counter(date.month for date in dates)
        
        # Activity gaps
        gaps = self._find_activity_gaps(dates)
        
        return {
            'weekday_distribution': {weekdays[i]: weekday_counts.get(i, 0) for i in range(7)},
            'month_distribution': {f"Month_{i}": month_counts.get(i, 0) for i in range(1, 13)},
            'activity_gaps': gaps,
            'most_active_weekday': weekdays[max(weekday_counts, key=weekday_counts.get)] if weekday_counts else None,
            'most_active_month': max(month_counts, key=month_counts.get) if month_counts else None
        }
        
    def _calculate_activity_span(self, events: List[Dict]) -> int:
        """Calculate the span of activity in days."""
        if len(events) < 2:
            return 0
        
        dates = [datetime.fromisoformat(e['date']) for e in events]
        return (max(dates) - min(dates)).days
        
    def _create_time_windows(self, dated_ttps: List[Dict], window_days: int = 30) -> List[Tuple]:
        """Create time windows for phase analysis."""
        if not dated_ttps:
            return []
        
        start_date = datetime.fromisoformat(dated_ttps[0]['date'])
        end_date = datetime.fromisoformat(dated_ttps[-1]['date'])
        
        windows = []
        current_start = start_date
        
        while current_start < end_date:
            current_end = min(current_start + timedelta(days=window_days), end_date)
            
            # Find TTPs in this window
            window_ttps = [
                ttp for ttp in dated_ttps
                if current_start <= datetime.fromisoformat(ttp['date']) < current_end
            ]
            
            if window_ttps:  # Only include windows with activity
                windows.append((
                    current_start.date().isoformat(),
                    current_end.date().isoformat(),
                    window_ttps
                ))
            
            current_start = current_end
        
        return windows
        
    def _get_top_items(self, items: List[str], limit: int) -> List[Dict]:
        """Get top items by frequency."""
        counter = Counter(items)
        return [{'item': item, 'count': count} 
                for item, count in counter.most_common(limit)]
        
    def _characterize_phase(self, ttps: List[Dict]) -> Dict:
        """Characterize a campaign phase based on its TTPs."""
        tactics = [ttp['tactic'] for ttp in ttps]
        tactic_counter = Counter(tactics)
        
        # Determine phase type based on dominant tactics
        if tactic_counter.get('initial-access', 0) > len(ttps) * 0.3:
            phase_type = 'initial_compromise'
        elif tactic_counter.get('persistence', 0) > len(ttps) * 0.3:
            phase_type = 'establishment'
        elif tactic_counter.get('lateral-movement', 0) > len(ttps) * 0.3:
            phase_type = 'expansion'
        elif tactic_counter.get('exfiltration', 0) > len(ttps) * 0.3:
            phase_type = 'data_theft'
        else:
            phase_type = 'mixed_activity'
        
        return {
            'phase_type': phase_type,
            'intensity': len(ttps),
            'complexity': len(set(ttp['technique_id'] for ttp in ttps)),
            'dominant_tactic': max(tactic_counter, key=tactic_counter.get) if tactic_counter else None
        }
        
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction from a series of values."""
        if len(values) < 2:
            return 'insufficient_data'
        
        # Simple trend calculation
        start_avg = statistics.mean(values[:len(values)//3]) if len(values) >= 3 else values[0]
        end_avg = statistics.mean(values[-len(values)//3:]) if len(values) >= 3 else values[-1]
        
        change_ratio = (end_avg - start_avg) / start_avg if start_avg > 0 else 0
        
        if change_ratio > 0.2:
            return 'increasing'
        elif change_ratio < -0.2:
            return 'decreasing'
        else:
            return 'stable'
            
    def _determine_lifecycle_stage(self, sorted_months: List[str], peak_index: int) -> str:
        """Determine the lifecycle stage of a technique."""
        total_months = len(sorted_months)
        
        if peak_index == 0:
            return 'declining'
        elif peak_index == total_months - 1:
            return 'growing'
        elif peak_index < total_months / 3:
            return 'early_decline'
        elif peak_index > total_months * 2 / 3:
            return 'late_growth'
        else:
            return 'mature'
            
    def _find_activity_gaps(self, dates: List[datetime], gap_threshold_days: int = 30) -> List[Dict]:
        """Find significant gaps in activity."""
        if len(dates) < 2:
            return []
        
        sorted_dates = sorted(dates)
        gaps = []
        
        for i in range(1, len(sorted_dates)):
            gap_days = (sorted_dates[i] - sorted_dates[i-1]).days
            
            if gap_days > gap_threshold_days:
                gaps.append({
                    'start_date': sorted_dates[i-1].date().isoformat(),
                    'end_date': sorted_dates[i].date().isoformat(),
                    'gap_days': gap_days
                })
        
        return gaps
