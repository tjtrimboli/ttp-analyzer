# MITRE ATT&CK TTP Analyzer

A modular Python application for parsing threat intelligence reports and analyzing MITRE ATT&CK Tactics, Techniques, and Procedures (TTPs) to understand threat actor evolution over time.

## Features

- **Multi-format Report Parsing**: Supports web URLs, PDFs, and local text files
- **Automated TTP Extraction**: Uses pattern matching and heuristics to identify MITRE ATT&CK techniques
- **Timeline Analysis**: Tracks TTP evolution and identifies campaign phases
- **Rich Visualizations**: Generates heatmaps, timelines, and frequency analysis charts
- **Modular Architecture**: Easy to extend and customize
- **Configurable**: Flexible configuration via YAML files or environment variables

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Install from Source

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ttp-analyzer.git
cd ttp-analyzer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Install the package:
```bash
pip install -e .
```

### Install from PyPI (when available)

```bash
pip install ttp-analyzer
```

## Quick Start

### 1. Set up Directory Structure

Create the required directory structure:

```
ttp-analyzer/
├── groups/
│   ├── APT1/
│   │   └── reports.txt
│   ├── scattered_spider/
│   │   └── reports.txt
│   └── lazarus/
│       └── reports.txt
├── output/
├── data/
└── logs/
```

### 2. Add Report Links

Create a `reports.txt` file in each threat actor directory with one URL per line:

```
# groups/APT1/reports.txt
https://example.com/apt1-report-1.pdf
https://example.com/apt1-analysis-2024.html
https://example.com/apt1-campaign-report.pdf
```

### 3. Download MITRE ATT&CK Data

Before running analysis, download the latest MITRE ATT&CK framework data:

```bash
python ttp_analyzer.py --update-attack-data
```

### 4. Run Analysis

Analyze a specific threat actor:

```bash
python ttp_analyzer.py --actor APT1
```

List available threat actors:

```bash
python ttp_analyzer.py --list-actors
```

Enable verbose logging:

```bash
python ttp_analyzer.py --actor scattered_spider --verbose
```

### 5. View Results

Analysis results are saved to `output/{actor_name}/`:

- `ttp_heatmap.png` - TTP frequency heatmap
- `ttp_timeline.png` - TTP evolution timeline
- `ttp_frequency.png` - Frequency analysis charts
- `analysis_results.json` - Detailed analysis data

## Configuration

### Configuration File

Copy `config.yaml` and modify as needed:

```yaml
# Basic settings
GROUPS_DIR: "groups"
OUTPUT_DIR: "output"
LOG_LEVEL: "INFO"

# TTP extraction settings
MIN_CONFIDENCE_THRESHOLD: 0.3
ENABLE_HEURISTIC_EXTRACTION: true

# Visualization settings
FIGURE_DPI: 300
COLOR_PALETTE: "husl"
```

### Environment Variables

Override configuration with environment variables:

```bash
export TTP_GROUPS_DIR="/custom/groups/path"
export TTP_LOG_LEVEL="DEBUG"
export TTP_MIN_CONFIDENCE="0.5"
```

## Usage Examples

### Basic Analysis

```bash
# Download MITRE ATT&CK data (required on first run)
python ttp_analyzer.py --update-attack-data

# Analyze APT1 threat actor
python ttp_analyzer.py --actor APT1

# Use custom configuration
python ttp_analyzer.py --actor lazarus --config custom_config.yaml

# List all available actors
python ttp_analyzer.py --list-actors
```

### Programmatic Usage

```python
from src import TTPAnalyzer

# Initialize analyzer
analyzer = TTPAnalyzer()

# Analyze threat actor
results = analyzer.analyze_actor("APT1")

# Access results
print(f"Found {results['total_ttps']} TTPs")
print(f"Date range: {results['date_range']}")
```

## Architecture

The application consists of several modular components:

### Core Modules

- **`ttp_analyzer.py`** - Main application and CLI interface
- **`config.py`** - Configuration management
- **`report_parser.py`** - Multi-format report parsing
- **`ttp_extractor.py`** - MITRE ATT&CK TTP extraction
- **`timeline_analyzer.py`** - Timeline and evolution analysis
- **`visualization.py`** - Chart and graph generation

### Data Flow

1. **Input**: Threat actor directory with report links
2. **Parsing**: Download and parse reports (PDF, HTML, text)
3. **Extraction**: Identify MITRE ATT&CK techniques using pattern matching
4. **Analysis**: Analyze timeline, phases, and evolution patterns
5. **Visualization**: Generate charts and save results

## Supported Report Formats

- **Web URLs**: HTML pages, blog posts, security reports
- **PDF Files**: Research papers, vendor reports
- **Local Files**: Text files, markdown documents

## Output Files

Each analysis generates several files:

- **`ttp_heatmap.png`** - Visual heatmap of TTP frequency by tactic
- **`ttp_timeline.png`** - Timeline showing TTP evolution over time
- **`ttp_frequency.png`** - Frequency analysis and distribution charts
- **`analysis_results.json`** - Complete analysis data in JSON format

## Configuration Options

### Directory Settings
- `GROUPS_DIR` - Threat actor directories location
- `OUTPUT_DIR` - Analysis output location
- `DATA_DIR` - Data files location
- `LOG_DIR` - Log files location

### Extraction Settings
- `MIN_CONFIDENCE_THRESHOLD` - Minimum confidence for TTP matches
- `ENABLE_HEURISTIC_EXTRACTION` - Enable pattern-based extraction
- `MAX_REPORT_SIZE_MB` - Maximum report size to process

### Performance Settings
- `REQUEST_TIMEOUT` - HTTP request timeout
- `RATE_LIMIT_DELAY` - Delay between requests
- `MAX_CONCURRENT_REQUESTS` - Concurrent request limit

## Troubleshooting

### Common Issues

1. **No reports found**: Ensure `reports.txt` exists in actor directory
2. **HTTP errors**: Check network connectivity and rate limiting
3. **PDF parsing errors**: Install additional PDF libraries if needed
4. **Memory issues**: Reduce `MAX_REPORT_SIZE_MB` for large files

### Debug Mode

Enable debug logging for detailed information:

```bash
python ttp_analyzer.py --actor APT1 --verbose
```

### Log Files

Check log files for detailed error information:

```bash
tail -f logs/ttp_analyzer.log
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

### Development Setup

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Format code
black src/ tests/

# Check types
mypy src/
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [MITRE ATT&CK Framework](https://attack.mitre.org/) for the comprehensive threat intelligence framework
- Contributors and the cybersecurity community for threat intelligence data

## Changelog

### Version 1.0.0
- Initial release
- Multi-format report parsing
- MITRE ATT&CK TTP extraction
- Timeline analysis and visualization
- Configurable and extensible architecture

## Support

For questions, issues, or contributions:

- GitHub Issues: [https://github.com/yourusername/ttp-analyzer/issues](https://github.com/yourusername/ttp-analyzer/issues)
- Documentation: [https://ttp-analyzer.readthedocs.io/](https://ttp-analyzer.readthedocs.io/)
- Email: contact@ttp-analyzer.com
