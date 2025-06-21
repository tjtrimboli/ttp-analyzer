#!/usr/bin/env python3
"""
Setup script for MITRE ATT&CK TTP Analyzer
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements from requirements.txt
requirements_file = Path(__file__).parent / "requirements.txt"
if requirements_file.exists():
    with open(requirements_file, 'r', encoding='utf-8') as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]
else:
    requirements = [
        'requests>=2.28.0',
        'beautifulsoup4>=4.11.0',
        'PyPDF2>=3.0.0',
        'pyyaml>=6.0',
        'pandas>=1.5.0',
        'numpy>=1.21.0',
        'matplotlib>=3.5.0',
        'seaborn>=0.11.0'
    ]

setup(
    name="ttp-analyzer",
    version="1.0.0",
    author="TTP Analyzer Team",
    author_email="contact@ttp-analyzer.com",
    description="MITRE ATT&CK TTP Analyzer for Threat Actor Evolution Analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/ttp-analyzer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-cov>=4.0.0',
            'black>=22.0.0',
            'flake8>=5.0.0',
            'mypy>=0.991'
        ],
        'docs': [
            'sphinx>=5.0.0',
            'sphinx-rtd-theme>=1.0.0'
        ]
    },
    entry_points={
        'console_scripts': [
            'ttp-analyzer=ttp_analyzer:main',
        ],
    },
    include_package_data=True,
    package_data={
        'src': ['data/*.json', 'templates/*.yaml'],
    },
    zip_safe=False,
    keywords="cybersecurity, threat-intelligence, mitre-attack, ttp-analysis, threat-actors",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/ttp-analyzer/issues",
        "Source": "https://github.com/yourusername/ttp-analyzer",
        "Documentation": "https://ttp-analyzer.readthedocs.io/",
    },
)
