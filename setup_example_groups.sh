#!/bin/bash
# Setup script for TTP Analyzer example groups

set -e

echo "Setting up TTP Analyzer example groups..."

# Create main directories
mkdir -p groups output data logs

# Function to create threat actor directory and reports file
create_actor() {
    local actor_name="$1"
    local actor_dir="groups/$actor_name"
    
    echo "Creating $actor_name..."
    mkdir -p "$actor_dir"
    
    # Create reports.txt with content passed as remaining arguments
    shift
    cat > "$actor_dir/reports.txt" << EOF
# $actor_name Threat Intelligence Reports
# Add one URL per line, comments start with #

EOF
    
    # Add each URL
    for url in "$@"; do
        echo "$url" >> "$actor_dir/reports.txt"
    done
    
    echo "✓ Created $actor_name with $(($# )) report URLs"
}

# Create APT1
create_actor "APT1" \
    "https://attack.mitre.org/groups/G0006/" \
    "https://www.mandiant.com/resources/blog/apt1-exposing-one-of-chinas-cyber-espionage-units" \
    "https://www.crowdstrike.com/blog/adversary-of-the-month-for-january/"

# Create Scattered Spider  
create_actor "scattered_spider" \
    "https://www.crowdstrike.com/blog/scattered-spider-attempts-to-avoid-detection-with-bring-your-own-vulnerable-driver-tactic/" \
    "https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/" \
    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a"

# Create Lazarus
create_actor "lazarus" \
    "https://attack.mitre.org/groups/G0032/" \
    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-239a" \
    "https://www.microsoft.com/en-us/security/blog/2021/01/28/zinc-attacks-against-security-researchers/"

# Create APT29
create_actor "apt29" \
    "https://attack.mitre.org/groups/G0016/" \
    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-116a" \
    "https://www.crowdstrike.com/blog/bears-midst-intrusion-campaigns-targeting-healthcare/"

# Create test actor for validation
create_actor "test_actor" \
    "https://attack.mitre.org/groups/G0006/" \
    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-116a"

echo ""
echo "✅ Example groups structure created successfully!"
echo ""
echo "Directory structure:"
echo "groups/"
find groups -type f -name "reports.txt" | sort | sed 's/^/├── /' | sed 's/reports.txt$/reports.txt (ready)/'

echo ""
echo "You can now run:"
echo "  python ttp_analyzer.py --list-actors"
echo "  python ttp_analyzer.py --actor APT1"
echo "  python ttp_analyzer.py --actor test_actor --verbose"

echo ""
echo "For a complete test run:"
echo "  python test_installation.py"
