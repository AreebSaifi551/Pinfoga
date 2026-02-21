# Pinfoga
A tool to find information about phone numbers, emails, domains and stealer data

# Requirments

pip install requests colorama tabulate bs4 dnspython whois

# Environment Setup

python -m venv osint_env
source osint_env/bin/activate  # Linux/Mac
osint_env\Scripts\activate     # Windows
pip install -r requirements.txt

# System Wide Installation

sudo apt-get install python3-pip python3-dev
pip3 install requests colorama tabulate bs4 dnspython whois

# Usage 

# Email analysis
python osint_tool.py --email "user@example.com"

# Phone analysis
python osint_tool.py --phone "+1234567890"

# Domain analysis
python osint_tool.py --domain "example.com"

# Stealer data analysis
python osint_tool.py --stealer-data "stealer.json"



