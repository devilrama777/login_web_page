import sys
import os

# Ensure current directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app

# Export for all WSGI runners
handler = app
application = app
