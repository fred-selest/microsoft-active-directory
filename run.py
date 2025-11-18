#!/usr/bin/env python3
"""
Cross-platform runner for AD Web Interface.
Automatically detects OS and uses appropriate server.
"""

import os
import sys
import platform

def main():
    # Ensure we're in the correct directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    # Load environment variables from .env if exists
    env_file = os.path.join(script_dir, '.env')
    if os.path.exists(env_file):
        try:
            from dotenv import load_dotenv
            load_dotenv(env_file)
            print(f"Loaded configuration from {env_file}")
        except ImportError:
            print("Note: python-dotenv not installed, .env file not loaded")

    # Import and run the app
    from app import run_server
    run_server()


if __name__ == '__main__':
    main()
