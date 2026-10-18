"""Start the ReleaseGuard dashboard:  python run.py"""
import os
from releaseguard.app import create_app

if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
