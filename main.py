"""
x2y AV Ultimate v8.0.5
Run: python main.py
Requirements: pip install -r requirements.txt
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from app import X2yAVApp

if __name__ == "__main__":
    app = X2yAVApp()
    app.mainloop()