import sys
import os

# Add the project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from website.app import create_app

# Create the Flask application
app = create_app()

if __name__ == "__main__":
    # Get port from environment variable, default to 10000
    port = int(os.environ.get("PORT", 10000))
    
    # IMPORTANT: Use 0.0.0.0 to bind to all interfaces
    app.run(host='0.0.0.0', port=port, debug=False)