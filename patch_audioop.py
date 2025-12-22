# patch_audioop.py - Mock audioop module for Python 3.13
import sys

# Check Python version
if sys.version_info >= (3, 13):
    # Mock audioop module
    class MockAudioop:
        def __getattr__(self, name):
            # Return a dummy function
            return lambda *args, **kwargs: b''
    
    # Replace audioop with mock
    sys.modules['audioop'] = MockAudioop()
    
    print("⚠️  Python 3.13+ detected - Mocking audioop module")