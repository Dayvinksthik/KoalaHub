# patch.py - Fix for audioop module in Python 3.13
import sys

# Mock audioop module for Python 3.13 compatibility
class MockAudioop:
    def __getattr__(self, name):
        return lambda *args, **kwargs: None

# Mock the audioop module before importing discord
if "audioop" not in sys.modules:
    sys.modules["audioop"] = MockAudioop()

# Now import and run your bot
try:
    import discord
    # Disable voice functionality
    discord.opus = None
    discord.VoiceClient = None
except ImportError:
    pass