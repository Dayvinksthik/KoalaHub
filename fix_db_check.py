import os
import sys

def fix_all_db_checks():
    """Fix all database boolean checks in the code"""
    
    # Files to fix
    files_to_fix = ['bot/bot.py']
    
    for filepath in files_to_fix:
        if os.path.exists(filepath):
            print(f"🔧 Fixing {filepath}...")
            
            with open(filepath, 'r') as f:
                content = f.read()
            
            # Fix all variations
            replacements = [
                ('if not self.db', 'if self.db is None'),
                ('if self.db', 'if self.db is not None'),
                ('if not self.db_client', 'if self.db_client is None'),
                ('if self.db_client', 'if self.db_client is not None'),
                ('if db is not None', 'if db is not None'),  # Already correct
                ('if db:', 'if db is not None:'),
                ('if not db:', 'if db is None:'),
            ]
            
            for old, new in replacements:
                if old in content:
                    content = content.replace(old, new)
                    print(f"  Replaced: {old} -> {new}")
            
            with open(filepath, 'w') as f:
                f.write(content)
            
            print(f"✅ Fixed {filepath}\n")
        else:
            print(f"❌ File not found: {filepath}")

if __name__ == "__main__":
    fix_all_db_checks()
    print("Now run the system again:")
    print("python run.py")