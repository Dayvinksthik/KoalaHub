import json
from datetime import datetime
import os
import shutil
from config import Config

def backup_database():
    """Backup MongoDB collections to JSON files"""
    try:
        from pymongo import MongoClient
        
        client = MongoClient(Config.MONGODB_URI)
        db = client[Config.DATABASE_NAME]
        
        # Create backup directory with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_dir = f"backups/{timestamp}"
        os.makedirs(backup_dir, exist_ok=True)
        
        # Backup collections
        collections = ['users', 'banned_ips']
        backup_info = {
            'timestamp': datetime.now().isoformat(),
            'collections': []
        }
        
        for collection_name in collections:
            try:
                collection = db[collection_name]
                # Convert ObjectId to string for JSON serialization
                data = list(collection.find())
                
                # Convert ObjectId to string
                for item in data:
                    if '_id' in item:
                        item['_id'] = str(item['_id'])
                
                if data:
                    backup_file = f"{backup_dir}/{collection_name}.json"
                    with open(backup_file, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=2, default=str)
                    
                    backup_info['collections'].append({
                        'name': collection_name,
                        'count': len(data),
                        'file': backup_file
                    })
                    
                    print(f"✅ Backed up {collection_name}: {len(data)} records")
                
            except Exception as e:
                print(f"❌ Failed to backup {collection_name}: {e}")
        
        # Save backup info
        info_file = f"{backup_dir}/backup_info.json"
        with open(info_file, 'w', encoding='utf-8') as f:
            json.dump(backup_info, f, indent=2, default=str)
        
        # Clean old backups (keep last 7 days)
        clean_old_backups()
        
        return backup_dir
        
    except Exception as e:
        print(f"❌ Backup failed: {e}")
        return None

def clean_old_backups(days_to_keep=7):
    """Clean old backup files"""
    try:
        if not os.path.exists('backups'):
            return
        
        current_time = datetime.now()
        
        for backup_folder in os.listdir('backups'):
            backup_path = os.path.join('backups', backup_folder)
            
            if os.path.isdir(backup_path):
                try:
                    # Extract timestamp from folder name (format: YYYYMMDD_HHMMSS)
                    folder_date = datetime.strptime(backup_folder, '%Y%m%d_%H%M%S')
                    
                    # Calculate age in days
                    age_days = (current_time - folder_date).days
                    
                    if age_days > days_to_keep:
                        shutil.rmtree(backup_path)
                        print(f"🗑️  Deleted old backup: {backup_folder} ({age_days} days old)")
                        
                except ValueError:
                    # Folder name doesn't match timestamp format, skip
                    pass
                    
    except Exception as e:
        print(f"❌ Failed to clean old backups: {e}")