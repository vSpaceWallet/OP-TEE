import json
import os
import logging
from Crypto.PublicKey import RSA, ECC

logger = logging.getLogger(__name__)

class KeyManager:
    def __init__(self):
        self.keys = {}
        self.key_file = 'keys.json'
        self.load_keys()
        logger.debug(f"Loaded keys: {self.keys}")

    def generate_key(self, key_type):
        try:
            if key_type == 'RSA':
                key = RSA.generate(2048)
            elif key_type == 'ECC':
                key = ECC.generate(curve='P-256')
            else:
                raise ValueError(f"Unsupported key type: {key_type}")
            
            key_id = f"{key_type}_{len(self.keys)}"
            self.keys[key_id] = {
                'type': key_type,
                'private_key': key.export_key(format='PEM').decode('utf-8') if isinstance(key.export_key(format='PEM'), bytes) else key.export_key(format='PEM'),
                'public_key': key.public_key().export_key(format='PEM').decode('utf-8') if isinstance(key.public_key().export_key(format='PEM'), bytes) else key.public_key().export_key(format='PEM')
            }
            self.save_keys()
            logger.info(f"Generated new {key_type} key with ID: {key_id}")
            return key_id
        except Exception as e:
            logger.error(f"Error generating {key_type} key: {str(e)}")
            raise

    def get_key(self, key_id):
        try:
            key_data = self.keys.get(key_id)
            if not key_data:
                raise ValueError(f"Key not found: {key_id}")
            
            if key_data['type'] == 'RSA':
                return RSA.import_key(key_data['private_key'])
            elif key_data['type'] == 'ECC':
                return ECC.import_key(key_data['private_key'])
        except Exception as e:
            logger.error(f"Error retrieving key {key_id}: {str(e)}")
            raise

    def get_public_key(self, key_id):
        try:
            key_data = self.keys.get(key_id)
            if not key_data:
                raise ValueError(f"Key not found: {key_id}")
            
            if key_data['type'] == 'RSA':
                return RSA.import_key(key_data['public_key'])
            elif key_data['type'] == 'ECC':
                return ECC.import_key(key_data['public_key'])
        except Exception as e:
            logger.error(f"Error retrieving public key for {key_id}: {str(e)}")
            raise

    def load_keys(self):
        try:
            if os.path.exists(self.key_file):
                with open(self.key_file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        self.keys = json.loads(content)
                    else:
                        self.keys = {}
            else:
                self.keys = {}
            logger.info("Keys loaded successfully")
        except Exception as e:
            logger.error(f"Error loading keys: {str(e)}")
            self.keys = {}

    def save_keys(self):
        try:
            with open(self.key_file, 'w') as f:
                json.dump(self.keys, f, indent=2)
            logger.info("Keys saved successfully")
        except Exception as e:
            logger.error(f"Error saving keys: {str(e)}")
            raise

    def list_keys(self):
        return list(self.keys.keys())

    def remove_key(self, key_id):
        try:
            if key_id in self.keys:
                del self.keys[key_id]
                self.save_keys()
                logger.info(f"Key {key_id} removed successfully")
            else:
                logger.warning(f"Key {key_id} not found for removal")
        except Exception as e:
            logger.error(f"Error removing key {key_id}: {str(e)}")
            raise

    def clear_keys(self):
        try:
            self.keys = {}
            self.save_keys()
            logger.info("All keys cleared successfully")
        except Exception as e:
            logger.error(f"Error clearing keys: {str(e)}")
            raise
