import hvac
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import db, UserChatLock, ChatParticipant

vault_bp = Blueprint('vault', __name__)

class KeyVault:
    def __init__(self):
        # Connect to the Vault container
        self.client = hvac.Client(
            url='http://vault:8200', 
            token='root-token-securebook-master'
        )
        self.mount_point = 'secret' # The mount path you created in the UI
        
        # --- NEW: Enforce Max Versions on Startup ---
        if self.is_ready():
            self.configure_vault_policy()

    def is_ready(self):
        try:
            return self.client.is_authenticated()
        except:
            return False

    # --- NEW METHOD: Set Max Versions ---
    def configure_vault_policy(self):
        try:
            # max_versions=5 means Vault will keep the 5 most recent keys 
            # and automatically delete anything older.
            self.client.secrets.kv.v2.configure(
                max_versions=5,
                mount_point=self.mount_point
            )
            print(f"Vault Configured: Max versions set to 5 for '{self.mount_point}'")
        except Exception as e:
            print(f"Vault Configuration Warning: {e}")

    def store_user_key(self, user_id, private_key_blob):
        try:
            # check_and_set (cas) can be used here if you want strict locking
            self.client.secrets.kv.v2.create_or_update_secret(
                path=f'users/{user_id}',
                secret=dict(private_key=private_key_blob),
                mount_point=self.mount_point
            )
            return True
        except Exception as e:
            print(f"Vault Store Error: {e}")
            return False

    def get_user_key(self, user_id):
        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=f'users/{user_id}',
                mount_point=self.mount_point
            )
            return response['data']['data']['private_key']
        except Exception:
            return None


    #--- Chat Lock ---
    def update_chat_lock(self, user_id, chat_id, lock_data):
        # We use PATCH to add/update just this chat_id without deleting others
        try:
            # Data structure: { "chat_123": { "type": "pin", "secret": "hash..." } }
            patch_data = { str(chat_id): lock_data }
            
            self.client.secrets.kv.v2.patch(
                path=f'locks/{user_id}',
                secret=patch_data,
                mount_point=self.mount_point
            )
            return True
        except Exception as e:
            print(f"Vault Lock Update Error: {e}")
            # If patch fails (e.g., first time creation), try create
            try:
                self.client.secrets.kv.v2.create_or_update_secret(
                    path=f'locks/{user_id}',
                    secret=patch_data,
                    mount_point=self.mount_point
                )
                return True
            except:
                return False
            
    def remove_chat_lock(self, user_id, chat_id):
        try:
            path = f'locks/{user_id}'
            # 1. Read the current list of locks
            try:
                response = self.client.secrets.kv.v2.read_secret_version(
                    path=path,
                    mount_point=self.mount_point
                )
                current_locks = response['data']['data']
            except:
                return True # If no secret exists, nothing to delete

            # 2. Delete the specific chat_id key
            chat_key = str(chat_id)
            if chat_key in current_locks:
                del current_locks[chat_key]

                # 3. Write the cleaned dictionary back (Replace)
                self.client.secrets.kv.v2.create_or_update_secret(
                    path=path,
                    secret=current_locks,
                    mount_point=self.mount_point
                )
            return True
        except Exception as e:
            print(f"Vault Remove Error: {e}")
            return False    

    def get_all_locks(self, user_id):
        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=f'locks/{user_id}',
                mount_point=self.mount_point
            )
            return response['data']['data']
        except Exception:
            return {}
# Initialize

vault_service = KeyVault()

# --- ROUTES ---

@vault_bp.route('/api/vault/backup_key', methods=['POST'])
@login_required
def vault_backup_key():
    data = request.get_json()
    private_key = data.get('private_key')
    
    if not private_key:
        return jsonify({'error': 'No key provided'}), 400

    success = vault_service.store_user_key(current_user.user_id, private_key)
    
    if success:
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Vault storage failed'}), 500

@vault_bp.route('/api/vault/restore_key', methods=['GET'])
@login_required
def vault_restore_key():
    private_key = vault_service.get_user_key(current_user.user_id)
    
    if private_key:
        return jsonify({'success': True, 'private_key': private_key})
    else:
        return jsonify({'success': False, 'message': 'No key found in vault'})
    

@vault_bp.route('/api/vault/sync_lock', methods=['POST'])
@login_required
def vault_sync_lock():
    data = request.get_json()
    chat_id = data.get('chat_id')
    lock_data = data.get('lock_data') # { type: 'pin', secret: '...' }
    
    if not chat_id or not lock_data:
        return jsonify({'error': 'Missing data'}), 400

    if lock_data is None:
        success = vault_service.remove_chat_lock(current_user.user_id, chat_id)
    else:
        success = vault_service.update_chat_lock(current_user.user_id, chat_id, lock_data)

    return jsonify({'success': success})

@vault_bp.route('/api/vault/get_locks', methods=['GET'])
@login_required
def vault_get_locks():
    locks = vault_service.get_all_locks(current_user.user_id)
    return jsonify({'success': True, 'locks': locks})

@vault_bp.route('/api/sync_chat_lock/<int:chat_id>', methods=['POST'])
@login_required
def sync_chat_lock(chat_id):
    """
    Sync chat lock per-user.
    Each user can lock/unlock independently.
    """
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        is_locked = data.get('is_locked')
        pin_hash = data.get('pin_hash')
        lock_type = data.get('lock_type')
        
        # Security: only allow user to lock their own chats
        if str(user_id) != str(current_user.user_id):
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Verify user is in this chat
        chat_participant = ChatParticipant.query.filter_by(
            chat_id=chat_id, 
            user_id=user_id
        ).first()
        
        if not chat_participant:
            return jsonify({'error': 'Not a chat participant'}), 403
        
        # Update UserChatLock for this user+chat combination
        lock = UserChatLock.query.filter_by(
            user_id=user_id,
            chat_id=chat_id
        ).first()
        
        if is_locked:
            if not lock:
                lock = UserChatLock(user_id=user_id, chat_id=chat_id)
            lock.is_locked = True
            lock.pin_hash = pin_hash
            lock.lock_type = lock_type
            db.session.add(lock)
        else:
            # Remove lock if exists
            if lock:
                db.session.delete(lock)
        
        db.session.commit()
        return jsonify({'ok': True})
        
    except Exception as e:
        app.logger.error(f"Error syncing chat lock: {e}")
        return jsonify({'error': str(e)}), 500
    
@vault_bp.route('/api/get_locked_chats', methods=['GET'])
@login_required
def get_locked_chats():
    """Get all locked chats for current user (per-user locks only)."""
    locked_chats = UserChatLock.query.filter_by(
        user_id=current_user.user_id,
        is_locked=True
    ).all()
    
    return jsonify({
        'locked_chats': {str(lock.chat_id): lock.pin_hash for lock in locked_chats}
    })


    