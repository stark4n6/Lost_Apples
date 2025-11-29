"""
iOS Keychain Parser for BeaconStore Key Extraction

This parser handles the decryption chain required to extract keys from
iOS keychain backups with the following structure:
1. Decode wrapped key from base64 -> nested bplist with IV, tag, ciphertext
2. Decrypt using class key -> reveals metadata key
3. Decode metadata from base64 -> nested bplist with IV, tag, ciphertext  
4. Decrypt using metadata key -> reveals metadata (including service name)
5. Decode data from base64 -> nested bplist with IV, tag, ciphertext
6. Decrypt using unwrapped key -> reveals actual key data (starts at offset 0x14)
"""

import plistlib
import base64
from Crypto.Cipher import AES
from typing import Dict, Any, Optional, Tuple
import struct


class iOSKeychainParser:
    """Parser for iOS keychain files with encrypted entries."""
    
    def __init__(self, keychain_path: str):
        """
        Initialize parser with keychain file.
        
        Args:
            keychain_path: Path to the backup_keychain_v2.plist file
        """
        self.keychain_path = keychain_path
        self.keychain_data = None
        self.class_keys = {}
        
    def load_keychain(self) -> bool:
        """
        Load and parse the keychain plist file.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(self.keychain_path, 'rb') as f:
                self.keychain_data = plistlib.load(f)
            
            # Load class keys
            if 'classKeyIdxToUnwrappedMetadataClassKey' in self.keychain_data:
                for idx, key_b64 in self.keychain_data['classKeyIdxToUnwrappedMetadataClassKey'].items():
                    # Decode base64 to get the class key
                    self.class_keys[int(idx)] = base64.b64decode(key_b64)
                    
            print(f"Loaded keychain with {len(self.keychain_data.get('keychainEntries', []))} entries")
            print(f"Loaded {len(self.class_keys)} class keys")
            return True
            
        except Exception as e:
            print(f"Error loading keychain: {e}")
            return False
    
    def _decrypt_aes_gcm(self, key: bytes, iv: bytes, ciphertext: bytes, tag: bytes) -> Optional[bytes]:
        """
        Decrypt data using AES-GCM.
        
        Args:
            key: Encryption key (32 bytes)
            iv: Initialization vector
            ciphertext: Encrypted data
            tag: Authentication tag
            
        Returns:
            Decrypted data or None if decryption fails
        """
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext
        except Exception as e:
            # Decryption can fail for many reasons - this is expected for non-matching keys
            return None
    
    def _parse_encrypted_plist(self, data: bytes) -> Optional[Dict[str, bytes]]:
        """
        Parse a nested bplist containing encrypted data.
        
        The plist should contain:
        - SFInitializationVector: IV for AES-GCM
        - SFAuthenticationCode: GCM tag
        - SFCipherText: Encrypted data
        
        Args:
            data: Binary plist data
            
        Returns:
            Dict with 'iv', 'tag', 'ciphertext' keys or None if parsing fails
        """
        try:
            plist = plistlib.loads(data)
            
            if not all(key in plist for key in ['SFInitializationVector', 'SFAuthenticationCode', 'SFCipherText']):
                return None
                
            return {
                'iv': plist['SFInitializationVector'],
                'tag': plist['SFAuthenticationCode'],
                'ciphertext': plist['SFCipherText']
            }
        except Exception:
            return None
    
    def _parse_metadata_asn1(self, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse ASN.1 encoded metadata.
        
        This is a simplified parser that extracts common keychain attributes.
        For a full parser, you'd need a proper ASN.1 library.
        
        Args:
            data: ASN.1 encoded metadata
            
        Returns:
            Dict of metadata attributes
        """
        metadata = {}
        
        # Look for common string patterns in the metadata
        # These are heuristic searches - a proper ASN.1 parser would be better
        try:
            # Try to find service name (svce)
            if b'svce' in data:
                idx = data.find(b'svce')
                # Try to extract the service name after the tag
                # This is a simplification - proper ASN.1 parsing would be better
                service_start = idx + 4
                if service_start < len(data):
                    # Look for length byte and extract
                    for i in range(service_start, min(service_start + 20, len(data))):
                        if data[i:i+11] == b'BeaconStore':
                            metadata['service'] = 'BeaconStore'
                            break
            
            # Look for account name (acct)  
            if b'acct' in data:
                idx = data.find(b'acct')
                acct_start = idx + 4
                if acct_start < len(data):
                    for i in range(acct_start, min(acct_start + 30, len(data))):
                        if data[i:i+14] == b'BeaconStoreKey':
                            metadata['account'] = 'BeaconStoreKey'
                            break
            
            # Try to decode as string to find readable text
            try:
                text = data.decode('utf-8', errors='ignore')
                if 'BeaconStore' in text:
                    metadata['service'] = 'BeaconStore'
                if 'BeaconStoreKey' in text:
                    metadata['account'] = 'BeaconStoreKey'
            except:
                pass
                
        except Exception as e:
            pass
            
        return metadata if metadata else None
    
    def _extract_key_from_asn1(self, data: bytes) -> Optional[bytes]:
        """
        Extract the 32-byte key from ASN.1 encoded data.
        
        According to the specification, the key starts at offset 0x14 (20 bytes).
        
        Args:
            data: ASN.1 encoded key data
            
        Returns:
            32-byte key or None if extraction fails
        """
        try:
            # Key should start at offset 0x14 and be 32 bytes long
            if len(data) >= 0x14 + 32:
                key = data[0x14:0x14 + 32]
                return key
            else:
                print(f"  Data too short: {len(data)} bytes (need at least {0x14 + 32})")
                return None
        except Exception as e:
            print(f"  Error extracting key: {e}")
            return None
    
    def process_keychain_entry(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process a single keychain entry through the full decryption chain.
        
        Steps:
        1. Get class key index and corresponding class key
        2. Decode wrapped key -> decrypt with class key -> get metadata key
        3. Decode metadata -> decrypt with metadata key -> get metadata (service/account)
        4. Decode data -> decrypt with unwrapped key -> get actual key
        
        Args:
            entry: Keychain entry dict
            
        Returns:
            Dict with decrypted information or None if processing fails
        """
        try:
            # Step 1: Get the class key
            class_key_idx = entry.get('classKeyIdx')
            if class_key_idx is None or class_key_idx not in self.class_keys:
                return None
                
            class_key = self.class_keys[class_key_idx]
            
            # Step 2: Decrypt wrapped key to get metadata key
            wrapped_key_b64 = entry.get('metadata', {}).get('wrappedKey')
            if not wrapped_key_b64:
                return None
                
            # Decode base64
            wrapped_key_data = base64.b64decode(wrapped_key_b64)
            
            # Parse nested plist
            wrapped_key_plist = self._parse_encrypted_plist(wrapped_key_data)
            if not wrapped_key_plist:
                return None
            
            # Decrypt with class key to get metadata key
            metadata_key = self._decrypt_aes_gcm(
                class_key,
                wrapped_key_plist['iv'],
                wrapped_key_plist['ciphertext'],
                wrapped_key_plist['tag']
            )
            
            if not metadata_key:
                return None
            
            # Verify metadata key is 32 bytes
            if len(metadata_key) != 32:
                return None
            
            # Step 3: Decrypt metadata to get service/account info
            metadata_b64 = entry.get('metadata', {}).get('ciphertext')
            if not metadata_b64:
                return None
            
            # Decode base64
            metadata_encrypted = base64.b64decode(metadata_b64)
            
            # Parse nested plist
            metadata_plist = self._parse_encrypted_plist(metadata_encrypted)
            if not metadata_plist:
                return None
            
            # Decrypt with metadata key
            metadata_decrypted = self._decrypt_aes_gcm(
                metadata_key,
                metadata_plist['iv'],
                metadata_plist['ciphertext'],
                metadata_plist['tag']
            )
            
            if not metadata_decrypted:
                return None
            
            # Parse metadata (ASN.1)
            metadata_info = self._parse_metadata_asn1(metadata_decrypted)
            
            # Step 4: Decrypt data to get actual key
            data_b64 = entry.get('data', {}).get('ciphertext')
            unwrapped_key_b64 = entry.get('data', {}).get('unwrappedKey')
            
            if not data_b64 or not unwrapped_key_b64:
                return None
            
            # Decode base64
            data_encrypted = base64.b64decode(data_b64)
            unwrapped_key = base64.b64decode(unwrapped_key_b64)
            
            # Verify unwrapped key is 32 bytes
            if len(unwrapped_key) != 32:
                return None
            
            # Parse nested plist
            data_plist = self._parse_encrypted_plist(data_encrypted)
            if not data_plist:
                return None
            
            # Decrypt with unwrapped key
            key_data_decrypted = self._decrypt_aes_gcm(
                unwrapped_key,
                data_plist['iv'],
                data_plist['ciphertext'],
                data_plist['tag']
            )
            
            if not key_data_decrypted:
                return None
            
            # Extract the actual key from offset 0x14
            actual_key = self._extract_key_from_asn1(key_data_decrypted)
            
            if not actual_key:
                return None
            
            # Return results
            return {
                'rowID': entry.get('rowID'),
                'table': entry.get('table'),
                'metadata': metadata_info,
                'key': actual_key,
                'key_hex': actual_key.hex()
            }
            
        except Exception as e:
            # Most entries will fail - this is normal as we're only looking for BeaconStore
            return None
    
    def find_beacon_store_key(self) -> Optional[bytes]:
        """
        Search through all keychain entries to find the BeaconStore key.
        
        Returns:
            32-byte BeaconStore key or None if not found
        """
        if not self.keychain_data:
            print("Keychain not loaded. Call load_keychain() first.")
            return None
        
        entries = self.keychain_data.get('keychainEntries', [])
        print(f"\nSearching {len(entries)} keychain entries for BeaconStore key...")
        
        found_count = 0
        
        for i, entry in enumerate(entries):
            if (i + 1) % 100 == 0:
                print(f"  Processed {i + 1}/{len(entries)} entries... (found {found_count} so far)")
            
            result = self.process_keychain_entry(entry)
            
            if result:
                found_count += 1
                metadata = result.get('metadata', {})
                
                print(f"\n✓ Successfully decrypted entry {result['rowID']}:")
                print(f"  Table: {result['table']}")
                if metadata:
                    print(f"  Service: {metadata.get('service', 'Unknown')}")
                    print(f"  Account: {metadata.get('account', 'Unknown')}")
                print(f"  Key: {result['key_hex']}")
                
                # Check if this is the BeaconStore key
                if metadata and metadata.get('service') == 'BeaconStore' and metadata.get('account') == 'BeaconStoreKey':
                    print(f"\n🎉 Found BeaconStore key!")
                    return result['key']
        
        print(f"\nProcessed all {len(entries)} entries.")
        print(f"Successfully decrypted {found_count} entries total.")
        print("BeaconStore key not found.")
        return None
    
    def get_all_keys(self) -> list:
        """
        Extract all successfully decrypted keys from the keychain.
        
        Returns:
            List of dicts containing key information
        """
        if not self.keychain_data:
            print("Keychain not loaded. Call load_keychain() first.")
            return []
        
        entries = self.keychain_data.get('keychainEntries', [])
        results = []
        
        print(f"\nProcessing {len(entries)} keychain entries...")
        
        for i, entry in enumerate(entries):
            if (i + 1) % 100 == 0:
                print(f"  Processed {i + 1}/{len(entries)} entries...")
            
            result = self.process_keychain_entry(entry)
            if result:
                results.append(result)
        
        print(f"\nSuccessfully decrypted {len(results)} entries out of {len(entries)} total.")
        return results


def main():
    """Example usage of the parser."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python ios_keychain_parser.py <path_to_keychain.plist>")
        sys.exit(1)
    
    keychain_path = sys.argv[1]
    
    # Create parser
    parser = iOSKeychainParser(keychain_path)
    
    # Load keychain
    if not parser.load_keychain():
        print("Failed to load keychain")
        sys.exit(1)
    
    # Find BeaconStore key
    beacon_key = parser.find_beacon_store_key()
    
    if beacon_key:
        print(f"\n✅ BeaconStore Key: {beacon_key.hex()}")
        print("\nYou can now use this key with the WildMode parser!")
    else:
        print("\n❌ Could not find BeaconStore key")
        print("\nTrying to show all decrypted keys...")
        all_keys = parser.get_all_keys()
        
        if all_keys:
            print(f"\nFound {len(all_keys)} decrypted keys:")
            for key_info in all_keys:
                metadata = key_info.get('metadata', {})
                print(f"\n  Entry {key_info['rowID']}:")
                print(f"    Service: {metadata.get('service', 'Unknown')}")
                print(f"    Account: {metadata.get('account', 'Unknown')}")
                print(f"    Key: {key_info['key_hex']}")


if __name__ == '__main__':
    main()
