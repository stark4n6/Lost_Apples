"""
BeaconNamingRecord Parser
This module parses encrypted .record files from the BeaconNamingRecord folder.
These files contain custom names and emojis assigned to trackers.
"""

import plistlib
from pathlib import Path
from typing import Dict, List, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class BeaconNamingRecord:
    """Represents a parsed beacon naming record."""
    
    def __init__(self, uuid: str):
        """
        Initialize a beacon naming record.
        
        Args:
            uuid: The UUID of the record (filename without .record extension)
        """
        self.uuid = uuid
        self.name = None
        self.emoji = None
        self.associated_beacon = None
        self.raw_data = {}
    
    def __str__(self) -> str:
        """Return a string representation of the record."""
        lines = [
            f"Record UUID: {self.uuid}",
            f"Name: {self.name or 'Not set'}",
            f"Emoji: {self.emoji or 'None'}",
            f"Associated Beacon: {self.associated_beacon or 'Unknown'}"
        ]
        return "\n".join(lines)


class BeaconNamingParser:
    """Parser for BeaconNamingRecord .record files."""
    
    def __init__(self, beacon_store_key: bytes):
        """
        Initialize the parser.
        
        Args:
            beacon_store_key: The 32-byte BeaconStore key from keychain
        """
        if len(beacon_store_key) != 32:
            raise ValueError(f"BeaconStore key must be 32 bytes, got {len(beacon_store_key)}")
        
        self.beacon_store_key = beacon_store_key
        self.aesgcm = AESGCM(beacon_store_key)
    
    def parse_record_file(self, record_path: str) -> Optional[BeaconNamingRecord]:
        """
        Parse a single .record file.
        
        Args:
            record_path: Path to the .record file
            
        Returns:
            BeaconNamingRecord object, or None if parsing fails
        """
        path = Path(record_path)
        
        # Extract UUID from filename
        uuid = path.stem
        record = BeaconNamingRecord(uuid)
        
        try:
            # Read the encrypted plist
            with open(record_path, 'rb') as f:
                encrypted_plist = plistlib.load(f)
            
            # Extract encryption components
            # Index 0: Nonce (IV) - 16 bytes
            # Index 1: GCM Tag - 16 bytes  
            # Index 2: Encrypted payload
            nonce = encrypted_plist[0]
            gcm_tag = encrypted_plist[1]
            encrypted_payload = encrypted_plist[2]
            
            # Verify sizes
            if len(nonce) != 16:
                print(f"Warning: Nonce is {len(nonce)} bytes, expected 16")
            if len(gcm_tag) != 16:
                print(f"Warning: GCM tag is {len(gcm_tag)} bytes, expected 16")
            
            # Decrypt using AES-256-GCM
            # In GCM mode, the tag is appended to the ciphertext
            ciphertext_with_tag = encrypted_payload + gcm_tag
            
            try:
                decrypted_data = self.aesgcm.decrypt(nonce, ciphertext_with_tag, None)
            except Exception as e:
                print(f"Decryption failed for {uuid}: {str(e)}")
                return None
            
            # Parse the decrypted plist
            decrypted_plist = plistlib.loads(decrypted_data)
            record.raw_data = decrypted_plist
            
            # Extract data from the decrypted plist
            self._extract_record_data(decrypted_plist, record)
            
            return record
            
        except Exception as e:
            print(f"Error parsing {record_path}: {str(e)}")
            return None
    
    def _extract_record_data(self, plist_data: dict, record: BeaconNamingRecord) -> None:
        """
        Extract relevant data from the decrypted plist.
        
        Args:
            plist_data: The decrypted plist dictionary
            record: The BeaconNamingRecord object to populate
        """
        # Extract the name
        # Common keys that might contain the name: 'name', 'displayName', 'beaconName'
        for name_key in ['name', 'displayName', 'beaconName', 'customName']:
            if name_key in plist_data:
                record.name = plist_data[name_key]
                break
        
        # Extract emoji
        # Common keys: 'emoji', 'symbol', 'icon'
        for emoji_key in ['emoji', 'symbol', 'icon', 'symbolName']:
            if emoji_key in plist_data:
                record.emoji = plist_data[emoji_key]
                break
        
        # Extract associated beacon UUID
        # The correct key is 'associatedBeacon' based on actual decrypted data
        for uuid_key in ['associatedBeacon', 'beaconIdentifier', 'uuid', 'beaconUUID', 'identifier']:
            if uuid_key in plist_data:
                uuid_value = plist_data[uuid_key]
                # Convert UUID object to string if needed
                if hasattr(uuid_value, '__str__'):
                    record.associated_beacon = str(uuid_value)
                else:
                    record.associated_beacon = uuid_value
                break
    
    def parse_directory(self, directory_path: str) -> List[BeaconNamingRecord]:
        """
        Parse all .record files in a directory and its subdirectories.
        
        Args:
            directory_path: Path to BeaconNamingRecord directory, or path to
                          the com.apple.icloud.searchpartyd parent directory
            
        Returns:
            List of successfully parsed BeaconNamingRecord objects
        """
        records = []
        directory = Path(directory_path)
        
        if not directory.exists():
            print(f"Directory not found: {directory_path}")
            return records
        
        # Check if this is the searchpartyd parent directory
        # If so, navigate to the BeaconNamingRecord subdirectory
        if directory.name == 'com.apple.icloud.searchpartyd':
            naming_dir = directory / 'BeaconNamingRecord'
            if naming_dir.exists():
                directory = naming_dir
                print(f"Using subdirectory: {naming_dir}")
            else:
                print(f"BeaconNamingRecord subdirectory not found in {directory_path}")
                return records
        
        # Find all .record files recursively (including in UUID subdirectories)
        record_files = list(directory.rglob("*.record"))
        
        print(f"Found {len(record_files)} .record files")
        
        for record_file in record_files:
            print(f"Parsing {record_file.name}...")
            record = self.parse_record_file(str(record_file))
            if record:
                records.append(record)
                print(f"  ✓ Successfully parsed")
            else:
                print(f"  ✗ Failed to parse")
        
        return records
    
    def export_to_csv(self, records: List[BeaconNamingRecord], output_path: str) -> bool:
        """
        Export parsed records to CSV format.
        
        Args:
            records: List of BeaconNamingRecord objects
            output_path: Path where the CSV file should be saved
            
        Returns:
            True if export successful, False otherwise
        """
        from .export_utils import ExportUtils, BeaconNamingExporter
        
        csv_data = BeaconNamingExporter.to_csv_format(records)
        return ExportUtils.export_to_csv(csv_data, output_path)


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 2:
        from keychain_parser import KeychainParser
        
        # Parse keychain to get BeaconStore key
        keychain_parser = KeychainParser(sys.argv[1])
        keys = keychain_parser.parse()
        beacon_key = keychain_parser.get_beacon_store_key()
        
        if not beacon_key:
            print("ERROR: BeaconStore key not found in keychain!")
            sys.exit(1)
        
        print(f"BeaconStore key found: {len(beacon_key)} bytes\n")
        
        # Parse BeaconNamingRecord files
        parser = BeaconNamingParser(beacon_key)
        records = parser.parse_directory(sys.argv[2])
        
        print(f"\n{'='*60}")
        print(f"Successfully parsed {len(records)} naming records")
        print(f"{'='*60}\n")
        
        # Display results
        for i, record in enumerate(records, 1):
            print(f"\n{'='*60}")
            print(f"Record {i}:")
            print(f"{'='*60}")
            print(record)
            print()
        
        # Offer to export
        print("\n" + "="*60)
        export_choice = input("\nExport to CSV? (y/n): ").strip().lower()
        
        if export_choice == 'y':
            csv_path = input("Enter CSV output path (default: beacon_naming_results.csv): ").strip()
            if not csv_path:
                csv_path = "beacon_naming_results.csv"
            parser.export_to_csv(records, csv_path)
    else:
        print("Usage: python beacon_naming_parser.py <keychain.plist> <BeaconNamingRecord_directory>")
        print("\nAlternatively, use with a hex key:")
        print("python beacon_naming_parser.py --key <hex_key> <BeaconNamingRecord_directory>")
