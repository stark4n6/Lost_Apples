"""
SharedBeacons Parser
This module parses encrypted .record files from the SharedBeacons folder.
These files contain information about beacons that have been shared with the iCloud account.
"""

import plistlib
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SharedBeaconRecord:
    """Represents a parsed shared beacon record."""
    
    def __init__(self, uuid: str):
        """
        Initialize a shared beacon record.
        
        Args:
            uuid: The UUID of the record (filename without .record extension)
        """
        self.uuid = uuid
        self.identifier = None  # UUID of the beacon
        self.destination = None  # iCloud account that shared the beacon (email or phone)
        self.share_date = None  # When the beacon was shared
        self.beacon_name = None  # Name associated with the beacon (from BeaconNamingRecord)
        self.raw_data = {}
    
    def __str__(self) -> str:
        """Return a string representation of the record."""
        lines = [
            f"Record UUID: {self.uuid}",
            f"Beacon Identifier: {self.identifier or 'Unknown'}",
            f"Shared By: {self.destination or 'Unknown'}",
            f"Share Date: {self.share_date or 'Unknown'}",
            f"Beacon Name: {self.beacon_name or '(Not assigned)'}"
        ]
        return "\n".join(lines)


class SharedBeaconsParser:
    """Parser for SharedBeacons .record files."""
    
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
    
    def parse_record_file(self, record_path: str) -> Optional[SharedBeaconRecord]:
        """
        Parse a single .record file.
        
        Args:
            record_path: Path to the .record file
            
        Returns:
            SharedBeaconRecord object, or None if parsing fails
        """
        path = Path(record_path)
        
        # Extract UUID from filename
        uuid = path.stem
        record = SharedBeaconRecord(uuid)
        
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
    
    def _extract_record_data(self, plist_data: dict, record: SharedBeaconRecord) -> None:
        """
        Extract relevant data from the decrypted plist.
        
        Args:
            plist_data: The decrypted plist dictionary
            record: The SharedBeaconRecord object to populate
        """
        # Extract the beacon identifier (UUID)
        for id_key in ['identifier', 'beaconIdentifier', 'uuid', 'beaconUUID', 'id']:
            if id_key in plist_data:
                id_value = plist_data[id_key]
                # Convert UUID object to string if needed
                if hasattr(id_value, '__str__'):
                    record.identifier = str(id_value)
                else:
                    record.identifier = id_value
                break
        
        # Extract the destination (who shared the beacon)
        # This can be an email address or phone number
        for dest_key in ['destination', 'sharedBy', 'owner', 'from', 'sharingIdentity']:
            if dest_key in plist_data:
                record.destination = plist_data[dest_key]
                break
        
        # Extract the share date
        for date_key in ['shareDate', 'sharedDate', 'dateShared', 'creationDate', 'timestamp']:
            if date_key in plist_data:
                date_value = plist_data[date_key]
                # Handle datetime objects
                if isinstance(date_value, datetime):
                    record.share_date = date_value
                # Handle Unix timestamps
                elif isinstance(date_value, (int, float)):
                    try:
                        record.share_date = datetime.fromtimestamp(date_value)
                    except (ValueError, OSError):
                        # Try as milliseconds timestamp
                        try:
                            record.share_date = datetime.fromtimestamp(date_value / 1000.0)
                        except:
                            pass
                # Handle string dates
                elif isinstance(date_value, str):
                    try:
                        record.share_date = datetime.fromisoformat(date_value)
                    except:
                        pass
                break
    
    def parse_directory(self, directory_path: str) -> List[SharedBeaconRecord]:
        """
        Parse all .record files in a directory.
        
        Args:
            directory_path: Path to SharedBeacons directory, or path to
                          the com.apple.icloud.searchpartyd parent directory
            
        Returns:
            List of successfully parsed SharedBeaconRecord objects
        """
        records = []
        directory = Path(directory_path)
        
        if not directory.exists():
            print(f"Directory not found: {directory_path}")
            return records
        
        # Check if this is the searchpartyd parent directory
        # If so, navigate to the SharedBeacons subdirectory
        if directory.name == 'com.apple.icloud.searchpartyd':
            shared_dir = directory / 'SharedBeacons'
            if shared_dir.exists():
                directory = shared_dir
                print(f"Using subdirectory: {shared_dir}")
            else:
                print(f"SharedBeacons subdirectory not found in {directory_path}")
                return records
        
        # Find all .record files
        record_files = list(directory.glob("*.record"))
        
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
    
    def associate_beacon_names(self, shared_records: List[SharedBeaconRecord],
                               naming_records: List) -> None:
        """
        Associate beacon names from BeaconNamingRecord with SharedBeacons.
        
        Args:
            shared_records: List of SharedBeaconRecord objects
            naming_records: List of BeaconNamingRecord objects
        """
        if not naming_records:
            print("No BeaconNamingRecord data available for name association")
            return
        
        # Create a mapping of beacon UUID to name
        name_map = {}
        for naming_record in naming_records:
            if naming_record.associated_beacon and naming_record.name:
                name_map[naming_record.associated_beacon.upper()] = naming_record.name
        
        # Associate names with shared beacons
        associations_made = 0
        for record in shared_records:
            if record.identifier:
                identifier_upper = record.identifier.upper()
                if identifier_upper in name_map:
                    record.beacon_name = name_map[identifier_upper]
                    associations_made += 1
        
        print(f"Associated names with {associations_made} of {len(shared_records)} shared beacons")
    
    def export_to_csv(self, records: List[SharedBeaconRecord], output_path: str) -> bool:
        """
        Export parsed records to CSV format.
        
        Args:
            records: List of SharedBeaconRecord objects
            output_path: Path where the CSV file should be saved
            
        Returns:
            True if export successful, False otherwise
        """
        from .export_utils import ExportUtils, SharedBeaconsExporter
        
        csv_data = SharedBeaconsExporter.to_csv_format(records)
        return ExportUtils.export_to_csv(csv_data, output_path)


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 2:
        from ios_keychain_extractor import iOSKeychainExtractor
        
        # Parse keychain to get BeaconStore key
        keychain_path = sys.argv[1]
        extractor = iOSKeychainExtractor(keychain_path)
        keys = extractor.parse()
        beacon_key = extractor.get_beacon_store_key()
        
        if not beacon_key:
            print("ERROR: BeaconStore key not found in keychain!")
            sys.exit(1)
        
        print(f"BeaconStore key found: {len(beacon_key)} bytes\n")
        
        # Parse SharedBeacons files
        parser = SharedBeaconsParser(beacon_key)
        records = parser.parse_directory(sys.argv[2])
        
        print(f"\n{'='*60}")
        print(f"Successfully parsed {len(records)} shared beacon records")
        print(f"{'='*60}\n")
        
        # Display results
        for i, record in enumerate(records, 1):
            print(f"\n{'='*60}")
            print(f"Record {i}:")
            print(f"{'='*60}")
            print(record)
            print()
        
        # Optionally associate beacon names if BeaconNamingRecord is available
        if len(sys.argv) > 3:
            from beacon_naming_parser import BeaconNamingParser
            
            print("\n" + "="*60)
            print("Associating beacon names...")
            print("="*60 + "\n")
            
            naming_parser = BeaconNamingParser(beacon_key)
            naming_records = naming_parser.parse_directory(sys.argv[3])
            
            parser.associate_beacon_names(records, naming_records)
            
            # Display updated results
            print("\n" + "="*60)
            print("Updated records with associated names:")
            print("="*60 + "\n")
            
            for i, record in enumerate(records, 1):
                print(f"\nRecord {i}:")
                print(f"  UUID: {record.uuid}")
                print(f"  Beacon ID: {record.identifier}")
                print(f"  Name: {record.beacon_name or '(Not assigned)'}")
                print(f"  Shared By: {record.destination}")
                print(f"  Share Date: {record.share_date}")
        
        # Offer to export
        print("\n" + "="*60)
        export_choice = input("\nExport to CSV? (y/n): ").strip().lower()
        
        if export_choice == 'y':
            csv_path = input("Enter CSV output path (default: shared_beacons_results.csv): ").strip()
            if not csv_path:
                csv_path = "shared_beacons_results.csv"
            parser.export_to_csv(records, csv_path)
    else:
        print("Usage: python shared_beacons_parser.py <keychain.plist> <SharedBeacons_directory> [BeaconNamingRecord_directory]")
        print("\nExample:")
        print("python shared_beacons_parser.py keychain.plist searchpartyd/SharedBeacons")
        print("\nWith name association:")
        print("python shared_beacons_parser.py keychain.plist searchpartyd/SharedBeacons searchpartyd/BeaconNamingRecord")
