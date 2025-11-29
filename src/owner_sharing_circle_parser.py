"""
OwnerSharingCircle Parser
This module parses encrypted .record files from the OwnerSharingCircle folder.
These files contain information about beacons that have been shared with others.
"""

import plistlib
from pathlib import Path
from typing import Dict, List, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class OwnerSharingCircleRecord:
    """Represents a parsed owner sharing circle record."""
    
    def __init__(self, filename: str):
        """
        Initialize an owner sharing circle record.
        
        Args:
            filename: The filename (UUID.record)
        """
        self.filename = filename
        self.identifier = None
        self.beacon_identifier = None  # UUID that corresponds to BeaconNamingRecord
        self.members = []  # List of peer trust UUIDs or dicts with acceptanceState
        self.acceptance_state = None
        self.sharing_circle_type = None
        self.beacon_name = None  # From BeaconNamingRecord (enriched later)
        self.beacon_emoji = None  # From BeaconNamingRecord (enriched later)
        self.raw_data = {}
    
    def __str__(self) -> str:
        """Return a string representation of the record."""
        lines = [
            f"Record ID: {self.identifier or 'Unknown'}",
            f"Beacon ID: {self.beacon_identifier or 'Unknown'}",
            f"Beacon Name: {self.beacon_name or 'Not enriched'}",
            f"Beacon Emoji: {self.beacon_emoji or 'None'}",
            f"Acceptance State: {self.acceptance_state}",
            f"Sharing Circle Type: {self.sharing_circle_type}",
            f"Members: {len(self.members)}"
        ]
        
        # Display member details
        for i, member in enumerate(self.members, 1):
            if isinstance(member, dict):
                acc_state = member.get('acceptanceState', 'Unknown')
                lines.append(f"  Member {i}: acceptanceState={acc_state}")
            else:
                lines.append(f"  Member {i}: {member}")
        
        return "\n".join(lines)


class OwnerSharingCircleParser:
    """Parser for OwnerSharingCircle .record files."""
    
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
    
    def parse_record_file(self, record_path: str) -> Optional[OwnerSharingCircleRecord]:
        """
        Parse a single .record file.
        
        Args:
            record_path: Path to the .record file
            
        Returns:
            OwnerSharingCircleRecord object, or None if parsing fails
        """
        path = Path(record_path)
        
        # Extract filename
        filename = path.name
        record = OwnerSharingCircleRecord(filename)
        
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
                print(f"Decryption failed for {filename}: {str(e)}")
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
    
    def _extract_record_data(self, plist_data: dict, record: OwnerSharingCircleRecord) -> None:
        """
        Extract relevant data from the decrypted plist.
        
        Args:
            plist_data: The decrypted plist dictionary
            record: The OwnerSharingCircleRecord object to populate
        """
        # Extract identifier (UUID of the sharing circle record)
        if 'identifier' in plist_data:
            record.identifier = plist_data['identifier']
        
        # Extract beacon identifier (UUID that corresponds to BeaconNamingRecord)
        if 'beaconIdentifier' in plist_data:
            record.beacon_identifier = plist_data['beaconIdentifier']
        
        # Extract acceptance state
        if 'acceptanceState' in plist_data:
            record.acceptance_state = plist_data['acceptanceState']
        
        # Extract sharing circle type
        if 'sharingCircleType' in plist_data:
            record.sharing_circle_type = plist_data['sharingCircleType']
        
        # Extract members list
        # Members can be a list of UUIDs (OwnerPeerTrust record IDs) 
        # or dicts with acceptanceState
        if 'members' in plist_data:
            members_data = plist_data['members']
            if isinstance(members_data, list):
                for member in members_data:
                    if isinstance(member, str):
                        # It's a UUID string
                        record.members.append(member)
                    elif isinstance(member, dict):
                        # It's a dict, likely with acceptanceState
                        record.members.append(member)
                    else:
                        # Unknown format, store as-is
                        record.members.append(member)
    
    def parse_directory(self, directory_path: str) -> List[OwnerSharingCircleRecord]:
        """
        Parse all .record files in a directory.
        
        Args:
            directory_path: Path to OwnerSharingCircle directory, or path to
                          the com.apple.icloud.searchpartyd parent directory
            
        Returns:
            List of successfully parsed OwnerSharingCircleRecord objects
        """
        records = []
        directory = Path(directory_path)
        
        if not directory.exists():
            print(f"Directory not found: {directory_path}")
            return records
        
        # Check if this is the searchpartyd parent directory
        # If so, navigate to the OwnerSharingCircle subdirectory
        if directory.name == 'com.apple.icloud.searchpartyd':
            sharing_dir = directory / 'OwnerSharingCircle'
            if sharing_dir.exists():
                directory = sharing_dir
                print(f"Using subdirectory: {sharing_dir}")
            else:
                print(f"OwnerSharingCircle subdirectory not found in {directory_path}")
                return records
        
        # Find all .record files
        record_files = [f for f in directory.glob("*.record") if f.is_file()]
        
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
    
    def get_member_uuids(self, record: OwnerSharingCircleRecord) -> List[str]:
        """
        Extract just the UUID strings from the members list.
        
        This is useful for looking up corresponding OwnerPeerTrust records.
        
        Args:
            record: The OwnerSharingCircleRecord object
            
        Returns:
            List of UUID strings from members
        """
        uuids = []
        for member in record.members:
            if isinstance(member, str):
                uuids.append(member)
        return uuids
    
    def enrich_with_naming_records(self, sharing_records: List[OwnerSharingCircleRecord], 
                                   naming_records: List) -> List[OwnerSharingCircleRecord]:
        """
        Add beacon names and emojis to OwnerSharingCircleRecords by matching with BeaconNamingRecords.
        
        This matches the 'beaconIdentifier' field from OwnerSharingCircle with the 
        'associated_beacon' field from BeaconNamingRecord.
        
        Args:
            sharing_records: List of OwnerSharingCircleRecord objects
            naming_records: List of BeaconNamingRecord objects
            
        Returns:
            The same list of OwnerSharingCircleRecord objects, now with beacon_name and beacon_emoji populated
        """
        # Create a lookup dictionary: associatedBeacon UUID -> (name, emoji)
        naming_lookup = {}
        for naming_record in naming_records:
            if naming_record.associated_beacon:
                # Store the custom name and emoji, using UUID as key
                uuid = str(naming_record.associated_beacon).upper()
                naming_lookup[uuid] = (naming_record.name, naming_record.emoji)
        
        # Match and populate beacon names and emojis
        matches_found = 0
        for sharing_record in sharing_records:
            if sharing_record.beacon_identifier:
                uuid = str(sharing_record.beacon_identifier).upper()
                if uuid in naming_lookup:
                    sharing_record.beacon_name, sharing_record.beacon_emoji = naming_lookup[uuid]
                    matches_found += 1
        
        print(f"\nMatched {matches_found} beacon names to sharing circle records")
        return sharing_records
    
    def export_to_csv(self, records: List[OwnerSharingCircleRecord], output_path: str) -> bool:
        """
        Export parsed records to CSV format.
        
        Args:
            records: List of OwnerSharingCircleRecord objects
            output_path: Path where the CSV file should be saved
            
        Returns:
            True if export successful, False otherwise
        """
        from .export_utils import ExportUtils, OwnerSharingCircleExporter
        
        csv_data = OwnerSharingCircleExporter.to_csv_format(records)
        return ExportUtils.export_to_csv(csv_data, output_path)


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # Get key from command line or use default
        if sys.argv[1] == "--key":
            key_hex = sys.argv[2]
            directory_path = sys.argv[3] if len(sys.argv) > 3 else "sample_Files/com.apple.icloud.searchpartyd/OwnerSharingCircle"
        else:
            from src.ios_keychain_extractor import iOSKeychainExtractor
            
            # Parse keychain to get BeaconStore key
            keychain_parser = iOSKeychainExtractor(sys.argv[1])
            keys = keychain_parser.parse()
            beacon_key = keychain_parser.get_beacon_store_key()
            
            if not beacon_key:
                print("ERROR: BeaconStore key not found in keychain!")
                sys.exit(1)
            
            key_hex = beacon_key.hex()
            directory_path = sys.argv[2] if len(sys.argv) > 2 else "sample_Files/com.apple.icloud.searchpartyd/OwnerSharingCircle"
        
        key_bytes = bytes.fromhex(key_hex)
        print(f"BeaconStore key: {len(key_bytes)} bytes\n")
        
        # Parse OwnerSharingCircle files
        parser = OwnerSharingCircleParser(key_bytes)
        records = parser.parse_directory(directory_path)
        
        print(f"\n{'='*60}")
        print(f"Successfully parsed {len(records)} owner sharing circle records")
        print(f"{'='*60}\n")
        
        # Display results
        for i, record in enumerate(records, 1):
            print(f"{'='*60}")
            print(f"Sharing Circle {i}:")
            print(f"{'='*60}")
            print(record)
            print()
        
        # Offer to export
        print("\n" + "="*60)
        export_choice = input("\nExport to CSV? (y/n): ").strip().lower()
        
        if export_choice == 'y':
            csv_path = input("Enter CSV output path (default: owner_sharing_circle_results.csv): ").strip()
            if not csv_path:
                csv_path = "owner_sharing_circle_results.csv"
            parser.export_to_csv(records, csv_path)
    else:
        print("Usage:")
        print("  With keychain: python owner_sharing_circle_parser.py <keychain.plist> [<OwnerSharingCircle_directory>]")
        print("  With hex key:  python owner_sharing_circle_parser.py --key <hex_key> [<OwnerSharingCircle_directory>]")
