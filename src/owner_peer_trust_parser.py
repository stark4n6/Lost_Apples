"""
OwnerPeerTrust Parser - FIXED VERSION
This module parses encrypted .record files from the OwnerPeerTrust folder.
These files contain information about the people with whom beacons have been shared.

FIXES:
- Updated enrich_with_beacon_names() to properly extract peer UUIDs from OwnerSharingCircle members
- Members can be either UUID strings OR dicts - now handles both properly
"""

import plistlib
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class OwnerPeerTrustRecord:
    """Represents a parsed owner peer trust record."""
    
    def __init__(self, filename: str):
        """
        Initialize an owner peer trust record.
        
        Args:
            filename: The filename (UUID.record)
        """
        self.filename = filename
        self.identifier = None
        self.display_identifier = None  # Email address or identifier
        self.destination = None  # Destination (e.g., mailto:email@address.com)
        self.sharing_timestamp = None  # Mac Absolute Time when tag was shared
        self.state = None
        self.peer_trust_type = None
        self.beacon_names = []  # List of (beacon_name, emoji) tuples from enrichment
        self.raw_data = {}
    
    def __str__(self) -> str:
        """Return a string representation of the record."""
        lines = [
            f"Record ID: {self.identifier or 'Unknown'}",
            f"Display Identifier: {self.display_identifier or 'Unknown'}",
            f"Destination: {self.destination or 'Unknown'}",
            f"Sharing Timestamp: {self.sharing_timestamp or 'Unknown'}",
            f"State: {self.state}",
            f"Type: {self.peer_trust_type}"
        ]
        
        # Display shared beacon names if available
        if self.beacon_names:
            lines.append(f"Shared Beacons: {len(self.beacon_names)}")
            for i, (name, emoji) in enumerate(self.beacon_names, 1):
                emoji_str = f" {emoji}" if emoji else ""
                lines.append(f"  Beacon {i}: {name}{emoji_str}")
        else:
            lines.append("Shared Beacons: None (not enriched)")
        
        return "\n".join(lines)


class OwnerPeerTrustParser:
    """Parser for OwnerPeerTrust .record files."""
    
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
    
    @staticmethod
    def mac_absolute_to_datetime(mac_absolute: float) -> datetime:
        """
        Convert Mac Absolute Time to datetime.
        
        Mac Absolute Time is the number of seconds since January 1, 2001.
        
        Args:
            mac_absolute: Mac Absolute Time value
            
        Returns:
            datetime object
        """
        mac_epoch = datetime(2001, 1, 1)
        return mac_epoch + timedelta(seconds=mac_absolute)
    
    def _extract_timestamp_from_cloudkit(self, cloudkit_metadata: bytes) -> Optional[datetime]:
        """
        Extract the NS.time timestamp from cloudKitMetadata.
        
        Args:
            cloudkit_metadata: Binary plist containing CloudKit metadata
            
        Returns:
            datetime object, or None if extraction fails
        """
        try:
            metadata = plistlib.loads(cloudkit_metadata)
            
            # Navigate through the NSKeyedArchiver structure
            # The structure is: $top -> RecordCtime or RecordMtime -> UID(x) -> $objects[x] -> NS.time
            if '$top' in metadata and '$objects' in metadata:
                top = metadata['$top']
                objects = metadata['$objects']
                
                # Look for RecordCtime or RecordMtime
                for time_key in ['RecordCtime', 'RecordMtime']:
                    if time_key in top:
                        uid_ref = top[time_key]
                        # uid_ref is typically a dict with 'CF$UID' key
                        if hasattr(uid_ref, 'data'):
                            # It's a UID object
                            uid_index = uid_ref.data
                        elif isinstance(uid_ref, dict) and 'CF$UID' in uid_ref:
                            uid_index = uid_ref['CF$UID']
                        else:
                            continue
                        
                        # Get the object at this index
                        if uid_index < len(objects):
                            time_obj = objects[uid_index]
                            if isinstance(time_obj, dict) and 'NS.time' in time_obj:
                                mac_time = time_obj['NS.time']
                                return self.mac_absolute_to_datetime(mac_time)
            
            return None
            
        except Exception as e:
            print(f"Warning: Could not extract timestamp from cloudKitMetadata: {e}")
            return None
    
    def parse_record_file(self, record_path: str) -> Optional[OwnerPeerTrustRecord]:
        """
        Parse a single .record file.
        
        Args:
            record_path: Path to the .record file
            
        Returns:
            OwnerPeerTrustRecord object, or None if parsing fails
        """
        path = Path(record_path)
        
        # Extract filename
        filename = path.name
        record = OwnerPeerTrustRecord(filename)
        
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
    
    def _extract_record_data(self, plist_data: dict, record: OwnerPeerTrustRecord) -> None:
        """
        Extract relevant data from the decrypted plist.
        
        Args:
            plist_data: The decrypted plist dictionary
            record: The OwnerPeerTrustRecord object to populate
        """
        # Extract identifier (UUID of the peer trust record)
        if 'identifier' in plist_data:
            record.identifier = plist_data['identifier']
        
        # Extract displayIdentifier (email address or name)
        if 'displayIdentifier' in plist_data:
            record.display_identifier = plist_data['displayIdentifier']
        
        # Extract destination from nested structure
        # Path: communicationsIdentifier -> familyIDS -> destination -> destination
        if 'communicationsIdentifier' in plist_data:
            comm_id = plist_data['communicationsIdentifier']
            if isinstance(comm_id, dict) and 'familyIDS' in comm_id:
                family_ids = comm_id['familyIDS']
                if isinstance(family_ids, dict) and 'destination' in family_ids:
                    dest_obj = family_ids['destination']
                    if isinstance(dest_obj, dict) and 'destination' in dest_obj:
                        record.destination = dest_obj['destination']
        
        # Extract state
        if 'state' in plist_data:
            record.state = plist_data['state']
        
        # Extract type
        if 'type' in plist_data:
            record.peer_trust_type = plist_data['type']
        
        # Extract timestamp from cloudKitMetadata
        if 'cloudKitMetadata' in plist_data:
            cloudkit_data = plist_data['cloudKitMetadata']
            if isinstance(cloudkit_data, bytes):
                record.sharing_timestamp = self._extract_timestamp_from_cloudkit(cloudkit_data)
    
    def parse_directory(self, directory_path: str) -> List[OwnerPeerTrustRecord]:
        """
        Parse all .record files in a directory.
        
        Args:
            directory_path: Path to OwnerPeerTrust directory, or path to
                          the com.apple.icloud.searchpartyd parent directory
            
        Returns:
            List of successfully parsed OwnerPeerTrustRecord objects
        """
        records = []
        directory = Path(directory_path)
        
        if not directory.exists():
            print(f"Directory not found: {directory_path}")
            return records
        
        # Check if this is the searchpartyd parent directory
        # If so, navigate to the OwnerPeerTrust subdirectory
        if directory.name == 'com.apple.icloud.searchpartyd':
            peer_dir = directory / 'OwnerPeerTrust'
            if peer_dir.exists():
                directory = peer_dir
                print(f"Using subdirectory: {peer_dir}")
            else:
                print(f"OwnerPeerTrust subdirectory not found in {directory_path}")
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
    
    def get_peer_by_identifier(self, identifier: str, records: List[OwnerPeerTrustRecord]) -> Optional[OwnerPeerTrustRecord]:
        """
        Find a peer trust record by its identifier UUID.
        
        This is useful for looking up peers referenced in OwnerSharingCircle records.
        
        Args:
            identifier: The UUID to find
            records: List of parsed peer trust records
            
        Returns:
            OwnerPeerTrustRecord if found, None otherwise
        """
        for record in records:
            if record.identifier and record.identifier.upper() == identifier.upper():
                return record
        return None
    
    def _extract_member_uuids(self, members_list: List) -> List[str]:
        """
        Extract UUID strings from a members list that may contain strings or dicts.
        
        The members list from OwnerSharingCircle can have different formats:
        - Simple UUID strings
        - Dictionaries with various keys that might contain UUIDs
        
        Args:
            members_list: List from OwnerSharingCircleRecord.members
            
        Returns:
            List of UUID strings
        """
        uuids = []
        
        for member in members_list:
            if isinstance(member, str):
                # Direct UUID string
                uuids.append(member.upper())
            elif isinstance(member, dict):
                # Dictionary - need to find the UUID
                # Common keys that might contain the peer UUID:
                # - 'identifier', 'peerIdentifier', 'uuid', 'id', etc.
                for key in ['identifier', 'peerIdentifier', 'uuid', 'id', 'memberIdentifier']:
                    if key in member and isinstance(member[key], str):
                        uuids.append(member[key].upper())
                        break
                else:
                    # If we didn't find a UUID in common keys, look at all string values
                    for value in member.values():
                        if isinstance(value, str) and len(value) == 36 and '-' in value:
                            # Looks like a UUID format (XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX)
                            uuids.append(value.upper())
                            break
        
        return uuids
    
    def enrich_with_beacon_names(self, peer_records: List[OwnerPeerTrustRecord],
                                 sharing_records: List, naming_records: List) -> List[OwnerPeerTrustRecord]:
        """
        Add beacon names to OwnerPeerTrustRecords by matching through OwnerSharingCircle records.
        
        This method:
        1. Creates a lookup: beacon UUID -> (name, emoji) from BeaconNamingRecords
        2. For each peer trust record:
           - Finds all OwnerSharingCircle records that include this peer UUID in members
           - Extracts the beacon identifiers from those sharing circles
           - Looks up the friendly names/emojis from the naming lookup
           - Adds them to the peer's beacon_names list
        
        Args:
            peer_records: List of OwnerPeerTrustRecord objects
            sharing_records: List of OwnerSharingCircleRecord objects
            naming_records: List of BeaconNamingRecord objects
            
        Returns:
            The same list of OwnerPeerTrustRecord objects, now with beacon_names populated
        """
        # Create a lookup dictionary: beacon UUID -> (name, emoji)
        naming_lookup = {}
        for naming_record in naming_records:
            if naming_record.associated_beacon:
                uuid = str(naming_record.associated_beacon).upper()
                naming_lookup[uuid] = (naming_record.name, naming_record.emoji)
        
        print(f"\nCreated naming lookup with {len(naming_lookup)} beacon names")
        
        # For each peer trust record, find all beacons shared with them
        matches_found = 0
        for peer_record in peer_records:
            if not peer_record.identifier:
                continue
            
            peer_uuid = str(peer_record.identifier).upper()
            print(f"\nProcessing peer: {peer_record.display_identifier} ({peer_uuid})")
            
            # Find all sharing circles that include this peer
            for sharing_record in sharing_records:
                # Extract all member UUIDs from this sharing circle
                member_uuids = self._extract_member_uuids(sharing_record.members)
                
                # Check if this peer is in the members list
                if peer_uuid in member_uuids:
                    print(f"  Found in sharing circle: {sharing_record.identifier}")
                    
                    # This peer has access to this beacon
                    if sharing_record.beacon_identifier:
                        beacon_uuid = str(sharing_record.beacon_identifier).upper()
                        print(f"    Beacon: {beacon_uuid}")
                        
                        # Look up the beacon name/emoji
                        if beacon_uuid in naming_lookup:
                            name, emoji = naming_lookup[beacon_uuid]
                            # Add to peer's beacon list if not already there
                            if (name, emoji) not in peer_record.beacon_names:
                                peer_record.beacon_names.append((name, emoji))
                                matches_found += 1
                                print(f"    ✓ Added: {name} {emoji}")
                        else:
                            print(f"    ✗ No naming record found for this beacon")
        
        print(f"\n✓ Enriched {matches_found} peer-beacon associations with friendly names")
        return peer_records
    
    def export_to_csv(self, records: List[OwnerPeerTrustRecord], output_path: str) -> bool:
        """
        Export parsed records to CSV format.
        
        Args:
            records: List of OwnerPeerTrustRecord objects
            output_path: Path where the CSV file should be saved
            
        Returns:
            True if export successful, False otherwise
        """
        from .export_utils import ExportUtils, OwnerPeerTrustExporter
        
        csv_data = OwnerPeerTrustExporter.to_csv_format(records)
        return ExportUtils.export_to_csv(csv_data, output_path)


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # Get key from command line or use default
        if sys.argv[1] == "--key":
            key_hex = sys.argv[2]
            directory_path = sys.argv[3] if len(sys.argv) > 3 else "sample_Files/com.apple.icloud.searchpartyd/OwnerPeerTrust"
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
            directory_path = sys.argv[2] if len(sys.argv) > 2 else "sample_Files/com.apple.icloud.searchpartyd/OwnerPeerTrust"
        
        key_bytes = bytes.fromhex(key_hex)
        print(f"BeaconStore key: {len(key_bytes)} bytes\n")
        
        # Parse OwnerPeerTrust files
        parser = OwnerPeerTrustParser(key_bytes)
        records = parser.parse_directory(directory_path)
        
        print(f"\n{'='*60}")
        print(f"Successfully parsed {len(records)} owner peer trust records")
        print(f"{'='*60}\n")
        
        # Display results
        for i, record in enumerate(records, 1):
            print(f"{'='*60}")
            print(f"Peer Trust {i}:")
            print(f"{'='*60}")
            print(record)
            print()
        
        # Offer to export
        print("\n" + "="*60)
        export_choice = input("\nExport to CSV? (y/n): ").strip().lower()
        
        if export_choice == 'y':
            csv_path = input("Enter CSV output path (default: owner_peer_trust_results.csv): ").strip()
            if not csv_path:
                csv_path = "owner_peer_trust_results.csv"
            parser.export_to_csv(records, csv_path)
    else:
        print("Usage:")
        print("  With keychain: python owner_peer_trust_parser.py <keychain.plist> [<OwnerPeerTrust_directory>]")
        print("  With hex key:  python owner_peer_trust_parser.py --key <hex_key> [<OwnerPeerTrust_directory>]")
