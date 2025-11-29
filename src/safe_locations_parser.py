"""
SafeLocations Parser
This module parses encrypted .record files from the SafeLocations folder.
These files contain information about locations marked as safe by the user.
"""

import plistlib
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SafeLocationRecord:
    """Represents a parsed safe location record."""
    
    def __init__(self, uuid: str):
        """
        Initialize a safe location record.
        
        Args:
            uuid: The UUID of the record (filename without .record extension)
        """
        self.uuid = uuid
        self.name = None
        self.latitude = None
        self.longitude = None
        self.radius = None
        self.associated_beacons = []
        self.beacon_names = {}  # Maps UUID to name from BeaconNaming/OwnedBeacons
        self.timestamps = []  # List of timestamps from metadata
        self.raw_data = {}
    
    def __str__(self) -> str:
        """Return a string representation of the record."""
        lines = [
            f"UUID: {self.uuid}",
            f"Name: {self.name or '(No custom name)'}",
            f"Latitude: {self.latitude}",
            f"Longitude: {self.longitude}",
            f"Radius: {self.radius} meters" if self.radius else "Radius: Unknown",
            f"Associated Beacons: {len(self.associated_beacons)}"
        ]
        
        # Add timestamps
        if self.timestamps:
            lines.append("\nTimestamps:")
            for i, ts in enumerate(self.timestamps, 1):
                lines.append(f"  {i}. {ts}")
        
        # Add associated beacons
        if self.associated_beacons:
            lines.append("\nAssociated Beacons:")
            for beacon_uuid in self.associated_beacons:
                beacon_name = self.beacon_names.get(beacon_uuid, beacon_uuid)
                lines.append(f"  - {beacon_name}")
        
        return "\n".join(lines)


class SafeLocationsParser:
    """Parser for SafeLocations .record files."""
    
    # Apple epoch starts at 2001-01-01 00:00:00 UTC
    APPLE_EPOCH = datetime(2001, 1, 1)
    
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
    
    def parse_record_file(self, record_path: str) -> Optional[SafeLocationRecord]:
        """
        Parse a single .record file.
        
        Args:
            record_path: Path to the .record file
            
        Returns:
            SafeLocationRecord object, or None if parsing fails
        """
        path = Path(record_path)
        
        # Extract UUID from filename
        uuid = path.stem
        record = SafeLocationRecord(uuid)
        
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
    
    def _extract_record_data(self, plist_data: dict, record: SafeLocationRecord) -> None:
        """
        Extract relevant data from the decrypted plist.
        
        Args:
            plist_data: The decrypted plist dictionary
            record: The SafeLocationRecord object to populate
        """
        # Extract name
        if 'name' in plist_data:
            name = plist_data['name']
            # Only set if not empty
            if name and name.strip():
                record.name = name
        
        # Extract latitude and longitude
        if 'latitude' in plist_data:
            record.latitude = plist_data['latitude']
        
        if 'longitude' in plist_data:
            record.longitude = plist_data['longitude']
        
        # Extract radius
        if 'radius' in plist_data:
            record.radius = plist_data['radius']
        
        # Extract associated beacons
        if 'associatedBeacons' in plist_data:
            beacons = plist_data['associatedBeacons']
            if isinstance(beacons, list):
                record.associated_beacons = [str(b) for b in beacons]
        
        # Extract timestamps from cloudKitMetadata
        if 'cloudKitMetadata' in plist_data:
            try:
                metadata = plistlib.loads(plist_data['cloudKitMetadata'])
                self._extract_timestamps(metadata, record)
            except Exception as e:
                print(f"Warning: Could not parse cloudKitMetadata for timestamps: {e}")
    
    def _extract_timestamps(self, metadata: dict, record: SafeLocationRecord) -> None:
        """
        Extract timestamps from CloudKit metadata.
        
        Args:
            metadata: The parsed cloudKitMetadata dictionary
            record: The SafeLocationRecord object to populate
        """
        # CloudKit metadata uses NSKeyedArchiver format
        if '$objects' in metadata:
            objects = metadata['$objects']
            
            # Look for NSDate objects with NS.time
            for obj in objects:
                if isinstance(obj, dict) and 'NS.time' in obj:
                    timestamp = self._convert_apple_timestamp(obj['NS.time'])
                    if timestamp:
                        record.timestamps.append(timestamp)
    
    def _convert_apple_timestamp(self, timestamp) -> Optional[datetime]:
        """
        Convert Apple timestamp to Python datetime.
        Apple uses seconds since 2001-01-01 00:00:00 UTC.
        
        Args:
            timestamp: Apple timestamp (seconds since 2001-01-01) or datetime object
            
        Returns:
            Python datetime object or None
        """
        # If it's already a datetime object, return it
        if isinstance(timestamp, datetime):
            return timestamp
        
        # If it's a number (float or int), convert from Apple epoch
        if isinstance(timestamp, (int, float)):
            try:
                return self.APPLE_EPOCH + timedelta(seconds=timestamp)
            except Exception:
                return None
        
        return None
    
    def parse_directory(self, directory_path: str) -> List[SafeLocationRecord]:
        """
        Parse all .record files in a directory.
        
        Args:
            directory_path: Path to SafeLocations directory, or path to
                          the com.apple.icloud.searchpartyd parent directory
            
        Returns:
            List of successfully parsed SafeLocationRecord objects
        """
        records = []
        directory = Path(directory_path)
        
        if not directory.exists():
            print(f"Directory not found: {directory_path}")
            return records
        
        # Check if this is the searchpartyd parent directory
        # If so, navigate to the SafeLocations subdirectory
        if directory.name == 'com.apple.icloud.searchpartyd':
            safe_dir = directory / 'SafeLocations'
            if safe_dir.exists():
                directory = safe_dir
                print(f"Using subdirectory: {safe_dir}")
            else:
                print(f"SafeLocations subdirectory not found in {directory_path}")
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
    
    def associate_beacon_names(self, records: List[SafeLocationRecord], 
                               beacon_naming_records: List = None,
                               owned_beacon_records: List = None) -> None:
        """
        Associate beacon UUIDs with their names from BeaconNaming and OwnedBeacons.
        
        Args:
            records: List of SafeLocationRecord objects
            beacon_naming_records: List of BeaconNamingRecord objects (optional)
            owned_beacon_records: List of OwnedBeaconRecord objects (optional)
        """
        # Build a mapping of beacon UUID to name
        uuid_to_name = {}
        
        # First, add names from BeaconNamingRecord
        if beacon_naming_records:
            for naming_record in beacon_naming_records:
                if hasattr(naming_record, 'associated_beacon') and hasattr(naming_record, 'name'):
                    beacon_uuid = str(naming_record.associated_beacon)
                    name = naming_record.name
                    if name:
                        uuid_to_name[beacon_uuid] = name
        
        # Then, add names from OwnedBeacons (if not already present)
        if owned_beacon_records:
            for owned_record in owned_beacon_records:
                if hasattr(owned_record, 'identifier') and hasattr(owned_record, 'name'):
                    beacon_uuid = str(owned_record.identifier)
                    # Only use if we don't have a custom name from BeaconNaming
                    if beacon_uuid not in uuid_to_name and owned_record.name:
                        uuid_to_name[beacon_uuid] = owned_record.name
        
        # Apply the mapping to all records
        for record in records:
            for beacon_uuid in record.associated_beacons:
                if beacon_uuid in uuid_to_name:
                    record.beacon_names[beacon_uuid] = uuid_to_name[beacon_uuid]
                else:
                    # Keep UUID if no name found
                    record.beacon_names[beacon_uuid] = beacon_uuid
    
    def export_to_csv(self, records: List[SafeLocationRecord], output_path: str) -> bool:
        """
        Export parsed records to CSV format.
        
        Args:
            records: List of SafeLocationRecord objects
            output_path: Path where the CSV file should be saved
            
        Returns:
            True if export successful, False otherwise
        """
        from .export_utils import ExportUtils, SafeLocationsExporter
        
        csv_data = SafeLocationsExporter.to_csv_format(records)
        return ExportUtils.export_to_csv(csv_data, output_path)
    
    def export_to_kml(self, records: List[SafeLocationRecord], output_path: str, 
                     name: str = "Safe Locations") -> bool:
        """
        Export location data to KML format.
        
        Args:
            records: List of SafeLocationRecord objects
            output_path: Path where the KML file should be saved
            name: Name for the KML document
            
        Returns:
            True if export successful, False otherwise
        """
        from .export_utils import ExportUtils, SafeLocationsExporter
        
        kml_data = SafeLocationsExporter.to_kml_format(records)
        return ExportUtils.export_to_kml(kml_data, output_path, name)


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 2:
        from ios_keychain_extractor import extract_beaconstore_key
        
        # Extract BeaconStore key from keychain
        beacon_key = extract_beaconstore_key(sys.argv[1])
        
        if not beacon_key:
            print("ERROR: BeaconStore key not found in keychain!")
            sys.exit(1)
        
        print(f"BeaconStore key found: {len(beacon_key)} bytes\n")
        
        # Parse SafeLocations files
        parser = SafeLocationsParser(beacon_key)
        records = parser.parse_directory(sys.argv[2])
        
        print(f"\n{'='*60}")
        print(f"Successfully parsed {len(records)} records")
        print(f"{'='*60}\n")
        
        # Display results
        for i, record in enumerate(records, 1):
            print(f"\n{'='*60}")
            print(f"Record {i}:")
            print(f"{'='*60}")
            print(record)
        
        # Offer to export
        print("\n" + "="*60)
        export_choice = input("\nExport results? (csv/kml/both/no): ").strip().lower()
        
        if export_choice in ['csv', 'both']:
            csv_path = input("Enter CSV output path (default: safe_locations.csv): ").strip()
            if not csv_path:
                csv_path = "safe_locations.csv"
            parser.export_to_csv(records, csv_path)
        
        if export_choice in ['kml', 'both']:
            kml_path = input("Enter KML output path (default: safe_locations.kml): ").strip()
            if not kml_path:
                kml_path = "safe_locations.kml"
            parser.export_to_kml(records, kml_path)
    else:
        print("Usage: python safe_locations_parser.py <keychain.plist> <SafeLocations_directory>")
