"""
BeaconEstimatedLocation Parser
This module parses encrypted .record files from the BeaconEstimatedLocation folder.
These files contain estimated location information for tracked items.
"""

import plistlib
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class BeaconEstimatedLocationRecord:
    """Represents a parsed beacon estimated location record."""
    
    # Apple epoch starts at 2001-01-01 00:00:00 UTC
    APPLE_EPOCH = datetime(2001, 1, 1)
    
    def __init__(self, uuid: str, beacon_uuid: str):
        """
        Initialize a beacon estimated location record.
        
        Args:
            uuid: The UUID of the record (filename without .record extension)
            beacon_uuid: The UUID of the associated beacon (parent folder name)
        """
        self.uuid = uuid
        self.beacon_uuid = beacon_uuid
        self.latitude = None
        self.longitude = None
        self.horizontal_accuracy = None
        self.timestamp = None
        self.beacon_name = None  # Will be populated by associate_beacon_names
        self.raw_data = {}
    
    def __str__(self) -> str:
        """Return a string representation of the record."""
        lines = [
            f"Record UUID: {self.uuid}",
            f"Associated Beacon: {self.beacon_uuid}",
            f"Beacon Name: {self.beacon_name or '(Not set)'}",
            f"Latitude: {self.latitude}",
            f"Longitude: {self.longitude}",
            f"Horizontal Accuracy: {self.horizontal_accuracy} meters" if self.horizontal_accuracy else "Horizontal Accuracy: Unknown",
            f"Timestamp: {self.timestamp}"
        ]
        return "\n".join(lines)


class BeaconEstimatedLocationParser:
    """Parser for BeaconEstimatedLocation .record files."""
    
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
    
    def parse_record_file(self, record_path: str, beacon_uuid: str) -> Optional[BeaconEstimatedLocationRecord]:
        """
        Parse a single .record file.
        
        Args:
            record_path: Path to the .record file
            beacon_uuid: The UUID of the associated beacon (from parent folder)
            
        Returns:
            BeaconEstimatedLocationRecord object, or None if parsing fails
        """
        path = Path(record_path)
        
        # Extract UUID from filename
        uuid = path.stem
        record = BeaconEstimatedLocationRecord(uuid, beacon_uuid)
        
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
    
    def _extract_record_data(self, plist_data: dict, record: BeaconEstimatedLocationRecord) -> None:
        """
        Extract relevant data from the decrypted plist.
        
        Args:
            plist_data: The decrypted plist dictionary
            record: The BeaconEstimatedLocationRecord object to populate
        """
        # Extract latitude
        if 'latitude' in plist_data:
            record.latitude = plist_data['latitude']
        
        # Extract longitude
        if 'longitude' in plist_data:
            record.longitude = plist_data['longitude']
        
        # Extract horizontal accuracy
        if 'horizontalAccuracy' in plist_data:
            record.horizontal_accuracy = plist_data['horizontalAccuracy']
        
        # Extract timestamp
        if 'timestamp' in plist_data:
            record.timestamp = self._convert_apple_timestamp(plist_data['timestamp'])
    
    def _convert_apple_timestamp(self, timestamp) -> datetime:
        """
        Convert Apple timestamp to Python datetime.
        Apple uses seconds since 2001-01-01 00:00:00 UTC.
        
        Args:
            timestamp: Apple timestamp (seconds since 2001-01-01) or datetime object
            
        Returns:
            Python datetime object
        """
        # If it's already a datetime object, return it
        if isinstance(timestamp, datetime):
            return timestamp
        
        # If it's a number (float or int), convert from Apple epoch
        if isinstance(timestamp, (int, float)):
            return BeaconEstimatedLocationRecord.APPLE_EPOCH + timedelta(seconds=timestamp)
        
        # If we can't convert it, return None
        return None
    
    def parse_directory(self, directory_path: str) -> List[BeaconEstimatedLocationRecord]:
        """
        Parse all .record files in a directory and its subdirectories.
        The BeaconEstimatedLocation folder has UUID subfolders, each containing .record files.
        
        Args:
            directory_path: Path to BeaconEstimatedLocation directory, or path to
                          the com.apple.icloud.searchpartyd parent directory
            
        Returns:
            List of successfully parsed BeaconEstimatedLocationRecord objects
        """
        records = []
        directory = Path(directory_path)
        
        if not directory.exists():
            print(f"Directory not found: {directory_path}")
            return records
        
        # Check if this is the searchpartyd parent directory
        # If so, navigate to the BeaconEstimatedLocation subdirectory
        if directory.name == 'com.apple.icloud.searchpartyd':
            location_dir = directory / 'BeaconEstimatedLocation'
            if location_dir.exists():
                directory = location_dir
                print(f"Using subdirectory: {location_dir}")
            else:
                print(f"BeaconEstimatedLocation subdirectory not found in {directory_path}")
                return records
        
        # Find all subdirectories (these are beacon UUIDs)
        beacon_dirs = [d for d in directory.iterdir() if d.is_dir() and not d.name.startswith('.')]
        
        print(f"Found {len(beacon_dirs)} beacon directories")
        
        for beacon_dir in beacon_dirs:
            beacon_uuid = beacon_dir.name
            print(f"\nProcessing beacon: {beacon_uuid}")
            
            # Find all .record files in this beacon's directory
            record_files = list(beacon_dir.glob("*.record"))
            print(f"  Found {len(record_files)} record files")
            
            for record_file in record_files:
                print(f"  Parsing {record_file.name}...")
                record = self.parse_record_file(str(record_file), beacon_uuid)
                if record:
                    records.append(record)
                    print(f"    ✓ Successfully parsed")
                else:
                    print(f"    ✗ Failed to parse")
        
        return records
    
    def associate_beacon_names(self, records: List[BeaconEstimatedLocationRecord], 
                               naming_records: List) -> None:
        """
        Associate beacon names from BeaconNamingRecord with the location records.
        
        Args:
            records: List of BeaconEstimatedLocationRecord objects
            naming_records: List of BeaconNamingRecord objects
        """
        # Create a mapping of beacon UUID to name
        beacon_name_map = {}
        for naming_record in naming_records:
            if naming_record.associated_beacon and naming_record.name:
                beacon_name_map[naming_record.associated_beacon] = naming_record.name
        
        # Apply names to location records
        for record in records:
            if record.beacon_uuid in beacon_name_map:
                record.beacon_name = beacon_name_map[record.beacon_uuid]
    
    def export_to_csv(self, records: List[BeaconEstimatedLocationRecord], output_path: str) -> bool:
        """
        Export parsed records to CSV format.
        
        Args:
            records: List of BeaconEstimatedLocationRecord objects
            output_path: Path where the CSV file should be saved
            
        Returns:
            True if export successful, False otherwise
        """
        from .export_utils import ExportUtils, BeaconEstimatedLocationExporter
        
        csv_data = BeaconEstimatedLocationExporter.to_csv_format(records)
        return ExportUtils.export_to_csv(csv_data, output_path)
    
    def export_to_kml(self, records: List[BeaconEstimatedLocationRecord], 
                      output_directory: str) -> int:
        """
        Export location data to individual KML files, one per unique beacon UUID.
        
        Args:
            records: List of BeaconEstimatedLocationRecord objects
            output_directory: Directory where KML files should be saved
            
        Returns:
            Number of KML files successfully created
        """
        from .export_utils import ExportUtils, BeaconEstimatedLocationExporter
        
        # Group records by beacon UUID
        beacon_groups = {}
        for record in records:
            if record.beacon_uuid not in beacon_groups:
                beacon_groups[record.beacon_uuid] = []
            beacon_groups[record.beacon_uuid].append(record)
        
        # Create output directory
        output_dir = Path(output_directory)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        success_count = 0
        
        # Export each beacon's locations to its own KML file
        for beacon_uuid, beacon_records in beacon_groups.items():
            # Get beacon name if available
            beacon_name = beacon_records[0].beacon_name if beacon_records[0].beacon_name else beacon_uuid
            
            # Create filename
            filename = f"{beacon_uuid}.kml"
            output_path = output_dir / filename
            
            # Convert records to KML format
            kml_data = BeaconEstimatedLocationExporter.to_kml_format(beacon_records)
            
            # Export to KML
            if ExportUtils.export_to_kml(kml_data, str(output_path), beacon_name):
                success_count += 1
        
        print(f"\nSuccessfully created {success_count} KML files in {output_directory}")
        return success_count


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
        
        # Parse BeaconEstimatedLocation files
        parser = BeaconEstimatedLocationParser(beacon_key)
        records = parser.parse_directory(sys.argv[2])
        
        print(f"\n{'='*60}")
        print(f"Successfully parsed {len(records)} location records")
        print(f"{'='*60}\n")
        
        # If BeaconNamingRecord directory is provided, associate names
        if len(sys.argv) > 3:
            print("\nAssociating beacon names...")
            from beacon_naming_parser import BeaconNamingParser
            naming_parser = BeaconNamingParser(beacon_key)
            naming_records = naming_parser.parse_directory(sys.argv[3])
            parser.associate_beacon_names(records, naming_records)
        
        # Display results
        for i, record in enumerate(records, 1):
            print(f"\n{'='*60}")
            print(f"Record {i}:")
            print(f"{'='*60}")
            print(record)
        
        # Offer to export
        print("\n" + "="*60)
        print("Export options:")
        print("  csv - Export to CSV file")
        print("  kml - Export to individual KML files (one per beacon)")
        print("  all - Export both CSV and KML")
        print("  no  - Don't export")
        
        export_choice = input("\nExport results: ").strip().lower()
        
        if export_choice in ['csv', 'all']:
            csv_path = input("Enter CSV output path (default: beacon_locations.csv): ").strip()
            if not csv_path:
                csv_path = "beacon_locations.csv"
            parser.export_to_csv(records, csv_path)
        
        if export_choice in ['kml', 'all']:
            kml_dir = input("Enter KML output directory (default: beacon_location_kml): ").strip()
            if not kml_dir:
                kml_dir = "beacon_location_kml"
            parser.export_to_kml(records, kml_dir)
    else:
        print("Usage: python beacon_estimated_location_parser.py <keychain.plist> <BeaconEstimatedLocation_directory> [BeaconNamingRecord_directory]")
        print("\nThe optional BeaconNamingRecord directory allows the parser to display custom beacon names.")
