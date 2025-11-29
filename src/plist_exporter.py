"""
Plist Exporter
This module exports decrypted binary plist files from parsed .record files.
The exported files are organized into folders matching the original record type folders.
"""

import plistlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime


class PlistExporter:
    """
    Exports decrypted plist data from parsed records to binary plist files.
    
    The exported files are organized into a folder structure that mirrors
    the original searchpartyd folder structure:
    
    decrypted_plists/
    ├── WildModeAssociationRecord/
    │   ├── UUID1.plist
    │   └── UUID2.plist
    ├── BeaconNamingRecord/
    │   └── UUID3.plist
    └── (other record types)
    """
    
    # Mapping of record type names to their folder names
    RECORD_TYPE_FOLDERS = {
        'WildModeAssociationRecord': 'WildModeAssociationRecord',
        'BeaconNamingRecord': 'BeaconNamingRecord',
        'OwnedBeacons': 'OwnedBeacons',
        'SafeLocations': 'SafeLocations',
        'BeaconEstimatedLocation': 'BeaconEstimatedLocation',
        'SharedBeacons': 'SharedBeacons',
        'OwnerSharingCircle': 'OwnerSharingCircle',
        'OwnerPeerTrust': 'OwnerPeerTrust',
    }
    
    def __init__(self, output_base_dir: Optional[str] = None):
        """
        Initialize the plist exporter.
        
        Args:
            output_base_dir: Base directory for exports. If None, uses current
                           working directory with 'decrypted_plists' subfolder.
        """
        if output_base_dir:
            self.output_base_dir = Path(output_base_dir) / 'decrypted_plists'
        else:
            self.output_base_dir = Path.cwd() / 'decrypted_plists'
    
    def _ensure_directory(self, record_type: str) -> Path:
        """
        Ensure the output directory for a record type exists.
        
        Args:
            record_type: The type of record (e.g., 'WildModeAssociationRecord')
            
        Returns:
            Path to the record type's output directory
        """
        folder_name = self.RECORD_TYPE_FOLDERS.get(record_type, record_type)
        output_dir = self.output_base_dir / folder_name
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir
    
    def _get_record_uuid(self, record) -> Optional[str]:
        """
        Extract the UUID from a record object.
        
        Different record types store the UUID in different attributes:
        - Some use 'uuid'
        - Some use 'filename' (which includes .record extension)
        - Some use 'identifier'
        
        Args:
            record: A parsed record object
            
        Returns:
            The UUID string, or None if not found
        """
        # Try common UUID attributes
        if hasattr(record, 'uuid') and record.uuid:
            return str(record.uuid)
        
        if hasattr(record, 'filename') and record.filename:
            # Remove .record extension if present
            filename = str(record.filename)
            if filename.endswith('.record'):
                return filename[:-7]  # Remove '.record'
            return filename
        
        if hasattr(record, 'identifier') and record.identifier:
            return str(record.identifier)
        
        return None
    
    def _get_raw_data(self, record) -> Optional[Dict[str, Any]]:
        """
        Extract the raw decrypted plist data from a record.
        
        Args:
            record: A parsed record object
            
        Returns:
            The raw_data dictionary, or None if not available
        """
        if hasattr(record, 'raw_data') and record.raw_data:
            return record.raw_data
        return None
    
    def export_record(self, record, record_type: str) -> Optional[str]:
        """
        Export a single record's decrypted plist data to a binary plist file.
        
        Args:
            record: A parsed record object with raw_data attribute
            record_type: The type of record (e.g., 'WildModeAssociationRecord')
            
        Returns:
            Path to the exported file, or None if export failed
        """
        # Get UUID
        uuid = self._get_record_uuid(record)
        if not uuid:
            print(f"Warning: Could not extract UUID from record")
            return None
        
        # Get raw data
        raw_data = self._get_raw_data(record)
        if not raw_data:
            print(f"Warning: No raw_data available for record {uuid}")
            return None
        
        # Ensure output directory exists
        output_dir = self._ensure_directory(record_type)
        
        # Create output file path
        output_path = output_dir / f"{uuid}.plist"
        
        try:
            # Write as binary plist
            with open(output_path, 'wb') as f:
                plistlib.dump(raw_data, f, fmt=plistlib.FMT_BINARY)
            
            return str(output_path)
            
        except Exception as e:
            print(f"Error exporting record {uuid}: {str(e)}")
            return None
    
    def export_records(self, records: List, record_type: str) -> Dict[str, Any]:
        """
        Export multiple records of the same type to binary plist files.
        
        Args:
            records: List of parsed record objects
            record_type: The type of records (e.g., 'WildModeAssociationRecord')
            
        Returns:
            Dictionary with export results:
            {
                'record_type': str,
                'total': int,
                'exported': int,
                'failed': int,
                'output_dir': str,
                'files': List[str]  # List of exported file paths
            }
        """
        results = {
            'record_type': record_type,
            'total': len(records),
            'exported': 0,
            'failed': 0,
            'output_dir': None,
            'files': []
        }
        
        if not records:
            return results
        
        # Set output directory
        results['output_dir'] = str(self._ensure_directory(record_type))
        
        for record in records:
            exported_path = self.export_record(record, record_type)
            if exported_path:
                results['exported'] += 1
                results['files'].append(exported_path)
            else:
                results['failed'] += 1
        
        return results
    
    def export_all_records(self, 
                          wild_mode_records: List = None,
                          beacon_naming_records: List = None,
                          owned_beacon_records: List = None,
                          safe_location_records: List = None,
                          beacon_location_records: List = None,
                          shared_beacon_records: List = None,
                          owner_sharing_circle_records: List = None,
                          owner_peer_trust_records: List = None) -> Dict[str, Any]:
        """
        Export all provided records to binary plist files.
        
        Args:
            wild_mode_records: List of WildModeRecord objects
            beacon_naming_records: List of BeaconNamingRecord objects
            owned_beacon_records: List of OwnedBeaconRecord objects
            safe_location_records: List of SafeLocationRecord objects
            beacon_location_records: List of BeaconEstimatedLocationRecord objects
            shared_beacon_records: List of SharedBeaconRecord objects
            owner_sharing_circle_records: List of OwnerSharingCircleRecord objects
            owner_peer_trust_records: List of OwnerPeerTrustRecord objects
            
        Returns:
            Dictionary with overall export results:
            {
                'output_base_dir': str,
                'total_exported': int,
                'total_failed': int,
                'record_types': Dict[str, results_dict]
            }
        """
        overall_results = {
            'output_base_dir': str(self.output_base_dir),
            'total_exported': 0,
            'total_failed': 0,
            'record_types': {}
        }
        
        # Define records to export with their types
        records_to_export = [
            (wild_mode_records, 'WildModeAssociationRecord'),
            (beacon_naming_records, 'BeaconNamingRecord'),
            (owned_beacon_records, 'OwnedBeacons'),
            (safe_location_records, 'SafeLocations'),
            (beacon_location_records, 'BeaconEstimatedLocation'),
            (shared_beacon_records, 'SharedBeacons'),
            (owner_sharing_circle_records, 'OwnerSharingCircle'),
            (owner_peer_trust_records, 'OwnerPeerTrust'),
        ]
        
        for records, record_type in records_to_export:
            if records:
                results = self.export_records(records, record_type)
                overall_results['record_types'][record_type] = results
                overall_results['total_exported'] += results['exported']
                overall_results['total_failed'] += results['failed']
        
        return overall_results
    
    def get_export_summary(self, results: Dict[str, Any]) -> str:
        """
        Generate a human-readable summary of export results.
        
        Args:
            results: Results dictionary from export_all_records()
            
        Returns:
            Formatted summary string
        """
        lines = [
            "=" * 60,
            "Decrypted Plist Export Summary",
            "=" * 60,
            f"\nOutput Directory: {results['output_base_dir']}",
            f"Total Exported: {results['total_exported']}",
            f"Total Failed: {results['total_failed']}",
            "\nBreakdown by Record Type:"
        ]
        
        for record_type, type_results in results['record_types'].items():
            lines.append(f"\n  {record_type}:")
            lines.append(f"    Exported: {type_results['exported']} of {type_results['total']}")
            if type_results['failed'] > 0:
                lines.append(f"    Failed: {type_results['failed']}")
        
        lines.append("\n" + "=" * 60)
        
        return "\n".join(lines)


# Example usage
if __name__ == "__main__":
    print("PlistExporter - Export decrypted binary plist files from parsed records")
    print("\nUsage:")
    print("  from src.plist_exporter import PlistExporter")
    print("  ")
    print("  exporter = PlistExporter()")
    print("  results = exporter.export_all_records(")
    print("      wild_mode_records=wild_records,")
    print("      beacon_naming_records=naming_records,")
    print("      # ... other record types")
    print("  )")
    print("  print(exporter.get_export_summary(results))")
