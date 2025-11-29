"""
Observations.db Query Handler for iOS SearchParty

This module handles on-demand SQLite querying of decrypted Observations.db,
supporting both database-only and database+WAL query modes.

The Observations.db tracks all FindMy-compatible devices observed by iOS,
including timestamps, locations, MAC addresses, and signal strength.

Query Modes:
1. Database Only: Query the main Observations.db without WAL data
2. Database + WAL: Commit WAL to database copy, then query

IMPORTANT: This handler PRESERVES the original decrypted files. All queries
are performed on temporary copies to avoid SQLite's automatic WAL checkpointing.

Reference: https://thebinaryhick.blog/2025/08/19/further-observations-more-on-ios-search-party/
"""

import sqlite3
import shutil
import csv
import os
import atexit
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime


class ObservationsQueryHandler:
    """
    Handles SQLite queries on decrypted Observations.db with optional WAL integration.
    
    This class supports two query modes:
    1. Database-only: Queries the decrypted database without WAL data
    2. Database + WAL: Creates a copy, commits WAL, then queries (more complete data)
    
    IMPORTANT: This handler creates temporary copies for all queries to prevent
    SQLite from automatically checkpointing (committing) the WAL file. The original
    decrypted database and WAL files are always preserved.
    
    The WAL file often contains the most recent observation data that hasn't
    been committed to the main database yet - especially important because
    Observations.db discards records very quickly.
    """
    
    # Primary SQL query from the Binary Hick blog article
    OBSERVATIONS_QUERY = """
    SELECT
        ObservedAdvertisement.scanDate AS "Seen_Time",
        ObservedAdvertisementLocation.latitude AS "Latitude",
        ObservedAdvertisementLocation.longitude AS "Longitude",
        ObservedAdvertisementBeaconInfo.beaconIdentifier AS "Identifier",
        ObservedAdvertisement.macAddress AS "MAC_Address",
        ObservedAdvertisement.rssi AS "Signal_Strength",
        ObservedAdvertisement.advertisementData AS "Advertised_Data"
    FROM
        ObservedAdvertisementLocation
    LEFT JOIN ObservedAdvertisement ON ObservedAdvertisement.advId = ObservedAdvertisementLocation.advId
    LEFT JOIN ObservedAdvertisementBeaconInfo ON ObservedAdvertisementBeaconInfo.advId = ObservedAdvertisementLocation.advId
    ORDER BY "Seen_Time"
    """
    
    # Extended query with Advertisement Identifier (from the article's second query)
    EXTENDED_OBSERVATIONS_QUERY = """
    SELECT
        ObservedAdvertisement.scanDate AS "Seen_Time",
        ObservedAdvertisementLocation.latitude AS "Latitude",
        ObservedAdvertisementLocation.longitude AS "Longitude",
        ObservedAdvertisementLocation.advId AS "Advertisement_Identifier",
        ObservedAdvertisementBeaconInfo.beaconIdentifier AS "Identifier",
        ObservedAdvertisement.macAddress AS "MAC_Address",
        ObservedAdvertisement.rssi AS "Signal_Strength",
        ObservedAdvertisement.advertisementData AS "Advertised_Data",
        ObservedAdvertisementBeaconInfo.sequence AS "Sequence_Number"
    FROM
        ObservedAdvertisementLocation
    LEFT JOIN ObservedAdvertisement ON ObservedAdvertisement.advId = ObservedAdvertisementLocation.advId
    LEFT JOIN ObservedAdvertisementBeaconInfo ON ObservedAdvertisementBeaconInfo.advId = ObservedAdvertisementLocation.advId
    ORDER BY "Seen_Time"
    """
    
    # Track all temporary files for cleanup
    _temp_files: List[Path] = []
    
    def __init__(self, decrypted_db_path: str, decrypted_wal_path: Optional[str] = None):
        """
        Initialize the query handler.
        
        Args:
            decrypted_db_path: Path to decrypted Observations.db
            decrypted_wal_path: Path to decrypted WAL file (optional)
        """
        self.db_path = Path(decrypted_db_path)
        self.wal_path = Path(decrypted_wal_path) if decrypted_wal_path else None
        
        # Verify paths exist
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {self.db_path}")
        
        if self.wal_path and not self.wal_path.exists():
            raise FileNotFoundError(f"WAL file not found: {self.wal_path}")
    
    @classmethod
    def cleanup_temp_files(cls):
        """
        Clean up all temporary files created by this handler.
        Should be called when the application closes.
        """
        for temp_file in cls._temp_files:
            try:
                if temp_file.exists():
                    temp_file.unlink()
            except Exception:
                pass  # Ignore cleanup errors
        cls._temp_files.clear()
    
    def _register_temp_file(self, path: Path):
        """Register a temporary file for cleanup."""
        self._temp_files.append(path)
    
    def _create_db_only_copy(self, output_dir: Path) -> Path:
        """
        Create a temporary copy of the database WITHOUT the WAL file.
        
        This ensures we query ONLY the main database content without
        any WAL data being automatically applied.
        
        Args:
            output_dir: Directory for temporary files
            
        Returns:
            Path to the temporary database copy
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        temp_db = output_dir / f"_temp_db_only_{timestamp}.db"
        
        # Copy only the main database file (no WAL, no SHM)
        shutil.copy(str(self.db_path), str(temp_db))
        self._register_temp_file(temp_db)
        
        # Also register potential SQLite journal files for cleanup
        for suffix in ['-wal', '-shm', '-journal']:
            temp_journal = output_dir / f"_temp_db_only_{timestamp}.db{suffix}"
            self._register_temp_file(temp_journal)
        
        return temp_db
    
    def _create_db_with_wal_copy(self, output_dir: Path) -> Path:
        """
        Create a temporary copy of the database WITH the WAL file.
        
        After copying, SQLite will be used to checkpoint the WAL,
        which commits the WAL data to the database copy.
        
        Args:
            output_dir: Directory for temporary files
            
        Returns:
            Path to the temporary database copy (with WAL committed)
        """
        if not self.wal_path or not self.wal_path.exists():
            raise FileNotFoundError("WAL file not available")
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        temp_db = output_dir / f"_temp_with_wal_{timestamp}.db"
        temp_wal = output_dir / f"_temp_with_wal_{timestamp}.db-wal"
        temp_shm = output_dir / f"_temp_with_wal_{timestamp}.db-shm"
        
        # Copy the database
        shutil.copy(str(self.db_path), str(temp_db))
        self._register_temp_file(temp_db)
        
        # Copy the WAL file
        shutil.copy(str(self.wal_path), str(temp_wal))
        self._register_temp_file(temp_wal)
        
        # Copy SHM if it exists
        shm_path = self.db_path.parent / f"{self.db_path.name}-shm"
        if shm_path.exists():
            shutil.copy(str(shm_path), str(temp_shm))
        self._register_temp_file(temp_shm)
        
        # Now checkpoint the WAL to commit it to the database
        conn = sqlite3.connect(str(temp_db))
        cursor = conn.cursor()
        
        # Full checkpoint to commit all WAL data
        cursor.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()
        
        return temp_db
    
    def get_table_info(self) -> Dict[str, int]:
        """
        Get information about tables in the database.
        
        Uses a temporary copy to avoid affecting the original database.
        
        Returns:
            Dictionary mapping table names to record counts
        """
        # Create temporary copy for safe reading
        output_dir = Path.cwd()
        temp_db = self._create_db_only_copy(output_dir)
        
        try:
            conn = sqlite3.connect(str(temp_db))
            cursor = conn.cursor()
            
            # Get table names
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            # Get counts
            table_info = {}
            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    table_info[table] = cursor.fetchone()[0]
                except sqlite3.Error:
                    table_info[table] = -1  # Error getting count
            
            conn.close()
            return table_info
            
        finally:
            # Clean up temp file
            try:
                if temp_db.exists():
                    temp_db.unlink()
            except Exception:
                pass
    
    def _format_mac_address(self, mac_bytes: bytes) -> Optional[str]:
        """Format MAC address bytes as colon-separated hex string."""
        if not mac_bytes:
            return None
        mac_hex = mac_bytes.hex()
        return ':'.join([mac_hex[i:i+2] for i in range(0, len(mac_hex), 2)])
    
    def _format_advertisement_data(self, ad_bytes: bytes) -> Optional[str]:
        """Format advertisement data bytes as hex string."""
        if not ad_bytes:
            return None
        return ad_bytes.hex()
    
    def _parse_observations(self, rows: List[sqlite3.Row]) -> List[Dict[str, Any]]:
        """
        Parse raw database rows into observation dictionaries.
        
        Args:
            rows: List of sqlite3.Row objects
            
        Returns:
            List of parsed observation dictionaries
        """
        observations = []
        
        for row in rows:
            # Format MAC address
            mac_bytes = row['MAC_Address']
            mac_formatted = self._format_mac_address(mac_bytes) if mac_bytes else None
            mac_raw = mac_bytes.hex() if mac_bytes else None
            
            # Format advertisement data
            ad_bytes = row['Advertised_Data']
            ad_hex = self._format_advertisement_data(ad_bytes) if ad_bytes else None
            
            # Format timestamp if it's a float (Unix timestamp)
            seen_time = row['Seen_Time']
            if isinstance(seen_time, (int, float)):
                # Convert Apple/Unix timestamp to readable format
                # Apple uses seconds since 2001-01-01, adjust if needed
                try:
                    seen_time_formatted = datetime.fromtimestamp(seen_time).strftime('%Y-%m-%d %H:%M:%S')
                except (ValueError, OSError):
                    seen_time_formatted = str(seen_time)
            else:
                seen_time_formatted = str(seen_time) if seen_time else None
            
            observation = {
                'Seen_Time': seen_time_formatted,
                'Seen_Time_Raw': seen_time,
                'Latitude': row['Latitude'],
                'Longitude': row['Longitude'],
                'Identifier': row['Identifier'],
                'MAC_Address': mac_formatted,
                'MAC_Address_Raw': mac_raw,
                'Signal_Strength_dBm': row['Signal_Strength'],
                'Advertised_Data': ad_hex
            }
            
            # Add extended fields if present
            if 'Advertisement_Identifier' in row.keys():
                observation['Advertisement_Identifier'] = row['Advertisement_Identifier']
            if 'Sequence_Number' in row.keys():
                observation['Sequence_Number'] = row['Sequence_Number']
            
            observations.append(observation)
        
        return observations
    
    def query_database_only(self, output_dir: str, use_extended_query: bool = False) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Query the decrypted database WITHOUT WAL data.
        
        Creates a temporary copy of the database (without WAL) to ensure
        SQLite doesn't automatically checkpoint any WAL data.
        
        Args:
            output_dir: Directory for temporary files
            use_extended_query: If True, use the extended query with additional fields
            
        Returns:
            Tuple of (observations list, metadata dict)
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Create a copy of the database WITHOUT the WAL file
        temp_db = self._create_db_only_copy(output_path)
        
        try:
            conn = sqlite3.connect(str(temp_db))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get journal mode for metadata
            cursor.execute("PRAGMA journal_mode")
            journal_mode = cursor.fetchone()[0]
            
            # Run the query
            query = self.EXTENDED_OBSERVATIONS_QUERY if use_extended_query else self.OBSERVATIONS_QUERY
            
            try:
                cursor.execute(query)
                rows = cursor.fetchall()
            except sqlite3.Error as e:
                conn.close()
                raise RuntimeError(f"Query failed: {e}")
            
            observations = self._parse_observations(rows)
            
            metadata = {
                'source': 'database_only',
                'db_path': str(self.db_path),
                'wal_included': False,
                'journal_mode': journal_mode,
                'record_count': len(observations),
                'query_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'query_type': 'extended' if use_extended_query else 'standard'
            }
            
            conn.close()
            return observations, metadata
            
        finally:
            # Clean up temp file
            try:
                if temp_db.exists():
                    temp_db.unlink()
                # Also clean any generated journal files
                for suffix in ['-wal', '-shm', '-journal']:
                    temp_journal = Path(str(temp_db) + suffix)
                    if temp_journal.exists():
                        temp_journal.unlink()
            except Exception:
                pass
    
    def query_with_wal(self, output_dir: str, use_extended_query: bool = False) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Query the database with WAL file committed.
        
        Creates a COPY of the database and WAL, commits the WAL to the copy,
        then queries. Original files are preserved.
        
        Args:
            output_dir: Directory for temporary working copy
            use_extended_query: If True, use the extended query with additional fields
            
        Returns:
            Tuple of (observations list, metadata dict)
        """
        if not self.wal_path or not self.wal_path.exists():
            raise FileNotFoundError("WAL file not available for this operation")
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Create a copy with WAL committed
        temp_db = self._create_db_with_wal_copy(output_path)
        
        try:
            # Open and query the database with committed WAL
            conn = sqlite3.connect(str(temp_db))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Run the query
            query = self.EXTENDED_OBSERVATIONS_QUERY if use_extended_query else self.OBSERVATIONS_QUERY
            
            try:
                cursor.execute(query)
                rows = cursor.fetchall()
            except sqlite3.Error as e:
                conn.close()
                raise RuntimeError(f"Query failed: {e}")
            
            observations = self._parse_observations(rows)
            
            metadata = {
                'source': 'database_with_wal',
                'db_path': str(self.db_path),
                'wal_path': str(self.wal_path),
                'wal_included': True,
                'record_count': len(observations),
                'query_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'query_type': 'extended' if use_extended_query else 'standard'
            }
            
            conn.close()
            return observations, metadata
            
        finally:
            # Clean up temp files
            try:
                if temp_db.exists():
                    temp_db.unlink()
                # Also clean any generated journal files
                for suffix in ['-wal', '-shm', '-journal']:
                    temp_journal = Path(str(temp_db) + suffix)
                    if temp_journal.exists():
                        temp_journal.unlink()
            except Exception:
                pass
    
    def export_to_csv(self, observations: List[Dict[str, Any]], output_path: str, 
                      metadata: Optional[Dict[str, Any]] = None) -> int:
        """
        Export observations to CSV file.
        
        Args:
            observations: List of observation dictionaries
            output_path: Path for CSV output
            metadata: Optional metadata to include in header comments
            
        Returns:
            Number of records exported
        """
        if not observations:
            # Create empty file with headers
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                # Write metadata as comments if provided
                if metadata:
                    f.write(f"# Query Time: {metadata.get('query_time', 'Unknown')}\n")
                    f.write(f"# Source: {metadata.get('source', 'Unknown')}\n")
                    f.write(f"# WAL Included: {metadata.get('wal_included', False)}\n")
                    f.write(f"# Records: 0\n")
                # Write header
                writer.writerow(['Seen_Time', 'Latitude', 'Longitude', 'Identifier', 
                               'MAC_Address', 'Signal_Strength_dBm', 'Advertised_Data'])
            return 0
        
        # Determine columns from first record
        fieldnames = list(observations[0].keys())
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            # Write metadata as comments if provided
            if metadata:
                f.write(f"# Query Time: {metadata.get('query_time', 'Unknown')}\n")
                f.write(f"# Source: {metadata.get('source', 'Unknown')}\n")
                f.write(f"# WAL Included: {metadata.get('wal_included', False)}\n")
                f.write(f"# Records: {len(observations)}\n")
                f.write("#\n")
            
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(observations)
        
        return len(observations)
    
    def export_to_kml(self, observations: List[Dict[str, Any]], output_path: str,
                      title: str = "Observations", description: str = None) -> int:
        """
        Export observations with GPS coordinates to KML file.
        
        Args:
            observations: List of observation dictionaries
            output_path: Path for KML output
            title: KML document title
            description: KML document description
            
        Returns:
            Number of points exported
        """
        # Filter to observations with valid coordinates
        with_location = [
            o for o in observations 
            if o.get('Latitude') is not None and o.get('Longitude') is not None
            and o.get('Latitude') != 0 and o.get('Longitude') != 0
        ]
        
        if description is None:
            description = f"Observed FindMy-compatible devices ({len(with_location)} locations)"
        
        kml_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>{title}</name>
    <description>{description}</description>
    <Style id="observationStyle">
      <IconStyle>
        <color>ff0000ff</color>
        <scale>0.8</scale>
        <Icon>
          <href>http://maps.google.com/mapfiles/kml/shapes/placemark_circle.png</href>
        </Icon>
      </IconStyle>
    </Style>
'''
        
        for obs in with_location:
            # Create placemark name
            name = obs.get('Identifier') or obs.get('MAC_Address') or 'Unknown Device'
            
            # Create description with available data
            desc_parts = []
            if obs.get('Seen_Time'):
                desc_parts.append(f"Time: {obs['Seen_Time']}")
            if obs.get('MAC_Address'):
                desc_parts.append(f"MAC: {obs['MAC_Address']}")
            if obs.get('Signal_Strength_dBm') is not None:
                desc_parts.append(f"RSSI: {obs['Signal_Strength_dBm']} dBm")
            if obs.get('Identifier'):
                desc_parts.append(f"Beacon ID: {obs['Identifier']}")
            desc_parts.append(f"Location: {obs['Latitude']:.6f}, {obs['Longitude']:.6f}")
            
            description_text = '\n'.join(desc_parts)
            
            # Escape special characters for XML
            name = name.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            
            kml_content += f'''
    <Placemark>
      <name>{name}</name>
      <description><![CDATA[{description_text}]]></description>
      <styleUrl>#observationStyle</styleUrl>
      <Point>
        <coordinates>{obs['Longitude']},{obs['Latitude']},0</coordinates>
      </Point>
    </Placemark>
'''
        
        kml_content += '''
  </Document>
</kml>
'''
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(kml_content)
        
        return len(with_location)
    
    def run_full_analysis(self, output_dir: str, use_extended_query: bool = False,
                          export_kml: bool = True) -> Dict[str, Any]:
        """
        Run complete two-stage analysis and export results.
        
        Stage 1: Query database without WAL (creates temporary copy without WAL)
        Stage 2: Query database with WAL committed (creates temporary copy with WAL)
        
        Both stages use temporary copies to preserve the original decrypted files.
        
        Args:
            output_dir: Directory for output files
            use_extended_query: If True, use extended query with additional fields
            export_kml: If True, also export KML files for each stage
            
        Returns:
            Dictionary with results and file paths
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        results = {
            'output_dir': str(output_path),
            'timestamp': timestamp,
            'original_db_preserved': str(self.db_path),
            'original_wal_preserved': str(self.wal_path) if self.wal_path else None,
            'stages': []
        }
        
        # Stage 1: Database only (no WAL)
        try:
            obs_db_only, meta_db_only = self.query_database_only(str(output_path), use_extended_query)
            
            csv_path_db = output_path / f"observations_database_only_{timestamp}.csv"
            self.export_to_csv(obs_db_only, str(csv_path_db), meta_db_only)
            
            stage1_result = {
                'name': 'Stage 1: Database Only (Without WAL)',
                'success': True,
                'record_count': len(obs_db_only),
                'csv_path': str(csv_path_db),
                'metadata': meta_db_only
            }
            
            if export_kml:
                kml_path_db = output_path / f"observations_database_only_{timestamp}.kml"
                kml_count_db = self.export_to_kml(
                    obs_db_only, 
                    str(kml_path_db), 
                    "Observations (Database Only)",
                    f"Observations from main database without WAL data"
                )
                stage1_result['kml_path'] = str(kml_path_db)
                stage1_result['location_count'] = kml_count_db
            
            results['stages'].append(stage1_result)
            db_only_count = len(obs_db_only)
            
        except Exception as e:
            results['stages'].append({
                'name': 'Stage 1: Database Only (Without WAL)',
                'success': False,
                'error': str(e)
            })
            db_only_count = 0
        
        # Stage 2: Database + WAL (if WAL exists)
        if self.wal_path and self.wal_path.exists():
            try:
                obs_with_wal, meta_with_wal = self.query_with_wal(str(output_path), use_extended_query)
                
                csv_path_wal = output_path / f"observations_with_wal_{timestamp}.csv"
                self.export_to_csv(obs_with_wal, str(csv_path_wal), meta_with_wal)
                
                # Calculate difference between stages
                wal_additional = len(obs_with_wal) - db_only_count
                
                stage2_result = {
                    'name': 'Stage 2: Database + WAL (With WAL Committed)',
                    'success': True,
                    'record_count': len(obs_with_wal),
                    'additional_from_wal': wal_additional,
                    'csv_path': str(csv_path_wal),
                    'metadata': meta_with_wal
                }
                
                if export_kml:
                    kml_path_wal = output_path / f"observations_with_wal_{timestamp}.kml"
                    kml_count_wal = self.export_to_kml(
                        obs_with_wal, 
                        str(kml_path_wal),
                        "Observations (With WAL)",
                        f"Observations including WAL data (most complete)"
                    )
                    stage2_result['kml_path'] = str(kml_path_wal)
                    stage2_result['location_count'] = kml_count_wal
                
                results['stages'].append(stage2_result)
                
            except Exception as e:
                results['stages'].append({
                    'name': 'Stage 2: Database + WAL (With WAL Committed)',
                    'success': False,
                    'error': str(e)
                })
        else:
            results['stages'].append({
                'name': 'Stage 2: Database + WAL (With WAL Committed)',
                'success': False,
                'error': 'WAL file not available',
                'skipped': True
            })
        
        # Summary
        successful_stages = [s for s in results['stages'] if s.get('success', False)]
        max_records = max((s.get('record_count', 0) for s in successful_stages), default=0)
        
        results['summary'] = {
            'stages_completed': len(successful_stages),
            'stages_total': len(results['stages']),
            'total_unique_records': max_records,
            'original_files_preserved': True
        }
        
        return results


# Command-line interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Query decrypted Observations.db database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run full two-stage analysis
  python -m src.observations_query_handler Observations_decrypted.db ./output
  
  # Query with WAL file
  python -m src.observations_query_handler Observations_decrypted.db ./output --wal Observations_decrypted.db-wal
  
  # Use extended query (includes Advertisement ID and Sequence Number)
  python -m src.observations_query_handler Observations_decrypted.db ./output --extended
  
  # Skip KML export
  python -m src.observations_query_handler Observations_decrypted.db ./output --no-kml
        """
    )
    
    parser.add_argument('database', help='Path to decrypted Observations.db')
    parser.add_argument('output_dir', help='Directory for output files')
    parser.add_argument('--wal', help='Path to decrypted WAL file')
    parser.add_argument('--extended', action='store_true', help='Use extended query with additional fields')
    parser.add_argument('--db-only', action='store_true', help='Query database only (skip WAL)')
    parser.add_argument('--no-kml', action='store_true', help='Skip KML export')
    
    args = parser.parse_args()
    
    try:
        # Create query handler
        handler = ObservationsQueryHandler(args.database, args.wal)
        
        print(f"Database: {args.database}")
        if args.wal:
            print(f"WAL file: {args.wal}")
        print(f"Output directory: {args.output_dir}")
        print()
        
        # Show table info
        print("Tables in database:")
        for table, count in handler.get_table_info().items():
            print(f"  {table}: {count} records")
        print()
        
        if args.db_only:
            # Database only query
            print("Running database-only query...")
            observations, metadata = handler.query_database_only(args.output_dir, args.extended)
            
            output_path = Path(args.output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            csv_path = output_path / f"observations_{timestamp}.csv"
            handler.export_to_csv(observations, str(csv_path), metadata)
            
            print(f"\n✓ Query complete!")
            print(f"  Records: {len(observations)}")
            print(f"  CSV: {csv_path}")
            
            if not args.no_kml:
                kml_path = output_path / f"observations_{timestamp}.kml"
                kml_count = handler.export_to_kml(observations, str(kml_path))
                print(f"  Locations: {kml_count}")
                print(f"  KML: {kml_path}")
        else:
            # Full two-stage analysis
            print("Running full two-stage analysis...")
            print("Note: Original decrypted files will be preserved.")
            print()
            
            results = handler.run_full_analysis(
                args.output_dir, 
                args.extended,
                export_kml=not args.no_kml
            )
            
            print(f"\n✓ Analysis complete!")
            print(f"\nOriginal files preserved:")
            print(f"  Database: {results['original_db_preserved']}")
            if results['original_wal_preserved']:
                print(f"  WAL: {results['original_wal_preserved']}")
            
            print(f"\nResults:")
            
            for stage in results['stages']:
                print(f"\n  {stage['name']}:")
                if stage.get('success'):
                    print(f"    Records: {stage['record_count']}")
                    if 'additional_from_wal' in stage:
                        print(f"    Additional from WAL: {stage['additional_from_wal']}")
                    if 'location_count' in stage:
                        print(f"    Locations: {stage.get('location_count', 0)}")
                    print(f"    CSV: {stage.get('csv_path', 'N/A')}")
                    if 'kml_path' in stage:
                        print(f"    KML: {stage.get('kml_path', 'N/A')}")
                else:
                    print(f"    Error: {stage.get('error', 'Unknown')}")
            
            print(f"\nOutput directory: {results['output_dir']}")
        
        # Cleanup temp files
        handler.cleanup_temp_files()
        
    except Exception as e:
        print(f"ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
