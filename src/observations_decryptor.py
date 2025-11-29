"""
Observations.db Decryptor for iOS SearchParty

This module decrypts the SQLite Encryption Extension (SEE) encrypted
Observations.db database and its associated WAL file from iOS devices.

The Observations.db database tracks all FindMy-compatible devices that
the iOS device has observed, including location data and MAC addresses.

Encryption Details:
- Method: SQLite Encryption Extension (SEE) with AES-256-OFB
- Page Size: 4096 bytes
- Reserved Area: 12 bytes at end of each page (contains IV/nonce)
- IV Construction: page_number (4 bytes, little-endian) + reserved (12 bytes)
- Header bytes 16-23 are NOT encrypted

WAL Decryption Details:
- The reserved area (IV) must be PRESERVED in decrypted WAL (not zeroed)
- Frame checksums must be RECALCULATED after decryption
- Checksums use native (little-endian) byte order for word interpretation
- Initial checksum values come from WAL header checksum (bytes 24-31)
- Each frame's checksum chains from the previous frame

Reference: https://thebinaryhick.blog/2025/08/19/further-observations-more-on-ios-search-party/
"""

import struct
import sqlite3
import shutil
import os
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class ObservationsDecryptor:
    """
    Decrypts Observations.db and its WAL file using SEE AES-256-OFB.
    """
    
    # Constants
    PAGE_SIZE = 4096
    RESERVED_BYTES = 12  # IV is stored in last 12 bytes of each page
    WAL_HEADER_SIZE = 32
    FRAME_HEADER_SIZE = 24
    SQLITE_MAGIC = b'SQLite format 3\x00'
    
    def __init__(self, key: bytes):
        """
        Initialize the decryptor with the Observations encryption key.
        
        Args:
            key: 32-byte AES-256 encryption key from keychain
        """
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")
        self.key = key
    
    @staticmethod
    def _wal_checksum(data: bytes, s1: int, s2: int) -> Tuple[int, int]:
        """
        Calculate SQLite WAL checksum.
        
        Uses native (little-endian) byte order for word interpretation.
        Processes two 32-bit words at a time:
          s1 += word1 + s2
          s2 += word2 + s1
        
        This matches the SQLite walChecksumBytes() function when
        nativeCksum is True (which it is for magic 0x377f0682 on
        little-endian systems).
        
        Args:
            data: Data to checksum (must be 8-byte aligned)
            s1: Initial s1 value
            s2: Initial s2 value
        
        Returns:
            (s1, s2) tuple with updated checksum values
        """
        for i in range(0, len(data), 8):
            # Use native (little-endian) byte order
            word1 = struct.unpack('<I', data[i:i+4])[0]
            word2 = struct.unpack('<I', data[i+4:i+8])[0]
            s1 = (s1 + word1 + s2) & 0xFFFFFFFF
            s2 = (s2 + word2 + s1) & 0xFFFFFFFF
        return s1, s2
        
    def decrypt_page(self, page_data: bytes, page_number: int) -> bytes:
        """
        Decrypt a single database page using AES-256-OFB.
        
        Args:
            page_data: Raw encrypted page data (4096 bytes)
            page_number: The page number (1-indexed)
            
        Returns:
            Decrypted page data (4096 bytes)
        """
        if len(page_data) != self.PAGE_SIZE:
            raise ValueError(f"Page must be {self.PAGE_SIZE} bytes, got {len(page_data)}")
        
        # Extract the IV from the reserved area (last 12 bytes)
        reserved = page_data[-self.RESERVED_BYTES:]
        encrypted_content = page_data[:-self.RESERVED_BYTES]
        
        # IV construction: page_number (4 bytes LE) + reserved (12 bytes) = 16 bytes
        iv = struct.pack('<I', page_number) + reserved
        
        # Decrypt using AES-256-OFB
        cipher = Cipher(algorithms.AES(self.key), modes.OFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_content) + decryptor.finalize()
        
        # For page 1, restore the unencrypted header bytes 16-23
        if page_number == 1:
            decrypted = decrypted[:16] + page_data[16:24] + decrypted[24:]
        
        # Clear the reserved area (set to zeros for standard SQLite format)
        return decrypted + (b'\x00' * self.RESERVED_BYTES)
    
    def decrypt_database(self, encrypted_db_path: str, output_path: str) -> bool:
        """
        Decrypt an entire Observations.db file.
        
        Args:
            encrypted_db_path: Path to encrypted database
            output_path: Path for decrypted output
            
        Returns:
            True if successful
        """
        with open(encrypted_db_path, 'rb') as f:
            encrypted_db = f.read()
        
        # Validate file size is multiple of page size
        if len(encrypted_db) % self.PAGE_SIZE != 0:
            raise ValueError(f"Database size ({len(encrypted_db)}) is not a multiple of page size ({self.PAGE_SIZE})")
        
        num_pages = len(encrypted_db) // self.PAGE_SIZE
        
        # Decrypt all pages
        decrypted_db = bytearray()
        for page_num in range(1, num_pages + 1):
            page_start = (page_num - 1) * self.PAGE_SIZE
            page_end = page_num * self.PAGE_SIZE
            page_data = encrypted_db[page_start:page_end]
            
            decrypted_page = self.decrypt_page(page_data, page_num)
            decrypted_db.extend(decrypted_page)
        
        # Verify SQLite header
        if decrypted_db[:16] != self.SQLITE_MAGIC:
            raise ValueError("Decryption failed - invalid SQLite header")
        
        # Write decrypted database with explicit flush to ensure it's persisted to disk
        with open(output_path, 'wb') as f:
            f.write(decrypted_db)
            f.flush()
            os.fsync(f.fileno())  # Force write to disk
        
        return True
    
    def decrypt_wal(self, encrypted_wal_path: str, output_path: str) -> Tuple[bool, int]:
        """
        Decrypt the WAL (Write-Ahead Log) file.
        
        The WAL file contains frames, each with:
        - 24-byte frame header
        - 4096-byte page data (encrypted same as main DB)
        
        For Page 1 entries in WAL, bytes 16-23 are NOT encrypted.
        
        IMPORTANT: Unlike the main database, WAL pages must:
        1. PRESERVE the reserved area (IV) - not zero it out
        2. Have frame checksums RECALCULATED after decryption
        
        The checksum algorithm:
        - Uses native (little-endian) byte order
        - Initial values come from WAL header checksum (bytes 24-31)
        - Each frame's checksum chains from the previous frame
        - Checksum covers frame header bytes 0-7 + page content
        
        Args:
            encrypted_wal_path: Path to encrypted WAL file
            output_path: Path for decrypted output
            
        Returns:
            Tuple of (success, number_of_frames)
        """
        with open(encrypted_wal_path, 'rb') as f:
            encrypted_wal = f.read()
        
        if len(encrypted_wal) < self.WAL_HEADER_SIZE:
            raise ValueError("WAL file too small")
        
        # WAL header (first 32 bytes) is not encrypted
        wal_header = bytearray(encrypted_wal[:self.WAL_HEADER_SIZE])
        
        # Verify WAL magic number (big-endian: 0x377f0682, little-endian: 0x377f0683)
        magic = struct.unpack('>I', wal_header[0:4])[0]
        if magic not in (0x377f0682, 0x377f0683):
            raise ValueError(f"Invalid WAL magic number: {hex(magic)}")
        
        # Get the WAL header checksum (bytes 24-31)
        # This is used as the initial value for frame checksums
        hdr_cksum1 = struct.unpack('>I', wal_header[24:28])[0]
        hdr_cksum2 = struct.unpack('>I', wal_header[28:32])[0]
        
        # Calculate number of frames
        frame_size = self.FRAME_HEADER_SIZE + self.PAGE_SIZE
        wal_data_size = len(encrypted_wal) - self.WAL_HEADER_SIZE
        num_frames = wal_data_size // frame_size
        
        # Start building decrypted WAL
        decrypted_wal = bytearray(wal_header)
        
        # Initial checksum values from WAL header checksum
        prev_s1, prev_s2 = hdr_cksum1, hdr_cksum2
        
        # Process each frame
        for frame_idx in range(num_frames):
            frame_start = self.WAL_HEADER_SIZE + frame_idx * frame_size
            frame_header = bytearray(encrypted_wal[frame_start:frame_start + self.FRAME_HEADER_SIZE])
            page_data = encrypted_wal[frame_start + self.FRAME_HEADER_SIZE:frame_start + frame_size]
            
            # Parse frame header to get page number
            page_number = struct.unpack('>I', frame_header[0:4])[0]
            
            # Decrypt the page (preserving reserved area for WAL)
            is_page_1 = (page_number == 1)
            decrypted_page = self._decrypt_wal_page(page_data, page_number, is_page_1)
            
            # Calculate new checksum for this frame
            # First, checksum frame header bytes 0-7
            s1, s2 = self._wal_checksum(bytes(frame_header[0:8]), prev_s1, prev_s2)
            # Then, checksum the decrypted page data
            s1, s2 = self._wal_checksum(decrypted_page, s1, s2)
            
            # Update frame header with new checksums (stored as big-endian)
            struct.pack_into('>I', frame_header, 16, s1)
            struct.pack_into('>I', frame_header, 20, s2)
            
            # Add frame header and decrypted page to output
            decrypted_wal.extend(frame_header)
            decrypted_wal.extend(decrypted_page)
            
            # Use this frame's checksum as initial for next frame
            prev_s1, prev_s2 = s1, s2
        
        # Write decrypted WAL with explicit flush to ensure it's persisted to disk
        with open(output_path, 'wb') as f:
            f.write(decrypted_wal)
            f.flush()
            os.fsync(f.fileno())  # Force write to disk
        
        # Verify file was actually written
        output_path_obj = Path(output_path)
        if not output_path_obj.exists():
            raise RuntimeError(f"WAL file was not created at {output_path}")
        
        actual_size = output_path_obj.stat().st_size
        expected_size = len(decrypted_wal)
        if actual_size != expected_size:
            raise RuntimeError(f"WAL file size mismatch: expected {expected_size}, got {actual_size}")
        
        return True, num_frames
    
    def _decrypt_wal_page(self, page_data: bytes, page_number: int, is_page_1: bool) -> bytes:
        """
        Decrypt a page from the WAL file.
        
        For Page 1, bytes 16-23 are NOT encrypted.
        
        IMPORTANT: Unlike main database pages, WAL pages must PRESERVE
        the reserved area (IV) for proper checksum calculation and
        SQLite compatibility.
        
        Args:
            page_data: Raw encrypted page data
            page_number: The page number
            is_page_1: Whether this is page 1 (has unencrypted header bytes)
            
        Returns:
            Decrypted page data with preserved reserved area
        """
        # Extract reserved area (IV) - keep it for later
        reserved = page_data[-self.RESERVED_BYTES:]
        encrypted_content = page_data[:-self.RESERVED_BYTES]
        
        # IV construction: page_number (4 bytes LE) + reserved (12 bytes)
        iv = struct.pack('<I', page_number) + reserved
        
        # Decrypt using AES-256-OFB
        cipher = Cipher(algorithms.AES(self.key), modes.OFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_content) + decryptor.finalize()
        
        # For page 1, restore unencrypted bytes 16-23
        if is_page_1:
            decrypted = decrypted[:16] + page_data[16:24] + decrypted[24:]
        
        # PRESERVE the reserved area (not zeroing it out!)
        # This is critical for WAL - the reserved area is included in
        # the checksum calculation and must be preserved
        return decrypted + reserved
    
    def decrypt_all(self, db_path: str, output_dir: str) -> Dict[str, str]:
        """
        Decrypt the database and its WAL file (if present).
        
        Args:
            db_path: Path to encrypted Observations.db
            output_dir: Directory for decrypted output files
            
        Returns:
            Dictionary with paths to decrypted files
        """
        db_path = Path(db_path)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        results = {}
        
        # Decrypt main database
        output_db = output_dir / f"Observations_decrypted.db"
        self.decrypt_database(str(db_path), str(output_db))
        results['database'] = str(output_db)
        
        # Check for WAL file
        wal_path = db_path.parent / f"{db_path.name}-wal"
        if wal_path.exists():
            output_wal = output_dir / f"Observations_decrypted.db-wal"
            success, num_frames = self.decrypt_wal(str(wal_path), str(output_wal))
            results['wal'] = str(output_wal)
            results['wal_frames'] = num_frames
        
        # Check for SHM file (doesn't need decryption, but copy it for completeness)
        shm_path = db_path.parent / f"{db_path.name}-shm"
        if shm_path.exists():
            output_shm = output_dir / f"Observations_decrypted.db-shm"
            shutil.copy(str(shm_path), str(output_shm))
            results['shm'] = str(output_shm)
        
        return results


class ObservationsParser:
    """
    Parses decrypted Observations.db database and extracts observation records.
    """
    
    # SQL query to extract observation data (from the blog post)
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
    
    def __init__(self, db_path: str):
        """
        Initialize the parser with path to decrypted database.
        
        Args:
            db_path: Path to decrypted Observations.db
        """
        self.db_path = db_path
    
    def get_tables(self) -> List[str]:
        """Get list of tables in the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        conn.close()
        return tables
    
    def get_table_counts(self) -> Dict[str, int]:
        """Get record counts for all tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        counts = {}
        for table in self.get_tables():
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            counts[table] = cursor.fetchone()[0]
        
        conn.close()
        return counts
    
    def get_observations(self) -> List[Dict[str, Any]]:
        """
        Extract all observation records using the standard query.
        
        Returns:
            List of observation dictionaries
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(self.OBSERVATIONS_QUERY)
        
        observations = []
        for row in cursor.fetchall():
            # Convert MAC address bytes to hex string
            mac_bytes = row['MAC_Address']
            mac_hex = mac_bytes.hex() if mac_bytes else None
            mac_formatted = ':'.join([mac_hex[i:i+2] for i in range(0, len(mac_hex), 2)]) if mac_hex else None
            
            # Convert advertisement data bytes to hex string
            ad_bytes = row['Advertised_Data']
            ad_hex = ad_bytes.hex() if ad_bytes else None
            
            observations.append({
                'seen_time': row['Seen_Time'],
                'latitude': row['Latitude'],
                'longitude': row['Longitude'],
                'identifier': row['Identifier'],
                'mac_address': mac_formatted,
                'mac_address_raw': mac_hex,
                'rssi': row['Signal_Strength'],
                'advertisement_data': ad_hex
            })
        
        conn.close()
        return observations
    
    def export_to_csv(self, output_path: str, observations: List[Dict[str, Any]] = None) -> int:
        """
        Export observations to CSV file.
        
        Args:
            output_path: Path for CSV output
            observations: List of observations (if None, will query database)
            
        Returns:
            Number of records exported
        """
        import csv
        
        if observations is None:
            observations = self.get_observations()
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            if observations:
                writer = csv.DictWriter(f, fieldnames=observations[0].keys())
                writer.writeheader()
                writer.writerows(observations)
        
        return len(observations)
    
    def export_to_kml(self, output_path: str, observations: List[Dict[str, Any]] = None,
                      title: str = "Observed Devices") -> int:
        """
        Export observations with locations to KML file.
        
        Args:
            output_path: Path for KML output
            observations: List of observations (if None, will query database)
            title: Title for the KML document
            
        Returns:
            Number of points exported
        """
        if observations is None:
            observations = self.get_observations()
        
        # Filter to observations with valid coordinates
        with_location = [o for o in observations if o['latitude'] and o['longitude']]
        
        kml_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>{title}</name>
    <description>Observed FindMy-compatible devices</description>
'''
        
        for obs in with_location:
            name = obs['identifier'] or obs['mac_address'] or 'Unknown'
            description = f"""
                Time: {obs['seen_time']}
                MAC: {obs['mac_address'] or 'Unknown'}
                RSSI: {obs['rssi']} dBm
                Identifier: {obs['identifier'] or 'None'}
            """
            
            kml_content += f'''
    <Placemark>
      <name>{name}</name>
      <description><![CDATA[{description}]]></description>
      <Point>
        <coordinates>{obs['longitude']},{obs['latitude']},0</coordinates>
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


def decrypt_observations(keychain_path: str, observations_db_path: str, 
                        output_dir: str) -> Dict[str, Any]:
    """
    Convenience function to decrypt Observations.db using keychain.
    
    Args:
        keychain_path: Path to iOS keychain plist
        observations_db_path: Path to encrypted Observations.db
        output_dir: Directory for output files
        
    Returns:
        Dictionary with results and paths
    """
    from src.ios_keychain_extractor import iOSKeychainExtractor
    
    # Extract Observations key from keychain
    extractor = iOSKeychainExtractor(keychain_path)
    extractor.parse()
    
    obs_key = extractor.get_key_by_service('Observations')
    if not obs_key:
        raise ValueError("Observations key not found in keychain")
    
    # Decrypt database and WAL
    decryptor = ObservationsDecryptor(obs_key)
    results = decryptor.decrypt_all(observations_db_path, output_dir)
    
    # Parse and get basic info
    if 'database' in results:
        parser = ObservationsParser(results['database'])
        results['tables'] = parser.get_tables()
        results['table_counts'] = parser.get_table_counts()
        
        # Get observations count
        observations = parser.get_observations()
        results['observation_count'] = len(observations)
    
    return results


# Command-line interface
if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Decrypt iOS Observations.db database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Decrypt using keychain
  python -m src.observations_decryptor keychain.plist Observations.db ./output
  
  # Decrypt using hex key directly
  python -m src.observations_decryptor --key f42ed0... Observations.db ./output
        """
    )
    
    parser.add_argument('keychain_or_key', help='Keychain plist path OR encryption key (with --key flag)')
    parser.add_argument('database', help='Path to encrypted Observations.db')
    parser.add_argument('output_dir', help='Directory for decrypted output')
    parser.add_argument('--key', action='store_true', help='Treat first argument as hex key instead of keychain path')
    parser.add_argument('--export-csv', help='Export observations to CSV file')
    parser.add_argument('--export-kml', help='Export observations to KML file')
    parser.add_argument('--query', action='store_true', help='Run observations query and display results')
    
    args = parser.parse_args()
    
    try:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Get the encryption key
        if args.key:
            # Direct key provided
            key = bytes.fromhex(args.keychain_or_key)
            print(f"Using provided key: {key.hex()[:16]}...")
        else:
            # Extract from keychain
            from src.ios_keychain_extractor import iOSKeychainExtractor
            
            print(f"Extracting Observations key from keychain...")
            extractor = iOSKeychainExtractor(args.keychain_or_key)
            extractor.parse()
            
            key = extractor.get_key_by_service('Observations')
            if not key:
                print("ERROR: Observations key not found in keychain")
                print(f"Available keys: {', '.join(extractor.list_available_keys())}")
                sys.exit(1)
            
            print(f"✓ Found Observations key: {key.hex()[:16]}...")
        
        # Decrypt
        print(f"\nDecrypting database...")
        decryptor = ObservationsDecryptor(key)
        results = decryptor.decrypt_all(args.database, str(output_dir))
        
        print(f"✓ Database decrypted: {results['database']}")
        if 'wal' in results:
            print(f"✓ WAL decrypted: {results['wal']} ({results['wal_frames']} frames)")
        
        # Verify and display info
        print(f"\nVerifying decrypted database...")
        parser = ObservationsParser(results['database'])
        
        print(f"\nTables found:")
        for table, count in parser.get_table_counts().items():
            print(f"  {table}: {count} records")
        
        # Run query if requested
        if args.query:
            print(f"\nObservation records:")
            observations = parser.get_observations()
            print(f"Total observations: {len(observations)}")
            
            if observations:
                print(f"\nFirst 5 observations:")
                for obs in observations[:5]:
                    print(f"  Time: {obs['seen_time']}")
                    print(f"  Location: {obs['latitude']}, {obs['longitude']}")
                    print(f"  MAC: {obs['mac_address']}")
                    print(f"  RSSI: {obs['rssi']} dBm")
                    print()
        
        # Export if requested
        if args.export_csv:
            observations = parser.get_observations()
            count = parser.export_to_csv(args.export_csv, observations)
            print(f"\n✓ Exported {count} records to CSV: {args.export_csv}")
        
        if args.export_kml:
            observations = parser.get_observations()
            count = parser.export_to_kml(args.export_kml, observations)
            print(f"\n✓ Exported {count} locations to KML: {args.export_kml}")
        
        print(f"\n✓ Decryption complete!")
        
    except Exception as e:
        print(f"ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
