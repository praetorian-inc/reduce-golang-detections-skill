#!/usr/bin/env python3
"""
PE Structural Analyzer — Comprehensive feature extraction for ML detection research.

Extracts all features that AV ML classifiers use, organized by detection vector.
Outputs JSON per-sample and CSV summary for correlation analysis.

Feature categories:
  1. Header fields (EMBER HeaderFileInfo equivalent)
  2. Section table (EMBER SectionInfo equivalent + Go-specific)
  3. Import table (EMBER ImportsInfo equivalent)
  4. Byte statistics (EMBER ByteHistogram + ByteEntropyHistogram equivalent)
  5. String features (EMBER StringExtractor equivalent)
  6. Data directories (EMBER DataDirectories equivalent)
  7. General file info (EMBER GeneralFileInfo equivalent)
  8. Go-specific features (custom: BSS ratio, symtab, linker fingerprint)
  9. Certificate/Authenticode features
  10. Resource features
  11. Anomaly scores (composite)

Usage:
  python3 pe_structural_analyzer.py /path/to/samples/ [--baseline /path/to/vanilla.exe]
"""

import pefile
import lief
import os
import sys
import json
import math
import hashlib
import struct
from collections import Counter
from pathlib import Path


def byte_histogram(data):
    """256-bin byte frequency histogram (EMBER ByteHistogram)."""
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    return [c / total for c in counts] if total > 0 else counts


def byte_entropy_histogram(data, window=2048):
    """Joint byte-value/entropy 2D histogram (EMBER ByteEntropyHistogram).
    Maps each byte to (byte_value_bin, entropy_bin) where:
    - byte_value: 16 bins (0-15, 16-31, ..., 240-255)
    - entropy: 16 bins (0.0-0.5, 0.5-1.0, ..., 7.5-8.0)
    Returns 256 values (16x16 flattened).
    """
    if len(data) < window:
        return [0.0] * 256

    hist2d = [[0] * 16 for _ in range(16)]
    total_pairs = 0

    # Sliding window entropy calculation (approximate with stride)
    stride = max(1, window // 4)
    for offset in range(0, len(data) - window, stride):
        chunk = data[offset:offset + window]
        # Compute entropy of this window
        counts = Counter(chunk)
        ent = 0.0
        for c in counts.values():
            p = c / window
            if p > 0:
                ent -= p * math.log2(p)

        ent_bin = min(15, int(ent * 2))  # 0-8 -> 0-15

        # Map center byte to histogram
        center = data[offset + window // 2]
        val_bin = center >> 4  # 0-255 -> 0-15
        hist2d[val_bin][ent_bin] += 1
        total_pairs += 1

    # Flatten and normalize
    result = []
    for row in hist2d:
        for val in row:
            result.append(val / total_pairs if total_pairs > 0 else 0.0)
    return result


def section_entropy(section_data):
    """Shannon entropy of a byte sequence."""
    if len(section_data) == 0:
        return 0.0
    counts = Counter(section_data)
    total = len(section_data)
    ent = 0.0
    for c in counts.values():
        p = c / total
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def string_features(data):
    """Extract string statistics (EMBER StringExtractor equivalent)."""
    # Find printable ASCII strings of length >= 5
    strings = []
    current = []
    for b in data:
        if 32 <= b <= 126:
            current.append(chr(b))
        else:
            if len(current) >= 5:
                strings.append(''.join(current))
            current = []
    if len(current) >= 5:
        strings.append(''.join(current))

    if not strings:
        return {
            'num_strings': 0, 'avg_len': 0, 'max_len': 0,
            'num_urls': 0, 'num_paths': 0, 'num_registry': 0,
            'num_mz_headers': 0, 'printable_ratio': 0.0,
            'string_entropy': 0.0
        }

    lengths = [len(s) for s in strings]
    all_text = ' '.join(strings)

    return {
        'num_strings': len(strings),
        'avg_len': sum(lengths) / len(lengths),
        'max_len': max(lengths),
        'num_urls': sum(1 for s in strings if 'http' in s.lower() or 'ftp' in s.lower()),
        'num_paths': sum(1 for s in strings if '\\' in s or '/' in s),
        'num_registry': sum(1 for s in strings if 'HKEY_' in s or 'Software\\' in s),
        'num_mz_headers': sum(1 for s in strings if s.startswith('MZ') or 'This program' in s),
        'printable_ratio': sum(1 for b in data if 32 <= b <= 126) / len(data),
        'string_entropy': section_entropy(all_text.encode()) if all_text else 0.0
    }


def analyze_pe(filepath, label=""):
    """Extract comprehensive PE features from a single binary."""
    data = open(filepath, 'rb').read()
    pe = pefile.PE(data=data)
    binary = lief.parse(list(data))

    total_size = len(data)
    oh = pe.OPTIONAL_HEADER
    fh = pe.FILE_HEADER

    features = {'file': os.path.basename(filepath), 'label': label, 'size': total_size}

    # ===== 1. HEADER FIELDS =====
    features['header'] = {
        'machine': fh.Machine,
        'num_sections': fh.NumberOfSections,
        'timestamp': fh.TimeDateStamp,
        'timestamp_is_zero': fh.TimeDateStamp == 0,
        'pointer_to_symbol_table': fh.PointerToSymbolTable,
        'num_symbols': fh.NumberOfSymbols,
        'sizeof_optional_header': fh.SizeOfOptionalHeader,
        'characteristics': fh.Characteristics,
        'magic': oh.Magic,
        'major_linker_version': oh.MajorLinkerVersion,
        'minor_linker_version': oh.MinorLinkerVersion,
        'sizeof_code': oh.SizeOfCode,
        'sizeof_initialized_data': oh.SizeOfInitializedData,
        'sizeof_uninitialized_data': oh.SizeOfUninitializedData,
        'entry_point': oh.AddressOfEntryPoint,
        'base_of_code': oh.BaseOfCode,
        'image_base': oh.ImageBase,
        'section_alignment': oh.SectionAlignment,
        'file_alignment': oh.FileAlignment,
        'major_os_version': oh.MajorOperatingSystemVersion,
        'minor_os_version': oh.MinorOperatingSystemVersion,
        'major_image_version': oh.MajorImageVersion,
        'minor_image_version': oh.MinorImageVersion,
        'major_subsystem_version': oh.MajorSubsystemVersion,
        'minor_subsystem_version': oh.MinorSubsystemVersion,
        'sizeof_image': oh.SizeOfImage,
        'sizeof_headers': oh.SizeOfHeaders,
        'checksum': oh.CheckSum,
        'checksum_is_valid': oh.CheckSum != 0,
        'subsystem': oh.Subsystem,
        'dll_characteristics': oh.DllCharacteristics,
        'sizeof_stack_reserve': oh.SizeOfStackReserve,
        'sizeof_stack_commit': oh.SizeOfStackCommit,
        'sizeof_heap_reserve': oh.SizeOfHeapReserve,
        'sizeof_heap_commit': oh.SizeOfHeapCommit,
        'num_rva_and_sizes': oh.NumberOfRvaAndSizes,
    }

    # Derived header features
    features['header']['code_to_init_data_ratio'] = (
        oh.SizeOfCode / oh.SizeOfInitializedData
        if oh.SizeOfInitializedData > 0 else 999
    )
    features['header']['code_to_file_ratio'] = oh.SizeOfCode / total_size

    # ===== 2. RICH HEADER =====
    features['rich_header'] = {
        'present': pe.RICH_HEADER is not None,
        'num_entries': len(pe.RICH_HEADER.values) // 2 if pe.RICH_HEADER else 0,
    }

    # ===== 3. SECTIONS =====
    sections = []
    section_entropies = []
    section_raw_sizes = []
    section_virt_sizes = []
    max_entropy = 0
    max_entropy_section_pct = 0
    high_entropy_sections = 0  # entropy > 7.0
    max_entropy_sections = 0   # entropy > 7.9
    discardable_sections = 0
    discardable_size = 0
    code_sections_size = 0
    data_sections_size = 0
    debug_like_size = 0
    numeric_section_names = 0
    symtab_size = 0
    has_edata = False
    has_rsrc = False
    bss_ratio = 0.0  # .data virt/raw

    for s in pe.sections:
        name = s.Name.decode('utf-8', errors='replace').rstrip('\x00')
        raw = s.SizeOfRawData
        virt = s.Misc_VirtualSize
        ent = s.get_entropy()
        flags = s.Characteristics
        pct_of_file = raw / total_size if total_size > 0 else 0

        sec_info = {
            'name': name,
            'raw_size': raw,
            'virtual_size': virt,
            'entropy': round(ent, 4),
            'characteristics': flags,
            'pct_of_file': round(pct_of_file, 4),
            'virt_raw_ratio': round(virt / raw, 2) if raw > 0 else 0,
            'is_executable': bool(flags & 0x20000000),
            'is_writable': bool(flags & 0x80000000),
            'is_discardable': bool(flags & 0x02000000),
        }
        sections.append(sec_info)
        section_entropies.append(ent)
        section_raw_sizes.append(raw)
        section_virt_sizes.append(virt)

        if ent > max_entropy:
            max_entropy = ent
            max_entropy_section_pct = pct_of_file
        if ent > 7.0:
            high_entropy_sections += 1
        if ent > 7.9:
            max_entropy_sections += 1
        if flags & 0x02000000:
            discardable_sections += 1
            discardable_size += raw
        if flags & 0x20000000:  # executable
            code_sections_size += raw
        if name.startswith('/') and name[1:].isdigit():
            numeric_section_names += 1
            debug_like_size += raw
        if name == '.symtab':
            symtab_size = raw
        if name == '.edata':
            has_edata = True
        if name == '.rsrc':
            has_rsrc = True
        if name == '.data' and raw > 0:
            bss_ratio = virt / raw

    # Section aggregates
    mean_entropy = sum(section_entropies) / len(section_entropies) if section_entropies else 0
    std_entropy = (sum((e - mean_entropy)**2 for e in section_entropies) / len(section_entropies))**0.5 if len(section_entropies) > 1 else 0

    features['sections'] = {
        'details': sections,
        'count': len(sections),
        'mean_entropy': round(mean_entropy, 4),
        'std_entropy': round(std_entropy, 4),
        'max_entropy': round(max_entropy, 4),
        'min_entropy': round(min(section_entropies) if section_entropies else 0, 4),
        'high_entropy_count': high_entropy_sections,
        'max_entropy_count': max_entropy_sections,
        'max_entropy_section_pct': round(max_entropy_section_pct, 4),
        'discardable_count': discardable_sections,
        'discardable_pct': round(discardable_size / total_size, 4) if total_size > 0 else 0,
        'numeric_name_count': numeric_section_names,
        'debug_like_pct': round(debug_like_size / total_size, 4) if total_size > 0 else 0,
        'code_pct': round(code_sections_size / total_size, 4) if total_size > 0 else 0,
        'symtab_size': symtab_size,
        'symtab_pct': round(symtab_size / total_size, 4) if total_size > 0 else 0,
        'has_edata': has_edata,
        'has_rsrc': has_rsrc,
        'bss_ratio': round(bss_ratio, 2),
        'largest_section_pct': round(max(section_raw_sizes) / total_size, 4) if section_raw_sizes else 0,
        'smallest_section_size': min(section_raw_sizes) if section_raw_sizes else 0,
    }

    # ===== 4. IMPORTS =====
    import_dlls = {}
    total_imports = 0
    has_get_proc_address = False
    has_load_library = False
    has_virtual_alloc = False
    has_create_thread = False
    has_write_process_memory = False

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode().lower()
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    fname = imp.name.decode()
                    funcs.append(fname)
                    fl = fname.lower()
                    if 'getprocaddress' in fl: has_get_proc_address = True
                    if 'loadlibrary' in fl: has_load_library = True
                    if 'virtualalloc' in fl: has_virtual_alloc = True
                    if 'createthread' in fl: has_create_thread = True
                    if 'writeprocessmemory' in fl: has_write_process_memory = True
            import_dlls[dll] = funcs
            total_imports += len(funcs)

    features['imports'] = {
        'num_dlls': len(import_dlls),
        'total_functions': total_imports,
        'dlls': {dll: len(funcs) for dll, funcs in import_dlls.items()},
        'dll_names': sorted(import_dlls.keys()),
        'imphash': pe.get_imphash(),
        'has_get_proc_address': has_get_proc_address,
        'has_load_library': has_load_library,
        'has_virtual_alloc': has_virtual_alloc,
        'has_create_thread': has_create_thread,
        'has_write_process_memory': has_write_process_memory,
        'suspicious_api_count': sum([has_get_proc_address, has_load_library,
                                     has_virtual_alloc, has_create_thread,
                                     has_write_process_memory]),
    }

    # ===== 5. DATA DIRECTORIES =====
    dd_names = ['EXPORT','IMPORT','RESOURCE','EXCEPTION','SECURITY','BASERELOC',
                'DEBUG','ARCHITECTURE','GLOBALPTR','TLS','LOAD_CONFIG',
                'BOUND_IMPORT','IAT','DELAY_IMPORT','CLR_RUNTIME','RESERVED']
    data_dirs = {}
    for i, d in enumerate(oh.DATA_DIRECTORY):
        n = dd_names[i] if i < len(dd_names) else f'DIR_{i}'
        data_dirs[n] = {'rva': d.VirtualAddress, 'size': d.Size}

    features['data_directories'] = {
        'present': {n: info['size'] > 0 for n, info in data_dirs.items()},
        'sizes': {n: info['size'] for n, info in data_dirs.items() if info['size'] > 0},
        'has_debug_dir': data_dirs.get('DEBUG', {}).get('size', 0) > 0,
        'has_tls': data_dirs.get('TLS', {}).get('size', 0) > 0,
        'has_load_config': data_dirs.get('LOAD_CONFIG', {}).get('size', 0) > 0,
        'has_security': data_dirs.get('SECURITY', {}).get('size', 0) > 0,
        'has_exception': data_dirs.get('EXCEPTION', {}).get('size', 0) > 0,
        'has_reloc': data_dirs.get('BASERELOC', {}).get('size', 0) > 0,
        'security_size': data_dirs.get('SECURITY', {}).get('size', 0),
    }

    # ===== 6. STRINGS =====
    features['strings'] = string_features(data)

    # ===== 7. BYTE STATISTICS =====
    histogram = byte_histogram(data)
    features['byte_stats'] = {
        'file_entropy': section_entropy(data),
        'byte_histogram_std': (sum((h - 1/256)**2 for h in histogram) / 256)**0.5,
        'byte_histogram_skew': sum((h - 1/256)**3 for h in histogram) / (256 * ((sum((h - 1/256)**2 for h in histogram) / 256)**0.5)**3) if sum((h - 1/256)**2 for h in histogram) > 0 else 0,
        'null_byte_ratio': histogram[0],
        'ff_byte_ratio': histogram[255],
        'ascii_byte_ratio': sum(histogram[32:127]),
    }

    # ===== 8. GO-SPECIFIC FEATURES =====
    features['go_specific'] = {
        'is_go_binary': oh.MajorLinkerVersion == 3 and oh.MinorLinkerVersion == 0,
        'linker_version_go': oh.MajorLinkerVersion == 3,
        'has_symtab': symtab_size > 0,
        'symtab_size': symtab_size,
        'has_coff_long_names': numeric_section_names > 0,
        'coff_long_name_count': numeric_section_names,
        'bss_ratio': round(bss_ratio, 2),
        'stack_reserve': oh.SizeOfStackReserve,
        'stack_reserve_is_go_default': oh.SizeOfStackReserve == 0x200000,
        'has_go_build_id': any(b'Go build ID' in data[i:i+20] for i in range(0, min(len(data), 0x1000), 1)),
    }

    # ===== 9. AUTHENTICODE =====
    sec_dir = oh.DATA_DIRECTORY[4]
    features['authenticode'] = {
        'signed': sec_dir.Size > 0,
        'cert_size': sec_dir.Size,
        'cert_pct': round(sec_dir.Size / total_size, 6) if total_size > 0 else 0,
    }

    # Parse certificate if present
    if sec_dir.Size > 0 and sec_dir.VirtualAddress > 0:
        try:
            cert_data = data[sec_dir.VirtualAddress:sec_dir.VirtualAddress + sec_dir.Size]
            if len(cert_data) >= 8:
                cert_len, cert_rev, cert_type = struct.unpack('<IHH', cert_data[:8])
                features['authenticode']['cert_revision'] = cert_rev
                features['authenticode']['cert_type'] = cert_type
        except:
            pass

    # ===== 10. VERSIONINFO =====
    version_info = {}
    if hasattr(pe, 'VS_VERSIONINFO'):
        for finfo in pe.FileInfo:
            for entry in finfo:
                if hasattr(entry, 'StringTable'):
                    for st in entry.StringTable:
                        for k, v in st.entries.items():
                            version_info[k.decode()] = v.decode()

    features['version_info'] = {
        'present': len(version_info) > 0,
        'fields': version_info,
        'field_count': len(version_info),
        'has_company': 'CompanyName' in version_info,
        'has_product': 'ProductName' in version_info,
        'has_description': 'FileDescription' in version_info,
        'has_original_filename': 'OriginalFilename' in version_info,
    }

    # ===== 11. OVERLAY =====
    overlay_offset = pe.get_overlay_data_start_offset()
    if overlay_offset:
        overlay_size = total_size - overlay_offset
        features['overlay'] = {
            'present': True,
            'offset': overlay_offset,
            'size': overlay_size,
            'pct': round(overlay_size / total_size, 4),
        }
    else:
        features['overlay'] = {'present': False, 'offset': 0, 'size': 0, 'pct': 0}

    # ===== 12. HASHES =====
    features['hashes'] = {
        'md5': hashlib.md5(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest(),
        'imphash': pe.get_imphash(),
    }

    # ===== 13. ANOMALY SCORES (composite) =====
    anomalies = 0
    anomaly_details = []

    if fh.TimeDateStamp == 0:
        anomalies += 1
        anomaly_details.append('timestamp_zero')
    if pe.RICH_HEADER is None:
        anomalies += 1
        anomaly_details.append('no_rich_header')
    if oh.MajorLinkerVersion == 3:
        anomalies += 1
        anomaly_details.append('linker_v3_go')
    if bss_ratio > 50:
        anomalies += 1
        anomaly_details.append(f'extreme_bss_ratio_{bss_ratio:.0f}')
    if high_entropy_sections >= 5:
        anomalies += 1
        anomaly_details.append(f'many_high_entropy_sections_{high_entropy_sections}')
    if numeric_section_names >= 3:
        anomalies += 1
        anomaly_details.append(f'numeric_section_names_{numeric_section_names}')
    if symtab_size > 0:
        anomalies += 1
        anomaly_details.append(f'has_coff_symtab_{symtab_size}')
    if has_edata and data_dirs.get('EXPORT', {}).get('size', 0) == 0:
        anomalies += 1
        anomaly_details.append('phantom_edata')
    if not data_dirs.get('DEBUG', {}).get('size', 0) > 0:
        anomalies += 1
        anomaly_details.append('no_debug_directory')
    if not data_dirs.get('LOAD_CONFIG', {}).get('size', 0) > 0:
        anomalies += 1
        anomaly_details.append('no_load_config')
    if debug_like_size / total_size > 0.4:
        anomalies += 1
        anomaly_details.append(f'debug_sections_over_40pct')
    if has_get_proc_address and has_load_library:
        anomalies += 1
        anomaly_details.append('dynamic_api_resolution')

    features['anomaly_score'] = {
        'total': anomalies,
        'details': anomaly_details,
    }

    return features


def flat_features_for_csv(features):
    """Flatten features dict into a single-level dict for CSV output."""
    flat = {
        'file': features['file'],
        'label': features['label'],
        'size': features['size'],
    }

    # Header
    for k, v in features['header'].items():
        flat[f'hdr_{k}'] = v

    # Rich header
    flat['rich_present'] = features['rich_header']['present']

    # Sections aggregate
    for k, v in features['sections'].items():
        if k != 'details':
            flat[f'sec_{k}'] = v

    # Imports
    for k, v in features['imports'].items():
        if k not in ('dlls', 'dll_names'):
            flat[f'imp_{k}'] = v

    # Data directories
    for k, v in features['data_directories'].items():
        if isinstance(v, dict):
            for kk, vv in v.items():
                flat[f'dd_{k}_{kk}'] = vv
        else:
            flat[f'dd_{k}'] = v

    # Strings
    for k, v in features['strings'].items():
        flat[f'str_{k}'] = v

    # Byte stats
    for k, v in features['byte_stats'].items():
        flat[f'byte_{k}'] = v

    # Go specific
    for k, v in features['go_specific'].items():
        flat[f'go_{k}'] = v

    # Authenticode
    for k, v in features['authenticode'].items():
        flat[f'auth_{k}'] = v

    # Version info
    flat['vi_present'] = features['version_info']['present']
    flat['vi_field_count'] = features['version_info']['field_count']
    for k, v in features['version_info'].get('fields', {}).items():
        flat[f'vi_{k}'] = v

    # Overlay
    flat['overlay_present'] = features['overlay']['present']
    flat['overlay_size'] = features['overlay']['size']
    flat['overlay_pct'] = features['overlay']['pct']

    # Anomaly
    flat['anomaly_score'] = features['anomaly_score']['total']
    flat['anomaly_details'] = '|'.join(features['anomaly_score']['details'])

    return flat


def main():
    import csv

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <sample_dir_or_file> [--baseline <vanilla.exe>] [--detections <json_file>]")
        sys.exit(1)

    target = sys.argv[1]
    baseline_path = None
    detections_path = None

    for i, arg in enumerate(sys.argv[2:], 2):
        if arg == '--baseline' and i + 1 < len(sys.argv):
            baseline_path = sys.argv[i + 1]
        if arg == '--detections' and i + 1 < len(sys.argv):
            detections_path = sys.argv[i + 1]

    # Load detection labels if provided
    detections = {}
    if detections_path and os.path.exists(detections_path):
        with open(detections_path) as f:
            detections = json.load(f)

    # Collect files
    if os.path.isdir(target):
        files = sorted([os.path.join(target, f) for f in os.listdir(target)
                       if f.endswith('.exe') or f.endswith('.dll')])
    else:
        files = [target]

    # Analyze baseline if provided
    baseline_features = None
    if baseline_path and os.path.exists(baseline_path):
        print(f"Analyzing baseline: {baseline_path}", file=sys.stderr)
        baseline_features = analyze_pe(baseline_path, "baseline")

    # Analyze all samples
    all_features = []
    all_flat = []

    for filepath in files:
        fname = os.path.basename(filepath)
        label = detections.get(fname, "unknown")
        print(f"Analyzing: {fname} (label: {label})", file=sys.stderr)
        features = analyze_pe(filepath, label)
        all_features.append(features)
        all_flat.append(flat_features_for_csv(features))

    # Output full JSON
    output = {
        'samples': all_features,
        'baseline': baseline_features,
        'summary': {
            'total_samples': len(all_features),
            'feature_count': len(all_flat[0]) if all_flat else 0,
        }
    }

    json_path = '/tmp/pe_analysis.json'
    with open(json_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"Full analysis: {json_path}", file=sys.stderr)

    # Output CSV
    if all_flat:
        csv_path = '/tmp/pe_analysis.csv'
        keys = list(all_flat[0].keys())
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for row in all_flat:
                writer.writerow(row)
        print(f"CSV summary: {csv_path}", file=sys.stderr)

    # Print summary comparison if we have detection labels
    labeled = [f for f in all_features if f['label'] in ('clean', 'detected')]
    if len(labeled) > 0:
        clean = [f for f in labeled if f['label'] == 'clean']
        detected = [f for f in labeled if f['label'] == 'detected']
        print(f"\n=== CLEAN ({len(clean)}) vs DETECTED ({len(detected)}) ===")

        # Compare key metrics
        if clean and detected:
            compare_metrics = [
                ('Section count', lambda f: f['sections']['count']),
                ('Mean entropy', lambda f: f['sections']['mean_entropy']),
                ('Max entropy', lambda f: f['sections']['max_entropy']),
                ('High entropy sections', lambda f: f['sections']['high_entropy_count']),
                ('Debug-like %', lambda f: f['sections']['debug_like_pct']),
                ('BSS ratio', lambda f: f['sections']['bss_ratio']),
                ('Code %', lambda f: f['sections']['code_pct']),
                ('Symtab size', lambda f: f['sections']['symtab_size']),
                ('Import DLLs', lambda f: f['imports']['num_dlls']),
                ('Total imports', lambda f: f['imports']['total_functions']),
                ('Suspicious APIs', lambda f: f['imports']['suspicious_api_count']),
                ('File entropy', lambda f: f['byte_stats']['file_entropy']),
                ('Null byte ratio', lambda f: f['byte_stats']['null_byte_ratio']),
                ('String count', lambda f: f['strings']['num_strings']),
                ('Printable ratio', lambda f: f['strings']['printable_ratio']),
                ('Cert size', lambda f: f['authenticode']['cert_size']),
                ('Anomaly score', lambda f: f['anomaly_score']['total']),
                ('File size', lambda f: f['size']),
            ]

            from statistics import mean, stdev
            print(f"{'Metric':<25s} {'Clean mean':>12s} {'Det mean':>12s} {'Delta':>10s} {'Cohen d':>10s}")
            print("-" * 75)
            for name, extractor in compare_metrics:
                clean_vals = [extractor(f) for f in clean]
                det_vals = [extractor(f) for f in detected]
                if not clean_vals or not det_vals:
                    continue
                cmean = mean(clean_vals)
                dmean = mean(det_vals)
                delta = dmean - cmean

                # Cohen's d
                if len(clean_vals) > 1 and len(det_vals) > 1:
                    cstd = stdev(clean_vals)
                    dstd = stdev(det_vals)
                    pooled = ((cstd**2 + dstd**2) / 2)**0.5
                    d = abs(delta) / pooled if pooled > 0 else 0
                else:
                    d = 0.0

                flag = " ***" if d > 0.8 else " **" if d > 0.5 else " *" if d > 0.3 else ""
                print(f"{name:<25s} {cmean:>12.4f} {dmean:>12.4f} {delta:>+10.4f} {d:>10.3f}{flag}")


if __name__ == '__main__':
    main()
