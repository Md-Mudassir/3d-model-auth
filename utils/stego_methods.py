"""
Steganography Methods for 3D Model Authentication
Implements various LSB-based methods from the research paper
"""

import numpy as np
import hashlib
import struct
import random
import json
import base64
from typing import Tuple, List, Dict, Optional


class LSBPlus1:
    """LSB+1: 3-bit embedding for higher capacity"""
    
    def __init__(self):
        self.bits_per_vertex = 3
    
    def embed_bits_in_coordinate(self, coord: float, bits: int) -> float:
        """Embed 3 bits into coordinate"""
        coord_int = struct.unpack('!I', struct.pack('!f', coord))[0]
        coord_int = coord_int & ~0b111  # Clear last 3 bits
        coord_int = coord_int | bits
        return struct.unpack('!f', struct.pack('!I', coord_int))[0]
    
    def extract_bits_from_coordinate(self, coord: float) -> int:
        """Extract 3 bits from coordinate"""
        coord_int = struct.unpack('!I', struct.pack('!f', coord))[0]
        return coord_int & 0b111
    
    def embed(self, obj_data: str, signature: str, artist_info: Dict) -> str:
        """Embed signature using LSB+1 method"""
        lines = obj_data.split('\n')
        vertex_lines = [i for i, line in enumerate(lines) if line.startswith('v ')]
        
        signature_bytes = bytes.fromhex(signature)
        required_vertices = int(np.ceil(len(signature_bytes) * 8 / self.bits_per_vertex))
        
        if len(vertex_lines) < required_vertices:
            raise ValueError(f"Need {required_vertices} vertices, have {len(vertex_lines)}")
        
        bit_stream = []
        for byte_val in signature_bytes:
            for i in range(8):
                bit_stream.append((byte_val >> (7 - i)) & 1)
        
        vertex_idx = 0
        for i in range(0, len(bit_stream), self.bits_per_vertex):
            if vertex_idx >= len(vertex_lines):
                break
            
            bits = 0
            for j in range(min(self.bits_per_vertex, len(bit_stream) - i)):
                bits = (bits << 1) | bit_stream[i + j]
            
            # Pad if needed
            if (i + self.bits_per_vertex) > len(bit_stream):
                bits = bits << (self.bits_per_vertex - (len(bit_stream) - i))
            
            line_idx = vertex_lines[vertex_idx]
            parts = lines[line_idx].split()
            if len(parts) >= 4:
                z_coord = float(parts[3])
                z_new = self.embed_bits_in_coordinate(z_coord, bits)
                parts[3] = repr(z_new)  # Full precision
                lines[line_idx] = ' '.join(parts)
            
            vertex_idx += 1
        
        # Add marker
        artist_info_b64 = base64.b64encode(json.dumps(artist_info).encode()).decode()
        original_hash = hashlib.sha256(obj_data.encode()).hexdigest()
        marker = f"# LSB+1 embedded - Hash:{original_hash} - Artist:{artist_info_b64} - Method:LSB+1"
        lines.insert(0 if not lines[0].startswith('#') else 1, marker)
        
        return '\n'.join(lines)
    
    def extract(self, obj_data: str) -> Tuple[Optional[str], Optional[str], Optional[Dict]]:
        """Extract signature using LSB+1 method"""
        lines = obj_data.split('\n')
        
        # Check for marker
        has_marker = False
        original_hash = None
        artist_info = None
        
        for i in range(min(5, len(lines))):
            if "LSB+1 embedded" in lines[i]:
                has_marker = True
                if "Hash:" in lines[i]:
                    parts = lines[i].split("Hash:", 1)[1]
                    original_hash = parts.split(" - ")[0].strip()
                if "Artist:" in lines[i]:
                    artist_part = lines[i].split("Artist:", 1)[1]
                    artist_b64 = artist_part.split(" - ")[0].strip()
                    try:
                        artist_info = json.loads(base64.b64decode(artist_b64).decode())
                    except:
                        pass
                break
        
        if not has_marker:
            return None, None, None
        
        vertex_lines = [i for i, line in enumerate(lines) if line.startswith('v ')]
        
        # Extract bits
        bit_stream = []
        for vertex_idx in range(min(len(vertex_lines), 687)):  # 256 bytes * 8 / 3
            line_idx = vertex_lines[vertex_idx]
            parts = lines[line_idx].split()
            if len(parts) >= 4:
                z_coord = float(parts[3])
                bits = self.extract_bits_from_coordinate(z_coord)
                for j in range(self.bits_per_vertex):
                    bit_stream.append((bits >> (self.bits_per_vertex - 1 - j)) & 1)
        
        # Reconstruct bytes
        signature_bytes = bytearray()
        for i in range(0, min(len(bit_stream), 2048), 8):  # 256 bytes = 2048 bits
            byte_val = 0
            for j in range(8):
                if i + j < len(bit_stream):
                    byte_val = (byte_val << 1) | bit_stream[i + j]
            signature_bytes.append(byte_val)
        
        return signature_bytes.hex(), original_hash, artist_info


class MLSB:
    """MLSB: Pseudo-random selection without geometry awareness"""
    
    def __init__(self):
        self.bits_per_vertex = 2
    
    def embed_bits_in_coordinate(self, coord: float, bits: int) -> float:
        """Embed 2 bits into coordinate"""
        coord_int = struct.unpack('!I', struct.pack('!f', coord))[0]
        coord_int = coord_int & ~0b11
        coord_int = coord_int | bits
        return struct.unpack('!f', struct.pack('!I', coord_int))[0]
    
    def extract_bits_from_coordinate(self, coord: float) -> int:
        """Extract 2 bits from coordinate"""
        coord_int = struct.unpack('!I', struct.pack('!f', coord))[0]
        return coord_int & 0b11
    
    def generate_vertex_selection(self, n_vertices: int, required_vertices: int, 
                                  seed: int) -> List[int]:
        """Generate pseudo-random vertex selection"""
        random.seed(seed)
        if required_vertices > n_vertices:
            raise ValueError(f"Need {required_vertices} vertices, have {n_vertices}")
        return random.sample(range(n_vertices), required_vertices)
    
    def embed(self, obj_data: str, signature: str, artist_public_key: str, 
              artist_info: Dict) -> str:
        """Embed signature using MLSB method"""
        lines = obj_data.split('\n')
        vertex_lines = [i for i, line in enumerate(lines) if line.startswith('v ')]
        
        signature_bytes = bytes.fromhex(signature)
        required_vertices = len(signature_bytes) * 4  # 2 bits per vertex, 8 bits per byte
        
        # Generate seed from artist key
        model_hash = hashlib.sha256(obj_data.encode()).hexdigest()
        seed = int(hashlib.sha256((artist_public_key + model_hash).encode()).hexdigest()[:16], 16)
        
        selected_indices = self.generate_vertex_selection(len(vertex_lines), required_vertices, seed)
        
        # Embed signature
        bit_index = 0
        for byte_val in signature_bytes:
            for bit_pair_idx in range(4):
                if bit_index // self.bits_per_vertex >= len(selected_indices):
                    break
                
                vertex_idx = selected_indices[bit_index // self.bits_per_vertex]
                line_idx = vertex_lines[vertex_idx]
                
                bit_pair = (byte_val >> (6 - bit_pair_idx * 2)) & 0b11
                
                parts = lines[line_idx].split()
                if len(parts) >= 4:
                    z_coord = float(parts[3])
                    z_new = self.embed_bits_in_coordinate(z_coord, bit_pair)
                    parts[3] = repr(z_new)  # Full precision
                    lines[line_idx] = ' '.join(parts)
                
                bit_index += self.bits_per_vertex
        
        # Add marker
        artist_info_b64 = base64.b64encode(json.dumps(artist_info).encode()).decode()
        original_hash = hashlib.sha256(obj_data.encode()).hexdigest()
        marker = f"# MLSB embedded - Hash:{original_hash} - Artist:{artist_info_b64} - Method:MLSB"
        lines.insert(0 if not lines[0].startswith('#') else 1, marker)
        
        return '\n'.join(lines)
    
    def extract(self, obj_data: str, artist_public_key: str) -> Tuple[Optional[str], Optional[str], Optional[Dict]]:
        """Extract signature using MLSB method"""
        lines = obj_data.split('\n')
        
        # Check for marker
        has_marker = False
        original_hash = None
        artist_info = None
        
        for i in range(min(5, len(lines))):
            if "MLSB embedded" in lines[i]:
                has_marker = True
                if "Hash:" in lines[i]:
                    parts = lines[i].split("Hash:", 1)[1]
                    original_hash = parts.split(" - ")[0].strip()
                if "Artist:" in lines[i]:
                    artist_part = lines[i].split("Artist:", 1)[1]
                    artist_b64 = artist_part.split(" - ")[0].strip()
                    try:
                        artist_info = json.loads(base64.b64decode(artist_b64).decode())
                    except:
                        pass
                break
        
        if not has_marker:
            return None, None, None
        
        vertex_lines = [i for i, line in enumerate(lines) if line.startswith('v ')]
        
        # Regenerate seed
        model_hash = original_hash if original_hash else hashlib.sha256(obj_data.encode()).hexdigest()
        seed = int(hashlib.sha256((artist_public_key + model_hash).encode()).hexdigest()[:16], 16)
        
        required_vertices = 256 * 4
        selected_indices = self.generate_vertex_selection(len(vertex_lines), required_vertices, seed)
        
        # Extract signature
        signature_bytes = bytearray()
        for i in range(256):
            byte_val = 0
            for j in range(4):
                vertex_idx = selected_indices[i * 4 + j]
                line_idx = vertex_lines[vertex_idx]
                
                parts = lines[line_idx].split()
                if len(parts) >= 4:
                    z_coord = float(parts[3])
                    bit_pair = self.extract_bits_from_coordinate(z_coord)
                    byte_val |= (bit_pair << (6 - j * 2))
            
            signature_bytes.append(byte_val)
        
        return signature_bytes.hex(), original_hash, artist_info


class MLSBPVD:
    """MLSB+PVD: Vertex value differencing with random selection"""
    
    def __init__(self):
        self.bits_per_vertex = 2  # Can be adaptive: 2-4 bits
    
    def calculate_pvd_capacity(self, diff: float) -> int:
        """Calculate embedding capacity based on vertex value difference"""
        abs_diff = abs(diff)
        if abs_diff < 0.01:
            return 2  # Low difference: 2 bits
        elif abs_diff < 0.1:
            return 3  # Medium difference: 3 bits
        else:
            return 4  # High difference: 4 bits
    
    def embed_bits_in_coordinate(self, coord: float, bits: int, num_bits: int) -> float:
        """Embed variable number of bits into coordinate"""
        coord_int = struct.unpack('!I', struct.pack('!f', coord))[0]
        mask = (1 << num_bits) - 1
        coord_int = coord_int & ~mask
        coord_int = coord_int | (bits & mask)
        return struct.unpack('!f', struct.pack('!I', coord_int))[0]
    
    def extract_bits_from_coordinate(self, coord: float, num_bits: int) -> int:
        """Extract variable number of bits from coordinate"""
        coord_int = struct.unpack('!I', struct.pack('!f', coord))[0]
        mask = (1 << num_bits) - 1
        return coord_int & mask
    
    def generate_vertex_selection(self, n_vertices: int, required_vertices: int, 
                                  seed: int) -> List[int]:
        """Generate pseudo-random vertex selection"""
        random.seed(seed)
        if required_vertices > n_vertices:
            raise ValueError(f"Need {required_vertices} vertices, have {n_vertices}")
        return random.sample(range(n_vertices), required_vertices)
    
    def embed(self, obj_data: str, signature: str, artist_public_key: str, 
              artist_info: Dict) -> str:
        """Embed signature using MLSB+PVD method"""
        lines = obj_data.split('\n')
        vertex_lines = [i for i, line in enumerate(lines) if line.startswith('v ')]
        
        signature_bytes = bytes.fromhex(signature)
        
        # Parse all vertices to calculate differences
        vertices = []
        for line_idx in vertex_lines:
            parts = lines[line_idx].split()
            if len(parts) >= 4:
                vertices.append(float(parts[3]))
        
        # Generate seed and selection
        model_hash = hashlib.sha256(obj_data.encode()).hexdigest()
        seed = int(hashlib.sha256((artist_public_key + model_hash).encode()).hexdigest()[:16], 16)
        
        # Estimate required vertices conservatively (assume minimum 2 bits per vertex)
        # This ensures we have enough vertices even if all have low capacity
        estimated_required = int(np.ceil(len(signature_bytes) * 8 / 2))  # Worst case: 2 bits/vertex
        selected_indices = self.generate_vertex_selection(len(vertex_lines), 
                                                          min(estimated_required, len(vertex_lines)), 
                                                          seed)
        
        # Convert signature to bit stream
        bit_stream = []
        for byte_val in signature_bytes:
            for i in range(8):
                bit_stream.append((byte_val >> (7 - i)) & 1)
        
        # Embed with adaptive capacity
        bit_pos = 0
        vertex_capacities = []  # Store capacities for extraction
        
        for vertex_idx in selected_indices:
            if bit_pos >= len(bit_stream):
                break
            
            line_idx = vertex_lines[vertex_idx]
            parts = lines[line_idx].split()
            
            if len(parts) >= 4:
                z_coord = float(parts[3])
                
                # Calculate capacity based on local differences
                if vertex_idx > 0:
                    diff = abs(vertices[vertex_idx] - vertices[vertex_idx - 1])
                else:
                    diff = 0.05  # Default medium capacity
                
                capacity = self.calculate_pvd_capacity(diff)
                vertex_capacities.append(capacity)
                
                # Extract bits to embed
                bits_to_embed = 0
                actual_bits = min(capacity, len(bit_stream) - bit_pos)
                for i in range(actual_bits):
                    bits_to_embed = (bits_to_embed << 1) | bit_stream[bit_pos]
                    bit_pos += 1
                
                # Shift to MSB position if we have fewer bits than capacity
                if actual_bits < capacity:
                    bits_to_embed = bits_to_embed << (capacity - actual_bits)
                
                # Embed - use repr() for full precision
                z_new = self.embed_bits_in_coordinate(z_coord, bits_to_embed, capacity)
                parts[3] = repr(z_new)
                lines[line_idx] = ' '.join(parts)
        
        # Verify all bits were embedded
        if bit_pos < len(bit_stream):
            raise ValueError(f"Failed to embed all signature bits. Embedded {bit_pos}/{len(bit_stream)} bits. Need more vertices or higher capacity.")
        
        # Store capacity map in marker at END (for extraction)
        capacity_map = ','.join(map(str, vertex_capacities))
        artist_info_b64 = base64.b64encode(json.dumps(artist_info).encode()).decode()
        original_hash = hashlib.sha256(obj_data.encode()).hexdigest()
        marker = f"# MLSB+PVD embedded - Hash:{original_hash} - Artist:{artist_info_b64} - Capacity:{capacity_map} - Method:MLSB+PVD"
        lines.append(marker)
        
        return '\n'.join(lines)
    
    def extract(self, obj_data: str, artist_public_key: str) -> Tuple[Optional[str], Optional[str], Optional[Dict]]:
        """Extract signature using MLSB+PVD method"""
        lines = obj_data.split('\n')
        
        # Check for marker at END and extract capacity map
        has_marker = False
        original_hash = None
        artist_info = None
        capacity_map = []
        
        # Check last few lines for marker
        for i in range(max(0, len(lines) - 5), len(lines)):
            if "MLSB+PVD embedded" in lines[i]:
                has_marker = True
                if "Hash:" in lines[i]:
                    parts = lines[i].split("Hash:", 1)[1]
                    original_hash = parts.split(" - ")[0].strip()
                if "Artist:" in lines[i]:
                    artist_part = lines[i].split("Artist:", 1)[1]
                    artist_b64 = artist_part.split(" - ")[0].strip()
                    try:
                        artist_info = json.loads(base64.b64decode(artist_b64).decode())
                    except:
                        pass
                if "Capacity:" in lines[i]:
                    cap_part = lines[i].split("Capacity:", 1)[1]
                    cap_str = cap_part.split(" - ")[0].strip()
                    capacity_map = [int(x) for x in cap_str.split(',') if x]
                break
        
        if not has_marker:
            return None, None, None
        
        vertex_lines = [i for i, line in enumerate(lines) if line.startswith('v ')]
        
        # Regenerate seed
        model_hash = original_hash if original_hash else hashlib.sha256(obj_data.encode()).hexdigest()
        seed = int(hashlib.sha256((artist_public_key + model_hash).encode()).hexdigest()[:16], 16)
        
        selected_indices = self.generate_vertex_selection(len(vertex_lines), len(capacity_map), seed)
        
        # Extract bits - only extract exactly 2048 bits (256 bytes signature)
        bit_stream = []
        bits_needed = 2048  # RSA-2048 signature = 256 bytes = 2048 bits
        
        for i, vertex_idx in enumerate(selected_indices):
            if i >= len(capacity_map) or len(bit_stream) >= bits_needed:
                break
            
            line_idx = vertex_lines[vertex_idx]
            parts = lines[line_idx].split()
            
            if len(parts) >= 4:
                z_coord = float(parts[3])
                capacity = capacity_map[i]
                bits = self.extract_bits_from_coordinate(z_coord, capacity)
                
                # Only extract as many bits as we still need
                bits_to_extract = min(capacity, bits_needed - len(bit_stream))
                for j in range(bits_to_extract):
                    bit_stream.append((bits >> (capacity - 1 - j)) & 1)
        
        # Verify we extracted exactly the right amount
        # Debug: print(f"DEBUG: bit_stream length = {len(bit_stream)} bits, need 2048 bits")
        
        # Reconstruct signature - need exactly 2048 bits (256 bytes)
        signature_bytes = bytearray()
        for i in range(0, min(len(bit_stream), 2048), 8):
            byte_val = 0
            for j in range(8):
                if i + j < len(bit_stream):
                    byte_val = (byte_val << 1) | bit_stream[i + j]
                else:
                    byte_val = byte_val << 1  # Pad with 0 if needed
            signature_bytes.append(byte_val)
            if len(signature_bytes) >= 256:
                break
        
        return signature_bytes.hex(), original_hash, artist_info


class CurvatureLSB:
    """Curvature-based LSB: Uses local curvature estimation to weight vertex selection"""
    
    def __init__(self):
        self.bits_per_vertex = 2
    
    def _estimate_curvature(self, vertices: List[List[float]], idx: int, k: int = 5) -> float:
        """Estimate local curvature using variance of neighboring vertices"""
        if len(vertices) < k:
            return 0.0
        v = np.array(vertices[idx])
        start = max(0, idx - k)
        end = min(len(vertices), idx + k + 1)
        neighbors = [vertices[i] for i in range(start, end) if i != idx]
        if not neighbors:
            return 0.0
        neighbors = np.array(neighbors)
        diffs = neighbors - v
        return float(np.var(diffs))
    
    def _float_to_int(self, coord: float) -> int:
        return struct.unpack('!I', struct.pack('!f', coord))[0]
    
    def _int_to_float(self, coord_int: int) -> float:
        return struct.unpack('!f', struct.pack('!I', coord_int))[0]
    
    def embed(self, obj_data: str, signature: str, artist_info: Dict) -> str:
        """Embed using curvature-weighted vertex selection"""
        lines = obj_data.split('\n')
        vertices = []
        vertex_lines = []
        for i, line in enumerate(lines):
            if line.startswith('v '):
                parts = line.split()
                if len(parts) >= 4:
                    vertices.append([float(parts[1]), float(parts[2]), float(parts[3])])
                    vertex_lines.append(i)
        
        curvatures = [(i, self._estimate_curvature(vertices, i), vertex_lines[i]) for i in range(len(vertices))]
        curvatures.sort(key=lambda x: x[1])
        
        signature_bytes = bytes.fromhex(signature)
        required = len(signature_bytes) * 8 // self.bits_per_vertex
        if len(curvatures) < required:
            raise ValueError(f"Need {required} vertices, have {len(curvatures)}")
        
        selected = curvatures[:required]
        bit_stream = []
        for byte_val in signature_bytes:
            for i in range(8):
                bit_stream.append((byte_val >> (7 - i)) & 1)
        
        selected_indices = []
        for i, (v_idx, curv, line_idx) in enumerate(selected):
            if i * 2 >= len(bit_stream):
                break
            bits = 0
            for j in range(2):
                if i * 2 + j < len(bit_stream):
                    bits = (bits << 1) | bit_stream[i * 2 + j]
                else:
                    bits = bits << 1
            
            parts = lines[line_idx].split()
            z = float(parts[3])
            z_int = self._float_to_int(z)
            z_int = (z_int & ~0b11) | (bits & 0b11)
            z_new = self._int_to_float(z_int)
            parts[3] = repr(z_new)
            lines[line_idx] = ' '.join(parts)
            selected_indices.append(v_idx)
        
        import zlib
        indices_bytes = ','.join(str(i) for i in selected_indices).encode()
        compressed = base64.b64encode(zlib.compress(indices_bytes)).decode()
        artist_b64 = base64.b64encode(json.dumps(artist_info).encode()).decode()
        orig_hash = hashlib.sha256(obj_data.encode()).hexdigest()
        marker = f"# Curvature-LSB embedded - Hash:{orig_hash} - Artist:{artist_b64} - Indices:{compressed}"
        lines.append(marker)
        return '\n'.join(lines)
    
    def extract(self, obj_data: str) -> Tuple[Optional[str], Optional[str], Optional[Dict]]:
        """Extract signature"""
        lines = obj_data.split('\n')
        has_marker = False
        orig_hash = None
        artist_info = None
        stored_indices = None
        
        for i in range(max(0, len(lines) - 10), len(lines)):
            if "Curvature-LSB embedded" in lines[i]:
                has_marker = True
                if "Hash:" in lines[i]:
                    orig_hash = lines[i].split("Hash:", 1)[1].split(" - ")[0].strip()
                if "Artist:" in lines[i]:
                    artist_b64 = lines[i].split("Artist:", 1)[1].split(" - ")[0].strip()
                    try:
                        artist_info = json.loads(base64.b64decode(artist_b64).decode())
                    except:
                        pass
                if "Indices:" in lines[i]:
                    idx_compressed = lines[i].split("Indices:", 1)[1].split(" - ")[0].strip()
                    try:
                        import zlib
                        idx_bytes = zlib.decompress(base64.b64decode(idx_compressed))
                        stored_indices = [int(x) for x in idx_bytes.decode().split(',')]
                    except:
                        pass
                break
        
        if not has_marker or not stored_indices:
            return None, None, None
        
        vertex_lines = [i for i, line in enumerate(lines) if line.startswith('v ')]
        bit_stream = []
        for v_idx in stored_indices:
            if v_idx >= len(vertex_lines):
                break
            line_idx = vertex_lines[v_idx]
            parts = lines[line_idx].split()
            if len(parts) >= 4:
                z = float(parts[3])
                z_int = self._float_to_int(z)
                bits = z_int & 0b11
                bit_stream.append((bits >> 1) & 1)
                bit_stream.append(bits & 1)
        
        sig_bytes = bytearray()
        for i in range(0, min(len(bit_stream), 2048), 8):
            if len(sig_bytes) >= 256:
                break
            byte_val = 0
            for j in range(8):
                if i + j < len(bit_stream):
                    byte_val = (byte_val << 1) | bit_stream[i + j]
            sig_bytes.append(byte_val)
        return sig_bytes.hex(), orig_hash, artist_info
