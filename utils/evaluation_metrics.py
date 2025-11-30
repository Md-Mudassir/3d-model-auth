"""
Evaluation Metrics for 3D Model Steganography
Implements metrics from the research paper
"""

import numpy as np
import time
import scipy.stats as stats
from typing import Tuple, Dict, List
import hashlib


class ImperceptibilityMetrics:
    """Metrics for measuring visual imperceptibility"""
    
    @staticmethod
    def compute_rmse(original_vertices: np.ndarray, modified_vertices: np.ndarray) -> float:
        """
        Root Mean Square Error for geometric distortion
        
        Args:
            original_vertices: (N, 3) array of original vertex positions
            modified_vertices: (N, 3) array of modified vertex positions
            
        Returns:
            RMSE value
        """
        if len(original_vertices) != len(modified_vertices):
            raise ValueError("Vertex counts must match")
        
        squared_diff = np.sum((modified_vertices - original_vertices) ** 2, axis=1)
        rmse = np.sqrt(np.mean(squared_diff))
        return rmse
    
    @staticmethod
    def compute_hausdorff_distance(original_vertices: np.ndarray, 
                                   modified_vertices: np.ndarray) -> float:
        """
        Hausdorff Distance - maximum deviation between surfaces
        
        Args:
            original_vertices: (N, 3) array
            modified_vertices: (N, 3) array
            
        Returns:
            Hausdorff distance
        """
        # Forward direction: max(min distance from each original vertex to modified)
        distances_forward = []
        for orig_v in original_vertices:
            min_dist = np.min(np.linalg.norm(modified_vertices - orig_v, axis=1))
            distances_forward.append(min_dist)
        
        # Backward direction: max(min distance from each modified vertex to original)
        distances_backward = []
        for mod_v in modified_vertices:
            min_dist = np.min(np.linalg.norm(original_vertices - mod_v, axis=1))
            distances_backward.append(min_dist)
        
        hausdorff = max(max(distances_forward), max(distances_backward))
        return hausdorff
    
    @staticmethod
    def compute_normal_deviation(original_normals: np.ndarray, 
                                modified_normals: np.ndarray) -> float:
        """
        Average angle deviation between surface normals (in degrees)
        
        Args:
            original_normals: (N, 3) array of normalized normals
            modified_normals: (N, 3) array of normalized normals
            
        Returns:
            Average angle deviation in degrees
        """
        # Compute dot products (cosine of angles)
        dot_products = np.sum(original_normals * modified_normals, axis=1)
        
        # Clip to valid range for arccos
        dot_products = np.clip(dot_products, -1.0, 1.0)
        
        # Compute angles in radians, then convert to degrees
        angles_rad = np.arccos(dot_products)
        angles_deg = np.degrees(angles_rad)
        
        return np.mean(angles_deg)
    
    @staticmethod
    def compute_max_vertex_displacement(original_vertices: np.ndarray, 
                                       modified_vertices: np.ndarray) -> float:
        """
        Maximum displacement of any single vertex
        
        Args:
            original_vertices: (N, 3) array
            modified_vertices: (N, 3) array
            
        Returns:
            Maximum displacement
        """
        displacements = np.linalg.norm(modified_vertices - original_vertices, axis=1)
        return np.max(displacements)


class SecurityMetrics:
    """Metrics for measuring security and steganalysis resistance"""
    
    @staticmethod
    def chi_square_test(embedded_bits: List[int]) -> Tuple[float, float]:
        """
        Chi-Square test for LSB bit distribution uniformity
        
        Args:
            embedded_bits: List of extracted LSB values
            
        Returns:
            (chi_square_statistic, p_value)
            p_value > 0.05 indicates undetectable
        """
        if len(embedded_bits) == 0:
            return 0.0, 1.0
        
        # Count frequencies of each bit value
        unique, counts = np.unique(embedded_bits, return_counts=True)
        
        # Expected frequency (uniform distribution)
        n = len(embedded_bits)
        expected = n / len(unique)
        
        # Chi-square statistic
        chi_square = np.sum((counts - expected) ** 2 / expected)
        
        # Degrees of freedom
        df = len(unique) - 1
        
        # p-value
        p_value = 1 - stats.chi2.cdf(chi_square, df) if df > 0 else 1.0
        
        return chi_square, p_value
    
    @staticmethod
    def compute_entropy(data: List[int]) -> float:
        """
        Shannon entropy of embedded data
        
        Args:
            data: List of embedded values
            
        Returns:
            Entropy value (higher = more random)
        """
        if len(data) == 0:
            return 0.0
        
        unique, counts = np.unique(data, return_counts=True)
        probabilities = counts / len(data)
        
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
        return entropy
    
    @staticmethod
    def rs_analysis(vertices: np.ndarray, modified_vertices: np.ndarray) -> Dict[str, float]:
        """
        Simplified RS (Regular/Singular) Analysis
        
        Returns statistics about embedding detectability
        """
        # Extract LSBs from z-coordinates
        import struct
        
        def get_lsb_pattern(coord):
            coord_int = struct.unpack('!I', struct.pack('!f', coord))[0]
            return coord_int & 0b11
        
        original_lsbs = [get_lsb_pattern(v[2]) for v in vertices]
        modified_lsbs = [get_lsb_pattern(v[2]) for v in modified_vertices]
        
        # Count transitions
        original_transitions = sum(1 for i in range(len(original_lsbs)-1) 
                                  if original_lsbs[i] != original_lsbs[i+1])
        modified_transitions = sum(1 for i in range(len(modified_lsbs)-1) 
                                  if modified_lsbs[i] != modified_lsbs[i+1])
        
        # Detection rate (higher transitions = more detectable)
        total_possible = len(original_lsbs) - 1
        original_rate = original_transitions / total_possible if total_possible > 0 else 0
        modified_rate = modified_transitions / total_possible if total_possible > 0 else 0
        
        detection_rate = abs(modified_rate - original_rate) * 100
        
        return {
            'original_transition_rate': original_rate,
            'modified_transition_rate': modified_rate,
            'detection_rate': detection_rate
        }


class CapacityMetrics:
    """Metrics for measuring embedding capacity"""
    
    @staticmethod
    def compute_capacity(num_vertices: int, bits_per_vertex: int) -> Dict[str, float]:
        """
        Compute embedding capacity metrics
        
        Args:
            num_vertices: Number of vertices in model
            bits_per_vertex: Bits embedded per vertex
            
        Returns:
            Dictionary of capacity metrics
        """
        total_bits = num_vertices * bits_per_vertex
        total_bytes = total_bits / 8
        
        # For RSA-2048 signature (256 bytes)
        signature_size = 256
        required_vertices = int(np.ceil(signature_size * 8 / bits_per_vertex))
        
        return {
            'total_capacity_bytes': total_bytes,
            'bits_per_vertex': bits_per_vertex,
            'required_vertices_for_signature': required_vertices,
            'utilization_rate': (required_vertices / num_vertices) * 100 if num_vertices > 0 else 0,
            'efficiency_ratio': bits_per_vertex / 3.0  # Normalized to max 3 bits
        }


class PerformanceMetrics:
    """Metrics for measuring computational performance"""
    
    @staticmethod
    def measure_embedding_time(embed_func, *args, **kwargs) -> Tuple[float, any]:
        """
        Measure time taken for embedding
        
        Returns:
            (time_seconds, result)
        """
        start_time = time.time()
        result = embed_func(*args, **kwargs)
        end_time = time.time()
        
        return end_time - start_time, result
    
    @staticmethod
    def measure_extraction_time(extract_func, *args, **kwargs) -> Tuple[float, any]:
        """
        Measure time taken for extraction
        
        Returns:
            (time_seconds, result)
        """
        start_time = time.time()
        result = extract_func(*args, **kwargs)
        end_time = time.time()
        
        return end_time - start_time, result


class ComprehensiveEvaluator:
    """Complete evaluation framework for comparing steganography methods"""
    
    def __init__(self):
        self.imperceptibility = ImperceptibilityMetrics()
        self.security = SecurityMetrics()
        self.capacity = CapacityMetrics()
        self.performance = PerformanceMetrics()
    
    def parse_obj_vertices(self, obj_data: str) -> np.ndarray:
        """Extract vertices from OBJ file"""
        lines = obj_data.split('\n')
        vertices = []
        
        for line in lines:
            if line.startswith('v '):
                parts = line.split()
                if len(parts) >= 4:
                    vertices.append([float(parts[1]), float(parts[2]), float(parts[3])])
        
        return np.array(vertices)
    
    def parse_obj_faces(self, obj_data: str) -> np.ndarray:
        """Extract faces from OBJ file"""
        lines = obj_data.split('\n')
        faces = []
        
        for line in lines:
            if line.startswith('f '):
                parts = line.split()[1:]
                face = []
                for p in parts:
                    vertex_idx = int(p.split('/')[0]) - 1
                    face.append(vertex_idx)
                if len(face) >= 3:
                    faces.append(face[:3])
        
        return np.array(faces)
    
    def compute_vertex_normals(self, vertices: np.ndarray, faces: np.ndarray) -> np.ndarray:
        """Compute vertex normals from faces"""
        normals = np.zeros_like(vertices)
        
        if len(faces) == 0:
            return normals
        
        for face in faces:
            if len(face) >= 3:
                v0, v1, v2 = vertices[face[0]], vertices[face[1]], vertices[face[2]]
                edge1 = v1 - v0
                edge2 = v2 - v0
                face_normal = np.cross(edge1, edge2)
                
                normals[face[0]] += face_normal
                normals[face[1]] += face_normal
                normals[face[2]] += face_normal
        
        # Normalize
        norms = np.linalg.norm(normals, axis=1, keepdims=True)
        norms[norms == 0] = 1
        normals = normals / norms
        
        return normals
    
    def evaluate_method(self, original_obj: str, signed_obj: str, 
                       method_name: str, embedding_time: float = 0.0,
                       extraction_time: float = 0.0) -> Dict:
        """
        Comprehensive evaluation of a single method
        
        Args:
            original_obj: Original OBJ file content
            signed_obj: Signed OBJ file content
            method_name: Name of the method
            embedding_time: Time taken for embedding
            extraction_time: Time taken for extraction
            
        Returns:
            Dictionary of all metrics
        """
        # Parse vertices
        orig_vertices = self.parse_obj_vertices(original_obj)
        mod_vertices = self.parse_obj_vertices(signed_obj)
        
        # Parse faces
        orig_faces = self.parse_obj_faces(original_obj)
        mod_faces = self.parse_obj_faces(signed_obj)
        
        results = {
            'method': method_name,
            'num_vertices': len(orig_vertices),
            'num_faces': len(orig_faces)
        }
        
        # Imperceptibility metrics
        try:
            results['rmse'] = self.imperceptibility.compute_rmse(orig_vertices, mod_vertices)
            results['max_displacement'] = self.imperceptibility.compute_max_vertex_displacement(
                orig_vertices, mod_vertices)
            
            # Compute normals if faces exist
            if len(orig_faces) > 0 and len(mod_faces) > 0:
                orig_normals = self.compute_vertex_normals(orig_vertices, orig_faces)
                mod_normals = self.compute_vertex_normals(mod_vertices, mod_faces)
                results['normal_deviation_deg'] = self.imperceptibility.compute_normal_deviation(
                    orig_normals, mod_normals)
            else:
                results['normal_deviation_deg'] = 0.0
            
            # Hausdorff distance (expensive, sample for large models)
            if len(orig_vertices) > 1000:
                sample_size = 1000
                sample_indices = np.random.choice(len(orig_vertices), sample_size, replace=False)
                results['hausdorff_distance'] = self.imperceptibility.compute_hausdorff_distance(
                    orig_vertices[sample_indices], mod_vertices[sample_indices])
            else:
                results['hausdorff_distance'] = self.imperceptibility.compute_hausdorff_distance(
                    orig_vertices, mod_vertices)
        except Exception as e:
            results['imperceptibility_error'] = str(e)
            results['rmse'] = None
            results['hausdorff_distance'] = None
            results['normal_deviation_deg'] = None
            results['max_displacement'] = None
        
        # Security metrics
        try:
            import struct
            
            # Extract LSB patterns
            modified_lsbs = []
            for v in mod_vertices:
                coord_int = struct.unpack('!I', struct.pack('!f', v[2]))[0]
                modified_lsbs.append(coord_int & 0b11)
            
            chi_stat, p_value = self.security.chi_square_test(modified_lsbs)
            results['chi_square_statistic'] = chi_stat
            results['chi_square_p_value'] = p_value
            results['undetectable'] = p_value > 0.05
            
            results['entropy'] = self.security.compute_entropy(modified_lsbs)
            
            rs_results = self.security.rs_analysis(orig_vertices, mod_vertices)
            results['rs_detection_rate'] = rs_results['detection_rate']
        except Exception as e:
            results['security_error'] = str(e)
            results['chi_square_p_value'] = None
            results['entropy'] = None
            results['rs_detection_rate'] = None
        
        # Capacity metrics
        bits_per_vertex = 2  # Default, can be adjusted per method
        if 'LSB+1' in method_name:
            bits_per_vertex = 3
        elif 'PVD' in method_name:
            bits_per_vertex = 3  # Average
        
        capacity_metrics = self.capacity.compute_capacity(len(orig_vertices), bits_per_vertex)
        results.update(capacity_metrics)
        
        # Performance metrics
        results['embedding_time_sec'] = embedding_time
        results['extraction_time_sec'] = extraction_time
        results['total_time_sec'] = embedding_time + extraction_time
        
        return results
    
    def compare_methods(self, results_list: List[Dict]) -> Dict:
        """
        Generate comparative analysis across methods
        
        Args:
            results_list: List of evaluation results from different methods
            
        Returns:
            Comparative statistics and rankings
        """
        if not results_list:
            return {}
        
        comparison = {
            'num_methods': len(results_list),
            'methods': [r['method'] for r in results_list]
        }
        
        # Imperceptibility comparison
        rmse_values = [r.get('rmse', float('inf')) for r in results_list]
        if any(v != float('inf') for v in rmse_values):
            best_rmse_idx = np.argmin(rmse_values)
            comparison['best_imperceptibility'] = results_list[best_rmse_idx]['method']
            comparison['rmse_values'] = rmse_values
            comparison['rmse_improvement'] = (
                (max(rmse_values) - min(rmse_values)) / max(rmse_values) * 100
                if max(rmse_values) > 0 else 0
            )
        
        # Security comparison
        p_values = [r.get('chi_square_p_value', 0) for r in results_list]
        if any(v is not None for v in p_values):
            best_security_idx = np.argmax([v if v is not None else 0 for v in p_values])
            comparison['best_security'] = results_list[best_security_idx]['method']
            comparison['p_values'] = p_values
        
        # Performance comparison
        times = [r.get('total_time_sec', float('inf')) for r in results_list]
        if any(v != float('inf') for v in times):
            fastest_idx = np.argmin(times)
            comparison['fastest_method'] = results_list[fastest_idx]['method']
            comparison['times'] = times
        
        return comparison
