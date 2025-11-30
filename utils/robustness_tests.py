"""
Robustness Testing for 3D Model Steganography
Tests resilience against various attacks and transformations
"""

import numpy as np
import random
from typing import Tuple, Dict


class RobustnessTests:
    """Test robustness of steganography methods against various attacks"""
    
    @staticmethod
    def add_gaussian_noise(obj_data: str, noise_level: float = 0.0001) -> str:
        """
        Add Gaussian noise to vertex coordinates
        
        Args:
            obj_data: OBJ file content
            noise_level: Standard deviation of noise (default: 0.0001)
            
        Returns:
            Modified OBJ data with noise
        """
        lines = obj_data.split('\n')
        modified_lines = []
        
        for line in lines:
            if line.startswith('v '):
                parts = line.split()
                if len(parts) >= 4:
                    # Add noise to x, y, z coordinates
                    x = float(parts[1]) + np.random.normal(0, noise_level)
                    y = float(parts[2]) + np.random.normal(0, noise_level)
                    z = float(parts[3]) + np.random.normal(0, noise_level)
                    line = f"v {x:.8f} {y:.8f} {z:.8f}"
            modified_lines.append(line)
        
        return '\n'.join(modified_lines)
    
    @staticmethod
    def quantize_coordinates(obj_data: str, precision: int = 6) -> str:
        """
        Reduce coordinate precision (simulates lossy compression)
        
        Args:
            obj_data: OBJ file content
            precision: Number of decimal places to keep
            
        Returns:
            Modified OBJ data with reduced precision
        """
        lines = obj_data.split('\n')
        modified_lines = []
        
        for line in lines:
            if line.startswith('v '):
                parts = line.split()
                if len(parts) >= 4:
                    x = round(float(parts[1]), precision)
                    y = round(float(parts[2]), precision)
                    z = round(float(parts[3]), precision)
                    line = f"v {x:.{precision}f} {y:.{precision}f} {z:.{precision}f}"
            modified_lines.append(line)
        
        return '\n'.join(modified_lines)
    
    @staticmethod
    def apply_scaling(obj_data: str, scale_factor: float = 1.01) -> str:
        """
        Apply uniform scaling transformation
        
        Args:
            obj_data: OBJ file content
            scale_factor: Scaling factor (1.0 = no change)
            
        Returns:
            Scaled OBJ data
        """
        lines = obj_data.split('\n')
        modified_lines = []
        
        for line in lines:
            if line.startswith('v '):
                parts = line.split()
                if len(parts) >= 4:
                    x = float(parts[1]) * scale_factor
                    y = float(parts[2]) * scale_factor
                    z = float(parts[3]) * scale_factor
                    line = f"v {x:.8f} {y:.8f} {z:.8f}"
            modified_lines.append(line)
        
        return '\n'.join(modified_lines)
    
    @staticmethod
    def apply_rotation(obj_data: str, angle_deg: float = 5.0) -> str:
        """
        Apply rotation around Z-axis
        
        Args:
            obj_data: OBJ file content
            angle_deg: Rotation angle in degrees
            
        Returns:
            Rotated OBJ data
        """
        lines = obj_data.split('\n')
        modified_lines = []
        
        angle_rad = np.radians(angle_deg)
        cos_a = np.cos(angle_rad)
        sin_a = np.sin(angle_rad)
        
        for line in lines:
            if line.startswith('v '):
                parts = line.split()
                if len(parts) >= 4:
                    x = float(parts[1])
                    y = float(parts[2])
                    z = float(parts[3])
                    
                    # Rotate around Z-axis
                    x_new = x * cos_a - y * sin_a
                    y_new = x * sin_a + y * cos_a
                    
                    line = f"v {x_new:.8f} {y_new:.8f} {z:.8f}"
            modified_lines.append(line)
        
        return '\n'.join(modified_lines)
    
    @staticmethod
    def vertex_reordering(obj_data: str, shuffle_percentage: float = 0.05) -> str:
        """
        Randomly reorder a percentage of vertices (attacks vertex order dependency)
        
        Args:
            obj_data: OBJ file content
            shuffle_percentage: Percentage of vertices to shuffle (0-1)
            
        Returns:
            OBJ data with reordered vertices
        """
        lines = obj_data.split('\n')
        vertex_lines = []
        other_lines = []
        
        # Separate vertices from other content
        for i, line in enumerate(lines):
            if line.startswith('v '):
                vertex_lines.append((i, line))
            else:
                other_lines.append((i, line))
        
        # Shuffle a percentage of vertices
        num_to_shuffle = int(len(vertex_lines) * shuffle_percentage)
        if num_to_shuffle > 1:
            indices_to_shuffle = random.sample(range(len(vertex_lines)), num_to_shuffle)
            shuffled_values = [vertex_lines[i][1] for i in indices_to_shuffle]
            random.shuffle(shuffled_values)
            
            for idx, new_val in zip(indices_to_shuffle, shuffled_values):
                vertex_lines[idx] = (vertex_lines[idx][0], new_val)
        
        # Reconstruct
        all_lines = vertex_lines + other_lines
        all_lines.sort(key=lambda x: x[0])
        
        return '\n'.join([line for _, line in all_lines])
    
    @staticmethod
    def test_all_attacks(obj_data: str) -> Dict[str, str]:
        """
        Apply all attack types and return dictionary of attacked versions
        
        Returns:
            Dictionary mapping attack name to attacked OBJ data
        """
        attacks = {
            'gaussian_noise_weak': RobustnessTests.add_gaussian_noise(obj_data, 0.00001),
            'gaussian_noise_medium': RobustnessTests.add_gaussian_noise(obj_data, 0.0001),
            'gaussian_noise_strong': RobustnessTests.add_gaussian_noise(obj_data, 0.001),
            'quantization_7': RobustnessTests.quantize_coordinates(obj_data, 7),
            'quantization_6': RobustnessTests.quantize_coordinates(obj_data, 6),
            'quantization_5': RobustnessTests.quantize_coordinates(obj_data, 5),
            'scaling_101': RobustnessTests.apply_scaling(obj_data, 1.01),
            'scaling_105': RobustnessTests.apply_scaling(obj_data, 1.05),
            'rotation_5deg': RobustnessTests.apply_rotation(obj_data, 5.0),
            'rotation_15deg': RobustnessTests.apply_rotation(obj_data, 15.0),
        }
        
        return attacks
    
    @staticmethod
    def calculate_ber(original_sig: str, extracted_sig: str) -> float:
        """
        Calculate Bit Error Rate between two signatures
        
        Args:
            original_sig: Original signature hex string
            extracted_sig: Extracted signature hex string (or None)
            
        Returns:
            BER (0-1), where 0 = perfect, 1 = completely wrong
        """
        if extracted_sig is None or len(extracted_sig) != len(original_sig):
            return 1.0  # Complete failure
        
        try:
            orig_bytes = bytes.fromhex(original_sig)
            extr_bytes = bytes.fromhex(extracted_sig)
            
            total_bits = len(orig_bytes) * 8
            error_bits = 0
            
            for o, e in zip(orig_bytes, extr_bytes):
                xor_result = o ^ e
                error_bits += bin(xor_result).count('1')
            
            return error_bits / total_bits
        except:
            return 1.0
