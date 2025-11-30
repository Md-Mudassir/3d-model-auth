"""
Advanced Evaluation Metrics for 3D Model Steganography
Includes perceptual quality, statistical analysis, and capacity analysis
"""

import numpy as np
from typing import Dict, List, Tuple
from scipy import stats


class AdvancedMetrics:
    """Advanced metrics for comprehensive steganography evaluation"""
    
    @staticmethod
    def compute_snr(original_vertices: np.ndarray, modified_vertices: np.ndarray) -> float:
        """
        Signal-to-Noise Ratio (higher is better)
        
        Args:
            original_vertices: (N, 3) array
            modified_vertices: (N, 3) array
            
        Returns:
            SNR in dB
        """
        signal_power = np.mean(original_vertices ** 2)
        noise = modified_vertices - original_vertices
        noise_power = np.mean(noise ** 2)
        
        if noise_power < 1e-10:
            return 100.0  # Very high SNR
        
        snr = 10 * np.log10(signal_power / noise_power)
        return snr
    
    @staticmethod
    def compute_psnr(original_vertices: np.ndarray, modified_vertices: np.ndarray) -> float:
        """
        Peak Signal-to-Noise Ratio
        
        Args:
            original_vertices: (N, 3) array
            modified_vertices: (N, 3) array
            
        Returns:
            PSNR in dB
        """
        max_val = np.max(np.abs(original_vertices))
        mse = np.mean((modified_vertices - original_vertices) ** 2)
        
        if mse < 1e-10:
            return 100.0
        
        psnr = 20 * np.log10(max_val / np.sqrt(mse))
        return psnr
    
    @staticmethod
    def compute_laplacian_distortion(vertices: np.ndarray, faces: np.ndarray,
                                     original_vertices: np.ndarray) -> float:
        """
        Measure smoothness preservation using Laplacian operator
        
        Args:
            vertices: Modified vertices (N, 3)
            faces: Face indices (M, 3)
            original_vertices: Original vertices (N, 3)
            
        Returns:
            Laplacian distortion metric
        """
        if len(faces) == 0:
            return 0.0
        
        def compute_laplacian(verts, faces):
            """Compute discrete Laplacian"""
            n = len(verts)
            laplacian = np.zeros_like(verts)
            degree = np.zeros(n)
            
            for face in faces:
                for i in range(3):
                    v1, v2 = face[i], face[(i + 1) % 3]
                    laplacian[v1] += verts[v2] - verts[v1]
                    degree[v1] += 1
            
            # Normalize
            for i in range(n):
                if degree[i] > 0:
                    laplacian[i] /= degree[i]
            
            return laplacian
        
        lap_orig = compute_laplacian(original_vertices, faces)
        lap_mod = compute_laplacian(vertices, faces)
        
        distortion = np.mean(np.linalg.norm(lap_mod - lap_orig, axis=1))
        return distortion
    
    @staticmethod
    def compute_correlation_coefficient(original_coords: np.ndarray, 
                                       modified_coords: np.ndarray) -> float:
        """
        Pearson correlation between original and modified coordinates
        
        Returns:
            Correlation coefficient (closer to 1.0 is better)
        """
        orig_flat = original_coords.flatten()
        mod_flat = modified_coords.flatten()
        
        correlation, _ = stats.pearsonr(orig_flat, mod_flat)
        return correlation
    
    @staticmethod
    def compute_embedding_efficiency(signature_bits: int, vertices_used: int,
                                    total_vertices: int) -> Dict[str, float]:
        """
        Analyze embedding capacity and efficiency
        
        Returns:
            Dictionary with efficiency metrics
        """
        return {
            'utilization_rate': vertices_used / total_vertices,
            'bits_per_vertex': signature_bits / vertices_used if vertices_used > 0 else 0,
            'capacity_percentage': (signature_bits / (total_vertices * 24)) * 100,  # 24 bits per coord (8-bit LSB)
            'embedding_density': signature_bits / total_vertices
        }
    
    @staticmethod
    def statistical_significance_test(results_method_a: List[float],
                                     results_method_b: List[float]) -> Dict[str, float]:
        """
        Perform statistical tests to determine if methods are significantly different
        
        Args:
            results_method_a: List of metric values for method A
            results_method_b: List of metric values for method B
            
        Returns:
            Dictionary with test statistics
        """
        # Paired t-test
        t_stat, t_pvalue = stats.ttest_rel(results_method_a, results_method_b)
        
        # Wilcoxon signed-rank test (non-parametric alternative)
        w_stat, w_pvalue = stats.wilcoxon(results_method_a, results_method_b)
        
        # Effect size (Cohen's d)
        mean_diff = np.mean(results_method_a) - np.mean(results_method_b)
        pooled_std = np.sqrt((np.var(results_method_a) + np.var(results_method_b)) / 2)
        cohens_d = mean_diff / pooled_std if pooled_std > 0 else 0
        
        return {
            't_statistic': t_stat,
            't_pvalue': t_pvalue,
            'wilcoxon_statistic': w_stat,
            'wilcoxon_pvalue': w_pvalue,
            'cohens_d': cohens_d,
            'significant_at_0.05': t_pvalue < 0.05
        }
    
    @staticmethod
    def analyze_bit_distribution(signature_bytes: bytes, embedded_coords: np.ndarray) -> Dict:
        """
        Analyze distribution of embedded bits
        
        Returns:
            Statistics about bit patterns
        """
        # Convert signature to bits
        bits = []
        for byte in signature_bytes:
            bits.extend([int(b) for b in format(byte, '08b')])
        
        bits = np.array(bits)
        
        return {
            'bit_entropy': stats.entropy([np.sum(bits == 0), np.sum(bits == 1)], base=2),
            'ones_ratio': np.mean(bits),
            'zeros_ratio': 1 - np.mean(bits),
            'runs_test_pvalue': stats.runs_test(bits).pvalue if len(bits) > 10 else 1.0
        }
    
    @staticmethod
    def compute_geometric_quality_index(original_vertices: np.ndarray,
                                       modified_vertices: np.ndarray,
                                       faces: np.ndarray = None) -> float:
        """
        Combined quality index considering multiple geometric factors
        
        Returns:
            Quality index (0-1, higher is better)
        """
        # RMSE component (normalized)
        rmse = np.sqrt(np.mean((modified_vertices - original_vertices) ** 2))
        bbox_diagonal = np.linalg.norm(np.max(original_vertices, axis=0) - 
                                      np.min(original_vertices, axis=0))
        rmse_normalized = 1 - min(rmse / (bbox_diagonal * 0.01), 1.0)
        
        # Correlation component
        correlation = AdvancedMetrics.compute_correlation_coefficient(
            original_vertices, modified_vertices)
        correlation_score = (correlation + 1) / 2  # Map [-1,1] to [0,1]
        
        # SNR component (normalized)
        snr = AdvancedMetrics.compute_snr(original_vertices, modified_vertices)
        snr_score = min(snr / 100.0, 1.0)  # Normalize to 0-1
        
        # Weighted combination
        quality_index = (0.4 * rmse_normalized + 
                        0.3 * correlation_score + 
                        0.3 * snr_score)
        
        return quality_index
