#!/usr/bin/env python3
"""
Metrics Collection for Network Filtering Performance Analysis
Real-time metrics for sequential vs hybrid comparison
"""

import time
import threading
import psutil
import logging
from typing import Dict, Any, List
from collections import deque
import json

logger = logging.getLogger(__name__)


class MetricsCollector:
    def __init__(self, enabled: bool = True, interval: float = 1.0):
        self.enabled = enabled
        self.interval = interval
        self.running = False
        
        # Thread-safe data structures
        self._lock = threading.Lock()
        self._metrics_thread = None
        
        # Packet-level metrics
        self.packet_metrics = {
            'total_packets': 0,
            'dropped_packets': 0,
            'accepted_packets': 0,
            'total_decision_time': 0.0,
            'total_processing_time': 0.0,
            'avg_decision_time': 0.0,
            'avg_processing_time': 0.0,
            'min_decision_time': float('inf'),
            'max_decision_time': 0.0,
            'packets_per_second': 0.0,
            'bytes_processed': 0,
            'p99_decision_time': 0.0,
            'p95_decision_time': 0.0
        }
        
        # System metrics
        self.system_metrics = {
            'cpu_percent': 0.0,
            'memory_rss': 0,
            'memory_vms': 0,
            'memory_percent': 0.0,
            'threads_count': 0,
            'load_avg': 0.0
        }
        
        # Rule performance metrics
        self.rule_metrics = {}
        
        # Time series data (last 100 measurements)
        self.time_series = deque(maxlen=100)
        
        # Decision time history for percentiles
        self.decision_times = deque(maxlen=1000)
        
        # Performance snapshots
        self.snapshots = []
        
        logger.info(f"MetricsCollector initialized (enabled: {enabled}, interval: {interval}s)")
    
    def start(self):
        """Start metrics collection in background thread"""
        if not self.enabled or self.running:
            return
        
        self.running = True
        self._metrics_thread = threading.Thread(target=self._collect_metrics_loop, daemon=True)
        self._metrics_thread.start()
        logger.info("Metrics collection started")
    
    def stop(self):
        """Stop metrics collection"""
        if not self.running:
            return
        
        self.running = False
        if self._metrics_thread:
            self._metrics_thread.join(timeout=2.0)
        
        # Save final snapshot
        self._take_snapshot("final")
        logger.info("Metrics collection stopped")
    
    def record_packet(self, action: str, rule_id: str, decision_time: float, 
                     total_time: float, packet_size: int):
        """Record metrics for a processed packet"""
        if not self.enabled:
            return
        
        with self._lock:
            # Update packet metrics
            self.packet_metrics['total_packets'] += 1
            
            if action == 'drop':
                self.packet_metrics['dropped_packets'] += 1
            else:
                self.packet_metrics['accepted_packets'] += 1
            
            self.packet_metrics['total_decision_time'] += decision_time
            self.packet_metrics['total_processing_time'] += total_time
            self.packet_metrics['bytes_processed'] += packet_size
            
            # Update averages
            total_packets = self.packet_metrics['total_packets']
            self.packet_metrics['avg_decision_time'] = (
                self.packet_metrics['total_decision_time'] / total_packets
            )
            self.packet_metrics['avg_processing_time'] = (
                self.packet_metrics['total_processing_time'] / total_packets
            )
            
            # Update min/max decision times
            self.packet_metrics['min_decision_time'] = min(
                self.packet_metrics['min_decision_time'], decision_time
            )
            self.packet_metrics['max_decision_time'] = max(
                self.packet_metrics['max_decision_time'], decision_time
            )
            
            # Add to decision times for percentiles
            self.decision_times.append(decision_time)
            self._update_percentiles()
            
            # Update rule metrics
            if rule_id not in self.rule_metrics:
                self.rule_metrics[rule_id] = {
                    'hits': 0,
                    'total_time': 0.0,
                    'avg_time': 0.0,
                    'action': action,
                    'min_time': float('inf'),
                    'max_time': 0.0
                }
            
            rule_stats = self.rule_metrics[rule_id]
            rule_stats['hits'] += 1
            rule_stats['total_time'] += decision_time
            rule_stats['avg_time'] = rule_stats['total_time'] / rule_stats['hits']
            rule_stats['min_time'] = min(rule_stats['min_time'], decision_time)
            rule_stats['max_time'] = max(rule_stats['max_time'], decision_time)
    
    def _update_percentiles(self):
        """Calculate P95 and P99 decision times"""
        if len(self.decision_times) < 20:  # Need minimum samples
            return
        
        sorted_times = sorted(self.decision_times)
        n = len(sorted_times)
        
        p95_idx = int(0.95 * n)
        p99_idx = int(0.99 * n)
        
        self.packet_metrics['p95_decision_time'] = sorted_times[min(p95_idx, n-1)]
        self.packet_metrics['p99_decision_time'] = sorted_times[min(p99_idx, n-1)]
    
    def _collect_metrics_loop(self):
        """Background thread to collect system metrics"""
        last_packet_count = 0
        last_time = time.time()
        
        while self.running:
            try:
                current_time = time.time()
                
                # Get current process
                process = psutil.Process()
                
                with self._lock:
                    # System metrics
                    self.system_metrics['cpu_percent'] = process.cpu_percent()
                    memory_info = process.memory_info()
                    self.system_metrics['memory_rss'] = memory_info.rss
                    self.system_metrics['memory_vms'] = memory_info.vms
                    self.system_metrics['memory_percent'] = process.memory_percent()
                    self.system_metrics['threads_count'] = process.num_threads()
                    
                    # System load average (Linux)
                    try:
                        load_avg = psutil.getloadavg()[0]  # 1-minute load average
                        self.system_metrics['load_avg'] = load_avg
                    except AttributeError:
                        # Not available on all systems
                        pass
                    
                    # Calculate packets per second
                    time_diff = current_time - last_time
                    packet_diff = self.packet_metrics['total_packets'] - last_packet_count
                    
                    if time_diff > 0:
                        self.packet_metrics['packets_per_second'] = packet_diff / time_diff
                    
                    # Add to time series
                    self.time_series.append({
                        'timestamp': current_time,
                        'cpu_percent': self.system_metrics['cpu_percent'],
                        'memory_rss_mb': self.system_metrics['memory_rss'] / (1024 * 1024),
                        'packets_per_second': self.packet_metrics['packets_per_second'],
                        'total_packets': self.packet_metrics['total_packets'],
                        'drop_rate': (self.packet_metrics['dropped_packets'] / 
                                    max(1, self.packet_metrics['total_packets'])) * 100,
                        'avg_decision_time_ms': self.packet_metrics['avg_decision_time'] * 1000,
                        'p99_decision_time_ms': self.packet_metrics['p99_decision_time'] * 1000
                    })
                
                last_packet_count = self.packet_metrics['total_packets']
                last_time = current_time
                
                time.sleep(self.interval)
                
            except Exception as e:
                logger.error(f"Error collecting metrics: {e}")
                time.sleep(self.interval)
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current metrics snapshot"""
        with self._lock:
            return {
                'timestamp': time.time(),
                'packet_metrics': self.packet_metrics.copy(),
                'system_metrics': self.system_metrics.copy(),
                'rule_metrics': self.rule_metrics.copy(),
                'performance_summary': self._calculate_performance_summary()
            }
    
    def _calculate_performance_summary(self) -> Dict[str, Any]:
        """Calculate performance summary statistics"""
        total_packets = self.packet_metrics['total_packets']
        
        if total_packets == 0:
            return {}
        
        drop_rate = (self.packet_metrics['dropped_packets'] / total_packets) * 100
        
        # Find top rules by hits
        top_rules = sorted(
            self.rule_metrics.items(),
            key=lambda x: x[1]['hits'],
            reverse=True
        )[:5]
        
        # Find slowest rules
        slowest_rules = sorted(
            [(rule_id, stats) for rule_id, stats in self.rule_metrics.items() if stats['hits'] > 0],
            key=lambda x: x[1]['avg_time'],
            reverse=True
        )[:3]
        
        return {
            'drop_rate_percent': drop_rate,
            'avg_decision_time_ms': self.packet_metrics['avg_decision_time'] * 1000,
            'p95_decision_time_ms': self.packet_metrics['p95_decision_time'] * 1000,
            'p99_decision_time_ms': self.packet_metrics['p99_decision_time'] * 1000,
            'min_decision_time_ms': self.packet_metrics['min_decision_time'] * 1000,
            'max_decision_time_ms': self.packet_metrics['max_decision_time'] * 1000,
            'avg_processing_time_ms': self.packet_metrics['avg_processing_time'] * 1000,
            'throughput_pps': self.packet_metrics['packets_per_second'],
            'memory_usage_mb': self.system_metrics['memory_rss'] / (1024 * 1024),
            'cpu_usage_percent': self.system_metrics['cpu_percent'],
            'top_rules': [{'rule_id': rule_id, 'hits': stats['hits'], 
                          'avg_time_ms': stats['avg_time'] * 1000} 
                         for rule_id, stats in top_rules],
            'slowest_rules': [{'rule_id': rule_id, 'avg_time_ms': stats['avg_time'] * 1000,
                              'hits': stats['hits']} 
                             for rule_id, stats in slowest_rules]
        }
    
    def _take_snapshot(self, label: str):
        """Take a labeled snapshot of current metrics"""
        snapshot = {
            'label': label,
            'timestamp': time.time(),
            'metrics': self.get_current_metrics()
        }
        self.snapshots.append(snapshot)
        logger.info(f"Metrics snapshot taken: {label}")
    
    def export_metrics(self, filepath: str):
        """Export all metrics to JSON file"""
        try:
            export_data = {
                'experiment_info': {
                    'tiger_fox_filtering_experiment': True,
                    'export_timestamp': time.time(),
                    'total_snapshots': len(self.snapshots),
                    'time_series_points': len(self.time_series)
                },
                'snapshots': self.snapshots,
                'time_series': list(self.time_series),
                'final_metrics': self.get_current_metrics()
            }
            
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            logger.info(f"Metrics exported to {filepath}")
        
        except Exception as e:
            logger.error(f"Error exporting metrics: {e}")
    
    def print_summary(self):
        """Print a summary of current metrics"""
        if not self.enabled:
            print("Metrics collection disabled")
            return
        
        metrics = self.get_current_metrics()
        packet_metrics = metrics['packet_metrics']
        system_metrics = metrics['system_metrics']
        summary = metrics['performance_summary']
        
        print("\n" + "="*70)
        print("TIGER-FOX FILTERING PERFORMANCE SUMMARY")
        print("="*70)
        
        print(f"Total Packets Processed: {packet_metrics['total_packets']:,}")
        print(f"Packets Dropped: {packet_metrics['dropped_packets']:,}")
        print(f"Packets Accepted: {packet_metrics['accepted_packets']:,}")
        
        if summary:
            print(f"Drop Rate: {summary['drop_rate_percent']:.2f}%")
            print(f"Throughput: {summary['throughput_pps']:.1f} packets/sec")
            print(f"Avg Decision Time: {summary['avg_decision_time_ms']:.3f} ms")
            print(f"P95 Decision Time: {summary['p95_decision_time_ms']:.3f} ms")
            print(f"P99 Decision Time: {summary['p99_decision_time_ms']:.3f} ms")
            print(f"Min Decision Time: {summary['min_decision_time_ms']:.3f} ms")
            print(f"Max Decision Time: {summary['max_decision_time_ms']:.3f} ms")
            print(f"CPU Usage: {summary['cpu_usage_percent']:.1f}%")
            print(f"Memory Usage: {summary['memory_usage_mb']:.1f} MB")
            
            if summary['top_rules']:
                print("\nTop Rules by Hits:")
                for rule in summary['top_rules']:
                    print(f"  {rule['rule_id']}: {rule['hits']} hits, "
                          f"{rule['avg_time_ms']:.3f}ms avg")
            
            if summary.get('slowest_rules'):
                print("\nSlowest Rules:")
                for rule in summary['slowest_rules']:
                    print(f"  {rule['rule_id']}: {rule['avg_time_ms']:.3f}ms avg, "
                          f"{rule['hits']} hits")
        
        print("="*70)