#!/usr/bin/env python3
"""
Tiger-Fox Network Filtering Experiment
Real NFQUEUE-based packet filtering with performance comparison
Author: Pascal DONFACK ARTHUR MONTGOMERY (Tiger Fox)
Modes: sequential vs hybrid parallel evaluation
"""

import sys
import signal
import threading
import time
import argparse
import yaml
import logging
from pathlib import Path
import os

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

try:
    import netfilterqueue
    import scapy.all as scapy
    import psutil
except ImportError as e:
    logger.error(f"Missing dependencies: {e}")
    logger.error("Install with: sudo pip install netfilterqueue scapy psutil pyyaml")
    sys.exit(1)

from engine.packet_handler import PacketHandler
from engine.metrics import MetricsCollector
from rules.rule_loader import RuleLoader


class TigerFoxFilteringSystem:
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.running = False
        self.nfqueue = None
        
        # Check if running as root (required for NFQUEUE)
        if not self._check_root():
            logger.error("This program must be run as root for NFQUEUE access")
            logger.error("Use: sudo python main.py")
            sys.exit(1)
        
        # Load rules
        rules_file = self.config['rules']['file']
        self.rules_by_layer = RuleLoader.load_rules(rules_file)
        total_rules = sum(len(rules) for rules in self.rules_by_layer.values())
        logger.info(f"Loaded {total_rules} rules:")
        logger.info(f"  L3 rules: {len(self.rules_by_layer[3])}")
        logger.info(f"  L4 rules: {len(self.rules_by_layer[4])}")
        logger.info(f"  L7 rules: {len(self.rules_by_layer[7])}")
        
        # Initialize components
        self.metrics = MetricsCollector(
            enabled=self.config['performance']['enable_metrics'],
            interval=self.config['performance']['metric_interval']
        )
        
        self.packet_handler = PacketHandler(
            rules_by_layer=self.rules_by_layer,
            mode=self.config['engine']['mode'],
            metrics=self.metrics
        )
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _load_config(self, config_path: str) -> dict:
        """Load YAML configuration"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config {config_path}: {e}")
            sys.exit(1)
    
    def _check_root(self) -> bool:
        """Check if running as root"""
        return os.geteuid() == 0
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
    
    def start(self):
        """Start the filtering system"""
        logger.info("="*60)
        logger.info("TIGER-FOX NETWORK FILTERING EXPERIMENT")
        logger.info("="*60)
        logger.info(f"Mode: {self.config['engine']['mode'].upper()}")
        logger.info(f"Queue number: {self.config['engine']['queue_num']}")
        
        # Print iptables setup instructions
        queue_num = self.config['engine']['queue_num']
        logger.info("\nSetup iptables rule first:")
        logger.info(f"  sudo iptables -I INPUT -j NFQUEUE --queue-num {queue_num}")
        logger.info("Or for specific traffic:")
        logger.info(f"  sudo iptables -I INPUT -p tcp --dport 80 -j NFQUEUE --queue-num {queue_num}")
        logger.info("\nTo remove later:")
        logger.info(f"  sudo iptables -D INPUT -j NFQUEUE --queue-num {queue_num}")
        logger.info("="*60)
        
        try:
            # Setup NFQUEUE
            self.nfqueue = netfilterqueue.NetfilterQueue()
            self.nfqueue.bind(
                self.config['engine']['queue_num'], 
                self.packet_handler.process_packet
            )
            
            # Start metrics collection in background
            if self.config['performance']['enable_metrics']:
                self.metrics.start()
                logger.info("Metrics collection started")
            
            self.running = True
            logger.info("Filtering system started. Waiting for packets...")
            logger.info("Press Ctrl+C to stop and show statistics")
            
            # Main loop - blocking call
            self.nfqueue.run()
            
        except KeyboardInterrupt:
            logger.info("\nKeyboard interrupt received")
        except PermissionError:
            logger.error("Permission denied. Make sure you run as root and iptables rule is set")
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the filtering system"""
        if not self.running:
            return
            
        logger.info("Stopping filtering system...")
        self.running = False
        
        # Stop components
        if hasattr(self, 'metrics') and self.metrics:
            self.metrics.stop()
        
        if hasattr(self, 'packet_handler') and self.packet_handler:
            # Print final statistics
            self._print_final_stats()
            self.packet_handler.shutdown()
        
        # Cleanup NFQUEUE
        if self.nfqueue:
            try:
                self.nfqueue.unbind()
            except:
                pass
        
        logger.info("Filtering system stopped")
    
    def _print_final_stats(self):
        """Print final statistics"""
        try:
            stats = self.packet_handler.get_stats()
            engine_stats = stats.get('engine_stats', {})
            
            print("\n" + "="*60)
            print("FINAL STATISTICS - TIGER-FOX EXPERIMENT")
            print("="*60)
            print(f"Mode: {self.config['engine']['mode'].upper()}")
            print(f"Total packets processed: {stats['total_packets']:,}")
            print(f"Packets dropped: {stats['dropped_packets']:,}")
            print(f"Packets accepted: {stats['accepted_packets']:,}")
            print(f"Drop rate: {stats['drop_rate']:.2f}%")
            
            if engine_stats:
                avg_time = engine_stats.get('avg_decision_time', 0) * 1000
                print(f"Average decision time: {avg_time:.3f} ms")
                
                # Top matched rules
                rule_matches = engine_stats.get('rule_matches', {})
                if rule_matches:
                    print("\nTop matched rules:")
                    sorted_rules = sorted(rule_matches.items(), 
                                        key=lambda x: x[1], reverse=True)[:5]
                    for rule_id, count in sorted_rules:
                        print(f"  {rule_id}: {count} matches")
            
            print("="*60)
            
        except Exception as e:
            logger.error(f"Error printing stats: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Tiger-Fox Network Filtering Experiment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python main.py                    # Run with default config
  sudo python main.py -m hybrid         # Run in hybrid mode  
  sudo python main.py -q 1 --verbose    # Use queue 1 with verbose logging
  
Setup iptables before running:
  sudo iptables -I INPUT -j NFQUEUE --queue-num 0
        """
    )
    
    parser.add_argument('--config', '-c', default='config.yaml', 
                       help='Configuration file path (default: config.yaml)')
    parser.add_argument('--mode', '-m', choices=['sequential', 'hybrid'], 
                       help='Override filter mode from config')
    parser.add_argument('--queue', '-q', type=int, 
                       help='Override NFQUEUE number from config')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--rules', '-r', type=str,
                       help='Override rules file from config')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load system
    try:
        system = TigerFoxFilteringSystem(args.config)
    except Exception as e:
        logger.error(f"Failed to initialize system: {e}")
        sys.exit(1)
    
    # Override config with CLI args if provided
    if args.mode:
        system.config['engine']['mode'] = args.mode
        system.packet_handler.mode = args.mode
        logger.info(f"Mode overridden to: {args.mode}")
    
    if args.queue is not None:
        system.config['engine']['queue_num'] = args.queue
        logger.info(f"Queue number overridden to: {args.queue}")
    
    if args.rules:
        system.config['rules']['file'] = args.rules
        # Reload rules
        system.rules_by_layer = RuleLoader.load_rules(args.rules)
        system.packet_handler.filter_engine.rules_by_layer = system.rules_by_layer
        logger.info(f"Rules file overridden to: {args.rules}")
    
    # Start system
    system.start()


if __name__ == "__main__":
    main()