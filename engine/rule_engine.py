import time
import re
import ipaddress
import threading
import concurrent.futures
from typing import List, Dict, Any, Tuple, Optional
from queue import Queue
from rules.rule_loader import Rule

class FilterEngine:
    def __init__(self, rules_by_layer: Dict[int, List[Rule]], max_workers: int = 4):
        self.rules_by_layer = rules_by_layer
        self.max_workers = max_workers
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        
        # Pre-compile IP networks pour optimisation
        self._precompile_ip_rules()
        
        # Statistiques thread-safe
        self._stats_lock = threading.Lock()
        self.stats = {
            'total_packets': 0,
            'dropped_l3': 0, 'dropped_l4': 0, 'dropped_l7': 0,
            'accepted': 0,
            'avg_decision_time': 0.0,
            'thread_usage': 0,
            'cache_hits': 0,
            'rule_matches': {}
        }
        
        # Cache thread-safe pour optimisation
        self._decision_cache = {}
        self._cache_lock = threading.Lock()
        
    def _precompile_ip_rules(self):
        """Pre-compile toutes les règles IP pour optimisation"""
        for layer_rules in self.rules_by_layer.values():
            for rule in layer_rules:
                if rule.type in ['ip_src_in', 'ip_dst_in', 'ip_src_country']:
                    if not hasattr(rule, 'compiled_networks'):
                        rule.compiled_networks = []
                        for value in rule.values:
                            try:
                                if '/' in value:  # CIDR
                                    rule.compiled_networks.append(ipaddress.ip_network(value, strict=False))
                                else:  # Single IP
                                    rule.compiled_networks.append(ipaddress.ip_network(f"{value}/32", strict=False))
                            except ValueError:
                                continue
    
    def filter_sequential(self, parsed_packet: Dict[str, Any]) -> Tuple[str, str, float]:
        """Mode Sequential: L3 → L4 → L7 (stop au premier DROP)"""
        start_time = time.perf_counter()
        packet_id = id(parsed_packet)
        
        # Cache check
        cached_result = self._check_cache(packet_id)
        if cached_result:
            return cached_result
        
        with self._stats_lock:
            self.stats['total_packets'] += 1
        
        # L3 filtering first (peut être parallélisé si beaucoup de règles)
        if len(self.rules_by_layer[3]) > 10:
            action, rule_id = self._evaluate_layer_parallel(3, parsed_packet['layer3'])
        else:
            action, rule_id = self._evaluate_layer_sequential(3, parsed_packet['layer3'])
        
        if action == 'drop':
            decision_time = time.perf_counter() - start_time
            self._update_stats('dropped_l3', rule_id, decision_time)
            result = (action, rule_id, decision_time)
            self._cache_result(packet_id, result)
            return result
        
        # L4 filtering
        if len(self.rules_by_layer[4]) > 15:
            action, rule_id = self._evaluate_layer_parallel(4, parsed_packet['layer4'])
        else:
            action, rule_id = self._evaluate_layer_sequential(4, parsed_packet['layer4'])
        
        if action == 'drop':
            decision_time = time.perf_counter() - start_time
            self._update_stats('dropped_l4', rule_id, decision_time)
            result = (action, rule_id, decision_time)
            self._cache_result(packet_id, result)
            return result
        
        # L7 filtering (toujours parallèle car plus lourd)
        action, rule_id = self._evaluate_layer_parallel(7, parsed_packet['layer7'])
        
        if action == 'drop':
            decision_time = time.perf_counter() - start_time
            self._update_stats('dropped_l7', rule_id, decision_time)
            result = (action, rule_id, decision_time)
            self._cache_result(packet_id, result)
            return result
        
        # Accept par défaut
        decision_time = time.perf_counter() - start_time
        self._update_stats('accepted', 'default', decision_time)
        result = ('accept', 'default', decision_time)
        self._cache_result(packet_id, result)
        return result
    
    def filter_hybrid(self, parsed_packet: Dict[str, Any]) -> Tuple[str, str, float]:
        """Mode Hybrid: TOUS les layers en VRAIE parallèle avec threads"""
        start_time = time.perf_counter()
        packet_id = id(parsed_packet)
        
        # Cache check
        cached_result = self._check_cache(packet_id)
        if cached_result:
            return cached_result
        
        with self._stats_lock:
            self.stats['total_packets'] += 1
        
        # Soumettre TOUS les layers en parallèle avec futures
        futures = []
        
        # L3 evaluation en thread séparé
        future_l3 = self.thread_pool.submit(
            self._evaluate_layer_parallel, 3, parsed_packet['layer3']
        )
        futures.append(('l3', future_l3))
        
        # L4 evaluation en thread séparé  
        future_l4 = self.thread_pool.submit(
            self._evaluate_layer_parallel, 4, parsed_packet['layer4']
        )
        futures.append(('l4', future_l4))
        
        # L7 evaluation en thread séparé
        future_l7 = self.thread_pool.submit(
            self._evaluate_layer_parallel, 7, parsed_packet['layer7']
        )
        futures.append(('l7', future_l7))
        
        # Attendre le premier DROP ou tous ACCEPT
        for layer_name, future in futures:
            try:
                action, rule_id = future.result(timeout=0.1)  # 100ms max par layer
                if action == 'drop':
                    # Annuler les autres futures
                    for _, other_future in futures:
                        if other_future != future:
                            other_future.cancel()
                    
                    decision_time = time.perf_counter() - start_time
                    stat_key = f'dropped_{layer_name}'
                    self._update_stats(stat_key, rule_id, decision_time)
                    result = (action, rule_id, decision_time)
                    self._cache_result(packet_id, result)
                    return result
                    
            except concurrent.futures.TimeoutError:
                # Layer trop lent, passer au suivant
                continue
            except Exception as e:
                # Erreur dans l'évaluation, continuer
                continue
        
        # Si aucun DROP trouvé → ACCEPT
        decision_time = time.perf_counter() - start_time
        self._update_stats('accepted', 'default', decision_time)
        result = ('accept', 'default', decision_time)
        self._cache_result(packet_id, result)
        return result
    
    def _evaluate_layer_sequential(self, layer: int, layer_data: Dict[str, Any]) -> Tuple[str, str]:
        """Evaluation séquentielle d'une layer"""
        for rule in self.rules_by_layer[layer]:
            if self._evaluate_rule_optimized(rule, layer_data):
                return rule.action, rule.id
        return 'accept', 'none'
    
    def _evaluate_layer_parallel(self, layer: int, layer_data: Dict[str, Any]) -> Tuple[str, str]:
        """Evaluation VRAIMENT parallèle d'une layer avec threads"""
        rules = self.rules_by_layer[layer]
        
        if len(rules) <= 3:
            # Trop peu de règles pour parallélisme
            return self._evaluate_layer_sequential(layer, layer_data)
        
        # Split les règles en chunks pour threads
        chunk_size = max(1, len(rules) // self.max_workers)
        rule_chunks = [rules[i:i + chunk_size] for i in range(0, len(rules), chunk_size)]
        
        # Soumettre chaque chunk à un thread
        futures = []
        for chunk in rule_chunks:
            future = self.thread_pool.submit(self._evaluate_rule_chunk, chunk, layer_data)
            futures.append(future)
        
        # Attendre les résultats (premier match gagne)
        for future in concurrent.futures.as_completed(futures, timeout=0.05):  # 50ms max
            try:
                result = future.result()
                if result[0] == 'drop':
                    # Annuler les autres
                    for other_future in futures:
                        if other_future != future:
                            other_future.cancel()
                    return result
            except Exception:
                continue
        
        return 'accept', 'none'
    
    def _evaluate_rule_chunk(self, rules: List[Rule], data: Dict[str, Any]) -> Tuple[str, str]:
        """Evaluer un chunk de règles (appelé par un thread)"""
        for rule in rules:
            if self._evaluate_rule_optimized(rule, data):
                return rule.action, rule.id
        return 'accept', 'none'
    
    def _evaluate_rule_optimized(self, rule: Rule, data: Dict[str, Any]) -> bool:
        """Evaluation ultra-optimisée d'une règle individuelle"""
        try:
            # L3 Rules (IP-based) - OPTIMISÉES
            if rule.type == 'ip_src_in':
                src_ip = data.get('src_ip')
                if not src_ip:
                    return False
                
                try:
                    ip_obj = ipaddress.ip_address(src_ip)
                    return any(ip_obj in network for network in rule.compiled_networks)
                except ValueError:
                    return False
            
            elif rule.type == 'ip_dst_in':
                dst_ip = data.get('dst_ip')
                if not dst_ip:
                    return False
                
                try:
                    ip_obj = ipaddress.ip_address(dst_ip)
                    return any(ip_obj in network for network in rule.compiled_networks)
                except ValueError:
                    return False
            
            elif rule.type == 'ip_src_country':
                # TODO: Intégrer GeoIP database pour efficacité
                src_ip = data.get('src_ip', '')
                # Simulation rapide pour certains ranges connus
                if any(country in ['CN', 'RU'] for country in rule.values):
                    # Ranges IP connus pour CN/RU (sample)
                    cn_ranges = ['220.', '221.', '222.', '223.']
                    ru_ranges = ['94.', '95.', '178.', '188.']
                    return any(src_ip.startswith(prefix) for prefix in cn_ranges + ru_ranges)
                return False
            
            # L4 Rules (Port/Protocol-based) - OPTIMISÉES
            elif rule.type == 'tcp_dst_port':
                return (data.get('protocol') == 'tcp' and 
                       data.get('dst_port') in rule.values)
            
            elif rule.type == 'tcp_dst_port_not_in':
                return (data.get('protocol') == 'tcp' and 
                       data.get('dst_port') not in rule.values)
            
            elif rule.type == 'udp_dst_port':
                return (data.get('protocol') == 'udp' and 
                       data.get('dst_port') in rule.values)
            
            elif rule.type == 'tcp_flags':
                return (data.get('protocol') == 'tcp' and 
                       any(flag in data.get('flags', '') for flag in rule.values))
            
            # L7 Rules (Application-based) - ULTRA-OPTIMISÉES
            elif rule.type == 'http_uri_regex':
                uri = data.get('uri', '')
                if not uri:
                    return False
                return any(pattern.search(uri) for pattern in rule.compiled_patterns)
            
            elif rule.type == 'http_header_contains':
                field = getattr(rule, 'field', 'user-agent').lower()
                headers = data.get('headers', {})
                header_value = headers.get(field, '').lower()
                return any(value.lower() in header_value for value in rule.values)
            
            elif rule.type == 'http_method':
                method = data.get('method', '').upper()
                return method in [v.upper() for v in rule.values]
            
            elif rule.type == 'http_payload_regex':
                payload = data.get('payload', '')
                if not payload:
                    return False
                return any(pattern.search(payload) for pattern in rule.compiled_patterns)
            
            elif rule.type == 'dns_query_contains':
                query_name = data.get('query_name', '').lower()
                return any(domain.lower() in query_name for domain in rule.values)
            
        except Exception as e:
            # Log error mais continue
            return False
        
        return False
    
    def _check_cache(self, packet_id: int) -> Optional[Tuple[str, str, float]]:
        """Check cache thread-safe"""
        with self._cache_lock:
            if packet_id in self._decision_cache:
                self.stats['cache_hits'] += 1
                return self._decision_cache[packet_id]
        return None
    
    def _cache_result(self, packet_id: int, result: Tuple[str, str, float]):
        """Cache result thread-safe avec LRU"""
        with self._cache_lock:
            if len(self._decision_cache) > 5000:  # LRU simple
                # Remove oldest 1000 entries
                for _ in range(1000):
                    self._decision_cache.pop(next(iter(self._decision_cache)))
            self._decision_cache[packet_id] = result
    
    def _update_stats(self, stat_type: str, rule_id: str, decision_time: float):
        """Update stats thread-safe"""
        with self._stats_lock:
            self.stats[stat_type] += 1
            
            # Track rule matches
            if rule_id not in self.stats['rule_matches']:
                self.stats['rule_matches'][rule_id] = 0
            self.stats['rule_matches'][rule_id] += 1
            
            # Update moyenne decision time
            total = sum([self.stats['dropped_l3'], self.stats['dropped_l4'], 
                        self.stats['dropped_l7'], self.stats['accepted']])
            if total > 0:
                self.stats['avg_decision_time'] = (
                    (self.stats['avg_decision_time'] * (total - 1) + decision_time) / total
                )
    
    def get_thread_safe_stats(self) -> Dict[str, Any]:
        """Retourner stats thread-safe"""
        with self._stats_lock:
            return self.stats.copy()
    
    def shutdown(self):
        """Nettoyer les threads"""
        self.thread_pool.shutdown(wait=True)