import json
import re
from typing import List, Dict, Any

class Rule:
    def __init__(self, rule_data: Dict[str, Any]):
        self.id = rule_data['id']
        self.layer = rule_data['layer']
        self.type = rule_data['type']
        self.values = rule_data['values']
        self.action = rule_data['action']
        
        # Precompile regex for L7 rules
        if self.type.endswith('_regex'):
            self.compiled_patterns = [re.compile(pattern) for pattern in self.values]

class RuleLoader:
    @staticmethod
    def load_rules(file_path: str) -> Dict[int, List[Rule]]:
        """Load rules grouped by layer for efficient processing"""
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        rules_by_layer = {3: [], 4: [], 7: []}
        
        for rule_data in data['rules']:
            rule = Rule(rule_data)
            rules_by_layer[rule.layer].append(rule)
        
        return rules_by_layer