"""
Unit Tests for TRUST Scoring & Risk Assessment Engine.
"""

import unittest

# Weight constants matching scoring.js
WEIGHTS = {
    'inputTiming': 25,
    'domScript': 25,
    'clipboard': 20,
    'browserEnv': 15,
    'canvasWebgl': 10,
    'environment': 5,  # Fixed: Changed from 3 to 5
    'networkSignals': 5  # Fixed: Changed from 2 to 5
}

def evaluate_scoring(detector_results, active_attack_count=0):
    total_weight = 0
    weighted_score_sum = 0
    critical_failures = 0

    for key, result in detector_results.items():
        weight = WEIGHTS.get(key, 10)
        score = max(0, min(100, result.get('score', 0)))
        total_weight += weight
        weighted_score_sum += (score * weight)

        for finding in result.get('findings', []):
            if finding.get('status') == 'FAILED' and finding.get('penalty', 0) >= 25:
                critical_failures += 1

    composite_score = round(weighted_score_sum / total_weight) if total_weight > 0 else 0

    if critical_failures > 0 and composite_score > 55:
        composite_score = min(55, composite_score)

    attack_load_penalty = min(100, active_attack_count * (active_attack_count + 1) * 2) if active_attack_count > 0 else 0
    composite_score = max(0, composite_score - attack_load_penalty)

    if composite_score >= 90:
        risk_level = "LOW"
        traffic_light = "green"
    elif composite_score >= 70:
        risk_level = "MEDIUM"
        traffic_light = "yellow"
    else:
        risk_level = "HIGH"
        traffic_light = "red"

    return {
        "score": composite_score,
        "riskLevel": risk_level,
        "trafficLight": traffic_light,
        "criticalFailures": critical_failures,
        "attackLoadPenalty": attack_load_penalty
    }


class TestTrustScoring(unittest.TestCase):

    def test_clean_baseline_passes_all(self):
        clean_state = {
            'inputTiming': {'score': 100, 'findings': []},
            'domScript': {'score': 100, 'findings': []},
            'clipboard': {'score': 100, 'findings': []},
            'browserEnv': {'score': 100, 'findings': []},
            'canvasWebgl': {'score': 100, 'findings': []},
            'environment': {'score': 100, 'findings': []},
            'networkSignals': {'score': 100, 'findings': []}
        }
        res = evaluate_scoring(clean_state)
        self.assertEqual(res['score'], 100)
        self.assertEqual(res['riskLevel'], 'LOW')
        self.assertEqual(res['trafficLight'], 'green')

    def test_keylogger_hook_drops_to_high_risk(self):
        hooked_state = {
            'inputTiming': {
                'score': 40,
                'findings': [{'status': 'FAILED', 'penalty': 35, 'title': 'Event Listener Tampering'}]
            },
            'domScript': {
                'score': 60,
                'findings': [{'status': 'FAILED', 'penalty': 40, 'title': 'Native Prototype Tampering'}]
            },
            'clipboard': {'score': 100, 'findings': []},
            'browserEnv': {'score': 100, 'findings': []},
            'canvasWebgl': {'score': 100, 'findings': []},
            'environment': {'score': 100, 'findings': []},
            'networkSignals': {'score': 100, 'findings': []}
        }
        res = evaluate_scoring(hooked_state)
        self.assertLessEqual(res['score'], 55)
        self.assertEqual(res['riskLevel'], 'HIGH')
        self.assertEqual(res['trafficLight'], 'red')
        self.assertGreaterEqual(res['criticalFailures'], 2)

    def test_minor_network_latency_medium_risk(self):
        moderate_risk_state = {
            'inputTiming': {'score': 80, 'findings': [{'status': 'WARN', 'penalty': 20}]},
            'domScript': {'score': 80, 'findings': [{'status': 'WARN', 'penalty': 20}]},
            'clipboard': {'score': 80, 'findings': [{'status': 'WARN', 'penalty': 20}]},
            'browserEnv': {'score': 70, 'findings': [{'status': 'WARN', 'penalty': 30}]},
            'canvasWebgl': {'score': 70, 'findings': [{'status': 'WARN', 'penalty': 30}]},
            'environment': {'score': 100, 'findings': []},
            'networkSignals': {'score': 80, 'findings': [{'status': 'WARN', 'penalty': 20}]}
        }
        res = evaluate_scoring(moderate_risk_state)
        self.assertGreaterEqual(res['score'], 70)
        self.assertLess(res['score'], 90)
        self.assertEqual(res['riskLevel'], 'MEDIUM')
        self.assertEqual(res['trafficLight'], 'yellow')

    def test_more_active_attacks_reduce_score_progressively(self):
        clean_state = {
            key: {'score': 100, 'findings': []}
            for key in WEIGHTS
        }
        one_attack = evaluate_scoring(clean_state, active_attack_count=1)
        two_attacks = evaluate_scoring(clean_state, active_attack_count=2)
        four_attacks = evaluate_scoring(clean_state, active_attack_count=4)

        self.assertEqual(one_attack['score'], 96)
        self.assertEqual(two_attacks['score'], 88)
        self.assertEqual(four_attacks['score'], 60)
        self.assertLess(two_attacks['score'], one_attack['score'])
        self.assertLess(four_attacks['score'], two_attacks['score'])


if __name__ == '__main__':
    unittest.main()
