"""
rule_matcher.py -- Minimal local evaluator for testing Sigma rule logic
SOC Home Lab Project | github.com/AurelioAvila

pySigma converts a Sigma rule into a query for a real backend (Splunk,
Elastic, ...) -- it doesn't execute rules locally, because a Sigma rule
has no meaning outside a query language until it's converted. To unit-test
rule *logic* against synthetic events without standing up a real SIEM,
this module implements a small, deliberately narrow evaluator.

Scope, exactly matched to what the three rules in sigma_rules/ use --
NOT a general-purpose Sigma engine:
  - Field modifiers: |endswith, |contains (the only two used here)
  - A field with multiple values is OR'd together (standard Sigma semantics)
  - Multiple fields within one selection are AND'd together
  - The top-level condition is a plain "and" of named selections (no OR/NOT)

Extending this to arbitrary Sigma syntax (aggregations, NOT, nested
conditions, other modifiers) is explicitly out of scope -- see the
Limitations section in README.md.
"""


def _plain_values(detection_item):
    """Strip Sigma's wildcard markers, returning the raw substrings the
    endswith/contains modifiers actually compare against."""
    values = []
    for v in detection_item.value:
        text = v.to_plain()
        values.append(text.strip("*"))
    return values


def _detection_item_matches(detection_item, event):
    field_value = str(event.get(detection_item.field, ""))
    modifier_names = {m.__name__ for m in detection_item.modifiers}
    candidates = _plain_values(detection_item)

    if "SigmaEndswithModifier" in modifier_names:
        return any(field_value.endswith(v) for v in candidates)
    if "SigmaContainsModifier" in modifier_names:
        return any(v in field_value for v in candidates)

    # No modifier -> exact match against any candidate value
    return any(field_value == v for v in candidates)


def _selection_matches(sigma_detection, event):
    """All detection_items within one selection are AND'd (Sigma default)."""
    return all(_detection_item_matches(item, event) for item in sigma_detection.detection_items)


def evaluate_rule(collection, event):
    """Evaluate a single-rule SigmaCollection against one event dict.
    Only supports a top-level condition of the form
    'selectionA and selectionB [and selectionC ...]', which is what every
    rule in this repo uses.
    """
    rule = list(collection.rules)[0]
    detections = rule.detection.detections
    condition_str = rule.detection.condition[0]

    selection_names = [name.strip() for name in condition_str.split(" and ")]
    return all(_selection_matches(detections[name], event) for name in selection_names)
