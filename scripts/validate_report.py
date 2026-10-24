"""Validate schema and cross-record invariants. Requires the development-only jsonschema package."""
import argparse
import json
from pathlib import Path
from jsonschema import Draft202012Validator


def validate(report, schema):
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(report)
    artifacts = {a['id']: a for a in report['artifacts']}
    evidence = {e['id']: e for e in report['evidence']}
    assert len(artifacts) == len(report['artifacts'])
    assert len(evidence) == len(report['evidence'])
    protected = set(report['plan']['protected_paths'])
    assert all(a['path'] in protected for a in artifacts.values())
    for candidate in report['candidates']:
        assert candidate['artifact_id'] in artifacts
        assert candidate['proposed_operation'] == 'investigate'
        assert candidate['blockers']
        for key in candidate['evidence_ids']:
            assert evidence[key]['artifact_id'] == candidate['artifact_id']
    counted = [a for a in artifacts.values() if a['counted']]
    assert len({a['identity'] for a in counted}) == len(counted)
    assert sum(a['logical_bytes'] for a in counted) == report['totals']['logical_bytes']
    assert report['plan']['roots'] == report['roots']
    if report['cancelled']:
        assert not report['complete']


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('report', type=Path)
    ap.add_argument('--schema', type=Path, default=Path(__file__).resolve().parents[1] / 'schemas/report-v1.schema.json')
    args = ap.parse_args()
    validate(json.loads(args.report.read_text(encoding='utf-8')), json.loads(args.schema.read_text(encoding='utf-8')))
    print('Schema and cross-record invariants passed.')
