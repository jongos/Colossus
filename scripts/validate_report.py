"""Validate schema and cross-record invariants. Requires the development-only jsonschema package."""
import argparse
import ntpath
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
            assert evidence[key]['artifact_id'] in artifacts
    counted = [a for a in artifacts.values() if a['counted']]
    assert len({a['identity'] for a in counted}) == len(counted)
    assert sum(a['logical_bytes'] for a in counted) == report['totals']['logical_bytes']
    assert report['plan']['roots'] == report['roots']
    if report['cancelled']:
        assert not report['complete']
    if 'provenance' in report:
        p=report['provenance']
        selections={s['manifest_path'].replace('/','\\'):s['lockfile_path'] for s in p.get('cargo_lockfiles',[])}
        assert len(selections)==len(p.get('cargo_lockfiles',[]))
        if selections: assert p['enabled']
        projects={v['id']:v for v in p['projects']}
        assert len(projects)==len(p['projects'])
        for project in projects.values():
            assert project['manifest_artifact_id'] in artifacts
            assert evidence[project['evidence_id']]['artifact_id']==project['manifest_artifact_id']
        workspaces={w['project_id']:w for w in p.get('cargo_workspaces',[])}
        assert len(workspaces)==len(p.get('cargo_workspaces',[]))
        assert sum(len(w['members'])+len(w['exclude']) for w in workspaces.values())<=10000
        for w in workspaces.values():
            assert projects[w['project_id']]['ecosystem']=='cargo'
            assert w['evidence_id']==projects[w['project_id']]['evidence_id']
        for dependency in p['dependencies']:
            assert dependency['project_id'] in projects
            assert dependency['evidence_id'] in evidence
            assert dependency['target_artifact_id'] is None or dependency['target_artifact_id'] in artifacts
        for claim in p['claims']:
            assert claim['record_artifact_id'] in artifacts
            assert evidence[claim['evidence_id']]['artifact_id']==claim['record_artifact_id']
            assert claim['target_artifact_id'] is None or claim['target_artifact_id'] in artifacts
        for owner in p['ownership']:
            assert owner['artifact_id'] in artifacts
            assert all(i in projects for i in owner['project_ids'])
            assert all(i in evidence for i in owner['evidence_ids'])
        hashes={h['artifact_id']:h for h in p['hashes']}
        for h in hashes.values():
            assert evidence[h['evidence_id']]['artifact_id']==h['artifact_id']
            assert h['bytes']==artifacts[h['artifact_id']]['logical_bytes']
        for group in p['duplicate_groups']:
            assert len({hashes[i]['sha256'] for i in group})==1
            assert len({artifacts[i]['identity'] for i in group})==len(group)

        for h in p.get('source_hashes', []):
            assert h['artifact_id'] in artifacts
            assert evidence[h['evidence_id']]['artifact_id']==h['artifact_id']
            assert h['bytes']==artifacts[h['artifact_id']]['logical_bytes']
        subjects={x['evidence_id']: 'source_revision' for x in p['claims'] if x['declared_source_revision'] is not None}
        subjects.update({x['evidence_id']: 'dependency_manifest' for x in p['dependencies']})
        pins={x['key_id']:x for x in p.get('trusted_keys',[])}
        assert len(pins)==len(p.get('trusted_keys',[]))
        assert len({x['public_key_hex'].lower() for x in pins.values()})==len(pins)
        auth={x['statement_artifact_id']:x for x in p.get('statement_authentications',[])}
        assert len(auth)==len(p.get('statement_authentications',[]))
        for a in auth.values():
            assert a['statement_artifact_id'] in artifacts
            assert evidence[a['evidence_id']]['artifact_id']==a['statement_artifact_id']
            assert all(k in pins for k in a['accepted_key_ids'])
            assert bool(a['accepted_key_ids'])==(a['status']=='verified_with_supplied_key')
            if a['status']=='no_trusted_keys': assert not pins
            if a['status']=='not_verified_with_supplied_keys': assert pins
        statements={x['evidence_id']:x for x in p.get('statement_subjects',[])}
        for statement in statements.values():
            assert statement['statement_artifact_id'] in artifacts
            if report['schema_version'] in ('1.4.0','1.5.0','1.6.0','1.7.0'):
                assert statement['authentication']==auth[statement['statement_artifact_id']]['status']
            assert evidence[statement['evidence_id']]['artifact_id']==statement['statement_artifact_id']
            assert statement['target_artifact_id'] is None or statement['target_artifact_id'] in artifacts
        seen=set()
        for check in p.get('checks', []):
            subject=check['subject_evidence_id']
            kind=check['kind']
            if kind=='statement_digest':
                assert subject in statements
                statement=statements[subject]
                if report['schema_version'] in ('1.4.0','1.5.0','1.6.0','1.7.0'): assert auth[statement['statement_artifact_id']]['evidence_id'] in check['supporting_evidence_ids']
                observed=hashes.get(statement['target_artifact_id'])
                expected=statement['declared_sha256']
                assert check['observed_value']==(observed['sha256'] if observed else None)
                expected_status=('consistent' if expected==observed['sha256'] else 'mismatch') if expected and observed else 'unresolved'
                assert check['status']==expected_status
                if observed:
                    assert observed['evidence_id'] in check['supporting_evidence_ids']
            elif kind=='cargo_selected_workspace_membership':
                member=next(x for x in projects.values() if x['evidence_id']==subject)
                assert member['ecosystem']=='cargo'
                manifest_path=artifacts[member['manifest_artifact_id']]['path'].replace('/','\\')
                assert manifest_path in selections
                root=projects.get(check['observed_value'])
                if root:
                    assert root['ecosystem']=='cargo'
                    assert root['evidence_id'] in check['supporting_evidence_ids']
                    assert ntpath.dirname(selections[manifest_path])==root['root']
                if check['status']=='consistent':
                    assert ntpath.basename(selections[manifest_path])=='Cargo.lock'
                    w=workspaces[root['id']];m=workspaces[member['id']]
                    assert w['supported'] and m['supported'] and w['has_workspace']
                    assert root['id']==member['id'] or not m['has_workspace']
                    if m['package_workspace'] is not None:
                        assert ntpath.normpath(ntpath.join(member['root'],m['package_workspace']))==root['root']
                    assert member['root'] not in [ntpath.normpath(ntpath.join(root['root'],x)) for x in w['exclude']]
                    assert (root['id']==member['id'] and member['declared_name']) or member['root'] in [ntpath.normpath(ntpath.join(root['root'],x)) for x in w['members']]
            elif kind=='cargo_lock_package_version':
                assert subject in {x['evidence_id'] for x in projects.values() if x['ecosystem']=='cargo'}
            elif kind in ('cargo_package_name','cargo_version_requirement','cargo_lock_dependency_version'):
                assert subjects[subject]=='dependency_manifest'
            else:
                assert subjects[subject]==kind
            if kind in ('cargo_lock_package_version','cargo_lock_dependency_version'):
                if kind=='cargo_lock_package_version':
                    project=next(x for x in projects.values() if x['evidence_id']==subject)
                else:
                    dependency=next(x for x in p['dependencies'] if x['evidence_id']==subject)
                    project=projects[dependency['project_id']]
                assert project['ecosystem']=='cargo'
                if check['status']!='unresolved':
                    lock_path=project['root'].rstrip('\\/')+'\\Cargo.lock'
                    manifest_path=artifacts[project['manifest_artifact_id']]['path'].replace('/','\\')
                    lock_path=selections.get(manifest_path,lock_path)
                    fingerprints={h['evidence_id']:h for h in p.get('source_hashes',[])}
                    assert any(i in fingerprints and artifacts[fingerprints[i]['artifact_id']]['path'].replace('/','\\')==lock_path.replace('/','\\') for i in check['supporting_evidence_ids'])
                    expected_project=project
                    if kind=='cargo_lock_dependency_version':
                        target=artifacts[dependency['target_artifact_id']]['path']
                        expected_project=next(x for x in projects.values() if x['root']==target and x['ecosystem']=='cargo')
                        assert expected_project['evidence_id'] in check['supporting_evidence_ids']
                        assert expected_project['declared_name']==dependency['declared_package']
                    assert expected_project['declared_name'] and expected_project['declared_version']
                    assert (check['observed_value']==expected_project['declared_version'])==(check['status']=='consistent')
            key=(subject,kind)
            assert key not in seen
            seen.add(key)
            assert all(i in evidence for i in check['supporting_evidence_ids'])
            if check['status'] != 'unresolved':
                assert check['observed_value'] is not None
                assert check['supporting_evidence_ids']
            if check['kind']=='dependency_manifest':
                assert check['status'] in ('consistent','unresolved')
                assert check['observed_value'] is None or check['observed_value'] in projects


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('report', type=Path)
    ap.add_argument('--schema', type=Path)
    args = ap.parse_args()
    report=json.loads(args.report.read_text(encoding='utf-8'))
    schema=args.schema or Path(__file__).resolve().parents[1] / 'schemas' / {'1.0.0':'report-v1.schema.json','1.1.0':'report-v1.1.schema.json','1.2.0':'report-v1.2.schema.json','1.3.0':'report-v1.3.schema.json','1.4.0':'report-v1.4.schema.json','1.5.0':'report-v1.5.schema.json','1.6.0':'report-v1.6.schema.json','1.7.0':'report-v1.7.schema.json'}[report['schema_version']]
    validate(report, json.loads(schema.read_text(encoding='utf-8')))
    print('Schema and cross-record invariants passed.')
