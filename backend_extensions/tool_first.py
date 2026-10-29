"""Deterministic planning extension for the qualified-pilot-v1 backend.

This module is installed in the backend source closure, not dynamically loaded
from a case or catalog. Existing cases retain their frozen workflow release.
"""
import json

def deterministic_plan(case):
    if case.stage_done('research_plan'):
        return
    plan = {
        'plan': 'Execute operator-approved recipes against bounded captures and local evidence. Model work is reserved for interpretation, challenge and adjudication.',
        'tool_choices': [{'id':r['id'], 'mode':r['mode'], 'phase':r['run_at']} for r in case.config.get('tool_recipes',[])],
        'missing_sources': ['Only approved sources are available. Tool outputs do not expand collection scope.'],
        'detractor': 'Check source independence, dates, extraction errors, identity ambiguity and whether citations support each conclusion.',
        'proposed_urls': [], 'tool_requests': [],
        'planning_method': 'deterministic_recipe_routing',
        'catalog_policy': 'Discovery catalogs are advisory. No source or model may install tools, execute arbitrary commands, or activate MCP services.'
    }
    path = case.root/'rounds'/'research_plan.json'
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps({'result':plan, 'receipt':{'kind':'deterministic_plan','model_called':False}},indent=2), encoding='utf-8')
    tmp.replace(path)
    case.stage('research_plan','rounds/research_plan.json')

def tools_only_complete(case):
    case.validate_claims({'claims':[]})
    case.event('tools_only_complete', {'model_called':False, 'detractor_performed':False,
        'limit':'Tool observations only. No model analysis, identity conclusion or adjudication was performed. Human review is required.'})
    case.stage('report','report.md')
    return {'phase':'complete'}
