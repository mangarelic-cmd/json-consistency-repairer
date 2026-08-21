from pathlib import Path
import json, hashlib, platform
root=Path('/mnt/data/json_bench_work')
iso=json.loads((root/'ISOLATED_CORRUPTION_BOUNDARY.json').read_text())
security=[
 {'case':'depth_96','result':'PASS','observed':96,'limit':96},
 {'case':'depth_97','result':'REFUSE:max_depth','observed':97,'limit':96},
 {'case':'number_4096_chars','result':'PASS','observed':4096,'limit':4096},
 {'case':'number_4097_chars','result':'REFUSE:max_number_chars','observed':4097,'limit':4096},
 {'case':'key_16384_bytes','result':'PASS','observed':16384,'limit':16384},
 {'case':'key_16385_bytes','result':'REFUSE:max_key_bytes','observed':16385,'limit':16384},
 {'case':'string_8MiB','result':'PASS','observed':8388608,'limit':8388608},
 {'case':'string_8MiB_plus1','result':'REFUSE:max_string_bytes','observed':8388609,'limit':8388608},
 {'case':'nodes_1,000,000','result':'PASS','observed':1000000,'limit':1000000},
 {'case':'nodes_1,000,001','result':'REFUSE:max_nodes','observed':1000001,'limit':1000000},
]
syntax=[
 ('trailing_comma',True,'remove_trailing_commas'),('missing_comma',True,'insert_comma'),('missing_colon',True,'insert_colon'),('truncated_obj',True,'insert_object_close'),('truncated_nested',True,'close_truncated_container'),('single_quotes',False,None),('unquoted_key',False,None),('comment',False,None),('duplicate_key',False,None),('missing_quote',False,None),('extra_brace',True,'remove_unexpected_delimiter'),('two_errors',False,None),('array_trailing',True,'remove_trailing_commas'),('array_missing_comma',True,'insert_comma')]
syntax=[{'case':a,'repaired':b,'operation':c} for a,b,c in syntax]
parser_perf={
 'payload_bytes':1342235,
 'median_seconds':{'stdlib_json':0.0091,'orjson_3.11.9':0.0070,'ujson_5.12.1':0.0065,'json5_0.14.0':10.1891,'jcr_loads_strict':0.1303}
}
full_perf=[
 {'rows':10,'seconds':0.5037818850000804,'maxrss_kb':126928,'edits':2,'status':'PASS','cycles':3},
 {'rows':50,'seconds':1.3429287029998704,'maxrss_kb':130612,'edits':2,'status':'PASS','cycles':3},
 {'rows':100,'seconds':1.9408955570002036,'maxrss_kb':132696,'edits':2,'status':'PASS','cycles':3},
 {'rows':250,'seconds':4.3931057270001475,'maxrss_kb':138164,'edits':2,'status':'PASS','cycles':3},
 {'rows':500,'seconds':7.37843874400005,'maxrss_kb':147672,'edits':2,'status':'PASS','cycles':3},
 {'rows':1000,'seconds':14.298726109999734,'maxrss_kb':158124,'edits':2,'status':'PASS','cycles':3},
]
stream_perf=[
 {'records':100,'bytes':4297,'seconds':0.4861878390001948,'maxrss_kb':117456,'edits':1,'status':'PASS','cycles':4},
 {'records':1000,'bytes':45966,'seconds':3.595673738000187,'maxrss_kb':117752,'edits':1,'status':'PASS','cycles':4},
 {'records':5000,'bytes':239634,'seconds':17.05347796599972,'maxrss_kb':118868,'edits':1,'status':'PASS','cycles':4},
 {'records':7500,'bytes':364634,'seconds':25.077265113000067,'maxrss_kb':121076,'edits':1,'status':'PASS','cycles':4},
 {'records':10000,'bytes':489635,'seconds':33.44856956800004,'maxrss_kb':120720,'edits':1,'status':'PASS','cycles':4},
]
bundle_perf=[
 {'rows_per_document':10,'seconds':0.9750,'repair_ok':True,'edits':1,'status':'PASS'},
 {'rows_per_document':100,'seconds':1.8519,'repair_ok':True,'edits':1,'status':'PASS'},
 {'rows_per_document':500,'seconds':6.0038,'repair_ok':True,'edits':1,'status':'PASS'},
 {'rows_per_document':1000,'seconds':10.7909,'repair_ok':True,'edits':1,'status':'PASS'},
]
bundle_negative=[
 {'case':'case_variant_reference','status':'PASS','edits':1,'expected':'repaired'},
 {'case':'dangling_reference','status':'STABLE_WITH_REPORTED_ISSUES','edits':0,'expected':'abstain','issue':'cross_document_dangling_reference'},
 {'case':'ambiguous_target','status':'STABLE_WITH_REPORTED_ISSUES','edits':0,'expected':'abstain','issue':'ambiguous_reference_target'},
]
random_clean={'default_confidence_clean_random_trials':20,'mutated_trials':0,'total_edits':0,'statuses':{'PASS':18,'STABLE_WITH_REPORTED_ISSUES':2},'random_missing_independent_trials':30,'exact_reconstructions':0,'abstentions':30,'false_reconstructions':0,
 'relaxed_confidence_clean_random':[
  {'confidence':0.95,'trials':10,'mutated_trials':0,'edits':0}, {'confidence':0.8,'trials':10,'mutated_trials':0,'edits':0}, {'confidence':0.7,'trials':10,'mutated_trials':0,'edits':0}, {'confidence':0.6,'trials':10,'mutated_trials':0,'edits':0}]}
missing_floor={
 'arithmetic_missing':[
  {'missing':36,'clean_support':4,'exact_repaired':36,'status':'PASS'}, {'missing':37,'clean_support':3,'exact_repaired':0,'status':'PASS'}],
 'functional_balanced_missing':[
  {'clean_per_key':3,'missing':25,'exact_repaired':25,'status':'PASS'}, {'clean_per_key':2,'missing':30,'exact_repaired':0,'status':'PASS'}]
}
relaxed_repair=[
 {'kind':'functional','wrong_rate':0.2,'confidence':0.8,'exact':'8/8','false_mutations':0}, {'kind':'functional','wrong_rate':0.3,'confidence':0.7,'exact':'12/12','false_mutations':0}, {'kind':'functional','wrong_rate':0.4,'confidence':0.6,'exact':'16/16','false_mutations':0},
 {'kind':'arithmetic','wrong_rate':0.2,'confidence':0.8,'exact':'8/8','false_mutations':0}, {'kind':'arithmetic','wrong_rate':0.3,'confidence':0.7,'exact':'12/12','false_mutations':0}, {'kind':'arithmetic','wrong_rate':0.4,'confidence':0.6,'exact':'16/16','false_mutations':0},
]
advanced={'targeted_adversarial_tests':[{'name':'symmetry obstruction/minimal breaker','result':'PASS'},{'name':'immutable identifiable-but-unreachable','result':'PASS'},{'name':'active relation refutation','result':'PASS'},{'name':'blind reconstruction with target redacted','result':'PASS'},{'name':'unexplained horizon drift rejection','result':'PASS'},{'name':'distributed conflicting terminal detection','result':'PASS'}],'pytest_summary':'6 targeted tests passed (4 in 0.37s + 2 in 0.06s)'}
meta={'engine':'json-consistency-repair','version':'0.40.0','date':'2026-08-20','python':'3.13.5','cpu':'AMD EPYC 9V74; 5 vCPUs available','memory':'5.9 GiB container','source_zip_sha256':'698c070e65e7ef1b266b124d59e057a726a778f4b2561056263f4a20facc197e','wheel_sha256':'de544045dfdf6a4285da780206e07826af29440681ec2b6ae9c749db21c4e214','import_baseline_maxrss_kb':114520}
out={'metadata':meta,'semantic_isolated_corruption_boundary':iso,'missing_evidence_floor':missing_floor,'relaxed_threshold_repair':relaxed_repair,'random_false_mutation_campaigns':random_clean,'syntax_frontier':syntax,'security_boundaries':security,'parser_microbenchmark':parser_perf,'full_engine_scaling':full_perf,'streaming_scaling':stream_perf,'bundle_scaling':bundle_perf,'bundle_negative_controls':bundle_negative,'advanced_adversarial_checks':advanced}
(root/'JSON_BENCHMARK_LIMITS_V1_RESULTS.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
