"""json-consistency-repair."""
from ._version import __version__
from .engine import RepairConfig, RepairResult, repair_file, repair_object
from .bundle import BundleRepairResult, analyze_bundle, apply_bundle_patch_set, bundle_digest, repair_bundle, repair_bundle_dir
from .streaming import StreamingConfig, StreamRepairResult, StreamingParseError, discover_stream_knowledge, iter_records, repair_stream_file
from .security import SecurityLimits, SecurityLimitError, validate_json_value
from .provenance import EXIT_CODES, MACHINE_CONTRACT, REPORT_CONTRACT, package_code_sha256, runtime_provenance
from .constraint_ir import Truth3, compile_typed_constraint_ir, compile_bundle_typed_constraint_ir, compile_stream_typed_constraint_ir
from .identifiability import ObservabilityState, IdentifiabilityState, assess_path_identifiability, compile_identifiability_registry
from .logic_exact import SATResult, solve_cnf, rule_system_certificate, evaluate_rule
from .conservation import stable_conservation_id, evaluate_conservation_rule, conservation_rule_patch, multiset_map, multiset_residue
from .modal import detect_regime, modal_analyze, recursive_morphology
from .fixedpoint import relation_snapshot, relation_delta, update_lifecycle, audit_patch_order
from .provenance_chain import build_provenance_chain, verify_provenance_chain
from .jsonpatch_exact import apply_patch, apply_candidate, replay_with_inverses
from .grammar_repair import minimal_grammar_repair
from .constraint_dsl import parse_dsl, ConstraintDSLError
from .causal_cone import authority_name, apply_authority_firewall, compile_double_cone, causal_dominance, prepare_causal_analysis
from .system_graph import analyze_system_rules, analyze_graph_rule, analyze_state_machine_rule, analyze_migration_rule, discover_graph_rules, system_summary
from .federation import federate_analysis, federation_fixed_point, compile_q_descent, q_compare, compile_stream_federation
from .multisource import analyze_multisource, source_registry, compile_identity_registry, multisource_summary
from .authority_scope import compile_authority_registry, evaluate_authority, verify_authority_registry, verify_authority_proof
from .boundary import compile_boundary_registry, apply_boundary_firewall, boundary_summary, project_numeric_boundary
from .proof_graph import compile_proof_graph, verify_proof_graph, compare_proof_graphs
from .materialization import materialize_missing_witnesses, materialization_summary
from .robust_envelope import apply_robust_envelope_firewall, robust_envelope_summary, verify_robust_envelope_certificate
from .rectification_packet import compile_rectification_packet, verify_rectification_packet, verify_rectification_packet_final, seal_rectification_packet
from .expression_ir import (ExpressionIRException, parse_expression, normalize_expression, evaluate_expression, solve_equation, compile_expression_rule, analyze_expression_rules, expression_ir_summary)
from .repair_algebra import (compile_repair_path_algebra, verify_repair_path_algebra, candidate_set_admissibility, critical_pair, action_record)
from .controllability import (apply_controllability_firewall, compile_control_plan, verify_controllability_certificate, controllability_summary)
from .relation_falsifier import (apply_relation_falsification_firewall, verify_relation_falsification_certificate, relation_falsification_summary)
from .persistent_open import (compile_open_obligation_registry, verify_open_obligation_registry, save_open_obligation_registry, load_open_obligation_registry, wake_open_obligations, verify_wake_plan, compile_proof_dependency_index, verify_proof_dependency_index, compile_incremental_recompute, verify_incremental_recompute_certificate, compile_incremental_equivalence, verify_incremental_equivalence_certificate, change_tokens_from_json_diff)
from .horizon import (compile_horizon_snapshot, verify_horizon_snapshot, compare_horizon_naturality,
    verify_horizon_naturality_certificate, compile_distributed_consistency, verify_distributed_consistency_certificate,
    compile_horizon_surface)
from .information_bounds import (minimum_fixed_width_selector_bits, compile_residual_information_bound, verify_residual_information_bound,
    compile_blind_carrier_reconstruction, verify_blind_carrier_reconstruction, verify_blind_reconstruction_trial,
    compile_residual_information_summary, verify_residual_information_summary, compile_information_surface, compile_information_bundle_surface)
from .symmetry import (compile_semantic_quotient, semantic_quotient_normal_form, semantic_quotient_digest,
    compare_modulo_semantic_quotient, compile_symmetry_obstruction, verify_semantic_quotient_certificate,
    verify_symmetry_certificate, symmetry_summary)
from .semantic_provenance import (compile_semantic_claim_registry, apply_semantic_claim_provenance_firewall,
    verify_semantic_claim_registry, verify_semantic_claim_proof, verify_semantic_firewall,
    merkle_root, merkle_inclusion, verify_merkle_inclusion, project_verified_semantic_config)

# PASS016 certifier exports are lazy by design. Importing the package must not
# pre-import json_consistency_repair.certifier, otherwise ``python -m ...certifier``
# is no longer an independent clean module entry point.
def verify_single_packet(*args, **kwargs):
    from .certifier import verify_single_packet as _verify_single_packet
    return _verify_single_packet(*args, **kwargs)

def verify_report_evidence(*args, **kwargs):
    from .certifier import verify_report_evidence as _verify_report_evidence
    return _verify_report_evidence(*args, **kwargs)

def certifier_code_sha256():
    from .certifier import certifier_code_sha256 as _certifier_code_sha256
    return _certifier_code_sha256()

__all__ = [
    "__version__", "RepairConfig", "RepairResult", "repair_file", "repair_object",
    "BundleRepairResult", "analyze_bundle", "apply_bundle_patch_set", "bundle_digest", "repair_bundle", "repair_bundle_dir",
    "StreamingConfig", "StreamRepairResult", "StreamingParseError", "discover_stream_knowledge", "iter_records", "repair_stream_file",
    "SecurityLimits", "SecurityLimitError", "validate_json_value",
    "EXIT_CODES", "MACHINE_CONTRACT", "REPORT_CONTRACT", "package_code_sha256", "runtime_provenance",
    "Truth3", "compile_typed_constraint_ir", "compile_bundle_typed_constraint_ir", "compile_stream_typed_constraint_ir",
    "ObservabilityState", "IdentifiabilityState", "assess_path_identifiability", "compile_identifiability_registry",
    "SATResult", "solve_cnf", "rule_system_certificate", "evaluate_rule",
    "stable_conservation_id", "evaluate_conservation_rule", "conservation_rule_patch", "multiset_map", "multiset_residue",
    "detect_regime", "modal_analyze", "recursive_morphology",
    "relation_snapshot", "relation_delta", "update_lifecycle", "audit_patch_order",
    "build_provenance_chain", "verify_provenance_chain",
    "apply_patch", "apply_candidate", "replay_with_inverses", "minimal_grammar_repair", "parse_dsl", "ConstraintDSLError",
    "authority_name", "apply_authority_firewall", "compile_double_cone", "causal_dominance", "prepare_causal_analysis",
    "analyze_system_rules", "analyze_graph_rule", "analyze_state_machine_rule", "analyze_migration_rule", "discover_graph_rules", "system_summary",
    "federate_analysis", "federation_fixed_point", "compile_q_descent", "q_compare", "compile_stream_federation",
    "analyze_multisource", "source_registry", "compile_identity_registry", "multisource_summary",
    "compile_authority_registry", "evaluate_authority", "verify_authority_registry", "verify_authority_proof",
    "compile_boundary_registry", "apply_boundary_firewall", "boundary_summary", "project_numeric_boundary",
    "compile_proof_graph", "verify_proof_graph", "compare_proof_graphs",
    "materialize_missing_witnesses", "materialization_summary",
    "apply_robust_envelope_firewall", "robust_envelope_summary", "verify_robust_envelope_certificate",
    "compile_rectification_packet", "verify_rectification_packet", "verify_rectification_packet_final", "seal_rectification_packet",
    "compile_semantic_claim_registry", "apply_semantic_claim_provenance_firewall", "verify_semantic_claim_registry",
    "verify_semantic_claim_proof", "verify_semantic_firewall", "merkle_root", "merkle_inclusion", "verify_merkle_inclusion", "project_verified_semantic_config",
    "ExpressionIRException", "parse_expression", "normalize_expression", "evaluate_expression", "solve_equation", "compile_expression_rule", "analyze_expression_rules", "expression_ir_summary",
    "compile_repair_path_algebra", "verify_repair_path_algebra", "candidate_set_admissibility", "critical_pair", "action_record",
    "apply_controllability_firewall", "compile_control_plan", "verify_controllability_certificate", "controllability_summary",
    "apply_relation_falsification_firewall", "verify_relation_falsification_certificate", "relation_falsification_summary",
    "compile_open_obligation_registry", "verify_open_obligation_registry", "save_open_obligation_registry", "load_open_obligation_registry",
    "wake_open_obligations", "verify_wake_plan", "compile_proof_dependency_index", "verify_proof_dependency_index",
    "compile_incremental_recompute", "verify_incremental_recompute_certificate", "compile_incremental_equivalence", "verify_incremental_equivalence_certificate", "change_tokens_from_json_diff",
    "compile_horizon_snapshot", "verify_horizon_snapshot", "compare_horizon_naturality", "verify_horizon_naturality_certificate",
    "compile_distributed_consistency", "verify_distributed_consistency_certificate", "compile_horizon_surface",
    "minimum_fixed_width_selector_bits", "compile_residual_information_bound", "verify_residual_information_bound",
    "compile_blind_carrier_reconstruction", "verify_blind_carrier_reconstruction", "verify_blind_reconstruction_trial",
    "compile_residual_information_summary", "verify_residual_information_summary", "compile_information_surface", "compile_information_bundle_surface",
    "compile_semantic_quotient", "semantic_quotient_normal_form", "semantic_quotient_digest", "compare_modulo_semantic_quotient", "compile_symmetry_obstruction", "verify_semantic_quotient_certificate", "verify_symmetry_certificate", "symmetry_summary",
    "verify_single_packet", "verify_report_evidence", "certifier_code_sha256", "compile_third_series_closure", "compile_fourth_series_closure", "compile_fifth_series_progress", "compile_fifth_series_closure",
]

from .moments import evaluate_moment_rule, analyze_moments, moment_summary

from .closure import compile_third_series_closure, compile_fourth_series_closure, compile_fifth_series_progress, compile_fifth_series_closure
