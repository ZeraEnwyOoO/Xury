# Xury
NAt lib
              🏆 XURY NAT ESPORTS

        TEAM A                 TEAM B
      5 NETWORK DEVS         5 NETWORK DEVS

      🧭 Scout                 🧭 Scout
      🔨 Hole Punch            🔨 Hole Punch
      🔑 Port Strategy          🌐 IPv6
      🧠 Predictor              ⚡ Blitz
      👑 Weapon Captain         👑 Weapon Captain

                VS

             █████████
             NAT WALL
             █████████

             💰 PRIZE


in develop so idk what to write
<img width="736" height="414" alt="Ryo in friend pc" src="https://github.com/user-attachments/assets/842068da-8e1a-448f-a978-2ae7395e3a0c" />
 
◄ 0s ◎ make run                                                  □ Xury 
═══════════════════════════════════════════
 Running Xury tests
═══════════════════════════════════════════

── build/tests/api/test_version ──
=== test/unit/api/test_version.c ===
  running test_version_string_not_null
  running test_version_string_matches_macro
  running test_build_commit_not_null
  running test_build_date_not_null
  running test_build_type_not_null
  running test_build_platform_not_null
  running test_api_version_positive
  running test_version_code_matches_macro
  running test_version_code_layout
  running test_parse_valid_full
  running test_parse_leading_v
  running test_parse_partial
  running test_parse_rejects_garbage
  running test_parse_rejects_overflow
  running test_parse_roundtrip_of_library_version
  running test_compare_less
  running test_compare_equal
  running test_compare_greater
  running test_compare_matches_at_least_macro
  running test_about_not_null_and_nonempty
  running test_about_starts_with_xury
  running test_tag_not_null_and_contains_version
  running test_full_not_null
  running test_cache_prefix_shape
  running test_self_check_ok
  running test_self_check_is_idempotent
--- 26/26 tests, 65 assertions, 0 failed ---

── build/tests/api/test_types ──
=== test/unit/api/test_types.c ===
  running test_endpoint_clear
  running test_endpoint_clear_null
  running test_endpoint_equal_basic
  running test_endpoint_equal_null
  running test_endpoint_valid
  running test_canonicalize_null
  running test_canonicalize_ipv4
  running test_canonicalize_ipv6_lowercases
  running test_canonicalize_ipv6_compresses
  running test_canonicalize_rejects_mismatched_family
  running test_canonicalize_rejects_garbage
  running test_is_loopback
  running test_is_link_local
  running test_is_multicast
  running test_is_private
  running test_is_private_v6_ula
  running test_is_global_v6
  running test_endpoint_hash_equal_for_equal
  running test_endpoint_hash_differs_for_diff_port
  running test_endpoint_hash_null
  running test_endpoint_compare
  running test_to_string_ipv4
  running test_to_string_ipv6
  running test_to_string_null
  running test_to_string_buffer_too_small
  running test_from_string_ipv4
  running test_from_string_ipv6
  running test_from_string_rejects_bad
  running test_from_string_roundtrip
  running test_peer_id_clear
  running test_peer_id_clear_null
  running test_peer_id_is_zero
  running test_peer_id_equal
  running test_peer_id_hash
  running test_peer_id_compare
  running test_peer_id_to_string
  running test_peer_id_to_string_small_buf
  running test_peer_id_from_string
  running test_peer_id_from_string_bad
  running test_peer_id_roundtrip
  running test_peer_id_random_is_not_implemented
--- 41/41 tests, 123 assertions, 0 failed ---

── build/tests/api/test_err ──
=== test/unit/api/test_err.c ===
  running test_strerror_ok
  running test_strerror_timeout
  running test_strerror_never_null
  running test_err_tag
  running test_err_is_ok_inline
  running test_err_is_error_inline
  running test_err_class
  running test_err_class_name
  running test_table_size_positive
  running test_table_at_out_of_range
  running test_table_at_valid
  running test_table_contains_ok_first
  running test_table_symbols_unique
  running test_table_codes_unique
  running test_by_symbol
  running test_by_symbol_returns_same_as_info
  running test_info_known
  running test_info_unknown
  running test_not_calibrated_exists
  running test_not_calibrated_strerror
  running test_not_calibrated_class
  running test_research_class_distinct
  running test_from_errno_zero_is_ok
  running test_from_errno_common
  running test_from_errno_unknown_falls_back_to_io
  running test_from_errno_ctx_matches_plain
  running test_to_errno_ok
  running test_to_errno_common
  running test_to_errno_unknown_falls_back_to_eio
  running test_to_errno_not_calibrated_is_eio
  running test_errno_roundtrip_for_known_pairs
  running test_is_retryable
  running test_is_fatal
  running test_is_benign
  running test_classification_mutually_consistent
  running test_last_errno_starts_clear
  running test_last_errno_set_get
  running test_last_errno_overwrites
  running test_context_starts_empty
  running test_context_push_pop
  running test_context_push_null_is_noop
  running test_context_push_truncates_label
  running test_context_push_bounded
  running test_context_format_empty
  running test_context_format_chain
  running test_context_format_truncation
  running test_context_at_out_of_range
--- 47/47 tests, 5372 assertions, 0 failed ---

── build/tests/api/test_weapon ──
=== test/unit/api/test_weapon.c ===
  running test_table_size
  running test_table_at_out_of_range
  running test_table_at_none_first
  running test_table_every_entry_well_formed
  running test_table_tags_unique
  running test_get_info_valid
  running test_get_info_invalid
  running test_info_or_null_matches_get_info
  running test_weapon_tag
  running test_weapon_name_not_null
  running test_weapon_category
  running test_weapon_category_tag
  running test_has_flag
  running test_has_flag_invalid
  running test_base_strength_range
  running test_base_cost_range
  running test_base_strength_ipv6_is_max
  running test_base_cost_ipv6_is_cheap
  running test_strength_cost_invalid
  running test_priority_range
  running test_priority_unique
  running test_priority_ipv6_first
  running test_priority_lan_second
  running test_priority_birthday_last
  running test_priority_invalid
  running test_at_priority_roundtrip
  running test_at_priority_out_of_range
  running test_applicable_invalid_weapon
  running test_applicable_null_ctx_blocks_aggressive
  running test_applicable_ipv6_needs_ipv6
  running test_applicable_ipv6_needs_global
  running test_applicable_lan_needs_same_lan
  running test_applicable_upnp_needs_upnp
  running test_applicable_hole_needs_peer
  running test_applicable_predict_needs_predictable
  running test_applicable_birthday_needs_symmetric_or_cgnat
  running test_applicable_relay_needs_helper
  running test_applicable_aggressive_needs_opt_in
  running test_applicable_mask_empty_context
  running test_applicable_mask_full_context
  running test_applicable_mask_null_ctx_blocks_aggressive
  running test_mask_count
  running test_mask_next_priority_order
  running test_mask_next_null_mask
  running test_mask_next_empty
  running test_mask_format_empty
  running test_mask_format_single
  running test_mask_format_multiple_priority_order
  running test_mask_format_truncation
  running test_from_tag_all
  running test_from_tag_invalid
  running test_mask_from_string_single
  running test_mask_from_string_multiple
  running test_mask_from_string_whitespace
  running test_mask_from_string_unknown_counted
  running test_mask_from_string_none_is_silent
  running test_mask_from_string_null
  running test_mask_from_string_empty
  running test_mask_from_string_roundtrip
--- 59/59 tests, 441 assertions, 0 failed ---

── build/tests/api/test_config ──
=== test/unit/api/test_config.c ===
  running test_validate_null
  running test_validate_zero_ok
  running test_validate_explicit_version_ok
  running test_validate_bad_struct_version
  running test_validate_bad_strategy
  running test_validate_weapon_mask_unknown_bit
  running test_validate_weapon_mask_none_bit
  running test_validate_weapon_mask_ok
  running test_validate_timeout_too_small
  running test_validate_timeout_too_large
  running test_validate_timeout_ok
  running test_validate_max_parallel_out_of_range
  running test_validate_interface_not_terminated
  running test_validate_allocator_partial
  running test_validate_allocator_all_set
  running test_validate_storage_partial
  running test_validate_storage_both_set
  running test_defaults_null_args
  running test_defaults_zero_fills_everything
  running test_defaults_preserves_explicit_values
  running test_defaults_explicit_version_keeps_booleans_off
  running test_normalize_null
  running test_normalize_clamps_scan_timeout
  running test_normalize_clamps_max_parallel
  running test_normalize_aggressive_gate
  running test_normalize_aggressive_allowed
  running test_normalize_sweet_needs_traversal
  running test_normalize_upgrade_needs_relay
  running test_normalize_disables_phases_when_no_weapons
  running test_normalize_is_idempotent
  running test_weapon_enabled_null
  running test_weapon_enabled_invalid
  running test_weapon_enabled_bit_set
  running test_effective_timeout_null
  running test_effective_timeout_zero_uses_default
  running test_effective_timeout_explicit
  running test_fingerprint_null_is_zero
  running test_fingerprint_deterministic
  running test_fingerprint_changes_with_weapons
  running test_fingerprint_ignores_hooks
  running test_fingerprint_changes_with_timeout
  running test_fingerprint_changes_with_strategy
  running test_fingerprint_includes_interface
--- 43/43 tests, 100 assertions, 0 failed ---

── build/tests/core/test_mem ──
=== test/unit/core/test_mem.c ===
  running test_alloc_zero_returns_null
  running test_alloc_basic
  running test_alloc_zero_fills
  running test_realloc_null_is_alloc
  running test_realloc_zero_frees
  running test_free_null_is_noop
  running test_custom_allocator_is_used
  running test_custom_allocator_fallback_when_incomplete
  running test_size_mul_ok
  running test_size_mul_zero
  running test_size_mul_overflow
  running test_size_mul_null_out
  running test_size_add_ok
  running test_size_add_overflow
  running test_size_add_mul_ok
  running test_size_add_mul_overflow_mul
  running test_size_add_mul_overflow_add
  running test_alloc_array_ok
  running test_alloc_array_overflow
  running test_alloc_array_zero_ok
  running test_zero
  running test_zero_null_is_noop
  running test_copy
  running test_copy_null_is_noop
  running test_move_overlap_forward
  running test_move_overlap_backward
  running test_compare
  running test_compare_zero_len
  running test_compare_null
  running test_is_zero
  running test_stats_reset
  running test_stats_alloc_increments
  running test_stats_get_null_is_noop
--- 33/33 tests, 140 assertions, 0 failed ---

── build/tests/core/test_log ──
=== test/unit/core/test_log.c ===
  running test_init_sets_fields
  running test_init_clamps_level
  running test_init_null_is_noop
  running test_set_get_level
  running test_get_level_null
  running test_enabled_respects_level
  running test_enabled_null
  running test_raw_emits
  running test_raw_filters_below_level
  running test_raw_null_hook_counts
  running test_fmt_specs
  running test_fmt_hex
  running test_fmt_ll
  running test_fmt_zu
  running test_fmt_pointer
  running test_fmt_percent
  running test_fmt_unknown_is_literal
  running test_fmt_null_string
  running test_fmt_truncates_safely
  running test_fmt_via_va
  running test_fmt_u64_basic
  running test_fmt_i64_basic
  running test_fmt_hex_basic
  running test_fmt_truncation_returns_would_be
  running test_fmt_errno_with_value
  running test_fmt_errno_without_value
--- 26/26 tests, 50 assertions, 0 failed ---

── build/tests/core/test_endian ──
=== test/unit/core/test_endian.c ===
  running test_bswap16
  running test_bswap32
  running test_bswap64
  running test_htobe_be16toh_roundtrip
  running test_htobe_be32toh_roundtrip
  running test_htobe_be64toh_roundtrip
  running test_htole_le16toh_roundtrip
  running test_htole_le32toh_roundtrip
  running test_htole_le64toh_roundtrip
  running test_be16_put_get
  running test_be32_put_get
  running test_be64_put_get
  running test_be_sequential_offsets
  running test_le16_put_get
  running test_le32_put_get
  running test_le64_put_get
  running test_be16_peek
  running test_be32_peek
  running test_be64_peek
  running test_peek_does_not_advance
  running test_null_safety
--- 21/21 tests, 90 assertions, 0 failed ---

── build/tests/core/test_bytes ──
=== test/unit/core/test_bytes.c ===
  running test_cursor_init
  running test_cursor_init_null
  running test_cursor_reset
  running test_cursor_remaining_null
  running test_get_be16
  running test_get_be32
  running test_get_be64
  running test_get_be_short_buffer
  running test_get_le16
  running test_get_le32
  running test_get_le64
  running test_get_raw
  running test_get_raw_zero_len
  running test_get_raw_short
  running test_get_slice
  running test_get_slice_short
  running test_skip
  running test_get_lp8
  running test_get_lp8_max_exceeded
  running test_get_lp8_short_payload
  running test_get_lp8_str
  running test_put_be16
  running test_put_be32
  running test_put_be64
  running test_put_be_short_buffer
  running test_put_le16
  running test_put_le32
  running test_put_le64
  running test_put_raw
  running test_put_zero
  running test_put_lp8
  running test_put_lp8_too_long
  running test_put_lp8_str
  running test_is_zero
  running test_equal_ct
  running test_roundtrip_be
  running test_roundtrip_lp8_str
--- 37/37 tests, 112 assertions, 0 failed ---

── build/tests/core/test_rand ──
=== test/unit/core/test_rand.c ===
  running test_mix64_zero
  running test_mix64_deterministic
  running test_mix64_different_inputs
  running test_mix64_avalanche
  running test_fast_seed_reproducible
  running test_fast_seed_zero_ok
  running test_fast_different_seeds_differ
  running test_fast_u32_not_stuck
  running test_fast_below_range
  running test_fast_below_zero
  running test_fast_below_covers_range
  running test_fast_bytes_fills_buffer
  running test_fast_bytes_zero_len
  running test_fast_bytes_null
  running test_fast_lazy_seed_works
  running test_secure_fill_inval
  running test_secure_zero_len_ok
  running test_secure_u32_inval
  running test_secure_u64_inval
  running test_secure_below_inval
  running test_secure_not_implemented_until_phase_d
--- 21/21 tests, 2039 assertions, 0 failed ---

── build/tests/core/test_sock ──
=== test/unit/core/test_sock.c ===
  running test_sock_init
  running test_sock_init_idempotent
  running test_sock_shutdown_is_noop
  running test_create_null_out
  running test_create_bad_family
  running test_create_bad_type
  running test_create_out_zeroed_on_inval
  running test_create_udp_v4
  running test_create_udp_v6
  running test_create_tcp_v4
  running test_close_invalid_is_ok
  running test_bind_invalid_handle
  running test_bind_null_endpoint
  running test_bind_bad_family
  running test_bind_honest
  running test_local_invalid
  running test_local_honest
  running test_set_reuseaddr_invalid
  running test_set_nonblocking_invalid
  running test_set_ttl_invalid
  running test_set_interface_invalid
  running test_sendto_invalid_handle
  running test_sendto_null_buf
  running test_sendto_null_to
  running test_sendto_bad_family
  running test_recvfrom_invalid_handle
  running test_recvfrom_null_out_len
  running test_recvfrom_zeroes_outputs
  running test_connect_invalid
  running test_connect_bad_family
  running test_wait_writable_invalid
  running test_wait_readable_invalid
  running test_not_implemented_contract
--- 33/33 tests, 44 assertions, 0 failed ---

── build/tests/scan/test_math ──
=== test/unit/scan/test_math.c ===
  running test_mean_null
  running test_mean_zero_n
  running test_mean_single
  running test_mean_two
  running test_mean_even_count
  running test_mean_odd_count
  running test_mean_all_same
  running test_mean_large_values
  running test_variance_null
  running test_variance_zero_n
  running test_variance_single
  running test_variance_all_same
  running test_variance_two_points
  running test_variance_known_sequence
  running test_variance_population_not_sample
  running test_slope_null
  running test_slope_zero_n
  running test_slope_single
  running test_slope_flat
  running test_slope_step_one
  running test_slope_step_two
  running test_slope_negative
  running test_slope_known_two_points
  running test_slope_known_nonperfect
  running test_monotonic_null
  running test_monotonic_zero_n
  running test_monotonic_single
  running test_monotonic_strictly_increasing
  running test_monotonic_non_strictly_increasing
  running test_monotonic_all_same
  running test_monotonic_decreasing
  running test_monotonic_one_drop
  running test_monotonic_only_at_end
  running test_predict_null
  running test_predict_zero_n
  running test_predict_single
  running test_predict_step_one
  running test_predict_step_two
  running test_predict_flat
  running test_predict_rounds_slope
  running test_predict_clamp_low
  running test_predict_clamp_high
  running test_predict_never_zero_port
--- 43/43 tests, 43 assertions, 0 failed ---

── build/tests/scan/test_sensing ──
=== test/unit/scan/test_sensing.c ===
  running test_null_out
  running test_null_out_does_not_crash
  running test_returns_ok
  running test_status_is_never_skipped
  running test_status_failed_implies_no_interface
  running test_status_ok_or_partial_implies_has_interface
  running test_has_interface_is_true_on_typical_host
  running test_gateway_mac_known_is_always_false
  running test_gateway_mac_is_zeroed
  running test_net_type_is_unknown
  running test_ipv6_global_matches_local_ipv6
  running test_ipv6_global_false_when_no_local_ipv6
  running test_local_ipv4_family_is_inet_or_unspec
  running test_local_ipv6_family_is_inet6_or_unspec
  running test_local_ipv4_port_is_zero
  running test_gateway_unspec_on_partial
  running test_gateway_family_is_inet_or_inet6_or_unspec
  running test_interface_name_terminated
  running test_interface_name_nonempty_when_has_interface
  running test_interface_name_empty_when_failed
  running test_elapsed_ms_is_recorded
  running test_consistent_between_calls
--- 22/22 tests, 48 assertions, 0 failed ---

── build/tests/scan/test_probing ──
=== test/unit/scan/test_probing.c ===
  running test_null_out
  running test_zero_peer_count
  running test_null_peers_with_nonzero_count
  running test_null_peers_with_zero_count
  running test_inval_leaves_out_untouched
  running test_returns_ok_when_peer_does_not_answer
  running test_status_failed_when_no_response
  running test_status_is_never_skipped
  running test_no_external_ports_when_no_response
  running test_no_rtt_samples_when_no_response
  running test_no_peer_reachable_when_no_response
  running test_ttl_fields_are_zero
  running test_sample_count_within_cap
  running test_rtt_count_within_cap
  running test_external_ports_known_matches_sample_count
  running test_failed_implies_no_samples
  running test_multiple_unreachable_peers
  running test_elapsed_ms_written
  running test_consistent_between_calls
--- 19/19 tests, 136 assertions, 0 failed ---

── build/tests/scan/test_scan ──
=== test/unit/scan/test_scan.c ===
  running test_run_null_ctx
  running test_run_null_out
  running test_run_null_both
  running test_quick_null_ctx
  running test_quick_null_out
  running test_result_is_reset_before_pipeline
  running test_sensing_runs_when_scan_enabled
  running test_probing_skipped_without_peer
  running test_math_skipped_without_samples
  running test_analysis_status_matches_inputs
  running test_ok_matches_analysis_status
  running test_quick_never_probes
  running test_quick_runs_sensing
  running test_quick_ok_matches_sensing
  running test_cache_round_trip_when_network_identified
  running test_no_cache_when_storage_null
  running test_total_elapsed_written
  running test_nat_type_str
  running test_nat_label_str
  running test_cgnat_type_str
  running test_network_type_str
  running test_scan_sub_status_str
  running test_scan_disabled_skips_sensing
  running test_cache_disabled_skips_memory
--- 24/24 tests, 75 assertions, 0 failed ---

── build/tests/analysis/test_classify ──
=== test/unit/analysis/test_classify.c ===
  running test_null_cfg
  running test_null_out
  running test_null_both
  running test_insufficient_null_ports
  running test_insufficient_zero_n
  running test_insufficient_below_min
  running test_exactly_min_is_sufficient
  running test_sequential_step_one
  running test_sequential_step_one_longer
  FAIL test/unit/analysis/test_classify.c:196
    expected: out.pattern == XURY_PATTERN_SEQUENTIAL_LIKE
    detail  : out.pattern=3, XURY_PATTERN_SEQUENTIAL_LIKE=1
    test_sequential_step_one_longer FAILED
  running test_sequential_predicted_is_not_zero
  running test_fixed_step_two
  FAIL test/unit/analysis/test_classify.c:232
    expected: out.pattern == XURY_PATTERN_FIXED_STEP_LIKE
    detail  : out.pattern=3, XURY_PATTERN_FIXED_STEP_LIKE=2
    test_fixed_step_two FAILED
  running test_fixed_step_ten
  FAIL test/unit/analysis/test_classify.c:244
    expected: out.pattern == XURY_PATTERN_FIXED_STEP_LIKE
    detail  : out.pattern=3, XURY_PATTERN_FIXED_STEP_LIKE=2
    test_fixed_step_ten FAILED
  running test_fixed_step_negative
  running test_fixed_step_zero
  running test_random_high_variance
  running test_random_slope_not_near_integer
  running test_random_predicted_is_zero
  running test_confidence_low_at_min
  running test_confidence_medium
  running test_confidence_high
  running test_confidence_high_well_above
  running test_confidence_medium_also_for_random
  running test_sequential_with_single_repeat
  FAIL test/unit/analysis/test_classify.c:455
    expected: out.pattern == XURY_PATTERN_SEQUENTIAL_LIKE
    detail  : out.pattern=3, XURY_PATTERN_SEQUENTIAL_LIKE=1
    test_sequential_with_single_repeat FAILED
  running test_pattern_name
  running test_confidence_name
--- 21/25 tests, 77 assertions, 4 failed ---

── build/tests/analysis/test_score ──
=== test/unit/analysis/test_score.c ===
  running test_score_table_has_eleven
  running test_score_table_names_unique
  running test_score_table_entries_non_null
  running test_all_return_not_calibrated
  running test_all_leave_out_untouched_on_not_calibrated
  running test_all_reject_null_out
  running test_null_r_same_as_populated
  running test_score_calibrated_is_false
  running test_score_calibrated_is_stable
  running test_smoke_ipv6
  running test_smoke_lan
  running test_smoke_upnp
  running test_smoke_natpmp
  running test_smoke_pcp
  running test_smoke_hole
  running test_smoke_predict
  running test_smoke_birthday
  running test_smoke_mirror
  running test_smoke_relay
  running test_smoke_upgrade
--- 20/20 tests, 190 assertions, 0 failed ---

── build/tests/analysis/test_analysis ──
=== test/unit/analysis/test_analysis.c ===
  running test_null_sensing
  running test_null_probing
  running test_null_out
  running test_all_null
  running test_status_ok_when_both_succeed
  running test_status_partial_when_only_sensing
  running test_status_partial_when_only_probing
  running test_status_failed_when_both_fail
  running test_status_partial_when_sensing_partial
  running test_status_partial_when_probing_partial
  running test_ipv6_viable_true_only_when_both
  running test_ipv6_viable_false_when_probing_failed
  running test_peer_reachable_matches_probing
  running test_lan_viable_always_false
  running test_nat_type_always_unknown
  running test_nat_type_unknown_on_all_inputs
  running test_recommended_weapon_none
  running test_recommended_weapon_none_across_cases
  running test_elapsed_ms_written
--- 19/19 tests, 71 assertions, 0 failed ---

── build/tests/smart/test_cache ──
=== test/unit/smart/test_cache.c ===
  running test_load_null_out
  running test_store_null_analysis
  running test_load_with_null_storage
  running test_load_with_zero_key
  running test_store_with_null_storage
  running test_store_with_zero_key
  running test_round_trip_fresh_entry
  running test_round_trip_with_ttl_zero
  running test_load_with_wrong_key
  running test_load_bad_magic
  running test_load_bad_version
  running test_load_short_blob
  running test_invalidate_clears_entry
  running test_invalidate_null_storage
  running test_invalidate_zero_key
  running test_load_broken_storage_is_not_fatal
  running test_store_broken_storage_is_error
  running test_load_status_consistent_with_flags
--- 18/18 tests, 69 assertions, 0 failed ---

── build/tests/smart/test_early_term ──
=== test/unit/smart/test_early_term.c ===
  running test_null_sensing
  running test_null_memory
  running test_null_out
  running test_all_null
  running test_nothing_fires
  running test_nothing_fires_without_probing
  running test_ipv6_global_fires
  running test_ipv6_global_fires_with_partial_sensing
  running test_ipv6_global_requires_local_v6
  running test_ipv6_global_requires_peer_v6
  running test_ipv6_global_requires_probing_ok
  running test_ipv6_global_requires_sensing_data
  running test_cached_fresh_fires
  running test_cached_fresh_fires_without_probing
  running test_cached_fresh_requires_loaded
  running test_cached_fresh_requires_valid
  running test_cached_fresh_requires_status_ok
  running test_cached_ipv6_fires
  FAIL test/unit/smart/test_early_term.c:406
    expected: d.reason == XURY_EARLY_TERM_CACHED_IPV6
    detail  : d.reason=1, XURY_EARLY_TERM_CACHED_IPV6=3
    test_cached_ipv6_fires FAILED
  running test_cached_ipv6_requires_classified_cache
  FAIL test/unit/smart/test_early_term.c:417
    expected: !d.terminate
    test_cached_ipv6_requires_classified_cache FAILED
  running test_cached_ipv6_requires_loaded
  FAIL test/unit/smart/test_early_term.c:430
    expected: !d.terminate
    test_cached_ipv6_requires_loaded FAILED
  running test_cached_ipv6_requires_ipv6_facts
  running test_ipv6_global_beats_cached_fresh
  running test_cached_fresh_beats_cached_ipv6
  running test_reason_names
  running test_decision_cleared_when_nothing_fires
--- 22/25 tests, 68 assertions, 3 failed ---

═══════════════════════════════════════════
 Passed: 18   Failed: 2
═══════════════════════════════════════════
make: *** [Makefile:173: run] Error 1
                                                                                     
◄ 17s ○                                                          □ Xury 
fuck 
