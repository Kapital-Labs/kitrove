# Shared native signature policy

The next installer boundary must reuse native signature policy without depending on
the operator signing tool or copying its rules. This checkpoint moves the existing
Apple Developer ID requirement, timestamp/runtime inspection and Windows publisher
verification script into the release-policy library. The signing tool consumes those
same definitions. Signing orchestration, tool invocation and credentials stay in xtask.

This is a behavior-preserving consolidation, not a runtime signature verifier. Text
inspection cannot authenticate a file. Consumer integration still needs trusted tool
selection, bounded process execution, retained-file revalidation and an independently
pinned Windows publisher; ambient operator configuration cannot grant consumer trust.
Executable publication and launch remain unavailable.

The Apple tests move with their implementation and add container timestamp coverage.
The Windows script is unchanged. No new dependency, credential access, native process,
permission repair or signing run is introduced. All three policy tests and five
operator-signing tests passed, as did canonical stable and Rust 1.85.0 validation.
Final review compared the moved requirement and Windows script with their original
definitions and the Apple inspection branches with their prior acceptance rules;
no policy or native invocation change was found. Consumer runtime verification is
still unimplemented and requires its own identity and process-boundary tests.

NS-07/NS-09 and INV-06/INV-07/INV-08/INV-12 remain unchanged. Portable capabilities,
native fidelity, ownership receipts, synchronization and application rollback are
unaffected. Installer authority stays distinct from application authority.
