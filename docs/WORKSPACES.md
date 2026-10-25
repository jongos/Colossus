# Literal Cargo workspace declaration checks

Milestone 8 checks explicitly selected manifest/lockfile associations against workspace declarations extracted from the same Cargo manifest bytes already collected. It adds no file discovery, content reads, package-manager execution or network access.

`provenance.cargo_workspaces` records one bounded declaration per observed Cargo project when within limits: project/evidence IDs, whether a workspace table exists, literal members/exclusions, optional package.workspace and a `supported` flag. At most 1,024 entries per members/exclude list, 1,024 bytes per path and 10,000 retained member/exclusion paths across the report are supported. Existing 1 MiB manifest and aggregate read budgets still apply. Unsupported field types, globs, absolute/drive paths or over-limit lists set `supported: false`; unsupported entries can be omitted. Never interpret a retained list as complete when that flag is false. Aggregate path-budget exhaustion omits the declaration and creates a coverage gap.

The new `cargo_selected_workspace_membership` check is emitted only for explicit selections whose member manifests were observed. A selected file named Cargo.lock identifies its adjacent observed Cargo.toml as the possible workspace root. Other filenames remain unresolved; the tool does not guess a root.

- `consistent`: supported literal members include the selected project, or it is the observed root package; no supported exclusion conflicts, and any explicit package.workspace pointer agrees.
- `mismatch`: the root explicitly excludes the selected member, the member points to a different inventoried location through package.workspace, or it declares its own workspace while selecting another root.
- `unresolved`: a needed declaration is missing/unsupported, exclusion or workspace-pointer paths cannot resolve within inventory, no literal member matches, or a selected filename/root is unsupported.

Relative paths resolve only against inventoried directories, using existing link and traversal guards. No parent search or external path read occurs. Globs and implicit path-dependency membership are unsupported; absence from a literal member list never proves nonmembership. Root/member evidence IDs link the comparison to observed manifests and their source fingerprints.

These checks compare declarations; they do not reproduce Cargo's workspace discovery or validation. They do not validate resolver options, default-members, inheritance, patches, features, dependency selection, intermediate workspace boundaries or successful builds. See [Cargo's workspace documentation](https://doc.rust-lang.org/cargo/reference/workspaces.html) for the broader behavior. A malformed project can still contain individually agreeing declarations.

Membership and lockfile-version checks remain separate. A version match may coexist with an exclusion or pointer conflict; neither automatically changes the caller's selected lockfile. Candidate propagation retains mismatch/unresolved blockers and every path remains protected. Schema 1.7.0 and the validator check declaration references and recorded literal consistency, not original bytes or Cargo's resolver.
