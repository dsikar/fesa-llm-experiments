# Frozen feature policy: primary-v1

This policy is fixed before any v3 inference. It is a conservative, semantics-based selection, not a selection optimized against pilot accuracy. All 20 phishing and 74 malware input columns are inventoried below. Class/category/family labels are forbidden inside feature mappings.

- **Phishing:** retain 8 direct URL counts/lengths; exclude 12 fields with unresolved derived encodings.
- **Malware:** retain 12 numeric static PE fields; exclude 62 identifiers, verdict-related counters and unresolved fields.

[Machine-readable inventory](../configs/features.toml) · [Primary configuration](../configs/primary.toml)

## Sources and interpretation

- **P1:** Chiew et al. (2019), [publisher paper](https://doi.org/10.1016/j.ins.2019.01.064), Appendix A, Table A1. The [author repository copy](https://ir.unimas.my/id/eprint/29603/1/A%20new%20hybrid.pdf) supplies feature meanings. Descriptions below are paraphrased.
- **P2:** Tan (2018), [author dataset record](https://data.mendeley.com/datasets/h3cgnj8hft/1), DOI 10.17632/h3cgnj8hft.1. Matching field names establish a candidate feature-family source; the exact lineage of the derived phishing split remains unresolved.
- **M1:** Hussain (2024), [Ransomware Dataset 2024](https://zenodo.org/records/13890887), DOI 10.5281/zenodo.13890887. The local source matches the publisher file checksum. Its binary Class target is benign versus malware, not ransomware versus benign; it contains other malware categories.
- **M2:** [Microsoft PE specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), optional-header and section-table definitions. Standards-based numeric meanings are distinguished from unsupported dataset-specific extractors.

## Encoding contract

Counts and lengths are non-negative integers. Numeric PE inputs may be unsigned decimal integers or explicit hexadecimal strings; exact integral floats from the existing CSV adapter are accepted only in the exactly representable safe-integer range. Output is canonical base-10 text. Boolean, negative, fractional, non-finite, missing, over-width and arbitrary-text inputs fail. No categorical code is translated into a guessed risk score.

PE values are checked for representation/width, not semantic validity of the executable: unusual alignment and size values are preserved. A field must not be dropped because it looks malicious. Renames such as source `SizeofStackReserve` to specification `SizeOfStackReserve` are explicit in the inventory. Section-specific fields are excluded until their extraction mapping and repeated/missing-section handling can be verified.

The primary adapters do not claim to reconstruct original feature extraction. Source lineage, grouping, missing-section treatment and data-use terms still need a dataset-level check before fresh-row collection. Confirmed uncertainty is recorded; no opaque binary/rule code is treated as established meaning.

## Leakage and timing review

File hashes are excluded as identifiers. `Class`, `Category` and `Family` are targets/target-related metadata and cannot enter a prompt as features. Named malicious/suspicious/threat counters may encode an earlier detector verdict; that is a risk finding, not proof of label leakage. Other runtime counters have unverified generating procedures and collection timing, so they are also excluded from this static primary condition. No detector-performance claim is based on this schema review.

Known excluded columns are projected out and their names recorded in private prompt metadata. Unexpected columns and target-like feature keys fail closed. Real feature values and source records are never written to public fixtures.

## Development-schema finding

The 116 existing malware query/pool records were checked without using their labels or model outcomes. Four records failed the numeric contract for `AddressOfEntryPoint`. The field is excluded for every row until a source-backed conversion is available; the records are not removed. Other selected fields passed this development-only compatibility check. This is not held-out accuracy evidence.

## Complete inventory

| Dataset | Feature | Primary | Meaning / evidence | Reason |
|---|---|---|---|---|
| phishing | `NumDots` | include | URL dot-character count. (P1:A1:1) | Direct URL measurement; no verdict or identifier string is supplied. |
| phishing | `NumDash` | include | URL hyphen-character count. (P1:A1:5) | Direct URL measurement; no verdict or identifier string is supplied. |
| phishing | `NumUnderscore` | include | URL underscore-character count. (P1:A1:9) | Direct URL measurement; no verdict or identifier string is supplied. |
| phishing | `NumQueryComponents` | include | Recorded number of URL query parts. (P1:A1:11) | Direct URL measurement; no verdict or identifier string is supplied. |
| phishing | `NumHash` | include | URL number-sign character count. (P1:A1:13) | Direct URL measurement; no verdict or identifier string is supplied. |
| phishing | `NumNumericChars` | include | Recorded count of numeric characters in the URL. (P1:A1:14) | Direct URL measurement; no verdict or identifier string is supplied. |
| phishing | `IpAddress` | exclude | Indicator concerning an IP address in the hostname. (P1:A1:17) | Binary polarity in the derived file was not independently verified. |
| phishing | `HostnameLength` | include | Character count of the URL hostname component. (P1:A1:21) | Direct URL measurement; no verdict or identifier string is supplied. |
| phishing | `PathLength` | include | Character count of the URL path component. (P1:A1:22) | Direct URL measurement; no verdict or identifier string is supplied. |
| phishing | `NumSensitiveWords` | exclude | URL keyword-match count. (P1:A1:25) | Exact keyword matching, case handling and extraction lineage are unresolved. |
| phishing | `PctExtHyperlinks` | exclude | External-link measure from webpage content. (P1:A1:27) | Percentage versus stored fraction and extractor denominator are not frozen. |
| phishing | `PctExtResourceUrls` | exclude | External-resource measure from webpage content. (P1:A1:28) | Percentage versus stored fraction and extractor denominator are not frozen. |
| phishing | `InsecureForms` | exclude | Indicator concerning form actions without HTTPS. (P1:A1:30) | Binary polarity in the derived file was not independently verified. |
| phishing | `PctNullSelfRedirectHyperlinks` | exclude | Null/self-redirect/abnormal hyperlink measure. (P1:A1:34) | Stored units, denominator and exact abnormal-link handling are unresolved. |
| phishing | `FrequentDomainNameMismatch` | exclude | Indicator concerning content-domain versus URL-domain mismatch. (P1:A1:35) | Binary polarity and domain counting/tie handling are unresolved. |
| phishing | `SubmitInfoToEmail` | exclude | Indicator concerning mailto use in webpage content. (P1:A1:39) | Binary polarity in the derived file was not independently verified. |
| phishing | `IframeOrFrame` | exclude | Indicator concerning frame elements in webpage content. (P1:A1:40) | Binary polarity in the derived file was not independently verified. |
| phishing | `MissingTitle` | exclude | Indicator concerning an empty webpage title. (P1:A1:41) | Binary polarity in the derived file was not independently verified. |
| phishing | `AbnormalExtFormActionR` | exclude | Rule-derived form-action code. (P1:A1:46) | The rule-code mapping and thresholds are unresolved; no risk ordering is assumed. |
| phishing | `PctExtNullSelfRedirectHyperlinksRT` | exclude | Rule-derived external/null/self-redirect link code. (P1:A1:48) | The rule-code mapping and thresholds are unresolved; no risk ordering is assumed. |
| malware | `md5` | exclude | File-content identifier. (M1) | Exclude identity lookup and sample memorization cues. |
| malware | `sha1` | exclude | File-content identifier. (M1) | Exclude identity lookup and sample memorization cues. |
| malware | `file_extension` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `EntryPoint` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `PEType` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `MachineType` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `magic_number` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `bytes_on_last_page` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `pages_in_file` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `relocations` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `size_of_header` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `min_extra_paragraphs` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `max_extra_paragraphs` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `init_ss_value` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `init_sp_value` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `init_ip_value` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `init_cs_value` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `over_lay_number` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `oem_identifier` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `address_of_ne_header` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `Magic` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `SizeOfCode` | include | Total code-section size in bytes. (M2:optional-header-standard-fields-image-only) | Static PE value available from file inspection without a security-tool verdict. |
| malware | `SizeOfInitializedData` | include | Total initialized-data section size in bytes. (M2:optional-header-standard-fields-image-only) | Static PE value available from file inspection without a security-tool verdict. |
| malware | `SizeOfUninitializedData` | include | Total uninitialized-data section size in bytes. (M2:optional-header-standard-fields-image-only) | Static PE value available from file inspection without a security-tool verdict. |
| malware | `AddressOfEntryPoint` | exclude | Entry-point offset relative to the preferred image base, in bytes. (M2:optional-header-standard-fields-image-only) | Unsupported hex-like strings occur; no source-backed conversion is defined. Exclude the field, not the rows. |
| malware | `BaseOfCode` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `BaseOfData` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `ImageBase` | include | Preferred load base address. (M2:optional-header-windows-specific-fields-image-only) | Static PE value available from file inspection without a security-tool verdict. |
| malware | `SectionAlignment` | include | Alignment of loaded sections, in bytes. (M2:optional-header-windows-specific-fields-image-only) | Static PE value available from file inspection without a security-tool verdict. |
| malware | `FileAlignment` | include | Alignment of section data on disk, in bytes. (M2:optional-header-windows-specific-fields-image-only) | Static PE value available from file inspection without a security-tool verdict. |
| malware | `OperatingSystemVersion` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `ImageVersion` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `SizeOfImage` | include | Loaded image extent including headers, in bytes. (M2:optional-header-windows-specific-fields-image-only) | Static PE value available from file inspection without a security-tool verdict. |
| malware | `SizeOfHeaders` | include | Aligned combined executable-header size, in bytes. (M2:optional-header-windows-specific-fields-image-only) | Static PE value available from file inspection without a security-tool verdict. |
| malware | `Checksum` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `Subsystem` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `DllCharacteristics` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `SizeofStackReserve` | include | Reserved stack capacity in bytes. (M2:optional-header-windows-specific-fields-image-only) | Static PE value available from file inspection without a security-tool verdict. |
| malware | `SizeofStackCommit` | include | Initially committed stack capacity in bytes. (M2:optional-header-windows-specific-fields-image-only) | Static PE value available from file inspection without a security-tool verdict. |
| malware | `SizeofHeapCommit` | include | Initially committed heap capacity in bytes. (M2:optional-header-windows-specific-fields-image-only) | Static PE value available from file inspection without a security-tool verdict. |
| malware | `SizeofHeapReserve` | include | Reserved heap capacity in bytes. (M2:optional-header-windows-specific-fields-image-only) | Static PE value available from file inspection without a security-tool verdict. |
| malware | `LoaderFlags` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `text_VirtualSize` | exclude | Loaded .text section extent in bytes. (M2:section-table-section-headers) | Section selection, repeated/missing-section handling and conversion are unresolved. |
| malware | `text_VirtualAddress` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `text_SizeOfRawData` | exclude | Initialized .text section data on disk, in bytes. (M2:section-table-section-headers) | Section selection, repeated/missing-section handling and conversion are unresolved. |
| malware | `text_PointerToRawData` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `text_PointerToRelocations` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `text_PointerToLineNumbers` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `text_Characteristics` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `rdata_VirtualSize` | exclude | Loaded .rdata section extent in bytes. (M2:section-table-section-headers) | Section selection, repeated/missing-section handling and conversion are unresolved. |
| malware | `rdata_VirtualAddress` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `rdata_SizeOfRawData` | exclude | Initialized .rdata section data on disk, in bytes. (M2:section-table-section-headers) | Section selection, repeated/missing-section handling and conversion are unresolved. |
| malware | `rdata_PointerToRawData` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `rdata_PointerToRelocations` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `rdata_PointerToLineNumbers` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `rdata_Characteristics` | exclude | PE/DOS, symbolic or metadata column outside the frozen numeric subset. (M1) | Symbolic/legacy/duplicate field or unresolved conversion; not inferred from its name. |
| malware | `registry_read` | exclude | Recorded counter; exact generating procedure is unverified. (M1) | Cannot establish units, execution conditions or prediction-time availability. |
| malware | `registry_write` | exclude | Recorded counter; exact generating procedure is unverified. (M1) | Cannot establish units, execution conditions or prediction-time availability. |
| malware | `registry_delete` | exclude | Recorded counter; exact generating procedure is unverified. (M1) | Cannot establish units, execution conditions or prediction-time availability. |
| malware | `registry_total` | exclude | Recorded counter; exact generating procedure is unverified. (M1) | Cannot establish units, execution conditions or prediction-time availability. |
| malware | `network_threats` | exclude | Field named for a security judgment or suspicious/threat count. (M1) | Potential proxy for a pre-existing security verdict; timing and label independence unresolved. |
| malware | `network_dns` | exclude | Recorded counter; exact generating procedure is unverified. (M1) | Cannot establish units, execution conditions or prediction-time availability. |
| malware | `network_http` | exclude | Recorded counter; exact generating procedure is unverified. (M1) | Cannot establish units, execution conditions or prediction-time availability. |
| malware | `network_connections` | exclude | Recorded counter; exact generating procedure is unverified. (M1) | Cannot establish units, execution conditions or prediction-time availability. |
| malware | `processes_malicious` | exclude | Field named for a security judgment or suspicious/threat count. (M1) | Potential proxy for a pre-existing security verdict; timing and label independence unresolved. |
| malware | `processes_suspicious` | exclude | Field named for a security judgment or suspicious/threat count. (M1) | Potential proxy for a pre-existing security verdict; timing and label independence unresolved. |
| malware | `processes_monitored` | exclude | Recorded counter; exact generating procedure is unverified. (M1) | Cannot establish units, execution conditions or prediction-time availability. |
| malware | `total_procsses` | exclude | Recorded counter; exact generating procedure is unverified. (M1) | Cannot establish units, execution conditions or prediction-time availability. |
| malware | `files_malicious` | exclude | Field named for a security judgment or suspicious/threat count. (M1) | Potential proxy for a pre-existing security verdict; timing and label independence unresolved. |
| malware | `files_suspicious` | exclude | Field named for a security judgment or suspicious/threat count. (M1) | Potential proxy for a pre-existing security verdict; timing and label independence unresolved. |
| malware | `files_text` | exclude | Recorded counter; exact generating procedure is unverified. (M1) | Cannot establish units, execution conditions or prediction-time availability. |
| malware | `files_unknown` | exclude | Recorded counter; exact generating procedure is unverified. (M1) | Cannot establish units, execution conditions or prediction-time availability. |
| malware | `dlls_calls` | exclude | Recorded counter; exact generating procedure is unverified. (M1) | Cannot establish units, execution conditions or prediction-time availability. |
| malware | `apis` | exclude | Recorded counter; exact generating procedure is unverified. (M1) | Cannot establish units, execution conditions or prediction-time availability. |
