# Compliance Mappings

A compliance mapping records how a curated profile relates to the controls or requirements of a named security and privacy framework. Where the definitions files catalog what a component can configure and the curated profiles record what to apply and why, a mapping records what the applied result contributes against a framework and what it leaves unaddressed. Each mapping covers one target and one framework, and is written for a system owner or assessor accounting for control coverage rather than for the sysadmin applying the profile.

## Available Files

### Policy

**Windows**

- [Policy-Windows-NIST-800-53.md](Policy-Windows-NIST-800-53.md) maps the 134 settings of the Windows base profile and the No Store Apps layer to NIST SP 800-53 Revision 5, Release 5.2.0. It records which control objectives the baseline supports and which it leaves unaddressed, which settings do not take effect on which Windows versions and editions, the six settings that improve one control objective at the cost of another, and the 28 catalog settings the baseline declines, each with the control objective the exclusion protects.
- [Policy-Windows-NIST-800-171.md](Policy-Windows-NIST-800-171.md) is its companion for NIST SP 800-171 Revision 2, the requirements CMMC Level 2 assesses, organized by requirement. It records which assessment objectives the baseline reaches and which remain the organization's, how each setting's 800-53 assignment carried into 800-171, the 34 settings that close a channel able to carry Controlled Unclassified Information, and the verdicts that change under 800-171.

## Naming Convention

Compliance mappings follow the pattern `Component-Target-Framework.md`. Component comes first, consistent with the definitions files and the curated profiles. Target is the operating system or application the mapping covers, matching the profile it maps. Framework is the canonical identifier of the framework mapped, and is the only name token that may contain hyphens.

Example: `Policy-Windows-NIST-800-53.md`

One target may have more than one mapping, since a target can be mapped against more than one framework. Each framework gets its own document rather than an additional column in an existing one, so that every mapping can be read, reviewed, and revised against a single framework release.

## Reading a Mapping

A mapping makes a narrow claim, and reading it as a broader one produces a false picture of a device's compliance posture.

A mapping asserts that applying a given setting advances a stated control objective. It does not assert that the baseline satisfies any control, that a device applying the baseline complies with any framework, or that the mapping is an assessment. It issues no findings. Whether a control is satisfied depends on organizational policy, procedure, monitoring, and evidence that no device configuration can supply, and much of what a configuration baseline contributes is against controls the framework itself designates as organization-implemented.

Three things are worth reading before the mapping tables. The coverage analysis states how much of each control or requirement falls to the organization rather than the system, which determines how much of it the baseline can reach at all. The scoping section states which settings do not take effect on which configurations, since one profile serves a range of Windows versions and editions and coverage should be read against the configuration being assessed. The sections on settings the baseline works against and settings it declines record the deliberate tradeoffs, and are the parts of the document a system owner most needs before applying anything.

## Mapping Principles

Every compliance mapping follows the same six principles.

1. **Baseline, not catalog.** A coverage claim can only be made about a configuration that is actually applied, so a mapping covers the curated profiles rather than the definitions files behind them. Settings cataloged but not curated appear as declined, with the control objective the exclusion protects.
2. **Support, not satisfaction.** A setting contributes to a control objective and does not satisfy a control, because every control carries obligations no setting can meet. The word satisfies appears only in explicit negation.
3. **Relationship, not linkage.** Each assignment records how the setting relates to the objective, not merely that it does: whether it advances the objective directly, advances one element of a multi-element objective, or advances it as a side effect of a different purpose. A table that draws a line without characterizing it asserts more than it establishes.
4. **Responsibility from the framework.** Where a framework publishes which controls an organization implements and which a system implements, the mapping takes that split from the framework rather than asserting its own. The division of responsibility is then the framework's position rather than the author's opinion. Where a framework publishes no such split, the mapping says so and states how it reads the split instead.
5. **Element-level reporting.** A control with lettered elements is rarely supported in full by a setting, so the mapping reports which element the baseline reaches and which remain organizational. Those elements are the granularity an assessment works from.
6. **Documented gaps.** Where no control directly covers a setting's objective, the mapping says so and assigns the nearest control at a reduced relationship rather than overstating the fit. A reader who knows the framework sees an overstated assignment immediately, and one discredits every other row.

## Framework Sources

A mapping is made against the edition of its framework that its reader is assessed under, at that edition's current release, and records the release rather than only the revision. Frameworks patch between revisions, and a mapping built from a published document that predates the current release can rest on superseded control text. The edition in force is usually the current revision. For NIST SP 800-171 it is Revision 2, which 32 CFR 170 incorporates for CMMC Level 2 although NIST has since published Revision 3.

Where a framework publishes a machine-readable form, that form is the source for control or requirement text rather than the published document. For NIST SP 800-53 it is the OSCAL catalog maintained at [usnistgov/oscal-content](https://github.com/usnistgov/oscal-content), which tracks the current release and carries the control text, the assessment objectives, and each control's implementation designation. For NIST SP 800-171 Revision 2, which has no OSCAL form, it is NIST's machine-readable requirement and assessment files. Where part of a framework exists only in the published document, as the Appendix D mapping and Appendix E tailoring tables of 800-171 Revision 2 do, the document is the source for that part.

## Related Documents

A mapping cites rather than repeats. Per-setting research and side effects live in the [definitions reference documents](../definitions/reference/). The editorial reasoning behind what the profile includes, excludes, and holds back for a layer lives in the [profile reference documents](../profiles/reference/). A mapping refers to both for detail and confines itself to what the applied result contributes against the framework.
