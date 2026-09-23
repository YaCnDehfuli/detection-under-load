# Contributions prepared for SigmaHQ

Three things the harness found in the pinned SigmaHQ tree, written up in the form
SigmaHQ asks for in `CONTRIBUTING.md`.

The Dumpert hash correction was approved by a SigmaHQ collaborator on 2026-09-21 as
[SigmaHQ/sigma#6311](https://github.com/SigmaHQ/sigma/pull/6311). The other two
findings remain drafts here so their evidence and wording can be reviewed.

| finding | what it is | status |
|---|---|---|
| [Dumpert IMPHASH correction](dumpert-imphash-correction.md) | The recorded executable form misses the hash branch because an import hash is labeled as an MD5; the separate `Dumpert.dll` command-line branch can still match other forms. | **Approved — [SigmaHQ/sigma#6311](https://github.com/SigmaHQ/sigma/pull/6311)** |
| [LSASS access-mask exclusions](lsass-access-mask-exclusions.md) | Measured evidence about one of four documented exclusions; a tuning tradeoff. | Draft |
| [Coverage mapping](coverage-mapping-issue.md) | A proposed mapping between a masquerading rule and the technique it covers. | Draft; better suited to an issue |

The remaining proposals need separate upstream discussion.
