## Summary

<!--
What changed and why. Bullet points are fine. If this closes an audit
finding or issue, name it (e.g. "This is audit finding C-23" or "Closes #123").
-->

-

## Test plan

<!-- Check off what you ran. Add rows for anything project-specific. -->

- [ ] `Invoke-ScriptAnalyzer` per CLAUDE.md's Development Commands (`Public`, `Private`, `Checks`, `MET.psm1`, `MET.psd1`, `Tests`) — 0 blocking findings
- [ ] Unit suite (`./Tests/Unit`) — passed / failed / skipped counts
- [ ] Integration suite (`./Tests/Integration`) — passed / failed counts
- [ ] Playwright HTML report tests (`Tests/Html`), if `Get-METReport`'s HTML/JS changed
- [ ] `Test-ModuleManifest -Path ./MET.psd1`, if `MET.psd1` changed
- [ ] Manual verification, if applicable (describe what you ran and observed)
