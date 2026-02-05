# Analysis: "The term 'if' is not recognized" Error

## Summary

When running `Get-WorkstationDiscovery.ps1` (e.g. with `-ConfigFile`, `-PlantId`, `-ExcludeConfigFiles`), the script can fail with:

```
The term 'if' is not recognized as the name of a cmdlet, function, script file, or operable program.
```

The error is reported at the **rethrow** in the outer catch (e.g. line ~3508: `throw "Discovery failed: $errorMessage"`). The **actual** failure occurs earlier, somewhere in the main try block or in the helper module; the message is preserved and rethrown.

---

## Root Causes (Two Possibilities)

### 1. PowerShell Constrained Language Mode (Most Likely on Locked-Down Systems)

In **Constrained Language Mode**, PowerShell restricts language features. The `if` **keyword** is not available and is treated as a **command name**. So when the engine hits a line that uses `if`, it tries to run a cmdlet/function named "if", which does not exist → "The term 'if' is not recognized...".

- **When it applies**: Often enforced by WDAC, AppLocker, or group policy. Common on jump servers, shared workstations, or locked-down domains.
- **You cannot fix it from inside the script**: You cannot change language mode from within a constrained session.
- **Resolution**: Run the script from a session in **Full Language** mode (different machine, different policy, or policy change). The script now checks language mode at startup and exits with a clear message if it is Constrained/Restricted/NoLanguage.

### 2. Parser Ambiguity: `if` as Expression (Older or Strict Hosts)

The pattern **`$variable = if (condition) { value1 } else { value2 }`** uses `if` as an **expression** (not a statement). Some PowerShell hosts or runspaces parse this so that `if` is interpreted as the start of a **command**, which again leads to "The term 'if' is not recognized".

- **When it applies**: Older Windows PowerShell builds, certain hosts, or constrained/minimal session states.
- **Resolution**: Avoid **if-as-expression** everywhere. Use normal statements instead, e.g.:
  - `$x = $default; if (condition) { $x = value }`  
  - or compute the value in a variable with `if (cond) { $v = a } else { $v = b }` and then assign `Property = $v` in hashtables.

---

## What Was Changed (Methodical Fixes)

### Commits in the Last ~9 Hours (Relevant to This Error)

- **911ee9d** – Enhancements for database discovery (Helpers + main script): introduced many new code paths and additional uses of `if` (including if-as-expression in Helpers).
- **e071aa9, 102047d, 81aa3d8, cacfee4** – Multiple “Update IF error” / “Update error messages” commits: attempted to remove or rephrase `if` usage.

The error can appear when:

1. **Constrained Language Mode** is in effect (any use of `if` can trigger it).
2. **If-as-expression** remains in code that runs during discovery (main script or Helpers). The first such line that runs causes the failure; the stack points to the catch rethrow.

### Code Changes Made in This Pass

1. **Early language mode check** (Get-WorkstationDiscovery.ps1, immediately after `param`):
   - Read `$ExecutionContext.SessionState.LanguageMode`.
   - Use a **switch** (no `if` keyword) to detect `ConstrainedLanguage`, `RestrictedLanguage`, `NoLanguage`.
   - Exit with a clear error so users know they must run in Full Language mode.

2. **Removed every remaining if-as-expression** in:
   - **Get-WorkstationDiscovery.ps1**: e.g. SCCM/Encase tenant, CrowdStrike/Qualys Kind/Raw, IIS/SQL/app config `matchedFieldsStr` and `pathVal`, credential manager `entry`, shared folders, result-building variables, catch-block variables, etc. Replaced with pre-assigned variables and normal `if`/`else` statements.
   - **DomainMigrationDiscovery.Helpers.psm1**: Credential Manager `$target`/`$userName`/`$profileName`, certificates `NotAfter`, SQL `$serverName`, application config `FileSize`, event log `TimeCreated`/`LevelDisplayName`, Oracle/RDS `Errors`. Same pattern: variables set with normal `if`/`else`, then used in hashtables or return values.

3. **No remaining `= if (` or `Property = if (...)`** in the domain-discovery scripts (verified by search).

---

## How to Verify

1. **Check language mode** (before or without running the script):
   ```powershell
   $ExecutionContext.SessionState.LanguageMode
   ```
   If this is `ConstrainedLanguage` (or Restricted/NoLanguage), the script will now exit early with an explicit message.

2. **Run the script** from the **updated** codebase (not an old zip). If you still see "The term 'if' is not recognized", then:
   - You are almost certainly in Constrained Language Mode (or a similar restriction), and the first normal `if` statement that runs (e.g. early in the script or in the helper) will trigger it.
   - Ensure you are using the latest version that includes the language-mode check and all if-as-expression removals.

---

## References

- [about_Language_Modes](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes) – Constrained vs Full language mode.
- “The term 'if' is not recognized” is a known symptom of Constrained Language Mode when scripts use the `if` keyword.
