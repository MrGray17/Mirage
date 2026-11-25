# Mirage visual system

The Observatory and Attack Lab use the same embedded CSS tokens and typography.
Both adapt to the operating system's light or dark preference and work offline.
The Observatory is a read-only inspector of a validated receipt; its counts,
outcome, mutation and hash information come from the receipt, not a simulation.
The Lab index distinguishes passed, executed and planned trials and links to
individual reports and raw evaluation data.

The UI deliberately does not claim verified signatures merely because receipt
integrity is valid. Signing and verification remain explicit CLI operations.
No external fonts, dependencies, network calls or new authority paths are
introduced. The existing hashed interaction script and CSP remain intact.
The UI remains usable with keyboard navigation and reduced-motion preferences.
