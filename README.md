# Audit Desk

Portable Windows audit viewer based on [audit.ps1](./audit-(legacy).ps1). No installer or external dependencies.

Run [AuditDesk.cmd](./AuditDesk.cmd). Choose the checks you want, press **Run selected audit**, then use **Export JSON** to save a compact structured report. Results are read-only: the app does not delete or alter anything.

Edit [AuditDesk.ini](./AuditDesk.ini) beside the launcher to change portable settings. `Console=hide` hides the PowerShell console; set it to `show` when troubleshooting. The file also controls the large-file threshold, Local AppData result limit, progress polling frequency, and whether the export folder opens automatically.

The large-file and recursive folder-size checks can take several minutes. Administrative access is required.
