# Routing Policy (Scaffold)

- SENSITIVE/SECRET default to local provider.
- Local requests require health gate pass.
- Interactive INTERNAL defaults to local router model.
- Batch or deep-preference requests default to local deep model.
- If local is unavailable, route to API provider allowlist order.
