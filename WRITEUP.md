# Write-up

### Analyze, choose, and justify the appropriate resource option for deploying the app.

After analyzing both options:

- VM offers full control but is costly, harder to scale, and requires manual setup and maintenance.
- App Service is cost-effective, auto-scales easily, has high availability by default, and integrates smoothly with GitHub for CI/CD.

Chosen: Azure App Service  
**Justification**: The CMS app is a standard web app with no special infrastructure needs. App Service simplifies deployment, handles scaling and updates automatically, and supports a faster, more reliable workflow.

---

### Assess app changes that would change your decision.

If the app:
- Needs custom networking (VPN)
- Requires OS-level access or running background services
- Runs non-HTTP workloads or complex tasks

Then a **VM** would be more appropriate. It provides the flexibility and control needed for such advanced scenarios.

