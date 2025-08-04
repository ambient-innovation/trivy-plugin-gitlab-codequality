# trivy-plugin-gitlab-codequality
A Trivy plugin that transforms the output to show up in the GitLab CodeQuality Widget.  
Supports filtering by severity levels for different scan types and custom output formatting.

# Usage
You canuse the plugin either as a standalone plugin for conversion or as an output plugin for the trivy scanning command.  
Make sure to run the trivy scan with the broadest possible severity and pkg-types filters you still want to include in any of the scan-reports.
  
Standalone usage:
```yaml
usage: gitlab-codeclimate [-h]
  [--severity SEVERITY]
  [--severity-license SEVERITY_LICENSE] [--severity-vuln SEVERITY_VULN]
  [--severity-misconfig SEVERITY_MISCONFIG] [--severity-secret SEVERITY_SECRET]
  [--pkg-types PKG_TYPES]
  [--pkg-types-license PKG_TYPES_LICENSE] [--pkg-types-vuln PKG_TYPES_VULN]
  [--pkg-types-misconfig PKG_TYPES_MISCONFIG] [--pkg-types-secret PKG_TYPES_SECRET]
  [--debug]
  [-o OUTPUT]

options:
  -h, --help
                        show this help message and exit
  --severity SEVERITY
                        Global Severity (Default)
  --severity-license SEVERITY_LICENSE
                        License Severity
  --severity-vuln SEVERITY_VULN
                        Vulnerabilities Severity
  --severity-misconfig SEVERITY_MISCONFIG
                        Misconfig Severity
  --severity-secret SEVERITY_SECRET
                        Secret Severity
  --pkg-types PKG_TYPES
                        Global Package Types (Default)
  --pkg-types-license PKG_TYPES_LICENSE
                        License Package Types
  --pkg-types-vuln PKG_TYPES_VULN
                        Vulnerabilities Package Types
  --pkg-types-misconfig PKG_TYPES_MISCONFIG
                        Misconfig Package Types
  --pkg-types-secret PKG_TYPES_SECRET
                        Secret Package Types
  --debug
                        Debug Outputs
  -o, --output OUTPUT
                        Output file
```

To use it in output mode add the arguments to your trivy scanning command via the --output plugin-arg string:
i.e.: `trivy image --format json  --output plugin=gitlab-codequality --output-plugin-arg "--severity-misconfig UNKNOWN,CRITICAL --severity-secret UNKNOWN,CRITICAL --pkg-types-license library" debian:12`

# License
Apache 2.0

