# trivy-plugin-gitlab-codequality
This plugin converts Trivy scan results into GitLab Code Quality format for integration with GitLab CI/CD pipelines and merge request reports.

# Usage
You can use the plugin either as a standalone plugin for conversion or as an output plugin for the trivy scanning command.  
Make sure to run the trivy scan with the broadest possible severity and pkg-types filters you still want to include in any of the scan-reports.
  
Standalone usage:
```yaml
  Usage:
    trivy image --format json --output report.json --output plugin=gitlab-codequality <image>
    trivy fs --format json --output report.json --output plugin=gitlab-codequality <path>
  
  Usage with plugin options (all options must be passed within --output-plugin-arg):
    trivy image --format json --output report.json \
      --output plugin=gitlab-codequality \
      --output-plugin-arg "--severity UNKNOWN,CRITICAL,HIGH --severity-misconfig UNKNOWN,CRITICAL --output codequality.json" \
      <image>
  
  Available plugin options (to be used within --output-plugin-arg, all are optional):
    --severity <SEVERITIES>          Global severity filter (comma-separated)
    --severity-license <SEVERITIES>  License-specific severity filter
    --severity-vuln <SEVERITIES>     Vulnerability-specific severity filter
    --severity-misconfig <SEVERITIES> Misconfiguration-specific severity filter
    --severity-secret <SEVERITIES>   Secret-specific severity filter
    --pkg-types <TYPES>              Global package types filter (comma-separated)
    --pkg-types-license <TYPES>      License-specific package types filter
    --pkg-types-vuln <TYPES>         Vulnerability-specific package types filter
    --pkg-types-misconfig <TYPES>    Misconfiguration-specific package types filter
    --pkg-types-secret <TYPES>       Secret-specific package types filter
    --debug                          Enable debug output
    --output <FILE>                  Output file path
    --input <FILE>                   Input file path

SEVERITIES: UNKNOWN,CRITICAL,HIGH,MEDIUM,LOW
TYPES: library,os
```

# License
Apache 2.0

