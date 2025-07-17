# trivy-plugin-severitycount

command example:

trivy image -f json -o plugin=severitycount  --output-plugin-arg "--published-after=2024-11-01 --severity-plugin high,low" debian:12