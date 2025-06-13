#!/bin/sh
ls
trivy --version
trivy plugin install .
trivy plugin list
trivy run image aquasec/trivy --report_path debian12_report.json --severity critical,medium        
