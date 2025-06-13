#!/bin/sh
ls
trivy --version
trivy plugin install https://github.com/TheTricky65/trivy-plugin-count/releases/download/macos/plugin-count.0.1.0.tar.gz
trivy plugin list
trivy run image aquasec/trivy --report_path debian12_report.json --severity critical,medium        
