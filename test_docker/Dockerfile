# Use official Alpine base for small size
FROM aquasec/trivy:latest

WORKDIR /home
COPY /debian12_report.json /home
RUN ls /home
COPY scanner.sh /home/scanner.sh
RUN chmod +x /home/scanner.sh
RUN ls /home

ENTRYPOINT [ "/home/scanner.sh" ]
