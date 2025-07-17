trivy plugin uninstall severitycount
echo 1
rm mysev.tar.gz 
echo 2
go build -o trivy-sev main.go    
echo 3   
tar -czvf mysev.tar.gz plugin.yaml trivy-sev 
echo 4
trivy plugin install mysev.tar.gz  
echo 5