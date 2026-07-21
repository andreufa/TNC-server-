Посмотреть сети 
docker inspect tnc-server tnc-postgres --format '{{.Name}}: {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
или
docker network ls