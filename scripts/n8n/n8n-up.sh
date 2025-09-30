docker compose -f /Users/ben/OneDrive/Projects/Docker/n8n/docker-compose.yml up -d
echo "\n\tLaunching n8n: http://localhost:5678...\n"
sleep 2

open -a "Firefox" http://localhost:5678 &