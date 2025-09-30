# Struggling to launch VECTR? Run `sudo docker ps`, `sudo docker stop {containerID}` (or `sudo docker stop $(docker ps -a -q)`) and `sudo docker system prune` and try again.
cd /opt/vectr
sudo docker compose up -d

VECTR_HOSTNAME=$(grep '^VECTR_HOSTNAME=' .env | cut -d= -f2-)
VECTR_PORT=$(grep '^VECTR_PORT=' .env | cut -d= -f2-)

echo "Please wait a few minutes..."
sleep 120
echo "\n\nNavigate to https://$VECTR_HOSTNAME:$VECTR_PORT/ to access VECTR"