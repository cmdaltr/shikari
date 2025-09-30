sudo docker stop $(sudo docker ps -a -q) -y
sudo docker system prune
sleep 1

cd /opt/vectr
sudo docker compose up -d

VECTR_HOSTNAME=$(grep '^VECTR_HOSTNAME=' .env | cut -d= -f2-)
VECTR_PORT=$(grep '^VECTR_PORT=' .env | cut -d= -f2-)

echo "Please wait a few minutes..."
sleep 120
echo "\n\nNavigate to https://$VECTR_HOSTNAME:$VECTR_PORT/ to access VECTR"