sudo apt-get update && sudo apt upgrade -y
sudo apt-get install ca-certificates curl git wget -y


# Add Docker’s official GPG key
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc


echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null


# Install Docker
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin qemu-user-static -y


# Install VECTR
sudo mkdir -p /opt/vectr
cd /opt/vectr
sudo wget https://github.com/SecurityRiskAdvisors/VECTR/releases/download/ce-9.8.3/sra-vectr-runtime-9.8.3-ce.zip 
sudo unzip sra-vectr-runtime-9.8.3-ce.zip


# Updating the hosts file
echo "127.0.0.1 sravectr.internal" | sudo tee -a /etc/hosts

# Start a new Terminal after adding these aliases
echo 'alias startvectr="cd /opt/vectr && sudo docker compose up -d"' | tee -a ~/.bashrc
echo 'alias stopvectr="cd /opt/vectr && sudo docker compose down"' | tee -a ~/.bashrc

# Edit docker-compose.yml to force use of linux/amd64 platform
sudo cp /opt/vectr/docker-compose.yml /opt/vectr/docker-compose.yml.orig
sudo sed '/^\s*image:/a\    platform: linux/amd64' "/opt/vectr/docker-compose.yml.orig" > "/opt/vectr/docker-compose.yml"

# Edit .env to replace all non-alphanumeric charcters in 
sed -i 's/[^[:alnum:]]/_/g' /opt/vectr/docker-compose.yml