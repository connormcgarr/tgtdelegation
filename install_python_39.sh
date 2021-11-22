#! /bin/bash
# install_python_39.sh
# Author: Connor McGarr (@33y0re)
# tgtParse scripts require Python 3.9. If you don't have it installed, here is a quick utility to do so
# If you are running a current image of Kali Linux, you should already have python3.9 installed

# First check if we are root
if [ "$EUID" -ne 0 ]
then
	echo "[-] Error! Please run install_python_39.sh as root!"
	exit 1
fi
	echo "[+] Installing python3.9. I will be adding python3.9 but not setting it as the default python3 version."
	sleep 1

# Update packages and install dependencies
echo "[+] Updating packages and installing dependencies: build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libsqlite3-dev libreadline-dev libffi-dev curl libbz2-dev"
apt update > /dev/null 2>&1
apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libsqlite3-dev libreadline-dev libffi-dev curl libbz2-dev -y > /dev/null 2>&1

# Grab python3.9.6
echo "[+] Grabbing Python 3.9.6 from the Python FTP server..."
wget https://www.python.org/ftp/python/3.9.6/Python-3.9.6.tgz > /dev/null 2>&1

# Unarchive the tgz
tar xvf Python-3.9.6.tgz > /dev/null 2>&1

# Change the current working directory
cd Python-3.9.6/

# Execute the configure script
echo "[+] Installing Python 3.9.6. Your screen will be flooded with make command output. This script will check to see if the installation is successful after execution."
sleep 2.5
./configure --enable-optimizations

# Build Python 3.9.6
# Determine the number of cores first
number_of_cores=$(nproc)
make -j $number_of_cores

# Install the Python 3.9.6 binaries, but don't overwrite the current python3 version
make altinstall

# Copy python3.9 to /usr/bin
mv /usr/local/bin/python3.9 /usr/bin/python3.9
mv /usr/local/bin/python3.9-config /usr/bin/python3.9-config

# Check if the installation was succesful
if python3.9 -V > /dev/null 2>&1
then
        echo "[+] Python 3.9.6 successfully installed!"
else
        echo "[-] Error! Could not find Python 3.9.6. Please either manually install or use the latest build of Kali Linux, which has python3.9 already installed!"
        exit 1
fi

# pip3.9 install six (needed as the system cannot find this module after installing python3.9)
python3.9 -m pip install six > /dev/null 2>&1
