# This script allows a Martus server to run on a Linux (unix) box
# It works in combination with ForceListenOnNonPrivelegedPorts.txt,
# which tells the server to listen on 9888, 9443, etc.

# Under Ubuntu, we use sudo rather than logging in as root.

# This script redirects client requests on ports like 443 
# to where the server is listening on 9443.
# It sets up daemons, so it only needs to be run once per reboot.

# ssh will ask for your password each time, unless you have set up 
# public keys. Basically, root must add your user's public key to 
# it's list of authorized keys.
# note that the ssh protocol 1 and 2 use different filenames.

# On my system (Kevin speaking), I must:
#   ssh-add
#   cd ~/work/eclipse/martus/martus-server/source/org/martus/server/main
#   sh create-tunnels.bash
#   exit

sudo ssh -f -N -L 988:localhost:9988 $USER@localhost
sudo ssh -f -N -L 987:localhost:9987 $USER@localhost
sudo ssh -f -N -L 986:localhost:9986 $USER@localhost
sudo ssh -f -N -L 985:localhost:9985 $USER@localhost
sudo ssh -f -N -L 984:localhost:9984 $USER@localhost
sudo ssh -f -N -L 443:localhost:9443 $USER@localhost
sudo ssh -f -N -L  80:localhost:9080 $USER@localhost
