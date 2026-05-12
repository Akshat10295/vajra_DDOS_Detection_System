VAJRA: It is a DDOS Detection system, which detects DDOS attacks and mitigates them by updating the firewall. It works using a ML model which trained using Random Forest with multiple datasets. It collects the data and stores tem in a file so the user can use the data to retrain the model.   


DETECTOR:(Windows)
cmd : python -m http.server 8000
cmd(Admin) : Go to the directory in which the file is stored : python vajra_server.py 

ATTACKER:(Kali linux) 
terminal : sudo su : kali : bash /home/kali/setup_namespaces.sh : 
ping:  ip netns exec ns1 ping 192.168.68.20 -c 5 (detector Ip address)

Normal packets:
ip netns exec ns1 python3 /home/hacked/vajra_attacker.py \
    --mode normal \
    --target 192.168.68.20 \
    --duration 120

Attack packets:
for i in $(seq 1 20); do
    ip netns exec ns$i python3 /home/hacked/vajra_attacker.py \
        --mode namespace \
        --target 192.168.68.20 \
        --attack mixed \
        --duration 60 &
done
