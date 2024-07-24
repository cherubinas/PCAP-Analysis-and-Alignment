#!/bin/bash

function retrieve_pcap_file {
    local vm_name="$1"
    local private_ip="$2"
    local port="${3:-22}"  # Default to port 22 if no port is provided
    local remote_file="$4"
    local local_dir="$5"
    local pcap_file_name="$6"  # Name of the pcap file to retrieve

    echo "Retrieving $pcap_file_name from $vm_name ($private_ip)..."
    sftp -P "$port" root@"$private_ip" <<EOF
    get "$remote_file" "${local_dir}/${vm_name}_${pcap_file_name}"
    bye
EOF
    echo "File retrieved successfully and stored at ${local_dir}/${vm_name}_${pcap_file_name}"
}

sudo rm -f /etc/ansible/hosts

VM_ATTACKER=attacker
VM_VICTIM=victim

CENDPOINT=https://grid5.mif.vu.lt/cloud3/RPC2

read -p 'Please enter username for your VU MIF cloud infrastructure: ' CUSER
read -sp 'Please enter password for your VU MIF cloud infrastructure: ' CPASSWORD

if [ -z "$CUSER" ]; then
    echo "No username provided. Skipping VM creation."
    VM_NOT_CREATED=false
else
    VM_NOT_CREATED=true
fi

echo "Making VM on user $CUSER"

eval $(ssh-agent)
if [ ! -f ~/.ssh/id_ed25519 ]; then
    ssh-keygen -t ed25519
fi

ssh-add

if $VM_NOT_CREATED; then
    # Create attacker-vm
    echo "Creating $VM_ATTACKER-vm..."
    VM_ATTACKER_VM_REZ=$(onetemplate instantiate "debian12" --name "$VM_ATTACKER" --net_context --ssh ~/.ssh/id_ed25519.pub --user $CUSER --password $CPASSWORD --endpoint $CENDPOINT)

    # Check if onetemplate command was successful
    if [ $? -ne 0 ]; then
        echo "Error: VM creation failed with error: $VM_ATTACKER_VM_REZ"
        echo "Exiting..."
        exit 1
    fi

    ATTACKER_VM_ID=$(echo $VM_ATTACKER_VM_REZ | cut -d ' ' -f 3)
    echo "$VM_ATTACKER VM ID: $ATTACKER_VM_ID"

    # Create victim-vm
    echo "Creating $VM_VICTIM-vm..."
    VM_VICTIM_VM_REZ=$(onetemplate instantiate "debian12" --name "$VM_VICTIM" --net_context --ssh ~/.ssh/id_ed25519.pub --user $CUSER --password $CPASSWORD --endpoint $CENDPOINT)

    # Check if onetemplate command was successful
    if [ $? -ne 0 ]; then
        echo "Error: VM creation failed with error: $VM_VICTIM_VM_REZ"
        echo "Exiting..."
        exit 1
    fi

    VICTIM_VM_ID=$(echo $VM_VICTIM_VM_REZ | cut -d ' ' -f 3)
    echo "$VM_VICTIM VM ID: $VICTIM_VM_ID"

    echo "Waiting for VM to RUN 45 sec."
    sleep 45

    echo "Adding newly created machine's IP address to Ansible hosts file"
    if [ ! -d /etc/ansible/ ]; then
        sudo mkdir -p /etc/ansible/
    fi

    ATTACKER_VM_DETAILS=$(onevm show $ATTACKER_VM_ID --user $CUSER --password $CPASSWORD --endpoint $CENDPOINT)

    CSSH_CON_ATTACKER=$(echo "$ATTACKER_VM_DETAILS" | grep "CONNECT\_INFO1" | cut -d '=' -f 2 | tr -d '"' | sed 's/'$CUSER'/root/')
    CSSH_PRIP_ATTACKER=$(echo "$ATTACKER_VM_DETAILS" | grep "PRIVATE\_IP" | cut -d '=' -f 2 | tr -d '"')

    echo "Connection string: $CSSH_CON_ATTACKER"
    echo "Local IP: $CSSH_PRIP_ATTACKER"

    if [ -n "$CSSH_PRIP_ATTACKER" ]; then
        echo -e "\n[$VM_ATTACKER]\n$CSSH_PRIP_ATTACKER" | sudo tee -a /etc/ansible/hosts
        echo "Added $CSSH_PRIP_ATTACKER to Ansible hosts file"
        ssh-keyscan -H $CSSH_PRIP_ATTACKER >> ~/.ssh/known_hosts
    else
        echo "Error: PRIVATE_IP not found or empty."
        exit 1
    fi

    VICTIM_VM_DETAILS=$(onevm show $VICTIM_VM_ID --user $CUSER --password $CPASSWORD --endpoint $CENDPOINT)

    CSSH_CON_VICTIM=$(echo "$VICTIM_VM_DETAILS" | grep "CONNECT\_INFO1" | cut -d '=' -f 2 | tr -d '"' | sed 's/'$CUSER'/root/')
    CSSH_PRIP_VICTIM=$(echo "$VICTIM_VM_DETAILS" | grep "PRIVATE\_IP" | cut -d '=' -f 2 | tr -d '"')

    echo "Connection string: $CSSH_CON_VICTIM"
    echo "Local IP: $CSSH_PRIP_VICTIM"

    if [ -n "$CSSH_PRIP_VICTIM" ]; then
        echo -e "\n[$VM_VICTIM]\n$CSSH_PRIP_VICTIM" | sudo tee -a /etc/ansible/hosts
        echo "Added $CSSH_PRIP_VICTIM to Ansible hosts file"
        ssh-keyscan -H $CSSH_PRIP_VICTIM >> ~/.ssh/known_hosts
    else
        echo "Error: PRIVATE_IP not found or empty."
        exit 1
    fi
fi

ansible-playbook $VM_VICTIM.yml --user root
ansible-playbook $VM_ATTACKER.yml --user root -e "target_ip=$CSSH_PRIP_VICTIM"

LOCAL_DIR="/home/eilu8315"
retrieve_pcap_file "$VM_ATTACKER" "$CSSH_PRIP_ATTACKER" "" "/home/captureA.pcap" "$LOCAL_DIR" "captureA.pcap"
retrieve_pcap_file "$VM_VICTIM" "$CSSH_PRIP_VICTIM" "" "/home/captureB.pcap" "$LOCAL_DIR" "captureB.pcap"

exit 0