#!/bin/bash

# "Script to Generate RSA Public/Private key Pair and Test Amal/Basim"
# Written By: Patrick Dodds and Conor McFadden
#!/bin/bash

echo
echo

# Create symbolic link to bunny.mp4 in the main project folder if not already existing
if [ ! -L "bunny.mp4" ]; then
    ln -s ../bunny.mp4 bunny.mp4
    echo "Symbolic link created for bunny.mp4"
else
    echo "Symbolic link for bunny.mp4 already exists"
fi

# Check if basimReference exists
if [ ! -f basim/basimReference ]; then
    echo "Error: basimReference file not found."
    exit 1
fi

# Generate 2048-bit public/private key-pair for Amal
cd amal
rm -f *.pem bunny.mp4

# Generate the private key for Amal
openssl genpkey -algorithm RSA -out amal_priv_key.pem -pkeyopt rsa_keygen_bits:2048

# Extract the public key from the private key for Amal
openssl rsa -pubout -in amal_priv_key.pem -out amal_pub_key.pem

# Ensure the private key has the correct permissions
chmod +r amal_priv_key.pem
chmod 644 amal_pub_key.pem

# Display Amal's private key information for debugging
openssl rsa -in amal_priv_key.pem -text -noout

# Now, copy Amal's public key to Basim directory
cd ../basim
rm -f *.pem
cp ../amal/amal_pub_key.pem .

# Go back to the main project folder
cd ..

# Compile Custom Amal (your `amal.c`)
gcc -o amal/amal amal/amal.c myCrypto.c -lcrypto -lssl
if [ $? -ne 0 ]; then
    echo "Error: Failed to compile amal.c"
    exit 1
fi

# Copy the basimReference to run as Basim
cp basim/basimReference basim/basim

# Grant execute permissions for Amal and Basim
chmod +x amal/amal basim/basim

# Compile Dispatcher (optional if dispatcher.c needs to be recompiled)
gcc -o dispatcher dispatcher.c wrappers.c -lcrypto -lssl
if [ $? -ne 0 ]; then
    echo "Error: Failed to compile dispatcher.c"
    exit 1
fi

# Run the dispatcher (which will run Amal and Basim)
./dispatcher
if [ $? -ne 0 ]; then
    echo "Error: Failed to run dispatcher"
    exit 1
fi

echo "Test complete. Check logs for results."
