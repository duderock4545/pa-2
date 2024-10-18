#!/bin/bash

# "Script to run Programming Assignment #2"
# "By: Mohamed Aboutabl"

# Clean up any old files from previous runs
rm -f dispatcher bunny.mp4 bunny.cpy
rm -f amal/amal amal/logAmal.txt 
rm -f basim/basim basim/logBasim.txt 

# Create symbolic link to the video file one level above the dispatcher's folder
ln -s ../bunny.mp4 bunny.mp4

echo "=============================="
echo "Compiling all source"

# Compile Amal using your custom amal.c
gcc amal/amal.c myCrypto.c -o amal/amal -lcrypto -lssl
if [ $? -ne 0 ]; then
    echo "Error: Failed to compile amal.c"
    exit 1
fi

# Use the basimReference executable for Basim
cp basim/basimReference basim/basim
chmod +x basim/basim  # Ensure basim has execute permissions

# Compile the Dispatcher
gcc wrappers.c dispatcher.c -o dispatcher
if [ $? -ne 0 ]; then
    echo "Error: Failed to compile dispatcher.c"
    exit 1
fi

echo "=============================="
echo "Starting the dispatcher"
./dispatcher
if [ $? -ne 0 ]; then
    echo "Error: Failed to run dispatcher"
    exit 1
fi

echo
echo "======  Amal's  LOG  ========="
cat amal/logAmal.txt
echo

echo "======  Basim's  LOG  ========="
cat basim/logBasim.txt
echo

echo "=============================="
echo "Verifying the File Unencrypted Transmission"
echo
diff -s bunny.mp4 bunny.cpy
echo
