#!/bin/bash

# "Script to run Programming Assignment #2"
# "By: Patrick Dodds and Conor McFadden"

# Clean up any old files from previous runs
rm -f dispatcher bunny.mp4 bunny.cpy
rm -f amal/amal amal/logAmal.txt 
rm -f basim/basim basim/logBasim.txt 

# Create symbolic link to the video file one level above the dispatcher's folder
ln -s ../bunny.mp4 bunny.mp4

echo "=============================="
echo "Setting up executables"

# Use the amalReference executable for Amal
cp amal/amalReference amal/amal
chmod +x amal/amal  # Ensure amal has execute permissions

# Use the basimReference executable for Basim
cp basim/basimReference basim/basim
chmod +x basim/basim  # Ensure basim has execute permissions

# Compile the Dispatcher
gcc wrappers.c dispatcher.c -o dispatcher


echo "=============================="
echo "Starting the dispatcher"
./dispatcher


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
