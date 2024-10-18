#!/bin/bash

# "Script to Remove Generated Files for PA-02"

# "Written By: Patrick Dodds and Conor McFadden"

echo "Cleaning up generated files..."

# Remove Amal's keys
cd amal
rm -f *.pem
rm -f amal

# Remove Basim's symbolic link and executable
cd ../basim
rm -f *.pem
rm -f basim

# Go back to the root directory and remove dispatcher and log files
cd ..
rm -f dispatcher
rm -f amal.log
rm -f amal/logAmal.txt

rm -f bunny.mp4

cd amal
rm -f bunny.mp4
cd .. 
rm -f basim/logBasim.txt
rm -f bunny.cpy
echo "Cleanup complete."
