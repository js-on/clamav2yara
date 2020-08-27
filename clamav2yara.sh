#!/bin/bash
# 
# File name: clamav2yara.py
# Author: Jakob Schaffarczyk
# Date created: 8/27/2020
# Date last modified: 8/27/2020
# Python Version: 3.7.4

python3 clamav2yara.py -d   # download newest database
python3 clamav2yara.py -a   # extract all supported data
python3 clamav2yara.py -m   # merge yara rules
rm -rf daily.* COPYING      # remove useless files
git add .                   # commit files
git commit -m "Update: $(date +%m-%e-%Y)"
git push -u origin master
