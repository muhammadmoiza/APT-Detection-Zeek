#!/bin/bash

tm=20
of="temp.txt"

# test cases file

# comprises
# -- multiple APTs
# -- multiple TTPs
# -- multiple IoCs

# --------- test cases start ---------


# --- the gorgon group ---

# -> url
curl --connect-timeout $tm http://h2020.myspecies.info/ > $of
echo "Blacklisted URL Tested - Gorgon Group"

# -> directory path
curl --connect-timeout $tm http://h2020.myspecies.info/content/more-h2020-guesses > $of
echo "Blacklisted Directory Path Tested - Gorgon Group"

# # -> malware hash
wget "http://h2020.myspecies.info/sites/all/themes/scratchpads/favicon.ico" 
echo "Blacklisted Malware Hash Tested - Gorgon Group"

# # --- cobalt group ---

# # -> url
curl --connect-timeout $tm http://weevil.info/ > $of
echo "Blacklisted URL Tested - Cobalt Group"

# # -> malware hash
wget "http://vbrant.eu/sites/vbrant.eu/themes/acquia_prosper/favicon.ico"
echo "Blacklisted Malware Hash Tested - Cobalt Group"


# # --- lazarus group ---

# # -> ip address
curl --connect-timeout $tm 157.140.2.32 > $of
echo "Blacklisted IP Tested - Lazarus Group"

# # -> url
curl --connect-timeout $tm http://diptera.myspecies.info/ > $of
echo "Blacklisted URL Tested - Lazarus Group"

# # -> malware hash
wget "http://diptera.myspecies.info/sites/diptera.myspecies.info/files/Logo_Thumb4.jpg"
echo "Blacklisted Malware Hash Tested - Lazarus Group"

# # --- oilrig ---

# # -> ip address
curl --connect-timeout $tm 52.216.142.123 > $of
echo "Blacklisted IP Tested - OilRig"

# # -> url
curl --connect-timeout $tm http://africhthy.org/ > $of
echo "Blacklisted URL Tested - OilRig"

# # -> malware hash
wget "http://www.gnu.org/graphics/gnu-head-mini.png"
echo "Blacklisted Malware Hash Tested - OilRig"

# # --- muddywater ---

# # -> ip address
curl --connect-timeout $tm 70.32.68.120 > $of
echo "Blacklisted IP Tested - MuddyWater"

# # -> url
curl --connect-timeout $tm http://www.asfaa.org/ > $of
echo "Blacklisted URL Tested - MuddyWater"

# # -> malware hash
wget "http://www.asfaa.org/img/favicon.png"
echo "Blacklisted Malware Hash Tested - MuddyWater"

# # -> DNS
curl --connect-timeout $tm github.map.fastly.net > $of
sleep 2
curl --connect-timeout $tm github.map.fastly.net > $of
sleep 2
curl --connect-timeout $tm github.map.fastly.net > $of
sleep 2
curl --connect-timeout $tm github.map.fastly.net > $of
sleep 2
curl --connect-timeout $tm github.map.fastly.net > $of
#drill github.map.fastly.net @4.2.2.2

# # --------- test cases end ---------

# clear temp file
rm temp.txt
rm *.png*
rm *.jpg*
rm *.ico*