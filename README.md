## clamav2yara

This repository provides Yara rules generated from the daily updated ClamAV Virus Database (CVD).

daily\_(ndb|ndu).yara -> containing digital signatures
daily\_(hsb|hdb).yara -> containing md5 hashes

total.yara contains all the Yara rulesets merged to one large file.



### Self hosting:

Git, ClamaV and Git-LFS needed.

Daily cronjob for *clamav2yara.sh* needed

Information about self hosting will be provided soon!



### Script usage:

#### Prerequisites:

[ClamAV Installation](https://www.clamav.net/documents/installing-clamav)

usage: clamav2yara.py [-h] [-i inputfile] [-o outputfile] [-a] [-d] [-m] 

optional arguments: 
  -h, --help   show this help message and exit 
  -i inputfile  clamav database [.ndu, .ndb, .hdb, .hsb] 
  -o outputfile  yara ruleset [.yara] 
  -a       convert all supported filetypes to .yara files 
  -d       download current clamav virus database 
  -m       merge all available yara rules

#### Download current database

`python3 clamav2yara.py -d`
Downloads current database (daily.cvd) file.

#### Convert specific file

`python3 clamav2yara.py -i daily.(ndu|ndb|hdb|hsb) -o output.yara`
Converts specified input file to Yara ruleset

#### Convert all files

`python3 clamav2yara.py -a`
Converts all supported filetypes to Yara rulesets

#### Merge files

`python3 clamav2yara.py m`
Merge all available Yara rules to one large ruleset

#### Help

`python3 clamav2yara.py --help`
Print the given help message.
