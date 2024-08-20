# asn_resolver
Simple script to resolve ip or network asn and country. Compatible with Ipv4 and Ipv6 ip and subnets. 

This script uses datasoures retrieve from this repo https://github.com/ipverse.

## how to 

Load database into local pandas dataframes. 
```
python lookup.py --refresh-db
```
Search an ip or network: 
```
python lookup.py --search 
```
Then provide a list of ip or network to the prompt. 

Two results files are generated in the script directory: res-asn-country.csv and res-asn-country-groupby.csv.
