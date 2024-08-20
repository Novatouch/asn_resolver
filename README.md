# asn_resolver
Simple script to get asn and country info for ip address or network ranges. Compatible with Ipv4 and Ipv6 ip and subnets. 

This script uses datasoures retrieved from this repo https://github.com/ipverse.

## How to 

Load or update data from remote zip archive into local pandas dataframes. 
```
python lookup.py --refresh-db
```
You are now able to search an ip or network: 
```
python lookup.py --search 
```
Provide a list of ips or subnets to the prompt. 

Two results files will be created in the script directory: res-asn-country.csv and res-asn-country-groupby.csv. First one contains the item list enriched with asn and country information, the second one contains results agregated by asn and countries. 
