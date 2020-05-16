# ADAudit
Some powershell to assist with auditing risk from an AD perspective. Makes use of rubeus, sharphound, preempt, and bloodhound as well as pulling some relevant AD properties. This is intended to be used with a list of cracked users, but could be easily tweaked for other purposes. 

The function is meant to build a comprehensive list for review. General flow is as follows:

1) Pull desired AD info for users with a password age of x years or older for all available domains
2) Enrich results for aged passwords with risk information from preempt (optional)
3) Use Rubeus to see which accounts with SPNs support old encryption algorithms
4) Pull all AD info with sharphound to build bloodhound neo4j DB
**currently requires user interaction to import sharphound data to DB
5) Update bloodhound database marking cracked users (read from list, not actively cracked) as "owned"

results returned as PSobject

From this point, the idea is to review the results and to review the bloodhound DB assessing which accounts pose the most risk and implementing appropriate remediations.