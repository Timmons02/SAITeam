def readServers(file1, file2):
    ips = open(file1,'r'); departs = open(file2,'r')
    serversDict = dict()    
    departs.readline() # first line is junk, get rid of it
    x = departs.readline()        
    while x != '':
        val = x.split(',')[0]
        key = (x.split(',')[1]).split('\n')[0]
        serversDict[key] = val,
        x = departs.readline()
    ips.readline() # first line is junk, get rid of it
    w = ips.readline() 
    while w != '':
        key = w.split(',')[0]
        val = (w.split(',')[2]).split('\n')[0]
        if val in serversDict:
            department = serversDict[val]
            if key in serversDict:
                oldVal = serversDict[key]
		serversDict[key] = oldVal + department
            else:
                serversDict[key] = department
        w = ips.readline()
    return serversDict

# Notes on usage:

# Call the method readServers() with the two files as parameters
# HOSTS.csv and ag_list.csv, in that order.

# The method returns a dictionary.
# The dictionary has a key (IP Address) and value (Department names).

# The dictionary will return a tuple of a variable number of elements. 
# Iterate through it to get each department to which an IP belongs.
# (I figured out how to make it work with Tuples of length 1, so don't worry
# about what I said the other day with strings)




            
            
                
            
