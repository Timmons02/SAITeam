import readServers
import mysql.connector
import sys
import getopt
import parser
import dbManager
import Department
import os
def main(argv):
	#getting the inputfile name and ouputfolder path 
	input_file = ''
	output_folder = ''
	try:
		opts, args = getopt.getopt(argv,"i:o:")
	except getopt.GetoptError:
		print 'usage: run.py -i <inputfile> -o <outputfolder>'
		sys.exit(2)
	for opt, arg in opts:
		if opt in ("-i"):
			input_file = arg
		elif opt in("-o"):
			output_folder = arg
	if (len(input_file) == 0):
		print "usage: run.py -i <inputfile> -o <outputfolder>"
		sys.exit(2)

	# Check to see if the folder you are writing to exists or not, and creates it
	if not os.path.exists("./"+output_folder):
		print 'Directory not found, creating...'
		os.makedirs("./"+output_folder)	

	#connecting to the database

	database = dbManager.dbManager()
	database.connect()
	# A dictionary that returns the servers that belong to a given ip

	servDict = readServers.readServers("/home/cmanker/HOSTS.csv", "/home/cmanker/ag_list.csv")
	
	# opening file to be parsed 
	
	whole_file = open(input_file,"r")
	text = whole_file.read()
	
	#selecting html portion of file as html_part
	js, css, html_part = text.split("</script>",2)

	#instantiating a parser and feeding it the html part of the file
	aParser = parser.MyHTMLParser()
	aParser.feed(html_part)
	
	servers = aParser.server_list
	print str(len(servers))+' machines in scan.'

	database.updateDb(servers)
	
	print 'Do you wish to send out notification emails for this scan?'
	emailflag = -1
	while (emailflag == -1):
		email = raw_input()
		if (email == 'yes') or (email == 'y'):
			emailflag = 1
		elif (email == 'no') or (email == 'n'):
			emailflag = 0
		else:
			print 'Did not understand input, please use yes/y or no/n.'
	departments = dict()
	for server in servers:
		for departs in servDict[server.getIp()]:
			if departs in departments:
				departments[departs].addServer(server)
			else:
				departments[departs] = Department.Department(database,server,output_folder,departs,"not yet",emailflag) 
			# ADD EMAIL STUFF 
	for departs in departments:
		departments[departs].writeFile()

if __name__ == "__main__":
	main(sys.argv[1:])
