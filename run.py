import readServers
import mysql.connector
import sys
import getopt
import parser
import dbManager
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

	#connecting to the database
	
	cursor = None
	conection = None
	try:
		connection = mysql.connector.connect(user='CS523',password='^^@keMYd@y',
											 host='127.0.0.1', database='CS523')
		cursor = connection.cursor()
	except mysql.connector.Error, err:
		print("Database connection error: ")
		print(err)


	# A dictionary that returns the servers that belong to a given ip

	servDict = readServers.readServers("/opt/Qualys523/data/HOSTS.csv", "/opt/Qualys523/results/ag_list.csv")
	
	# opening file to be parsed 
	
	whole_file = open(input_file,"r")
	text = whole_file.read()
	
	#selecting html portion of file as html_part
	js, css, html_part = text.split("</script>",2)

	#instantiating a parser and feeding it the html part of the file
	aParser = parser.MyHTMLParser()
	aParser.feed(html_part)
	
	servers = aParser.getList()

	dbManager.updateDb(cursor, connection, servers)

if __name__ == "__main__":
	main(sys.argv[1:])
