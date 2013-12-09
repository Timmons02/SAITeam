Program Documentation

USAGE

This program is used by running the "run.py" file. This command is "python run.py -i inputfile -o output_directory".
After running "run.py", the user will be asked if they want to send emails, and must type "y" (yes) or "n" (no).


DESIGN

When running this program, run.py takes the input and output, connects to the databases (dbManager.py, email_db.py), 
creates the dictionary (ReadServers.py) between IP addresses and departments, parses the HTML file (parser.py), and 
then creates output files and writes emails (Department.py). 

dbManager.py: Connects to the database which keeps track of vulnerability dates when they were first and last seen.
The schema of the database is as follows:
+-----------+-------------+------+-----+---------+-------+
| Field     | Type        | Null | Key | Default | Extra |
+-----------+-------------+------+-----+---------+-------+
| first_saw | date        | YES  |     | NULL    |       |
| last_saw  | date        | YES  |     | NULL    |       |
| qid       | int(11)     | NO   | PRI | NULL    |       |
| ip        | varchar(30) | NO   | PRI | NULL    |       |
+-----------+-------------+------+-----+---------+-------+
email_db.py: Makes a connection to the email database and gets a list of emails for a given department.
The schema is as follows:
+-----------+------+------+-----+---------+-------+
| Field     | Type | Null | Key | Default | Extra |
+-----------+------+------+-----+---------+-------+
| SAI_GROUP | text | YES  |     | NULL    |       |
| NAME      | text | YES  |     | NULL    |       |
| ONYEN     | text | YES  |     | NULL    |       |
| E_MAIL    | text | YES  |     | NULL    |       |
+-----------+------+------+-----+---------+-------+

ReadServers.py: Takes the two CSV files, ag_list.csv and HOSTS.csv and concatentates them into a dictionary
	where the IP address is the key and the department is the value. This is used for sort hosts into 
	two departments.
parser.py: Used to look through an HTML file for specific start tags and data, sometimes with specific
	name/value pairs. When certain tags or data are encountered, flags are set to determine when to
	accept data. When data is accepted, it is stored in an object that contains information about 
	server scans and vulnerabilities.
Department.py: Takes the database connection as an input, an initial host, the output folder, the department name, and 
	the email addresses associated with it. It contains a method to add more servers to the department which happens 
	as they are found in the scan. Once the scan is completed, it contains methods which will write files and 
	emails. 


DEPENDENCIES

The html structure is critical to the parser. Changing the following tags/data will result in incorrect parsing.

The following start tags and their name/value pair attributes are used in settings important flags in the Python code:
	�dl� tag with attribute name = �id� value = �rpt_sum_det� before the date data
	�dd� tag marking the date, directly after the above tag
	�span� tag with attribute name = �class� and value = �host_id� before the host name data
	�div� tag with attribute 1 name = �class� value = �severity_icon� and attribute 2 name = �title� value = �Vulnerability � level 4� OR value = �Vulnerability � level 5� before a vulnerability level
	�img� tag after the above tag to mark incoming vulnerability level data
	�acronym� tag with attribute name = �title� value = �Qualys Identification�
	�dd� tag after the above tag to mark a following QID
	�div� tag with attribute name = �id� value = �94652� before hosts not alive
	�div� tag with attribute name = �id� value = �94654� before failed Windows hosts
	�div� tag with attribute name = �class� value = �report_result� before failed Windows hosts
	�div� tag with attribute name = �id� value = �94655� before failed Unix/Cisco hosts
	�div� tag with attribute name = �class� value = �report_result� before failed Unix/Cisco hosts
	�div� tag with attribute name = �id� value = �94656� before failed Oracle hosts
	�div� tag with attribute name = �class� value = �report_result� before failed Oracle hosts

The following data is used in setting important flags in the Python code:
	�THREAT� before the threat summary data
	�IMPACT� before the impact summary data
	�SOLUTION� before the solution summary data

	
PARSER CLASS STRUCTURE

Server 
This object represents one of the scanned servers.

	Fields
	date 		[string] � the date of the scan
	ip_host 	[string] � the IP address and host name of the scanned server
	vuls 		[array] � a list of Vulnerability objects
	failed_port 	[string] � a port that failed to scan. This only occurs on Oracle servers.

	Methods
	__init__ (ip_host)	Initializes a server with an IP address and host name.
    	setDate(date)		Sets a date.
    	setIpHost(ip_host)	Sets an IP address and host name.
    	setFailedPort(port) 	Sets a failed Oracle port
    	addVulnerability(vul)	Adds a Vulnerability object to the vuls array
    	getDate()		returns the date of the scan
    	getIpHost()		returns the ip_host field
   	getVuls()		returns the vuls array
    	getFailedPort()		returns the failed Oracle port number
	getIp()			returns only the IP address, not the host name too

Vulnerability
This object represents a vulnerability that is found on a server.

	Fields
	name		[string] - the name of the vulnerability
	qid 		[string] � the Qualys Identifier for this specific vulnerability
	level 		[integer] � the assigned Qualys level of this threat
	sum_threat	[string] � the threat summary
	sum_impact 	[string] � the impact summary
	sum_solution	[string] � the solution summary

	Methods
	__init__(string, integer, string, string, string)	initializes the Vulnerability object
	getName()		returns the vulnerability name	
	getQID()		returns the qid field
	getLevel()		returns the level field
	getSum_threat()		returns the sum_threat field
	getSum_impact()		returns the sum_impact field
	getSum_solution()	returns the sum_solution field
	setName(string)		sets the vulnerability name
	setQID(string)		sets the QID field
	setLevel(integer)	sets the level field
	setSum_threat(string)	sets the sum_threat field	
	setSum_impact()		sets the sum_impact field
	setSum_solution()	sets the sum_solution field


MyHTMLParser	
	This is a subclass of HTMLParser that overrides the handle_starttag and handle_data methods. 	The handler methods use flags to determine when to extract data. The result of feeding the 	correct HTML file into the parser will result in MyHTMLParser having a list of server objects and 		their respective vulnerabilities.

	Fields
	24 booleans for setting appropriate flags
	server_list[]		[array] list of server objects
    	list_index		[integer] index of the server_list
  	date			[string] a date for the scan
    	threat 			[string] temp summary of the threat
   	impact			[string] temp summary of the impact
    	solution 		[string] temp summary of the solution
    	level = -1		[integer] temp vulnerability level
	name			[string] temp name of a vulnerability
    	qid			[string] temp qid number
    	oracle_port		[string] the failed port number
	v_count			[integer] the total number of vulnerabilities found

	Methods
	printList()				prints all of the servers, their fields, and their vulnerabilities
	handle_starttag(string, string[])	Sets flags for the handle_data() method to know when to extract data
	handle_data(string)			Extracts data.  					
	hostParser(string)			parses a string that contains an IP address and returns a list of the IP addresses
	portParser(string)			parsers a string that contains  a port number and returns the port number
	getList()				returns the list of server objects

