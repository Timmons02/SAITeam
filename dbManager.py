import mysql.connector
# servers is a list of server objecs
class dbManager:
	connection = None
	cursor = None
	def connect(self):
		try:
			self.connection = mysql.connector.connect(user='CS523',password='^^@keMYd@y',
										host='127.0.0.1', database='CS523')
			self.cursor = self.connection.cursor()
		except mysql.connector.Error, err:
			print("Database connection error: ")
			print(err)

	def updateDb(self, servers):
		#inserting the new vulnerabilities into the database and updating if the already exsist
		for server in servers:
			for vul in server.getVuls():
				self.cursor.execute(
					"INSERT INTO Vulnerability (qid, ip, first_saw, last_saw)\
					 VALUES (%s,%s,%s,%s)\
				ON DUPLICATE KEY UPDATE last_saw = Values(last_saw)",
				(vul.getQID(),server.getIp(),server.getDate(),server.getDate()))
	
		#deleting the vulnerabilities that no longer exsist
		if (len(servers) > 0):
			date = servers[0].getDate()
			self.cursor.execute(
				"Delete FROM Vulnerability\
				WHERE last_saw < %s", (date,) 	
			)
		self.connection.commit()
	# first_saw given an ip returns the date of a vulnerability in a string "YYYY-MM-DD" or 
	# if no date found it returns an empty string
	
	def first_saw(self, ip, qid):
		date_format = "%Y-%m-%d"
		self.cursor.execute("SELECT DATE_FORMAT(first_saw, %s) FROM Vulnerability WHERE ip=%s AND qid=%s",(date_format,ip,qid))
		date = self.cursor.fetchall()
		return date[0][0]
	def dateDiff(self, dateOne, dateTwo):
		self.cursor.execute("SELECT DATEDIFF(%s, %s)",(dateOne, dateTwo))
		return self.cursor.fetchall()[0][0]
