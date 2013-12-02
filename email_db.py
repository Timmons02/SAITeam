import mysql.connector
class email_db:
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

	def getEmail(self, department):
		self.cursor.execute("SELECT E_MAIL FROM  email WHERE SAI_GROUP=%s", (department,))
		emails = self.cursor.fetchall()
		ret = []
		i = 0;
		while (i<len(emails)):
			ret.append(emails[i][0])
			i= i+1
		return ret

emails = email_db()
emails.connect()
print emails.getEmail("CHARLES")
