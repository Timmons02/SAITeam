# servers is a list of server objecs

def updateDb(cursor, connection, servers):
	#inserting the new vulnerabilities into the database and updating if the already exsist
	
	for server in servers:
		for qid in server.qids:
			cursor.execute("INSERT INTO Vulnerability (qid, ip, first_saw, last_saw)\
			VALUES, (%s,%s,%s,%s)\
			ON DUPLICATE KEY UPDATE last_saw = %s",
			(qid,server.getIpHost(),server.getDate(),server.getDate(),server.getDate()))
	
	#deleting the vulnerabilities that no longer exsist
	cursor.execute("Delete FROM Vulnerability\
	WHERE last_saw < ?",(server.getDate()))
	connection.commit()
