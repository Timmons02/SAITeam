class Department:
	def __init__(self, database, server, folder, name, emails):
		self.database = database
		self.servers = [server]
		self.path = folder
		self.name = name
		self.emails = emails
	def writeFile(self):
		ninetyDays = list()
		sixtyDays = list()
		thirtyDays = list()
		zeroDays = list()
		self.date = self.servers[0].getDate() 
		for server in self.servers:
			for vuln in server.getVuls():
				days = self.database.dateDiff(self.database.first_saw(server.getIp(),vuln.getQID()),self.date)
				if days >= 90:
					ninetyDays.append((vuln,server.getIpHost()))
				elif days >= 60:
					sixtyDays.append((vuln,server.getIpHost()))
				elif days >= 30:
					thirtyDays.append((vuln,server.getIpHost()))
				elif days >= 0:
					zeroDays.append((vuln,server.getIpHost()))
		file = open(self.path+"/"+self.name+".txt",'w')  # is path properly formatted here?
		file.write("These are the results of a monthly scan of your system conducted on "+self.date+".\n\n\n")
		if len(sixtyDays) > 0:
			file.write("The following vulnerabilities have been on your system for a period greater than 60 days. Please address them as soon as possible or immediate action will be taken by the university.\n\n")
			for vuln in sixtyDays:
				file.write(vuln[1]+": QID: "+vuln[0].getQID()+" Threat: "+vuln[0].getSum_threat()+" Impact: "+vuln[0].getSum_impact()+"\n\n")
		if len(thirtyDays) > 0:
			file.write("The following vulnerabilities have been on your system for a period greater than 30 days and are no longer in compliance with UNC standards. Please address them as soon as possible.\n\n")
			for vuln in thirtyDays:
				file.write(vuln[1]+" QID: "+vuln[0].getQID()+" Threat: "+vuln[0].getSum_threat()+" Impact: "+vuln[0].getSum_impact()+"\n\n")
		if len(zeroDays) > 0:
			file.write("The following vulnerabilities have newly arisen on your systems. Please patch them as soon as possible.\n\n")
			for vuln in zeroDays:
				file.write(vuln[1]+" QID: "+vuln[0].getQID()+" Threat: "+vuln[0].getSum_threat()+" Impact: "+vuln[0].getSum_impact()+"\n\n")
		file.close()
		if (len(sixtyDays) != 0) or (len(thirtyDays) != 0) or (len(zeroDays) != 0):
			self.writeMail()  
		if len(ninetyDays) > 0: 
			self.referral(ninetyDays)
	def writeMail(self):
		import smtplib
		from email.MIMEText import MIMEText 
		text = open("/home/cmanker/"+self.path+"/"+self.name+".txt",'r')
		msg = MIMEText(text.read())
		text.close()
		msg['Subject'] = self.name+" security scan summary "+self.date
		msg['To'] = 'charlesmanker@gmail.com' # to be changeD
		msg['From'] = 'charlesmanker@gmail.com' # We will change this later
		smtp = smtplib.SMTP('smtp.gmail.com',587)
		smtp.ehlo()  
		smtp.starttls()
		smtp.ehlo()
		smtp.login('charlesmanker@gmail.com','fakepassword')
		smtp.sendmail('charlesmanker@gmail.com',['charlesmanker@gmail.com'],msg.as_string())
		smtp.quit()
	def referral(self,ninetyDays):
		import smtplib
		from email.mime.text import MIMEText
		text = "The department "+self.name+" has had the following vulnerabilities on its system for a period of greater than 90 days.\n\n"
		for vuln in ninetyDays:
			text = text + vuln[1]+" QID: "+vuln[0].getQID()+" Description: "+vuln[0].getSum_threat()+"\n\n"
		msg = MIMEText(text)
		msg['Subject'] = "VPR_Referral "+self.name
		msg['To'] = 'charlesmanker@gmail.com' # security@unc.edu
		msg['From'] = 'charlesmanker@gmail.com' # change this
		smtp = smtplib.SMTP('smtp.gmail.com',587)
		smtp.ehlo()
		smtp.starttls()
		smtp.login('charlesmanker@gmail.com','fakepassword')
		smtp.sendmail('charlesmanker@gmail.com',['charlesmanker@gmail.com'],msg.as_string())
		smtp.quit()
	def addServer(self, server):
		self.servers.append(server)


