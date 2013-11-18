from HTMLParser import HTMLParser
import  mysql.connector
class Server:
    date = "none"
    ip_host = "none"
    vul = "none"
    vulnerabilities = []
    qid = "none"
    qids = []
    sum = "none"
    def __init__(self, ip_host):
        self.ip_host = ip_host   
    def setName(self, name):
        self.name = name
    def setDate(self, date):
        self.date = date
    def setIpHost(self, ip_host):
        self.ip_host = ip_host
    def setVulnerability(self, vul):
        self.vul = vul
    def setQID(self, qid):
        self.qid = qid
    def setErrorSummary(self, summary):
        self.sum = summary
    def addQID(self, qid):
        self.qids.append(qid)
    def addVulnerability(self, vul):
        self.vulnerabilities.append(vul)
    def getDate(self):
        return self.date
    def getIpHost(self):
        return self.ip_host
    def getVulnerability(self):
        return self.vul
    def getQID(self):
        return self.qid

# create a subclass and override the handler methods
class MyHTMLParser(HTMLParser):
    # booleans for detecting when to get data
    date_next_dd_tag = 0
    date_ready = 0
    ip_host_ready = 0
    vul_ready = 0
    vul_next_img_tag = 0
    record_qid = 0
    qid_next_dd_tag = 0
    qid_ready = 0
    error_sum_next_a_tag = 0
    error_sum_ready = 0
    cur = None
    con = None
    list = []           # list of department objects
    list_index = -1     # index of the list
    qid_index = 0
    date = "none"
    def getList (self):
		return this.list
    def setCur(self, cur, con):
        self.cur=cur
        self.con=con
    def handle_starttag(self, tag, attrs):
        if tag == "dd" and self.date_next_dd_tag == 1:
            self.date_ready = 1
        if tag == "dl" and attrs[0]==('id','rpt_sum_det'):   
            self.date_next_dd_tag = 1 
        if tag == "span" and attrs[0]==('class','host_id'):
            self.ip_host_ready = 1
        if tag == "div" and len(attrs)>1 and attrs[0]==('class','severity_icon') and (attrs[1]==('title','Vulnerability - level 4') or attrs[1]==('title','Vulnerability - level 5')): 
            self.vul_next_img_tag = 1
        if self.vul_next_img_tag == 1 and tag == "img":
            self.vul_ready = 1
            self.record_qid = 1             
        if tag == "acronym" and attrs[0]==('title','Qualys Identification') and self.record_qid == 1:
            self.qid_next_dd_tag = 1
        if self.qid_next_dd_tag == 1 and tag == "dd":
            self.qid_ready = 1  
        #if self.error_sum_next_a_tag == 1 and tag == "a"       
    def handle_data(self, data):
        if self.date_ready == 1:
            print "Date data encountered."
            print data
            self.date = data
            self.date_ready = 0
            self.date_next_dd_tag = 0
        if self.ip_host_ready == 1:
            print "IP and Host data encountered."
            print data
            self.list_index = self.list_index + 1
            dpt = Server(data)
            self.list.append(dpt)
            self.list[self.list_index].setDate(self.date)
            self.ip_host_ready = 0
        if self.vul_ready == 1:
            print "Vulnerability level encountered."
            print data
            self.list[self.qid_index].addVulnerability(data)
            self.vul_next_img_tag = 0
            self.vul_ready = 0
        if self.qid_ready == 1:
            print "QID encountered."
            print data
            self.list[self.qid_index].addQID(data)
            self.qid_index = self.qid_index + 1
            self.qid_next_dd_tag = 0
            self.qid_ready = 0
            self.record_qid = 0
            
    def getAllData(self):
        s = "IP"
    def updateDataBase(self):
		i = 0
		for d in self.list:
			for q in d.qids:
				cur.execute("INSERT INTO Vulnerability (vid, qid, date, ip) VALUES (?,?,?,?)", (i,q, d.getDate(), d.getIpHost()))
				i = i + 1
		con.commit()

print "Execution has begun."
# instantiate the parser and fed it some HTML
parser = MyHTMLParser()

# open a file and feed it to the parser
my_file = open("fakehtml.html", "r")
condition = True
#
#while condition:
#	line = my_file.readline()
#	if "</script>" in line:
#		condition = False
text = my_file.read()
one, two, three  = text.split("</script>",2)
open("output.txt", 'wt').write(three)
my_file = open("output.txt","r")
parser.feed(my_file.read())
#parser.close()
#parser.setCur(cur, con)
#parser.insert()
print "Execution complete."
