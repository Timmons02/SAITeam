from HTMLParser import HTMLParser
import  mysql.connector
class Server:
    
    def __init__(self, ip_host):
        self.date = "none"
        self.ip_host = "none"
        self.failed_port = "none"
        self.vuls = list()
        self.i = 0
        self.ip_host = ip_host   
    def setDate(self, date):
        self.date = date
    def setIpHost(self, ip_host):
        self.ip_host = ip_host
    def setFailedPort(self, port):
        self.failed_port = port
    def addVulnerability(self, vul):
        self.vuls.append(vul)
        self.i = self.i + 1
    def getDate(self):
        return self.date
    def getIpHost(self):
        return self.ip_host
    def getVuls(self):
        return self.vuls
    def getLastVul(self):
        return self.vuls[self.i-1]
    def getFailedPort(self):
        return self.failed_port


class Vulnerability():
    
    def __init__(self, qid, level, threat, impact, solution):
        self.qid = qid
        self.level = level
        self.sum_threat = threat
        self.sum_impact = impact
        self.sum_solution = solution
    def getQID(self):
        return self.qid
    def getLevel(self):
        return self.level
    def getSum_threat(self):
        return self.sum_threat
    def getSum_impact(self):
        return self.sum_impact
    def getSum_solution(self):
        return self.sum_solution
    def setQID(self, qid):
        self.qid = qid
    def setLevel(self, level):
        self.level = level
    def setSum_threat(self, sum_threat):
        self.sum_threat = sum_threat
    def setSum_impact(self, sum_impact):
        self.sum_impact = sum_impact
    def setSum_solution(self, sum_solution):
        self.sum_solution = sum_solution
        
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
    cur = None
    con = None
    server_list = []           # server_list of department objects
    list_index = -1     # index of the server_list
    date = "none"
    
    not_alive_tag = 0
    not_alive_next = 0
    win_auth_fail = 0
    win_fail = 0
    unixcisco_auth_fail = 0
    unixcisco_fail = 0
    oracle_auth_fail = 0
    oracle_fail = 0
    host_flag = 0
    oracle_port = "none"
    sum_imminent = 0
    sum_now = 0
    sum_threat = 0
    sum_impact = 0
    sum_solution = 0
    ready_for_sum = 0
    threat = "none"
    impact = "none"
    solution = "none"
    level = -1
    qid = -1
    v_index = 0
    
    def printList(self):
        print "amount of servers " + str(len(self.server_list))
        for i in self.server_list:
            print "SERVER:"
            print i.getDate()
            print i.getIpHost()
            if i.getFailedPort() != "none":
                print "Server failed to scan. " + str(i.getFailedPort())
                return
            for j in i.getVuls():
                print j.getQID()
                print j.getLevel()
                print j.getSum_threat()
                print j.getSum_impact()
                print j.getSum_solution()
                
    def getList (self):
        return self.server_list
    def setCur(self, cur, con):
        self.cur=cur
        self.con=con
    def handle_starttag(self, tag, attrs):
        if tag == "dd" and self.date_next_dd_tag == 1:
            self.date_ready = 1
        elif tag == "dl" and attrs[0]==('id','rpt_sum_det'):   
            self.date_next_dd_tag = 1 
        elif tag == "span" and attrs[0]==('class','host_id'):
            self.ip_host_ready = 1
        elif tag == "div" and len(attrs)>1 and attrs[0]==('class','severity_icon') and (attrs[1]==('title','Vulnerability - level 4') or attrs[1]==('title','Vulnerability - level 5')): 
            self.vul_next_img_tag = 1
            self.ready_for_sum = 1
        elif self.vul_next_img_tag == 1 and tag == "img":
            self.vul_ready = 1
            self.record_qid = 1             
        elif tag == "acronym" and attrs[0]==('title','Qualys Identification') and self.record_qid == 1:
            self.qid_next_dd_tag = 1
        elif self.qid_next_dd_tag == 1 and tag == "dd":
            self.qid_ready = 1  
        # Handling hosts that were not scanned
        elif tag == "div" and len(attrs)>0 and attrs[0]==('id', '94652'):
            self.not_alive_tag = 1
        elif tag == "div" and len(attrs)>0 and attrs[0]==('id', '94654'):
            self.win_auth_fail = 1
        elif self.win_auth_fail == 1 and tag == "div" and len(attrs)>0 and attrs[0]==('class', 'report_result'):
            self.win_fail = 1
        elif tag == "div" and len(attrs)>0 and attrs[0]==('id', '94655'):
            self.unixcisco_auth_fail = 1
        elif self.unixcisco_auth_fail == 1 and tag == "div" and len(attrs)>0 and attrs[0]==('class', 'report_result'):
            self.unixcisco_fail = 1
        elif tag == "div" and len(attrs)>0 and attrs[0]==('id', '94656'):
            self.oracle_auth_fail = 1
        elif self.oracle_auth_fail == 1 and tag == "div" and len(attrs)>0 and attrs[0]==('class', 'report_result'):
            self.oracle_fail = 1
        elif tag == "div" and len(attrs)>0 and attrs[0]==('id', '94657'):
            self.oracle_auth_fail = 0
        elif tag == "dl" and len(attrs)>0 and attrs[0]==('class', 'vulnDetails'):
            self.sum_imminent = 1
    
    def handle_data(self, data):
        if self.ready_for_sum == 1 and self.sum_imminent == 1 and "THREAT" in data:
            self.sum_threat = 1
        elif self.ready_for_sum == 1 and self.sum_threat == 1:
            self.threat = data
            self.sum_threat = 0
        elif self.ready_for_sum == 1 and self.sum_imminent == 1 and "IMPACT" in data:
            self.sum_impact = 1
        elif self.ready_for_sum == 1 and self.sum_impact == 1:
            self.impact = data
            self.sum_impact = 0
        elif self.ready_for_sum == 1 and self.sum_imminent == 1 and "SOLUTION" in data:
            self.sum_solution = 1
        elif self.ready_for_sum == 1 and self.sum_solution == 1:
            self.solution = data
            self.sum_solution = 0
            self.sum_imminent = 0
            self.ready_for_sum = 0
            self.server_list[self.list_index].addVulnerability(Vulnerability(self.qid, self.level, self.threat, self.impact, self.solution))
            #print "For server:"
            #print self.server_list[self.list_index].getIpHost() + " at index " + str(self.list_index)
            #print "Added vulnerability:"
            #print "QID: " + self.server_list[self.list_index].getLastVul().getQID() + " and level " + self.server_list[self.list_index].getLastVul().getLevel()
        elif self.date_ready == 1:
            #print "Date data encountered."
            #print data
            self.date = data
            self.date_ready = 0
            self.date_next_dd_tag = 0
        elif self.ip_host_ready == 1:
            #print "IP and Host data encountered."
            #print data
            self.list_index = self.list_index + 1
            serv = Server(data)
            serv.setDate(self.date)
            #print "Server added: " + serv.getIpHost() + " at index " + str(self.list_index)
            self.server_list.append(serv)
            #print "List total: " + str(len(self.server_list))
            self.ip_host_ready = 0
        elif self.vul_ready == 1:
            #print "Vulnerability level encountered."
            vlevel = -1
            for c in data:
                if c.isdigit():
                    vlevel = c
                    #print c
                    break
            self.level = vlevel
            self.vul_next_img_tag = 0
            self.vul_ready = 0
        elif self.qid_ready == 1:
            #print "QID encountered."
            #print data
            self.qid = data
            self.qid_next_dd_tag = 0
            self.qid_ready = 0
            self.record_qid = 0
        # Handling hosts not scanned.
        elif self.oracle_auth_fail == 1:
            if "Port" in data:
                self.oracle_port = data
        """elif self.oracle_fail == 1:
            self.list_index = self.list_index + 1
            serv = Server(data)
            serv.setDate(self.date)
            serv.setFailedPort(self.oracle_port)
            self.server_list.append(serv)
            #print "ORACLE FAIL SERVER"
            #print "Oracle authentication failed for host and port:"
            #print "Host:"
            #print data
            #print "Port:"
            #print self.oracle_port
            self.oracle_fail = 0"""
        elif self.win_fail == 1:
            #print "Windows authentication failed for these hosts:"
            #print data
            self.win_fail = 0
            self.win_auth_fail = 0
        elif self.unixcisco_fail == 1:
            #print "Unix/Cisco authentication failed for these hosts:"
            #print data
            self.unixcisco_fail = 0
            self.unixcisco_auth_fail = 0
        elif self.not_alive_next == 1:
            #print "Hosts not alive:"
            #print data
            self.not_alive_next = 0
        elif self.not_alive_tag == 1:
            #print "Hosts not alive encountered."
            self.not_alive_next = 1
            self.not_alive_tag = 0
        
    def updateDataBase(self):
        i = 0
        for d in self.server_list:
            for q in d.qids:
                cur.execute("INSERT INTO Vulnerability (vid, qid, date, ip) VALUES (?,?,?,?)", (i,q, d.getDate(), d.getIpHost()))
                i = i + 1
        con.commit()
                
print "Execution has begun."

# instantiate the parser and fed it some HTML
parser = MyHTMLParser()

# open a file and feed it to the parser
my_file = open("fakehtml.html", "r")
parser.feed(my_file.read())
parser.printList()
print "Execution complete."