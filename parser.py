from HTMLParser import HTMLParser
#import  mysql.connector

# This program is intended for parsing a Qualys HTML file resulting 
# from a Qualys scan. The format and structure of the HTML file is 
# important in determining relevant data.

# A server represents one of the scanned servers. Each server has:
#    ip_host - An IP address and host name
#    date - A date that the server was scanned
#    vuls[] - A python list of vulnerability objects
#    failed_port - A port that failed to scan. This will only 
#                  occur on Oracle servers that fail to scan.
#    
#    This class has Getter and Setter methods for each field.
class Server:
    
    def __init__(self, ip_host):
        self.date = "none"
        self.ip_host = "none"       
        self.failed_port = "none"   # For failed Oracle servers only
        self.vuls = list()          # A list of vulnerabilities
        self.ip_host = ip_host   
    def setDate(self, date):
        self.date = date
    def setIpHost(self, ip_host):
        self.ip_host = ip_host
    def setFailedPort(self, port):
        self.failed_port = port
    def addVulnerability(self, vul):
        self.vuls.append(vul)
    def getDate(self):
        date = self.date.split()[0].split('/')
        return date[2] + "-" + date[0] + "-" + date[1]
    def getIpHost(self):
        return self.ip_host
    def getVuls(self):
        return self.vuls
    def getFailedPort(self):
        return self.failed_port
    def getIp(self):
        return self.ip_host.split(" ")[0]

# A Vulnerability represents a vulnerability that is found on a server.
# Each Vulnerability  contains:
#    qid - the Qualys Identifier for this specific vulnerability
#    level - the assigned Qualys level of this threat
#    sum_threat - the threat summary
#    sum_impact - the impact summary
#    sum_solution - the solution summary
# This class has Getter and Setter methods for each field.
class Vulnerability():
    
    def __init__(self, name, qid, level, threat, impact, solution):
        self.name = name
        self.qid = qid
        self.level = level
        self.sum_threat = threat
        self.sum_impact = impact
        self.sum_solution = solution
    def getName(self):
        return self.name
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
    def setName(self, name):
        self.name = name
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
        
# Create a subclass of HTMLParser and override the handler methods. This
# class uses the inherited HTMLParser to detect when HTML start tags,
# data, and end tags are encountered and calls the appropriate handler 
# methods. The handler methods use flags to determine when to extract
# data. The result of feeding the correct HTML file into the parser will
# result in MyHTMLParser having a list of server objects and their 
# respective vulnerabilities.
class MyHTMLParser(HTMLParser):
    
    server_list = []           # server_list of server objects
    list_index = -1
    date = "none"
    cur = None
    con = None
    name = "none"
    threat = "none"
    impact = "none"
    solution = "none"
    level = -1
    qid = -1
    oracle_port = "none"
    
    # Booleans for detecting when to extract data
    ip_host_ready = 0
    date_next_dd_tag = 0
    vul_next_img_tag = 0
    qid_next_dd_tag = 0
    name_next_a_tag = 0
    qid_section = 0
    date_ready = 0
    vul_ready = 0
    qid_ready = 0
    name_ready = 0
    not_alive_section = 0
    win_fail_section = 0
    unixcisco_fail_section = 0
    oracle_fail_section = 0
    not_alive = 0
    win_fail = 0
    unixcisco_fail = 0
    oracle_fail = 0
    host_flag = 0
    sum_section = 0
    sum_threat = 0
    sum_impact = 0
    sum_solution = 0
    ready_for_sum = 0
    
    # This method prints all of the servers and their vulnerabilities.
    def printList(self):
        print "Amount of servers " + str(len(self.server_list))
        for i in self.server_list:
            print "SERVER:"
            print "Date:        " + i.getDate()
            print "IP and Host: " + i.getIpHost()
            if i.getFailedPort() != "none":
                print "Server failed to scan on port " + str(i.getFailedPort())
            for j in i.getVuls():
                print "  Vulnerability found."
                print "    Name: " + j.getName()
                print "    QID: " + str(j.getQID())
                print "    Level: " + str(j.getLevel())
                print "    Threat: " + j.getSum_threat()
                print "    Impact: " + j.getSum_impact()
                print "    Solution: " + j.getSum_solution()  
                        
    # This method uses the structure of the HTML file to set and remove
    # flags for the handle_data() method to know when to extract data.
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
            self.name_next_a_tag = 1
        elif self.vul_next_img_tag == 1 and tag == "img":
            self.vul_ready = 1
            self.qid_section = 1             
        elif tag == "acronym" and attrs[0]==('title','Qualys Identification') and self.qid_section == 1:
            self.qid_next_dd_tag = 1
        elif self.qid_next_dd_tag == 1 and tag == "dd":
            self.qid_ready = 1  
        elif self.name_next_a_tag == 1 and tag == "a":
            self.name_ready = 1
            self.name_next_a_tag = 0
        # Handling hosts that were not scanned
        elif tag == "div" and len(attrs)>0 and attrs[0]==('id', '94652'):
            self.not_alive_section = 1
        elif tag == "div" and len(attrs)>0 and attrs[0]==('id', '94654'):
            self.win_fail_section = 1
        elif self.win_fail_section == 1 and tag == "div" and len(attrs)>0 and attrs[0]==('class', 'report_result'):
            self.win_fail = 1
        elif tag == "div" and len(attrs)>0 and attrs[0]==('id', '94655'):
            self.unixcisco_fail_section = 1
        elif self.unixcisco_fail_section == 1 and tag == "div" and len(attrs)>0 and attrs[0]==('class', 'report_result'):
            self.unixcisco_fail = 1
        elif tag == "div" and len(attrs)>0 and attrs[0]==('id', '94656'):
            self.oracle_fail_section = 1
        elif self.oracle_fail_section == 1 and tag == "div" and len(attrs)>0 and attrs[0]==('class', 'report_result'):
            self.oracle_fail = 1
        elif tag == "div" and len(attrs)>0 and attrs[0]==('id', '94657'):
            self.oracle_fail_section = 0
        elif tag == "dl" and len(attrs)>0 and attrs[0]==('class', 'vulnDetails'):
            self.sum_section = 1
    
    # This method (1) sets and removes flags to know when to extract 
    # data and (2) uses flags to extract data when appropriate and
    # (3) uses collected data to create server objects, vulnerability
    # objects, and add the vulnerabilities to the correct servers.
    def handle_data(self, data):
        # Next data will be the threat information. Sets appropriate flag.
        if self.ready_for_sum == 1 and self.sum_section == 1 and "THREAT" in data:
            self.sum_threat = 1
        # Threat data encountered.
        elif self.ready_for_sum == 1 and self.sum_threat == 1:
            self.threat = data
            self.sum_threat = 0
        # Next data will be the impact information. Sets appropriate flag.
        elif self.ready_for_sum == 1 and self.sum_section == 1 and "IMPACT" in data:
            self.sum_impact = 1
        # Impact data encountered.
        elif self.ready_for_sum == 1 and self.sum_impact == 1:
            self.impact = data
            self.sum_impact = 0
        # Next data will be the solution information. Sets appropriate flag.
        elif self.ready_for_sum == 1 and self.sum_section == 1 and "SOLUTION" in data:
            self.sum_solution = 1
        # Data contains the solution string.
        # All data for a vulnerability has been extracted. 
        # The vulnerability is created and added to the current server.
        elif self.ready_for_sum == 1 and self.sum_solution == 1:
            self.solution = data
            self.sum_solution = 0
            self.sum_section = 0
            self.ready_for_sum = 0
            self.server_list[self.list_index].addVulnerability(Vulnerability(self.name, self.qid, self.level, self.threat, self.impact, self.solution))
        # Data contains a date.
        elif self.date_ready == 1:
            self.date = data
            self.date_ready = 0
            self.date_next_dd_tag = 0
        # Data contains and IP and host name.
        elif self.ip_host_ready == 1:
            self.list_index = self.list_index + 1
            serv = Server(data)
            serv.setDate(self.date)
            self.server_list.append(serv)
            self.ip_host_ready = 0
        # Data contains a vulnerability level.
        elif self.vul_ready == 1:
            vlevel = -1
            for c in data:
                if c.isdigit():
                    vlevel = c
                    #print c
                    break
            self.level = vlevel
            self.vul_next_img_tag = 0
            self.vul_ready = 0
        # Data contains a QID.
        elif self.qid_ready == 1:
            self.qid = data
            self.qid_next_dd_tag = 0
            self.qid_ready = 0
            self.qid_section = 0
        # Data contains a vulnerability name
        elif self.name_ready == 1:
            self.name = data
            self.name_ready = 0
        # Data contains an Oracle server that failed to scan.
        # Creates the server object and adds it to the server list.
        elif self.oracle_fail == 1:
            self.list_index = self.list_index + 1
            serv = Server(data)
            serv.setDate(self.date)
            serv.setFailedPort(self.oracle_port)
            serv.addVulnerability(Vulnerability("Oracle Authentication failed", 60000001, 5, "Oracle Authentication failed for this host.", "This server may be vulnerable.", "Scan this host."))
            self.server_list.append(serv)
            self.oracle_fail = 0
        # Data contains a failed Oracle port.
        elif self.oracle_fail_section == 1:
            if "Port" in data:
                self.oracle_port = self.portParser(data)
        # Data contains a list of Windows hosts that failed to scan.
        # Parses the list of hosts and creates server objects for each.
        elif self.win_fail == 1:
            h = self.hostParser(data)
            for i in h:
                serv = Server(i)
                serv.setDate(self.date)
                serv.addVulnerability(Vulnerability("Windows Authentication failed", 60000001, 5, "Windows Authentication failed for this host.", "This server may be vulnerable.", "Scan this host."))
                self.server_list.append(serv)
            self.win_fail = 0
            self.win_fail_section = 0
        # Data contains a list of Unix/Cisco objects that failed to scan.
        # Parses the list of hosts and creates server objects for each.
        elif self.unixcisco_fail == 1:
            h = self.hostParser(data)
            for i in h:
                serv = Server(i)
                serv.setDate(self.date)
                serv.addVulnerability(Vulnerability("Unix/Cisco Authentication failed", 60000001, 5, "Unix/Cisco Authentication failed for this host.", "This server may be vulnerable.", "Scan this host."))
                self.server_list.append(serv)
            self.unixcisco_fail = 0
            self.unixcisco_fail_section = 0
        # Data contains a list of hosts that were not alive.
        # Parses the list of hosts and creates server objects for each.
        elif self.not_alive == 1:
            h = self.hostParser(data)
            for i in h:
                serv = Server(i)
                serv.setDate(self.date)
                serv.addVulnerability(Vulnerability("Host not alive", 60000002, 5, "Host not alive for scan.", "This server may be vulnerable.", "Scan this host."))
                self.server_list.append(serv)
            self.not_alive = 0
        # Current data is not useful; but the section is relevant.
        elif self.not_alive_section == 1:
            self.not_alive = 1
            self.not_alive_section = 0
    
    # This method parses a string that has IP addresses. It 
    # splits the string to put each IP address into a list
    # and returns the list.
    def hostParser(self, host_str):
        begin = 0
        end = 0
        host_list = []
        for c in host_str:
            if c == ',':
                host_list.append(host_str[begin:end])
                begin = end + 3
                end = end + 1
            else:
                end = end + 1
        host_list.append(host_str[begin:end])
        return host_list
    
    # This method takes a string and parses it for the 
    # port number that is expected in the string. The port
    # number is expected 5 characters after the first 'P'
    # char that is seen. ('P' for Port as in Port 123)
    def portParser(self, port_str):
        begin = 0
        end = 0
        index = 0
        for c in port_str:
            if c == 'P':
                begin = index + 5
                index = index + 1
            elif c == ':':
                end = index 
                return port_str[begin:end]
            else:
                index = index + 1
                
    # This method returns the list of servers.
    def getList (self):
        return self.server_list
    
    def setCur(self, cur, con):
        self.cur=cur
        self.con=con        
                
print "Execution has begun."

# instantiate the parser and fed it some HTML
parser = MyHTMLParser()

# open a file and feed it to the parser
my_file = open("fakehtml.html", "r")
parser.feed(my_file.read())
parser.printList()
print "Execution complete."