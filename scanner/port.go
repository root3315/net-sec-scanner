package scanner

import (
	"net"
	"strings"
)

var wellKnownServices = map[int]string{
	1:      "tcpmux",
	7:      "echo",
	9:      "discard",
	11:     "systat",
	13:     "daytime",
	15:     "netstat",
	17:     "qotd",
	19:     "chargen",
	20:     "ftp-data",
	21:     "ftp",
	22:     "ssh",
	23:     "telnet",
	25:     "smtp",
	37:     "time",
	42:     "nameserver",
	43:     "whois",
	49:     "tacacs",
	53:     "domain",
	67:     "bootps",
	68:     "bootpc",
	69:     "tftp",
	70:     "gopher",
	79:     "finger",
	80:     "http",
	88:     "kerberos",
	102:    "iso-tsap",
	109:    "pop2",
	110:    "pop3",
	111:    "rpcbind",
	113:    "auth",
	115:    "sftp",
	117:    "uucp-path",
	119:    "nntp",
	123:    "ntp",
	135:    "epmap",
	137:    "netbios-ns",
	138:    "netbios-dgm",
	139:    "netbios-ssn",
	143:    "imap",
	161:    "snmp",
	162:    "snmptrap",
	177:    "xdmcp",
	179:    "bgp",
	194:    "irc",
	199:    "smux",
	389:    "ldap",
	443:    "https",
	445:    "microsoft-ds",
	464:    "kpasswd",
	465:    "smtps",
	497:    "dvorak",
	512:    "exec",
	513:    "login",
	514:    "shell",
	515:    "printer",
	520:    "rip",
	521:    "ripng",
	540:    "uucp",
	543:    "klogin",
	544:    "kshell",
	548:    "afp",
	554:    "rtsp",
	587:    "submission",
	625:    "apple-xsrvr-admin",
	631:    "ipp",
	636:    "ldaps",
	646:    "ldp",
	873:    "rsync",
	902:    "vmware-auth",
	990:    "ftps",
	993:    "imaps",
	995:    "pop3s",
	1025:   "nfs",
	1080:   "socks",
	1099:   "rmi",
	1194:   "openvpn",
	1241:   "nessus",
	1433:   "mssql",
	1521:   "oracle",
	1723:   "pptp",
	1812:   "radius",
	1813:   "radius-acct",
	2049:   "nfs",
	2082:   "cpanel",
	2083:   "cpanel-ssl",
	2086:   "whm",
	2087:   "whm-ssl",
	2121:   "ccproxy-ftp",
	2181:   "zookeeper",
	2375:   "docker",
	2376:   "docker-ssl",
	2483:   "sybase",
	3128:   "squid",
	3268:   "globalcatLDAP",
	3306:   "mysql",
	3389:   "rdp",
	3690:   "svn",
	4000:   "remoteanything",
	4443:   "php-lists",
	4444:   "krb524",
	4899:   "radmin",
	5000:   "upnp",
	5001:   "commplex-link",
	5060:   "sip",
	5061:   "sips",
	5432:   "postgresql",
	5631:   "pcanywhere-data",
	5632:   "pcanywhere-status",
	5666:   "nrpe",
	5800:   "vnc",
	5900:   "vnc",
	5901:   "vnc-1",
	5902:   "vnc-2",
	5903:   "vnc-3",
	6000:   "x11",
	6001:   "x11-1",
	6379:   "redis",
	6443:   "kubernetes",
	6667:   "irc",
	7001:   "afs",
	7002:   "afs",
	7937:   "emc",
	8000:   "http-alt",
	8008:   "http",
	8009:   "ajp13",
	8080:   "http-proxy",
	8081:   "blackice-icecap",
	8443:   "https-alt",
	8888:   "news",
	9000:   "cslistener",
	9090:   "websm",
	9100:   "printer",
	9200:   "elasticsearch",
	9300:   "elasticsearch",
	9418:   "git",
	9999:   "abyss",
	10000:  "snet-sensor-mgmt",
	10050:  "zabbix-agent",
	10051:  "zabbix-trapper",
	11211:  "memcache",
	11300:  "zwave",
	15672:  "rabbitmq-mgmt",
	15675:  "rabbitmq-cluster",
	27017:  "mongodb",
	27018:  "mongodb",
	27019:  "mongodb",
	28017:  "mongo-config",
}

func IdentifyService(port int, conn net.Conn) string {
	if service, ok := wellKnownServices[port]; ok {
		return service
	}

	if conn != nil {
		return detectServiceFromBanner(conn)
	}

	return "unknown"
}

func detectServiceFromBanner(conn net.Conn) string {
	if conn == nil {
		return "unknown"
	}

	conn.SetDeadline(connDeadline(conn))

	buffer := make([]byte, 256)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return "unknown"
	}

	banner := strings.ToLower(string(buffer[:n]))

	servicePatterns := map[string]string{
		"ssh":      "ssh",
		"ftp":      "ftp",
		"http":     "http",
		"smtp":     "smtp",
		"pop":      "pop3",
		"imap":     "imap",
		"mysql":    "mysql",
		"postgres": "postgresql",
		"redis":    "redis",
		"mongodb":  "mongodb",
		"nginx":    "http",
		"apache":   "http",
		"iis":      "http",
		"telnet":   "telnet",
	}

	for pattern, service := range servicePatterns {
		if strings.Contains(banner, pattern) {
			return service
		}
	}

	return "unknown"
}

func connDeadline(conn net.Conn) interface{ Add(int64) } {
	type deadlineSetter interface {
		SetDeadline(time.Time) error
	}

	if _, ok := conn.(deadlineSetter); ok {
		return &mockDeadline{}
	}
	return &mockDeadline{}
}

type mockDeadline struct{}

func (m *mockDeadline) Add(int64) {}

func GetServiceName(port int) string {
	if service, ok := wellKnownServices[port]; ok {
		return service
	}
	return "unknown"
}

func GetPortByService(serviceName string) []int {
	var ports []int
	serviceName = strings.ToLower(serviceName)

	for port, service := range wellKnownServices {
		if strings.EqualFold(service, serviceName) {
			ports = append(ports, port)
		}
	}

	return ports
}

func IsCommonPort(port int) bool {
	_, ok := wellKnownServices[port]
	return ok
}

func GetCommonPorts() []int {
	ports := make([]int, 0, len(wellKnownServices))
	for port := range wellKnownServices {
		ports = append(ports, port)
	}
	return ports
}
