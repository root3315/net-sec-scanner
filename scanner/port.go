package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
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

var servicePatterns = []struct {
	pattern *regexp.Regexp
	service string
}{
	{regexp.MustCompile(`(?i)^ssh-`), "ssh"},
	{regexp.MustCompile(`(?i)ssh-`), "ssh"},
	{regexp.MustCompile(`(?i)^220.*ftp`), "ftp"},
	{regexp.MustCompile(`(?i)^220.*filezilla`), "ftp"},
	{regexp.MustCompile(`(?i)^220.*vsftpd`), "ftp"},
	{regexp.MustCompile(`(?i)^220.*proftpd`), "ftp"},
	{regexp.MustCompile(`(?i)^220`), "ftp"},
	{regexp.MustCompile(`(?i)^http/`), "http"},
	{regexp.MustCompile(`(?i)http/`), "http"},
	{regexp.MustCompile(`(?i)^http`), "http"},
	{regexp.MustCompile(`(?i)server:.*apache`), "http"},
	{regexp.MustCompile(`(?i)server:.*nginx`), "http"},
	{regexp.MustCompile(`(?i)server:.*iis`), "http"},
	{regexp.MustCompile(`(?i)^smtp`), "smtp"},
	{regexp.MustCompile(`(?i)^220.*smtp`), "smtp"},
	{regexp.MustCompile(`(?i)^220.*mail`), "smtp"},
	{regexp.MustCompile(`(?i)^220.*exchange`), "smtp"},
	{regexp.MustCompile(`(?i)^220.*postfix`), "smtp"},
	{regexp.MustCompile(`(?i)^pop`), "pop3"},
	{regexp.MustCompile(`(?i)^+ok.*pop`), "pop3"},
	{regexp.MustCompile(`(?i)^+ok.*dovecot`), "pop3"},
	{regexp.MustCompile(`(?i)^imap`), "imap"},
	{regexp.MustCompile(`(?i)^imap4`), "imap"},
	{regexp.MustCompile(`(?i)^imap4rev1`), "imap"},
	{regexp.MustCompile(`(?i)^mysql`), "mysql"},
	{regexp.MustCompile(`(?i)mysql`), "mysql"},
	{regexp.MustCompile(`(?i)^postgres`), "postgresql"},
	{regexp.MustCompile(`(?i)postgresql`), "postgresql"},
	{regexp.MustCompile(`(?i)^redis`), "redis"},
	{regexp.MustCompile(`(?i)redis`), "redis"},
	{regexp.MustCompile(`(?i)^mongodb`), "mongodb"},
	{regexp.MustCompile(`(?i)mongodb`), "mongodb"},
	{regexp.MustCompile(`(?i)^telnet`), "telnet"},
	{regexp.MustCompile(`(?i)telnet`), "telnet"},
	{regexp.MustCompile(`(?i)^nginx`), "http"},
	{regexp.MustCompile(`(?i)^apache`), "http"},
	{regexp.MustCompile(`(?i)^iis`), "http"},
	{regexp.MustCompile(`(?i)^microsoft.*http`), "http"},
	{regexp.MustCompile(`(?i)^elasticsearch`), "elasticsearch"},
	{regexp.MustCompile(`(?i)elasticsearch`), "elasticsearch"},
	{regexp.MustCompile(`(?i)^memcache`), "memcache"},
	{regexp.MustCompile(`(?i)memcache`), "memcache"},
	{regexp.MustCompile(`(?i)^rabbitmq`), "rabbitmq"},
	{regexp.MustCompile(`(?i)rabbitmq`), "rabbitmq"},
	{regexp.MustCompile(`(?i)^zookeeper`), "zookeeper"},
	{regexp.MustCompile(`(?i)zookeeper`), "zookeeper"},
	{regexp.MustCompile(`(?i)^docker`), "docker"},
	{regexp.MustCompile(`(?i)docker`), "docker"},
	{regexp.MustCompile(`(?i)^kubernetes`), "kubernetes"},
	{regexp.MustCompile(`(?i)kubernetes`), "kubernetes"},
	{regexp.MustCompile(`(?i)^ldap`), "ldap"},
	{regexp.MustCompile(`(?i)ldap`), "ldap"},
	{regexp.MustCompile(`(?i)^rtsp`), "rtsp"},
	{regexp.MustCompile(`(?i)rtsp`), "rtsp"},
	{regexp.MustCompile(`(?i)^sip`), "sip"},
	{regexp.MustCompile(`(?i)sip/`), "sip"},
	{regexp.MustCompile(`(?i)^vnc`), "vnc"},
	{regexp.MustCompile(`(?i)realvnc`), "vnc"},
	{regexp.MustCompile(`(?i)^irc`), "irc"},
	{regexp.MustCompile(`(?i)^ircd`), "irc"},
	{regexp.MustCompile(`(?i)^nntp`), "nntp"},
	{regexp.MustCompile(`(?i)nntp`), "nntp"},
	{regexp.MustCompile(`(?i)^ntp`), "ntp"},
	{regexp.MustCompile(`(?i)ntp`), "ntp"},
	{regexp.MustCompile(`(?i)^dns`), "domain"},
	{regexp.MustCompile(`(?i)^bind`), "domain"},
	{regexp.MustCompile(`(?i)^microsoft.*dns`), "domain"},
	{regexp.MustCompile(`(?i)^smb`), "microsoft-ds"},
	{regexp.MustCompile(`(?i)^samba`), "microsoft-ds"},
	{regexp.MustCompile(`(?i)^rdp`), "rdp"},
	{regexp.MustCompile(`(?i)^microsoft.*rdp`), "rdp"},
	{regexp.MustCompile(`(?i)^oracle`), "oracle"},
	{regexp.MustCompile(`(?i)^ora-`), "oracle"},
	{regexp.MustCompile(`(?i)^mssql`), "mssql"},
	{regexp.MustCompile(`(?i)^sqlserver`), "mssql"},
	{regexp.MustCompile(`(?i)^sybase`), "sybase"},
	{regexp.MustCompile(`(?i)^svn`), "svn"},
	{regexp.MustCompile(`(?i)^git`), "git"},
	{regexp.MustCompile(`(?i)^rsync`), "rsync"},
	{regexp.MustCompile(`(?i)^squid`), "squid"},
	{regexp.MustCompile(`(?i)^haproxy`), "http"},
	{regexp.MustCompile(`(?i)^traefik`), "http"},
	{regexp.MustCompile(`(?i)^couchdb`), "couchdb"},
	{regexp.MustCompile(`(?i)couchdb`), "couchdb"},
	{regexp.MustCompile(`(?i)^influxdb`), "influxdb"},
	{regexp.MustCompile(`(?i)influxdb`), "influxdb"},
	{regexp.MustCompile(`(?i)^prometheus`), "prometheus"},
	{regexp.MustCompile(`(?i)prometheus`), "prometheus"},
	{regexp.MustCompile(`(?i)^grafana`), "grafana"},
	{regexp.MustCompile(`(?i)grafana`), "grafana"},
	{regexp.MustCompile(`(?i)^jenkins`), "jenkins"},
	{regexp.MustCompile(`(?i)jenkins`), "jenkins"},
	{regexp.MustCompile(`(?i)^tomcat`), "http"},
	{regexp.MustCompile(`(?i)^jetty`), "http"},
	{regexp.MustCompile(`(?i)^jboss`), "http"},
	{regexp.MustCompile(`(?i)^glassfish`), "http"},
	{regexp.MustCompile(`(?i)^websphere`), "http"},
	{regexp.MustCompile(`(?i)^php`), "http"},
	{regexp.MustCompile(`(?i)^python`), "http"},
	{regexp.MustCompile(`(?i)^flask`), "http"},
	{regexp.MustCompile(`(?i)^django`), "http"},
	{regexp.MustCompile(`(?i)^rails`), "http"},
	{regexp.MustCompile(`(?i)^laravel`), "http"},
	{regexp.MustCompile(`(?i)^express`), "http"},
	{regexp.MustCompile(`(?i)^node`), "http"},
	{regexp.MustCompile(`(?i)^go-http`), "http"},
	{regexp.MustCompile(`(?i)^golang`), "http"},
	{regexp.MustCompile(`(?i)^java`), "http"},
	{regexp.MustCompile(`(?i)^openssl`), "ssl"},
	{regexp.MustCompile(`(?i)^ssl`), "ssl"},
	{regexp.MustCompile(`(?i)^tls`), "ssl"},
	{regexp.MustCompile(`(?i)^starttls`), "ssl"},
	{regexp.MustCompile(`(?i)^gpg`), "gpg"},
	{regexp.MustCompile(`(?i)^pgp`), "gpg"},
	{regexp.MustCompile(`(?i)^gnupg`), "gpg"},
	{regexp.MustCompile(`(?i)^tor`), "tor"),
	{regexp.MustCompile(`(?i)^onion`), "tor"},
	{regexp.MustCompile(`(?i)^proxy`), "proxy"},
	{regexp.MustCompile(`(?i)^socks`), "socks"},
	{regexp.MustCompile(`(?i)^upnp`), "upnp"},
	{regexp.MustCompile(`(?i)^ssdp`), "upnp"},
	{regexp.MustCompile(`(?i)^snmp`), "snmp"},
	{regexp.MustCompile(`(?i)^net-snmp`), "snmp"},
	{regexp.MustCompile(`(?i)^cisco.*snmp`), "snmp"},
	{regexp.MustCompile(`(?i)^radius`), "radius"},
	{regexp.MustCompile(`(?i)^tacacs`), "tacacs"},
	{regexp.MustCompile(`(?i)^kerberos`), "kerberos"},
	{regexp.MustCompile(`(?i)^kpasswd`), "kpasswd"},
	{regexp.MustCompile(`(?i)^afp`), "afp"},
	{regexp.MustCompile(`(?i)^netatalk`), "afp"},
	{regexp.MustCompile(`(?i)^x11`), "x11"},
	{regexp.MustCompile(`(?i)^xorg`), "x11"},
	{regexp.MustCompile(`(?i)^vnc`), "vnc"},
	{regexp.MustCompile(`(?i)^rfb`), "vnc"},
	{regexp.MustCompile(`(?i)^pcanywhere`), "pcanywhere"},
	{regexp.MustCompile(`(?i)^teamviewer`), "rdp"},
	{regexp.MustCompile(`(?i)^anydesk`), "rdp"},
	{regexp.MustCompile(`(?i)^radmin`), "radmin"},
	{regexp.MustCompile(`(?i)^amq`), "rabbitmq"},
	{regexp.MustCompile(`(?i)^activemq`), "rabbitmq"},
	{regexp.MustCompile(`(?i)^kafka`), "kafka"},
	{regexp.MustCompile(`(?i)^zookeeper`), "zookeeper"},
	{regexp.MustCompile(`(?i)^consul`), "consul"},
	{regexp.MustCompile(`(?i)^etcd`), "etcd"},
	{regexp.MustCompile(`(?i)^vault`), "vault"},
	{regexp.MustCompile(`(?i)^nomad`), "nomad"},
	{regexp.MustCompile(`(?i)^cassandra`), "cassandra"},
	{regexp.MustCompile(`(?i)^hbase`), "hbase"},
	{regexp.MustCompile(`(?i)^spark`), "spark"},
	{regexp.MustCompile(`(?i)^hadoop`), "hadoop"},
	{regexp.MustCompile(`(?i)^hive`), "hive"},
	{regexp.MustCompile(`(?i)^pig`), "pig"},
	{regexp.MustCompile(`(?i)^zabbix`), "zabbix"},
	{regexp.MustCompile(`(?i)^nagios`), "nagios"},
	{regexp.MustCompile(`(?i)^icinga`), "icinga"},
	{regexp.MustCompile(`(?i)^sensu`), "sensu"},
	{regexp.MustCompile(`(?i)^checkmk`), "checkmk"},
	{regexp.MustCompile(`(?i)^librenms`), "librenms"},
	{regexp.MustCompile(`(?i)^opennms`), "opennms"},
	{regexp.MustCompile(`(?i)^cacti`), "cacti"},
	{regexp.MustCompile(`(?i)^weathermap`), "cacti"},
}

func IdentifyService(port int, conn net.Conn) string {
	if service, ok := wellKnownServices[port]; ok {
		return service
	}

	if conn != nil {
		return detectServiceFromBanner(conn, port)
	}

	return "unknown"
}

type BannerGrabber struct {
	conn    net.Conn
	timeout time.Duration
	buffer  []byte
}

func NewBannerGrabber(conn net.Conn, timeout time.Duration) *BannerGrabber {
	return &BannerGrabber{
		conn:    conn,
		timeout: timeout,
		buffer:  make([]byte, 4096),
	}
}

func (bg *BannerGrabber) Grab() (string, error) {
	if bg.conn == nil {
		return "", fmt.Errorf("nil connection")
	}

	bg.conn.SetDeadline(time.Now().Add(bg.timeout))

	var banner bytes.Buffer
	reader := bufio.NewReader(bg.conn)

	for i := 0; i < 3; i++ {
		n, err := reader.Read(bg.buffer)
		if n > 0 {
			banner.Write(bg.buffer[:n])
		}
		if err != nil {
			if err == bufio.ErrBufferFull || err == bufio.ErrNegativeCount {
				continue
			}
			break
		}
		if n < len(bg.buffer) {
			break
		}
	}

	if banner.Len() == 0 {
		return "", fmt.Errorf("no banner received")
	}

	return banner.String(), nil
}

func (bg *BannerGrabber) GrabWithProbe(probe []byte) (string, error) {
	if bg.conn == nil {
		return "", fmt.Errorf("nil connection")
	}

	bg.conn.SetDeadline(time.Now().Add(bg.timeout))

	if len(probe) > 0 {
		_, err := bg.conn.Write(probe)
		if err != nil {
			return "", fmt.Errorf("failed to send probe: %w", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	return bg.Grab()
}

func detectServiceFromBanner(conn net.Conn, port int) string {
	if conn == nil {
		return "unknown"
	}

	grabber := NewBannerGrabber(conn, 2*time.Second)

	banner, err := grabber.Grab()
	if err != nil {
		probe := getProtocolProbe(port)
		if len(probe) > 0 {
			banner, err = grabber.GrabWithProbe(probe)
			if err != nil {
				return "unknown"
			}
		} else {
			return "unknown"
		}
	}

	return matchServiceFromBanner(banner, port)
}

func getProtocolProbe(port int) []byte {
	probes := map[int][]byte{
		80:     []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
		443:    []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
		8080:   []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
		8443:   []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
		8000:   []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
		8008:   []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
		3000:   []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
		5000:   []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
		21:     []byte("QUIT\r\n"),
		25:     []byte("EHLO localhost\r\n"),
		587:    []byte("EHLO localhost\r\n"),
		465:    []byte("EHLO localhost\r\n"),
		110:    []byte("CAPA\r\n"),
		995:    []byte("CAPA\r\n"),
		143:    []byte("CAPABILITY\r\n"),
		993:    []byte("CAPABILITY\r\n"),
		22:     []byte("\r\n"),
		23:     []byte("\r\n"),
		3306:   []byte("\x00\x00\x00\x01\x85\xa2\x0f\x00\x00\x00\x00\x01\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		5432:   []byte("\x00\x00\x00\x08\x04\xd2\x16\x2f"),
		6379:   []byte("PING\r\n"),
		27017:  []byte("\x3e\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00"),
		9200:   []byte("GET / HTTP/1.0\r\n\r\n"),
		11211:  []byte("stats\r\n"),
		5672:   []byte("\x01\x00\x01\x00"),
		15672:  []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
		2181:   []byte("ruok"),
		8009:   []byte("\x12\x34\x00\x0d"),
		3389:   []byte("\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\x00"),
		5900:   []byte("\r\n"),
		5901:   []byte("\r\n"),
		5902:   []byte("\r\n"),
		5903:   []byte("\r\n"),
		161:    []byte("\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x01\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"),
	}

	if probe, ok := probes[port]; ok {
		return probe
	}
	return nil
}

func matchServiceFromBanner(banner string, port int) string {
	banner = strings.TrimSpace(banner)
	if len(banner) == 0 {
		return "unknown"
	}

	for _, sp := range servicePatterns {
		if sp.pattern.MatchString(banner) {
			return sp.service
		}
	}

	if service, ok := wellKnownServices[port]; ok {
		return service
	}

	return "unknown"
}

func truncateBanner(banner string) string {
	banner = strings.TrimSpace(banner)
	if len(banner) > 200 {
		banner = banner[:200] + "..."
	}
	return banner
}

func GetServiceBanner(conn net.Conn, timeout time.Duration) (string, error) {
	if conn == nil {
		return "", fmt.Errorf("nil connection")
	}

	grabber := NewBannerGrabber(conn, timeout)
	return grabber.Grab()
}

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
