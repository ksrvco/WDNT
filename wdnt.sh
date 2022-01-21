#/bin/bash
# Project name: WDNT - Web Defense from Network Traffic
# Written by: KsrvcO
# Version: 1.1
# Detecting this web attacks from analyzing network traffic: 
#      Sql injection
#      Cross site scripting
#      Local file inclusion
#      Web Login bypasses
# Contact me: flower.k2000[at]gmail.com
# Video demo: None
reset
mkdir -p /tmp/wndt
cappath="/tmp/wndt"
echo -e "

░██╗░░░░░░░██╗██████╗░███╗░░██╗████████╗
░██║░░██╗░░██║██╔══██╗████╗░██║╚══██╔══╝
░╚██╗████╗██╔╝██║░░██║██╔██╗██║░░░██║░░░
░░████╔═████║░██║░░██║██║╚████║░░░██║░░░
░░╚██╔╝░╚██╔╝░██████╔╝██║░╚███║░░░██║░░░
░░░╚═╝░░░╚═╝░░╚═════╝░╚═╝░░╚══╝░░░╚═╝░░░
                               by KsrvcO

Project name: WDNT - Web Defense from Network Traffic
Written by: KsrvcO
Version: 1.1
Contact me: flower.k2000[at]gmail.com

"
sleep 3
read -p "[+] Enter your network interface: " netinterface
ifconfig $netinterface promisc
if [ $(cat /sys/class/net/$netinterface/operstate) == "up" ]
	then
	ifconfig $netinterface promisc
	sleep 1
	echo "[-] Monitoring mode enabled on $netinterface"
else
	clear
	echo "[-] Network interface not found on your system. Exiting..."
fi
echo "[+] Started monitoring ..."
sleep 2
while (true)
do
	tshark -i $netinterface -a duration:60 'tcp port 80' >> $cappath/captured.txt 2>/dev/null

		# Check sql injection attacks
		sqluserip=$(cat $cappath/captured.txt | grep -e order -e union -e select -e information_schema | awk '/GET/ {print $3}' | sort -u)
		sqltargetip=$(cat $cappath/captured.txt | grep -e order -e union -e select -e information_schema | awk '/GET/ {print $5}' | sort -u)
		sqlurl=$(cat $cappath/captured.txt | grep -e order -e union -e select -e information_schema | awk '/GET/ {print $9}' | sort -u)
		echo "" >> $cappath/sqlattack.txt
		date >> $cappath/sqlattack.txt
		echo "------------------------------------" >> $cappath/sqlattack.txt
		echo "AttackerIP:$sqluserip" >> $cappath/sattack.txt
		echo "TargetIP:$sqltargetip" >> $cappath/sattack.txt
		echo "AttackedURL:$sqlurl" >> $cappath/sattack.txt
		sed -e '/AttackerIP:$/,+3d' $cappath/sattack.txt >> $cappath/sqlattack.txt
		rm -rf $cappath/sattack.txt

		# Check cross site scripting attacks
		xssuserip=$(cat $cappath/captured.txt | grep -e "<script>" -e alert -e "document.cookie" -e "window.location" | awk '/GET/ {print $3}' | sort -u)
		xsstargetip=$(cat $cappath/captured.txt | grep -e "<script>" -e alert -e "document.cookie" -e "window.location" | awk '/GET/ {print $5}' | sort -u)
		xssurl=$(cat $cappath/captured.txt | grep -e "<script>" -e alert -e "document.cookie" -e "window.location" | awk '/GET/ {print $9}' | sort -u)
		echo "" >> $cappath/xssattack.txt
		date >> $cappath/xssattack.txt
		echo "------------------------------------" >> $cappath/xssattack.txt
		echo "AttackerIP:$xssuserip" >> $cappath/xattack.txt
		echo "TargetIP:$xsstargetip" >> $cappath/xattack.txt
		echo "AttackedURL:$xssurl" >> $cappath/xattack.txt
		sed -e '/AttackerIP:$/,+3d' $cappath/xattack.txt >> $cappath/xssattack.txt
		rm -rf $cappath/xattack.txt

		# Check Local file inclusion attacks
		lfiuserip=$(cat $cappath/captured.txt | grep -e /etc/passwd -e /etc/ | awk '/GET/ {print $3}' | sort -u)
		lfitargetip=$(cat $cappath/captured.txt | grep -e /etc/passwd -e /etc/ | awk '/GET/ {print $5}' | sort -u)
		lfiurl=$(cat $cappath/captured.txt | grep -e /etc/passwd -e /etc/ | awk '/GET/ {print $9}' | sort -u)
		echo "" >> $cappath/lfiattack.txt
		date >> $cappath/lfiattack.txt
		echo "------------------------------------" >> $cappath/lfiattack.txt
		echo "AttackerIP:$lfiuserip" >> $cappath/lattack.txt
		echo "TargetIP:$lfitargetip" >> $cappath/lattack.txt
		echo "AttackedURL:$lfiurl" >> $cappath/lattack.txt
		sed -e '/AttackerIP:$/,+3d' $cappath/lattack.txt >> $cappath/lfiattack.txt
		rm -rf $cappath/lattack.txt
		
		# Check web portal login bypass attacks
		bypuserip=$(cat $cappath/captured.txt | grep -e or= -e 1=1 | awk '/GET/ {print $3}' | sort -u)
		byptargetip=$(cat $cappath/captured.txt | grep -e or= -e 1=1 | awk '/GET/ {print $5}' | sort -u)
		bypurl=$(cat $cappath/captured.txt | grep -e or= -e 1=1 | awk '/GET/ {print $9}' | sort -u)
		echo "" >> $cappath/bypassattack.txt
		date >> $cappath/bypassattack.txt
		echo "------------------------------------" >> $cappath/bypassattack.txt
		echo "AttackerIP:$lfiuserip" >> $cappath/bpassattack.txt
		echo "TargetIP:$lfitargetip" >> $cappath/bpassattack.txt
		echo "AttackedURL:$lfiurl" >> $cappath/bpassattack.txt
		sed -e '/AttackerIP:$/,+3d' $cappath/bpassattack.txt >> $cappath/bypassattack.txt
		rm -rf $cappath/bpassattack.txt
	rm -rf $cappath/captured.txt
done



