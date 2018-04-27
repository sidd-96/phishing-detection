import re
import requests
import socket
import ssl
import datetime
from tldextract import extract
import pythonwhois
from bs4 import BeautifulSoup
import subprocess
import whois
from google import search
import time
sty=time.clock()
file=open('file.txt','w')
file1 = open('data.txt', 'r') 
urltemp =  file1.read()
start = urltemp.find("'") + 1
end = urltemp.find("'", start)
url = urltemp[start:end]
print(url)
li=[]
co=1


gf=1
try:
    r=requests.get(url)
except:
    gf=-1
# URL having IP address in domain

symbol = re.findall(r'(http((s)?)://)((((\d)+).)*)((\w)+)/((\w)+)',url)
if(len(symbol)==0):
 IP_atr='1'
else:
  IP_atr='-1'
li.append(IP_atr+',')
print('checking ip address in url')

# URL having long length 

length=len(url)
length_atr='0'
if (length>=54 and length<=75):
  length_atr='0'
elif (length<54):
  length_atr='1'
elif() :
  length_atr='-1'
li.append(length_atr+',')
print('checking for long length')
#tiny url
tsd, td, tsu = extract(url) 

host = td + '.' + tsu 
try:
    response = requests.get(url)
    furl=response.url
    tsd, td, tsu = extract(furl) 

    fhost = td + '.' + tsu 
    if(host == fhost):
      shortened_atr='1'
    else:
      shortened_atr='-1'
    li.append(shortened_atr+',')
except:
    li.append('-1,')
print('checking for tiny url')
# URL having @ symbol

symbol=re.findall(r'@',url)
if(len(symbol)==0):
 at_the_rate_symbol='1'
else:
 at_the_rate_symbol='-1' 
li.append(at_the_rate_symbol+',')
print('checking for  @ symbol')

# URL having // beyond 7th position

symbol=re.findall(r'http://www.((\w)*)//((\w)*)',url)
symbol1=re.findall(r'https://www.((\w)*)//((\w)*)',url)
if(len(symbol)!=0 and len(symbol1)!=0):
  slash_atr=-1
elif((len(symbol)!=0 and len(symbol1)==0) or (len(symbol)==0 and len(symbol1)!=0)):
  slash_atr='-1'
else:
  slash_atr='1'
li.append(slash_atr+',')
print('checking for \\reidrect')

# URL having - attribute

symbol = re.findall(r'http((s)?)://www.((\w)+)-((\w)+).com',url)
if(len(symbol)!=0):
 dash_atr=-1
else:
 dash_atr=1 
li.append('-1,')
print('checking for - symbol')

#top levelomain

if(url.count('.')<3):
    li.append('1,')
elif(url.count('.')<=4):
    li.append('0,')
else:
    li.append('-1,')

print('checking for no of levels in domain')
#HTTPs certificate
    
#print('https')  
if(re.search('^https',url)):
    containhttps = 1
else:
    containhttps = 0


tsd, td, tsu = extract(url) 

host = td + '.' + tsu 

try:
  hostname = host
  ctx = ssl.create_default_context()
  s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
  s.connect((hostname, 443))
  cert = s.getpeercert()

  # if you will print cert , you will get various information about certificate like issuer,starting date , ending date
  subject = dict(x[0] for x in cert['subject'])
  issued_to = subject['commonName']
  issuer = dict(x[0] for x in cert['issuer'])
  issued_by = issuer['commonName']
  # it contains issuer name, but its data type is in unicode
  issued_by = str(issued_by)
  issued_by = issued_by.split()
  if(issued_by[0] == "Network" or issued_by == "Deutsche"):
    issued_by = issued_by[0] + " " + issued_by[1]
  elif(issued_by[0] == "Google"):
    issued_by = issued_by[0] + " " + issued_by[1] + " " + issued_by[2] 	
  else:
    issued_by = issued_by[0] 
  # changing the data type of issued_by to str
  starting = str(cert['notBefore'])
  # it contains starting date , since its data type is unicode , so converting it to str
  ending = str(cert['notAfter'])
  # it contains ending date , and its data type is str
  words = starting.split()
  syear = words[3]
  # now syear contains starting year , but it is in string format

  words2 = ending.split()
  eyear = words2[3]
  # it contains ending year , but it is in str format
  syear = int(syear)
  eyear = int(eyear)
  # converting both syear and eyear in int format


  duration = eyear - syear
  # duration is the age of certificate in years
 
  issuers = ['Comodo','Symantec','GoDaddy','GlobalSign','DigiCert','StartCom','Entrust','Verizon','Trustwave','Unizeto','Buypass','QuoVadis','Deutsche Telekom','Network Solutions','SwissSign','IdenTrust','Secom','TWCA','GeoTrust','Thawte','Doster','VeriSign','Google Internet Authority']
  if((containhttps == 1) and (issued_by in issuers) and (duration >= 1)):
    li.append('1,')
  elif((containhttps == 1) and (issued_by in issuers)):
    li.append('0,')
  else:
    li.append('-1,') 	
except:
    li.append('-1,')
print('checking for age of https certificate')

#domain registration length
#print('drl')
domain = host

try:
  w = pythonwhois.get_whois(domain)
  if  'id' not in w:
    li.append('-1,')
  else :

   
    ud = w['updated_date']

    ed = w['expiration_date']

    diff = ed[0] - ud[0]


    comp = datetime.timedelta(365,0,0,0)


    if(diff > comp):
      li.append('1,')
    else:
     li.append('-1,')	
except:
    li.append('-1,')
print('checking for domain registrtion length')
#favicon
#print('fav')
try:
    r=requests.get(url)
    d=r.text
    s=BeautifulSoup(d,"lxml")
    l=[]
    for link in s.find_all('link'):
       l.append(link.get('href'))
    b=" "
    for x in l:
       x=str(x)
       b=x
       c= x.find(".ico")
       if c!=-1:
         break

    tsd, td, tsu = extract(url) 

    ourl = td + '.' + tsu
    tsd, td, tsu = extract(b) 

    favurl = td + '.' + tsu
#print(ourl," ",favurl)
    if(favurl==ourl or favurl=='.'):
       li.append('1,')
    else:
     li.append('-1,')

except:
    li.append('-1,')
print('checking for favicon url')
#port
#print('port')
try:
   subprocess.call('clear', shell=True)


   remoteServer    = tsd + '.' + host
   remoteServerIP  = socket.gethostbyname(remoteServer)
   p=[22,80,443,445]
   st=[10060,0,0,10060]
   i=0
   f=1

   for port in p:  
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((remoteServerIP, port))
        #print(result)
        if result != st[i]:
            f=0
            break
        sock.close()
        i=i+1
   if f:
    li.append('1,')
   else:
    li.append('-1,')
except:
    li.append('-1,')
print('checking for different ports ....connecting to http,https,ftp....')
#https symbol
#print('https')
symbol= re.findall(r'https://((\w)*)https((\w)*)',url)
if(len(symbol)==0):
  http_atr='1'
else :
  http_atr='-1'
li.append(http_atr+',')


#request url

#print('request')
tsd, td, tsu = extract(url) 

hurl = td + '.' + tsu 
try:
    r=requests.get(url)
    c=0
    t=0
    soup = BeautifulSoup(r.content,'lxml')
    imgs = soup.find_all("img",{ "src":True})
    t+=len(imgs)
    for img in imgs:
      tsd, td, tsu = extract( img['src'])
      lurl = td + '.' + tsu
      if(hurl==lurl or lurl=='.'):
        c+=1
    soup = BeautifulSoup(r.content,'lxml')        
    imgs = soup.find_all("video",{"src":True})
    t+=len(imgs)
    for img in imgs:
      tsd, td, tsu = extract( img['src'])
       #print(img['source'])
      lurl = td + '.' + tsu
      if(hurl==lurl or lurl=='.'):
        c+=1
    ans=1
      #print(c,t)
    if(t==0):
        li.append('1,')
    else :
        ans=c/t
    if(ans>=0.6 and t!=0):
        li.append('1,')
    elif ans>0.3 and t!=0:
        li.append('0,')
    elif t!=0:
        li.append('-1,')

except:
    li.append('-1,')

print('checking ratio of request url')
#a tag request
#print('a')
try:
   r= requests.get(url)
   soup=BeautifulSoup(r.content,'lxml')
   tsd, td, tsu = extract(url) 

   hurl = td + '.' + tsu 
   d=0
   t=1
   sor=soup.find_all("a",{"href":True})
   t+=len(sor)
   for link in sor:
       tsd, td, tsu = extract(link['href']) 

       lurl = td + '.' + tsu
        
       if(hurl==lurl or lurl=='.'):
    
        
                    d=d+1
   avg=0
   if(t!=0):
     avg=d/t
     avg=1-avg
   if(avg<.17 and t!=0):
    ans=1
   elif(avg>=.17 and avg<=.81 and t!=0):
    ans=0
   elif(t!=0):
    ans=-1
   ans=str(ans)
   li.append(ans+',')

except:
    li.append('-1,')
print('cheking for anchor tag request......')
#links in meta etc
#print('meta')
try:
    r= requests.get(url)
    soup=BeautifulSoup(r.content,'lxml')
    a=0
    b=0
    c=0
    d=0
    for link in soup.find_all("meta"):
     if(link.get("href")):
        a=a+1
    for link in soup.find_all("link"):
     if(link.get("href")):
        b=b+1
    for link in soup.find_all("script"):
     if(link.get("src")):
        c=c+1
    for link in soup.find_all("a"):
    
     if(link.get("href")):
        d=d+1
    tot=a+b+c+d
    nume=a+b+c
    avg=1
    if(tot!=0):
     avg=float(nume/tot)
    if(avg<.17):
     ans=1
    elif(avg>=.17 and avg<=.81):
     ans=0
    else:
     ans=-1
    ans=str(ans)
    li.append(ans+',')
except:
    li.append('-1,')

print('counting no of links in meta.....')


#sfh


li.append('NA,')




#mail send
try:
    r=requests.get(url)
    d=r.text
    s=BeautifulSoup(d,"lxml")
#print(s)
    s=str(s)
    if s.find("mailto:")!=-1:
     li.append('-1,')
    else:
     li.append('1,')

except:
    li.append('-1,')
print('checking for if form send to mail.......')
#abnormal url
try:
    w = pythonwhois.get_whois(host)
    if  'id' not in w:
     li.append('-1,')
    else :
     li.append('1,')
except:
    li.append('-1,')
print('checking for abnormality of url...........')
#redirect url


try:
  response = requests.get(url)
  c=0;
  for resp in response.history:
     #print(resp.url)
     c+=1

  if(c<2):
     li.append('0,')
  elif(c>=2 and c<=4):
     li.append('0,')
  else :
     li.append('0,')

except:
    li.append('-1,')
print('checking for no of redirects.........')
#status barcustomization
try:
 r=requests.get(url)
 d=r.text
 s=BeautifulSoup(d,"lxml")
 #print(s)
 s=str(s)
 if s.find("location.href")!=-1 or (s.find("onmouseover")!=-1 and s.find("window.status")!=-1):
    li.append('-1,')
 else:
    li.append('1,')

except:
    li.append('-1,')
print('checking for status bar customization........')
#diabling right click
try:
 r=requests.get(url)
 d=r.text
 s=BeautifulSoup(d,"lxml")
 #print(s)
 s=str(s)
 if s.find("oncontextmenu")!=-1 or s.find(".button==2")!=-1 or s.find(".mousedown==3")!=-1:
    li.append('-1,')
 else:
    li.append('1,')
except:
    li.append('-1,')
print('checkinf for no source code visible........')
#popup window
try:
 r=requests.get(url)
 d=r.text
 s=BeautifulSoup(d,"lxml")
 #print(s)
 s=str(s)
 #print(s)
 if s.find("prompt")!=-1 :
    li.append('-1,')
 else:
    li.append('1,')
except:
    li.append('-1,')
print('checking for popup window.......')
#iframe tags
try:
 r=requests.get(url)
 s=str(s)
 s=BeautifulSoup(r.content,'lxml')
 if(len(s.find_all('iframe'))!=0):
    li.append('-1,')

 else:
    li.append('1,')

except:
    li.append('-1,')
print('checking for iframe tags...........')
#age of domsin


w=0
try:
    w=whois.whois(host)
    #print(w) 
    w=w.creation_date

    if (w==None):
     li.append('-1,')
    else:
     c=w

     n=datetime.datetime.now()
     end_date = n
     start_date = c
     ans = abs((end_date - start_date).days)
     if (ans>180):
      li.append('1,')
     else:
      li.append('-1,')
except:
    li.append('-1,')
print('checking for age of domain.........')

#name servers

w=0
try:
   w=whois.whois(host)
   w=w.name_servers
   if(len(w)>0):
    li.append('1,')
   else:
    li.append('-1,') 
except:
   li.append('-1,')
print('chacking for nameservers....')

#website traffic


li.append('-1,')


#googlepagerank

try:
    rurl="https://pr.domaineye.com/pr/"+ tsd+'.'+host
    r= requests.get(rurl)
    soup=BeautifulSoup(r.content,'lxml')
    s=soup.find_all('em')
    b=s[1]
    b=str(b)
    b=b[4:6]
    if(b[1]!='0'):
     b=b[0]
    b=int(b)
    #print(b)
    if(b>2):
     li.append('1,')
    else:
     li.append('-1,')
except:
    li.append('-1,')
print('checking for google page rank...........')

#google search
c=0
query = "info" + url
for j in search(query, tld="co.in", num=10, stop=1, pause=0):
    tsd, td, tsu = extract(j) 

    hurl = td + '.' + tsu
    if(hurl==host):
        c+=1
if(c!=0):
    li.append('1,')
else :
    li.append('1,')
print('checking for google search..........')
#no of links pointing to page

li.append('NA,')





#phistank database

li.append('NA,')
li.append('NA\n')
sty=time.clock()-sty
sty=str(sty)
print('tottal execution time '+ sty)
for l in li:
    file.write(l)
    print(l)
file.close()
