# Progetto di Modelli per dati categoriali, corso della prof.ssa Giordano Sabrina
# Studente Micieli Ottavio, matricola 214209
# Titolo: I'm hacking your safety! 
# Sottotitolo: Implementazione di un modello per la classificazione dei siti internet

# Il progetto si focalizza sull'analisi di alcune variabili che potrebbero aumentare o diminuire la propensione di un 
# determinato sito web ad essere pericoloso. Al termine di tale analisi si vogliono fornire alcuni semplici e immediati
# accorgimenti per individuare un sito pericoloso, o per lo meno evitare quelli che sembrano tali.
# Il dataset che viene utilizzato per condurre l'analisi proveniene dal sito Kaggle.com 
# (URL: https://www.kaggle.com/xwolf12/malicious-and-benign-websites). Tale dataset venne utilizzato in un'università
# Colombiana dai professori Urcuqui, Osorio, Navarro e Garcìa per la creazione di un algoritmo di intellingenza 
# artificiale volto al riconoscimento dei siti pericolosi mediante alcune caratteristiche proprie. 
# Non tutte le variabili presenti nel dataset verranno utilizzate nell'analisi, poichè alcune di esse richiedono
# alcune conoscenze di informatica e di architettura delle rete internet più avanzate. Tali competenze non sono 
# evidentemente in posseso di un navigatore medio, per cui non risultano utili per l'elaborazione di un modello 
# utilizzabile anche da chi non è esperto di informatica.

# librerie utilizzate nel corso dell'analisi
library(tidyverse)
library(lubridate)
library(car)
library(ResourceSelection)
library(pROC)
library(plotrix)
library(ggthemes)

temp<-read_csv("dataset.csv", col_names=T, na=c("None","","NA")); str(temp)
temp<-temp[,c(1:5,7,9,14,21)] #manteniamo solo le variabili di interesse
temp<-temp %>% column_to_rownames("URL") #URL serve solo per distinguere i casi, per cui si può mettere come nome di riga
head(temp,10)

#### Descrizione, analisi e codifica delle variabili ####

# Variabile URL_LENGTH: indica il numero di caratteri alfanumerici presenti nell'URL
temp[!complete.cases(temp$URL_LENGTH),] #individuazione dei valori mancanti (risultano essere pari a 0)
summary(temp$URL_LENGTH); sd(temp$URL_LENGTH)

# Variabile NUMBER_SPECIAL_CHARACTERS: indica il numero di caratteri speciali all'interno dell'URL
temp[!complete.cases(temp$NUMBER_SPECIAL_CHARACTERS),] #non ci sono valori mancanti
summary(temp$NUMBER_SPECIAL_CHARACTERS); sd(temp$NUMBER_SPECIAL_CHARACTERS)

# Variabile CHARSET: indica il tipo di codifica utilizzata all'interno del sito per quanto riguarda i caratteri alfanumerici
count(temp[!complete.cases(temp$CHARSET),]) #in questa variabile vi sono 7 valori mancanti, a cui si decide di assegnare
# la categoria Other
table(temp$CHARSET) #si può notare come nella trascrizione dei dati alcuni valori siano uguali ma con lettera maiuscola
# dove invece è minuscola o altro. Si uniforma l'etichetta, si creano i livelli e le classi con pochi elementi si uniscono
# in Other
temp<-temp %>%  
  mutate(CHARSET=
           dplyr::recode(CHARSET,
                  "iso-8859-1"="ISO-8859",
                  "ISO-8859-1"="ISO-8859",
                  "utf-8"="UTF-8",
                  "windows-1251"="Other",
                  "windows-1252"="Other",
                  .missing="Other",
                  .default=levels(CHARSET)
           )
  )
temp$CHARSET<-factor(temp$CHARSET,levels=c("UTF-8","ISO-8859","us-ascii","Other"),
                  labels=c("UTF-8","ISO-8859","us-ascii","Other"))
table(temp$CHARSET)

# Variabile SERVER: indica appunto il server che gestisce l'accesso al sito web
count(temp[!complete.cases(temp$SERVER),]) #in questo caso ci sono 176 valori mancanti, che si inserisco nella categoria
# UNknow. 
table(temp$SERVER) #si può notare come ogni categoria abbia pochi elementi. Alcune di esse sono dovute al fatto che 
# si tratta sempre dello stesso server ma con versioni differenti, mentre altri sono server non largamente utilizzati.
# si raggruppano le categorie provenienti dallo stesso server, i server con poche unità vengono raggrupati in altro.
temp<-temp %>%
  mutate(SERVER=
           dplyr::recode(SERVER,
                  ".V01 Apache"="Apache",
                  "AkamaiGHost"="Other",
                  "294"="Other",
                  "Aeria Games & Entertainment"="Other",
                  "AmazonS3"="Other",
                  "Apache-Coyote/1.1"="Apache",
                  "Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_perl/1.26 PHP/4.3.3 FrontPage/5.0.2 mod_ssl/2.8.12 OpenSSL/0.9.6b"="Apache",
                  "Apache/1.3.27 (Unix) PHP/4.4.1"="Apache",
                  "Apache/1.3.31 (Unix) PHP/4.3.9 mod_perl/1.29 rus/PL30.20"="Apache",
                  "Apache/1.3.33 (Unix) mod_ssl/2.8.24 OpenSSL/0.9.7e-p1 PHP/4.4.8"="Apache",
                  "Apache/1.3.34 (Unix) PHP/4.4.4"="Apache",
                  "Apache/1.3.37 (Unix) mod_perl/1.29 mod_ssl/2.8.28 OpenSSL/0.9.7e-p1"="Apache",
                  "Apache/1.3.39 (Unix) PHP/5.2.5 mod_auth_passthrough/1.8 mod_bwlimited/1.4 mod_log_bytes/1.2 mod_gzip/1.3.26.1a FrontPage/5.0.2.2635 DAV/1.0.3 mod_ssl/2.8.30 OpenSSL/0.9.7a"="Apache",
                  "Apache/1.3.42 Ben-SSL/1.60 (Unix) mod_gzip/1.3.26.1a mod_fastcgi/2.4.6 mod_throttle/3.1.2 Chili!Soft-ASP/3.6.2 FrontPage/5.0.2.2635 mod_perl/1.31 PHP/4.4.9"="Apache",
                  "Apache/2"="Apache",
                  "Apache/2.0.52 (Red Hat)"="Apache",
                  "Apache/2.0.63 (Unix) mod_ssl/2.0.63 OpenSSL/0.9.8e-fips-rhel5 mod_auth_passthrough/2.1 mod_bwlimited/1.4 PHP/5.3.6"="Apache",
                  "Apache/2.2.0 (Fedora)"="Apache",
                  "Apache/2.2.10 (Linux/SUSE)"="Apache",
                  "Apache/2.2.11 (Unix) PHP/5.2.6"="Apache",
                  "Apache/2.2.13 (Unix) mod_ssl/2.2.13 OpenSSL/0.9.8e-fips-rhel5 mod_auth_passthrough/2.1 mod_bwlimited/1.4 PHP/5.2.10"="Apache",
                  "Apache/2.2.14 (FreeBSD) mod_ssl/2.2.14 OpenSSL/0.9.8y DAV/2 PHP/5.2.12 with Suhosin-Patch"="Apache",
                  "Apache/2.2.14 (Ubuntu)"="Apache",
                  "Apache/2.2.14 (Unix) mod_ssl/2.2.14 OpenSSL/0.9.8a"="Apache",
                  "Apache/2.2.14 (Unix) mod_ssl/2.2.14 OpenSSL/0.9.8e-fips-rhel5"="Apache",
                  "Apache/2.2.15 (CentOS)"="Apache",
                  "Apache/2.2.15 (CentOS) DAV/2 mod_ssl/2.2.15 OpenSSL/1.0.1e-fips PHP/5.3.3"="Apache",
                  "Apache/2.2.15 (Red Hat)"="Apache",
                  "Apache/2.2.16 (Debian)"="Apache",
                  "Apache/2.2.16 (Unix) mod_ssl/2.2.16 OpenSSL/0.9.8e-fips-rhel5 mod_auth_passthrough/2.1 mod_bwlimited/1.4"="Apache",
                  "Apache/2.2.20 (Unix)"="Apache",
                  "Apache/2.2.21 (Unix) mod_ssl/2.2.21 OpenSSL/0.9.8e-fips-rhel5 PHP/5.3.10"="Apache",
                  "Apache/2.2.22"="Apache",
                  "Apache/2.2.22 (Debian)"="Apache",
                  "Apache/2.2.22 (Debian) mod_python/3.3.1 Python/2.7.3 mod_ssl/2.2.22 OpenSSL/1.0.1t"="Apache",
                  "Apache/2.2.22 (Ubuntu)"="Apache",
                  "Apache/2.2.23 (Amazon)"="Apache",
                  "Apache/2.2.24 (Unix) DAV/2 PHP/5.3.26 mod_ssl/2.2.24 OpenSSL/0.9.8y"="Apache",
                  "Apache/2.2.25 (Unix) mod_ssl/2.2.25 OpenSSL/0.9.8e-fips-rhel5 mod_bwlimited/1.4"="Apache",
                  "Apache/2.2.26 (Unix) mod_ssl/2.2.26 OpenSSL/0.9.8e-fips-rhel5 mod_bwlimited/1.4 PHP/5.4.26"="Apache",
                  "Apache/2.2.26 (Unix) mod_ssl/2.2.26 OpenSSL/1.0.1e-fips DAV/2 mod_bwlimited/1.4"="Apache",
                  "Apache/2.2.27 (CentOS)"="Apache",
                  "Apache/2.2.27 (Unix) OpenAM Web Agent/4.0.1-1 mod_ssl/2.2.27 OpenSSL/1.0.1p PHP/5.3.28"="Apache",
                  "Apache/2.2.29 (Amazon)"="Apache",
                  "Apache/2.2.29 (Unix) mod_ssl/2.2.29 OpenSSL/1.0.1e-fips DAV/2 mod_bwlimited/1.4"="Apache",
                  "Apache/2.2.29 (Unix) mod_ssl/2.2.29 OpenSSL/1.0.1e-fips mod_bwlimited/1.4"="Apache",
                  "Apache/2.2.29 (Unix) mod_ssl/2.2.29 OpenSSL/1.0.1e-fips mod_bwlimited/1.4 PHP/5.4.35"="Apache",
                  "Apache/2.2.3 (CentOS)"="Apache",
                  "Apache/2.2.3 (Red Hat)"="Apache",
                  "Apache/2.2.31 (Amazon)"="Apache",
                  "Apache/2.2.31 (CentOS)"="Apache",
                  "Apache/2.2.31 (FreeBSD) PHP/5.4.15 mod_ssl/2.2.31 OpenSSL/1.0.2d DAV/2"="Apache",
                  "Apache/2.2.31 (Unix) mod_ssl/2.2.31 OpenSSL/0.9.8e-fips-rhel5 mod_bwlimited/1.4"="Apache",
                  "Apache/2.2.31 (Unix) mod_ssl/2.2.31 OpenSSL/1.0.1e-fips mod_bwlimited/1.4"="Apache",
                  "Apache/2.2.31 (Unix) mod_ssl/2.2.31 OpenSSL/1.0.1e-fips mod_bwlimited/1.4 mod_fcgid/2.3.9"="Apache",
                  "Apache/2.2.31 (Unix) mod_ssl/2.2.31 OpenSSL/1.0.1e-fips mod_bwlimited/1.4 mod_perl/2.0.8 Perl/v5.10.1"="Apache",
                  "Apache/2.2.32"="Apache",
                  "Apache/2.4"="Apache",
                  "Apache/2.4.10"="Apache",
                  "Apache/2.4.10 (Debian)"="Apache",
                  "Apache/2.4.10 (Debian) PHP/5.6.30-0+deb8u1 mod_perl/2.0.9dev Perl/v5.20.2"="Apache",
                  "Apache/2.4.10 (Ubuntu)"="Apache",
                  "Apache/2.4.10 (Unix) OpenSSL/1.0.1k"="Apache",
                  "Apache/2.4.12 (Ubuntu)"="Apache",
                  "Apache/2.4.12 (Unix) OpenSSL/1.0.1e-fips mod_bwlimited/1.4"="Apache",
                  "Apache/2.4.16 (Ubuntu)"="Apache",
                  "Apache/2.4.17 (Unix) OpenSSL/1.0.1e-fips PHP/5.6.19"="Apache",
                  "Apache/2.4.18 (Ubuntu)"="Apache",
                  "Apache/2.4.18 (Unix) OpenSSL/0.9.8e-fips-rhel5 mod_bwlimited/1.4"="Apache",
                  "Apache/2.4.18 (Unix) OpenSSL/1.0.2e Communique/4.1.10"="Apache",
                  "Apache/2.4.23 (Unix)"="Apache",
                  "Apache/2.4.23 (Unix) OpenSSL/0.9.8e-fips-rhel5 mod_bwlimited/1.4"="Apache",
                  "Apache/2.4.23 (Unix) OpenSSL/1.0.1e-fips mod_bwlimited/1.4"="Apache",
                  "Apache/2.4.25"="Apache",
                  "Apache/2.4.25 (Amazon) OpenSSL/1.0.1k-fips"="Apache",
                  "Apache/2.4.25 (Amazon) PHP/7.0.14"="Apache",
                  "Apache/2.4.25 (cPanel) OpenSSL/1.0.1e-fips mod_bwlimited/1.4"="Apache",
                  "Apache/2.4.25 (Debian)"="Apache",
                  "Apache/2.4.25 (FreeBSD) OpenSSL/1.0.1s-freebsd PHP/5.6.30"="Apache",
                  "Apache/2.4.25 (Unix) OpenSSL/1.0.1e-fips mod_bwlimited/1.4"="Apache",
                  "Apache/2.4.6"="Apache",
                  "Apache/2.4.6 (CentOS)"="Apache",
                  "Apache/2.4.6 (CentOS) mod_fcgid/2.3.9 PHP/5.6.30"="Apache",
                  "Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips"="Apache",
                  "Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips mod_fcgid/2.3.9 PHP/5.4.16 mod_jk/1.2.40"="Apache",
                  "Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips PHP/5.4.16"="Apache",
                  "Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips PHP/5.4.16 mod_apreq2-20090110/2.8.0 mod_perl/2.0.10 Perl/v5.24.1"="Apache",
                  "Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips PHP/5.5.38"="Apache",
                  "Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips PHP/7.0.14"="Apache",
                  "Apache/2.4.6 (CentOS) PHP/5.6.8"="Apache",
                  "Apache/2.4.6 (Red Hat Enterprise Linux) OpenSSL/1.0.1e-fips mod_fcgid/2.3.9 Communique/4.2.0"="Apache",
                  "Apache/2.4.6 (Unix) mod_jk/1.2.37"="Apache",
                  "Apache/2.4.6 (Unix) mod_jk/1.2.37 PHP/5.5.1 OpenSSL/1.0.1g mod_fcgid/2.3.9"="Apache",
                  "Apache/2.4.7 (Ubuntu)"="Apache",
                  "Apache/Not telling (Unix) AuthTDS/1.1"="Apache",
                  "Application-Server"="Other",
                  "ATS/5.3.0"="ATS",
                  "barista/5.1.3"="Other",
                  "Boston.com Frontend"="Other",
                  "CherryPy/3.6.0"="Other",
                  "cloudflare-nginx"="nginx",
                  "Cowboy"="Other",
                  "DMS/1.0.42"="Other",
                  "DOSarrest"="Other",
                  "DPS/1.1.8"="Other",
                  "ebay server"="Other",
                  "ECD (fll/0790)"="Other",
                  "fbs"="Other",
                  "gunicorn/19.7.1"="Other",
                  "Heptu web server"="Other",
                  "HTTPDaemon"="Other",
                  "IdeaWebServer/v0.80"="Other",
                  "Jetty(9.0.z-SNAPSHOT)"="Other",
                  "KHL"="Other",
                  "lighttpd"="Other",
                  "lighttpd/1.4.28"="Other",
                  "LiteSpeed"="Other",
                  "marrakesh 1.12.2"="Other",
                  "MediaFire"="Other",
                  "MI"="Other",
                  "Microsoft-HTTPAPI/2.0"="Microsoft Server",
                  "Microsoft-IIS/6.0"="Microsoft Server",
                  "Microsoft-IIS/7.0"="Microsoft Server",
                  "Microsoft-IIS/7.5"="Microsoft Server",
                  "Microsoft-IIS/7.5; litigation_essentials.lexisnexis.com  9999"="Microsoft Server",
                  "Microsoft-IIS/8.0"="Microsoft Server",
                  "Microsoft-IIS/8.5"="Microsoft Server",
                  "mw2097.codfw.wmnet"="wmnet",
                  "mw2101.codfw.wmnet"="wmnet",
                  "mw2103.codfw.wmnet"="wmnet",
                  "mw2104.codfw.wmnet"="wmnet",
                  "mw2106.codfw.wmnet"="wmnet",
                  "mw2107.codfw.wmnet"="wmnet",
                  "mw2109.codfw.wmnet"="wmnet",
                  "mw2110.codfw.wmnet"="wmnet",
                  "mw2113.codfw.wmnet"="wmnet",
                  "mw2114.codfw.wmnet"="wmnet",
                  "mw2164.codfw.wmnet"="wmnet",
                  "mw2165.codfw.wmnet"="wmnet",
                  "mw2171.codfw.wmnet"="wmnet",
                  "mw2172.codfw.wmnet"="wmnet",
                  "mw2173.codfw.wmnet"="wmnet",
                  "mw2175.codfw.wmnet"="wmnet",
                  "mw2176.codfw.wmnet"="wmnet",
                  "mw2177.codfw.wmnet"="wmnet",
                  "mw2178.codfw.wmnet"="wmnet",
                  "mw2180.codfw.wmnet"="wmnet",
                  "mw2182.codfw.wmnet"="wmnet",
                  "mw2185.codfw.wmnet"="wmnet",
                  "mw2187.codfw.wmnet"="wmnet",
                  "mw2190.codfw.wmnet"="wmnet",
                  "mw2192.codfw.wmnet"="wmnet",
                  "mw2197.codfw.wmnet"="wmnet",
                  "mw2198.codfw.wmnet"="wmnet",
                  "mw2199.codfw.wmnet"="wmnet",
                  "mw2224.codfw.wmnet"="wmnet",
                  "mw2225.codfw.wmnet"="wmnet",
                  "mw2226.codfw.wmnet"="wmnet",
                  "mw2228.codfw.wmnet"="wmnet",
                  "mw2230.codfw.wmnet"="wmnet",
                  "mw2231.codfw.wmnet"="wmnet",
                  "mw2232.codfw.wmnet"="wmnet",
                  "mw2233.codfw.wmnet"="wmnet",
                  "mw2236.codfw.wmnet"="wmnet",
                  "mw2238.codfw.wmnet"="wmnet",
                  "mw2239.codfw.wmnet"="wmnet",
                  "mw2240.codfw.wmnet"="wmnet",
                  "mw2241.codfw.wmnet"="wmnet",
                  "mw2242.codfw.wmnet"="wmnet",
                  "mw2255.codfw.wmnet"="wmnet",
                  "mw2257.codfw.wmnet"="wmnet",
                  "mw2260.codfw.wmnet"="wmnet",
                  "My Arse"="Other",
                  "openresty"="Other",
                  "Nginx (OpenBSD)"="nginx",
                  "nginx + Phusion Passenger"="nginx",
                  "nginx/0.7.65"="nginx",
                  "nginx/0.8.35"="nginx",
                  "nginx/0.8.38"="nginx",
                  "nginx/0.8.54"="nginx",
                  "nginx/0.8.55"="nginx",
                  "nginx/1.1.19"="nginx",
                  "nginx/1.10.0"="nginx",
                  "nginx/1.10.0 (Ubuntu)"="nginx",
                  "nginx/1.10.1"="nginx",
                  "nginx/1.10.1 + Phusion Passenger 5.0.30"="nginx",
                  "nginx/1.10.2"="nginx",
                  "nginx/1.10.3"="nginx",
                  "nginx/1.11.10"="nginx",
                  "nginx/1.11.2"="nginx",
                  "nginx/1.11.3"="nginx",
                  "nginx/1.12.0"="nginx",
                  "nginx/1.13.0"="nginx",
                  "nginx/1.2.1"="nginx",
                  "nginx/1.2.6"="nginx",
                  "nginx/1.4.3"="nginx",
                  "nginx/1.4.4"="nginx",
                  "nginx/1.4.6 (Ubuntu)"="nginx",
                  "nginx/1.6.2"="nginx",
                  "nginx/1.6.3"="nginx",
                  "nginx/1.6.3 + Phusion Passenger"="nginx",
                  "nginx/1.7.12"="nginx",
                  "nginx/1.7.4"="nginx",
                  "nginx/1.8.0"="nginx",
                  "nginx/1.8.1"="nginx",
                  "nginx/1.9.13"="nginx",
                  "nxfps"="Other",
                  "openresty"="Other",
                  "openresty/1.11.2.1"="Other",
                  "openresty/1.11.2.2"="Other",
                  "Oracle-iPlanet-Web-Server/7.0"="Other",
                  "Pagely Gateway/1.5.1"="Other",
                  "Pepyaka/1.11.3"="Other",
                  "Pizza/pepperoni"="Other",
                  "Play"="Other",
                  "Proxy Pandeiro UOL"="Other",
                  "PWS/8.2.0.7"="Other",
                  "Resin/3.1.8"="Other",
                  "Roxen/5.4.98-r2"="Other",
                  "Scratch Web Server"="Other",
                  "Server"="Other",
                  "Squeegit/1.2.5 (3_sir)"="Other",
                  "squid/3.3.8"="Other",
                  "SSWS"="Other",
                  "Sucuri/Cloudproxy"="Other",
                  "Sun-ONE-Web-Server/6.1"="Other",
                  "Tengine"="Other",
                  "tsa_c"="Other",
                  "Varnish"="Other",
                  "Virtuoso/07.20.3217 (Linux) i686-generic-linux-glibc212-64  VDB"="Other",
                  "www.lexisnexis.com  9999"="Other",
                  "XXXXXXXXXXXXXXXXXXXXXX"="Other",
                  "Yippee-Ki-Yay"="Other",
                  "Zope/(2.13.16; python 2.6.8; linux2) ZServer/1.1"="Other",
                  .deafaul= levels(SERVER),
                  .missing= "Unknow"
           )
  )
table(temp$SERVER)
temp$SERVER<-factor(temp$SERVER,levels=c("Other","Apache","ATS","GSE","Microsoft Server","nginx","Unknow","wmnet","YouTubeFrontEnd"), 
                 labels=c("Other","Apache","ATS","GSE","Microsoft Server","nginx","Unknow","wmnet","YouTubeFrontEnd"))

# Variabile WHOIS_COUNTRY: indica la nazione alla quale appartiene il sito
count(temp[!complete.cases(temp$WHOIS_COUNTRY),]) # si hanno 306 valori mancanti, che prenderanno l'etichetta di 
# Unknow. Le nazioni sono codificate con le proprie sigle, ad alcune sono ripetute con lettere maiuscole e minuscole
# invertite. Si uniforma il tutto sostituendo alle sigle il nome della Nazione
temp<-temp %>%
  mutate(WHOIS_COUNTRY=
           dplyr::recode(WHOIS_COUNTRY,
                  "[u'GB'; u'UK']"="Gran Bretagna",
                  "AE"="Emirati Arabi Uniti",
                  "AT"="Austria",
                  "AU"="Australia",
                  "BE"="Belgio",
                  "BR"="Brasile",
                  "BS"="Bahama",
                  "BY"="Bielorussia",
                  "CA"="Canada",
                  "CH"="Svizzera",
                  "CN"="Cina",
                  "CZ"="Repubblica Ceca",
                  "DE"="Germania",
                  "ES"="Spagna",
                  "FR"="Francia",
                  "GB"="Gran Bretagna",
                  "HK"="Hong Kong",
                  "IE"="Irlanda",
                  "IL"="Israele",
                  "IN"="India",
                  "IT"="Italia",
                  "JP"="Giappone",
                  "KG"="Kirghizistan",
                  "KR"="Corea del Sud",
                  "KY"="Cayman",
                  "LU"="Lussemburgo",
                  "LV"="Lettonia",
                  "NL"="Olanda",
                  "NO"="Norvegia",
                  "PA"="Panama",
                  "PH"="Filippine",
                  "PK"="Pakistan",
                  "ru"="Russia",
                  "RU"="Russia",
                  "SC"="Seychelles",
                  "se"="Svezia",
                  "SE"="Svezia",
                  "SI"="Slovenia",
                  "TH"="Tailandia",
                  "TR"="Turchia",
                  "UA"="Ucraina",
                  "UG"="Uganda",
                  "UK"="Gran Bretagna",
                  "United Kingdom"="Gran Bretagna",
                  "us"="Stati Uniti d'America",
                  "US"="Stati Uniti d'America",
                  "UY"="Uruguay",
                  .default= levels(WHOIS_COUNTRY),
                  .missing= "Unknow"
           )         
  )
# Si hanno comunque troppe categorie considerando le singole nazioni, per cui si preferisce raggrupparle in Continenti
# creando comunque una nuova variabile Continente
temp<-temp %>%
  mutate(Continente=
           dplyr::recode(WHOIS_COUNTRY,
                  "Emirati Arabi Uniti"="Asia",
                  "Austria"="Europa",
                  "Australia"="Oceania",
                  "Belgio"="Europa",
                  "Brasile"="America",
                  "Bahama"="America",
                  "Bielorussia"="Europa",
                  "Canada"="America",
                  "Svizzera"="Europa",
                  "Cina"="Asia",
                  "Repubblica Ceca"="Europa",
                  "Germania"="Europa",
                  "Spagna"="Europa",
                  "Francia"="Europa",
                  "Gran Bretagna"="Europa",
                  "Hong Kong"="Asia",
                  "Irlanda"="Europa",
                  "Israele"="Asia",
                  "India"="Asia",
                  "Italia"="Europa",
                  "Giappone"="Asia",
                  "Kirghizistan"="Asia",
                  "Corea del Sud"="Asia",
                  "Cayman"="America",
                  "Lussemburgo"="Europa",
                  "Lettonia"="Europa",
                  "Olanda"="Europa",
                  "Norvegia"="Europa",
                  "Panama"="America",
                  "Filippine"="Asia",
                  "Pakistan"="Asia",
                  "Russia"="Asia",
                  "Seychelles"="Africa",
                  "Svezia"="Europa",
                  "Slovenia"="Europa",
                  "Tailandia"="Asia",
                  "Turchia"="Asia",
                  "Ucraina"="Europa",
                  "Uganda"="Africa",
                  "Stati Uniti d'America"="America",
                  "Uruguay"="America",
                  "Cyprus"="Asia",
                  .default= levels(WHOIS_COUNTRY)
           )         
  )
table(temp$Continente) #Africa, Asia e Oceania hanno poche unità statistiche rispetto ad America ed Europa, si decide
# quindi di unirle in un'unica categoria
temp<-temp %>%
  mutate(Continente=
      dplyr::recode(Continente,
          "Africa"="Africa_Asia_Oceania",
          "Asia"="Africa_Asia_Oceania",
          "Oceania"="Africa_Asia_Oceania",
          .default=levels(Continente)
      )       
  )
table(temp$Continente)
temp$Continente<-factor(temp$Continente,levels=c("Unknow","Africa_Asia_Oceania","America","Europa"),
                        labels=c("Unknow","Africa_Asia_Oceania","America","Europa"))

# Variabile WHOIS_REGDATE: indica la data in cui il server è stato inserito in internet, in cui ha preso funzione,
# può essere utilizzato come indicatore del livello si obsolescenza di un server. Quelli più vecchi avranno delle
# patch di sicurezza meno performanti rispetto a quelli di recente sviluppo, nonché non avranno proprio le risorse 
# utili a fronteggiare le nuove minacce nate negli ultimi anni.
# vi è il bisogno di trasformare i dati da formato carattere a formato data. Si può fare attraverso l'utilizzo del
# pacchetto lubridate, precedentemente caricato
count(temp[!complete.cases(temp$WHOIS_REGDATE),]) #ci sono 127 valori mancanti, che diverrano degli Unknow, ma prima,
# per essere valutati dalla funzione del pacchetto lubridate, vengono trasformati in una data fittizia.
table(temp$WHOIS_REGDATE)
temp$WHOIS_REGDATE<-ifelse(temp$WHOIS_REGDATE=="2002-03-20T23:59:59.0Z","21/03/2002 00:00",
                           ifelse(temp$WHOIS_REGDATE=="0",NA,
                                  ifelse(temp$WHOIS_REGDATE=="b",NA,temp$WHOIS_REGDATE)))
temp<-temp %>%
  mutate(RegDate=
           dmy_hm(temp$WHOIS_REGDATE) #trasformiamo i caratteri in data. la funzione indica che la data è costituita da
                                    # giorno,mese,anno e poi ora e minuti
  ) %>%
  mutate(RegDate=
           dplyr::recode(WHOIS_REGDATE,
                  .default=as.character(year(RegDate)), #estraiamo solo l'anno da ogni data e lo ritrasformiamo in carattere
                  .missing="Unknow" #valore per dati mancanti
           )
  ) %>%
  mutate(RegDate=
           dplyr::recode(RegDate,
                  "1990"="anni 90",
                  "1991"="anni 90",
                  "1992"="anni 90",
                  "1993"="anni 90",
                  "1994"="anni 90",
                  "1995"="anni 90",
                  "1996"="anni 90",
                  "1997"="anni 90",
                  "1998"="anni 90",
                  "1999"="anni 90",
                  "2000"="anni 2000",
                  "2001"="anni 2000",
                  "2002"="anni 2000",
                  "2003"="anni 2000",
                  "2004"="anni 2000",
                  "2005"="anni 2000",
                  "2006"="anni 2000",
                  "2007"="anni 2000",
                  "2008"="anni 2000",
                  "2009"="anni 2000",
                  "2010"="anni 2010",
                  "2011"="anni 2010",
                  "2012"="anni 2010",
                  "2013"="anni 2010",
                  "2014"="anni 2010",
                  "2015"="anni 2010",
                  "2016"="anni 2010",
                  "2017"="anni 2010",
                  .default=levels(RegDate)
           )         
  )
table(temp$RegDate)
temp<-temp[,-6] #eliminiamo la variabile WHOIS_REGDATE
temp$RegDate<-factor(temp$RegDate,levels=c("anni 90","anni 2000","anni 2010","Unknow"))

# Variabile APP_BYTES
count(temp[!complete.cases(temp$APP_BYTES),]) #non ci sono valori mancanti
summary(temp$APP_BYTES)

# Variabile Type: è la nostra variabile risposta, 1 indica che il sito è pericoloso, 0 che il sito è sicuro
count(temp[!complete.cases(temp$Type),]) #non ci sono valori mancanti
table(temp$Type)
temp$Typefac<-factor(temp$Type, levels=c(0,1), labels=c("sicuro","pericoloso"))

#### Termine della codifica iniziale delle variabili

attach(temp)

#### Analisi descrittiva delle variabili e delle loro interazioni con la variabile risposta ####
prop.table(table(Typefac))
ggplot()+
  geom_bar(aes(x=Typefac,y=..prop..,group=1), fill=c("#f9ba32","#f0810f"))+
  labs(title= "Siti sicuri e siti pericoli in percentuale",
       x= "Tipologia di sito",
       y= "Proporzione")+
  theme(
    text=element_text(colour="white",size=20),
    plot.background=element_rect(fill="#2f3131"),
    panel.background=element_rect(fill="#2f3131"),
    plot.title=element_text(hjust=0.5),
    axis.text=element_text(colour="White"),
    plot.margin=margin(30,30,30,30,unit="pt")
  )

ggplot()+
  geom_freqpoly(aes(URL_LENGTH),colour="#f9ba32",bins=round(sqrt(1781),0),size=2)+
  theme(
    text=element_text(colour="white",size=20),
    plot.background=element_rect(fill="#2f3131"),
    panel.background=element_rect(fill="#2f3131"),
    plot.title=element_text(hjust=0.5),
    axis.text=element_text(colour="White"),
    plot.margin=margin(30,30,30,10,unit="pt"),
    axis.title.y=element_text(colour="#2f3131")
  )

ggplot()+
  geom_freqpoly(aes(NUMBER_SPECIAL_CHARACTERS),colour="#f9ba32",bins=round(sqrt(1781),0),size=2)+
  theme(
    text=element_text(colour="white",size=20),
    plot.background=element_rect(fill="#2f3131"),
    panel.background=element_rect(fill="#2f3131"),
    plot.title=element_text(hjust=0.5),
    axis.text=element_text(colour="White"),
    plot.margin=margin(30,30,30,10,unit="pt"),
    axis.title.y=element_text(colour="#2f3131")
  )

ggplot()+
  geom_freqpoly(aes(APP_BYTES),colour="#f9ba32",bins=round(sqrt(1781),0),size=2)+
  theme(
    text=element_text(colour="white",size=20),
    plot.background=element_rect(fill="#2f3131"),
    panel.background=element_rect(fill="#2f3131"),
    plot.title=element_text(hjust=0.5),
    axis.text=element_text(colour="White"),
    plot.margin=margin(30,30,30,10,unit="pt"),
    axis.title.y=element_text(colour="#2f3131")
  )
count(temp[APP_BYTES==0,])/1781 #percentuale di valori pari a 0 nella variabile APP_BYTES


# Type ~ ULR_LENGTH
plot(URL_LENGTH,Type)
# verifichiamo se si può avere un adattamento con un modello logistico
# dividiamo le unità statistiche in gruppi rispetto ad un partizionamento di URL_LENGTH. Di tali gruppi calcoliamo la
# probabilità di essere un sito pericolo e ne facciamo il logit
table_1<-addmargins(table(cut(URL_LENGTH,breaks=20),Type),2)
pi1<-table_1[,2]/table_1[,3]
plot(1:20,pi1)  #sembrerebbe che il modello logistico abbia un discreto adattamento sui dati, effettivamente i dati
# hanno una forma ad S, non mi aspetto però un alto livello di variabilità spiegata da parte del modello
ggplot()+
  geom_boxplot(aes(Typefac,URL_LENGTH), fill="#f9ba32", outlier.colour="#7E2217", outlier.size = 2)+
  labs(title="Boxplot lunghezza dell'URL",x="Tipologia di sito")+
  theme_economist_white()+
  theme(
    text=element_text(size=20),
    plot.background=element_rect(fill="white"),
    panel.background=element_rect(fill="white"),
    plot.title=element_text(hjust=0.5),
    plot.margin=margin(30,30,30,10,unit="pt"),
    axis.title.y=element_text(colour="white"),
    axis.ticks=element_line(colour="white"),
    panel.grid.major.x=element_line(colour="white"),
  )
# sembrerebbe che i siti pericolosi abbiano una lunghezza dell'URL maggiore rispetto i siti sicuri, anche se nei siti
# sicuri sono presenti molti outliers

# Type ~ NUMBER_SPECIAL_CHARACTER
plot(NUMBER_SPECIAL_CHARACTERS,Type)
# verifichiamo se si può avere un adattamento con un modello logistico
table_2<-addmargins(table(cut(NUMBER_SPECIAL_CHARACTERS,breaks=30),Type),2)
pi2<-table_2[,2]/table_2[,3]
plot(1:30,pi2)  #anche qui il modello logistico sembrerebbe adattarsi abbastanza discretamente. anche qui non mi aspetto
                # un gran livello di adattamento
ggplot()+
  geom_boxplot(aes(Typefac,NUMBER_SPECIAL_CHARACTERS), fill="#f9ba32", outlier.colour="#7E2217", outlier.size = 2)+
  labs(title="Boxplot numero di caratteri speciali nell'URL",x="Tipologia di sito")+
  theme_economist_white()+
  theme(
    text=element_text(size=20),
    title=element_text(size=15),
    plot.background=element_rect(fill="white"),
    panel.background=element_rect(fill="white"),
    plot.title=element_text(hjust=0.5),
    plot.margin=margin(30,30,30,10,unit="pt"),
    axis.title.y=element_text(colour="white"),
    axis.ticks=element_line(colour="white"),
    panel.grid.major.x=element_line(colour="white"),
  )
# sembrerebbe che i siti pericolosi abbiano un numero maggiore di caratteri speciali rispetto i siti sicuri, anche se nei siti
# sicuri sono presenti molti outliers

# Type ~ CHARSET
table(CHARSET,Type)
chisq.test(CHARSET,Type) #L'approssimazione al chi-quadro potrebbe essere inesatta per via dei valori bassi in Other
# anche us-ascii presenta valori bassi per cui si potrebbero unire le categorie

detach(temp)
temp<-temp %>%
  mutate(CHARSET=
    dplyr::recode(CHARSET,
           "us-ascii"="Other",
           .default=levels(CHARSET)
    )
  )
temp$CHARSET<-factor(temp$CHARSET, levels=c("Other","UTF-8","ISO-8859"))
attach(temp)
table(CHARSET,Type)
ggplot(temp)+
  geom_bar(aes(CHARSET,..count../sum(..count..),fill=Typefac),show.legend=F)+
  labs(x="",y="")+
  coord_flip()+
  scale_fill_manual(values=c("#426e86","#f9ba32"))+
  theme(
    axis.text=element_text(colour="white",size=12),
    panel.background = element_rect(colour="#2f3131",fill="#2f3131"),
    plot.background = element_rect(colour="#2f3131",fill="#2f3131"),
  )
chisq.test(CHARSET,Type) #vi è una relazione tra charset e il tipo di sito

# funzione KATERI
G2 <- function(data){
  # computes the G2 test of independence
  # for a two-way contingency table
  # data: IxJ matrix
  X2 <- chisq.test(data)
  mle <- X2$expected
  df <- X2$parameter
  term.G2 <- data*log(data/mle)
  term.G2[data==0] <- 0
  G2 <- 2 * sum(term.G2)
  p <- 1-pchisq(G2, df)
  return(list(G2=G2, df=df, p.value=p))
}
G2(table(CHARSET,Type)) #anche la variabile statistica G2 mostra dipendenza tra CHARSET e Type

# Type ~ SERVER
table(SERVER,Type) #vi sono categorie con presenza di 0 nei siti pericoli, si preferisci ragrupparli tutti nella categoria
# OTHER
detach(temp)
temp<-temp %>%
  mutate(SERVER=
           dplyr::recode(SERVER,
                  "ATS"="Other",
                  "GSE"="Other",
                  "Unknow"="Other",
                  "wmnet"="Other",
                  "YouTubeFrontEnd"="Other",
                  .default=levels(SERVER)
           )
  )
temp$SERVER<-factor(temp$SERVER, levels=c("Other","Apache","Microsoft Server","nginx"))
attach(temp)
table(SERVER,Type)
ggplot(temp)+
  geom_bar(aes(SERVER,..count../sum(..count..),fill=Typefac),show.legend=F)+
  labs(x="",y="")+
  coord_flip()+
  scale_fill_manual(values=c("#426e86","#f9ba32"))+
  theme(
    axis.text=element_text(colour="white",size=12),
    panel.background = element_rect(colour="#2f3131",fill="#2f3131"),
    plot.background = element_rect(colour="#2f3131",fill="#2f3131"),
  )
chisq.test(SERVER,Type) #si ha che il server di provenienza incide sul tipo di sito che si visita
G2(table(SERVER,Type)) #stessa cosa si ha con il G2

# Type~Continente
table(Continente,Type)
odds_ratio.Am_Eu<-(79*1162)/(74*58)
odds_ratio.Am_Eu-(qnorm(0.975,0,1)*sqrt(1/79+1/1162+1/74+1/58))
odds_ratio.Am_Eu+(qnorm(0.975,0,1)*sqrt(1/79+1/1162+1/74+1/58))
ggplot(temp)+
  geom_bar(aes(Continente,..count../sum(..count..),fill=Typefac),show.legend=F)+
  labs(x="",y="")+
  coord_flip()+
  scale_fill_manual(values=c("#426e86","#f9ba32"))+
  theme(
    axis.text=element_text(colour="white",size=12),
    panel.background = element_rect(colour="#2f3131",fill="#2f3131"),
    plot.background = element_rect(colour="#2f3131",fill="#2f3131"),
  )
chisq.test(Continente,Type)
G2(table(Continente,Type)) #entrambi i test indicano che ci sia dipendenza tra il continente di provenienza del sito 
# e la loro tipologia
table(WHOIS_COUNTRY,Type)


# Type~RegDate
table(RegDate,Type)
ggplot(temp)+
  geom_bar(aes(RegDate,..count../sum(..count..),fill=Typefac),show.legend=F)+
  labs(x="",y="")+
  coord_flip()+
  scale_fill_manual(values=c("#426e86","#f9ba32"))+
  theme(
    axis.text=element_text(colour="white",size=12),
    panel.background = element_rect(colour="#2f3131",fill="#2f3131"),
    plot.background = element_rect(colour="#2f3131",fill="#2f3131"),
  )
chisq.test(RegDate,Type)
G2(table(RegDate,Type)) #anche RegDate sembra essere significativo sulla tipologia di sito

# Type~APP_BYTES
summary(APP_BYTES)
ggplot()+
  geom_boxplot(aes(Typefac,APP_BYTES), fill="#f9ba32", outlier.colour="#7E2217", outlier.size = 2)+
  labs(title="Boxplot numero di pacchetti scambiati",x="Tipologia di sito")+
  theme_economist_white()+
  theme(
    text=element_text(size=20),
    title=element_text(size=15),
    plot.background=element_rect(fill="white"),
    panel.background=element_rect(fill="white"),
    plot.title=element_text(hjust=0.5),
    plot.margin=margin(30,30,30,10,unit="pt"),
    axis.title.y=element_text(colour="white"),
    axis.ticks=element_line(colour="white"),
    panel.grid.major.x=element_line(colour="white"),
  )
# anche se si nota la presenza di valori anomali molto grandi rispetto agli altri, si preferisce lasciarli così come sono, poichè
# potrebbero essere indicatori della tipologia di sito. Poichè sono presenti sui siti sicuri, può darsi che il maggior numero 
# di pacchetti scambiati sia dovuto ad un numero maggiore di certificati di sicurezza che il sito invia al client.

#### Costruzione del modello aggiungendo regressori di volta in volta ####
m1<-glm(Type~URL_LENGTH, family=binomial(link="logit")); summary(m1)
m2<-update(m1,.~.+NUMBER_SPECIAL_CHARACTERS); summary(m2)

# verifichiamo che se ci potrebbe essere una certa correlazione tra la lunghezza dell'Url e il numero di caratteri
# speciali presenti in esso
cor(URL_LENGTH,NUMBER_SPECIAL_CHARACTERS) #c'è un alta correlazione tra il numero di caratteri speciali e la 
# lunghezza dell'URL
vif(m2) #effettivamente anche l'utilizzo del vif ce lo conferma, riporatando valori al di sopra di 10
# inserendo entrambi i regressori all'interno del modello si hanno problemi di multicollinearità
# proviamo a risolvere tale problema considerando invece del numero di caratteri speciali, la loro proporzione rispetto
# al numero di caratteri totali nell'URL
prop.spec<-NUMBER_SPECIAL_CHARACTERS/URL_LENGTH
m3<-glm(Type~URL_LENGTH+prop.spec, family=binomial(link="logit")); summary(m3)
vif(m3) #il problema della multicollinearità è stato eliminato
fit3<-ifelse(fitted(m3)>0.5,1,0)
hoslem.test(Type,fit3) #non si ha un buon fit del modello, quindi aggiungiamo qualche altro regressore
pseudoR2<-function(mod) {1-(deviance(mod)/mod$null.deviance)} 
pseudoR2(m3)

#aggiungiamo ora la provenienza geografica del sito internet
m4<-update(m3, .~.+Continente); summary(m4)
# aggiungendo la variabile continente si ha una diminuzione dell'AIC per cui la variabile porta con se maggiore
# variabilità, e significativa.
anova(m3,m4, test="Chisq") # il p-value è praticamente 0, per cui vi è effitavemente un certo livello di significatività
# del continente da cui proviene il sito. Tuttavia, il fatto che il sito provenga dall'Africa, dall'Oceania oppure dall'Asia
# non risulta essere statisticamente significativo, e quindi non influisce sulla propensione ad essere un sito pericoloso
# Si prova a riunire tale categoria con quella di riferimento, inserendola come Other
detach(temp)
temp<-temp %>%
  mutate(Continente=
    dplyr::recode(Continente,
        "Unknow"="Other",
        "Africa_Asia_Oceania"="Other",
        .default=levels(Continente)
    )         
  )
temp$Continente<-factor(temp$Continente,levels=c("Other","America","Europa"))
attach(temp)
m5<-update(m3, .~.+Continente); summary(m5)
fit5<-ifelse(fitted(m5)>.5,1,0)
hoslem.test(Type,fit5)
pseudoR2(m5) #risulta essere spiegato un 37% della variabilità totale, proviamo ad aggiungere qualche altro regressore

m6<-update(m5, .~.+CHARSET); summary(m6) #la variabile CHARSET non sembra essere statisticamente significativa
# a spiegare la propensione ad essere un sito pericoloso
anova(m5,m6,test="Chisq") #anche il test della deviance osserva tale cose. L'inserimento del nuovo regressore non
# apporta maggiore bontà di adattamento, tant'è che m5 e m6 sono statisticamente uguali per quanto riguarda la bontà
# di adattamento del modello
pseudoR2(m6) #anche i due pseudoR2 sono simili tra di loro

#aggiungiamo le informazioni sul server
m6.5<-update(m5, .~.+SERVER); summary(m6.5)
anova(m5,m6.5,test="Chisq")
m7<-update(m5, .~.+SERVER+RegDate); summary(m7)
pseudoR2(m7)
anova(m6.5,m7,test="Chisq") #le variabili relative al Server sono statisticamente significative a spiegare la propensione
#ad essere un sito pericoloso

#Proviamo ad inserire un'interazione tra il server e la sua data di creazione
m8<-update(m7, .~.+SERVER*RegDate); summary(m8)
anova(m7,m8,test="Chisq") 
pseudoR2(m8)
# la bontà di adattamento migliora inserendo l'interazione, ma i regressori inseriti non hanno significatività. 
chisq.test(SERVER,RegDate)
vif(m8)

m10<-update(m7, .~.+APP_BYTES); summary(m10) #la variabile app_bytes non è statisticamente significativa

# Il modello che al meglio riesce a spiegare la propensione ad essere un sito pericolo è m7
summary(m7)
# si ha comunque un problema con il continente America, che risulta essere non significativo. Nell'analisi comunque
# fatta precedentemente sulle nazioni, vi è visto come la nazione con maggior numero di siti pericolosi siano gli USA
# ma anche la Spagna (nonché la nazione sconosciuta).
# Proviamo a stimare un modello togliendo il continente e inserendo un politoma che indica se il sito è americano, 
# se è spagnolo, se non se ne conosce la provenienza o altro.
detach(temp)
temp<-temp %>%
  mutate(IS_NATION=
    dplyr::recode(WHOIS_COUNTRY,
           "Stati Uniti d'America"="USA",
           "Spagna"="Spagna",
           "Unknow"="Unknow",
           .default="Other"
    )         
  )
temp$IS_NATION<-factor(temp$IS_NATION, levels=c("Other","USA","Spagna","Unknow"))
attach(temp)

m11<-update(m7, .~.-Continente+IS_NATION); summary(m11) #sapere che il sito è degli USA non è statisticamente
# significativo, proviamo a mettere USA con Other, stessa cosa vale per lo stato sconosciuto.
detach(temp)
temp<-temp %>%
  mutate(IS_NATION=
           dplyr::recode(IS_NATION,
                         "Spagna"="Spagna",
                         .default="Other"
           )         
  )
temp$IS_NATION<-factor(temp$IS_NATION, levels=c("Other","Spagna","Unknow"))
attach(temp)
m12<-update(m11, .~.); summary(m12)
pseudoR2(m12)

# il modello 12 è migliore del modello 7, per cui si sceglie di usare questo come modello finale.
# Su tale modello applichiamo tutte le analisi per la bontà di adattamento e sui residui del caso
fit12<-ifelse(fitted(m12)>.5,1,0)
hoslem.test(Type,fit12) #non è un modello proprio preciso in quanto i valori osservati e i valori stimati
# differiscono statisticamente
vif(m12) #non sembra ci siano problemi di multicolliarità

anova12<-anova(m12)
p_value<-1-pchisq(anova12$Deviance,anova12$Df)
anova12<-cbind(anova12,p_value)

ggplot(m12)+
  geom_jitter(aes(1:1781,residuals(m12)),colour="#426e86")+
  geom_line(aes(1:1781,3),colour="#f9ba32",size=1.8)+
  geom_line(aes(1:1781,-3),colour="#f9ba32",size=1.8)+
  labs(x="",y="")+
  theme_bw()#i residui sembrano abbastanza erratici e contenuti nella banda -3,3 (tranne qualche eccezione)

acc<-table(Typefac,fitted(m12)>0.5) #si considerano pericolosi i siti con un valore di probabilità maggiore di 0.5
sum(diag(acc))/sum(acc) #si ha un buon livello di accuratezza del modello
acc[2,2]/sum(Type) #valore della sensibilità (veri positivi su totale siti pericolosi)
acc[1,1]/(1781-sum(Type)) #valore di specificità (veri negativi su siti sicuri)
# il modello presenta un alto grado si specificità. Questo significa che riesce a predire quasi con esattezza quali 
# sono i siti sicuri. Il livello di sensibilità è invece basso, per cui, succede che nel quasi 50% dei casi un sito 
# che viene giudicato pericoloso in realtà non lo sia

# Analizziamo il livello di cut-off attraverso le curve di ROC
par(pty="s") #plot type to square
roc(Type,fitted(m12),plot=T, legacy.axes=T, percent=T,print.auc=T) #Area under the curve
roc.info<-roc(Type,fitted(m12),plot=T, legacy.axes=T)
roc.df<-data.frame(Sensibilità=roc.info$sensitivities*100, #prendiamo la percentuale di veri positivi
                   Specificità=(1-roc.info$specificities)*100, #prendiamo la percentuale di falsi positivi
                   cut_off=roc.info$thresholds) #prendiamo il livello di cut-off
head(roc.df); tail(roc.df)
# andiamo a ricercare quel cut_off per cui il grafico della curva di Roc raggiunge maggiormente l'angolo del grafico
# in alto a sinistra
draw.circle(78,95,2,border="#f0810f",col="white") #più o meno un livello di sensibilità dell'89% e uno di specificità
# dell'86%
roc.df[700:900,] #visualizziamo tali valori e ci possiamo rendere conto che nel punto in cui la curva ROC è più
# vicina all'angolo in alto a sinistra del grafico il livello di cut-off è pari circa a 0.07. Proviamo ad inserire tale valore
# nel livello di accuratezza, sensibilità e specificità
acc_0.1<-table(Typefac,fitted(m12)>0.07)
sum(diag(acc_0.1))/sum(acc_0.1) 
acc_0.1[2,2]/sum(Type) 
acc_0.1[1,1]/(1781-sum(Type)) 

# Facciamo alcune considerazioni finali sul modello
odds_ratio<-exp(m12$coefficients) # calcoliamo gl odds-ratio
summ<-summary(m12)
odds_ratio_lower<-exp(m12$coefficients)-qnorm(0.975,0,1)*(summ$coefficients[,2]) #inf i.c. odds-ratio
odds_ratio_upper<-exp(m12$coefficients)+qnorm(0.975,0,1)*(summ$coefficients[,2]) #inf i.c odds-ratio
tab<-data.frame(odds_ratio,odds_ratio_lower,odds_ratio_upper); tab

exp(10*0.028641)
# Un aumento di 10 caratteri nell'Url comporta un aumento del 33% della propensione ad essere un sito pericoloso
exp(5.579515)
exp(5.579515)-qnorm(0.975,0,1)*(1.078129)
exp(5.579515)+qnorm(0.975,0,1)*(1.078129)
# la propensione ad essere un sito pericolo nel caso in cui si stia per visitare una pagina web spagnola è da un minimo
#di 262 volte, fino ad un massimo di 267 volte, la stessa propensione che si avrebbe visitando un sito proveniente da un'altra nazione. 
exp(2.067017)
# la propensione ad essere un sito pericolo nel caso in cui si stia visitando una pagina web gestita dal server 
# Apache è il 7.90 volte maggiore della stessa propensione nel caso in cui si stia visitando un sito gestito da 
# un altro server.
exp(2.067017-2.061322)
# la propensione ad essere un sito pericoloso nel caso in cui esso provenga dal server Apache è solo maggiore 
# dello 0,5% della stessa propensione nel caso in cui il sito provenga dal server Microsoft. Si può quindi 
# affermare che vi è la stessa propabilità che i due server web gestiscano siti pericolosi.
exp(2.776011-3.212477)
# la propensione ad essere un sito pericoloso nel caso in cui esso provenga da un server degli anni 2000 è il
# 65% della stessa propensione nel caso in cui il sito provenga da un server degli anni 2010. Questo significa
# che i siti gestiti dai server più moderni sono quelli più attaccati dai crimanali informatici

V<-vcov(m12) #recuperiamo la matrice di varianza e covarianze del modello
# operiamo ora alcune simulazioni, per capire il livello di probabilità che un sito sia pericoloso

exp(-16.676901+0.028641*30+38.634638*0.5+2.067017+3.451874)/(1+exp(-16.676901+0.028641*30+38.634638*0.5+2.067017+3.451874))

exp(-16.676901+0.028641*70+38.634638*0.1+2.044437+5.579515)/(1+exp(-16.676901+0.028641*70+38.634638*0.1+2.044437+5.579515))

exp(-16.676901+0.028641*50+38.634638*(1/5)+2.061322+2.776011)/(1+exp(-16.676901+0.028641*50+38.634638*(1/5)+2.061322+2.776011))
example<-c(1,50,0.20,0,1,0,1,0,0,0) #immettiamo i valori assunti dall'esempio precendente
example2<-example*example
var<-sum(diag(V)*example2) # calcoliamo passo passo la varianza che ci serve per IC della probabilità
cov<-0;
for (i in 1:9){
  for (j in (i+1):10){
    cov<-cov+2*V[i,j]*example[j]*example[i]}}
sqrtprop<-sqrt(var+cov)
lower<-sum(example*m12$coefficients)-qnorm(0.975,0,1)*sqrtprop
upper<-sum(example*m12$coefficients)+qnorm(0.975,0,1)*sqrtprop
exp(lower)/(1+exp(lower)); exp(upper)/(1+exp(upper)) #l'intervallo di confidenza per la proporzione
