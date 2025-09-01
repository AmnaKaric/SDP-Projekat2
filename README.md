# Projekat 2 
## Protokol za upravljanje sistemom sportskih terena
Ovaj projekat predstavlja sistem za upravljanje sportskim kompleksom. 
Korisnicima omogućava registraciju, prijavu i rezervaciju termina za različite sportske aktivnosti, 
praćenje stanja na računu i korištenje programa lojalnosti. 

Administratorima pruža mogućnost ažuriranja usluga, cijena i radnog vremena kompleksa, te slanje reklamnih poruka korisnicima. 

Komunikacija između klijenta i servera realizovana je putem vlastitog mrežnog protokola 
(izgrađenog na TCP/TLS konekciji), bez oslanjanja na HTTP, 
sa podrškom za sinhronu i asinhronu razmjenu poruka.

## Instalacija

### 1. Kloniranje repozitorija
```bash
git clone https://github.com/AmnaKaric/SDP-Projekat2
```

### 2. Instalacija zavisnosti
Potrebno je imati instalirano:
- **C++17 kompajler** 
- **Boost.Asio** biblioteka
- **OpenSSL** (za TLS konekciju)
- **MySQL**

Na Ubuntu/Debian sistemu:
```bash
sudo apt update
sudo apt install g++ make cmake libboost-all-dev libssl-dev libmysqlclient-dev
```

### 3. Konfiguracija baze
```bash
URL: jdbc:mysql://100.100.129.70:3306/Sportski_tereni
username: sdp
password: Sdp!12345
```

### 4. Kompajliranje servera i klijenta
```bash
g++ -std=c++17 server.cpp -o server -lssl -lcrypto -lmysqlclient -lpthread
g++ -std=c++17 -O2 client.cpp -o client -lssl -lcrypto -lboost_system -lpthread
```

### 5. Pokretanje
1. Pokrenuti server:
```bash
./server
```
2. Pokrenuti klijent i povezati se na server:
```bash
./client 
```

### 6. Pokretanje testnih skripti
```bash
g++ -std=c++11 test.cpp -o test -lssl -lcrypto -lpthread
./test --catch_system_errors=no
```
