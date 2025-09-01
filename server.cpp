#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <sstream>
#include <nlohmann/json.hpp>
#include "Db.hpp"
#include <set>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <regex>
#include <openssl/sha.h>


using boost::asio::ip::tcp;
namespace ssl = boost::asio::ssl;
using json = nlohmann::json;


static std::string ok() { return std::string("{\"ok\":true}\n"); }
static std::string error_msg(const std::string& e) { return std::string("{\"ok\":false,\"error\":\"") + e + "\"}\n"; }
static std::string ok_with(const nlohmann::json& data) {
    nlohmann::json j; j["ok"] = true; j["data"] = data; return j.dump() + "\n";
}
static std::string err_with(const std::string& msg) {
    nlohmann::json j; j["ok"] = false; j["error"] = msg; return j.dump() + "\n";
}

static bool is_valid_email(const std::string& s) {
    static const std::regex re(
        R"(^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$)",
        std::regex::ECMAScript | std::regex::icase
    );
    return std::regex_match(s, re);
}

static std::string sha256_hex(const std::string& s) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), hash);
    static const char* hex = "0123456789abcdef";
    std::string out; out.resize(64);
    for (int i=0;i<32;i++) { out[2*i]=hex[(hash[i]>>4)&0xF]; out[2*i+1]=hex[hash[i]&0xF]; }
    return out;
}

static int kompleks_to_id(const std::string& k) {
    if (k == "Kompleks_A" || k == "A" || k == "a") return 1;
    if (k == "Kompleks_B" || k == "B" || k == "b") return 2;
    return 0;
}

class AsyncNotifier : public std::enable_shared_from_this<AsyncNotifier> {
public:
    explicit AsyncNotifier(boost::asio::io_context& io, uint16_t port)
        : io_(io), acceptor_(io, tcp::endpoint(tcp::v4(), port)) {}

    void start() { do_accept(); }

void broadcast(const std::string& msg_line) {
    auto self = shared_from_this();
    boost::asio::dispatch(io_, [this, self, msg_line] {
        for (auto it = sessions_.begin(); it != sessions_.end(); ) {
            auto s = *it;

            std::shared_ptr<std::string> out;
            if (s->framed) {
                const std::string& body = msg_line; // može imati '\n', u redu je
                uint32_t n = static_cast<uint32_t>(body.size());
                auto framed = std::make_shared<std::string>();
                framed->resize(4 + n);
                (*framed)[0] = static_cast<char>((n >> 24) & 0xFF);
                (*framed)[1] = static_cast<char>((n >> 16) & 0xFF);
                (*framed)[2] = static_cast<char>((n >> 8)  & 0xFF);
                (*framed)[3] = static_cast<char>((n)       & 0xFF);
                std::memcpy(&(*framed)[4], body.data(), n);
                out = framed;
            } else {
                out = std::make_shared<std::string>(msg_line);
            }

            boost::asio::async_write(s->socket, boost::asio::buffer(*out),
                [this, s](const boost::system::error_code& ec, std::size_t){
                    if (ec) {
                        boost::system::error_code ignored;
                        s->socket.shutdown(tcp::socket::shutdown_both, ignored);
                    }
                });
            ++it;
        }
    });
}

private:
    struct Session : public std::enable_shared_from_this<Session> {
        explicit Session(boost::asio::io_context& io) : socket(io) {}
        tcp::socket socket;
        boost::asio::streambuf buf;
        bool framed = false; // NEW: length-prefixed (4B) data-stream mode
    };

    void do_accept() {
        auto s = std::make_shared<Session>(io_);
        acceptor_.async_accept(s->socket, [this, self=shared_from_this(), s](boost::system::error_code ec){
            if (!ec) {
                do_read_subscribe(s);
            }
            do_accept();
        });
    }

    boost::asio::io_context& io_;
    tcp::acceptor acceptor_;
    std::vector<std::shared_ptr<Session>> sessions_;

void do_read_subscribe(std::shared_ptr<Session> s) {
    auto self = shared_from_this();
    boost::asio::async_read_until(s->socket, s->buf, '\n',
        [this, self, s](boost::system::error_code ec, std::size_t){
            if (ec) return;
            std::istream is(&s->buf); std::string line; std::getline(is, line);
            if (line == "SUBSCRIBE" || line == "SUBSCRIBE\r") {
                sessions_.push_back(s);
                auto hello = std::make_shared<std::string>(std::string("{\"event\":\"hello\"}\n"));
                boost::asio::async_write(s->socket, boost::asio::buffer(*hello),
                    [hello](const boost::system::error_code&, std::size_t){});
                // keep connection open
            } else if (line == "STREAM" || line == "STREAM\r") {
                s->framed = true;
                sessions_.push_back(s);
                // pošalji framed hello
                std::string hello = "{\"event\":\"hello\",\"stream\":\"framed\"}\n";
                uint32_t n = static_cast<uint32_t>(hello.size());
                auto pkt = std::make_shared<std::string>();
                pkt->resize(4 + n);
                (*pkt)[0] = static_cast<char>((n >> 24) & 0xFF);
                (*pkt)[1] = static_cast<char>((n >> 16) & 0xFF);
                (*pkt)[2] = static_cast<char>((n >> 8)  & 0xFF);
                (*pkt)[3] = static_cast<char>((n)       & 0xFF);
                std::memcpy(&(*pkt)[4], hello.data(), n);
                boost::asio::async_write(s->socket, boost::asio::buffer(*pkt),
                    [pkt](const boost::system::error_code&, std::size_t){});
            }
        });
}

};
// --------------- TLS session (blocking, JSON-per-line) ---------------
static void session_tls(std::shared_ptr<ssl::stream<tcp::socket>> ssl_sock,
                        Db& db,
                        const std::shared_ptr<AsyncNotifier>& notifier)
{
    try {
    // --- kontekst po TLS sesiji (važi dok je konekcija otvorena) ---
std::string session_email;     // popunjava se nakon REGISTER/LOGIN
std::string session_kompleks;  // npr. "Kompleks_A" / "Kompleks_B"
std::string logged_role;

        // TLS handshake already done by caller
        boost::asio::streambuf buf;
        for (;;) {
            boost::asio::read_until(*ssl_sock, buf, '\n');
            std::istream is(&buf);
            std::string line; std::getline(is, line);
            if (line.empty()) continue;

            json req = json::parse(line, nullptr, false);
            if (req.is_discarded()) {
                boost::asio::write(*ssl_sock, boost::asio::buffer(error_msg("bad json")));
                continue;
            }

         
            
           
              std::string cmd = req.value("cmd", "");   // obavezno bez const!

            if (cmd == "Check services")                 cmd = "LIST_SERVICES";
            if (cmd == "Reservation" || cmd == "RESERVATION") cmd = "RESERVATION_MENU";
            if (cmd == "Reserve by service")             cmd = "RESERVE_BY_SERVICE_MENU";
            if(cmd == "Check existing matches")  cmd = "CHECK_MATCH";
            if(cmd == "Join match") cmd = "JOIN_MATCH";
            if (cmd == "Reserve by time")                cmd = "RESERVE_BY_TIME_MENU";
            if (cmd == "Reserve by code")                cmd = "RESERVE_BY_CODE"; 
            
            if (cmd == "Balance")                        cmd = "BALANCE_MENU";
            if (cmd == "Check balance")                  cmd = "BALANCE_CHECK";
            if (cmd == "Add balance")                    cmd = "BALANCE_ADD";
            if (cmd == "Delete account")                 cmd = "DELETE_ACCOUNT";
            if (cmd == "Check the working hours")        cmd = "GET_HOURS";
            if (cmd == "Cancel reservation")             cmd = "CANCEL";
            if (cmd == "Log off" || cmd == "Logout")    cmd = "LOGOFF";
            if (cmd == "Send promo")                cmd = "SEND_PROMO";
            if (cmd == "Need player alert")         cmd = "ALERT_NEED_PLAYER";

            
            if(cmd != "LOGOFF" && cmd != "REGISTER" && cmd !="LOGIN"){
              if (session_email.empty()) {
                boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Niste prijavljeni...")));
                continue;
              }
            }

            if (cmd == "CHECK_EMAIL") {
                bool ex = db.email_exists(req.value("email",""));
                boost::asio::write(*ssl_sock, boost::asio::buffer(ok_with(json{{"exists", ex}})));
            }
            else if (cmd == "CHECK_URI") {
                bool ex = db.uri_exists(req.value("uri",""));
                boost::asio::write(*ssl_sock, boost::asio::buffer(ok_with(json{{"exists", ex}})));
            }
            
            
            // ----------------------------REGISTER------------------------OKEJ
            else if (cmd == "REGISTER") {
                std::string email    = req.value("email", "");
                std::string pass     = req.value("password", "");
                std::string ime      = req.value("ime", "");
                std::string lokacija = req.value("lokacija", "");
               if (pass.size() < 8) {
               boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Password mora imati 8 znakova!")));
               continue;
              }
              
              if (!is_valid_email(email)) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Neispravan e-mail format!")));
        continue;
    }
    
                // 1) Does email already exist?
                std::string check = "SELECT id FROM Korisnici WHERE e_mail='" + email + "' LIMIT 1;";
                if (mysql_query(db.conn, check.c_str()) == 0) {
                    MYSQL_RES* res = mysql_store_result(db.conn);
                    if (res) {
                        if (mysql_num_rows(res) > 0) {
                            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Odabrani e-mail već postoji!")));
                            mysql_free_result(res);
                            continue;
                        }
                        mysql_free_result(res);
                    }
                }
                
                std::string pass_h = sha256_hex(pass);
                // 2) Insert user
                std::string q =
                    "INSERT INTO Korisnici (e_mail, sifra, lokacija) "
                    "VALUES ('" + email + "', '" + pass_h + "', '" + lokacija + "');";
                if (mysql_query(db.conn, q.c_str()) == 0) {
                bool isAdmin = (email == "admin@gmail.com" || email == "admin@admin.com");
    logged_role  = isAdmin ? "admin" : "user";
                json resp;
        resp["ok"]   = true;
        resp["role"] = logged_role;
        resp["msg"]  = "Uspješno ste registrovani!";
        
        boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));
                    //boost::asio::write(*ssl_sock, boost::asio::buffer(ok_with(json{{"msg","User registered"}})));
                    session_email = email;
                    session_kompleks = lokacija;
                } else {
                    boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
                }
            }


// ----------------- LOGIN ----------------- OKEJ
// ----------------- LOGIN -----------------
if (cmd == "LOGIN") {
    std::string email = req.value("email", "");
    std::string pass  = req.value("password", "");

    std::string pass_h = sha256_hex(pass);
    // 1) provjera kredencijala u bazi
    bool okCreds = false;
    {
        std::string q = "SELECT id FROM Korisnici WHERE e_mail='" + email +
                        "' AND sifra='" + pass_h + "' LIMIT 1;";
        if (mysql_query(db.conn, q.c_str()) == 0) {
            if (MYSQL_RES* r = mysql_store_result(db.conn)) {
                okCreds = (mysql_num_rows(r) > 0);
                mysql_free_result(r);
            }
        } else {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
            continue;
        }
    }

    if (!okCreds) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(error_msg("Neispravni kredencijali")));
        continue;
    }

    // 2) session cache: email + povuci lokaciju iz baze
    session_email = email;
    {
        std::string q2 = "SELECT lokacija FROM Korisnici WHERE e_mail='" + email + "' LIMIT 1;";
        if (mysql_query(db.conn, q2.c_str()) == 0) {
            if (MYSQL_RES* r2 = mysql_store_result(db.conn)) {
                if (MYSQL_ROW row = mysql_fetch_row(r2)) {
                    if (row[0]) session_kompleks = row[0]; // npr. "Kompleks_A"
                }
                mysql_free_result(r2);
            }
        }
    }

    // 3) uloga
    bool isAdmin = (email == "admin@gmail.com" || email == "admin@admin.com");
    logged_role  = isAdmin ? "admin" : "user";

    // 4) odgovor
    if (isAdmin) {
        json resp;
        resp["ok"]   = true;
        resp["role"] = "admin";
        resp["msg"]  = "Prijava kao administrator!";
        resp["description"] =
            "Ova opcija je moguća samo za određene kredencijale sa administratorskim pravima."
            "Nakon prijave, administrator ima tri moguće opcije:\n"
            "• Ažuriranje cjenovnika usluga\n"
            "• Ažuriranje radnog vremena\n"
            "• Ažuriranje kapaciteta svake od usluga";
        resp["options"] = json::array({
            "UPDATE_PRICES",
            "UPDATE_HOURS",
            "UPDATE_CAPACITY"
        });
        boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));
    } else {
        json resp;
        resp["ok"]   = true;
        resp["role"] = "user";
        resp["msg"]  = "Uspješna prijava!";
        resp["options"] = json::array({
            "Check services",
            "Reservation",
            "Check loyalty system",
            "Delete account",
            "Check the working hours",
            "Balance",
            "Cancel reservation",
            "Log off"
        });
        boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));
    }
}

else if (cmd == "DELETE_ACCOUNT") {
    // mora biti ulogovan
    if (session_email.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Niste prijavljeni...")));
        continue;
    }

    // 1) user id
    int uid = db.get_user_id_by_email(session_email);
    if (uid <= 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Korisnik nije pronađen.")));
        continue;
    }

    // 2) provjera aktivnih rezervacija
    //    (status NULL, 'CONFIRMED' ili 'PENDING' smatramo aktivnim)
    long long active_cnt = 0;
    {
        std::ostringstream q;
q << "SELECT COUNT(*) "
  << "FROM Rezervacije r "
  << "JOIN Termini t ON t.id = r.termin_id "   // ili r.id_termina, zavisi od tvog FK naziva
  << "WHERE r.korisnik_id=" << uid << " "
  << "AND (t.datum > CURDATE() "
  << "     OR (t.datum = CURDATE() AND t.vrijeme >= CURTIME()));";


        if (mysql_query(db.conn, q.str().c_str()) != 0) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
            continue;
        }
        if (MYSQL_RES* r = mysql_store_result(db.conn)) {
            if (MYSQL_ROW row = mysql_fetch_row(r)) {
                if (row[0]) active_cnt = std::atoll(row[0]);
            }
            mysql_free_result(r);
        }
    }

    if (active_cnt > 0) {
        // upozorenje ako ima rezervacije
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Imate aktivne rezervacije.")));
        continue;
    }

    
    {
        std::ostringstream qdelr;
        qdelr << "DELETE FROM Korisnici WHERE id=" << uid << ";";
        if (mysql_query(db.conn, qdelr.str().c_str()) != 0) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
            continue;
        }
        
        if (mysql_affected_rows(db.conn) == 0) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Brisanje neuspješno.")));
            continue;
        }
    }

    // 4) očisti sesiju
    session_email.clear();
    session_kompleks.clear();
    logged_role.clear();

    // 5) odgovor + (opciono) notifikacija
    json resp;
    resp["ok"] = true;
    resp["data"] = {
        {"msg", "Vaš račun je uspješno obrisan."}
    };
    boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));
}
else if (cmd == "LOGOFF") {
    if (session_email.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Niste prijavljeni...")));
        continue;
    }

    // očisti sesijski kontekst
    session_email.clear();
    session_kompleks.clear();
    logged_role.clear();

    json resp;
    resp["ok"] = true;
    resp["data"] = { {"msg", "Uspješno ste odjavljeni!"} };
    boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));
}
// ----------------- ADMIN: UPDATE_HOURS -----------------OKEJ
else if (cmd == "UPDATE_HOURS") {
    if (logged_role != "admin") {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Zabranjeno! Dostupno samo za administratora.")));
        continue;
    }

    std::string location = req.value("location", req.value("lokacija", ""));
    std::string from     = req.value("from",     req.value("od", ""));
    std::string to       = req.value("to",       req.value("do", ""));

    if (location.empty() || from.empty() || to.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Neispravan unos!")));
        continue;
    }

    // UPDATE nad tabelom Kompleksi, po koloni 'lokacija'
    std::ostringstream q;
    q << "UPDATE Kompleksi "
      << "SET radno_od='" << from << "', radno_do='" << to << "' "
      << "WHERE lokacija='" << location << "';";

    if (mysql_query(db.conn, q.str().c_str()) != 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
        continue;
    }

    json resp;
    resp["ok"] = true;
    resp["msg"] = "Radno vrijeme uspješno ažurirano!";
    resp["data"] = {
        {"location", location},
        {"from", from},
        {"to", to}
    };
    boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));
    if (notifier) notifier->broadcast(std::string("{\"event\":\"update\",\"type\":\"hours\"}\n"));
}


// ----------------- ADMIN: UPDATE_CAPACITY -----------------OKEJ
else if (cmd == "UPDATE_CAPACITY") {
    if (logged_role != "admin") {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Zabranjeno! Dostupno samo za administratora.")));
        continue;
    }

    std::string kompleks = req.value("kompleks", "");   // npr. "A" (Kompleksi.lokacija)
    std::string usluga   = req.value("usluga",   "");   // npr. "Fudbal"
    int novi_kapacitet   = req.value("novi_kapacitet", 0);

    if (kompleks.empty() || usluga.empty() || novi_kapacitet <= 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Neispravan unos!")));
        continue;
    }

    // 1) Dohvati id kompleksa prema lokaciji
    std::string qk = "SELECT id FROM Kompleksi WHERE lokacija='" + kompleks + "' LIMIT 1;";
    if (mysql_query(db.conn, qk.c_str()) != 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
        continue;
    }
    MYSQL_RES* rk = mysql_store_result(db.conn);
    if (!rk) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Neuspjelo spašavanje podataka.")));
        continue;
    }
    MYSQL_ROW rowk = mysql_fetch_row(rk);
    if (!rowk) {
        mysql_free_result(rk);
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Lokacija nije pronađena.")));
        continue;
    }
    std::string id_kompleksa = rowk[0] ? rowk[0] : "";
    mysql_free_result(rk);

    // 2) UPDATE nad Usluge po id_kompleksa + naziv
    std::ostringstream q;
q << "UPDATE Usluge "
   << "SET kapacitet=" << novi_kapacitet
   << " WHERE id_kompleksa=(SELECT id FROM Kompleksi WHERE TRIM(lokacija)='" 
   << kompleks << "') "
   << "AND TRIM(naziv)='" << usluga << "';";


    if (mysql_query(db.conn, q.str().c_str()) != 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
        continue;
    }

    // 3) Provjeri da li je išta ažurirano
    my_ulonglong changed = mysql_affected_rows(db.conn);
    if (changed == 0) {
        // Najčešći razlozi: naziv ne odgovara tačno, ili već ista vrijednost
        json resp{
            {"ok", false},
            {"error", "no_rows_updated"},
            {"hint", "Provjeri da li postoji usluga sa ovim nazivom u tom kompleksu i da li je nova vrijednost različita od stare."},
            {"kompleks", kompleks},
            {"usluga", usluga},
            {"pokusani_kapacitet", novi_kapacitet}
        };
        boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));
        continue;
    }

    // 4) Uspjeh
    json resp;
    resp["ok"] = true;
    resp["msg"] = "Kapacitet je uspješno ažuriran!"; 
    resp["data"] = {
        {"kompleks", kompleks},
        {"usluga", usluga},
        {"novi_kapacitet", novi_kapacitet},
        {"rows_affected", (uint64_t)changed}
    };
    boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));
    if (notifier) notifier->broadcast(std::string("{\"event\":\"update\",\"type\":\"capacity\"}\n"));
}



// ----------------- ADMIN: UPDATE_PRICES -----------------OKEJ
else if (cmd == "UPDATE_PRICES") {
    if (logged_role != "admin") {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Zabranjeno! Dostupno samo za administratora.")));
        continue;
    }

    std::string lok    = req.value("lokacija", req.value("location",""));  // "A"/"B"
    std::string usluga = req.value("usluga",   req.value("service",""));   // npr "Fudbal"
    double nova_cijena = req.value("nova_cijena", req.value("new_price", 0.0));
    if (lok.empty() || usluga.empty() || nova_cijena <= 0.0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Neispravan unos.")));
        continue;
    }

    std::string idk = "0";
    if(lok == "A") idk = "1";
    else if(lok == "B") idk = "2";
    else {
      boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Nepostojeća lokacija!")));
      continue;
    }
  
    std::ostringstream q;
    q << "UPDATE Usluge SET cijena_pojedinacnog_termina=" << nova_cijena
      << " WHERE id_kompleksa=" << idk << " AND naziv='" << usluga << "';";
    if (mysql_query(db.conn, q.str().c_str()) == 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(ok_with(json{
            {"msg","Cijena uspješno ažurirana"},
            {"location", lok},
            {"service", usluga},
            {"new_price", nova_cijena}
        })));
        
        if (notifier) notifier->broadcast(std::string("Obavijest: upravo je promijenjena cijena usluge " + usluga + " u Kompleksu " + lok + " na " + std::to_string(nova_cijena) + "KM\n"));
    } else {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
    }
}

else if (cmd == "SEND_PROMO") {
    // samo admin smije
    if (logged_role != "admin") {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(logged_role)));
        continue;
    }
    std::string text = req.value("message", "");
    if (text.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Neispravan unos.")));
        continue;
    }

    json evt{
        {"event", "promo"},
        {"text",  text}
    };
    if (notifier) notifier->broadcast(evt.dump() + "\n");

    boost::asio::write(*ssl_sock, boost::asio::buffer(ok_with(json{
        {"msg","promo_sent"}
    })));
}


else if (cmd == "ALERT_NEED_PLAYER") {
    // 1) mora biti ulogovan
    if (session_email.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Niste prijavljeni...")));
        continue;
    }

    // --- robustno parsiranje code kao INT (podržava i broj i string) ---
    int term_id = 0;
    if (req.contains("code")) {
        try {
            if (req["code"].is_number_integer()) {
                term_id = req["code"].get<int>();
            } else if (req["code"].is_string()) {
                std::string s = req["code"].get<std::string>();
                if (!s.empty()) term_id = std::stoi(s);
            }
        } catch (...) { term_id = 0; }
    }
    if (term_id <= 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Nedostaje šifra!")));
        continue;
    }

    // Pošiljalac mora biti učesnik (u grupi) tog termina
    int uid = db.get_user_id_by_email(session_email);
    if (uid <= 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Korisnik nije pronađen.")));
        continue;
    }
    {
        std::ostringstream q;
        q << "SELECT 1 FROM Rezervacije "
             "WHERE termin_id=" << term_id << " AND korisnik_id=" << uid << " LIMIT 1;";
        if (mysql_query(db.conn, q.str().c_str()) != 0) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
            continue;
        }
        bool in_group = false;
        if (MYSQL_RES* r = mysql_store_result(db.conn)) {
            in_group = mysql_num_rows(r) > 0;
            mysql_free_result(r);
        }
        if (!in_group) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Niste u grupi termina.")));
            continue;
        }
    }

    // Termin mora biti u budućnosti
    long long mins_left = 0;
    {
        std::ostringstream q;
        q << "SELECT TIMESTAMPDIFF(MINUTE, NOW(), "
             "STR_TO_DATE(CONCAT(datum,' ',vrijeme), '%Y-%m-%d %H:%i:%s')) "
             "FROM Termini WHERE id=" << term_id << " LIMIT 1;";
        if (mysql_query(db.conn, q.str().c_str()) != 0) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
            continue;
        }
        if (MYSQL_RES* r = mysql_store_result(db.conn)) {
            if (MYSQL_ROW row = mysql_fetch_row(r)) {
                if (row[0]) mins_left = std::atoll(row[0]);
            }
            mysql_free_result(r);
        }
    }
    if (mins_left <= 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Termin je u toku ili već završen..")));
        continue;
    }

    // Kapacitet/popunjenost + opis termina
    int capacity = 0, filled = 0;
    std::string when_str, usluga, lok;
    {
        std::ostringstream q;
        q <<
        "SELECT u.kapacitet, "
        " (SELECT COUNT(*) FROM Rezervacije r WHERE r.termin_id=t.id) AS filled, "
        " CONCAT(t.datum,' ',t.vrijeme) AS when_str, "
        " t.tip_usluge, k.lokacija "
        "FROM Termini t "
        "JOIN Kompleksi k ON k.id=t.id_kompleksa "
        "JOIN Usluge u ON u.id_kompleksa=t.id_kompleksa AND u.naziv=t.tip_usluge "
        "WHERE t.id=" << term_id << " LIMIT 1;";
        if (mysql_query(db.conn, q.str().c_str()) != 0) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
            continue;
        }
        if (MYSQL_RES* r = mysql_store_result(db.conn)) {
            if (MYSQL_ROW row = mysql_fetch_row(r)) {
                capacity = row[0] ? std::atoi(row[0]) : 0;
                filled   = row[1] ? std::atoi(row[1]) : 0;
                when_str = row[2] ? row[2] : "";
                usluga   = row[3] ? row[3] : "";
                lok      = row[4] ? row[4] : "";
            }
            mysql_free_result(r);
        }
    }

    int missing = std::max(0, capacity - filled);
    if (missing <= 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Nema slobodnog mjesta.")));
        continue;
    }

    // multicast “need_player”
    json evt{
        {"event",        "need_player"},
        {"termin_id",    term_id},
        {"missing",      missing},
        {"when",         when_str},
        {"service",      usluga},
        {"location",     lok},
        {"requested_by", session_email}
    };
    if (notifier) notifier->broadcast(evt.dump() + "\n");

    boost::asio::write(*ssl_sock, boost::asio::buffer(ok_with(json{
        {"msg","Notifikacija poslana!"},
        {"missing",missing}
    })));
}

else if (cmd == "LIST_SERVICES") {
    // 1) pokušaj uzeti lokaciju iz zahtjeva (ako je korisnik ipak pošalje)
    std::string lokacija = req.value("lokacija", "");

    // 2) ako nije poslana, koristi sesijsku
    if (lokacija.empty() && !session_kompleks.empty()) {
        lokacija = session_kompleks;
    }

    // 3) ako i dalje prazno, a znamo ko je ulogovan → povuci iz baze
    if (lokacija.empty() && !session_email.empty()) {
        std::string q2 = "SELECT lokacija FROM Korisnici WHERE e_mail='" + session_email + "' LIMIT 1;";
        if (mysql_query(db.conn, q2.c_str()) == 0) {
            if (MYSQL_RES* r2 = mysql_store_result(db.conn)) {
                if (MYSQL_ROW row = mysql_fetch_row(r2)) {
                    if (row[0]) lokacija = row[0];
                }
                mysql_free_result(r2);
            }
        }
        if (!lokacija.empty()) session_kompleks = lokacija; // osvježi sesiju
    }

    // 4) ako još uvijek nemamo lokaciju → nema konteksta
    if (lokacija.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Nedostaje lokacija!")));

        continue;
    }

    // 5) query prema Usluge: koristi id_kompleksa i ispravne nazive kolona
int kid = kompleks_to_id(lokacija);
if (kid == 0) {
    boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Nepostojeći kompleks.")));
    continue;
}

std::string q =
    "SELECT id_usluge, naziv, trajanje_pojedinacnog_termina, cijena_pojedinacnog_termina, kapacitet "
    "FROM Usluge WHERE id_kompleksa=" + std::to_string(kid) + " ORDER BY naziv ASC;";

json arr = json::array();
if (mysql_query(db.conn, q.c_str()) == 0) {
    if (MYSQL_RES* r = mysql_store_result(db.conn)) {
        MYSQL_ROW row;
        while ((row = mysql_fetch_row(r))) {
            json one;
            // redoslijed: id_usluge, naziv, trajanje_pojedinacnog_termina, cijena_pojedinacnog_termina
            one["id"]       = row[0] ? std::atoi(row[0]) : 0;
            one["naziv"]    = row[1] ? row[1] : "";
            one["trajanje"] = row[2] ? std::atof(row[2]) : 0.0;
            one["cijena"]   = row[3] ? std::atof(row[3]) : 0.0;
            one["kapacitet"] = row[4] ? std::atoi(row[4]) : 0;
            arr.push_back(one);
        }
        mysql_free_result(r);
    }
    json resp;
    resp["ok"]       = true;
    resp["kompleks"] = lokacija;
    resp["services"] = arr;
    boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));
} else {
    boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
}

}
         
else if (cmd == "RESERVE") {
    if (session_email.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Niste prijavljeni...")));
        continue;
    }
    std::string time = req.value("time", "");
    std::string usluga = req.value("usluga", "");
    std::string date = req.value("date", "");
    if(time.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(error_msg("Nedostaje vrijeme!")));
        continue;
    }
    if (usluga.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(error_msg("Nedostaje usluga!")));
        continue;
    }
    if (date.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(error_msg("Nedostaje datum!")));
        continue;
    }

    std::string reason;
    double final_price = 0.0;
    bool loyalty_applied = false;

    int kid = 0;
    if      (session_kompleks == "Kompleks_A" || session_kompleks == "A" || session_kompleks == "a") kid = 1;
    else if (session_kompleks == "Kompleks_B" || session_kompleks == "B" || session_kompleks == "b") kid = 2;
    
    bool okr = db.reserve_slot_multi(session_email, time, date, usluga, kid, reason);
    if (okr) {
        json resp;
        resp["ok"]                = true;
        resp["msg"]               = "reservation_confirmed";
        resp["sifra"]             = "test";
        resp["loyalty_applied"]   = loyalty_applied;
        resp["cijena_obracunata"] = final_price;
        boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));

        if (notifier) {
            std::string msg = std::string("{\"event\":\"update\",\"type\":\"reserve\",\"sifra\":\"") + "test" + "\"}\n";
            notifier->broadcast(msg);
        }
    } else {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(reason)));
    }
}


// NOVO DODANO ZA REZERVACIJU
    else if (cmd == "RESERVATION_MENU") {
    // zahtijeva login jer koristimo session kontekst
    if (session_email.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Niste prijavljeni...")));
        continue;
    }

    json resp;
    resp["ok"]    = true;
    resp["menu"]  = "reservation";
    resp["msg"]   = "Odaberi način rezervacije";
    resp["options"] = json::array({
        "Reserve by service",
        "Reserve by time",
        "Check existing matches",
    });
    boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));
}

else if (cmd == "LOYALTY_POINTS") {
    // provjera sesije — prilagodi ako koristiš drugi mehanizam
    int uid = db.get_user_id_by_email(session_email);
    if (uid <= 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(error_msg("Niste prijavljeni..")));
        continue;
    }

    // 1) započni transakciju (FOR UPDATE traži transakciju u InnoDB)
    if (mysql_query(db.conn, "START TRANSACTION") != 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(error_msg(mysql_error(db.conn))));
        continue;
    }

    // 2) dohvat svih “lotova” bodova koji važe i još nisu potpuno potrošeni
    std::string qLots =
        "SELECT id, iznos, iskoristeni_iznos "
        "FROM BonusPoeni "
        "WHERE korisnik_id = " + std::to_string(uid) + " "
        "  AND datum_isteka > NOW() "
        "  AND iskoristeni_iznos < iznos "
        "ORDER BY datum_isteka ASC, id ASC "
        "FOR UPDATE;";

    if (mysql_query(db.conn, qLots.c_str()) != 0) {
        mysql_query(db.conn, "ROLLBACK");
        boost::asio::write(*ssl_sock, boost::asio::buffer(error_msg(mysql_error(db.conn))));
        continue;
    }

    MYSQL_RES* res = mysql_store_result(db.conn);
    if (!res) {
        mysql_query(db.conn, "ROLLBACK");
        boost::asio::write(*ssl_sock, boost::asio::buffer(error_msg(mysql_error(db.conn))));
        continue;
    }

    unsigned long long total_points = 0;
    // (opc.) unsigned long long lots_count = 0;

    for (MYSQL_ROW row; (row = mysql_fetch_row(res)); ) {
        // kolone: 0=id, 1=qty, 2=consumed_qty
        unsigned long long qty      = row[1] ? std::strtoull(row[1], nullptr, 10) : 0ULL;
        unsigned long long consumed = row[2] ? std::strtoull(row[2], nullptr, 10) : 0ULL;
        if (qty > consumed) {
            total_points += (qty - consumed);
            // (opc.) ++lots_count;
        }
    }
    mysql_free_result(res);

    // 3) commit
    if (mysql_query(db.conn, "COMMIT") != 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(error_msg(mysql_error(db.conn))));
        continue;
    }

    // 4) vrati rezultat — "count" je ukupan broj dostupnih bodova
    boost::asio::write(
        *ssl_sock,
        boost::asio::buffer(ok_with(nlohmann::json{
            {"count", total_points}
            // ako ti zatreba broj lotova: ,{"lots", lots_count}
        }))
    );
}


else if (cmd == "GET_HOURS") {
    // opcionalno: samo ulogovani mogu vidjeti
    // if (session_email.empty()) { boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Niste prijavljeni..."))); continue; }

    // Može doći kao "kompleks" (A/B), ili "lokacija" (Kompleks_A / Kompleks_B).
    std::string lok = req.value("kompleks", req.value("lokacija", ""));
    if (lok.empty() && !session_kompleks.empty()) lok = session_kompleks;

    std::string q;
    bool single = false;
    if (!lok.empty()) {
        // podrži i kratku i punu formu (A / Kompleks_A)
        if (lok == "A" || lok == "a") lok = "A";
        if (lok == "B" || lok == "b") lok = "B";
        q = "SELECT lokacija, radno_od, radno_do FROM Kompleksi WHERE lokacija='" + lok + "' LIMIT 1;";
        single = true;
    } else {
        q = "SELECT lokacija, radno_od, radno_do FROM Kompleksi ORDER BY lokacija ASC;";
    }

    if (mysql_query(db.conn, q.c_str()) != 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
        continue;
    }

    json hours = json::array();
    if (MYSQL_RES* r = mysql_store_result(db.conn)) {
        MYSQL_ROW row;
        while ((row = mysql_fetch_row(r))) {
            std::string lokacija = row[0] ? row[0] : "";
            std::string od       = row[1] ? row[1] : "";
            std::string d0       = row[2] ? row[2] : "";

            json item;
            item["lokacija"] = lokacija;   // npr. "Kompleks_A"
            item["from"]     = od;         // npr. "08:00:00"
            item["to"]       = d0;         // npr. "22:00:00"
            hours.push_back(item);
        }
        mysql_free_result(r);
    }

    if (single && hours.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Lokacija nije pronađena.")));
        continue;
    }

    json resp;
    resp["ok"] = true;
    resp["data"] = {
        {"msg", "Radno vrijeme kompleksa."},
        {"hours", hours}
    };
    boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));
}

else if (cmd == "RESERVE_BY_SERVICE_MENU") {
    if (session_email.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Niste prijavljeni...")));
        continue;
    }

    // mapiranje kompleksa → id (isti mapping kao u LIST_SERVICES)
    int kid = 0;
    if      (session_kompleks == "Kompleks_A" || session_kompleks == "A" || session_kompleks == "a") kid = 1;
    else if (session_kompleks == "Kompleks_B" || session_kompleks == "B" || session_kompleks == "b") kid = 2;
    if (kid == 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Nepostojeći kompleks.")));
        continue;
    }

    // dohvat distinct naziva usluga
    std::vector<std::string> services;
    std::string q =
        "SELECT naziv FROM Usluge WHERE id_kompleksa=" + std::to_string(kid) +
        " GROUP BY naziv ORDER BY naziv ASC;";
    if (mysql_query(db.conn, q.c_str()) == 0) {
        if (MYSQL_RES* r = mysql_store_result(db.conn)) {
            MYSQL_ROW row;
            while ((row = mysql_fetch_row(r))) if (row[0]) services.emplace_back(row[0]);
            mysql_free_result(r);
        }
    } else {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
        continue;
    }

    json resp;
    resp["ok"]      = true;
    resp["menu"]    = "reserve_by_service";
    resp["msg"]     = "Odaberi uslugu";
    resp["options"] = json::array();
    for (auto& s : services) resp["options"].push_back(s);  // npr. "Fudbal","Košarka",...
    resp["next"]    = "SELECT_SERVICE"; // sljedeći korak

    boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));
}


else if (cmd == "JOIN_MATCH") {
    if (session_email.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Niste prijavljeni...")));
        continue;
    }

    int termin_id = 0;
    if (req.contains("code")) {
        try {
            if (req["code"].is_number_integer()) {
                termin_id = req["code"].get<int>();
            } else if (req["code"].is_string()) {
                std::string s = req["code"].get<std::string>();
                termin_id = s.empty() ? 0 : std::stoi(s);
            }
        } catch (...) {
            termin_id = 0;
        }
    }
    if (termin_id <= 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(error_msg("Nedostaje šifra!")));
        continue;
    }

    int user_id = db.get_user_id_by_email(session_email);
    if (user_id <= 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Korisnik nije pronađen.")));
        continue;
    }

    // 0) već u grupi?
    {
        std::ostringstream q;
        q << "SELECT 1 FROM Rezervacije WHERE termin_id=" << termin_id
          << " AND korisnik_id=" << user_id << " LIMIT 1;";
        if (mysql_query(db.conn, q.str().c_str()) != 0) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
            continue;
        }
        if (MYSQL_RES* r = mysql_store_result(db.conn)) {
            bool already = mysql_num_rows(r) > 0;
            mysql_free_result(r);
            if (already) {
                boost::asio::write(*ssl_sock, boost::asio::buffer(error_msg("Već imate aktivnu rezervaciju u ovom terminu.")));
                continue;
            }
        }
    }

    // 1) ATOMSKI claim mjesta (FIFO: prvi INSERT koji prođe)
    {
        
        std::ostringstream ins;
ins <<
"INSERT INTO Rezervacije(termin_id, korisnik_id) "
"SELECT " << termin_id << ", " << user_id << " "
"FROM DUAL WHERE "
" (SELECT COUNT(*) FROM Rezervacije r WHERE r.termin_id=" << termin_id << ") "
" < (SELECT u.kapacitet FROM Usluge u "
"    JOIN Termini t ON t.id_kompleksa=u.id_kompleksa AND u.naziv=t.tip_usluge "
"    WHERE t.id=" << termin_id << ");";


        if (mysql_query(db.conn, ins.str().c_str()) != 0) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
            continue;
        }
        if (mysql_affected_rows(db.conn) == 0) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Termin je popunjen!")));
            continue;
        }
    }

    // 2) nova popunjenost
    int capacity = 0, filled = 0;
    {
        std::ostringstream q;
        q <<
        "SELECT "
        " (SELECT COUNT(*) FROM Rezervacije r WHERE r.termin_id=t.id) AS filled, "
        " u.kapacitet "
        "FROM Termini t "
        "JOIN Usluge u ON u.id_kompleksa=t.id_kompleksa AND u.naziv=t.tip_usluge "
        "WHERE t.id=" << termin_id << " LIMIT 1;";
        if (mysql_query(db.conn, q.str().c_str()) != 0) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
            continue;
        }
        if (MYSQL_RES* r = mysql_store_result(db.conn)) {
            if (MYSQL_ROW row = mysql_fetch_row(r)) {
                filled   = row[0] ? std::atoi(row[0]) : 0;
                capacity = row[1] ? std::atoi(row[1]) : 0;
            }
            mysql_free_result(r);
        }
    }

    // 3) odgovor klijentu
    {
        json resp;
        resp["ok"]     = true;
        resp["msg"]    = "Uspješno ste se pridružili terminu!";
        resp["filled"] = filled;
        resp["max"]    = capacity;
        boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));
    }

    // 4) real-time event (izoluj od izuzetaka)
    if (notifier) {
        try {
            json evt{
                {"event","spot_filled"},
                {"termin_id", termin_id},
                {"filled", filled},
                {"max", capacity},
                {"user", session_email}
            };
            notifier->broadcast(evt.dump() + "\n");
        } catch (...) {
            // nemoj rušiti TLS sesiju zbog broadcast-a
        }
    }
}


// -- BALANCE MENI --

else if (cmd == "BALANCE_MENU") {
    if (session_email.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Niste prijavljeni...")));
        continue;
    }
    json resp;
    resp["ok"]      = true;
    resp["menu"]    = "balance";
    resp["options"] = json::array({ "Check balance", "Add balance" });
    boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));
}


else if (cmd == "BALANCE_CHECK") {
    // korisnik mora biti ulogovan
    if (session_email.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Niste prijavljeni...")));
        continue;
    }

    // povuci balance iz Korisnici
    double stanje_na_racunu = 0.0;
    bool ok_found = false;

    {
        std::string q =
            "SELECT stanje_na_racunu FROM Korisnici WHERE e_mail='" + session_email + "' LIMIT 1;";

        if (mysql_query(db.conn, q.c_str()) != 0) {
            // ako nema kolone ili drugi SQL problem
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
            continue;
        }

        if (MYSQL_RES* r = mysql_store_result(db.conn)) {
            if (MYSQL_ROW row = mysql_fetch_row(r)) {
                if (row[0]) {
                    stanje_na_racunu = std::atof(row[0]);
                    ok_found = true;
                }
            }
            mysql_free_result(r);
        }
    }

    if (!ok_found) {
        // korisnik ne postoji ili nema postavljen balance
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Nemate dovoljno sredstava na računu!")));
        continue;
    }

    // po želji dodaj valutu ako je fiksna (npr. BAM)
    json resp;
    resp["ok"] = true;
    resp["data"] = {
        {"msg", "Current balance"},
        {"currency", "BAM"},
        {"balance", stanje_na_racunu}
    };
    boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + std::string("\n")));
}


else if (cmd == "BALANCE_ADD") {
    if (session_email.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Niste prijavljeni...")));
        continue;
    }

    // očekujemo {"cmd":"Add balance","amount": 20.0}
    double amount = 0.0;
    if (req.contains("amount")) {
        amount = req.value("amount", 0.0);
    }
    if (amount <= 0.0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Neispravan unos!")));
        continue;
    }
    // zaštita od slučajne pogrešne uplate (npr. 1e9)
    if (amount > 10000.0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Unos prevelik!")));
        continue;
    }

    // 1) UPDATE
    {
        std::ostringstream q;
        q << "UPDATE Korisnici "
          << "SET stanje_na_racunu = COALESCE(stanje_na_racunu,0) + "
          << std::fixed << std::setprecision(2) << amount
          << " WHERE e_mail='" << session_email << "';";
        if (mysql_query(db.conn, q.str().c_str()) != 0) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
            continue;
        }
        // provjera da li je iko ažuriran
        if (mysql_affected_rows(db.conn) == 0) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Neuspjelo ažuriranje!")));
            continue;
        }
    }

    // 2) SELECT novo stanje
    double novo_stanje = 0.0;
    {
        std::string q =
            "SELECT COALESCE(stanje_na_racunu, 0) "
            "FROM Korisnici WHERE e_mail='" + session_email + "' LIMIT 1;";

        if (mysql_query(db.conn, q.c_str()) != 0) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
            continue;
        }
        if (MYSQL_RES* r = mysql_store_result(db.conn)) {
            if (MYSQL_ROW row = mysql_fetch_row(r)) {
                if (row[0]) novo_stanje = std::atof(row[0]);
            }
            mysql_free_result(r);
        }
    }

    json resp;
    resp["ok"] = true;
    resp["data"] = {
        {"msg", "Ažurirano stanje na računu!"},
        {"currency", "BAM"},
        {"added", amount},
        {"total balance", novo_stanje}
    };
    boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));
}
else if (cmd == "CHECK_MATCH") {
  if (session_email.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Niste prijavljeni...")));
        continue;
    }
    std::string usluga    = req.value("usluga", "");
    std::string date = req.value("date", "");
    
    if (usluga.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(error_msg("Nedostaje usluga!")));
        continue;
    }
    if (date.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(error_msg("Nedostaje datum!")));
        continue;
    }
    int kid = 0;
    if      (session_kompleks == "Kompleks_A" || session_kompleks == "A" || session_kompleks == "a") kid = 1;
    else if (session_kompleks == "Kompleks_B" || session_kompleks == "B" || session_kompleks == "b") kid = 2;
    
    std::string terminiUpit =
    "SELECT t.id, t.vrijeme, k.lokacija, u.kapacitet, "
    "       (SELECT COUNT(*) FROM Rezervacije r WHERE r.termin_id = t.id) AS filled_slots "
    "FROM Termini t "
    "JOIN Kompleksi k ON t.id_kompleksa = k.id "
    "JOIN Usluge u ON u.id_kompleksa = k.id "
    "WHERE u.naziv = '" + usluga + "' "
    "AND t.datum = '" + date + "';";


    json uslugaRez = json::array();
    if (mysql_query(db.conn, terminiUpit.c_str()) != 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
        continue;
    }
    if (MYSQL_RES* r = mysql_store_result(db.conn)) {
        MYSQL_ROW row;
        while ((row = mysql_fetch_row(r))) {
            int id = std::atoi(row[0]);
            std::string time   = row[1] ? row[1] : "";
            std::string location   = row[2] ? row[2] : "";
            std::string capacity = row[3] ? row[3] : "";
            std::string filled = row[4] ? row[4] : "";

            json s;
            s["code"] = id;
            s["time"]      = time;
            s["location"]    = location;
            s["capacity"] = filled + "/" + capacity;
            uslugaRez.push_back(s);
        }
        mysql_free_result(r);
    }
    json resp;
    resp["Sessions"] = uslugaRez;
    resp["next"]    = "JOIN_MATCH"; // sledeći korak: {"cmd":"RESERVE","sifra":"..."}
    boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));
}

else if (cmd == "LIST_MY_SESSIONS") {
int uid = db.get_user_id_by_email(session_email);
    if (uid <= 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(error_msg("Niste prijavljeni..")));
        continue;
    }

    // Samo nadolazeći termini za ovog korisnika
    std::string q =
        "SELECT id, tip_usluge, DATE_FORMAT(datum, '%Y-%m-%d') AS d, "
        "       TIME_FORMAT(vrijeme, '%H:%i:%s') AS t "
        "FROM Termini "
        "WHERE korisnik_id = " + std::to_string(uid) + " "
        "  AND (datum > CURDATE() OR (datum = CURDATE() AND vrijeme >= CURTIME())) "
        "ORDER BY datum ASC, vrijeme ASC;";

    if (mysql_query(db.conn, q.c_str()) != 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(error_msg(mysql_error(db.conn))));
        continue;
    }

    MYSQL_RES* res = mysql_store_result(db.conn);
    if (!res) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(error_msg(mysql_error(db.conn))));
        continue;
    }

    nlohmann::json sessions = nlohmann::json::array();
    for (MYSQL_ROW row; (row = mysql_fetch_row(res)); ) {
        // kolone: 0=id (int), 1=tip_usluge (string), 2=datum (YYYY-MM-DD), 3=vrijeme (HH:MM:SS)
        sessions.push_back({
            {"code",   row[0] ? std::atoi(row[0]) : 0},
            {"usluga", row[1] ? row[1] : ""},
            {"datum",  row[2] ? row[2] : ""},
            {"vrijeme",row[3] ? row[3] : ""}
        });
    }
    mysql_free_result(res);

    boost::asio::write(*ssl_sock,
        boost::asio::buffer(ok_with(nlohmann::json{{"sessions", sessions}})));
}



else if (cmd == "SELECT_SERVICE") {
    if (session_email.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Niste prijavljeni...")));
        continue;
    }
    std::string usluga    = req.value("usluga", "");
    std::string date_from = req.value("date_from", "");
    std::string date_to   = req.value("date_to",   "");
    std::string time_from = req.value("time_from", "");
    std::string time_to   = req.value("time_to",   "");
    bool   only_free      = req.value("only_free", false);
    double price_max      = req.value("price_max", 0.0);

    if (usluga.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(error_msg("Nedostaje usluga!")));
        continue;
    }

    // kompleks → id
    int kid = 0;
    if      (session_kompleks == "Kompleks_A" || session_kompleks == "A" || session_kompleks == "a") kid = 1;
    else if (session_kompleks == "Kompleks_B" || session_kompleks == "B" || session_kompleks == "b") kid = 2;
    if (kid == 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Nepostojeći kompleks. ")));
        continue;
    }

    // (A) osnovni parametri usluge (kapacitet/cijena/trajanje) – validira da usluga postoji u tom kompleksu
    int max_igraca = 0; double cijena = 0.0; double trajanje = 0.0;
    {
        std::string q =
            "SELECT kapacitet, cijena_pojedinacnog_termina, trajanje_pojedinacnog_termina "
            "FROM Usluge WHERE id_kompleksa=" + std::to_string(kid) +
            " AND naziv='" + usluga + "' LIMIT 1;";
        if (mysql_query(db.conn, q.c_str()) != 0) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
            continue;
        }
        bool found = false;
        if (MYSQL_RES* r = mysql_store_result(db.conn)) {
            if (MYSQL_ROW row = mysql_fetch_row(r)) {
                if (row[0]) max_igraca = std::atoi(row[0]);
                if (row[1]) cijena     = std::atof(row[1]);
                if (row[2]) trajanje   = std::atof(row[2]);
                found = true;
            }
            mysql_free_result(r);
        }
        if (!found) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Nepostojeća usluga!")));
            continue;
        }
    }

    // (B) upit za slotove u Termini sa filtrima
    //provjera
    std::string qslots =
    "SELECT t.datum, t.vrijeme "
    "FROM Termini t "
    "JOIN Usluge u ON u.naziv = t.tip_usluge "
    "WHERE u.id_kompleksa = " + std::to_string(kid) + " "
    "AND u.naziv = '" + usluga + "'";
    
   

// po želji samo budući slotovi
// qslots += " AND t.datum >= CURDATE()";

if (!date_from.empty()) qslots += " AND t.datum >= '" + date_from + "'";
if (!date_to.empty())   qslots += " AND t.datum <= '" + date_to   + "'";
if (!time_from.empty()) qslots += " AND t.vrijeme >= '" + time_from + "'";
if (!time_to.empty())   qslots += " AND t.vrijeme <= '" + time_to   + "'";

qslots += " ORDER BY t.datum ASC, t.vrijeme ASC";

    // (C) pročitaj slotove i filtriraj po zauzetosti/cijeni (if needed)
    json slots = json::array();
    if (mysql_query(db.conn, qslots.c_str()) != 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
        continue;
    }
    if (MYSQL_RES* r = mysql_store_result(db.conn)) {
        MYSQL_ROW row;
        while ((row = mysql_fetch_row(r))) {
            std::string datum   = row[0] ? row[0] : "";
            std::string vrijeme = row[1] ? row[1] : "";

            json s;
            s["datum"]      = datum;
            s["vrijeme"]    = vrijeme;
            slots.push_back(s);
        }
        mysql_free_result(r);
    }

std::string uslugaUpit =
    "SELECT u.dostupnost_od, u.dostupnost_do, u.trajanje_pojedinacnog_termina, u.cijena_pojedinacnog_termina "
    "FROM Usluge u "
    "WHERE u.id_kompleksa = " + std::to_string(kid) +
    " AND u.naziv = '" + usluga + "' "
    "LIMIT 1;";


      
    json uslugaRez = json::array();
    if (mysql_query(db.conn, uslugaUpit.c_str()) != 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
        continue;
    }
    if (MYSQL_RES* r = mysql_store_result(db.conn)) {
        MYSQL_ROW row;
        while ((row = mysql_fetch_row(r))) {
            std::string dostupnost_od   = row[0] ? row[0] : "";
            std::string dostupnost_do   = row[1] ? row[1] : "";
            std::string duration = row[2] ? row[2] : "";
            std::string price = row[3] ? row[3] : "";

            json s;
            s["time_from"]      = dostupnost_od;
            s["time_to"]    = dostupnost_do;
            s["duration"] = duration;
            s["price"] = price;
            uslugaRez.push_back(s);
        }
        mysql_free_result(r);
    }
    
    json resp;
    resp["usluga"]  = usluga;
    resp["time_from"] = uslugaRez[0]["time_from"];
    resp["time_to"] = uslugaRez[0]["time_to"];
    resp["price"] = uslugaRez[0]["price"];
    resp["duration"] = uslugaRez[0]["duration"];
    resp["reserved_slots"]   = slots;   // može biti i []
    resp["next"]    = "RESERVE"; // sledeći korak: {"cmd":"RESERVE","sifra":"..."}
    boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));
}


else if (cmd == "CANCEL") {
    // 1) mora biti ulogovan
    if (session_email.empty()) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Niste prijavljeni...")));
        continue;
    }

    // --- robustno parsiranje code kao INT (podržava i broj i string) ---
    int term_id = 0;
    if (req.contains("code")) {
        try {
            if (req["code"].is_number_integer()) {
                term_id = req["code"].get<int>();
            } else if (req["code"].is_string()) {
                std::string s = req["code"].get<std::string>();
                if (!s.empty()) term_id = std::stoi(s);
            }
        } catch (...) { term_id = 0; }
    }
    if (term_id <= 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Šifra mora biti pozitivan broj!")));
        continue;
    }

    // 2) pronađi termin
    std::string datum, vrijeme;
    {
        std::ostringstream q;
        q << "SELECT id, datum, vrijeme FROM Termini WHERE id=" << term_id << " LIMIT 1;";
        if (mysql_query(db.conn, q.str().c_str()) != 0) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
            continue;
        }
        if (MYSQL_RES* r = mysql_store_result(db.conn)) {
            if (MYSQL_ROW row = mysql_fetch_row(r)) {
                // id već imamo kao term_id
                if (row[1]) datum   = row[1];
                if (row[2]) vrijeme = row[2];
            }
            mysql_free_result(r);
        }
        if (datum.empty() || vrijeme.empty()) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Nepostojeći termin!")));
            continue;
        }
    }

    // 3) provjeri da li ovaj korisnik ima rezervaciju za termin
    int uid = db.get_user_id_by_email(session_email);
    if (uid <= 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Korisnik nije pronađen.")));
        continue;
    }
    long long my_cnt = 0;
    {
        std::ostringstream q;
        q << "SELECT COUNT(*) FROM Rezervacije WHERE termin_id=" << term_id
          << " AND korisnik_id=" << uid << ";";
        if (mysql_query(db.conn, q.str().c_str()) != 0) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
            continue;
        }
        if (MYSQL_RES* r = mysql_store_result(db.conn)) {
            if (MYSQL_ROW row = mysql_fetch_row(r)) {
                if (row[0]) my_cnt = std::atoll(row[0]);
            }
            mysql_free_result(r);
        }
    }
    if (my_cnt == 0) {
        boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Korisnik nema rezervacije.")));
        continue;
    }

    // 4) vremensko ograničenje: najkasnije 60 min prije početka
    long long mins_until = 0;
    {
        std::ostringstream q;
        q << "SELECT TIMESTAMPDIFF(MINUTE, NOW(), "
          << "STR_TO_DATE(CONCAT(datum,' ',vrijeme), '%Y-%m-%d %H:%i:%s')) "
          << "FROM Termini WHERE id=" << term_id << " LIMIT 1;";
        if (mysql_query(db.conn, q.str().c_str()) != 0) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
            continue;
        }
        if (MYSQL_RES* r = mysql_store_result(db.conn)) {
            if (MYSQL_ROW row = mysql_fetch_row(r)) {
                if (row[0]) mins_until = std::atoll(row[0]);
            }
            mysql_free_result(r);
        }
    }
    if (mins_until < 60) {
        json resp;
        resp["ok"] = false;
        resp["error"] = "Nije dopušteno otkazivanje usluge. Uslugu morate otkazati bar sat vremena prije početka!";
        resp["data"] = {{"minutes_until_start", mins_until}, {"limit_minutes", 60}};
        boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));
        continue;
    }

    // 5) dvostepena potvrda
    bool confirm = req.value("confirm", false);
    if (!confirm) {
        json resp;
        resp["ok"] = true;
        resp["confirm_required"] = true;
        resp["data"] = {
            {"msg", "Da li ste sigurni da želite otkazati rezervaciju?"},
            {"termin_id", term_id},
            {"start", datum + " " + vrijeme},
            {"minutes_until_start", mins_until},
            {"hint", std::string("Resend with {\"cmd\":\"CANCEL\",\"code\":") +
                     std::to_string(term_id) + ",\"confirm\":true}"}
        };
        boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));
        continue;
    }

    // 6) brisanje rezervacije (uklanjanje korisnika iz grupe)
    {
        std::ostringstream q;
        q << "DELETE FROM Rezervacije WHERE termin_id=" << term_id
          << " AND korisnik_id=" << uid << " LIMIT 1;";
        if (mysql_query(db.conn, q.str().c_str()) != 0) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
            continue;
        }
        if (mysql_affected_rows(db.conn) == 0) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with("Rezervacija nije pronađena ili je već otkazana!")));
            continue;
        }
    }

    // 7) ako je korisnik bio posljednji – obriši termin
    bool group_deleted = false;
    {
        long long left_cnt = 0;
        std::ostringstream qcnt;
        qcnt << "SELECT COUNT(*) FROM Rezervacije WHERE termin_id=" << term_id << ";";
        if (mysql_query(db.conn, qcnt.str().c_str()) != 0) {
            boost::asio::write(*ssl_sock, boost::asio::buffer(err_with(mysql_error(db.conn))));
            continue;
        }
        if (MYSQL_RES* r = mysql_store_result(db.conn)) {
            if (MYSQL_ROW row = mysql_fetch_row(r)) {
                if (row[0]) left_cnt = std::atoll(row[0]);
            }
            mysql_free_result(r);
        }
        if (left_cnt == 0) {
            std::ostringstream qdel;
            qdel << "DELETE FROM Termini WHERE id=" << term_id << " LIMIT 1;";
            if (mysql_query(db.conn, qdel.str().c_str()) == 0) {
                group_deleted = (mysql_affected_rows(db.conn) > 0);
            }
        }
    }

    // 8) odgovor + notifikacija
    {
        json resp;
        resp["ok"] = true;
        resp["data"] = {
            {"msg", "reservation_canceled"},
            {"termin_id", term_id},
            {"group_deleted", group_deleted}
        };
        boost::asio::write(*ssl_sock, boost::asio::buffer(resp.dump() + "\n"));
    }
}



//--------------------CANCEL------------------
          
            else {
                boost::asio::write(*ssl_sock, boost::asio::buffer(error_msg("unknown cmd")));
            }
        }
    } catch (const std::exception&) {
        // swallow per-session errors
    }
}

// --------------------------- main ---------------------------
int main(int argc, char** argv) {
    unsigned short cmd_port = (argc > 1) ? (unsigned short)std::stoi(argv[1]) : 5555;   // TLS command port
    unsigned short ntf_port = (argc > 2) ? (unsigned short)std::stoi(argv[2]) : 5556;   // async notifier port (plain)

    try {
        Db db;

        // Two io_contexts: one for TLS command server (blocking per thread), one for async notifier
        boost::asio::io_context io_cmd;  // used only for accept + sockets handed off to worker threads
        boost::asio::io_context io_ntf;  // runs async notifier

        // ---- init notifier ----
        auto notifier = std::make_shared<AsyncNotifier>(io_ntf, ntf_port);
        notifier->start();
        std::thread ntf_thr([&]{ io_ntf.run(); });

        // ---- TLS context ----
        ssl::context tls_ctx(ssl::context::tls_server);
        tls_ctx.set_options(ssl::context::default_workarounds | ssl::context::no_sslv2 | ssl::context::single_dh_use);
        tls_ctx.use_certificate_chain_file("certs/cert.pem");
        tls_ctx.use_private_key_file("certs/key.pem", ssl::context::pem);

        // ---- acceptor for TLS command channel ----
        tcp::acceptor acc(io_cmd, tcp::endpoint(tcp::v4(), cmd_port));
        std::cout << "[server] TLS command listening on 0.0.0.0:" << cmd_port << "\n";
        std::cout << "[notifier] async TCP listening on 0.0.0.0:" << ntf_port << " (SUBSCRIBE then receive events)\n";

        for (;;) {
            tcp::socket raw(io_cmd);
            acc.accept(raw);

            // create SSL stream per connection
            auto ssl_sock = std::make_shared<ssl::stream<tcp::socket>>(std::move(raw), tls_ctx);
            // perform blocking handshake here so that we can fail fast without creating thread
            boost::system::error_code ec;
            ssl_sock->handshake(ssl::stream_base::server, ec);
            if (ec) {
                // handshake failed; continue accepting
                continue;
            }

            // Hand off to a detached worker thread (blocking read_until loop)
            std::thread(session_tls, ssl_sock, std::ref(db), notifier).detach();
        }

        ntf_thr.join(); // unreachable, accept loop is infinite
    } catch (const std::exception& e) {
        std::cerr << "server error: " << e.what() << "\n";
        return 1;
    }
}
