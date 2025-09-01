// client.cpp — konzolni klijent za tvoj server (TLS 5555 + async notifier 5556)
// Build: g++ -std=c++17 client.cpp -o client -lboost_system -lssl -lcrypto -lpthread
// Run:   ./client 127.0.0.1 5555

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <iostream>
#include <iomanip>
#include <thread>
#include <atomic>
#include <sstream>
#include <vector>
#include <map>
#include <optional>
#include <memory>
#include <array>
#include <cstdint>
#include <limits>
#include <nlohmann/json.hpp>

#if defined(_WIN32)
  #include <conio.h>
  #include <windows.h>
#else
  #include <termios.h>
  #include <unistd.h>
#endif


using json = nlohmann::json;
using boost::asio::ip::tcp;
namespace ssl = boost::asio::ssl;

// ---------- util ----------
static std::string pretty(const json& j) { return j.dump(2); }

static void send_line(ssl::stream<tcp::socket>& s, const std::string& line) {
    std::string msg = line;
    if (msg.empty() || msg.back() != '\n') msg.push_back('\n');
    boost::asio::write(s, boost::asio::buffer(msg));
}

static std::optional<json> read_json_line(ssl::stream<tcp::socket>& s) {
    boost::asio::streambuf buf;
    boost::system::error_code ec;
    std::size_t n = boost::asio::read_until(s, buf, '\n', ec);

    if (n == 0 && (ec == boost::asio::ssl::error::stream_truncated ||
                   ec == boost::asio::error::eof)) return std::nullopt; // čista diskonekcija
    if (ec && ec != boost::asio::ssl::error::stream_truncated &&
             ec != boost::asio::error::eof) throw boost::system::system_error(ec);

    std::istream is(&buf);
    std::string line; std::getline(is, line);
    if (line.empty()) return json::object();
    json j = json::parse(line, nullptr, false);
    if (j.is_discarded()) return std::nullopt;
    return j;
}


static void reconnect(ssl::stream<tcp::socket>& sock,
                      boost::asio::io_context& io,
                      ssl::context& ctx,
                      const std::string& host,
                      const std::string& port)
{
    // 1) Zatvori staru konekciju (tiho)
    try {
        boost::system::error_code ec;
        sock.lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
        sock.lowest_layer().close(ec);
    } catch (...) {}

    // 2) Napravi novi socket objekt “na mjestu”
    new (&sock) ssl::stream<tcp::socket>(io, ctx);

    // 3) Ponovo se spoji i handshake
    tcp::resolver res(io);
    auto eps = res.resolve(host, port);
    boost::asio::connect(sock.next_layer(), eps);
    sock.handshake(ssl::stream_base::client);
}

// UVIJEK sačeka ENTER, čak i ako ima zaostali '\n' u stdin bufferu
static void wait_enter() {
    std::cout << "Pritisnite ENTER za povratak na početnu stranicu..." << std::flush;
    // prvo “počisti” eventualni zaostali kraj reda
    while (std::cin.rdbuf()->in_avail() > 0) {
        char c = std::cin.get();
        if (c == '\n') break;
    }
    // sad čekamo “svježi” ENTER
    std::cin.get();
    std::cout << "\n";
}

static std::string ask(const std::string& label, const std::string& def = "") {
    std::string v;
    std::cout << label;
    if (!def.empty()) std::cout << " [" << def << "]";
    std::cout << ": ";
    std::getline(std::cin, v);
    if (v.empty()) return def;
    return v;
}

static std::string ask_password(const std::string& label, bool mask_with_asterisks = true) {
    std::string pwd;
    std::cout << label << ": " << std::flush;

#if defined(_WIN32)
    for (;;) {
        int ch = _getch();                        // ne echa na ekran
        if (ch == '\r' || ch == '\n') break;     // Enter
        if (ch == 3) return "";                  // Ctrl+C → prekid (po želji)
        if (ch == 8 || ch == 127) {              // Backspace
            if (!pwd.empty()) {
                pwd.pop_back();
                if (mask_with_asterisks) { std::cout << "\b \b" << std::flush; }
            }
            continue;
        }
        if (ch == 0 || ch == 224) { _getch(); continue; } // spec. tasteri (strelice itd.)
        pwd.push_back(static_cast<char>(ch));
        if (mask_with_asterisks) std::cout << '*' << std::flush;
    }
    std::cout << "\n";
#else
    // POSIX: ugasi echo (i po potrebi canonical mode) i čitaj char po char
    termios oldt{};
    if (!isatty(STDIN_FILENO)) {                 // ako nije TTY (npr. pipe), fallback
        std::getline(std::cin, pwd);
        return pwd;
    }
    if (tcgetattr(STDIN_FILENO, &oldt) != 0) {
        std::getline(std::cin, pwd);             // fallback
        return pwd;
    }
    termios newt = oldt;
    if (mask_with_asterisks) newt.c_lflag &= ~(ECHO | ICANON);
    else                     newt.c_lflag &= ~(ECHO);
    newt.c_cc[VMIN]  = 1;
    newt.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    for (;;) {
        int ch = getchar();
        if (ch == '\n' || ch == '\r') break;     // Enter
        if (ch == 127 || ch == 8) {              // Backspace
            if (!pwd.empty()) {
                pwd.pop_back();
                if (mask_with_asterisks) { std::cout << "\b \b" << std::flush; }
            }
            continue;
        }
        if (ch == EOF) break;
        pwd.push_back(static_cast<char>(ch));
        if (mask_with_asterisks) std::cout << '*' << std::flush;
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);     // vrati terminal u prvobitno stanje
    std::cout << "\n";
#endif
    return pwd;
}

static size_t utf8_display_len(const std::string& s) {
    // Broji UTF-8 “code points” (svaki multibajtni znak kao 1)
    size_t n = 0;
    for (unsigned char c : s) if ((c & 0xC0) != 0x80) ++n;
    return n;
}
static void print_col_utf8(const std::string& text, size_t width) {
    size_t vis = utf8_display_len(text);
    std::cout << text;
    if (vis < width) std::cout << std::string(width - vis, ' ');
}

// ---------- notifier (TCP 5556) ----------
class Notifier {
public:
    Notifier(const std::string& host, uint16_t port, const std::string& token = "")
      : host_(host), port_(port), token_(token) {}

    void start() {
        stop_flag_ = false;
        th_ = std::thread([this]{ run(); });
    }
    void stop() {
        stop_flag_ = true;
        try {
            if (sock_) {
                boost::system::error_code ec;
                sock_->close(ec);
            }
        } catch (...) {}
        if (th_.joinable()) th_.join();
    }
    ~Notifier() { stop(); }

private:
    void run() {
        using boost::asio::buffer;
        try {
            boost::asio::io_context io;
            tcp::resolver res(io);
            auto eps = res.resolve(host_, std::to_string(port_));
            sock_ = std::make_unique<tcp::socket>(io);
            boost::asio::connect(*sock_, eps);

            // STREAM (4B length prefix)
            {
                std::string hello = token_.empty() ? "STREAM\n" : ("STREAM " + token_ + "\n");
                boost::asio::write(*sock_, buffer(hello));

                for (;;) {
                    if (stop_flag_) return;
                    std::array<unsigned char,4> hdr{};
                    boost::asio::read(*sock_, buffer(hdr));
                    uint32_t n = (uint32_t(hdr[0])<<24) | (uint32_t(hdr[1])<<16)
                               | (uint32_t(hdr[2])<<8)  | (uint32_t(hdr[3]));
                    std::string body(n, '\0');
                    boost::asio::read(*sock_, buffer(body.data(), body.size()));
                    handle_event(body);
                }
            }
        } catch (...) {
            // fallback: line-based SUBSCRIBE
            try {
                boost::asio::io_context io;
                tcp::resolver res(io);
                auto eps = res.resolve(host_, std::to_string(port_));
                sock_ = std::make_unique<tcp::socket>(io);
                boost::asio::connect(*sock_, eps);
                std::string hi = token_.empty() ? "SUBSCRIBE\n" : ("SUBSCRIBE " + token_ + "\n");
                boost::asio::write(*sock_, boost::asio::buffer(hi));

                boost::asio::streambuf buf;
                while (!stop_flag_) {
                    boost::asio::read_until(*sock_, buf, '\n');
                    std::istream is(&buf);
                    std::string line; std::getline(is, line);
                    if (!line.empty()) handle_event(line);
                }
            } catch (...) {
                if (!stop_flag_) {
                    std::cerr << "\n[notifier] disconnected.\n> ";
                }
            }
        }
    }

    void handle_event(const std::string& payload) {
        json j = json::parse(payload, nullptr, false);
        if (j.is_discarded()) {
            std::cout << "\n" << payload << "\n> ";
            std::cout.flush();
            return;
        }
        std::string ev = j.value("event", "");
        if (ev == "hello") {
            
        } else if (ev == "promo") {
            std::cout << "\nPROMO: " << j.value("text", "") << "\n> ";
        } else if (ev == "need_player") {
            std::cout << "\nPOTREBAN IGRAČ — termin #"
                      << j.value("termin_id", 0) << " ("
                      << j.value("service","") << ", "
                      << j.value("location","") << ", "
                      << j.value("when","") << ") — fali: "
                      << j.value("missing", 0)
                      << " | poslao: " << j.value("requested_by","") << "\n> ";
        } else if (ev == "spot_filled") {
            std::cout << "\nMJESTO POPUNJENO — termin #"
                      << j.value("termin_id",0) << " "
                      << j.value("filled",0) << "/"
                      << j.value("max",0)
                      << " (user: " << j.value("user","") << ")\n> ";
        } else if (ev == "update") {
            std::cout << "\nUPDATE: " << j.value("type","") << "\n> ";
        } else {
            std::cout << "\n[EVENT] " << pretty(j) << "\n> ";
        }
        std::cout.flush();
    }

    std::string host_;
    uint16_t port_;
    std::string token_;
    std::unique_ptr<tcp::socket> sock_;
    std::thread th_;
    std::atomic<bool> stop_flag_{false};
};

// ---------- prikazi ----------
static void print_services(const json& resp) {
    if (!resp.value("ok", false)) {
        std::cout << "Greška: " << resp.value("error","") << "\n"; return;
    }
    if (!resp.contains("services")) { std::cout << pretty(resp) << "\n"; return; }
    auto arr = resp["services"];
    std::cout << "\nUsluge (" << resp.value("kompleks","") << "):\n";
    std::cout << "------------------------------------------------------\n";
    const size_t W_NAME = 20, W_DUR = 12, W_PRICE = 12, W_CAP = 10;

std::cout << std::left
          << std::setw(W_NAME) << "Naziv"
          << std::setw(W_DUR)  << "Trajanje"
          << std::setw(W_PRICE)<< "Cijena"
          << std::setw(W_CAP)  << "Kapacitet" << "\n";
std::cout << "------------------------------------------------------\n";

for (auto& s : arr) {
    std::ostringstream traj; traj << s.value("trajanje",0.0) << "h";
    std::ostringstream cij;  cij  << s.value("cijena",0.0)   << "KM";

    // Naziv (UTF-8 poravnanje ručno)
    print_col_utf8(s.value("naziv",""), W_NAME);

    // ostale kolone mogu ostati sa setw jer su ASCII
    std::cout << std::setw(W_DUR)   << traj.str()
              << std::setw(W_PRICE) << cij.str()
              << std::setw(W_CAP)   << s.value("kapacitet",0)
              << "\n";
}


}

// ---------- main ----------
int main(int argc, char** argv) {
    std::string host = (argc > 1) ? argv[1] : "100.100.129.70";
    std::string port = (argc > 2) ? argv[2] : "5555";

    try {
        boost::asio::io_context io;
        ssl::context ctx(ssl::context::tlsv12_client);
        ctx.set_verify_mode(ssl::verify_none); // testno okruženje

        tcp::resolver res(io);
        auto eps = res.resolve(host, port);
        ssl::stream<tcp::socket> sock(io, ctx);
        boost::asio::connect(sock.next_layer(), eps);
        sock.handshake(ssl::stream_base::client);

        // ========== POČETNI ODABIR LOKACIJE ==========
        std::string default_lok = "A";
        //for (;;) {
            //std::cout << "\nOdaberite jednu od lokacija\n";
            //std::cout << "1. Sportski kompleks Sarajevo (A)\n";
            //std::cout << "2. Sportski kompleks Sanski Most (B)\n> ";
            //std::string sel; std::getline(std::cin, sel);
            //if (sel == "1") { default_lok = "A"; break; }
            //if (sel == "2") { default_lok = "B"; break; }
            //std::cout << "Nepoznata opcija. Pokušajte ponovo.\n";
        //}

        // Notifier konfig (popunjava se nakon login-a)
        std::string role;              // "user" ili "admin"
        std::string notifier_host = host;
        uint16_t    notifier_port = 5556;
        std::string notifier_token;
        std::unique_ptr<Notifier> notifier;

        // --- helpers ---
        auto do_register = [&](){
    std::string ime = ask("Ime i prezime");
    std::string email = ask("E-mail");
    std::string pass = ask_password("Lozinka (min 8)", true);
    std::string lokacija = ask("Početni kompleks (A/B ili Kompleks_A/B)", default_lok);

    json req = {{"cmd","REGISTER"}, {"ime", ime}, {"email", email}, {"password", pass}, {"lokacija", lokacija}};
    send_line(sock, req.dump());
    auto j = read_json_line(sock);
    if (!j) { std::cout << "Neispravan odgovor.\n"; return; }
            if (!j->value("ok",false)) { std::cout << "Greška: " << j->value("error","") << "\n"; return; }

    std::cout << "Uspješno ste registrovani!\n";

    // —— hard reset konekcije nakon REGISTER-a ——
    reconnect(sock, io, ctx, host, port);
    
        json login = {{"cmd","LOGIN"},{"email",email},{"password",pass}};
        send_line(sock, login.dump());
        auto l = read_json_line(sock);
        if (l && l->value("ok",false)) {
            role = l->value("role","");
        } else {
            std::cout << "Napomena: auto-prijava nakon registracije nije uspjela.\n";
        }
    
};
        
        auto do_check_loyalty = [&](){
    json req = {{"cmd","LOYALTY_POINTS"}};
    send_line(sock, req.dump());
    auto j = read_json_line(sock);
    if (!j) { std::cout << "Neispravan odgovor.\n"; return; }
    if (!j->value("ok", false)) {
        std::cout << "Greška: " << j->value("error","") << "\n";
        return;
    }
    unsigned long long pts = 0ULL;
    try { pts = (*j)["data"].value("count", 0ULL); } catch (...) {}

    std::cout << "\n╔════════════════════════════════════╗\n";
    std::cout <<   "║            LOYALTY BODOVI          ║\n";
    std::cout <<   "╠════════════════════════════════════╣\n";
    std::cout <<   "║       Imate "<<pts<<" loyalty bodova.      ║\n";
    std::cout <<   "╚════════════════════════════════════╝\n";
};

        auto do_login = [&](){
            std::string email = ask("E-mail");
            std::string pass  = ask_password("Lozinka", true);
            json req = {{"cmd","LOGIN"},{"email",email},{"password",pass}};
            send_line(sock, req.dump());
            auto j = read_json_line(sock);
            if (!j) { std::cout << "Neispravan odgovor.\n"; return; }
            if (!j->value("ok",false)) { std::cout << "Greška: " << j->value("error","") << "\n"; return; }

            role = j->value("role", "");
            std::cout << "Prijava uspješna!\n";

            if (j->contains("notifier")) {
                auto n = (*j)["notifier"];
                notifier_host = n.value("host", notifier_host);
                notifier_port = static_cast<uint16_t>(n.value("port", (int)notifier_port));
                notifier_token = n.value("token", "");
            }
            if(role!="admin") {
              std::string sub = ask("Želite li primati reklamne poruke (Y/N)", "Y");
              if (!sub.empty() && (sub[0]=='y' || sub[0]=='Y')) {
                  notifier = std::make_unique<Notifier>(notifier_host, notifier_port, notifier_token);
                  notifier->start();
              }
            }
        };

        auto do_list_services = [&](bool for_session_complex){
            json req = {{"cmd","LIST_SERVICES"}};
            if (!for_session_complex) req["lokacija"] = default_lok; // "A" ili "B"
            send_line(sock, req.dump());
            auto j = read_json_line(sock);
            if (!j) { std::cout << "Neispravan odgovor.\n"; return; }
            if (!j->value("ok",false)) { std::cout << "Greška: " << j->value("error","") << "\n"; return; }
            print_services(*j);
        };

        auto do_get_hours = [&](){
            json req = {{"cmd","GET_HOURS"}};
            std::string k = ask("Kompleks (A/B)", "");
            if (!k.empty()) {
                if (k=="A"||k=="a"||k=="B"||k=="b") req["kompleks"] = k;
                else req["lokacija"] = k;
            }
            send_line(sock, req.dump());
            auto j = read_json_line(sock);
            if (!j) { std::cout << "Neispravan odgovor.\n"; return; }
            if (!j->value("ok",false)) { std::cout << "Greška: " << j->value("error","") << "\n"; return; }
            auto hours = (*j)["data"]["hours"];
            std::cout << "\nRadno vrijeme:\n";
            for (auto& h : hours) {
                std::cout << " - " << h.value("lokacija","") << ": "
                          << h.value("from","") << " - " << h.value("to","") << "\n";
            }
        };

        auto do_reserve_by_time = [&](){
            std::string usluga = ask("Usluga (npr. Fudbal)");
            std::string date   = ask("Datum (YYYY-MM-DD)");
            std::string time   = ask("Vrijeme (HH:MM:SS)");
            json req = {{"cmd","RESERVE"},{"usluga",usluga},{"date",date},{"time",time}};
            send_line(sock, req.dump());
            auto j = read_json_line(sock);
            if (!j) { std::cout << "Neispravan odgovor.\n"; return; }
            if (!j->value("ok",false)) { std::cout << "Greška! " << j->value("error","") << "\n"; return; }
            std::cout << "Rezervacija potvrđena.\n";
        };

        auto do_check_matches = [&](){
            std::string usluga = ask("Usluga");
            std::string date   = ask("Datum (YYYY-MM-DD)");
            json req = {{"cmd","CHECK_MATCH"},{"usluga",usluga},{"date",date}};
            send_line(sock, req.dump());
            auto j = read_json_line(sock);
            if (!j) { std::cout << "Neispravan odgovor.\n"; return; }
            auto arr = (*j)["Sessions"];
            if (!arr.is_array() || arr.empty()) { std::cout << "Nema dostupnih termina.\n"; return; }
            std::cout << "\nDostupne sesije:\n";
            std::cout << std::left << std::setw(8) <<"CODE" << std::setw(10) << "TIME"
                      << std::setw(12) << "LOCATION" << "CAPACITY\n";
            for (auto& s : arr) {
                std::cout << std::setw(8)  << s.value("code",0)
                          << std::setw(10) << s.value("time","")
                          << std::setw(12) << s.value("location","")
                          << s.value("capacity","") << "\n";
            }
            std::string code = ask("Unesite šifru za priključivanje terminu (prazno za odustajanje)");
            if (!code.empty()) {
                json join = {{"cmd","JOIN_MATCH"},{"code", std::stoi(code)}};
                send_line(sock, join.dump());
                auto jj = read_json_line(sock);
                if (!jj) { std::cout << "Neispravan odgovor.\n"; return; }
                if (!jj->value("ok",false)) { std::cout << "Greška: " << jj->value("error","") << "\n"; return; }
                std::cout << "Uspjeh\n" << jj->value("msg","Joined")
                          << " " << jj->value("filled",0) << "/" << jj->value("max",0) << "\n";
            }
        };

        auto do_need_player = [&](){
            json list = {{"cmd","LIST_MY_SESSIONS"}};
    send_line(sock, list.dump());
    auto jr = read_json_line(sock);
    if (!jr || !jr->value("ok", false)) {
        std::cout << "Ne mogu dohvatiti vaše termine. "
                  << (jr ? jr->value("error","") : "greška") << "\n";
        return;
    }

    auto arr = (*jr)["data"]["sessions"];
    if (!arr.is_array() || arr.empty()) {
        std::cout << "\nNemate nadolazećih termina.\n";
        return;
    }

    // 2) Lijep ispis (bosanski naslovi, samo tražena polja)
    std::cout << "\nVaši termini (nadolazeći):\n";
    std::cout << std::left
              << std::setw(8)  << "ŠIFRA"
              << std::setw(16) << "USLUGA"
              << std::setw(12) << "DATUM"
              << std::setw(10) << "VRIJEME" << "\n";
    for (auto& s : arr) {
        std::cout << std::setw(8)  << s.value("code",0)
                  << std::setw(16) << s.value("usluga","")
                  << std::setw(12) << s.value("datum","")
                  << std::setw(10) << s.value("vrijeme","") << "\n";
    }
            
            std::string code = ask("Šifra termina");
            json req = {{"cmd","ALERT_NEED_PLAYER"},{"code", std::stoi(code)}};
            send_line(sock, req.dump());
            auto j = read_json_line(sock);
            if (!j) { std::cout << "Neispravan odgovor.\n"; return; }
            if (!j->value("ok",false)) { std::cout << "X" << j->value("error","") << "\n"; return; }
            std::cout << "Signal poslan: Potrebni igrači (" << (*j)["data"].value("missing",0) << ")\n";
        };

        auto do_balance_menu = [&](){
            for (;;) {
                std::cout << "\n=== STANJE NA RAČUNU ===\n";
                std::cout << "1) Provjera stanja na računu\n";
                std::cout << "2) Uplati iznos\n";
                std::cout << "0) Nazad\n> ";
                std::string op; std::getline(std::cin, op);
                if (op=="0") break;
                if (op=="1") {
                    json req = {{"cmd","BALANCE_CHECK"}};
                    send_line(sock, req.dump());
                    auto j = read_json_line(sock);
                    if (j && j->value("ok",false)) {
                        auto d = (*j)["data"];
                        std::cout << "Stanje: " << d.value("balance",0.0) << " " << d.value("currency","") << "\n";
                    } else {
                        std::cout << "Greška.\n";
                    }
                } else if (op=="2") {
                    std::string amount = ask("Iznos (BAM)");
                    json req = {{"cmd","BALANCE_ADD"},{"amount", std::stod(amount)}};
                    send_line(sock, req.dump());
                    auto j = read_json_line(sock);
                    if (j && j->value("ok",false)) {
                        auto d = (*j)["data"];
                        std::cout << "Dodano: " << d.value("added",0.0) << " — Novo stanje: "
                                  << d.value("total balance",0.0) << " " << d.value("currency","") << "\n";
                    } else {
                        std::cout << "Greška.\n";
                    }
                }
            }
        };

        auto do_cancel = [&](){
    // 1) Moji termini
    json list = {{"cmd","LIST_MY_SESSIONS"}};
    send_line(sock, list.dump());
    auto jr = read_json_line(sock);
    if (!jr || !jr->value("ok", false)) {
        std::cout << "Ne mogu dohvatiti vaše termine. "
                  << (jr ? jr->value("error","") : "greška") << "\n";
        return;
    }

    auto arr = (*jr)["data"]["sessions"];
    if (!arr.is_array() || arr.empty()) {
        std::cout << "\nNemate termina za otkazivanje.\n";
        return;
    }

    // 2) Lijep ispis (bosanski naslovi, samo tražena polja)
    std::cout << "\nVaši termini (nadolazeći):\n";
    std::cout << std::left
              << std::setw(8)  << "ŠIFRA"
              << std::setw(16) << "USLUGA"
              << std::setw(12) << "DATUM"
              << std::setw(10) << "VRIJEME" << "\n";
    for (auto& s : arr) {
        std::cout << std::setw(8)  << s.value("code",0)
                  << std::setw(16) << s.value("usluga","")
                  << std::setw(12) << s.value("datum","")
                  << std::setw(10) << s.value("vrijeme","") << "\n";
    }

    // 3) Pitaj koju šifru otkazati (ID)
    std::string code = ask("Unesite šifru (ID) termina za otkazivanje");
    if (code.empty()) return;

    json req = {{"cmd","CANCEL"},{"code", std::stoi(code)}};
    send_line(sock, req.dump());
    auto j = read_json_line(sock);
    if (!j) { std::cout << "Neispravan odgovor.\n"; return; }

    if (j->contains("confirm_required") && (*j)["confirm_required"] == true) {
        std::cout << (*j)["data"].value("msg","Potvrditi otkazivanje?") << "\n";
        std::string ans = ask("Potvrda (y/n)","y");
        if (ans=="y" || ans=="Y") {
            json req2 = {{"cmd","CANCEL"},{"code", std::stoi(code)}, {"confirm", true}};
            send_line(sock, req2.dump());
            auto j2 = read_json_line(sock);
            if (j2 && j2->value("ok",false)) std::cout << "Otkazano.\n";
            else std::cout << "X" << (j2 ? j2->value("error","") : "error") << "\n";
        }
    } else {
        if (j->value("ok",false)) std::cout << "Otkazano.\n";
        else std::cout << "X" << j->value("error","") << "\n";
    }
};



        auto do_admin_updates = [&](){
            if (role != "admin") { std::cout << "Samo admin.\n"; return; }
            for (;;) {
                std::cout << "\n=== ADMIN ===\n";
                std::cout << "1) Ažuriraj radno vrijeme kompleksa\n";
                std::cout << "2) Ažuriraj kapacitet usluga\n";
                std::cout << "3) Ažuriraj cijene usluga\n";
                std::cout << "4) Pošalji reklamnu poruku\n";
                std::cout << "0) Nazad\n> ";
                std::string op; std::getline(std::cin, op);
                if (op=="0") break;
                if (op=="1") {
                    std::string loc = ask("Kompleks (A/B)");
                    std::string from= ask("Od (HH:MM:SS)");
                    std::string to  = ask("Do (HH:MM:SS)");
                    json req = {{"cmd","UPDATE_HOURS"},{"location",loc},{"from",from},{"to",to}};
                    send_line(sock, req.dump());
                    auto j = read_json_line(sock);
                    if(j && j->value("ok", false)){
                          std::cout << j->value("msg","Radno vrijeme uspješno ažurirano!") << "\n"<< "\n";
                    } else {
                      std::cout << (j ? pretty(*j) : "Greška") << "\n";
                    }
                } else if (op=="2") {
                    std::string k = ask("Kompleks (A/B)");
                    std::string u = ask("Usluga (npr. Fudbal)");
                    std::string cap = ask("Novi kapacitet");
                    json req = {{"cmd","UPDATE_CAPACITY"},{"kompleks",k},{"usluga",u},{"novi_kapacitet", std::stoi(cap)}};
                    send_line(sock, req.dump());
                    auto j = read_json_line(sock);
                    if(j && j->value("ok", false)){
                          std::cout << j->value("msg","Radno vrijeme uspješno ažurirano!") << "\n"<< "\n";
                    } else {
                      std::cout << (j ? pretty(*j) : "Greška") << "\n";
                    }
                    
                } else if (op=="3") {
                    std::string k = ask("Kompleks (A/B)");
                    std::string u = ask("Usluga");
                    std::string p = ask("Nova cijena");
                    json req = {{"cmd","UPDATE_PRICES"},{"lokacija",k},{"usluga",u},{"nova_cijena", std::stod(p)}};
                    send_line(sock, req.dump());
                    auto j = read_json_line(sock);
                    if(j && j->value("ok", false)){
                          std::cout << j->value("msg","Radno vrijeme uspješno ažurirano!") << "\n"<< "\n";
                    } else {
                      std::cout << (j ? pretty(*j) : "Greška") << "\n";
                    }
                } else if (op=="4") {
                    std::string txt = ask("Reklamna poruka");
                    json req = {{"cmd","SEND_PROMO"},{"message",txt}};
                    send_line(sock, req.dump());
                    auto j = read_json_line(sock);
                    if (j && j->value("ok",false)) std::cout << "Reklamna poruka poslana.\n";
                    else std::cout << "Greška: " << (j? j->value("error",""):"error") << "\n";
                }
            }
        };
        auto do_reserve_menu = [&](){
            for (;;) {
                std::cout << "\n=== REZERVACIJE ===\n";
                std::cout << "1) Izvrši rezervaciju\n";
                std::cout << "2) Priključi se dostupnom terminu\n";
                std::cout << "3) Potreban igrač? Obavijesti korisnike!\n";
                std::cout << "0) Nazad\n> ";
                std::string op; std::getline(std::cin, op);
                if (op=="0") break;
                if (op=="1") do_reserve_by_time();
                else if (op=="2") do_check_matches();
                else if (op=="3") do_need_player();
            }
        };

        // ========== GLAVNI LOOP (DOBRODOŠLI) ==========
        for (;;) {
            std::cout << "\n===================================\n";
            std::cout << "   DOBRODOŠLI — odaberite opciju\n";
            std::cout << "===================================\n";
            //std::cout << "1) Pregled usluga\n";
            std::cout << "1) Prijava\n";
            std::cout << "2) Registracija\n";
            std::cout << "3) Dostupni kompleksi\n";
            std::cout << "0) Izlaz\n> ";
            std::string op; std::getline(std::cin, op);
            if (op=="0" || std::cin.eof()) break;

            //if (op=="1") {
              //  do_list_services(false /*po lokaciji*/);
               // wait_enter();
            //}
            else if (op=="1") {
                do_login();
                if (role.empty()) { wait_enter(); continue; }

                // ——— USER/ADMIN meni  ———
                for (;;) {
                    
                    if (role=="admin") {
                        std::cout << "1) Ažuriraj radno vrijeme kompleksa\n";
                        std::cout << "2) Ažuriraj kapacitet usluga\n";
                        std::cout << "3) Ažuriraj cijene usluga\n";
                        std::cout << "4) Pošalji reklamnu poruku\n";
                        std::cout << "5) Odjava\n";
                    } else {
                        std::cout << "\n=== GLAVNI MENI ===\n";
                        std::cout << "1) Prikaz usluga\n";
                        std::cout << "2) Prikaz radnog vremena kompleksa\n";
                        std::cout << "3) Rezerviši termin\n";
                        std::cout << "4) Stanje na računu\n";
                        std::cout << "5) Otkaži rezervaciju\n";
                        std::cout << "6) Sistem lojalnosti \n";
                        std::cout << "7) Izbriši račun\n";
                        std::cout << "8) Odjava\n";
                        
                    }
                    //std::cout << "0) Nazad na početni meni\n> ";
                    std::string op2; std::getline(std::cin, op2);
                    //if (op2=="0") { break; }

                    if (role!="admin" && op2=="1") {
                        do_list_services(true /*za sesijski kompleks*/);
                        wait_enter();
                    }
                    else if (role!="admin" && op2=="2") {
                        do_get_hours();
                        wait_enter();
                    }
                    else if (role!="admin" && op2=="3") {
                        do_reserve_menu();
                        wait_enter();
                    }
                    else if (role!="admin" && op2=="4") {
                        do_balance_menu();
                        wait_enter();
                    }
                    else if (role!="admin" && op2=="5") {
                        do_cancel();
                        wait_enter();
                    }
                    else if (role!="admin" && op2=="6") {
                        do_check_loyalty();
                        wait_enter();
                    }
                    else if (role!="admin" && op2=="7") {
                        // DELETE_ACCOUNT
                        json req = {{"cmd","DELETE_ACCOUNT"}};
                        send_line(sock, req.dump());
                        auto j = read_json_line(sock);
                        if(j && j->value("ok", false)){
                          std::cout << j->value("msg","Vaš račun je obrisan!") << "\n";
                          break;
                        } else {
                        std::cout << "Greška: " << j->value("error","") << "\n";
                          
                        }
                        wait_enter();
                    }
                    else if ((role=="admin" && op2=="5") || (role!="admin" && op2=="8")) {
                        // LOGOFF → *uvijek* pokaži “Pritisnite ENTER…” i tek onda nazad na DOBRODOŠLI
                        json req = {{"cmd","LOGOFF"}};
                        send_line(sock, req.dump());
                        auto j = read_json_line(sock);
                        if (j && j->value("ok",false)) {
                            std::cout << "Odjavili ste se.\n";
                        } else {
                            std::cout << (j ? pretty(*j) : "Greška") << "\n";
                        }
                        //if (notifier) { notifier->stop(); notifier.reset(); }
                        role.clear();
                        wait_enter();
                             // <<<<<<<<<<<<<< ostaje: vraća na DOBRODOŠLI nakon ENTER
                        break;               // izađi iz user/admin menija → pokaži opet DOBRODOŠLI
                    } else if (role=="admin" && op2=="1") {
                    std::string loc = ask("Kompleks (A/B)");
                    std::string from= ask("Od (HH:MM:SS)");
                    std::string to  = ask("Do (HH:MM:SS)");
                    json req = {{"cmd","UPDATE_HOURS"},{"location",loc},{"from",from},{"to",to}};
                    send_line(sock, req.dump());
                    auto j = read_json_line(sock);
                    if(j && j->value("ok", false)){
                          std::cout << j->value("msg","Radno vrijeme uspješno ažurirano!") << "\n"<< "\n";
                    } else {
                      std::cout << (j ? pretty(*j) : "Greška") << "\n";
                    }
                    
                } else if (role=="admin" && op2=="2") {
                    std::string k = ask("Kompleks (A/B)");
                    std::string u = ask("Usluga (npr. Fudbal)");
                    std::string cap = ask("Novi kapacitet");
                    json req = {{"cmd","UPDATE_CAPACITY"},{"kompleks",k},{"usluga",u},{"novi_kapacitet", std::stoi(cap)}};
                    send_line(sock, req.dump());
                    auto j = read_json_line(sock);
                    if(j && j->value("ok", false)){
                          std::cout << j->value("msg","Kapacitet je uspješno ažuriran!") << "\n"<< "\n";
                    } else {
                      std::cout << (j ? pretty(*j) : "Greška") << "\n";
                    }
                } else if (role=="admin" && op2=="3") {
                    std::string k = ask("Kompleks (A/B)");
                    std::string u = ask("Usluga");
                    std::string p = ask("Nova cijena");
                    json req = {{"cmd","UPDATE_PRICES"},{"lokacija",k},{"usluga",u},{"nova_cijena", std::stod(p)}};
                    send_line(sock, req.dump());
                    auto j = read_json_line(sock);
                    if(j && j->value("ok", false)){
                          std::cout << j->value("msg","Cijena uspješno ažurirana!") << "\n"<< "\n";
                    } else {
                      std::cout << (j ? pretty(*j) : "Greška") << "\n";
                    }
                } else if (role=="admin" && op2=="4") {
                    std::string txt = ask("Reklamna poruka");
                    json req = {{"cmd","SEND_PROMO"},{"message",txt}};
                    send_line(sock, req.dump());
                    auto j = read_json_line(sock);
                    if (j && j->value("ok",false)) std::cout << "Reklamna poruka poslana.\n"<< "\n";
                    else std::cout << "X" << (j? j->value("error",""):"error") << "\n";
                }
                }
            } else if (op=="3") {
              std::cout << "A) Sportski kompleks Sarajevo\n";
              std::cout << "B) Sportski kompleks Sanski Most\n> ";
              wait_enter();
            }
            else if (op=="2") {
                do_register();
                if (role.empty()) { wait_enter(); continue; }
                for (;;) {
                    std::cout << "\n=== GLAVNI MENI ===\n";
                    std::cout << "1) Prikaz usluga\n";
                    std::cout << "2) Prikaz radnog vremena kompleksa\n";
                    std::cout << "3) Rezerviši termin\n";
                    std::cout << "4) Stanje na računu\n";
                    std::cout << "5) Otkaži rezervaciju\n";
                    if (role=="admin") {
                        std::cout << "6) Administratorske opcije\n";
                        std::cout << "7) Izbriši račun\n";
                        std::cout << "8) Odjava\n";
                    } else {
                        std::cout << "6) Izbriši račun\n";
                        std::cout << "7) Odjava\n";
                    }
                    //std::cout << "0) Nazad na početni meni\n> ";
                    std::string op2; std::getline(std::cin, op2);
                    //if (op2=="0") { break; }

                    if (op2=="1") {
                        do_list_services(true /*za sesijski kompleks*/);
                        wait_enter();
                    }
                    else if (op2=="2") {
                        do_get_hours();
                        wait_enter();
                    }
                    else if (op2=="3") {
                        do_reserve_menu();
                        wait_enter();
                    }
                    else if (op2=="4") {
                        do_balance_menu();
                        wait_enter();
                    }
                    else if (op2=="5") {
                        do_cancel();
                        wait_enter();
                    }
                    else if ((role=="admin" && op2=="7") || (role!="admin" && op2=="6")) {
                        // DELETE_ACCOUNT
                        json req = {{"cmd","DELETE_ACCOUNT"}};
                        send_line(sock, req.dump());
                        auto j = read_json_line(sock);
                        std::cout << (j ? "Vaš račun je obrisan!" : "Greška") << "\n";
                        wait_enter();
                        break;
                    }
                    else if ((role=="admin" && op2=="8") || (role!="admin" && op2=="7")) {
                        // LOGOFF → *uvijek* pokaži “Pritisnite ENTER…” i tek onda nazad na DOBRODOŠLI
                        json req = {{"cmd","LOGOFF"}};
                        send_line(sock, req.dump());
                        auto j = read_json_line(sock);
                        if (j && j->value("ok",false)) {
                            std::cout << "Odjavili ste se.\n";
                        } else {
                            std::cout << (j ? pretty(*j) : "Greška") << "\n";
                        }
                        //if (notifier) { notifier->stop(); notifier.reset(); }
                        role.clear();
                        wait_enter();
                             // <<<<<<<<<<<<<< ostaje: vraća na DOBRODOŠLI nakon ENTER
                        break;               // izađi iz user/admin menija → pokaži opet DOBRODOŠLI
                    }
                }
            }
        }

        if (notifier) { notifier->stop(); notifier.reset(); }
        std::cout << "Kraj.\n";

    } catch (const std::exception& e) {
        std::cerr << "Greška: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

