// Build: g++ -std=c++11 test.cpp -o test -lssl -lcrypto -lpthread

#define BOOST_TEST_MODULE SportskiKompleksi_test
#include <boost/test/included/unit_test.hpp>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <string>
#include <sstream>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <ctime>
#include <regex>

using boost::asio::ip::tcp;
namespace ssl = boost::asio::ssl;

// ------------------ helperi ------------------
static const char* env_or(const char* k, const char* def) {
    const char* v = std::getenv(k);
    return (v && *v) ? v : def;
}
static std::string HOST() { return env_or("HOST", "100.100.129.70"); }
static std::string PORT() { return env_or("PORT", "5555"); }

static std::string uniq() {
    return std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
}

// ------------------  helperi ------------------
static std::string tomorrow_date() {
    using namespace std::chrono;
    auto now = system_clock::now() + hours(24);
    std::time_t tt = system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &tt);
#else
    localtime_r(&tt, &tm);
#endif
    char buf[11]; // "YYYY-MM-DD" + '\0'
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%d", &tm) == 0) {
        return "2099-01-01";
    }
    return buf;
}

static int hhmm_to_min(const std::string& t) {
    int h=0,m=0;
    if (t.size() >= 5) {
        h = std::atoi(t.substr(0,2).c_str());
        m = std::atoi(t.substr(3,2).c_str());
    }
    return h*60+m;
}
static std::string min_to_hhmmss(int minutes) {
    if (minutes < 0) minutes = 0;
    if (minutes > 23*60+59) minutes = 23*60+59;
    int h = minutes/60, m = minutes%60;
    char buf[9];
    std::snprintf(buf, sizeof(buf), "%02d:%02d:00", h, m);
    return buf;
}

static std::string talk_once(const std::string& host,
                             const std::string& port,
                             const std::string& json_line) {
    boost::asio::io_context io;
    ssl::context ctx(ssl::context::tls_client);
    ctx.set_verify_mode(ssl::verify_none); 

    ssl::stream<tcp::socket> s(io, ctx);
    tcp::resolver res(io);
    auto it = res.resolve(host, port);
    boost::asio::connect(s.lowest_layer(), it);
    s.handshake(ssl::stream_base::client);

    std::string line = json_line;
    if (line.empty() || line.back() != '\n') line.push_back('\n');
    boost::asio::write(s, boost::asio::buffer(line));

    boost::asio::streambuf buf;
    boost::asio::read_until(s, buf, '\n');
    std::istream is(&buf);
    std::string reply;
    std::getline(is, reply);
    return reply;
}

// ------------------ Session klijent ------------------
struct TlsLineClient {
    boost::asio::io_context  io;
    ssl::context             ctx;
    ssl::stream<tcp::socket> sock;

    TlsLineClient(const std::string& host, const std::string& port)
        : ctx(ssl::context::tls_client), sock(io, ctx) {
        ctx.set_verify_mode(ssl::verify_none);
        tcp::resolver res(io);
        auto it = res.resolve(host, port);
        boost::asio::connect(sock.lowest_layer(), it);
        sock.handshake(ssl::stream_base::client);
    }

    std::string send_once(const std::string& json_line) {
        std::string line = json_line;
        if (line.empty() || line.back() != '\n') line.push_back('\n');
        boost::asio::write(sock, boost::asio::buffer(line));
        boost::asio::streambuf buf;
        boost::asio::read_until(sock, buf, '\n');
        std::istream is(&buf);
        std::string reply;
        std::getline(is, reply);
        return reply;
    }
};

// ------------------ helperi ------------------
static void expect_substr(const std::string& where, const char* needle) {
    if (where.find(needle) == std::string::npos) {
        std::cerr << "\n=== FULL RESPONSE ===\n" << where << "\n=====================\n";
        BOOST_CHECK_MESSAGE(false, std::string("nije pronađen substring: ") + needle);
    } else {
        BOOST_CHECK(true);
    }
}


struct TestUser {
    std::string email;
    std::string pass;
};

static TestUser create_user_in_db_first(const std::string& lok="A") {
    TestUser tu;
    tu.email = "amra+" + uniq() + "@example.com";
    tu.pass  = "lozinka123";
    std::ostringstream reg;
    reg << R"({"cmd":"REGISTER","email":")" << tu.email
        << R"(","password":")" << tu.pass
        << R"(","ime":"Amra","lokacija":")" << lok << R"("})";
    auto resp = talk_once(HOST(), PORT(), reg.str());
    // može biti OK ili već postoji -- bitno je da postoji korisnik
    return tu;
}

static std::string login(TlsLineClient& c, const TestUser& tu) {
    std::ostringstream login;
    login << R"({"cmd":"LOGIN","email":")" << tu.email
          << R"(","password":")" << tu.pass << R"("})";
    return c.send_once(login.str());
}

static void topup(TlsLineClient& c, double amount) {
    std::ostringstream ss;
    ss << R"({"cmd":"BALANCE_ADD","amount":)" << amount << "}";
    (void)c.send_once(ss.str());
}


static int extract_first_code(const std::string& json) {
    std::regex re("\"code\"\\s*:\\s*(\\d+)");
    std::smatch m;
    if (std::regex_search(json, m, re)) {
        return std::atoi(m[1].str().c_str());
    }
    return 0;
}


static bool extract_first_hours(const std::string& json, std::string& from, std::string& to) {
    std::regex from_re("\"from\"\\s*:\\s*\"([0-9]{2}:[0-9]{2}:[0-9]{2})\"");
    std::regex to_re  ("\"to\"\\s*:\\s*\"([0-9]{2}:[0-9]{2}:[0-9]{2})\"");
    std::smatch m1, m2;
    if (std::regex_search(json, m1, from_re) && std::regex_search(json, m2, to_re)) {
        from = m1[1].str();
        to   = m2[1].str();
        return true;
    }
    return false;
}

// ------------------ OSNOVNI TESTOVI ------------------

// 1) REGISTER – loš format e-maila 
BOOST_AUTO_TEST_CASE(register_invalid_email) {
    auto resp = talk_once(HOST(), PORT(),
        R"({"cmd":"REGISTER","email":"amra_at_example.com","password":"abcdefgh","ime":"Amra","lokacija":"Kompleks_A"})");
    expect_substr(resp, "\"ok\":false");
    expect_substr(resp, "Neispravan"); // dio poruke
    expect_substr(resp, "format");
}

// 2) REGISTER – prekratka lozinka (< 8)
BOOST_AUTO_TEST_CASE(register_short_password) {
    auto resp = talk_once(HOST(), PORT(),
        R"({"cmd":"REGISTER","email":"amra@example.com","password":"short","ime":"Amra","lokacija":"Kompleks_A"})");
    expect_substr(resp, "\"ok\":false");
    expect_substr(resp, "Password");
    expect_substr(resp, "8");
}

// 3) REGISTER – ispravno pa duplikat
BOOST_AUTO_TEST_CASE(register_ok_then_duplicate) {
    std::string em = "amra+" + uniq() + "@example.com";
    std::ostringstream req;
    req << R"({"cmd":"REGISTER","email":")" << em
        << R"(","password":"lozinka123","ime":"Amra","lokacija":"A"})";

    auto ok_resp  = talk_once(HOST(), PORT(), req.str());
    expect_substr(ok_resp, "\"ok\":true");

    auto dup_resp = talk_once(HOST(), PORT(), req.str());
    expect_substr(dup_resp, "\"ok\":false"); 
}

// 4) Reservation meni
BOOST_AUTO_TEST_CASE(session_register_then_reservation_menu) {
    auto tu = create_user_in_db_first();

    TlsLineClient c(HOST(), PORT());
    auto login_resp = login(c, tu);
    expect_substr(login_resp, "\"ok\":true");
    expect_substr(login_resp, "\"role\":\"user\"");

    auto menu_resp = c.send_once(R"({"cmd":"Reservation"})");
    expect_substr(menu_resp, "\"ok\":true");
    expect_substr(menu_resp, "\"menu\":\"reservation\"");
    expect_substr(menu_resp, "Odaberi način rezervacije");
}

// 5) GET_HOURS (lokacija "A")
BOOST_AUTO_TEST_CASE(session_register_then_get_hours) {
    auto tu = create_user_in_db_first();

    TlsLineClient c(HOST(), PORT());
    expect_substr(login(c, tu), "\"ok\":true");

    auto resp = c.send_once(R"({"cmd":"GET_HOURS","lokacija":"A"})");
    expect_substr(resp, "\"ok\":true");
    expect_substr(resp, "\"hours\"");
    
    if (resp.find("Radno vrijeme kompleksa") == std::string::npos) {

        expect_substr(resp, "Working hours");
    }
}

// 6) LIST_SERVICES
BOOST_AUTO_TEST_CASE(session_list_services) {
    auto tu = create_user_in_db_first();

    TlsLineClient c(HOST(), PORT());
    expect_substr(login(c, tu), "\"ok\":true");

    auto resp = c.send_once(R"({"cmd":"LIST_SERVICES"})");
    expect_substr(resp, "\"ok\":true");
    expect_substr(resp, "\"services\"");
}

// 7) LOGIN – loši kredencijali
BOOST_AUTO_TEST_CASE(login_bad_credentials) {
    auto resp = talk_once(HOST(), PORT(),
        R"({"cmd":"LOGIN","email":"nepostoji@example.com","password":"pogresna"})");
    expect_substr(resp, "\"ok\":false");
    expect_substr(resp, "Neispravni kredencijali");
}

// 8) BALANCE meni
BOOST_AUTO_TEST_CASE(session_balance_menu) {
    auto tu = create_user_in_db_first();

    TlsLineClient c(HOST(), PORT());
    expect_substr(login(c, tu), "\"ok\":true");

    auto resp = c.send_once(R"({"cmd":"Balance"})"); // alias → BALANCE_MENU
    expect_substr(resp, "\"ok\":true");
    expect_substr(resp, "\"menu\":\"balance\"");
    expect_substr(resp, "Check balance");
}

// 9) BALANCE_ADD pa BALANCE_CHECK
BOOST_AUTO_TEST_CASE(session_balance_add_then_check) {
    auto tu = create_user_in_db_first();

    TlsLineClient c(HOST(), PORT());
    expect_substr(login(c, tu), "\"ok\":true");

    auto add = c.send_once(R"({"cmd":"BALANCE_ADD","amount":12.5})");
    expect_substr(add, "\"ok\":true");

    if (add.find("Ažurirano stanje") == std::string::npos) {

        expect_substr(add, "Balance");
    }

    auto chk = c.send_once(R"({"cmd":"BALANCE_CHECK"})");
    expect_substr(chk, "\"ok\":true");
    expect_substr(chk, "\"balance\"");
}

// ------------------ DODATNI SCENARIJI ------------------

// A) Pokušaj admin komandi bez admin kredencijala
BOOST_AUTO_TEST_CASE(admin_actions_forbidden_for_regular_user) {
    auto tu = create_user_in_db_first();

    TlsLineClient c(HOST(), PORT());
    expect_substr(login(c, tu), "\"ok\":true");

    auto r1 = c.send_once(R"({"cmd":"UPDATE_HOURS","location":"A","from":"08:00:00","to":"22:00:00"})");
    expect_substr(r1, "\"ok\":false");

    if (r1.find("Zabranjeno") == std::string::npos &&
        r1.find("forbidden")  == std::string::npos) {
        expect_substr(r1, "admin");
    }

    auto r2 = c.send_once(R"({"cmd":"UPDATE_PRICES","lokacija":"A","usluga":"Fudbal","nova_cijena":12.0})");
    expect_substr(r2, "\"ok\":false");

    auto r3 = c.send_once(R"({"cmd":"UPDATE_CAPACITY","kompleks":"A","usluga":"Fudbal","novi_kapacitet":9})");
    expect_substr(r3, "\"ok\":false");
}

// B) Brisanje računa blokirano ako postoji aktivna rezervacija
BOOST_AUTO_TEST_CASE(delete_account_with_active_reservation_is_blocked) {
    auto tu = create_user_in_db_first(); // lokacija A

    TlsLineClient c(HOST(), PORT());
    expect_substr(login(c, tu), "\"ok\":true");


    topup(c, 50.0);


    // 1) probaj naći termin za Fudbal sutra
    std::string date = tomorrow_date();
    std::ostringstream chk;
    chk << R"({"cmd":"CHECK_MATCH","usluga":"Fudbal","date":")" << date << R"("})";
    auto list = c.send_once(chk.str());
    int code = extract_first_code(list);

    if (code == 0) {
        // Ako nema grupa, pokušaj kreirati rezervaciju termina (10:00)
        auto rr = c.send_once(std::string(R"({"cmd":"RESERVE","date":")") + date + R"(","time":"10:00:00","usluga":"Fudbal"})");
        if (rr.find("\"ok\":true") == std::string::npos) {
            // Ako ni to ne uspije, odustani 
            BOOST_TEST_MESSAGE("Preskačem: nije moguće napraviti aktivnu rezervaciju (nema termina / DB pravila).");
            BOOST_CHECK(true);
            return;
        }
        

        auto del = c.send_once(R"({"cmd":"DELETE_ACCOUNT"})");
        expect_substr(del, "\"ok\":false");

        if (del.find("aktivne") == std::string::npos) {
            expect_substr(del, "active");
        }
    } else {
        // Pridruži se postojećem terminu
        std::ostringstream join;
        join << R"({"cmd":"JOIN_MATCH","code":)" << code << "}";
        auto jresp = c.send_once(join.str());
        if (jresp.find("\"ok\":true") == std::string::npos) {
            BOOST_TEST_MESSAGE("Preskačem: JOIN_MATCH nije uspio (možda je termin pun).");
            BOOST_CHECK(true);
            return;
        }
        // Sad pokušaj brisanje računa
        auto del = c.send_once(R"({"cmd":"DELETE_ACCOUNT"})");
        expect_substr(del, "\"ok\":false");
        if (del.find("aktivne") == std::string::npos) {
            expect_substr(del, "active");
        }
    }
}

//  ALERT_NEED_PLAYER odbija ako korisnik nije u grupi termina 
BOOST_AUTO_TEST_CASE(alert_need_player_requires_membership) {
    auto tu = create_user_in_db_first();

    TlsLineClient c(HOST(), PORT());
    expect_substr(login(c, tu), "\"ok\":true");

    // pokušaj alert za nasumičan id (100000) – očekuje se odbijanje
    auto resp = c.send_once(R"({"cmd":"ALERT_NEED_PLAYER","code":100000})");
    expect_substr(resp, "\"ok\":false"); // poruka može biti "Niste u grupi termina." ili sl.
}



// E) Rezervacija u okviru radnog vremena
BOOST_AUTO_TEST_CASE(reservation_within_working_hours_positive) {
    auto tu = create_user_in_db_first();

    TlsLineClient c(HOST(), PORT());
    expect_substr(login(c, tu), "\"ok\":true");
    topup(c, 50.0);

    auto gh = c.send_once(R"({"cmd":"GET_HOURS","lokacija":"A"})");
    std::string from, to;
    if (!extract_first_hours(gh, from, to)) {
        BOOST_TEST_MESSAGE("Preskačem: ne mogu parsirati working hours.");
        BOOST_CHECK(true);
        return;
    }
    int fm = hhmm_to_min(from);
    int tm = hhmm_to_min(to);
    int mid = fm + std::max(30, (tm - fm)/2);
    std::string tmid = min_to_hhmmss(mid);

    auto rr = c.send_once(std::string(R"({"cmd":"RESERVE","date":")") + tomorrow_date() +
                          R"(","time":")" + tmid + R"(","usluga":"Fudbal"})");

    expect_substr(rr, "\"ok\":true");
}

// F) ne može se prijaviti dva puta na isti termin (JOIN_MATCH dva puta)
BOOST_AUTO_TEST_CASE(cannot_join_same_session_twice) {
    auto tu = create_user_in_db_first();

    TlsLineClient c(HOST(), PORT());
    expect_substr(login(c, tu), "\"ok\":true");

    // pronađi termin za Fudbal sutra
    std::string date = tomorrow_date();
    std::ostringstream chk;
    chk << R"({"cmd":"CHECK_MATCH","usluga":"Fudbal","date":")" << date << R"("})";
    auto list = c.send_once(chk.str());
    int code = extract_first_code(list);
    if (code == 0) {
        BOOST_FAIL("Nije pronađen termin za JOIN_MATCH test");
        return;
    }

    // prvi join – treba proći
    {
        std::ostringstream join;
        join << R"({"cmd":"JOIN_MATCH","code":)" << code << "}";
        auto r = c.send_once(join.str());
        expect_substr(r, "\"ok\":true");
    }
    // drugi join – treba biti odbijen
    {
        std::ostringstream join;
        join << R"({"cmd":"JOIN_MATCH","code":)" << code << "}";
        auto r = c.send_once(join.str());
        expect_substr(r, "\"ok\":false");
        // poruka može biti “Već imate…” ili “already…”
        if (r.find("Već") == std::string::npos && r.find("already") == std::string::npos) {
            expect_substr(r, "join");
        }
    }
}

// G) CANCEL zahtijeva confirm=false prvo, a dopušten je za vise od 1h prije početka
BOOST_AUTO_TEST_CASE(cancel_requires_confirm_and_allows_if_far_enough) {
    auto tu = create_user_in_db_first();

    TlsLineClient c(HOST(), PORT());
    expect_substr(login(c, tu), "\"ok\":true");

    // pronađi termin sutra i pridruži se
    std::string date = tomorrow_date();
    std::ostringstream chk;
    chk << R"({"cmd":"CHECK_MATCH","usluga":"Fudbal","date":")" << date << R"("})";
    auto list = c.send_once(chk.str());
    int code = extract_first_code(list);
    if (code == 0) {
        BOOST_FAIL("Nije pronađen termin za CANCEL test");
        return;
    }
    {
        std::ostringstream join;
        join << R"({"cmd":"JOIN_MATCH","code":)" << code << "}";
        auto r = c.send_once(join.str());
        if (r.find("\"ok\":true") == std::string::npos) {
            BOOST_TEST_MESSAGE("Preskačem: JOIN_MATCH nije uspio (možda je pun).");
            BOOST_CHECK(true);
            return;
        }
    }

    // 1) pozovi CANCEL bez confirm → očekuje se confirm_required=true
    {
        std::ostringstream can;
        can << R"({"cmd":"CANCEL","code":)" << code << "}";
        auto r = c.send_once(can.str());
        expect_substr(r, "\"ok\":true");
        expect_substr(r, "confirm_required");
    }
    // 2) sada confirm=true → očekuje se prolaz 
    {
        std::ostringstream can;
        can << R"({"cmd":"CANCEL","code":)" << code << R"(,"confirm":true})";
        auto r = c.send_once(can.str());
        expect_substr(r, "\"ok\":true");
        expect_substr(r, "reservation_canceled");
    }
}

