#pragma once
// Db.hpp - MySQL helper for SDP Project 2
#include <mysql/mysql.h>
#include <nlohmann/json.hpp>
#include <string>
#include <optional>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <cstring>
#include <iomanip>

using json = nlohmann::json;

struct Db {
    MYSQL* conn {nullptr};

    inline static const char* DB_HOST = "127.0.0.1";
    inline static unsigned    DB_PORT = 3306;
    inline static const char* DB_USER = "sdp";
    inline static const char* DB_PASS = "Sdp!12345";
    inline static const char* DB_NAME = "Sportski_tereni";

    Db() {
        conn = mysql_init(nullptr);
        if (!conn) throw std::runtime_error("mysql_init failed");
        if (!mysql_real_connect(conn, DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT, nullptr, 0)) {
            throw std::runtime_error(std::string("MySQL connect failed: ") + mysql_error(conn));
        }
        mysql_autocommit(conn, 1);
    }
    ~Db() { if (conn) mysql_close(conn); }

    
    MYSQL_STMT* prep(const char* sql) {
        MYSQL_STMT* st = mysql_stmt_init(conn);
        if (!st) throw std::runtime_error("mysql_stmt_init failed");
        if (mysql_stmt_prepare(st, sql, (unsigned long)std::strlen(sql)) != 0) {
            std::string err = mysql_error(conn);
            mysql_stmt_close(st);
            throw std::runtime_error("mysql_stmt_prepare failed: " + err);
        }
        return st;
    }
bool login_user(const std::string& email, const std::string& pass);

    
    bool email_exists(const std::string& email) {
        std::ostringstream q;
        q << "SELECT id FROM Korisnici WHERE e_mail='" << email << "' LIMIT 1;";
        if (mysql_query(conn, q.str().c_str()) != 0) return false;
        MYSQL_RES* res = mysql_store_result(conn);
        if (!res) return false;
        bool exists = mysql_num_rows(res) > 0;
        mysql_free_result(res);
        return exists;
    }

    bool uri_exists(const std::string& uri) {
        std::ostringstream q;
        q << "SELECT id FROM Korisnici WHERE uri='" << uri << "' LIMIT 1;";
        if (mysql_query(conn, q.str().c_str()) != 0) return false;
        MYSQL_RES* res = mysql_store_result(conn);
        if (!res) return false;
        bool exists = mysql_num_rows(res) > 0;
        mysql_free_result(res);
        return exists;
    }

    
    json working_hours_all() {
        const char* sql = "SELECT lokacija, vrijeme_od, vrijeme_do FROM RadnoVrijeme";
        if (mysql_query(conn, sql) != 0) {
            throw std::runtime_error(mysql_error(conn));
        }
        MYSQL_RES* res = mysql_store_result(conn);
        if (!res) return json::array();

        json arr = json::array();
        MYSQL_ROW row;
        while ((row = mysql_fetch_row(res))) {
            json obj;
            obj["lokacija"] = row[0] ? row[0] : "";
            obj["from"]     = row[1] ? row[1] : "";
            obj["to"]       = row[2] ? row[2] : "";
            arr.push_back(obj);
        }
        mysql_free_result(res);
        return arr;
    }

    bool update_hours(const std::string& location,
                      const std::string& from,
                      const std::string& to) {
        std::ostringstream q;
        q << "UPDATE RadnoVrijeme "
          << "SET vrijeme_od='" << from << "', vrijeme_do='" << to << "' "
          << "WHERE lokacija='" << location << "'";
        if (mysql_query(conn, q.str().c_str()) != 0) return false;
        return mysql_affected_rows(conn) > 0;
    }

    

    // --- users ---
    std::optional<int> user_id_by_email(const std::string& email) {
        const char* sql = "SELECT id FROM Korisnici WHERE e_mail=?";
        MYSQL_STMT* st = prep(sql);
        MYSQL_BIND b[1]{}; 
        b[0].buffer_type=MYSQL_TYPE_STRING; b[0].buffer=(void*)email.c_str(); b[0].buffer_length=(unsigned long)email.size();
        mysql_stmt_bind_param(st, b);
        if (mysql_stmt_execute(st)!=0) { mysql_stmt_close(st); return std::nullopt; }
        int uid=0; MYSQL_BIND r[1]{}; r[0].buffer_type=MYSQL_TYPE_LONG; r[0].buffer=&uid;
        mysql_stmt_bind_result(st, r);
        std::optional<int> out; if (mysql_stmt_fetch(st)==0) out=uid;
        mysql_stmt_close(st);
        return out;
    }

    
    

    
    
int get_user_id_by_email(const std::string& email) {
    int uid = 0;
    std::string q = "SELECT id FROM Korisnici WHERE e_mail='" + email + "' LIMIT 1;";
    if (mysql_query(conn, q.c_str()) == 0) {
        if (MYSQL_RES* r = mysql_store_result(conn)) {
            if (MYSQL_ROW row = mysql_fetch_row(r)) if (row[0]) uid = std::atoi(row[0]);
            mysql_free_result(r);
        }
    }
    return uid;
}


bool get_usluga_info_by_termin(int termin_id,
                               int& id_kompleksa,
                               std::string& naziv_usluge,
                               int& max_igraca,
                               double& cijena,
                               double& trajanje,
                               std::string& datum,
                               std::string& vrijeme) {
    id_kompleksa = 0; max_igraca = 0; cijena = 0.0; trajanje = 0.0;
    naziv_usluge.clear(); datum.clear(); vrijeme.clear();

    std::string q =
        "SELECT u.id_kompleksa, u.naziv, u.max_igraca, "
        "u.cijena_pojedinacnog_termina, u.trajanje_pojedinacnog_termina, "
        "t.datum, t.vrijeme "
        "FROM Termini t "
        "JOIN Usluge u ON u.naziv=t.tip_usluge "
        "WHERE t.id=" + std::to_string(termin_id) + " LIMIT 1;";

    if (mysql_query(conn, q.c_str()) != 0) return false;

    bool ok = false;
    if (MYSQL_RES* r = mysql_store_result(conn)) {
        if (MYSQL_ROW row = mysql_fetch_row(r)) {
            if (row[0]) id_kompleksa  = std::atoi(row[0]);
            if (row[1]) naziv_usluge  = row[1];
            if (row[2]) max_igraca    = std::atoi(row[2]);
            if (row[3]) cijena        = std::atof(row[3]);
            if (row[4]) trajanje      = std::atof(row[4]);
            if (row[5]) datum         = row[5];
            if (row[6]) vrijeme       = row[6];
            ok = true;
        }
        mysql_free_result(r);
    }
    return ok;
}


int count_reservations_for_termin(int termin_id) {
    int cnt = 0;
    std::string q =
    "SELECT COUNT(*) FROM Rezervacije WHERE termin_id=" + std::to_string(termin_id) + ";";

    if (mysql_query(conn, q.c_str()) == 0) {
        if (MYSQL_RES* r = mysql_store_result(conn)) {
            if (MYSQL_ROW row = mysql_fetch_row(r)) if (row[0]) cnt = std::atoi(row[0]);
            mysql_free_result(r);
        }
    }
    return cnt;
}

// korisnik ima rezervaciju u isto vrijeme
bool user_has_overlap_dt(int korisnik_id, const std::string& datum, const std::string& vrijeme) {
    
    {
        std::ostringstream q1;
        q1 << "SELECT 1 FROM Termini "
           << "WHERE korisnik_id=" << korisnik_id
           << " AND datum='" << sql_escape(conn, datum) << "'"
           << " AND vrijeme='" << sql_escape(conn, vrijeme) << "'"
           << " LIMIT 1;";
        if (mysql_query(conn, q1.str().c_str()) != 0) {
            std::cerr << "[user_has_overlap_dt/dup] " << mysql_error(conn) << "\nQuery: " << q1.str() << "\n";
            return true; // konzervativno: blokiraj
        }
        if (MYSQL_RES* r = mysql_store_result(conn)) {
            bool dup = mysql_num_rows(r) > 0;
            mysql_free_result(r);
            if (dup) return true;
        }
    }

    // 2) Provjera preklapanja po trajanju
    std::ostringstream q2;
    q2 << "SELECT 1 "
       << "FROM Termini r "
       << "JOIN Usluge u ON u.naziv = r.tip_usluge "
       << "WHERE r.korisnik_id=" << korisnik_id << " "
       << "AND r.datum='" << sql_escape(conn, datum) << "' "
       << "AND ( "
       << "  TIME('" << sql_escape(conn, vrijeme) << "') < ADDTIME(r.vrijeme, SEC_TO_TIME(u.trajanje_pojedinacnog_termina*3600)) "
       << "  AND r.vrijeme < ADDTIME(TIME('" << sql_escape(conn, vrijeme) << "'), SEC_TO_TIME(u.trajanje_pojedinacnog_termina*3600)) "
       << ") "
       << "LIMIT 1;";

    if (mysql_query(conn, q2.str().c_str()) != 0) {
        std::cerr << "[user_has_overlap_dt/overlap] " << mysql_error(conn) << "\nQuery: " << q2.str() << "\n";
        return true; 
    }
    bool exists = false;
    if (MYSQL_RES* r = mysql_store_result(conn)) {
        exists = (mysql_num_rows(r) > 0);
        mysql_free_result(r);
    }
    return exists;
}

bool user_has_overlap_with_others(int kid, const std::string& datum, const std::string& vrijeme, const std::string& usluga) {
    
    {
        std::ostringstream q1;
q1 << "SELECT 1 "
   << "FROM Usluge u "
   << "JOIN Termini t ON t.tip_usluge = u.naziv "
   << "WHERE u.id_kompleksa = " << kid << " "
   << "AND u.naziv = '" << sql_escape(conn, usluga) << "' "
   << "AND t.datum = '" << sql_escape(conn, datum) << "' "
   << "AND t.vrijeme = '" << sql_escape(conn, vrijeme) << "' "
   << "LIMIT 1;";

        if (mysql_query(conn, q1.str().c_str()) != 0) {
            std::cerr << "[user_has_overlap_with_others/dup] " << mysql_error(conn) << "\nQuery: " << q1.str() << "\n";
            return true; // konzervativno: blokiraj
        }
        if (MYSQL_RES* r = mysql_store_result(conn)) {
            bool dup = mysql_num_rows(r) > 0;
            mysql_free_result(r);
            if (dup) return true;
        }
    }

    // 2) Provjera preklapanja po trajanju
    std::ostringstream q2;
    q2 << "SELECT 1 "
       << "FROM Termini r "
       << "JOIN Usluge u ON u.naziv = r.tip_usluge "
       << "WHERE r.datum='" << sql_escape(conn, datum) << "' "
       << "AND ( "
       << "  TIME('" << sql_escape(conn, vrijeme) << "') < ADDTIME(r.vrijeme, SEC_TO_TIME(u.trajanje_pojedinacnog_termina*3600)) "
       << "  AND r.vrijeme < ADDTIME(TIME('" << sql_escape(conn, vrijeme) << "'), SEC_TO_TIME(u.trajanje_pojedinacnog_termina*3600)) "
       << ") "
       << "LIMIT 1;";

    if (mysql_query(conn, q2.str().c_str()) != 0) {
        std::cerr << "[user_has_overlap_with_others/overlap] " << mysql_error(conn) << "\nQuery: " << q2.str() << "\n";
        return true; // konzervativno: blokiraj
    }
    bool exists = false;
    if (MYSQL_RES* r = mysql_store_result(conn)) {
        exists = (mysql_num_rows(r) > 0);
        mysql_free_result(r);
    }
    return exists;
}





bool insert_reservation(int termin_id, int korisnik_id) {
    std::ostringstream q;
q << "INSERT INTO Rezervacije (korisnik_id, termin_id) "
  << "VALUES (" << korisnik_id << ", " << termin_id << ");";


    return (mysql_query(conn, q.str().c_str()) == 0);
}



static std::string sql_escape(MYSQL* c, const std::string& s) {
    std::string out;
    out.resize(s.size() * 2 + 1);
    unsigned long n = mysql_real_escape_string(c, out.data(), s.c_str(),
                                               (unsigned long)s.size());
    out.resize(n);
    return out;
}

std::optional<int> insert_termin(int korisnik_id,
                                 const std::string& datum,
                                 const std::string& vrijeme,
                                 const std::string& tip_usluge,
                                 int kid)
{
    const std::string d  = sql_escape(conn, datum);
    const std::string v  = sql_escape(conn, vrijeme);
    const std::string tu = sql_escape(conn, tip_usluge);

    std::ostringstream q;
q << "INSERT INTO Termini (datum, vrijeme, tip_usluge, id_kompleksa, korisnik_id) "
  << "VALUES ('" << d << "', '" << v << "', '" << tu << "', "
  << kid << ", " << korisnik_id << ");";


    

    if (mysql_query(conn, q.str().c_str()) != 0) {
        std::cerr << "[insert_termin] MySQL error (" << mysql_errno(conn) << "): "
                  << mysql_error(conn) << "\n"
                  << "Query: " << q.str() << std::endl; 
        return std::nullopt;
    }

    long long_id = static_cast<long>(mysql_insert_id(conn));
    if (long_id <= 0) return std::nullopt;
    return static_cast<int>(long_id);
}




// +1 bonus bod korisniku
bool add_bonus_point(const std::string& email) {
    std::string q = "UPDATE Korisnici SET bonus_bodovi = bonus_bodovi + 1 WHERE e_mail='" + email + "';";
    return (mysql_query(conn, q.c_str()) == 0);
}

bool reserve_slot_multi(const std::string& email,
                        const std::string& time,
                        const std::string& date,
                        const std::string& usluga,
                        const int& kid,
                        std::string& reason)
{
    reason.clear();

    int uid = get_user_id_by_email(email);
    if (uid <= 0) { reason = "Korisnik nije pronađen."; return false; }

    int idk = 0, max_igraca = 0; 
    double cijena = 0.0, trajanje = 0.0;

    // Slot ne smije biti u prošlosti
    {
        std::string q = "SELECT (STR_TO_DATE(CONCAT('" + date + " ','" + time + "'), '%Y-%m-%d %H:%i:%s') < NOW())";
        if (mysql_query(conn, q.c_str()) == 0) {
            if (MYSQL_RES* r = mysql_store_result(conn)) {
                if (MYSQL_ROW row = mysql_fetch_row(r)) {
                    int in_past = row[0] ? std::atoi(row[0]) : 0;
                    mysql_free_result(r);
                    if (in_past) { reason = "Vrijeme je pogrešno."; return false; }
                } else {
                    mysql_free_result(r);
                }
            }
        }
    }

    
    {
        std::string start_h, end_h;
        
        if (get_hours_for_usluga(kid, usluga, start_h, end_h)) {
            if (!start_h.empty() && !end_h.empty()) {
                if (time <= start_h || time >= end_h) {
                    reason = "Teren nije dostupan u izabranom terminu."; return false;
                }
            }
        } else { reason = "Usluga ne postoji."; return false;}
    }

    // korisnik ne smije imati drugi termin u isto vrijeme
    if (user_has_overlap_dt(uid, date, time)) { reason = "Termin se preklapa sa već postojećim!"; return false; }
    
    if (user_has_overlap_with_others(kid, date, time, usluga)) { reason = "Termin je već rervisan!"; return false; }

    std::string qPrice =
    "SELECT cijena_pojedinacnog_termina FROM Usluge "
    "WHERE id_kompleksa = " + std::to_string(kid) + " "
    "AND naziv = '" + sql_escape(conn, usluga) + "' "
    "LIMIT 1;";

if (mysql_query(conn, qPrice.c_str()) != 0) { reason = mysql_error(conn); return false; }

double price = 0.0;
if (MYSQL_RES* r = mysql_store_result(conn)) {
    if (MYSQL_ROW row = mysql_fetch_row(r)) {
        price = row[0] ? std::atof(row[0]) : 0.0;
    }
    mysql_free_result(r);
}
if (price <= 0.0) { reason = "Neispravan unos."; return false; }

mysql_autocommit(conn, 0); // BEGIN

{
    std::string qUser =
        "SELECT stanje_na_racunu FROM Korisnici "
        "WHERE id = " + std::to_string(uid) + " FOR UPDATE;";

    if (mysql_query(conn, qUser.c_str()) != 0) {
        reason = mysql_error(conn); mysql_rollback(conn); mysql_autocommit(conn, 1); return false;
    }
}

double money = 0.0;
{
    MYSQL_RES* r = mysql_store_result(conn);
    if (!r) { reason = "Korisnik nije pronađen."; mysql_rollback(conn); mysql_autocommit(conn, 1); return false; }
    MYSQL_ROW row = mysql_fetch_row(r);
    if (!row) { mysql_free_result(r); reason = "Korisnik nije pronađen."; mysql_rollback(conn); mysql_autocommit(conn, 1); return false; }
    money = row[0] ? std::atof(row[0]) : 0.0;
    mysql_free_result(r);
}

std::string qLots =
    "SELECT id, iznos, iskoristeni_iznos "
    "FROM BonusPoeni "
    "WHERE korisnik_id = " + std::to_string(uid) + " "
    "  AND datum_isteka > NOW() "
    "  AND iskoristeni_iznos < iznos "
    "ORDER BY datum_isteka ASC, id ASC "
    "FOR UPDATE;";

if (mysql_query(conn, qLots.c_str()) != 0) {
    reason = mysql_error(conn); mysql_rollback(conn); mysql_autocommit(conn, 1); return false;
}

struct Lot { long long id; int qty; int consumed; };
std::vector<Lot> lots;
{
    MYSQL_RES* r = mysql_store_result(conn);
    if (r) {
        MYSQL_ROW row;
        while ((row = mysql_fetch_row(r))) {
            Lot L{};
            L.id       = row[0] ? std::strtoll(row[0], nullptr, 10) : 0;
            L.qty      = row[1] ? std::atoi(row[1]) : 0;
            L.consumed = row[2] ? std::atoi(row[2]) : 0;
            lots.push_back(L);
        }
        mysql_free_result(r);
    }
}


int available = 0;
for (const auto& L : lots) available += (L.qty - L.consumed);

bool use_loyalty = (available >= 3);
double effective_price = use_loyalty ? (price / 2.0) : price;


if (money + 1e-9 < effective_price) {
    mysql_rollback(conn); mysql_autocommit(conn, 1);
    reason = "Nemate dovoljno sredstava!";
    return false;
}

if (use_loyalty) {
    int need = 3;
    for (auto& L : lots) {
        if (need <= 0) break;
        int rem = L.qty - L.consumed;
        if (rem <= 0) continue;

        int use = (rem < need) ? rem : need;

        std::ostringstream qUse;
        qUse << "UPDATE BonusPoeni SET iskoristeni_iznos = iskoristeni_iznos + " << use
             << " WHERE id = " << L.id << ";";
        if (mysql_query(conn, qUse.str().c_str()) != 0) {
            reason = mysql_error(conn); mysql_rollback(conn); mysql_autocommit(conn, 1); return false;
        }
        need -= use;
    }
    
    if (need > 0) {
        mysql_rollback(conn); mysql_autocommit(conn, 1);
        reason = "Nemoguće iskoristiti bonus poene!";
        return false;
    }
}


{
    std::ostringstream qUpd;
    qUpd << "UPDATE Korisnici SET "
         << "stanje_na_racunu = stanje_na_racunu - " << std::fixed << std::setprecision(2) << effective_price << " "
         << "WHERE id = " << uid << ";";
    if (mysql_query(conn, qUpd.str().c_str()) != 0) {
        reason = mysql_error(conn); mysql_rollback(conn); mysql_autocommit(conn, 1); return false;
    }
}

{
    std::ostringstream qAward;
    qAward << "INSERT INTO BonusPoeni (korisnik_id, iznos, iskoristeni_iznos, datum_zarade, datum_isteka) "
           << "VALUES (" << uid << ", 1, 0, NOW(), NOW() + INTERVAL 30 DAY);";
    if (mysql_query(conn, qAward.str().c_str()) != 0) {
        reason = mysql_error(conn); mysql_rollback(conn); mysql_autocommit(conn, 1); return false;
    }
}

if (mysql_commit(conn) != 0) {
    reason = mysql_error(conn); mysql_rollback(conn); mysql_autocommit(conn, 1); return false;
}
mysql_autocommit(conn, 1);

    auto maybe_tid = insert_termin(uid, date, time, usluga, kid);
if (!maybe_tid) {
    reason = "Neispravan unos termina.";
    return false;
}
int termin_id = *maybe_tid;

    
    
    if (!insert_reservation(termin_id, uid)) {
        
        reason = "Već rezervisan termin!";
        return false;
    }

    

    return true;
}

bool get_hours_for_usluga(int id_kompleksa,
                          const std::string& usluga,
                          std::string& start_hhmmss,
                          std::string& end_hhmmss)
{
    start_hhmmss.clear();
    end_hhmmss.clear();

    std::string lok;
    if      (id_kompleksa == 1) lok = "Kompleks_A";
    else if (id_kompleksa == 2) lok = "Kompleks_B";
    else return false;

    std::string q =
    "SELECT dostupnost_od, dostupnost_do "
    "FROM Usluge "
    "WHERE id_kompleksa = " + std::to_string(id_kompleksa) +
    " AND naziv = '" + usluga + "';";

    if (mysql_query(conn, q.c_str()) != 0) return false;

    bool ok = false;
    if (MYSQL_RES* r = mysql_store_result(conn)) {
        if (MYSQL_ROW row = mysql_fetch_row(r)) {
            if (row[0]) start_hhmmss = row[0];
            if (row[1]) end_hhmmss   = row[1];
            ok = !start_hhmmss.empty() && !end_hhmmss.empty();
        }
        mysql_free_result(r);
    }
    return ok;
}

};

