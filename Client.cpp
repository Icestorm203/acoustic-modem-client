#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <winsock2.h>
#include <Ws2tcpip.h>
#include <windows.h>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <thread>
#include <atomic>
#include <chrono>
#include <mutex>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")

using Clock = std::chrono::high_resolution_clock;

// ================== Logger ==================
class Logger {
    std::ofstream f;
    std::mutex    m;
public:
    Logger(const std::string& fn = "log.txt") {
        f.open(fn, std::ios::out);
    }
    void log(const std::string& event,
        int src, int dst,
        const std::string& cmd,
        const std::string& res,
        int size, int att,
        double dt = 0.0)
    {
        double ts = std::chrono::duration<double>(
            Clock::now().time_since_epoch()).count();
        std::lock_guard<std::mutex> lk(m);
        f << ts << " | "
            << event << " | "
            << "src=" << src << " "
            << "dst=" << dst << " | "
            << "cmd=" << cmd << " | "
            << "res=" << res << " | "
            << "size=" << size << " | "
            << "att=" << att << " | "
            << "dt(ms)=" << dt << "\n";
        f.flush();
    }
    void flush() {
        std::lock_guard<std::mutex> lk(m);
        f.flush();
    }
};

Logger* loggerPtr = nullptr;

// ================== Stats ==================
struct Stats {
    std::atomic<int>    sent{ 0 }, success{ 0 };
    std::vector<double> delays;
    std::mutex          m;
    int                 attempts{ 0 };

    void recordSend() {
        sent++; attempts++;
    }
    void recordReceive(bool ok, double dt) {
        if (!ok) return;
        success++;
        std::lock_guard<std::mutex> lk(m);
        delays.push_back(dt);
    }
    void printSummary() {
        double pdr = sent ? 100.0 * success / sent : 0.0;
        double avg = 0.0;
        {
            std::lock_guard<std::mutex> lk(m);
            for (auto d : delays) avg += d;
            if (!delays.empty()) avg /= delays.size();
        }
        std::cout << "\n=== Summary ===\n"
            << "Sent:    " << sent << "\n"
            << "Success: " << success << "\n"
            << "PDR (%): " << pdr << "\n"
            << "Avg delay(ms): " << avg << "\n";
    }
} stats;

std::atomic<bool> running(true);

enum class SendMode { RAW = 0, DACAP = 1 };
enum class DacapCmd { PAYLOAD = 0, RTS = 1, CTS = 2 };

// ================== DACAP Packet ==================
struct DacapPacket {
    SendMode    mode{ SendMode::RAW };
    DacapCmd    cmd{ DacapCmd::PAYLOAD };
    double      ts{ 0.0 };
    std::string payload;

    std::string serialize() const {
        std::ostringstream oss;
        oss.imbue(std::locale::classic());
        std::string safePayload = payload;
        std::replace(safePayload.begin(), safePayload.end(), ';', '|');

        oss << int(mode) << ";" << int(cmd) << ";" << ts << ";" << safePayload;
        return oss.str();
    }

    static bool parse(const std::string& s, DacapPacket& out) {
        std::vector<std::string> parts;
        std::istringstream ss(s);
        std::string fld;
        while (std::getline(ss, fld, ';'))
            parts.push_back(fld);
        if (parts.size() < 3)
            return false;

        out.mode = SendMode(std::stoi(parts[0]));
        out.cmd = DacapCmd(std::stoi(parts[1]));
        out.ts = std::stod(parts[2]);
        out.payload.clear();
        if (parts.size() >= 4)
            out.payload = parts[3];

        std::replace(out.payload.begin(), out.payload.end(), '|', ';');
        return true;
    }
};

// ================== RECVIM Parser ==================
struct Recvim {
    int    length{ 0 }, src{ 0 }, dst{ 0 };
    std::string flag, dur, rssi, integ, vel, data;
};

static std::vector<std::string> split(const std::string& s, char d) {
    std::vector<std::string> res;
    std::istringstream ss(s);
    std::string t;
    while (std::getline(ss, t, d))
        res.push_back(t);
    return res;
}

bool parseRecvim(const std::string& m, Recvim& out) {
    if (m.rfind("RECVIM,", 0) != 0)
        return false;
    auto v = split(m, ',');
    if (v.size() < 12)
        return false;

    std::string d;
    for (size_t i = 9; i < v.size(); ++i) {
        if (i > 9) d.push_back(',');
        d += v[i];
    }
    while (!d.empty() && (d.back() == '\r' || d.back() == '\n'))
        d.pop_back();
    out.data = d;
    out.length = int(d.size());

    out.src = std::stoi(v[2]);
    out.dst = std::stoi(v[3]);
    out.flag = v[4];
    out.dur = v[5];
    out.rssi = v[6];
    out.integ = v[7];
    out.vel = v[8];
    return true;
}

// ================== Distance & Backoff ==================
double estimateDistance(double rtt_ms) {
    const double c = 1500.0;
    return (rtt_ms / 1000.0) * c / 2.0;
}

double computeBackoff(int sz, double dist) {
    const double c = 1500.0, tmin = 0.05, rate = 1000.0;
    double tdata = sz * 8.0 / rate;
    return 2 * dist / c + tdata + tmin;
}

// ================== Build SENDIM ==================
std::string buildSend(int dst,
    const std::string& ackText,
    const std::string& txt,
    SendMode mode,
    DacapCmd cmd)
{
    double ts = std::chrono::duration<double>(
        Clock::now().time_since_epoch()).count();

    std::string payload = (mode == SendMode::RAW
        ? txt
        : DacapPacket{ mode, cmd, ts, txt }.serialize());

    int sz = int(payload.size());

    return "AT*SENDIM," +
        std::to_string(sz) + "," +
        std::to_string(dst) + "," +
        ackText + "," +
        payload + "\n";
}

// ================== Protocol Handler ==================
void handleProtocol(const Recvim& r, int myAddr, SOCKET sock, SendMode mode) {
    DacapPacket pkt;
    bool ok = DacapPacket::parse(r.data, pkt);
    if (!ok || pkt.mode != SendMode::DACAP) return;

    double now = std::chrono::duration<double>(Clock::now().time_since_epoch()).count();
    double rtt = (now - pkt.ts) * 1000.0;
    double dist = estimateDistance(rtt);

    loggerPtr->log("RECV", r.src, r.dst,
        pkt.cmd == DacapCmd::RTS ? "RTS"
        : pkt.cmd == DacapCmd::CTS ? "CTS"
        : "DATA",
        "OK", r.length, stats.attempts, rtt);
    stats.recordReceive(true, rtt);

    if (pkt.cmd == DacapCmd::RTS) {
        if (r.dst == myAddr) {
            auto l = buildSend(r.src, "ack", "", SendMode::DACAP, DacapCmd::CTS);
            send(sock, l.c_str(), int(l.size()), 0);
            loggerPtr->log("SEND", myAddr, r.src, "CTS", "OK", int(l.size()), ++stats.attempts);
        }
        else {
            double b = computeBackoff(int(pkt.payload.size()), dist);
            std::this_thread::sleep_for(std::chrono::duration<double>(b));
            loggerPtr->log("BACKOFF", r.src, r.dst, "RTS", "WAIT",
                int(pkt.payload.size()), ++stats.attempts, b * 1000.0);
        }
    }
    else if (pkt.cmd == DacapCmd::CTS) {
        if (r.dst == myAddr) {
            std::string txt = "Hello_to_" + std::to_string(myAddr);
            auto l = buildSend(r.src, "ack", txt, SendMode::DACAP, DacapCmd::PAYLOAD);
            send(sock, l.c_str(), int(l.size()), 0);
            loggerPtr->log("SEND", myAddr, r.src, "DATA", "OK", int(l.size()), ++stats.attempts);
        }
    }
    else if (pkt.cmd == DacapCmd::PAYLOAD) {
        if (r.dst == myAddr) {
            std::cout << "[DATA] from " << r.src << ": " << pkt.payload << "\n";
        }
    }
}

void receiver(SOCKET sock, SendMode mode, int myAddr) {
    while (running) {
        char buf[2048];
        int n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        buf[n] = 0;
        std::string msg(buf, n);

        if (msg.rfind("DELIVERED,", 0) == 0) continue;
        if (msg.rfind("MESSAGE_FORMAT_ERROR", 0) == 0) continue;

        Recvim r;
        if (parseRecvim(msg, r) && mode == SendMode::DACAP)
            handleProtocol(r, myAddr, sock, mode);

        std::cout << "Enter dest addr: ";
    }
}

BOOL WINAPI consoleHandler(DWORD c) {
    if (c == CTRL_CLOSE_EVENT ||
        c == CTRL_LOGOFF_EVENT ||
        c == CTRL_SHUTDOWN_EVENT)
    {
        loggerPtr->log("SYSTEM", 0, 0, "EXIT", "OK", 0, 0, 0.0);
        loggerPtr->flush();
        stats.printSummary();
        Sleep(100);
    }
    return FALSE;
}

// ================== MAIN ==================
int main(int argc, char* argv[]) {
    SetConsoleCtrlHandler(consoleHandler, TRUE);
    setlocale(LC_ALL, "Russian");
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);

    // ---- Parse arguments ----
    int myAddr = -1;
    SendMode mode = SendMode::RAW;
    bool modeProvided = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--id" && i + 1 < argc) {
            myAddr = std::stoi(argv[++i]);
        }
        else if (arg == "--mode" && i + 1 < argc) {
            std::string m = argv[++i];
            if (m == "dacap") mode = SendMode::DACAP;
            else mode = SendMode::RAW;
            modeProvided = true;
        }
    }

    if (myAddr < 0) {
        std::cout << "Usage: Client.exe --id <node_address> [--mode raw|dacap]\n";
        return 1;
    }

    // ---- Hybrid mode selection ----
    if (!modeProvided) {
        int modeSel;
        std::cout << "Mode (1=RAW,2=DACAP): ";
        std::cin >> modeSel;
        mode = (modeSel == 2 ? SendMode::DACAP : SendMode::RAW);
    }

    // ---- Logger with unique filename ----
    std::string logName = "log_" + std::to_string(myAddr) + ".txt";
    Logger logger(logName);
    loggerPtr = &logger;

    // ---- Connect ----
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in svr{};
    svr.sin_family = AF_INET;
    svr.sin_port = htons(9200);
    inet_pton(AF_INET, "10.78.1.1", &svr.sin_addr);
    connect(sock, (sockaddr*)&svr, sizeof(svr));

    std::thread thr(receiver, sock, mode, myAddr);

    std::cout << "Mode: " << (mode == SendMode::DACAP ? "DACAP" : "RAW") << "\n";
    std::cout << "Enter dest addr: ";

    while (true) {
        int dst;
        std::cin >> dst;
        if (dst < 0) break;

        std::string ackText;
        std::cout << "Ack? (ack/noack): ";
        std::cin >> ackText;

        std::string txt;
        std::cout << "Data: ";
        std::cin >> txt;

        DacapCmd cmd = (mode == SendMode::DACAP ? DacapCmd::RTS : DacapCmd::PAYLOAD);

        auto line = buildSend(dst, ackText, txt, mode, cmd);

        stats.recordSend();
        auto t0 = Clock::now();
        int res = send(sock, line.c_str(), int(line.size()), 0);
        auto t1 = Clock::now();

        double dt = std::chrono::duration<double, std::milli>(t1 - t0).count();

        if (res != SOCKET_ERROR)
            stats.recordReceive(true, dt);

        logger.log("SEND", myAddr, dst,
            cmd == DacapCmd::RTS ? "RTS" : "DATA",
            res != SOCKET_ERROR ? "OK" : "ERR",
            int(line.size()), stats.attempts, dt);

        double pdr = stats.sent ? 100.0 * stats.success / stats.sent : 0.0;
        std::cout << ">>> PDR=" << pdr << "%  delay=" << dt << "ms\n\n";

        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "Enter dest addr: ";
    }

    running = false;
    thr.join();
    stats.printSummary();

    closesocket(sock);
    WSACleanup();
    return 0;
}
