#include "qpd/rsp.hpp"
#include <cstring>
#include <iostream>
#include <regex>
#include <sstream>
#include <libxml/parser.h>
#ifdef __linux__
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace qpd {
namespace {
std::string hex_number(std::uint64_t value) { return hex(value).substr(2); }
std::string encode(std::string_view value) {
    const char* digits = "0123456789abcdef"; std::string out;
    for (const unsigned char c : value) { out += digits[c >> 4]; out += digits[c & 15]; } return out;
}
Bytes unhex(std::string_view value) {
    require(value.size() % 2 == 0, "Invalid hex reply"); Bytes out;
    for (std::size_t i = 0; i < value.size(); i += 2) out.push_back(static_cast<std::uint8_t>(number("0x" + std::string(value.substr(i, 2)))));
    return out;
}
}
Bytes decode_rsp(std::string_view raw) {
    Bytes out;
    for (std::size_t i = 0; i < raw.size(); ++i) {
        auto c = static_cast<std::uint8_t>(raw[i]);
        if (c == '}') { require(++i < raw.size(), "Truncated RSP escape"); out.push_back(static_cast<std::uint8_t>(raw[i]) ^ 0x20); }
        else if (c == '*') {
            require(!out.empty() && ++i < raw.size(), "Invalid RSP run length"); const int count = static_cast<unsigned char>(raw[i]) - 29;
            require(count >= 3 && count <= 97, "Invalid RSP run length"); const auto last = out.back(); out.insert(out.end(), static_cast<std::size_t>(count), last);
        } else out.push_back(c);
        require(out.size() <= 4 * 1024 * 1024, "Oversized decoded RSP packet");
    }
    return out;
}
Rsp::Rsp(const std::string& endpoint) {
#ifdef __linux__
    auto connect_socket = [&](int family, const sockaddr* address, socklen_t size) {
        const int fd = socket(family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0); require(fd >= 0, "Cannot create GDB socket");
        if (connect(fd, address, size) == 0) return fd;
        if (errno == EINPROGRESS) {
            pollfd wait{fd, POLLOUT, 0}; int error = 0; socklen_t length = sizeof error;
            if (poll(&wait, 1, 5000) > 0 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && !error) return fd;
        }
        ::close(fd); return -1;
    };
    if (endpoint.starts_with("unix:")) {
        sockaddr_un address{}; address.sun_family = AF_UNIX; const auto path = endpoint.substr(5);
        require(path.size() < sizeof address.sun_path, "GDB socket path too long"); std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
        fd_ = connect_socket(AF_UNIX, reinterpret_cast<const sockaddr*>(&address), sizeof address);
    } else {
        require(endpoint.starts_with("tcp:"), "Endpoint must be unix:/path or tcp:host:port");
        const auto split = endpoint.rfind(':'); require(split > 4, "Invalid GDB endpoint"); const auto host = endpoint.substr(4, split - 4), port = endpoint.substr(split + 1);
        require(number(port) && number(port) <= 65535, "Invalid GDB port"); addrinfo hints{}; hints.ai_socktype = SOCK_STREAM; addrinfo* raw = nullptr;
        require(getaddrinfo(host.c_str(), port.c_str(), &hints, &raw) == 0, "Cannot resolve GDB host");
        std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> addresses(raw, freeaddrinfo);
        for (auto* a = raw; a && fd_ < 0; a = a->ai_next) fd_ = connect_socket(a->ai_family, a->ai_addr, a->ai_addrlen);
    }
    require(fd_ >= 0, "Cannot connect to GDB endpoint");
#else
    (void)endpoint; throw Error("Legacy GDB transport requires the Linux backend");
#endif
}
Rsp::~Rsp() {
#ifdef __linux__
    if (fd_ >= 0) ::close(fd_);
#endif
}
void Rsp::write(std::string_view data) {
#ifdef __linux__
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!data.empty()) {
        require(std::chrono::steady_clock::now() < deadline, "GDB write timeout"); pollfd wait{fd_, POLLOUT, 0};
        if (poll(&wait, 1, 100) <= 0) continue;
        const auto count = send(fd_, data.data(), data.size(), MSG_NOSIGNAL);
        if (count < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        require(count > 0, "GDB connection write failed"); data.remove_prefix(static_cast<std::size_t>(count));
    }
#else
    (void)data; throw Error("GDB transport unavailable");
#endif
}
char Rsp::byte(std::chrono::steady_clock::time_point deadline) {
#ifdef __linux__
    for (;;) {
        if (cancellation_) check_cancelled();
        require(std::chrono::steady_clock::now() < deadline, "GDB response timed out"); pollfd wait{fd_, POLLIN, 0};
        if (poll(&wait, 1, 100) <= 0) continue;
        char c; const auto count = recv(fd_, &c, 1, 0);
        if (count < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        require(count == 1, "GDB connection closed"); return c;
    }
#else
    (void)deadline; throw Error("GDB transport unavailable");
#endif
}
std::string Rsp::receive(std::chrono::steady_clock::time_point deadline) {
    for (;;) {
        const auto marker = byte(deadline); if (marker == '+' || marker == '-') return {marker}; require(marker == '$', "Unexpected RSP marker");
        std::string raw; unsigned sum = 0;
        for (;;) { const auto c = byte(deadline); if (c == '#') break; raw += c; sum += static_cast<unsigned char>(c); require(raw.size() <= 1024 * 1024, "Oversized RSP packet"); }
        std::string checksum; checksum += byte(deadline); checksum += byte(deadline); bool valid = false;
        try { valid = number("0x" + checksum) == (sum & 255); } catch (const Error&) { /* Request retransmission. */ }
        write(valid ? "+" : "-"); if (valid) { const auto data = decode_rsp(raw); return {data.begin(), data.end()}; }
    }
}
std::string Rsp::request(const std::string& payload, unsigned timeout) {
    unsigned sum = 0; for (const unsigned char c : payload) sum += c;
    auto checksum = hex_number(sum & 255); if (checksum.size() == 1) checksum.insert(0, "0"); const auto frame = '$' + payload + '#' + checksum;
    write(frame); const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout); unsigned retries = 0; console.clear();
    for (;;) {
        const auto reply = receive(deadline); if (reply == "+") continue;
        if (reply == "-") { require(++retries <= 3, "Repeatedly rejected RSP checksum"); write(frame); continue; }
        if (reply.starts_with('O') && reply != "OK") { const auto data = unhex(reply.substr(1)); console.append(data.begin(), data.end()); require(console.size() <= 4 * 1024 * 1024, "Oversized RSP console"); continue; }
        require(!reply.starts_with('E'), "QEMU rejected " + payload.substr(0, payload.find(':')) + ": " + reply); return reply;
    }
}
void Rsp::ok(const std::string& payload) { require(request(payload) == "OK", "Unsupported RSP request: " + payload); }
std::string Rsp::interrupt() {
    // Cleanup must remain possible after the signal flag has been set.
    struct Restore { bool& flag; bool previous; ~Restore() { flag = previous; } } restore{cancellation_, cancellation_};
    cancellation_ = false;
    write(std::string(1, '\3')); const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    for (;;) { const auto reply = receive(deadline); if (!reply.empty() && std::string_view("TSWX").find(reply.front()) != std::string_view::npos) return reply; }
}
Qemu::Qemu(const std::string& endpoint) : rsp_(endpoint) {}
Qemu::~Qemu() { if (!closed_) try { close(false); } catch (const std::exception& e) { std::cerr << "Legacy cleanup failed: " << e.what() << '\n'; } }
void Qemu::mode(bool physical) { if (physical_mode_ != physical) { rsp_.ok(std::string("Qqemu.PhyMemMode:") + (physical ? '1' : '0')); physical_mode_ = physical; } }
void Qemu::initialize() {
    const auto features = rsp_.request("qSupported:multiprocess+;qXfer:features:read+"); multiprocess_ = features.find("multiprocess+") != std::string::npos;
    const auto position = features.find("PacketSize="); if (position != std::string::npos) {
        const auto start = position + 11, end = features.find(';', start); packet_size_ = static_cast<unsigned>(std::min<std::uint64_t>(number("0x" + features.substr(start, end - start)), 65536));
        require(packet_size_ > 128, "Invalid RSP packet size");
    }
    last_stop = rsp_.request("?"); require(last_stop.starts_with('T') || last_stop.starts_with('S'), "Guest is not stopped");
    const auto initial = rsp_.request("qqemu.PhyMemMode"); require(initial == "0" || initial == "1", "Physical-memory GDB extension required"); initial_mode_ = physical_mode_ = initial == "1";
    require(features.find("qXfer:features:read+") != std::string::npos, "Target XML required"); unsigned next = 0; std::set<std::string> seen; xml("target.xml", next, seen);
    require(registers_.contains("rip"), "Only x86-64 QEMU targets supported"); select(cpus().front());
}
void Qemu::xml(const std::string& annex, unsigned& next, std::set<std::string>& seen) {
    require(seen.size() <= 32 && seen.insert(annex).second && annex.find_first_of(":,\0", 0, 3) == std::string::npos, "Invalid/cyclic XML include"); std::string data;
    for (;;) {
        const auto reply = rsp_.request("qXfer:features:read:" + annex + ':' + hex_number(data.size()) + ",800");
        require(reply.starts_with('m') || reply.starts_with('l'), "Invalid target XML reply"); data += reply.substr(1);
        require(data.size() <= 2 * 1024 * 1024 && (reply.front() == 'l' || reply.size() > 1), "Invalid target XML size"); if (reply.front() == 'l') break;
    }
    if (data.find("xmlns:xi=") == std::string::npos) for (std::size_t p = 0; (p = data.find("xi:include", p)) != std::string::npos;) data.replace(p, 10, "include");
    std::unique_ptr<xmlDoc, decltype(&xmlFreeDoc)> doc(xmlReadMemory(data.data(), static_cast<int>(data.size()), "target.xml", nullptr, XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING), xmlFreeDoc);
    // QEMU emits a DOCTYPE declaration, but external entities are never loaded.
    require(bool(doc), "Invalid target XML");
    auto prop = [](xmlNode* node, const char* name) { std::unique_ptr<xmlChar, decltype(xmlFree)> ptr(xmlGetProp(node, BAD_CAST name), xmlFree); return ptr ? std::string(reinterpret_cast<const char*>(ptr.get())) : std::string{}; };
    for (auto* n = xmlDocGetRootElement(doc.get())->children; n; n = n->next) {
        if (xmlStrEqual(n->name, BAD_CAST "include")) xml(prop(n, "href"), next, seen);
        else if (xmlStrEqual(n->name, BAD_CAST "reg")) {
            const auto raw = prop(n, "regnum"), name = prop(n, "name"); const auto index = raw.empty() ? next : number(raw), bits = number(prop(n, "bitsize"));
            require(index < 65536 && bits && bits <= 65536 && !name.empty(), "Invalid register XML"); registers_[name] = {static_cast<unsigned>(index), static_cast<unsigned>(bits)}; next = static_cast<unsigned>(index + 1);
        }
    }
}
std::vector<std::string> Qemu::cpus() {
    std::vector<std::string> result;
    for (unsigned i = 0; i < 4096; ++i) {
        const auto reply = rsp_.request(i ? "qsThreadInfo" : "qfThreadInfo");
        if (reply == "l") { require(!result.empty(), "No QEMU CPUs"); return result; }
        require(reply.starts_with('m'), "Invalid vCPU list"); std::istringstream parts(reply.substr(1)); std::string cpu;
        while (std::getline(parts, cpu, ',')) result.push_back(cpu);
    }
    throw Error("Excessive vCPU list");
}
void Qemu::select(const std::string& cpu) { rsp_.ok("Hg" + cpu); selected = cpu; }
std::map<std::string, std::uint64_t> Qemu::monitor_registers() {
    if (!selected.empty()) { const auto thread = number("0x" + selected.substr(selected.find_last_of('.') + 1)); require(thread, "Invalid vCPU ID"); rsp_.ok("qRcmd," + encode("cpu " + std::to_string(thread - 1))); }
    rsp_.ok("qRcmd," + encode("info registers")); const std::regex entry(R"(\b([A-Z][A-Z0-9_]*)\s*=\s*([0-9a-fA-F]{4,16})\b)"); std::map<std::string,std::uint64_t> result;
    for (auto i = std::sregex_iterator(rsp_.console.begin(), rsp_.console.end(), entry); i != std::sregex_iterator(); ++i) result[(*i)[1].str()] = number("0x" + (*i)[2].str());
    return result;
}
std::uint64_t Qemu::reg(const std::string& name) {
    if (!registers_.contains(name)) {
        auto upper = name; for (auto& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        const auto registers = monitor_registers(); require(registers.contains(upper), "Unavailable register: " + name); return registers.at(upper);
    }
    const auto [index,bits] = registers_.at(name); require(bits <= 64, "Register too wide for scalar read");
    const auto data = unhex(rsp_.request("p" + hex_number(index))); require(data.size() * 8 == bits, "Unexpected register size"); return get(data, 0, static_cast<unsigned>(data.size()));
}
Bytes Qemu::read(std::uint64_t address, std::size_t size) {
    require(size <= 16 * 1024 * 1024 && address <= UINT64_MAX - size, "Invalid physical read"); mode(true); Bytes out;
    while (out.size() < size) {
        const auto count = std::min<std::size_t>(size - out.size(), (packet_size_ - 128) / 2); const auto data = unhex(rsp_.request("m" + hex_number(address + out.size()) + ',' + hex_number(count)));
        require(data.size() == count, "Short QEMU memory reply"); out.insert(out.end(),data.begin(),data.end());
    }
    return out;
}
void Qemu::breakpoint(std::uint64_t address, bool insert) {
    mode(false); rsp_.ok(std::string(insert ? "Z1," : "z1,") + hex_number(address) + ",1");
    if (insert) breakpoints.insert(address); else breakpoints.erase(address);
}
std::string Qemu::run(bool step, unsigned timeout) {
    mode(false); stopped_ = false;
    try { last_stop = rsp_.request(step ? "vCont;s:" + selected : "vCont;c", timeout); }
    catch (...) { last_stop = rsp_.interrupt(); stopped_ = true; throw; }
    stopped_ = true; require(last_stop.starts_with('T') || last_stop.starts_with('S'), "Unexpected guest stop");
    std::smatch match; if (std::regex_search(last_stop, match, std::regex("thread:([^;]+);"))) select(match[1].str()); return last_stop;
}
void Qemu::close(bool resume) {
    if (closed_) return;
    rsp_.ignore_cancellation();
    if (!stopped_) { rsp_.interrupt(); stopped_ = true; }
    const auto owned = breakpoints; for (const auto address : owned) breakpoint(address, false);
    if (initial_mode_) mode(*initial_mode_);
    if (resume) {
        if (multiprocess_) {
            std::set<std::string> pids; for (const auto& cpu : cpus()) if (cpu.starts_with('p')) pids.insert(cpu.substr(1, cpu.find('.') - 1));
            require(!pids.empty(), "Cannot determine QEMU process ID for detach"); for (const auto& pid : pids) rsp_.ok("D;" + pid);
        } else rsp_.ok("D");
    }
    closed_ = true;
}
} // namespace qpd
