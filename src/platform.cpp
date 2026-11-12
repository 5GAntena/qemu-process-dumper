#include "qpd/platform.hpp"

#include <chrono>
#include <csignal>
#include <cstring>
#include <iostream>
#include <limits>
#include <memory>
#include <regex>
#include <sstream>
#include <thread>
#include <libxml/parser.h>
#ifdef __linux__
#include <fcntl.h>
#include <grp.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace qpd {
namespace {
volatile std::sig_atomic_t interrupted = 0;
void on_signal(int) { interrupted = 1; }
std::string text_file(const std::filesystem::path& path) {
    auto bytes = read_file(path, 16 * 1024 * 1024); return {bytes.begin(), bytes.end()};
}
using Xml = std::unique_ptr<xmlDoc, decltype(&xmlFreeDoc)>;
Xml xml_parse(const std::string& text) {
    require(text.size() <= 16 * 1024 * 1024, "Domain XML is too large");
    Xml doc(xmlReadMemory(text.data(), static_cast<int>(text.size()), "domain.xml", nullptr,
                          XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING), xmlFreeDoc);
    require(bool(doc) && !doc->intSubset && !doc->extSubset, "Invalid domain XML or forbidden DTD"); return doc;
}
xmlNode* child(xmlNode* parent, const char* name) {
    for (auto* p = parent ? parent->children : nullptr; p; p = p->next)
        if (p->type == XML_ELEMENT_NODE && xmlStrEqual(p->name, BAD_CAST name)) return p;
    return nullptr;
}
std::string xml_string(xmlChar* ptr) {
    if (!ptr) return {};
    std::unique_ptr<xmlChar, decltype(xmlFree)> owner(ptr, xmlFree); return reinterpret_cast<const char*>(ptr);
}
#ifdef __linux__
class Temporary {
public:
    explicit Temporary(const std::filesystem::path& directory = std::filesystem::temp_directory_path()) {
        auto name = (directory / ".qpd-XXXXXX").string();
        std::vector<char> buffer(name.begin(), name.end()); buffer.push_back(0);
        fd = mkstemp(buffer.data()); require(fd >= 0, "Cannot create temporary file"); path = buffer.data();
        if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) { close(fd); unlink(path.c_str()); throw Error("Cannot protect temporary descriptor"); }
    }
    ~Temporary() { if (fd >= 0) close(fd); if (!path.empty()) unlink(path.c_str()); }
    Temporary(const Temporary&) = delete;
    Temporary& operator=(const Temporary&) = delete;
    Temporary(Temporary&&) = delete;
    Temporary& operator=(Temporary&&) = delete;
    void write(std::span<const std::uint8_t> data, bool sync = true) {
        std::size_t offset = 0;
        while (offset < data.size()) {
            check_cancelled(); const auto n = ::write(fd, data.data() + offset, data.size() - offset);
            if (n < 0 && errno == EINTR) continue;
            require(n > 0, "Temporary file write failed"); offset += static_cast<std::size_t>(n);
        }
        if (sync) require(fsync(fd) == 0, "Temporary file sync failed");
    }
    int fd = -1;
    std::filesystem::path path;
};
std::string start_time(std::uint64_t pid) {
    const auto text = text_file("/proc/" + std::to_string(pid) + "/stat");
    const auto closing = text.rfind(')'); require(closing != std::string::npos, "Invalid QEMU stat");
    std::istringstream fields(text.substr(closing + 1)); std::string field;
    for (unsigned i = 0; i < 20; ++i) require(bool(fields >> field), "Truncated QEMU stat");
    return field;
}
#endif
}
void check_cancelled() { if (interrupted) throw Cancelled(); }
void install_signals() { std::signal(SIGINT, on_signal); std::signal(SIGTERM, on_signal); }
bool terminal_input() {
#ifdef __linux__
    return isatty(STDIN_FILENO);
#else
    return false;
#endif
}
std::filesystem::path executable_path() {
#ifdef __linux__
    return std::filesystem::read_symlink("/proc/self/exe");
#else
    return std::filesystem::current_path() / "qemu-process-dumper";
#endif
}
void drop_privileges() {
#ifdef __linux__
    const auto* uid_text = std::getenv("SUDO_UID"); const auto* gid_text = std::getenv("SUDO_GID");
    if (geteuid() == 0 && uid_text) {
        require(gid_text, "SUDO_GID is missing"); const auto uid = number(uid_text), gid = number(gid_text);
        require(uid <= std::numeric_limits<uid_t>::max() && gid <= std::numeric_limits<gid_t>::max(), "Invalid sudo identity");
        if (uid && gid) require(setgroups(0, nullptr) == 0 && setgid(static_cast<gid_t>(gid)) == 0 && setuid(static_cast<uid_t>(uid)) == 0, "Cannot drop sudo privileges");
    }
#endif
}
CommandResult command(const std::vector<std::string>& args, unsigned timeout, std::size_t limit) {
    require(!args.empty() && timeout && limit && limit <= max_file, "Invalid subprocess parameters");
    for (const auto& arg : args) require(arg.find('\0') == std::string::npos, "NUL in subprocess argument");
#ifdef __linux__
    Temporary output, errors;
    std::vector<char*> argv; for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str())); argv.push_back(nullptr);
    const auto pid = fork(); require(pid >= 0, "Cannot fork subprocess");
    if (pid == 0) {
        setpgid(0, 0);
        const rlimit bound{limit, limit};
        if (setrlimit(RLIMIT_FSIZE, &bound) || dup2(output.fd, 1) < 0 || dup2(errors.fd, 2) < 0) _exit(126);
        const int input = open("/dev/null", O_RDONLY);
        if (input < 0 || dup2(input, 0) < 0) _exit(126);
        close(input); setenv("LC_ALL", "C.UTF-8", 1); execvp(argv[0], argv.data()); _exit(127);
    }
    setpgid(pid, pid);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout);
    int status = 0;
    try {
        for (;;) {
            const auto done = waitpid(pid, &status, WNOHANG);
            if (done == pid) break;
            require(done >= 0 || errno == EINTR, "Cannot wait for subprocess");
            check_cancelled(); require(std::chrono::steady_clock::now() < deadline, "Subprocess timed out: " + args.front());
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    } catch (...) { kill(-pid, SIGKILL); kill(pid, SIGKILL); while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {} throw; }
    auto err = read_file(errors.path, limit);
    return {WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status), read_file(output.path, limit), {err.begin(), err.end()}};
#else
    throw Error("External host commands require the Linux backend");
#endif
}
std::string command_text(const std::vector<std::string>& args, unsigned timeout) {
    const auto result = command(args, timeout, 16 * 1024 * 1024);
    require(result.status == 0, args.front() + " failed: " + result.error);
    std::string text(result.output.begin(), result.output.end());
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) text.pop_back();
    return text;
}
void publish(const std::filesystem::path& path, std::span<const std::uint8_t> data) {
    publish_generated(path, [&](const Sink& sink) { sink(data); });
}
void publish_generated(const std::filesystem::path& path, const std::function<void(const Sink&)>& produce) {
#ifdef __linux__
    Temporary temp(path.parent_path());
    produce([&](std::span<const std::uint8_t> data) { temp.write(data, false); });
    check_cancelled(); require(fsync(temp.fd) == 0, "Temporary file sync failed");
    require(link(temp.path.c_str(), path.c_str()) == 0, "Cannot publish without overwriting: " + path.string());
#else
    // Portable exclusive directory reservation and same-volume hard-link publication.
    // Live acquisition is unavailable on these hosts; offline output uses this branch.
    static std::uint64_t sequence = 0;
    const auto dir = path.parent_path() / (".qpd-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "-" + std::to_string(sequence++));
    require(std::filesystem::create_directory(dir), "Cannot reserve temporary directory");
    try {
        const auto temp = dir / "data";
        std::ofstream out(temp, std::ios::binary);
        produce([&](std::span<const std::uint8_t> data) { check_cancelled(); out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size())); require(bool(out), "Output write failed"); });
        out.close();
        require(bool(out), "Output write failed"); std::filesystem::create_hard_link(temp, path);
        std::filesystem::remove_all(dir);
    } catch (...) { std::filesystem::remove_all(dir); throw; }
#endif
}
void publish_pair(const std::filesystem::path& path, const Bytes& data, const Json& report) {
    auto text = report.dump() + "\n";
    publish(path, data);
    try { publish(path.string() + ".json", std::span(reinterpret_cast<const std::uint8_t*>(text.data()), text.size())); }
    catch (...) { std::filesystem::remove(path); throw; }
}
Physical::Physical(const std::filesystem::path& image) {
#ifdef __linux__
    fd_ = open(image.c_str(), O_RDONLY | O_CLOEXEC);
    require(fd_ >= 0, "Cannot open read-only RAM: " + image.string());
    struct stat info{};
    if (fstat(fd_, &info) != 0) { close(fd_); fd_ = -1; throw Error("Cannot stat RAM file"); }
    if (info.st_size >= 0) regions.push_back({0, static_cast<std::uint64_t>(info.st_size), 0});
#else
    file_.open(image, std::ios::binary);
    require(bool(file_), "Cannot open read-only RAM: " + image.string());
    file_.seekg(0, std::ios::end); const auto size = file_.tellg();
    if (size >= 0) regions.push_back({0, static_cast<std::uint64_t>(size), 0});
    file_.clear(); file_.seekg(0);
#endif
}
Physical::~Physical() {
#ifdef __linux__
    if (fd_ >= 0) close(fd_);
#endif
}
Bytes Physical::read(std::uint64_t address, std::size_t size) {
    check_cancelled(); require(size <= 16 * 1024 * 1024 && address <= UINT64_MAX - size, "Invalid physical range");
    Bytes out; out.reserve(size);
    while (out.size() < size) {
        const auto current = address + out.size();
        const auto r = std::find_if(regions.begin(), regions.end(), [&](const Region& v) { return current >= v.address && current - v.address < v.size; });
        require(r != regions.end(), "PA " + hex(current) + " is not ordinary guest RAM");
        const auto count = std::min<std::uint64_t>(size - out.size(), r->size - (current - r->address));
        require(r->offset <= UINT64_MAX - (current - r->address), "RAM offset overflow");
        const auto offset = r->offset + current - r->address;
        require(offset <= std::uint64_t(std::numeric_limits<std::streamoff>::max()), "RAM offset is too large");
        Bytes data(count);
#ifdef __linux__
        std::size_t consumed = 0;
        while (consumed < count) {
            const auto n = pread(fd_, data.data() + consumed, count - consumed, static_cast<off_t>(offset + consumed));
            if (n < 0 && errno == EINTR) { check_cancelled(); continue; }
            require(n > 0, "Short guest RAM read at " + hex(current));
            consumed += static_cast<std::size_t>(n);
        }
#else
        file_.clear(); file_.seekg(static_cast<std::streamoff>(offset));
        file_.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(count));
        require(file_.gcount() == static_cast<std::streamsize>(count), "Short guest RAM read at " + hex(current));
#endif
        out.insert(out.end(), data.begin(), data.end());
    }
    return out;
}
std::vector<Physical::Region> parse_ram_map(const std::string& blocks, const std::string& tree) {
    const std::regex block(R"(^\s*pc\.ram\s+\d+\s+\w+\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+rw\s*$)", std::regex::icase);
    std::istringstream lines(blocks); std::string line; std::smatch m; unsigned count = 0; std::uint64_t used = 0, host = 0;
    while (std::getline(lines, line)) if (std::regex_match(line, m, block)) {
        ++count; used = number(m[2].str()); host = number(m[4].str()); require(used && used <= number(m[3].str()) && host, "Invalid pc.ram allocation");
    }
    require(count == 1, "Expected exactly one pc.ram block; NUMA/hotplug is unsupported");
    const std::regex view(R"(^FlatView #\d+\s*$)"), system(R"(^\s*AS "memory", root: system\s*$)");
    const std::regex region(R"(^\s*([0-9a-f]+)-([0-9a-f]+) \(prio -?\d+, ram\): pc\.ram(?: @([0-9a-f]+))?(?: KVM)?\s*$)", std::regex::icase);
    bool selected = false; unsigned views = 0; std::vector<Physical::Region> result;
    std::istringstream tree_lines(tree);
    while (std::getline(tree_lines, line)) {
        if (std::regex_match(line, view)) selected = false;
        if (std::regex_match(line, system)) { selected = true; ++views; }
        if (selected && std::regex_match(line, m, region)) {
            const auto start = number("0x" + m[1].str()), end = number("0x" + m[2].str());
            const auto offset = m[3].matched ? number("0x" + m[3].str()) : 0;
            require(end >= start && end - start < UINT64_MAX, "Invalid RAM interval"); const auto size = end - start + 1;
            require(offset <= used && size <= used - offset && host <= UINT64_MAX - offset - size, "Invalid pc.ram alias");
            result.push_back({start, size, host + offset});
        }
    }
    std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) { return a.address < b.address; });
    require(views == 1 && !result.empty() && result.front().address == 0, "Incomplete system RAM map");
    for (std::size_t i = 1; i < result.size(); ++i) require(result[i - 1].size <= result[i].address - result[i - 1].address, "Overlapping RAM aliases");
    return result;
}
std::string domain_xml(const std::string& domain, const std::string& uri) { return command_text({"virsh", "-c", uri, "dumpxml", domain}); }
std::vector<std::string> block_disks(const std::string& text) {
    auto doc = xml_parse(text); std::vector<std::string> result;
    for (auto* disk = child(xmlDocGetRootElement(doc.get()), "devices"); disk;) {
        for (auto* d = disk->children; d; d = d->next) {
            if (!xmlStrEqual(d->name, BAD_CAST "disk") || xml_string(xmlGetProp(d, BAD_CAST "type")) != "block" || xml_string(xmlGetProp(d, BAD_CAST "device")) != "disk") continue;
            auto* source = child(d, "source"); require(source, "Missing block disk source");
            auto path = xml_string(xmlGetProp(source, BAD_CAST "dev")); require(path.starts_with("/dev/"), "Unexpected block disk path"); result.push_back(path);
        }
        break;
    }
    require(!result.empty(), "Guest disk must be attached as a host block device"); return result;
}
std::unique_ptr<Physical> Physical::live(const std::string& domain, const std::string& uri) {
#ifdef __linux__
    auto virsh = [&](std::vector<std::string> args) { args.insert(args.begin(), {"virsh", "-c", uri}); return command_text(args); };
    require(virsh({"domstate", domain}) == "running", "Domain must already be running");
    auto doc = xml_parse(domain_xml(domain, uri)); auto* root = xmlDocGetRootElement(doc.get());
    require(!child(root, "launchSecurity"), "Encrypted/protected guest RAM is unsupported");
    const auto uuid = xml_string(xmlNodeGetContent(child(root, "uuid"))); require(!uuid.empty(), "Domain UUID is missing");
    // The only QMP requests in this backend are these three read-only queries.
    auto query = [&](const std::string& execute, const std::optional<std::string>& hmp = {}) {
        require(execute == "query-cpus-fast" || (execute == "human-monitor-command" && hmp && (*hmp == "info ramblock" || *hmp == "info mtree -f")), "Forbidden live QMP query");
        auto request = Json::object({{"execute", execute}});
        if (hmp) request["arguments"] = Json::object({{"command-line", *hmp}});
        auto response = Json::parse(virsh({"qemu-monitor-command", domain, request.dump()}));
        require(!response.contains("error"), "QMP query failed: " + response.dump()); return response.at("return");
    };
    const auto cpus = query("query-cpus-fast"); require(!cpus.items().empty(), "No QEMU CPUs");
    const auto tid = cpus.items().front().at("thread-id").integer();
    std::smatch match; auto status = text_file("/proc/" + std::to_string(tid) + "/status");
    require(std::regex_search(status, match, std::regex(R"((?:^|\n)Tgid:\s+(\d+))")), "Cannot find QEMU PID");
    const auto pid = number(match[1].str()); const auto proc = "/proc/" + std::to_string(pid);
    const auto args = text_file(proc + "/cmdline");
    require(args.find(std::string("\0-uuid\0", 7) + uuid + '\0') != std::string::npos, "QEMU/domain UUID mismatch");
    require(std::filesystem::read_symlink(proc + "/exe").filename().string().starts_with("qemu-system-"), "Domain process is not QEMU");
    const auto started = start_time(pid);
    auto regions = parse_ram_map(query("human-monitor-command", "info ramblock").string(), query("human-monitor-command", "info mtree -f").string());
    const auto maps = text_file(proc + "/maps");
    for (const auto& r : regions) {
        auto current = r.offset; const auto end = r.offset + r.size; std::istringstream entries(maps); std::string line;
        while (std::getline(entries, line)) {
            std::istringstream fields(line); std::string range, permissions; fields >> range >> permissions;
            if (!permissions.starts_with("rw")) continue;
            const auto dash = range.find('-'); require(dash != std::string::npos, "Invalid QEMU memory map");
            const auto lo = number("0x" + range.substr(0, dash)), hi = number("0x" + range.substr(dash + 1));
            if (lo <= current && current < hi) current = std::min(end, hi);
            if (current == end) break;
        }
        require(current == end, "Guest RAM alias is outside writable QEMU mappings");
    }
    auto memory = std::make_unique<Physical>(proc + "/mem"); memory->regions = std::move(regions);
    memory->pid_ = pid; memory->start_ = started; memory->is_live = true;
    memory->check_identity(); memory->read(0x1000, 16); return memory;
#else
    (void)domain; (void)uri; throw Error("Live QEMU RAM acquisition requires Linux; use --image for offline analysis");
#endif
}
void Physical::check_identity() const {
#ifdef __linux__
    if (is_live) require(start_time(pid_) == start_, "QEMU exited or its PID was reused");
#endif
}
} // namespace qpd
