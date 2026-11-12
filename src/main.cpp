#include "qpd/backing.hpp"
#include <iomanip>
#include <iostream>
#ifdef __linux__
#include <unistd.h>
#endif

namespace qpd {
int legacy_main(const std::vector<std::string>& args);
int attach_domain_main(const std::vector<std::string>& args);
namespace {
const char* help = R"(QEMU process dumper (C++20)
Usage: qemu-process-dumper [options]
       qemu-process-dumper copy-guest-file --path PATH|--pid PID --output FILE
       qemu-process-dumper legacy --allow-vm-pause --endpoint ENDPOINT [options]

  --domain NAME        Running libvirt domain (default windows11-hardware)
  --uri URI            Libvirt URI (default qemu:///system)
  --profile FILE       Exact AMD64 kernel ISF JSON, .gz, or .xz
  --kernel-base VA     Current boot's kernel virtual address
  --kernel-cr3 DTB     Current boot's kernel page-table root
  --image FILE         Offline guest-physical RAM image
  --list               List Windows processes and exit
  --pid PID            Select process (otherwise prompt on a terminal)
  --modules            List selected process's native/WOW64 modules
  --module NAME        Capture this module instead of main image
  --base VA            Explicit loaded PE base, including manually mapped images
  --output FILE        Filename saved with report under outputs/STEM/
  --no-imports         Capture sections without rebuilding imports
  --iat-rva RVA        Manual IAT RVA (requires --iat-size)
  --iat-size BYTES     Positive multiple of image pointer width
  --oep RVA            Set entry point inside captured image
  --import-map FILE    JSON list of {slot,dll,name|ordinal} overrides
  --allow-missing      Explicitly accept zero-filled unavailable section pages
  --backing-file FILE  Matching original PE for verified nonresident image pages
  --json               JSON process/module lists
  --help               Show this text

copy-guest-file additionally accepts --path PATH and --partition DEVICE.
Its --output is an exact destination path. Existing files are preserved.
Live reads never connect to GDB or request VM pause/resume. Reads are non-atomic.
)";
}
int run(const std::vector<std::string>& argv) {
    if (!argv.empty() && argv.front() == "legacy") return legacy_main({argv.begin() + 1, argv.end()});
    if (!argv.empty() && argv.front() == "attach-domain") return attach_domain_main({argv.begin() + 1, argv.end()});
    const bool copy = !argv.empty() && argv.front() == "copy-guest-file";
    std::map<std::string, std::string> args; std::set<std::string> flags;
    const std::set<std::string> switches{"--list", "--modules", "--no-imports", "--allow-missing", "--json"};
    const std::set<std::string> values{"--domain", "--uri", "--profile", "--kernel-base", "--kernel-cr3", "--image", "--pid", "--module", "--base", "--output", "--iat-rva", "--iat-size", "--oep", "--import-map", "--backing-file", "--path", "--partition"};
    for (std::size_t i = copy ? 1 : 0; i < argv.size(); ++i) {
        const auto& key = argv[i]; if (key == "--help" || key == "-h") { std::cout << help; return 0; }
        require(!flags.contains(key) && !args.contains(key), "Duplicate option: " + key);
        if (switches.contains(key)) flags.insert(key);
        else { require(values.contains(key), "Unknown option: " + key); require(i + 1 < argv.size(), "Missing value: " + key); args[key] = argv[++i]; }
    }
    const auto root = executable_path().parent_path().parent_path();
    auto value = [&](const std::string& key, const std::string& fallback) { return args.contains(key) ? args.at(key) : fallback; };
    auto numeric = [&](const std::string& key) -> std::optional<std::uint64_t> { return args.contains(key) ? std::optional(number(args.at(key))) : std::nullopt; };
    const auto domain = value("--domain", "windows11-hardware"), uri = value("--uri", "qemu:///system");
    require(args.contains("--iat-rva") == args.contains("--iat-size"), "Supply both --iat-rva and --iat-size");
    require(!args.contains("--module") || !args.contains("--base"), "Choose --module or --base");
    require(!flags.contains("--list") || (!args.contains("--pid") && !flags.contains("--modules") && !args.contains("--output") && !args.contains("--module") && !args.contains("--base")), "--list only enumerates processes");
    require(copy || (!args.contains("--path") && !args.contains("--partition")), "--path/--partition require copy-guest-file");
    if (copy) require(args.contains("--output") && (args.contains("--path") != args.contains("--pid")), "copy-guest-file requires --output and exactly one of --path/--pid");
    else require(flags.contains("--list") || args.contains("--pid") || terminal_input(), "Use --list or --pid when stdin is not a terminal");
    std::optional<std::string> partition; if (args.contains("--partition")) partition = args.at("--partition");
    if (copy && args.contains("--path")) {
        auto data = copy_guest_file(domain, uri, args.at("--path"), partition); drop_privileges(); publish(std::filesystem::absolute(args.at("--output")), data);
        std::cout << Json::object({{"file", std::filesystem::absolute(args.at("--output")).string()}, {"size", data.size()}, {"method", "read-only ntfsls/ntfscat; no VM control"}}).dump() << '\n'; return 0;
    }
    const auto profile = Profile::load(value("--profile", (root / "profiles/B661C6FE72991D160FE37C48B8BC5470-1.json").string()));
    auto memory = args.contains("--image") ? std::make_unique<Physical>(args.at("--image")) : Physical::live(domain, uri);
    if (!copy) drop_privileges();
    auto windows = discover(*memory, profile, numeric("--kernel-base"), numeric("--kernel-cr3"));
    std::cerr << "Kernel " << hex(windows->base) << ", DTB " << hex(windows->kernel.dtb) << "; exact PDB verified.\n";
    auto list = [&] {
        auto processes = windows->processes(); auto json = Json::array();
        if (!flags.contains("--json")) { std::cout << "     PID  PROCESS\n"; std::sort(processes.begin(), processes.end(), [](const auto& a, const auto& b) { return a.pid < b.pid; }); }
        for (const auto& p : processes) { json.push(p.json()); if (!flags.contains("--json")) std::cout << std::setw(8) << p.pid << "  " << p.name << '\n'; }
        if (flags.contains("--json")) std::cout << json.dump() << '\n';
    };
    if (flags.contains("--list")) { list(); memory->check_identity(); return 0; }
    auto pid = numeric("--pid");
    if (!pid) {
        list(); std::cout << "PID to dump (q to exit): " << std::flush; std::string answer; std::getline(std::cin, answer);
        if (answer.empty() || answer == "q" || answer == "quit" || answer == "exit") return 0;
        pid = number(answer);
    }
    auto target = windows->attach(*pid); const auto modules = target->modules();
    if (flags.contains("--modules")) {
        auto json = Json::array();
        for (const auto& m : modules) { json.push(m.json()); if (!flags.contains("--json")) std::cout << hex(m.base) << "  " << hex(m.size) << "  " << m.name << '\n'; }
        if (flags.contains("--json")) std::cout << json.dump() << '\n';
        memory->check_identity(); return 0;
    }
    std::uint64_t base = 0;
    std::string name = target->process.name;
    if (args.contains("--base")) { base = number(args.at("--base")); name = "module-" + hex(base); }
    else if (args.contains("--module")) {
        std::vector<Module> matches; for (const auto& m : modules) if (lower(m.name) == lower(args.at("--module"))) matches.push_back(m);
        require(matches.size() == 1, "Module missing/ambiguous; use --modules or --base"); base = matches.front().base; name = matches.front().name;
    } else {
        base = target->main_image_base();
        for (const auto& m : modules) if (m.base == base) name = m.name;
    }
    require(base, "Cannot determine main image base; use --modules or --base");
    if (copy) {
        const auto match = std::find_if(modules.begin(), modules.end(), [&](const Module& m) { return m.base == base && !m.path.empty(); });
        require(match != modules.end(), "Cannot read main image path; supply --path");
        PE pe([&](std::uint64_t a, std::size_t n) { return target->read(a, n); }, base);
        auto data = copy_guest_file(domain, uri, match->path, partition, &pe); memory->check_identity(); drop_privileges(); publish(std::filesystem::absolute(args.at("--output")), data);
        std::cout << Json::object({{"file", std::filesystem::absolute(args.at("--output")).string()}, {"size", data.size()}, {"live_pe_headers_matched", true}}).dump() << '\n'; return 0;
    }
    for (char& c : name) if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-' && c != '_') c = '_';
    auto filename = std::filesystem::path(value("--output", name + '.' + std::to_string(*pid) + ".dump.exe")).filename();
    require(!filename.empty() && filename != "." && filename != ".." && filename.stem() != "." && !filename.stem().empty(), "Output must include a filename");
    const auto output = root / "outputs" / filename.stem() / filename; std::filesystem::create_directories(output.parent_path());
    DumpOptions options; options.imports = !flags.contains("--no-imports"); options.allow_missing = flags.contains("--allow-missing");
    options.iat_rva = numeric("--iat-rva"); options.iat_size = numeric("--iat-size"); options.oep = numeric("--oep");
    if (args.contains("--import-map")) { const auto raw = read_file(args.at("--import-map"), 16 * 1024 * 1024); options.import_map = Json::parse({reinterpret_cast<const char*>(raw.data()), raw.size()}); require(options.import_map.is_array(), "Import map must be JSON list"); }
    if (args.contains("--backing-file")) options.backing_file = args.at("--backing-file");
    if (memory->is_live && !options.backing_file && !options.allow_missing) {
        const auto m = std::find_if(modules.begin(), modules.end(), [&](const Module& module) { return module.base == base && !module.path.empty(); });
        if (m != modules.end()) options.backing_provider = [&, guest = m->path] {
            std::vector<std::string> cmd{executable_path().string(), "copy-guest-file", "--domain", domain, "--uri", uri, "--path", guest};
            // Run a privileged read helper with a binary stdout mode; no temporary
            // guest file survives cancellation, and sudo is never interactive.
#ifdef __linux__
            if (geteuid() != 0) cmd.insert(cmd.begin(), {"sudo", "-n", "--"});
#endif
            // The internal mode is handled before general argument parsing below.
            auto it = std::find(cmd.begin(), cmd.end(), "copy-guest-file"); *it = "copy-guest-bytes";
            auto result = command(cmd, 300); if (!result.error.empty()) std::cerr << result.error;
            require(result.status == 0, "Automatic backing-file recovery failed: " + result.error); return result.output;
        };
    }
    CaptureTarget capture{[&](std::uint64_t a, std::size_t n) { return target->read(a, n); }, [&] { target->validate(); memory->check_identity(); },
                          [&] { return target->modules(); }, target->process, &target->shared_pages};
    const auto summary = dump_pe(capture, base, output, options); std::cout << summary.dump() << '\n'; return 0;
}
} // namespace qpd

int main(int argc, char** argv) {
    qpd::install_signals();
    try {
        std::vector<std::string> args(argv + 1, argv + argc);
        if (!args.empty() && args.front() == "copy-guest-bytes") {
            qpd::require(args.size() == 7 && args[1] == "--domain" && args[3] == "--uri" && args[5] == "--path", "Invalid internal recovery request");
            const auto data = qpd::copy_guest_file(args[2], args[4], args[6]);
            std::cout.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size())); qpd::require(bool(std::cout), "Backing helper stdout failed"); return 0;
        }
        return qpd::run(args);
    } catch (const qpd::Cancelled&) { std::cerr << "Cancelled. No guest execution state was changed by live capture.\n"; return 130; }
    catch (const std::exception& e) { std::cerr << "error: " << e.what() << '\n'; return 1; }
}
