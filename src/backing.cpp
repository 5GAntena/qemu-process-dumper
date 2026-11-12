#include "qpd/backing.hpp"
#include <array>
#include <iostream>
#include <sstream>
#ifdef __linux__
#include <dlfcn.h>
#include <unicode/unistr.h>
#endif

namespace qpd {
std::optional<unsigned> compression_format(const Bytes& data) {
    if (data.size() < 4 || get(data, 0, 4) != 0x80000017) return {};
    require(data.size() == 24 && get(data, 4, 2) == 16 && get(data, 6, 2) == 0, "Invalid WOF reparse point size/reserved field");
    require(get(data, 8, 4) == 1 && get(data, 12, 4) == 2 && get(data, 16, 4) == 1, "Unsupported WOF provider/version");
    const auto algorithm = get(data, 20, 4); require(algorithm <= 3, "Unsupported WOF algorithm"); return static_cast<unsigned>(algorithm);
}
namespace {
constexpr std::array<std::size_t, 4> chunk_sizes{4096, 32768, 8192, 16384};
#ifdef __linux__
class Decoder {
public:
    explicit Decoder(unsigned algorithm) : algorithm_(algorithm) {
        const std::string prefix = algorithm == 1 ? "lzx" : "xpress";
        for (const auto* root : {"/usr/lib64", "/usr/lib", "/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu"}) {
            const auto path = std::filesystem::path(root) / "ntfs-3g/ntfs-plugin-80000017.so";
            library_ = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL); if (!library_) continue;
            // POSIX specifies conversion of dlsym results to function pointers.
            decode_ = reinterpret_cast<Decode>(dlsym(library_, (prefix + "_decompress").c_str()));
            free_ = reinterpret_cast<Free>(dlsym(library_, (prefix + "_free_decompressor").c_str()));
            auto* allocate = dlsym(library_, (prefix + "_allocate_decompressor").c_str());
            if (decode_ && free_ && allocate) {
                context_ = algorithm == 1 ? reinterpret_cast<void*(*)(std::size_t)>(allocate)(32768) : reinterpret_cast<void*(*)()>(allocate)();
                if (context_) return;
            }
            dlclose(library_); library_ = nullptr;
        }
        throw Error("WOF decompression requires the installed ntfs-3g-system-compression plugin");
    }
    ~Decoder() { if (context_) free_(context_); if (library_) dlclose(library_); }
    Decoder(const Decoder&) = delete;
    Decoder& operator=(const Decoder&) = delete;
    Decoder(Decoder&&) = delete;
    Decoder& operator=(Decoder&&) = delete;
    Bytes decode(const Bytes& source, std::size_t size) {
        if (algorithm_ != 1) {
            require(source.size() >= 260, "Truncated XPRESS Huffman stream"); unsigned sum = 0;
            for (unsigned i = 0; i < 256; ++i) for (const auto length : {source[i] & 15, source[i] >> 4}) if (length) sum += 1U << (15 - length);
            require(sum == 32768, "Invalid XPRESS Huffman code lengths");
        }
        Bytes result(size); require(decode_(context_, source.data(), source.size(), result.data(), size) == 0, "Invalid compressed WOF chunk"); return result;
    }
private:
    using Decode = int(*)(void*, const void*, std::size_t, void*, std::size_t);
    using Free = void(*)(void*);
    unsigned algorithm_;
    void* library_ = nullptr;
    void* context_ = nullptr;
    Decode decode_ = nullptr;
    Free free_ = nullptr;
};
#endif
std::string casefold(const std::string& value) {
#ifdef __linux__
    auto text = icu::UnicodeString::fromUTF8(value); text.foldCase(); std::string result; text.toUTF8String(result); return result;
#else
    return lower(value);
#endif
}
}
Bytes decompress_wof(const Bytes& source, std::size_t size, unsigned algorithm) {
    require(algorithm <= 3 && size && size <= max_file, "Unsupported WOF algorithm/file size");
    const auto chunk = chunk_sizes[algorithm], count = (size + chunk - 1) / chunk, table_size = (count - 1) * 4;
    require(table_size < source.size() && source.size() <= size + table_size, "Invalid WOF stream size");
    std::vector<std::uint64_t> offsets{0};
    for (std::size_t i = 0; i < count - 1; ++i) offsets.push_back(get(source, i * 4, 4));
    offsets.push_back(source.size() - table_size);
    for (std::size_t i = 0; i < count; ++i) require(offsets[i + 1] > offsets[i] && offsets[i + 1] - offsets[i] <= std::min(chunk, size - i * chunk), "Invalid WOF chunk offsets");
    Bytes output; output.reserve(size);
#ifdef __linux__
    std::unique_ptr<Decoder> decoder;
#endif
    for (std::size_t i = 0; i < count; ++i) {
        check_cancelled(); const auto length = std::min(chunk, size - i * chunk); auto data = slice(source, table_size + offsets[i], offsets[i + 1] - offsets[i]);
        if (data.size() != length) {
#ifdef __linux__
            if (!decoder) decoder = std::make_unique<Decoder>(algorithm);
            data = decoder->decode(data, length);
#else
            throw Error("Compressed WOF decoding requires the Linux NTFS plugin backend");
#endif
        }
        output.insert(output.end(), data.begin(), data.end());
    }
    return output;
}
std::string normalize_guest_path(std::string path) {
    std::replace(path.begin(), path.end(), '\\', '/');
    if (path.starts_with("//?/") || path.starts_with("/?" "?/")) path.erase(0, 4);
    else require(!path.starts_with("//") || path.size() <= 2 || path[2] == '/', "UNC paths cannot be read from local block disk");
    if (path.size() > 2 && path[1] == ':' && path[2] == '/' && std::isalpha(static_cast<unsigned char>(path[0]))) path.erase(0, 2);
    require(path.starts_with('/') && std::none_of(path.begin(), path.end(), [](unsigned char c) { return c < 32; }), "Provide absolute local guest path without control characters");
    std::istringstream stream(path); std::string part, result;
    while (std::getline(stream, part, '/')) { require(part != "..", "Guest path cannot contain '..'"); if (!part.empty() && part != ".") result += '/' + part; }
    require(!result.empty(), "Provide guest file path, not root"); return result;
}
Bytes copy_guest_file(const std::string& domain, const std::string& uri, const std::string& path, const std::optional<std::string>& selected, const PE* live) {
    const auto guest = normalize_guest_path(path); std::set<std::string> partitions;
    std::function<void(const Json&)> walk = [&](const Json& node) {
        if (node.contains("fstype") && !node.at("fstype").null() && lower(node.at("fstype").string()) == "ntfs") {
            const auto device = node.at("path").string(); require(device.starts_with("/dev/"), "Unexpected NTFS device path"); partitions.insert(device);
        }
        if (node.contains("children")) for (const auto& child : node.at("children").items()) walk(child);
    };
    for (const auto& disk : block_disks(domain_xml(domain, uri))) {
        const auto data = Json::parse(command_text({"lsblk", "--json", "--paths", "--output", "PATH,FSTYPE,TYPE", disk}));
        for (const auto& node : data.at("blockdevices").items()) walk(node);
    }
    std::string failures;
    for (const auto& partition : partitions) {
        if (selected && std::filesystem::canonical(partition) != std::filesystem::canonical(*selected)) continue;
        try {
            std::string current = "/", component; std::istringstream parts(guest.substr(1));
            while (std::getline(parts, component, '/')) {
                const auto listing = command_text({"ntfsls", "--all", "--system", "--path", current, partition});
                std::istringstream lines(listing); std::string name; std::vector<std::string> matches; std::optional<std::string> exact;
                while (std::getline(lines, name)) {
                    if (!name.empty() && name.back() == '\r') name.pop_back();
                    if (name.empty() || name == "." || name == "..") continue;
                    if (name == component) exact = name;
                    if (casefold(name) == casefold(component)) matches.push_back(name);
                }
                require(exact || matches.size() == 1, "Missing/ambiguous NTFS path component: " + component);
                const auto chosen = exact ? *exact : matches.front(); require(chosen.find_first_of("/\\") == std::string::npos, "Invalid NTFS directory name");
                if (current != "/") current += '/';
                current += chosen;
            }
            std::cerr << "Read-only source: " << partition << ':' << current << '\n';
            auto raw = command({"ntfscat", partition, current}, 60); require(raw.status == 0 && !raw.output.empty(), "ntfscat failed: " + raw.error);
            const auto meta = command({"ntfscat", "-a", "0xc0", partition, current}, 60, 16384);
            if (meta.status == 0) if (const auto algorithm = compression_format(meta.output)) {
                const auto compressed = command({"ntfscat", "-n", "WofCompressedData", partition, current}, 60);
                require(compressed.status == 0, "Cannot read WofCompressedData: " + compressed.error);
                raw.output = decompress_wof(compressed.output, raw.output.size(), *algorithm);
                const auto after = command({"ntfscat", "-a", "0xc0", partition, current}, 60, 16384);
                require(after.status == 0 && compression_format(after.output) == algorithm, "WOF metadata changed during copying");
            }
            if (live) { BackingImage verified(raw.output, *live, partition + ':' + current); }
            else { PE verified([&](std::uint64_t a, std::size_t size) { return slice(raw.output, a, size); }, 0); }
            return raw.output;
        } catch (const Cancelled&) { throw; } catch (const Error& e) { failures += partition + ": " + e.what() + "; "; }
    }
    throw Error("Could not copy from selected guest NTFS block disks: " + failures);
}
} // namespace qpd
