#pragma once
#include "qpd/windows.hpp"

namespace qpd {
struct Section {
    std::string name;
    std::uint64_t rva, virtual_size, raw_size, flags;
};
struct Import {
    std::uint64_t slot;
    std::string dll;
    std::optional<std::string> name;
    std::uint64_t ordinal = 0;
    Json json() const;
};
class PE {
public:
    PE(Read read, std::uint64_t base);
    Bytes rva(std::uint64_t address, std::size_t size) const;
    std::string string(std::uint64_t address, std::size_t limit = 4096) const;
    std::pair<std::uint64_t, std::uint64_t> directory(unsigned index) const;
    std::vector<std::pair<std::uint64_t, Import>> exports(const std::string& fallback) const;
    Read read;
    std::uint64_t base, pe, opt, optional_size, section_table, image_size, headers_size;
    std::uint64_t entry, section_alignment, file_alignment, ordinal_bit;
    unsigned width, dir_offset, base_offset, directory_count;
    Bytes headers;
    std::vector<Section> sections;
};
class ExportIndex {
public:
    ExportIndex(Read read, std::vector<Module> modules, unsigned width);
    void load();
    Import resolve(std::uint64_t address, const std::string& preferred = {});
    std::map<std::uint64_t, std::vector<Import>> by_address;
    Json errors = Json::array();
private:
    Read read_;
    std::vector<Module> modules_;
    unsigned width_;
    bool loaded_ = false;
};
std::vector<Import> recover_imports(const PE& pe, ExportIndex& exports,
                                   std::optional<std::uint64_t> iat_rva = {}, std::optional<std::uint64_t> iat_size = {},
                                   const Json& overrides = Json::array());
struct ImportSection {
    Bytes data;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> patches;
    std::uint64_t descriptor_size;
};
ImportSection build_imports(const std::vector<Import>& entries, std::uint64_t rva, unsigned width);
class BackingImage {
public:
    BackingImage(Bytes raw, const PE& live, std::string source);
    Bytes read(std::uint64_t rva, std::size_t size);
    Json identity;
private:
    void relocate();
    Bytes data_, relocations_;
    unsigned width_;
    std::uint64_t headers_size_, delta_, count_ = 0;
    bool relocated_ = false;
};
struct DumpOptions {
    bool imports = true, allow_missing = false;
    std::optional<std::uint64_t> iat_rva, iat_size, oep;
    Json import_map = Json::array();
    std::optional<std::filesystem::path> backing_file;
    std::function<Bytes()> backing_provider;
};
// Read/validate callbacks allow deterministic capture tests without a VM.
struct CaptureTarget {
    Read read;
    std::function<void()> validate;
    std::function<std::vector<Module>()> modules;
    Process process;
    const std::set<std::uint64_t>* shared_pages = nullptr;
};
Json dump_pe(CaptureTarget target, std::uint64_t base, const std::filesystem::path& output, const DumpOptions& options);
} // namespace qpd
