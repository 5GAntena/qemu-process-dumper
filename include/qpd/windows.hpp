#pragma once
#include "qpd/platform.hpp"
#include <memory>
#include <set>

namespace qpd {
class Profile {
public:
    explicit Profile(Json value);
    static Profile load(const std::filesystem::path& path);
    std::uint64_t offset(std::string_view type, std::string_view field) const;
    std::optional<std::uint64_t> optional(std::string_view type, std::string_view field) const;
    std::uint64_t symbol(std::string_view name) const;
    Json data;
};
struct PageUnavailable : Error {
    PageUnavailable(std::uint64_t value, std::string message, bool file = false);
    std::uint64_t entry;
    bool file_backed;
    std::optional<std::uint64_t> primary_entry, file_backed_va, image_vad_start;
};
using Checks = std::vector<std::pair<std::uint64_t, std::uint64_t>>;
struct Mapping {
    std::uint64_t address, physical, size;
    bool writable, executable;
};
class AddressSpace {
public:
    AddressSpace(Read physical, std::uint64_t dtb, bool software = true);
    Bytes read(std::uint64_t address, std::size_t size) const;
    std::uint64_t scalar(std::uint64_t address, unsigned width = 8) const;
    void user_mappings(const std::function<void(const Mapping&)>& consume) const;
    std::optional<std::uint64_t> walk(std::uint64_t address, Checks& checks, unsigned depth = 0) const;
    std::optional<std::uint64_t> leaf(std::uint64_t entry, std::uint64_t offset, Checks& checks,
                                     unsigned depth, bool prototype = false) const;
    std::uint64_t dtb;
    std::function<std::optional<std::uint64_t>(std::uint64_t, Checks&)> resolver;
private:
    Read physical_;
    bool software_;
};
struct Process {
    std::uint64_t pid, eprocess, dtb, user_dtb, peb;
    std::string name;
    Json json() const;
};
struct Module {
    std::uint64_t base, size;
    std::string name, path, name_error;
    Json json() const;
};
class Windows;
class Target {
public:
    // A target is immovable: its resolver captures this, and Windows must outlive it.
    Target(Windows& windows, Process process);
    Target(const Target&) = delete;
    Target& operator=(const Target&) = delete;
    void validate() const;
    Bytes read(std::uint64_t address, std::size_t size) const;
    std::vector<Module> modules() const;
    std::uint64_t main_image_base() const;
    const Windows& windows() const { return windows_; }
    Process process;
    AddressSpace space;
    std::set<std::uint64_t> shared_pages;
private:
    Windows& windows_;
    std::optional<std::uint64_t> create_offset_, create_time_;
    std::vector<Module> native_modules() const;
    std::optional<std::uint64_t> resolve_vad(std::uint64_t address, Checks& checks);
};
class Windows {
public:
    Windows(Read physical, const Profile& profile, std::uint64_t base, std::uint64_t dtb);
    std::vector<Process> processes() const;
    Process process_at(std::uint64_t address) const;
    std::unique_ptr<Target> attach(std::uint64_t pid);
    std::vector<std::uint64_t> list(const AddressSpace& space, std::uint64_t head, std::uint64_t offset) const;
    Read physical;
    const Profile& profile;
    std::uint64_t base;
    AddressSpace kernel;
    Json identity;
};
std::unique_ptr<Windows> discover(Physical& memory, const Profile& profile,
                                std::optional<std::uint64_t> base = {}, std::optional<std::uint64_t> dtb = {});
Json pe_identity(const AddressSpace& space, std::uint64_t base);
} // namespace qpd
