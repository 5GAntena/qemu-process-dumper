#pragma once
#include "qpd/common.hpp"
#include <fstream>
#include <memory>

namespace qpd {
// A read-only stream owns its descriptor through std::ifstream; no guest writes.
class Physical {
public:
    struct Region { std::uint64_t address, size, offset; };
    explicit Physical(const std::filesystem::path& image);
    ~Physical();
    Physical(const Physical&) = delete;
    Physical& operator=(const Physical&) = delete;
    Physical(Physical&&) = delete;
    Physical& operator=(Physical&&) = delete;
    static std::unique_ptr<Physical> live(const std::string& domain, const std::string& uri);
    Bytes read(std::uint64_t address, std::size_t size);
    void check_identity() const;
    std::vector<Region> regions;
    bool is_live = false;
private:
    std::ifstream file_;
    int fd_ = -1;
    std::string start_;
    std::uint64_t pid_ = 0;
};
std::vector<Physical::Region> parse_ram_map(const std::string& blocks, const std::string& tree);
std::string domain_xml(const std::string& domain, const std::string& uri);
std::vector<std::string> block_disks(const std::string& xml);
} // namespace qpd
