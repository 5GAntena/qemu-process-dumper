#pragma once
#include "qpd/pe.hpp"

namespace qpd {
std::optional<unsigned> compression_format(const Bytes& reparse);
Bytes decompress_wof(const Bytes& source, std::size_t size, unsigned algorithm);
std::string normalize_guest_path(std::string path);
Bytes copy_guest_file(const std::string& domain, const std::string& uri, const std::string& path,
                      const std::optional<std::string>& partition = {}, const PE* live = nullptr);
} // namespace qpd
