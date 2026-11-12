#pragma once
#include "qpd/pe.hpp"

namespace qpd {
// Both operations stream bytes and publish only complete files. The caller of
// dump_process must establish that the guest is halted for the entire operation.
Json dump_range(CaptureTarget target, std::uint64_t address, std::uint64_t size,
                const std::filesystem::path& filename);
Json dump_process(Target& target, const std::filesystem::path& filename, bool guest_halted);
} // namespace qpd
