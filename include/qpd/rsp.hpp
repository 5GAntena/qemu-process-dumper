#pragma once
#include "qpd/common.hpp"
#include <chrono>
#include <memory>
#include <set>

namespace qpd {
Bytes decode_rsp(std::string_view raw);
// The legacy transport is separate from live acquisition and requires an explicit
// --allow-vm-pause before construction. Closing a socket alone leaves QEMU halted.
class Rsp {
public:
    explicit Rsp(const std::string& endpoint);
    ~Rsp();
    Rsp(const Rsp&) = delete;
    Rsp& operator=(const Rsp&) = delete;
    Rsp(Rsp&&) = delete;
    Rsp& operator=(Rsp&&) = delete;
    std::string request(const std::string& payload, unsigned timeout = 5);
    void ok(const std::string& payload);
    std::string interrupt();
    void ignore_cancellation() { cancellation_ = false; }
    std::string console;
private:
    void write(std::string_view data);
    char byte(std::chrono::steady_clock::time_point deadline);
    std::string receive(std::chrono::steady_clock::time_point deadline);
    int fd_ = -1;
    bool cancellation_ = true;
};
class Qemu {
public:
    explicit Qemu(const std::string& endpoint);
    ~Qemu();
    Qemu(const Qemu&) = delete;
    Qemu& operator=(const Qemu&) = delete;
    Qemu(Qemu&&) = delete;
    Qemu& operator=(Qemu&&) = delete;
    void initialize();
    void close(bool resume);
    Bytes read(std::uint64_t address, std::size_t size);
    std::vector<std::string> cpus();
    void select(const std::string& cpu);
    std::uint64_t reg(const std::string& name);
    std::map<std::string, std::uint64_t> monitor_registers();
    void breakpoint(std::uint64_t address, bool insert);
    std::string run(bool step, unsigned timeout);
    bool stopped() const { return stopped_; }
    std::string selected, last_stop;
    std::set<std::uint64_t> breakpoints;
private:
    void xml(const std::string& annex, unsigned& next, std::set<std::string>& seen);
    void mode(bool physical);
    Rsp rsp_;
    std::map<std::string, std::pair<unsigned, unsigned>> registers_;
    std::optional<bool> initial_mode_, physical_mode_;
    unsigned packet_size_ = 4096;
    bool multiprocess_ = false, stopped_ = true, closed_ = false;
};
} // namespace qpd
