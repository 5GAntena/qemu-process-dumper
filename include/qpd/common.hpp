#pragma once

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace qpd {
using Bytes = std::vector<std::uint8_t>;
using Read = std::function<Bytes(std::uint64_t, std::size_t)>;
struct Error : std::runtime_error { using runtime_error::runtime_error; };
struct Cancelled : Error { Cancelled() : Error("Cancelled") {} };
void check_cancelled();
constexpr std::uint64_t address_mask = 0x000ffffffffff000ULL;
constexpr std::size_t max_file = 1024ULL * 1024 * 1024;
void require(bool condition, std::string_view message);
bool canonical(std::uint64_t address, unsigned bits = 48);
std::uint64_t number(std::string_view value);
std::string hex(std::uint64_t value);
std::string lower(std::string value);
std::string utf16(std::span<const std::uint8_t> data);
std::uint64_t get(std::span<const std::uint8_t> data, std::size_t offset, unsigned width);
void put(Bytes& data, std::size_t offset, std::uint64_t value, unsigned width);
Bytes slice(std::span<const std::uint8_t> data, std::uint64_t offset, std::size_t size);
void copy_into(Bytes& data, std::size_t offset, std::span<const std::uint8_t> source);
std::size_t align(std::size_t value, std::size_t alignment);
Bytes read_file(const std::filesystem::path& path, std::size_t limit = max_file);
std::string sha256(std::span<const std::uint8_t> data);
class Digest {
public:
    Digest();
    ~Digest();
    Digest(const Digest&) = delete;
    Digest& operator=(const Digest&) = delete;
    Digest(Digest&&) = delete;
    Digest& operator=(Digest&&) = delete;
    void update(std::span<const std::uint8_t> data);
    std::string finish();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// An integer-preserving JSON value. Guest addresses must never pass through double.
class Json {
public:
    using Array = std::vector<Json>;
    using Object = std::map<std::string, Json, std::less<>>;
    Json() = default;
    Json(std::nullptr_t) {}
    Json(bool value);
    Json(int value);
    Json(unsigned value);
    Json(std::uint64_t value);
    Json(std::string value);
    Json(const char* value);
    Json(Array value);
    Json(Object value);
    static Json object(std::initializer_list<Object::value_type> values);
    static Json array();
    static Json parse(std::string_view text);
    std::string dump() const;
    bool null() const;
    bool is_array() const;
    bool contains(std::string_view key) const;
    const Json& at(std::string_view key) const;
    Json& operator[](std::string key);
    const Array& items() const;
    Array& items();
    const Object& fields() const;
    void push(Json value);
    std::string string() const;
    std::uint64_t integer() const;
    bool boolean() const;
    bool operator==(const Json&) const = default;
private:
    enum class Kind { null, boolean, integer, number, string, array, object };
    Kind kind_ = Kind::null;
    bool bool_ = false;
    std::uint64_t integer_ = 0;
    std::string string_;
    Array array_;
    Object object_;
};

// File/process operations have explicit platform implementations in platform.cpp.
struct CommandResult { int status; Bytes output; std::string error; };
CommandResult command(const std::vector<std::string>& arguments, unsigned timeout = 15,
                      std::size_t limit = max_file);
std::string command_text(const std::vector<std::string>& arguments, unsigned timeout = 15);
void publish(const std::filesystem::path& path, std::span<const std::uint8_t> data);
using Sink = std::function<void(std::span<const std::uint8_t>)>;
void publish_generated(const std::filesystem::path& path, const std::function<void(const Sink&)>& produce);
void publish_pair(const std::filesystem::path& path, const Bytes& data, const Json& report);
void drop_privileges();
void install_signals();
bool terminal_input();
std::filesystem::path executable_path();
} // namespace qpd
