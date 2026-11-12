#include "qpd/common.hpp"

#include <charconv>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <limits>
#include <memory>
#include <openssl/evp.h>
#include <sstream>

namespace qpd {
void require(bool condition, std::string_view message) {
    if (!condition) throw Error(std::string(message));
}
bool canonical(std::uint64_t a, unsigned bits) {
    return (a >> bits) == ((a & (1ULL << (bits - 1))) ? (~0ULL >> bits) : 0);
}
std::uint64_t number(std::string_view s) {
    unsigned base = 10;
    if (s.starts_with("0x") || s.starts_with("0X")) { base = 16; s.remove_prefix(2); }
    std::uint64_t value = 0;
    const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), value, base);
    require(!s.empty() && ec == std::errc{} && end == s.data() + s.size(), "Invalid unsigned integer");
    return value;
}
std::string hex(std::uint64_t value) {
    std::ostringstream out; out << "0x" << std::hex << value; return out.str();
}
std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
static void append_utf8(std::string& out, std::uint32_t c) {
    require(c <= 0x10ffff && !(c >= 0xd800 && c <= 0xdfff), "Invalid Unicode scalar");
    if (c < 0x80) out += static_cast<char>(c);
    else if (c < 0x800) { out += static_cast<char>(0xc0 | (c >> 6)); out += static_cast<char>(0x80 | (c & 63)); }
    else if (c < 0x10000) {
        out += static_cast<char>(0xe0 | (c >> 12)); out += static_cast<char>(0x80 | ((c >> 6) & 63)); out += static_cast<char>(0x80 | (c & 63));
    } else {
        out += static_cast<char>(0xf0 | (c >> 18)); out += static_cast<char>(0x80 | ((c >> 12) & 63));
        out += static_cast<char>(0x80 | ((c >> 6) & 63)); out += static_cast<char>(0x80 | (c & 63));
    }
}
std::string utf16(std::span<const std::uint8_t> data) {
    require(data.size() % 2 == 0, "Invalid UTF-16 length");
    std::string out;
    for (std::size_t i = 0; i < data.size(); i += 2) {
        auto c = static_cast<std::uint32_t>(get(data, i, 2));
        if (c >= 0xd800 && c <= 0xdbff) {
            const auto low = get(data, i + 2, 2);
            require(low >= 0xdc00 && low <= 0xdfff, "Invalid UTF-16 surrogate");
            c = 0x10000 + ((c - 0xd800) << 10) + static_cast<std::uint32_t>(low - 0xdc00); i += 2;
        }
        append_utf8(out, c);
    }
    return out;
}
std::uint64_t get(std::span<const std::uint8_t> data, std::size_t offset, unsigned width) {
    require(width <= 8 && offset <= data.size() && width <= data.size() - offset, "Truncated binary field");
    std::uint64_t value = 0;
    for (unsigned i = 0; i < width; ++i) value |= std::uint64_t(data[offset + i]) << (i * 8);
    return value;
}
void put(Bytes& data, std::size_t offset, std::uint64_t value, unsigned width) {
    require(width <= 8 && offset <= data.size() && width <= data.size() - offset, "Binary write out of bounds");
    for (unsigned i = 0; i < width; ++i) data[offset + i] = static_cast<std::uint8_t>(value >> (i * 8));
}
Bytes slice(std::span<const std::uint8_t> data, std::uint64_t offset, std::size_t size) {
    require(offset <= data.size() && size <= data.size() - offset, "Binary range out of bounds");
    return {data.begin() + static_cast<std::ptrdiff_t>(offset), data.begin() + static_cast<std::ptrdiff_t>(offset + size)};
}
void copy_into(Bytes& data, std::size_t offset, std::span<const std::uint8_t> source) {
    require(offset <= data.size() && source.size() <= data.size() - offset, "Binary copy out of bounds");
    std::copy(source.begin(), source.end(), data.begin() + static_cast<std::ptrdiff_t>(offset));
}
std::size_t align(std::size_t value, std::size_t alignment) {
    require(alignment && value <= SIZE_MAX - (alignment - 1), "Alignment overflow");
    return (value + alignment - 1) / alignment * alignment;
}
Bytes read_file(const std::filesystem::path& path, std::size_t limit) {
    std::ifstream in(path, std::ios::binary);
    require(in.good(), "Cannot open file: " + path.string());
    Bytes result;
    char block[65536];
    while (in) {
        check_cancelled(); in.read(block, sizeof block);
        const auto count = static_cast<std::size_t>(in.gcount());
        require(count <= limit - result.size(), "File exceeds size limit");
        result.insert(result.end(), block, block + count);
    }
    require(in.eof(), "File read failed");
    return result;
}
struct Digest::Impl {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx{EVP_MD_CTX_new(), EVP_MD_CTX_free};
    bool finished = false;
};
Digest::Digest() : impl_(std::make_unique<Impl>()) {
    require(impl_->ctx && EVP_DigestInit_ex(impl_->ctx.get(), EVP_sha256(), nullptr) == 1, "SHA-256 failed");
}
Digest::~Digest() = default;
void Digest::update(std::span<const std::uint8_t> data) {
    require(!impl_->finished && EVP_DigestUpdate(impl_->ctx.get(), data.data(), data.size()) == 1, "SHA-256 update failed");
}
std::string Digest::finish() {
    unsigned char bytes[EVP_MAX_MD_SIZE]; unsigned length = 0;
    require(!impl_->finished && EVP_DigestFinal_ex(impl_->ctx.get(), bytes, &length) == 1, "SHA-256 failed");
    impl_->finished = true;
    std::ostringstream out;
    for (unsigned i = 0; i < length; ++i) out << std::hex << std::setw(2) << std::setfill('0') << unsigned(bytes[i]);
    return out.str();
}
std::string sha256(std::span<const std::uint8_t> data) { Digest digest; digest.update(data); return digest.finish(); }
Json::Json(bool v) : kind_(Kind::boolean), bool_(v) {}
Json::Json(int v) : kind_(v < 0 ? Kind::number : Kind::integer), integer_(v < 0 ? 0 : static_cast<std::uint64_t>(v)) {
    if (v < 0) string_ = std::to_string(v);
}
Json::Json(unsigned v) : Json(std::uint64_t(v)) {}
Json::Json(std::uint64_t v) : kind_(Kind::integer), integer_(v) {}
Json::Json(std::string v) : kind_(Kind::string), string_(std::move(v)) {}
Json::Json(const char* v) : Json(std::string(v)) {}
Json::Json(Array v) : kind_(Kind::array), array_(std::move(v)) {}
Json::Json(Object v) : kind_(Kind::object), object_(std::move(v)) {}
Json Json::object(std::initializer_list<Object::value_type> v) { return Object(v); }
Json Json::array() { return Array{}; }
bool Json::null() const { return kind_ == Kind::null; }
bool Json::is_array() const { return kind_ == Kind::array; }
bool Json::contains(std::string_view key) const { return kind_ == Kind::object && object_.contains(key); }
const Json& Json::at(std::string_view key) const {
    require(contains(key), "Missing JSON field: " + std::string(key)); return object_.find(key)->second;
}
Json& Json::operator[](std::string key) {
    if (null()) kind_ = Kind::object;
    require(kind_ == Kind::object, "Expected JSON object"); return object_[std::move(key)];
}
const Json::Array& Json::items() const { require(is_array(), "Expected JSON array"); return array_; }
Json::Array& Json::items() { require(is_array(), "Expected JSON array"); return array_; }
const Json::Object& Json::fields() const { require(kind_ == Kind::object, "Expected JSON object"); return object_; }
void Json::push(Json value) { items().push_back(std::move(value)); }
std::string Json::string() const { require(kind_ == Kind::string, "Expected JSON string"); return string_; }
std::uint64_t Json::integer() const { require(kind_ == Kind::integer, "Expected unsigned JSON integer"); return integer_; }
bool Json::boolean() const { require(kind_ == Kind::boolean, "Expected JSON boolean"); return bool_; }
Json Json::parse(std::string_view text) {
    std::size_t pos = 0;
    auto ws = [&] { while (pos < text.size() && (text[pos] == ' ' || text[pos] == '\n' || text[pos] == '\r' || text[pos] == '\t')) ++pos; };
    auto take = [&]() { require(pos < text.size(), "Truncated JSON"); return text[pos++]; };
    auto escape = [&]() {
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = take(); const auto found = std::string_view("0123456789abcdef").find(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            require(found != std::string_view::npos, "Invalid JSON Unicode escape"); v = (v << 4) | static_cast<std::uint32_t>(found);
        }
        return v;
    };
    auto string = [&]() {
        require(take() == '"', "Expected JSON string"); std::string out;
        for (;;) {
            const unsigned char c = static_cast<unsigned char>(take());
            if (c == '"') return out;
            require(c >= 32, "Control character in JSON string");
            if (c != '\\') { out += static_cast<char>(c); continue; }
            switch (take()) {
            case '"': out += '"'; break; case '\\': out += '\\'; break; case '/': out += '/'; break;
            case 'b': out += '\b'; break; case 'f': out += '\f'; break; case 'n': out += '\n'; break;
            case 'r': out += '\r'; break; case 't': out += '\t'; break;
            case 'u': {
                auto v = escape();
                if (v >= 0xd800 && v <= 0xdbff) {
                    require(take() == '\\' && take() == 'u', "Missing JSON surrogate");
                    const auto lo = escape(); require(lo >= 0xdc00 && lo <= 0xdfff, "Invalid JSON surrogate");
                    v = 0x10000 + ((v - 0xd800) << 10) + lo - 0xdc00;
                }
                append_utf8(out, v); break;
            }
            default: throw Error("Invalid JSON escape");
            }
        }
    };
    std::function<Json(unsigned)> value = [&](unsigned depth) -> Json {
        require(depth <= 128, "Excessive JSON nesting"); ws(); require(pos < text.size(), "Truncated JSON");
        const char c = text[pos];
        if (c == '"') return string();
        if (c == '{' || c == '[') {
            ++pos; Json result = c == '{' ? Json(Object{}) : array(); ws(); const char close = c == '{' ? '}' : ']';
            if (pos < text.size() && text[pos] == close) { ++pos; return result; }
            for (;;) {
                ws();
                if (c == '{') {
                    const auto key = string(); require(!result.contains(key), "Duplicate JSON key"); ws(); require(take() == ':', "Expected JSON colon"); result[key] = value(depth + 1);
                } else result.push(value(depth + 1));
                ws(); const char next = take(); if (next == close) return result;
                require(next == ',', "Expected JSON comma");
            }
        }
        for (auto literal : {std::string_view("true"), std::string_view("false"), std::string_view("null")}) {
            if (text.substr(pos).starts_with(literal)) { pos += literal.size(); return literal == "null" ? Json{} : Json(literal == "true"); }
        }
        const auto start = pos;
        if (text[pos] == '-') ++pos;
        require(pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos])), "Invalid JSON value");
        if (text[pos] == '0') ++pos;
        else while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) ++pos;
        bool integral = text[start] != '-';
        auto digits = [&] {
            const auto before = pos;
            while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) ++pos;
            require(pos > before, "Invalid JSON number");
        };
        if (pos < text.size() && text[pos] == '.') { integral = false; ++pos; digits(); }
        if (pos < text.size() && (text[pos] == 'e' || text[pos] == 'E')) {
            integral = false; ++pos;
            if (pos < text.size() && (text[pos] == '+' || text[pos] == '-')) ++pos;
            digits();
        }
        const auto token = text.substr(start, pos - start);
        if (integral) return number(token);
        Json result; result.kind_ = Kind::number; result.string_ = token; return result;
    };
    auto result = value(0); ws(); require(pos == text.size(), "Trailing JSON data"); return result;
}
static std::string quote(std::string_view value) {
    std::ostringstream out; out << '"';
    for (const unsigned char c : value) {
        if (c == '"' || c == '\\') out << '\\' << static_cast<char>(c);
        else if (c < 32) out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << unsigned(c);
        else out << static_cast<char>(c);
    }
    out << '"'; return out.str();
}
std::string Json::dump() const {
    switch (kind_) {
    case Kind::null: return "null"; case Kind::boolean: return bool_ ? "true" : "false";
    case Kind::integer: return std::to_string(integer_); case Kind::number: return string_; case Kind::string: return quote(string_);
    case Kind::array: {
        std::string out = "["; for (const auto& v : array_) { if (out.size() > 1) out += ','; out += v.dump(); } return out + ']';
    }
    case Kind::object: {
        std::string out = "{"; for (const auto& [key, v] : object_) { if (out.size() > 1) out += ','; out += quote(key) + ':' + v.dump(); } return out + '}';
    }
    }
    throw Error("Invalid JSON kind");
}
} // namespace qpd
