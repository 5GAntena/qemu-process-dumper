#include "qpd/pe.hpp"
#include <chrono>
#include <iostream>
#include <tuple>

namespace qpd {
Json Import::json() const { return Json::object({{"slot", slot}, {"dll", dll}, {"name", name ? Json(*name) : Json{}}, {"ordinal", ordinal}}); }
PE::PE(Read reader, std::uint64_t image_base) : read(std::move(reader)), base(image_base) {
    const auto dos = read(base, 64); require(get(dos, 0, 2) == 0x5a4d, "No PE header at " + hex(base));
    pe = get(dos, 60, 4); require(pe >= 64 && pe <= 1024 * 1024 && base <= UINT64_MAX - pe - 24, "Invalid PE header offset");
    const auto fixed = read(base + pe, 24); require(get(fixed, 0, 4) == 0x4550, "Invalid PE signature");
    const auto machine = get(fixed, 4, 2), count = get(fixed, 6, 2); optional_size = get(fixed, 20, 2);
    require(count && count <= 96 && optional_size >= 96 && optional_size <= 4096, "Invalid PE section count/optional header");
    opt = pe + 24; const auto optional = read(base + opt, optional_size); const auto magic = get(optional, 0, 2);
    if (magic == 0x20b && machine == 0x8664) { width = 8; dir_offset = 112; base_offset = 24; }
    else if (magic == 0x10b && machine == 0x14c) { width = 4; dir_offset = 96; base_offset = 28; }
    else throw Error("Only native x86/x64 PE images are supported");
    ordinal_bit = 1ULL << (width * 8 - 1); entry = get(optional, 16, 4);
    section_alignment = get(optional, 32, 4); file_alignment = get(optional, 36, 4);
    image_size = get(optional, 56, 4); headers_size = get(optional, 60, 4);
    directory_count = static_cast<unsigned>(std::min<std::uint64_t>(get(optional, dir_offset - 4, 4), 16));
    require(optional_size >= dir_offset + directory_count * 8 && image_size >= 512 && image_size <= max_file && base <= UINT64_MAX - image_size &&
            entry < image_size && file_alignment && file_alignment <= 65536 && !(file_alignment & (file_alignment - 1)) &&
            section_alignment >= file_alignment && section_alignment <= 16 * 1024 * 1024 && !(section_alignment & (section_alignment - 1)) &&
            headers_size && headers_size <= std::min<std::uint64_t>(image_size, 1024 * 1024), "Invalid PE dimensions/alignment");
    section_table = opt + optional_size; require(section_table + count * 40 <= headers_size, "Section table extends beyond headers");
    headers = read(base, headers_size); require(headers.size() == headers_size, "Short PE header read");
    for (unsigned i = 0; i < count; ++i) {
        const auto offset = section_table + i * 40;
        const auto name = slice(headers, offset, 8);
        Section s{{name.begin(), std::find(name.begin(), name.end(), 0)}, get(headers, offset + 12, 4), get(headers, offset + 8, 4), get(headers, offset + 16, 4), get(headers, offset + 36, 4)};
        const auto size = std::max(s.virtual_size, s.raw_size);
        require(s.rva >= headers_size && s.rva <= image_size && size <= image_size - s.rva, "Invalid section virtual range"); sections.push_back(std::move(s));
    }
    auto sorted = sections; std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.rva < b.rva; });
    for (std::size_t i = 1; i < sorted.size(); ++i) require(sorted[i - 1].rva + std::max(sorted[i - 1].virtual_size, sorted[i - 1].raw_size) <= sorted[i].rva, "Overlapping PE sections");
}
Bytes PE::rva(std::uint64_t a, std::size_t size) const {
    require(a <= image_size && size <= image_size - a, "PE RVA is outside loaded image");
    auto data = read(base + a, size); require(data.size() == size, "Short PE read"); return data;
}
std::pair<std::uint64_t, std::uint64_t> PE::directory(unsigned i) const {
    if (i >= directory_count) return {};
    return {get(headers, opt + dir_offset + i * 8, 4), get(headers, opt + dir_offset + i * 8 + 4, 4)};
}
std::string PE::string(std::uint64_t a, std::size_t limit) const {
    std::string out;
    while (out.size() < limit && a <= image_size && out.size() < image_size - a) {
        const auto count = std::min<std::uint64_t>({128, limit - out.size(), image_size - a - out.size(), 4096 - ((base + a + out.size()) & 4095)});
        const auto data = rva(a + out.size(), count);
        for (const auto c : data) { if (!c) return out; require(c < 128, "Non-ASCII PE string"); out += static_cast<char>(c); }
    }
    throw Error("Unterminated PE string");
}
std::vector<std::pair<std::uint64_t, Import>> PE::exports(const std::string& fallback) const {
    const auto [start, size] = directory(0); if (!start || size < 40) return {};
    const auto d = rva(start, 40); const auto functions = get(d, 20, 4), names = get(d, 24, 4);
    require(functions <= 1000000 && names <= functions, "Invalid export table dimensions");
    const auto dll = get(d, 12, 4) ? string(get(d, 12, 4)) : fallback;
    const auto addresses = rva(get(d, 28, 4), functions * 4), pointers = rva(get(d, 32, 4), names * 4), ordinals = rva(get(d, 36, 4), names * 2);
    std::map<std::uint64_t, std::vector<std::string>> by_index;
    for (std::size_t i = 0; i < names; ++i) { const auto index = get(ordinals, i * 2, 2); require(index < functions, "Invalid export ordinal"); by_index[index].push_back(string(get(pointers, i * 4, 4))); }
    std::vector<std::pair<std::uint64_t, Import>> result;
    for (std::size_t i = 0; i < functions; ++i) {
        const auto a = get(addresses, i * 4, 4); if (!a || (a >= start && a - start < size)) continue;
        require(a < image_size, "Export outside module"); const auto ordinal = get(d, 16, 4) + i;
        if (by_index.contains(i)) for (const auto& name : by_index.at(i)) result.emplace_back(base + a, Import{0, dll, name, ordinal});
        else result.emplace_back(base + a, Import{0, dll, {}, ordinal});
    }
    return result;
}
ExportIndex::ExportIndex(Read reader, std::vector<Module> modules, unsigned width) : read_(std::move(reader)), modules_(std::move(modules)), width_(width) {}
void ExportIndex::load() {
    if (loaded_) return;
    loaded_ = true;
    for (const auto& module : modules_) {
        check_cancelled();
        try {
            std::map<std::uint64_t, Bytes> pages;
            auto read = [&](std::uint64_t a, std::size_t size) {
                Bytes out;
                while (out.size() < size) {
                    const auto current = a + out.size();
                    const auto page = current & ~4095ULL;
                    if (!pages.contains(page)) pages[page] = read_(page, 4096);
                    const auto part = slice(pages.at(page), current & 4095, std::min<std::size_t>(size - out.size(), 4096 - (current & 4095)));
                    out.insert(out.end(), part.begin(), part.end());
                }
                return out;
            };
            PE pe(read, module.base); if (pe.width != width_) continue;
            for (const auto& [address, symbol] : pe.exports(module.name)) by_address[address].push_back(symbol);
        } catch (const Cancelled&) { throw; } catch (const Error& e) { errors.push(Json::object({{"module", module.name}, {"error", e.what()}})); }
    }
}
Import ExportIndex::resolve(std::uint64_t a, const std::string& preferred) {
    load(); std::vector<Import> choices;
    if (by_address.contains(a)) choices = by_address.at(a);
    std::vector<Import> matches; for (const auto& s : choices) if (!preferred.empty() && lower(s.dll) == lower(preferred)) matches.push_back(s);
    if (!matches.empty()) choices = std::move(matches);
    matches.clear(); for (const auto& s : choices) if (s.name) matches.push_back(s);
    if (!matches.empty()) choices = std::move(matches);
    std::map<std::tuple<std::string, std::optional<std::string>, std::uint64_t>, Import> unique;
    for (auto& s : choices) unique[{lower(s.dll), s.name, s.ordinal}] = s;
    require(!unique.empty(), "Cannot resolve import pointer " + hex(a) + " to loaded export");
    require(unique.size() == 1, "Ambiguous import pointer " + hex(a) + "; supply an import map"); return unique.begin()->second;
}
std::vector<Import> recover_imports(const PE& pe, ExportIndex& exports, std::optional<std::uint64_t> iat_rva, std::optional<std::uint64_t> iat_size, const Json& overrides) {
    std::map<std::uint64_t, Import> manual, result;
    for (const auto& v : overrides.items()) {
        const auto& raw_slot = v.at("slot"); std::uint64_t slot;
        try { slot = raw_slot.integer(); } catch (const Error&) { slot = number(raw_slot.string()); }
        Import s{slot, v.at("dll").string(), {}, 0}; if (v.contains("name") && !v.at("name").null()) s.name = v.at("name").string();
        if (v.contains("ordinal")) s.ordinal = v.at("ordinal").integer();
        require(!s.dll.empty() && ((s.name && !s.name->empty()) || s.ordinal), "Import map requires DLL and name or ordinal");
        require(manual.emplace(slot, std::move(s)).second, "Duplicate import override slot");
    }
    auto add = [&](std::uint64_t slot, std::uint64_t value, const std::string& dll = {}, std::optional<std::uint64_t> original = {}) {
        Import s;
        if (manual.contains(slot)) s = manual.at(slot);
        else if (original && (*original & pe.ordinal_bit)) s = {slot, dll, {}, *original & 65535};
        else if (original && *original < pe.image_size) s = {slot, dll, pe.string(*original + 2), 0};
        else s = exports.resolve(value, dll);
        require(slot <= pe.image_size && pe.width <= pe.image_size - slot, "IAT slot outside image");
        s.slot = slot; require(result.emplace(slot, std::move(s)).second, "Overlapping import slots");
    };
    auto scan = [&](std::uint64_t rva, std::uint64_t size) {
        require(size && size % pe.width == 0, "IAT size must be a positive multiple of pointer width");
        const auto data = pe.rva(rva, size);
        for (std::size_t i = 0; i < size; i += pe.width) if (const auto value = get(data, i, pe.width)) add(rva + i, value);
    };
    if (iat_rva) { require(iat_size.has_value(), "Missing IAT size"); scan(*iat_rva, *iat_size); }
    else {
        const auto [directory, size] = pe.directory(1);
        if (directory && size >= 20) {
            bool terminated = false;
            for (std::size_t i = 0; i < std::min<std::uint64_t>(size / 20, 4096); ++i) {
                const auto d = pe.rva(directory + i * 20, 20); const auto oft = get(d, 0, 4), name = get(d, 12, 4), first = get(d, 16, 4);
                if (!oft && !name && !first) { terminated = true; break; }
                require(name && first, "Malformed import descriptor"); const auto dll = pe.string(name); bool end = false;
                for (unsigned j = 0; j < 65536; ++j) {
                    const auto slot = first + j * pe.width, value = get(pe.rva(slot, pe.width), 0, pe.width);
                    if (!value) { end = true; break; }
                    const auto original = oft ? get(pe.rva(oft + j * pe.width, pe.width), 0, pe.width) : 0;
                    add(slot, value, dll, original ? std::optional(original) : std::nullopt);
                }
                require(end, "Unterminated IAT");
            }
            require(terminated, "Unterminated import descriptor table");
        }
        if (result.empty()) {
            const auto [iat, length] = pe.directory(12);
            if (iat && length) scan(iat, length);
            else {
                exports.load(); std::vector<std::pair<std::uint64_t, std::uint64_t>> runs;
                for (const auto& section : pe.sections) {
                    if (section.flags & 0x20000000) continue;
                    const auto end = section.rva + std::max(section.virtual_size, section.raw_size);
                    std::vector<std::pair<std::uint64_t, std::uint64_t>> run; std::optional<std::uint64_t> previous = 0;
                    for (auto slot = align(section.rva, pe.width); slot <= end && pe.width <= end - slot; slot += pe.width) {
                        std::uint64_t value;
                        try { value = get(pe.rva(slot, pe.width), 0, pe.width); }
                        catch (const Cancelled&) { throw; } catch (const Error&) { require(run.empty(), "Unreadable data adjacent to possible IAT; specify bounds"); previous.reset(); continue; }
                        if (exports.by_address.contains(value)) { require(!run.empty() || previous == 0, "Possible IAT has unknown preceding pointer; specify bounds"); run.emplace_back(slot, value); }
                        else {
                            if (run.size() >= 2) { require(value == 0, "Possible IAT has unresolved pointer; specify bounds/import map"); runs.insert(runs.end(), run.begin(), run.end()); }
                            run.clear();
                        }
                        previous = value;
                    }
                    require(run.empty(), "Possible IAT reaches section boundary; specify bounds");
                }
                for (const auto& [slot, value] : runs) add(slot, value);
            }
        }
    }
    require(!result.empty(), "No imports recovered. Supply --iat-rva/--iat-size or use --no-imports");
    std::vector<Import> entries; for (auto& [slot, s] : result) entries.push_back(std::move(s)); return entries;
}
static void append_string(Bytes& data, const std::string& text, std::size_t limit) {
    require(!text.empty() && text.size() <= limit && std::all_of(text.begin(), text.end(), [](unsigned char c) { return c && c < 128; }), "Invalid ASCII import name");
    data.insert(data.end(), text.begin(), text.end()); data.push_back(0);
}
ImportSection build_imports(const std::vector<Import>& entries, std::uint64_t rva, unsigned width) {
    require(width == 4 || width == 8, "Invalid import pointer width");
    std::vector<std::vector<Import>> groups;
    for (const auto& e : entries) {
        if (!groups.empty() && lower(groups.back().back().dll) == lower(e.dll) && groups.back().back().slot + width == e.slot) groups.back().push_back(e);
        else groups.push_back({e});
    }
    ImportSection result{Bytes(20 * (groups.size() + 1)), {}, 20 * (groups.size() + 1)};
    for (std::size_t i = 0; i < groups.size(); ++i) {
        const auto& group = groups[i]; const auto dll_rva = rva + result.data.size(); append_string(result.data, group.front().dll, 4096);
        std::vector<std::uint64_t> lookup;
        for (const auto& e : group) {
            if (e.name) {
                result.data.resize(align(result.data.size(), 2)); lookup.push_back(rva + result.data.size());
                result.data.resize(result.data.size() + 2); append_string(result.data, *e.name, 65534);
            } else { require(e.ordinal && e.ordinal <= 65535, "Invalid import ordinal"); lookup.push_back((1ULL << (width * 8 - 1)) | e.ordinal); }
        }
        result.data.resize(align(result.data.size(), width)); const auto lookup_rva = rva + result.data.size();
        for (std::size_t j = 0; j < group.size(); ++j) {
            const auto offset = result.data.size(); result.data.resize(offset + width); put(result.data, offset, lookup[j], width); result.patches.emplace_back(group[j].slot, lookup[j]);
        }
        result.data.resize(result.data.size() + width); require(lookup_rva <= UINT32_MAX && dll_rva <= UINT32_MAX, "Import section RVA overflow");
        put(result.data, i * 20, lookup_rva, 4); put(result.data, i * 20 + 12, dll_rva, 4); put(result.data, i * 20 + 16, group.front().slot, 4);
    }
    return result;
}
BackingImage::BackingImage(Bytes raw, const PE& live, std::string source) {
    require(raw.size() >= 64 && raw.size() <= max_file, "Invalid backing file size");
    PE disk([&raw](std::uint64_t a, std::size_t n) { return slice(raw, a, n); }, 0);
    auto expected = disk.headers; auto adjustments = Json::array();
    const auto preferred = get(disk.headers, disk.opt + disk.base_offset, disk.width);
    if (disk.opt == live.opt && disk.width == live.width) {
        const auto mapped = get(live.headers, live.opt + live.base_offset, live.width);
        if (preferred != mapped && mapped == live.base) { put(expected, disk.opt + disk.base_offset, mapped, disk.width); adjustments.push(Json::object({{"field", "ImageBase"}, {"file", preferred}, {"memory", mapped}})); }
    }
    require(expected == live.headers, "Backing PE headers do not exactly match loaded image; refusing file recovery");
    data_.resize(disk.image_size); copy_into(data_, 0, disk.headers);
    for (std::size_t i = 0; i < disk.sections.size(); ++i) {
        const auto& s = disk.sections[i]; copy_into(data_, s.rva, slice(raw, get(disk.headers, disk.section_table + i * 40 + 20, 4), s.raw_size));
    }
    width_ = disk.width; headers_size_ = disk.headers_size; delta_ = live.base - preferred;
    const auto [rva, size] = disk.directory(5); if (rva && size) relocations_ = slice(data_, rva, size);
    identity = Json::object({{"path", std::move(source)}, {"sha256", sha256(raw)}, {"verification", "all PE header bytes match after recorded ImageBase normalization"},
                            {"header_adjustments", adjustments}, {"preferred_image_base", preferred}, {"loaded_image_base", live.base},
                            {"relocation_delta_modulo_2_64", delta_}, {"relocations_applied", 0}});
}
void BackingImage::relocate() {
    if (!delta_) return;
    require(!relocations_.empty(), "Backing PE requires ASLR adjustment but has no relocations"); std::set<std::uint64_t> seen;
    for (std::size_t pos = 0; pos < relocations_.size();) {
        check_cancelled(); if (std::all_of(relocations_.begin() + static_cast<std::ptrdiff_t>(pos), relocations_.end(), [](auto b) { return b == 0; })) break;
        const auto page = get(relocations_, pos, 4), size = get(relocations_, pos + 4, 4);
        require(size >= 8 && size % 2 == 0 && size <= relocations_.size() - pos, "Invalid relocation block");
        for (std::size_t i = pos + 8; i < pos + size; i += 2) {
            const auto entry = get(relocations_, i, 2), type = entry >> 12, a = page + (entry & 4095);
            if (!type) continue;
            unsigned width = 0; std::uint64_t adjustment = delta_; bool highadj = false;
            if (type == 10 && width_ == 8) width = 8;
            else if (type == 3 && width_ == 4) width = 4;
            else if (type == 1 && width_ == 4) { width = 2; adjustment = (delta_ >> 16) & 65535; }
            else if (type == 2 && width_ == 4) { width = 2; adjustment = delta_ & 65535; }
            else if (type == 4 && width_ == 4) { width = 2; highadj = true; }
            else throw Error("Unsupported backing PE relocation type " + std::to_string(type));
            require(a >= headers_size_ && a <= data_.size() && width <= data_.size() - a, "Invalid relocation target");
            for (unsigned j = 0; j < width; ++j) require(seen.insert(a + j).second, "Overlapping relocation targets");
            auto value = get(data_, a, width);
            if (highadj) {
                require(i + 2 < pos + size, "Truncated HIGHADJ relocation"); i += 2; const auto extra = get(relocations_, i, 2);
                // Unsigned modular arithmetic avoids signed overflow for negative deltas.
                const auto signed_extra = extra < 32768 ? extra : extra | ~65535ULL;
                value = ((value << 16) + signed_extra + delta_ + 0x8000) >> 16;
            } else value += adjustment;
            put(data_, a, value, width); ++count_;
        }
        pos += size;
    }
}
Bytes BackingImage::read(std::uint64_t rva, std::size_t size) {
    require(rva <= data_.size() && size <= data_.size() - rva, "Backing image RVA out of bounds");
    if (!relocated_) { relocate(); relocated_ = true; identity["relocations_applied"] = count_; }
    return slice(data_, rva, size);
}
Json dump_pe(CaptureTarget target, std::uint64_t base, const std::filesystem::path& path, const DumpOptions& options) {
    const auto started = std::chrono::steady_clock::now(); target.validate(); PE pe(target.read, base);
    const auto destination = std::filesystem::absolute(path);
    // symlink_status also detects dangling symlinks.
    require(!std::filesystem::exists(std::filesystem::symlink_status(destination)) && !std::filesystem::exists(std::filesystem::symlink_status(destination.string() + ".json")), "Output or report already exists");
    std::unique_ptr<BackingImage> backing;
    if (options.backing_file) backing = std::make_unique<BackingImage>(read_file(*options.backing_file), pe, std::filesystem::absolute(*options.backing_file).string());
    Bytes image(pe.image_size); copy_into(image, 0, pe.headers); auto missing = Json::array(), recovered = Json::array();
    auto record = [](Json& ranges, std::uint64_t address, std::size_t size, Json value) {
        auto& entries = ranges.items();
        if (!entries.empty() && entries.back().at("address").integer() + entries.back().at("size").integer() == address)
            entries.back()["size"] = entries.back().at("size").integer() + size;
        else { value["address"] = address; value["size"] = std::uint64_t(size); ranges.push(std::move(value)); }
    };
    for (const auto& section : pe.sections) {
        std::cerr << "Capturing " << section.name << '\n'; const auto size = std::max(section.virtual_size, section.raw_size);
        for (std::uint64_t offset = 0; offset < size;) {
            check_cancelled(); const auto address = base + section.rva + offset, rva = section.rva + offset;
            const auto count = std::min<std::uint64_t>(size - offset, 4096 - (address & 4095));
            try { const auto data = target.read(address, count); require(data.size() == count, "Short capture read"); copy_into(image, rva, data); }
            catch (const Cancelled&) { throw; }
            catch (const Error& error) {
                const auto* page = dynamic_cast<const PageUnavailable*>(&error);
                const bool eligible = page && page->file_backed && page->file_backed_va == (address & ~4095ULL) && page->image_vad_start == base;
                if (!backing && eligible && options.backing_provider) backing = std::make_unique<BackingImage>(options.backing_provider(), pe, "automatic read-only guest disk recovery");
                if (backing && eligible) {
                    copy_into(image, rva, backing->read(rva, count)); record(recovered, address, count, Json::object({{"rva", rva}, {"source", "matching backing PE, relocated to live base"}}));
                } else {
                    require(options.allow_missing, "Cannot capture " + hex(address) + ": " + error.what() + ". Supply matching --backing-file for eligible image pages, or explicitly accept --allow-missing");
                    record(missing, address, count, Json::object({{"error", error.what()}}));
                }
            }
            offset += count;
        }
    }
    auto captured = [&](std::uint64_t a, std::size_t size) {
        require(a >= base && a - base <= image.size() && size <= image.size() - (a - base), "Import metadata outside captured image");
        for (const auto& range : missing.items()) {
            const auto start = range.at("address").integer(), length = range.at("size").integer();
            require(!(a < start + length && start < a + size), "Required import metadata is unreadable; provide explicit IAT/import map");
        }
        return slice(image, a - base, size);
    };
    PE captured_pe(captured, base); ExportIndex exports(target.read, target.modules(), pe.width);
    const auto entries = options.imports ? recover_imports(captured_pe, exports, options.iat_rva, options.iat_size, options.import_map) : std::vector<Import>{};
    auto sections = pe.sections; std::optional<ImportSection> imports; std::uint64_t import_rva = 0;
    if (options.imports) {
        import_rva = align(pe.image_size, pe.section_alignment); imports = build_imports(entries, import_rva, pe.width);
        sections.push_back({".imprec", import_rva, imports->data.size(), imports->data.size(), 0xc0000040});
        for (const auto& [slot, value] : imports->patches) {
            require(slot + pe.width <= pe.headers_size || std::any_of(pe.sections.begin(), pe.sections.end(), [&](const Section& s) { return s.rva <= slot && slot + pe.width <= s.rva + std::max(s.virtual_size, s.raw_size); }), "IAT slot outside captured headers/sections");
            put(image, slot, value, pe.width);
        }
    }
    const auto headers_size = align(std::max(pe.headers_size, pe.section_table + sections.size() * 40), pe.file_alignment);
    for (const auto& section : pe.sections) require(headers_size <= section.rva, "Insufficient virtual header space");
    Bytes output(headers_size); copy_into(output, 0, slice(image, 0, pe.headers_size));
    require(sections.size() <= 96 && (pe.width == 8 || base <= UINT32_MAX), "Reconstructed image exceeds PE limits");
    put(output, pe.pe + 6, sections.size(), 2); put(output, pe.opt + pe.base_offset, base, pe.width);
    if (options.oep) { require(*options.oep < pe.image_size, "OEP must be an RVA inside image"); put(output, pe.opt + 16, *options.oep, 4); }
    put(output, pe.opt + 60, headers_size, 4); put(output, pe.opt + 64, 0, 4);
    auto set_dir = [&](unsigned index, std::uint64_t rva, std::uint64_t size) {
        if (index >= pe.directory_count) { require(!rva && !size, "Optional header lacks data directory space"); return; }
        put(output, pe.opt + pe.dir_offset + index * 8, rva, 4); put(output, pe.opt + pe.dir_offset + index * 8 + 4, size, 4);
    };
    set_dir(4, 0, 0); set_dir(11, 0, 0);
    if (imports) { set_dir(1, import_rva, imports->descriptor_size); set_dir(12, entries.front().slot, entries.back().slot + pe.width - entries.front().slot); }
    std::uint64_t image_end = 0; for (const auto& s : sections) image_end = std::max(image_end, s.rva + std::max(s.virtual_size, s.raw_size));
    require(align(image_end, pe.section_alignment) <= UINT32_MAX, "Reconstructed image size overflow"); put(output, pe.opt + 56, align(image_end, pe.section_alignment), 4);
    auto file_sections = Json::array();
    for (std::size_t i = 0; i < sections.size(); ++i) {
        const auto& s = sections[i]; const auto raw_offset = align(output.size(), pe.file_alignment), size = std::max(s.virtual_size, s.raw_size), raw_size = align(size, pe.file_alignment);
        require(raw_offset <= max_file && raw_size <= max_file - raw_offset, "Reconstructed file exceeds 1 GiB limit");
        output.resize(raw_offset + raw_size); copy_into(output, raw_offset, imports && s.rva == import_rva ? imports->data : slice(image, s.rva, size));
        const auto offset = pe.section_table + i * 40; std::fill_n(output.begin() + static_cast<std::ptrdiff_t>(offset), 40, 0);
        copy_into(output, offset, std::span(reinterpret_cast<const std::uint8_t*>(s.name.data()), std::min<std::size_t>(s.name.size(), 8)));
        put(output, offset + 8, s.virtual_size, 4); put(output, offset + 12, s.rva, 4); put(output, offset + 16, raw_size, 4); put(output, offset + 20, raw_offset, 4);
        put(output, offset + 36, (s.flags & ~0x80ULL) | (raw_size ? 0x40 : 0), 4);
        file_sections.push(Json::object({{"name", s.name}, {"rva", s.rva}, {"size", size}, {"raw_offset", raw_offset}, {"raw_size", raw_size}}));
    }
    auto raw_for = [&](std::uint64_t rva, std::uint64_t size) -> std::uint64_t {
        if (rva <= headers_size && size <= headers_size - rva) return rva;
        for (const auto& s : file_sections.items()) {
            const auto start = s.at("rva").integer(), length = s.at("size").integer();
            if (rva >= start && rva - start <= length && size <= length - (rva - start)) return s.at("raw_offset").integer() + rva - start;
        }
        throw Error("Data directory outside captured sections");
    };
    const auto [debug_rva, debug_size] = pe.directory(6);
    if (debug_rva && debug_size) {
        try {
            require(debug_size % 28 == 0 && debug_size <= 28 * 4096, "Invalid debug directory"); const auto position = raw_for(debug_rva, debug_size);
            for (std::size_t i = 0; i < debug_size; i += 28) { const auto size = get(output, position + i + 16, 4), rva = get(output, position + i + 20, 4); put(output, position + i + 24, size ? raw_for(rva, size) : 0, 4); }
        } catch (const Error&) { put(output, pe.opt + pe.dir_offset + 48, 0, 8); }
    }
    target.validate(); const auto digest = sha256(output); auto imports_json = Json::array(), shared = Json::array();
    for (const auto& i : entries) imports_json.push(i.json());
    if (target.shared_pages) for (const auto a : *target.shared_pages) shared.push(a);
    const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count();
    auto report = Json::object({{"format", "vmidbg-pe-dump"}, {"version", 1}, {"implementation", "qemu-process-dumper C++"}, {"process", target.process.json()},
                               {"image_base", base}, {"entry_point_rva", options.oep.value_or(pe.entry)}, {"architecture", pe.width == 8 ? "x64" : "x86"},
                               {"size", output.size()}, {"sha256", digest}, {"guest_pause_requested", false}, {"guest_memory_writes", false},
                               {"capture_consistency", "live, non-atomic"}, {"imports_rebuilt", options.imports}, {"capture_sources", recovered.items().empty() ? "memory" : "memory and backing file"},
                               {"imports", imports_json}, {"export_read_errors", exports.errors}, {"missing_pages", missing}, {"sections", file_sections},
                               {"duration_milliseconds", std::uint64_t(duration)}, {"shared_image_pages_recovered", shared}, {"backing_file", backing ? backing->identity : Json{}},
                               {"file_recovered_pages", recovered}, {"limits", Json(Json::Array{"Overlays and certificates are absent", "Live capture is non-atomic; execution is not guaranteed"})}});
    check_cancelled(); publish_pair(destination, output, report);
    return Json::object({{"file", destination.string()}, {"report", destination.string() + ".json"}, {"pid", target.process.pid}, {"size", output.size()}, {"sha256", digest},
                         {"imports", entries.size()}, {"missing_ranges", missing.items().size()}, {"file_recovered_ranges", recovered.items().size()}});
}
} // namespace qpd
