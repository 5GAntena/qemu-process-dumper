#include "qpd/windows.hpp"
#include <iostream>
#include <lzma.h>
#include <zlib.h>

namespace qpd {
Profile::Profile(Json value) : data(std::move(value)) {
    require(data.at("metadata").at("windows").at("pdb").at("machine_type").integer() == 0x8664, "Only AMD64 Windows kernel profiles are supported");
    symbol("PsActiveProcessHead"); offset("_EPROCESS", "UniqueProcessId"); offset("_EPROCESS", "ActiveProcessLinks"); offset("_KPROCESS", "DirectoryTableBase");
}
Profile Profile::load(const std::filesystem::path& path) {
    const auto raw = read_file(path, 128 * 1024 * 1024); Bytes text;
    const auto ext = path.extension();
    if (ext == ".xz" || ext == ".gz") {
        constexpr std::size_t limit = 128 * 1024 * 1024;
        std::size_t consumed = 0; bool done = false;
        if (ext == ".xz") {
            lzma_stream stream = LZMA_STREAM_INIT;
            require(lzma_stream_decoder(&stream, 256 * 1024 * 1024, LZMA_CONCATENATED) == LZMA_OK, "Cannot initialize XZ decoder");
            struct End { lzma_stream* p; ~End() { lzma_end(p); } } end{&stream};
            stream.next_in = raw.data(); stream.avail_in = raw.size();
            while (!done) {
                std::uint8_t block[65536]; stream.next_out = block; stream.avail_out = sizeof block;
                const auto status = lzma_code(&stream, LZMA_FINISH);
                require(status == LZMA_OK || status == LZMA_STREAM_END, "Invalid XZ profile");
                const auto size = sizeof block - stream.avail_out; require(size <= limit - text.size(), "Profile exceeds decompressed limit"); text.insert(text.end(), block, block + size);
                done = status == LZMA_STREAM_END; require(done || size || stream.avail_in != consumed, "Truncated XZ profile"); consumed = stream.avail_in; check_cancelled();
            }
        } else {
            z_stream stream{}; require(inflateInit2(&stream, 15 + 16) == Z_OK, "Cannot initialize gzip decoder");
            struct End { z_stream* p; ~End() { inflateEnd(p); } } end{&stream};
            stream.next_in = const_cast<Bytef*>(raw.data()); stream.avail_in = static_cast<uInt>(raw.size());
            while (!done) {
                std::uint8_t block[65536]; stream.next_out = block; stream.avail_out = sizeof block;
                const auto status = inflate(&stream, Z_NO_FLUSH);
                require(status == Z_OK || status == Z_STREAM_END, "Invalid gzip profile");
                const auto size = sizeof block - stream.avail_out; require(size <= limit - text.size(), "Profile exceeds decompressed limit"); text.insert(text.end(), block, block + size);
                done = status == Z_STREAM_END; require(done || size || stream.avail_in != consumed, "Truncated gzip profile"); consumed = stream.avail_in; check_cancelled();
            }
            require(stream.avail_in == 0, "Trailing gzip profile data");
        }
    } else text = raw;
    return Profile(Json::parse(std::string_view(reinterpret_cast<const char*>(text.data()), text.size())));
}
std::uint64_t Profile::offset(std::string_view type, std::string_view field) const {
    const auto value = data.at("user_types").at(type).at("fields").at(field).at("offset").integer();
    require(value < 1024 * 1024, "Invalid profile field offset"); return value;
}
std::optional<std::uint64_t> Profile::optional(std::string_view type, std::string_view field) const {
    const auto& types = data.at("user_types");
    if (!types.contains(type) || !types.at(type).at("fields").contains(field)) return {};
    return offset(type, field);
}
std::uint64_t Profile::symbol(std::string_view name) const {
    const auto value = data.at("symbols").at(name).at("address").integer(); require(value < max_file, "Invalid image-relative symbol"); return value;
}
PageUnavailable::PageUnavailable(std::uint64_t value, std::string message, bool file)
    : Error(std::move(message) + " (PTE " + hex(value) + ")"), entry(value), file_backed(file) {}
AddressSpace::AddressSpace(Read physical, std::uint64_t root, bool software)
    : dtb(root & address_mask), physical_(std::move(physical)), software_(software) { require(dtb, "Zero page-table root"); }
std::optional<std::uint64_t> AddressSpace::walk(std::uint64_t address, Checks& checks, unsigned depth) const {
    require(depth <= 8 && canonical(address), "Invalid/cyclic Windows page translation"); auto table = dtb;
    for (unsigned shift : {39U, 30U, 21U, 12U}) {
        const auto slot = table + ((address >> shift) & 511) * 8;
        const auto entry = get(physical_(slot, 8), 0, 8); checks.emplace_back(slot, entry);
        if (!(entry & 1)) {
            require(software_ && shift == 12, "Page table not present for VA " + hex(address));
            try { return leaf(entry, address & 4095, checks, depth); }
            catch (PageUnavailable& error) { if (depth == 0) error.primary_entry = entry; throw; }
        }
        if (shift == 12 || ((shift == 21 || shift == 30) && (entry & 128))) {
            const auto mask = (1ULL << shift) - 1; return (entry & address_mask & ~mask) | (address & mask);
        }
        require(!(entry & 128), "Reserved page-table bit"); table = entry & address_mask;
    }
    throw Error("Unreachable page-table level");
}
std::optional<std::uint64_t> AddressSpace::leaf(std::uint64_t entry, std::uint64_t offset, Checks& checks, unsigned depth, bool prototype) const {
    require(depth <= 8, "Excessive prototype PTE recursion");
    if ((entry & 1) || (entry & 0xc01) == 0x800) return (entry & address_mask) | offset;
    if (prototype && (entry & 0x400)) throw PageUnavailable(entry, "Shared image page is file-backed and not resident in RAM", true);
    if ((entry & 0x8000000000070401ULL) == 0x8000000000000400ULL) {
        const auto pointer = (entry >> 16) | 0xffff000000000000ULL;
        if (pointer < 0xffff800000000000ULL || pointer == 0xffffffffffff0000ULL || (pointer & 7)) throw PageUnavailable(entry, "Unsupported prototype PTE");
        const auto physical = walk(pointer, checks, depth + 1); require(physical.has_value(), "Prototype points to demand-zero data");
        const auto value = get(physical_(*physical, 8), 0, 8); checks.emplace_back(*physical, value);
        return leaf(value, offset, checks, depth + 1, true);
    }
    if (entry && !(entry & ~0x3e0ULL)) return {};
    throw PageUnavailable(entry, "Page is absent, paged out, compressed, or has an unsupported PTE");
}
Bytes AddressSpace::read(std::uint64_t address, std::size_t size) const {
    require(size <= 16 * 1024 * 1024 && address <= UINT64_MAX - size && canonical(address) &&
            (!size || (canonical(address + size - 1) && (address >> 48) == ((address + size - 1) >> 48))), "Invalid virtual read range");
    Bytes out; out.reserve(size);
    while (out.size() < size) {
        check_cancelled(); const auto va = address + out.size(); const auto count = std::min<std::size_t>(size - out.size(), 4096 - (va & 4095));
        for (unsigned attempt = 0;; ++attempt) {
            Checks checks; std::optional<std::uint64_t> physical;
            try { physical = walk(va, checks); }
            catch (const PageUnavailable& e) {
                if (!resolver || !e.primary_entry || (*e.primary_entry != 0 && !(*e.primary_entry & 0x400))) throw;
                physical = resolver(va, checks);
            }
            auto data = physical ? physical_(*physical, count) : Bytes(count);
            require(data.size() == count, "Short physical read");
            if (std::all_of(checks.begin(), checks.end(), [&](const auto& item) { return get(physical_(item.first, 8), 0, 8) == item.second; })) {
                out.insert(out.end(), data.begin(), data.end()); break;
            }
            require(attempt < 2, "VA repeatedly changed mappings during capture");
        }
    }
    return out;
}
std::uint64_t AddressSpace::scalar(std::uint64_t a, unsigned width) const { return get(read(a, width), 0, width); }
void AddressSpace::user_mappings(const std::function<void(const Mapping&)>& consume) const {
    std::set<std::uint64_t> ancestors; std::size_t tables = 0;
    std::function<void(std::uint64_t,unsigned,std::uint64_t,bool,bool)> walk_table;
    walk_table = [&](std::uint64_t table, unsigned shift, std::uint64_t base, bool writable, bool executable) {
        check_cancelled(); require(++tables <= 1000000 && ancestors.insert(table).second, "Cyclic/excessive user page tables");
        const auto data = physical_(table,4096); require(data.size()==4096,"Short user page-table read");
        const unsigned count = shift == 39 ? 256 : 512;
        for (unsigned index=0;index<count;++index) {
            const auto entry=get(data,index*8,8); if((entry&5)!=5)continue;
            const auto address=base|(std::uint64_t(index)<<shift); const bool write=writable&&(entry&2),execute=executable&&!(entry&(1ULL<<63));
            require(shift<=30||!(entry&128),"Reserved large-page bit in user page table");
            if(shift==12||((shift==21||shift==30)&&(entry&128))) {
                const std::uint64_t size=1ULL<<shift;consume({address,entry&address_mask&~(size-1),size,write,execute});
            } else walk_table(entry&address_mask,shift-9,address,write,execute);
        }
        ancestors.erase(table);
    };
    walk_table(dtb,39,0,true,true);
}
Json Process::json() const { return Json::object({{"pid", pid}, {"name", name}, {"eprocess", eprocess}, {"dtb", dtb}, {"user_dtb", user_dtb}, {"peb", peb}}); }
Json Module::json() const {
    auto value = Json::object({{"base", base}, {"size", size}, {"name", name}});
    if (!path.empty()) value["path"] = path;
    if (!name_error.empty()) value["name_read_error"] = name_error;
    return value;
}
Json pe_identity(const AddressSpace& space, std::uint64_t base) {
    require(space.read(base, 2) == Bytes({'M', 'Z'}), "Kernel base does not point to a PE");
    const auto offset = space.scalar(base + 0x3c, 4); require(offset >= 64 && offset <= 1024 * 1024, "Invalid kernel PE offset");
    const auto fixed = space.read(base + offset, 24); const auto opt = base + offset + 24;
    require(get(fixed, 0, 4) == 0x4550 && get(fixed, 4, 2) == 0x8664 && get(fixed, 20, 2) >= 168 && space.scalar(opt, 2) == 0x20b && space.scalar(opt + 108, 4) > 6, "Invalid AMD64 kernel debug directory");
    const auto image_size = space.scalar(opt + 56, 4), rva = space.scalar(opt + 160, 4), size = space.scalar(opt + 164, 4);
    require(size && size <= 28 * 128 && size % 28 == 0 && rva && rva < image_size && size <= image_size - rva, "Invalid debug range");
    const auto entries = space.read(base + rva, size);
    for (std::size_t i = 0; i < size; i += 28) {
        if (get(entries, i + 12, 4) != 2) continue;
        const auto length = get(entries, i + 16, 4), address = get(entries, i + 20, 4);
        require(length > 24 && length <= 4096 && address && address < image_size && length <= image_size - address, "Invalid CodeView range");
        const auto record = space.read(base + address, length);
        if (get(record, 0, 4) != 0x53445352) continue;
        std::string guid; const char* digits = "0123456789ABCDEF";
        for (const unsigned n : {7U,6U,5U,4U,9U,8U,11U,10U,12U,13U,14U,15U,16U,17U,18U,19U}) { guid += digits[record[n] >> 4]; guid += digits[record[n] & 15]; }
        std::string name(record.begin() + 24, std::find(record.begin() + 24, record.end(), 0)); std::replace(name.begin(), name.end(), '\\', '/');
        return Json::object({{"GUID", guid}, {"age", get(record, 20, 4)}, {"database", name.substr(name.find_last_of('/') + 1)}, {"machine_type", 0x8664}});
    }
    throw Error("No RSDS identity in kernel PE");
}
Windows::Windows(Read reader, const Profile& p, std::uint64_t b, std::uint64_t root)
    : physical(std::move(reader)), profile(p), base(b), kernel(physical, root) {
    AddressSpace hardware(physical, root, false); const auto actual = pe_identity(hardware, base);
    identity = actual;
    const auto& expected = profile.data.at("metadata").at("windows").at("pdb");
    for (const auto* key : {"GUID", "database", "age", "machine_type"}) {
        if (std::string_view(key) == "GUID" || std::string_view(key) == "database") {
            auto a = lower(actual.at(key).string()), e = lower(expected.at(key).string());
            std::erase(a, '-'); std::erase(e, '-'); require(a == e, "Kernel/profile mismatch: " + std::string(key));
        } else require(actual.at(key) == expected.at(key), "Kernel/profile mismatch: " + std::string(key));
    }
}
std::vector<std::uint64_t> Windows::list(const AddressSpace& space, std::uint64_t head, std::uint64_t offset) const {
    auto previous = head, node = space.scalar(head); std::set<std::uint64_t> seen; std::vector<std::uint64_t> result;
    while (node != head) {
        require(node && !(node & 7) && canonical(node) && node >= offset && seen.size() < 65536 && seen.insert(node).second, "Corrupt/excessive Windows linked list");
        require(space.scalar(node + 8) == previous, "Windows list backlink mismatch");
        result.push_back(node - offset); previous = node; node = space.scalar(node);
    }
    require(space.scalar(head + 8) == previous, "Windows list tail mismatch"); return result;
}
Process Windows::process_at(std::uint64_t a) const {
    auto name = kernel.read(a + profile.offset("_EPROCESS", "ImageFileName"), 15); name.erase(std::find(name.begin(), name.end(), 0), name.end());
    for (auto& c : name) if (c > 127) c = '?';
    const auto pcb = a + profile.offset("_EPROCESS", "Pcb"); const auto user = profile.optional("_KPROCESS", "UserDirectoryTableBase");
    return {kernel.scalar(a + profile.offset("_EPROCESS", "UniqueProcessId")), a,
            kernel.scalar(pcb + profile.offset("_KPROCESS", "DirectoryTableBase")) & address_mask,
            user ? kernel.scalar(pcb + *user) & address_mask : 0,
            kernel.scalar(a + profile.offset("_EPROCESS", "Peb")), {name.begin(), name.end()}};
}
std::vector<Process> Windows::processes() const {
    for (unsigned attempt = 0;; ++attempt) {
        try {
            std::vector<Process> result;
            for (auto a : list(kernel, base + profile.symbol("PsActiveProcessHead"), profile.offset("_EPROCESS", "ActiveProcessLinks"))) result.push_back(process_at(a));
            return result;
        } catch (const Cancelled&) { throw; } catch (const Error&) { if (attempt == 2) throw; }
    }
}
std::unique_ptr<Target> Windows::attach(std::uint64_t pid) {
    for (const auto& p : processes()) if (p.pid == pid) return std::make_unique<Target>(*this, p);
    throw Error("Windows PID " + std::to_string(pid) + " was not found");
}
Target::Target(Windows& w, Process p) : process(std::move(p)), space(w.physical, process.dtb), windows_(w), create_offset_(w.profile.optional("_EPROCESS", "CreateTime")) {
    if (create_offset_) create_time_ = w.kernel.scalar(process.eprocess + *create_offset_);
    space.resolver = [this](std::uint64_t a, Checks& checks) { return resolve_vad(a, checks); };
}
void Target::validate() const {
    const auto current = windows_.process_at(process.eprocess);
    require(current.pid == process.pid && current.dtb == process.dtb && current.peb == process.peb, "Target exited or its address space changed");
    if (create_offset_) require(windows_.kernel.scalar(process.eprocess + *create_offset_) == create_time_, "Process exited or its PID was reused");
}
Bytes Target::read(std::uint64_t a, std::size_t size) const { validate(); return space.read(a, size); }
std::uint64_t Target::main_image_base() const {
    const auto field = windows_.profile.optional("_EPROCESS", "SectionBaseAddress");
    if (field) return windows_.kernel.scalar(process.eprocess + *field);
    const auto mods = modules(); return mods.empty() ? 0 : mods.front().base;
}
std::vector<Module> Target::native_modules() const {
    const auto& p = windows_.profile; if (!process.peb) return {};
    const auto ldr = space.scalar(process.peb + p.offset("_PEB", "Ldr")); if (!ldr) return {};
    std::vector<Module> result;
    auto string = [&](std::uint64_t a) {
        const auto length = space.scalar(a + p.offset("_UNICODE_STRING", "Length"), 2); require(length <= 65534 && length % 2 == 0, "Invalid module name length");
        return utf16(space.read(space.scalar(a + p.offset("_UNICODE_STRING", "Buffer")), length));
    };
    for (const auto a : windows_.list(space, ldr + p.offset("_PEB_LDR_DATA", "InLoadOrderModuleList"), p.offset("_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks"))) {
        Module m{space.scalar(a + p.offset("_LDR_DATA_TABLE_ENTRY", "DllBase")), space.scalar(a + p.offset("_LDR_DATA_TABLE_ENTRY", "SizeOfImage"), 4), {}, {}, {}};
        try { m.name = string(a + p.offset("_LDR_DATA_TABLE_ENTRY", "BaseDllName")); }
        catch (const Cancelled&) { throw; } catch (const Error& e) { m.name = "module@" + hex(m.base); m.name_error = e.what(); }
        if (const auto full = p.optional("_LDR_DATA_TABLE_ENTRY", "FullDllName")) {
            try { m.path = string(a + *full); } catch (const Cancelled&) { throw; } catch (const Error&) { /* Optional path may be paged out. */ }
        }
        result.push_back(std::move(m));
    }
    return result;
}
std::vector<Module> Target::modules() const {
    for (unsigned attempt = 0;; ++attempt) {
        try {
            validate(); auto native = native_modules(); const auto& p = windows_.profile;
            const auto field = p.optional("_EPROCESS", "WoW64Process"); const auto wow = field ? windows_.kernel.scalar(process.eprocess + *field) : 0;
            if (!wow) return native;
            const auto peb = windows_.kernel.scalar(wow + p.offset("_EWOW64PROCESS", "Peb")), ldr = space.scalar(peb + 12, 4), head = ldr + 12;
            auto node = space.scalar(head, 4), previous = head; std::set<std::uint64_t> seen; std::vector<Module> result;
            while (node != head) {
                require(node && seen.size() < 4096 && seen.insert(node).second && space.scalar(node + 4, 4) == previous, "Corrupt WOW64 module list");
                auto string = [&](std::uint64_t offset) { const auto length = space.scalar(node + offset, 2); require(length <= 65534 && length % 2 == 0, "Invalid WOW64 name length"); return utf16(space.read(space.scalar(node + offset + 4, 4), length)); };
                Module m{space.scalar(node + 0x18, 4), space.scalar(node + 0x20, 4), string(0x2c), {}, {}};
                try { m.path = string(0x24); } catch (const Cancelled&) { throw; } catch (const Error&) { /* Optional path. */ }
                result.push_back(std::move(m)); previous = node; node = space.scalar(node, 4);
            }
            require(space.scalar(head + 4, 4) == previous, "Unstable WOW64 module list tail");
            for (auto& m : native) if (std::none_of(result.begin(), result.end(), [&](const Module& x) { return m.base == x.base; })) result.push_back(std::move(m));
            return result;
        } catch (const Cancelled&) { throw; } catch (const Error&) { if (attempt == 2) throw; }
    }
}
std::optional<std::uint64_t> Target::resolve_vad(std::uint64_t address, Checks& checks) {
    const auto& p = windows_.profile; auto& kernel = windows_.kernel;
    auto scalar = [&](std::uint64_t va, unsigned width = 8) {
        require((va & 7) + width <= 8, "Unaligned VAD scalar"); const auto physical = kernel.walk(va & ~7ULL, checks);
        require(physical.has_value(), "VAD metadata is not resident"); const auto data = windows_.physical(*physical, 8);
        checks.emplace_back(*physical, get(data, 0, 8)); return get(data, va & 7, width);
    };
    auto node = scalar(process.eprocess + p.offset("_EPROCESS", "VadRoot") + p.offset("_RTL_AVL_TREE", "Root"));
    const auto page = address >> 12; std::set<std::uint64_t> seen;
    for (unsigned depth = 0; depth < 128; ++depth) {
        require(node && canonical(node) && (node >> 63) && !(node & 7) && seen.insert(node).second, "Missing/cyclic image VAD");
        const auto vad = node - p.offset("_MMVAD_SHORT", "VadNode");
        const auto start = scalar(vad + p.offset("_MMVAD_SHORT", "StartingVpn"), 4) | (scalar(vad + p.offset("_MMVAD_SHORT", "StartingVpnHigh"), 1) << 32);
        const auto end = scalar(vad + p.offset("_MMVAD_SHORT", "EndingVpn"), 4) | (scalar(vad + p.offset("_MMVAD_SHORT", "EndingVpnHigh"), 1) << 32);
        require(start <= end, "Invalid VAD interval");
        if (page < start) { node = scalar(node + p.offset("_RTL_BALANCED_NODE", "Left")); continue; }
        if (page > end) { node = scalar(node + p.offset("_RTL_BALANCED_NODE", "Right")); continue; }
        const auto flags = scalar(vad + p.offset("_MMVAD_SHORT", "u"), 4);
        auto flag = [&](std::string_view name) {
            const auto& type = p.data.at("user_types").at("_MMVAD_FLAGS").at("fields").at(name).at("type");
            const auto shift = type.at("bit_position").integer(), bits = type.at("bit_length").integer();
            require(shift < 32 && bits && bits <= 32 - shift, "Invalid VAD flag bitfield"); return (flags >> shift) & ((1ULL << bits) - 1);
        };
        require(!flag("PrivateMemory") && flag("VadType") == 2, "Missing process page is not in a shared image VAD");
        const auto long_vad = vad - p.offset("_MMVAD", "Core"), first = scalar(long_vad + p.offset("_MMVAD", "FirstPrototypePte")), last = scalar(long_vad + p.offset("_MMVAD", "LastContiguousPte"));
        require(canonical(first) && (first >> 63) && !(first & 7), "Invalid prototype PTE pointer");
        auto index = page - start; require(index <= (UINT64_MAX - first) / 8, "Prototype pointer overflow"); auto prototype = first + index * 8;
        if (!(prototype <= last && canonical(last) && !(last & 7))) {
            auto subsection = scalar(long_vad + p.offset("_MMVAD", "Subsection")); std::set<std::uint64_t> visited; bool found = false;
            for (unsigned i = 0; i < 4096; ++i) {
                require(subsection && canonical(subsection) && (subsection >> 63) && visited.insert(subsection).second, "Invalid/cyclic image subsection");
                const auto base = scalar(subsection + p.offset("_SUBSECTION", "SubsectionBase")), count = scalar(subsection + p.offset("_SUBSECTION", "PtesInSubsection"), 4);
                require(canonical(base) && (base >> 63) && !(base & 7) && count && count <= (1ULL << 30), "Invalid subsection prototype array");
                require(i || first >= base, "First prototype is outside subsection"); const auto skip = i == 0 ? (first - base) / 8 : 0;
                require(skip < count, "First prototype is outside subsection");
                if (index < count - skip) { require(skip + index <= (UINT64_MAX - base) / 8, "Prototype overflow"); prototype = base + (skip + index) * 8; found = true; break; }
                index -= count - skip; subsection = scalar(subsection + p.offset("_SUBSECTION", "NextSubsection"));
            }
            require(found, "Excessive subsection chain");
        }
        try {
            const auto physical = kernel.leaf(scalar(prototype), address & 4095, checks, 1, true);
            require(physical.has_value(), "Shared prototype is not a resident data page"); shared_pages.insert(address & ~4095ULL); return physical;
        } catch (PageUnavailable& e) { if (e.file_backed) { e.file_backed_va = address & ~4095ULL; e.image_vad_start = start << 12; } throw; }
    }
    throw Error("Excessive VAD depth");
}
std::unique_ptr<Windows> discover(Physical& memory, const Profile& profile, std::optional<std::uint64_t> base, std::optional<std::uint64_t> dtb) {
    std::vector<std::pair<std::uint64_t, std::optional<std::uint64_t>>> candidates;
    if (dtb) candidates.emplace_back(*dtb, base);
    for (const auto& r : memory.regions) {
        const auto end = std::min<std::uint64_t>(0x100000, r.address + r.size);
        for (auto a = align(std::max<std::uint64_t>(0x1000, r.address), 4096); a < end; a += 4096) {
            try {
                const auto block = memory.read(a, 0xa8);
                if ((get(block, 0, 8) & 0xffffffffffff00ffULL) != 0x00000001000600e9ULL) continue;
                const auto hint = get(block, 0x70, 8), root = get(block, 0xa0, 8) & address_mask;
                if (root && canonical(hint) && (hint >> 63)) candidates.emplace_back(root, base ? base : hint);
            } catch (const Cancelled&) { throw; } catch (const Error&) { /* Low RAM holes are allowed. */ }
        }
    }
    if (base && !dtb) for (std::uint64_t a = 0x100000; a < 0x200000; a += 4096) {
        try { const auto page = memory.read(a, 4096); for (unsigned i = 256; i < 512; ++i) { const auto entry = get(page, i * 8, 8); if ((entry & 1) && (entry & address_mask) == a) { candidates.emplace_back(a, base); break; } } }
        catch (const Cancelled&) { throw; } catch (const Error&) { /* Candidate page absent. */ }
    }
    Read reader = [&memory](std::uint64_t a, std::size_t size) { return memory.read(a, size); };
    std::set<std::pair<std::uint64_t, std::uint64_t>> seen; std::string mismatch;
    for (const auto& [root, hint] : candidates) {
        if (!hint) continue;
        const auto start = *hint & ~65535ULL;
        for (unsigned i = 0; i < (base ? 1U : 1024U); ++i) {
            check_cancelled(); if (start < std::uint64_t(i) * 65536) break; const auto b = base.value_or(start - std::uint64_t(i) * 65536);
            if (!seen.emplace(root, b).second) continue;
            try {
                AddressSpace space(reader, root, false); if (space.read(b, 2) != Bytes({'M','Z'})) continue;
                auto w = std::make_unique<Windows>(reader, profile, b, root);
                if (w->process_at(w->kernel.scalar(b + profile.symbol("PsInitialSystemProcess"))).pid == 4) return w;
            } catch (const Cancelled&) { throw; } catch (const Error& e) { if (std::string_view(e.what()).find("mismatch") != std::string_view::npos) mismatch = e.what(); }
        }
    }
    throw Error("Could not locate matching Windows kernel. Supply current --kernel-base and --kernel-cr3 or matching --profile. " + mismatch);
}
} // namespace qpd
