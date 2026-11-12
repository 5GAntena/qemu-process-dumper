#include "qpd/backing.hpp"
#include "qpd/rsp.hpp"
#include "qpd/dump.hpp"
#include <array>
#include <chrono>
#include <iostream>
#include <sstream>

using namespace qpd;
namespace {
unsigned checks = 0;
void expect(bool condition, std::string_view message) { ++checks; require(condition, message); }
template<class F> void fails(F&& action, std::string_view text = {}) {
    ++checks;
    try { action(); } catch (const Error& e) { require(text.empty() || std::string_view(e.what()).find(text) != std::string_view::npos, std::string("Wrong failure: ") + e.what()); return; }
    throw Error("Expected operation to fail");
}
struct Temp {
    std::filesystem::path path = std::filesystem::temp_directory_path() / ("qpd-tests-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    Temp() { require(std::filesystem::create_directory(path), "Cannot reserve fixture directory"); }
    ~Temp() { std::error_code ec; std::filesystem::remove_all(path, ec); }
};
void text(Bytes& data, std::size_t offset, const std::string& value) { copy_into(data, offset, std::span(reinterpret_cast<const std::uint8_t*>(value.data()), value.size())); }
Bytes loaded(unsigned width = 8, bool dll = false, bool original = true) {
    Bytes data(0x4000); text(data, 0, "MZ"); put(data, 60, 0x80, 4); put(data, 0x80, 0x4550, 4);
    const auto optional = width == 8 ? 240U : 224U; const unsigned opt = 0x98, dir = opt + (width == 8 ? 112 : 96);
    put(data, 0x84, width == 8 ? 0x8664 : 0x14c, 2); put(data, 0x86, 3, 2); put(data, 0x94, optional, 2);
    put(data, opt, width == 8 ? 0x20b : 0x10b, 2); put(data, opt + 16, 0x1000, 4);
    put(data, opt + (width == 8 ? 24 : 28), dll ? 0x700000 : 0x400000, width);
    put(data, opt + 32, 0x1000, 4); put(data, opt + 36, 0x200, 4); put(data, opt + 56, 0x4000, 4); put(data, opt + 60, 0x400, 4); put(data, dir - 4, 16, 4);
    const std::array<std::string, 3> names{".text", ".rdata", ".data"};
    for (unsigned i = 0; i < 3; ++i) {
        const auto offset = opt + optional + 40 * i; text(data, offset, names[i]);
        put(data, offset + 8, 0x1000, 4); put(data, offset + 12, 0x1000 * (i + 1), 4); put(data, offset + 16, 0x1000, 4); put(data, offset + 20, 0x400 + i * 0x1000, 4);
        put(data, offset + 36, i == 0 ? 0x60000020 : (i == 1 ? 0x40000040 : 0xc0000040), 4);
    }
    std::fill(data.begin() + 0x1000, data.begin() + 0x2000, 0x90);
    if (dll) {
        put(data, dir, 0x2000, 4); put(data, dir + 4, 0x100, 4);
        put(data, 0x200c, 0x2080, 4); put(data, 0x2010, 8, 4); put(data, 0x2014, 2, 4); put(data, 0x2018, 1, 4);
        put(data, 0x201c, 0x20a0, 4); put(data, 0x2020, 0x20b0, 4); put(data, 0x2024, 0x20c0, 4);
        text(data, 0x2080, "fixture.dll"); put(data, 0x20a0, 0x1000, 4); put(data, 0x20a4, 0x1100, 4); put(data, 0x20b0, 0x20d0, 4); text(data, 0x20d0, "Alpha");
    } else {
        put(data, dir + 8, 0x2000, 4); put(data, dir + 12, 40, 4); put(data, dir + 96, 0x20a0, 4); put(data, dir + 100, width * 3, 4);
        put(data, 0x2000, original ? 0x2080 : 0, 4); put(data, 0x200c, 0x2050, 4); put(data, 0x2010, 0x20a0, 4); text(data, 0x2050, "fixture.dll");
        put(data, 0x2080, 0x2200, width); put(data, 0x2080 + width, (1ULL << (width * 8 - 1)) | 9, width);
        put(data, 0x20a0, 0x701000, width); put(data, 0x20a0 + width, 0x701100, width); text(data, 0x2202, "Alpha");
    }
    return data;
}
void json_tests() {
    const auto j = Json::parse(R"({"a":18446744073709551615,"b":[true,null,"\uD83D\uDE00"],"n":-12,"r":1.25e+3})");
    expect(j.at("a").integer() == UINT64_MAX, "JSON address precision"); expect(Json::parse(j.dump()) == j, "JSON round trip");
    expect(Json(0x8664) == Json::parse("34404"), "JSON programmatic integers equal parsed profile values");
    for (const auto* invalid : {"01", "[1,]", "{\"a\":1,\"a\":2}", "18446744073709551616", "\"\\uD800\"", "1e", "{}{}", "{\"a\":true,}"}) fails([&] { Json::parse(invalid); });
    fails([&] { j.at("n").integer(); }); fails([&] { number("-1"); }); fails([&] { number("0x"); });
    expect(sha256(Bytes{'a','b','c'}) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA256");
}
void memory_tests() {
    Bytes ram(0x20000); put(ram, 0x1000, 0x2003, 8); put(ram, 0x2000, 0x3003, 8); put(ram, 0x3000, 0x4003, 8); put(ram, 0x4000, 0xa001, 8);
    text(ram, 0xa000, "resident"); Read read = [&](std::uint64_t a, std::size_t n) { return slice(ram, a, n); }; AddressSpace space(read, 0x1000);
    expect(space.read(0, 8) == Bytes({'r','e','s','i','d','e','n','t'}), "Present mapping");
    put(ram, 0x4000, 0xa800, 8); expect(space.read(0, 8) == slice(ram, 0xa000, 8), "Transition mapping");
    put(ram, 0x4000, 0x80, 8); expect(space.read(0, 8) == Bytes(8), "Demand zero");
    put(ram, 0x4000, 0, 8); fails([&] { space.read(0, 8); }, "absent");
    put(ram, 0x4000, 0x123400000080ULL, 8); fails([&] { space.read(0, 8); });
    Checks mappings; fails([&] { space.leaf(0xbc0acc09da580460ULL, 0, mappings, 1, true); }, "file-backed");
    fails([&] { space.read(0x800000000000, 1); }, "Invalid virtual"); fails([&] { space.read(UINT64_MAX, 2); });
    put(ram, 0x3000, 0x83 | (1ULL << 12), 8); put(ram, 0, 0xab, 1); expect(space.read(0, 1) == Bytes{0xab}, "Large page PAT is not address");
    put(ram, 0x3000, 0x4003, 8); put(ram, 0x4000, 0xa001, 8); unsigned changes = 0;
    AddressSpace unstable([&](std::uint64_t a, std::size_t n) { auto data = slice(ram, a, n); if (a == 0xa000) { ++changes; put(ram, 0x4000, get(ram, 0x4000, 8) ^ 2, 8); } return data; }, 0x1000);
    fails([&] { unstable.read(0, 8); }, "changed mappings"); expect(changes == 3, "Bounded unstable reads");
    const auto regions = parse_ram_map("pc.ram 4 KiB 0x0 0x1000000 0x1000000 0x100000000 rw\n",
        "FlatView #0\n AS \"memory\", root: system\n  00000000-0002ffff (prio 0, ram): pc.ram KVM\n  00050000-000fffff (prio 0, ram): pc.ram @00050000 KVM\n  80000000-ffffffff (prio 0, ramd): PCI BAR\nFlatView #1\n AS \"cpu-smm-0\", root: smm\n  00030000-0004ffff (prio 0, ram): pc.ram @00030000\n");
    expect(regions.size() == 2 && regions[1].offset == 0x100050000, "Exclude SMM/MMIO");
    Temp temp; publish(temp.path / "ram", ram); Physical file(temp.path / "ram"); expect(file.read(0, 16) == slice(ram, 0, 16), "Offline physical reader");
    file.regions = {{0,4096,0}, {8192,4096,4096}}; fails([&] { file.read(4094,4); }, "ordinary guest RAM");
    CaptureTarget raw{read, [] {}, [] { return std::vector<Module>{}; }, {1,0,0x1000,0,0,"raw"}, nullptr};
    const auto summary=dump_range(raw,0xa000,32,temp.path/"raw");expect(read_file(temp.path/"raw")==slice(ram,0xa000,32),"Streaming raw range");
    expect(summary.at("sha256").string()==sha256(slice(ram,0xa000,32)),"Streaming raw digest");
    fails([&]{dump_range(raw,0,0,temp.path/"empty");});
    raw.read=[](std::uint64_t,std::size_t)->Bytes{throw Error("read failure");};fails([&]{dump_range(raw,0,4096,temp.path/"failed");});
    expect(!std::filesystem::exists(temp.path/"failed"),"Raw failure leaves no destination");
}
void pe_tests() {
    Temp temp;
    for (const auto width : {4U, 8U}) for (const bool original : {true, false}) {
        auto image = loaded(width, false, original), dll = loaded(width, true);
        Read read = [&](std::uint64_t a, std::size_t n) { if (a >= 0x400000 && a - 0x400000 < image.size()) return slice(image, a - 0x400000, n); if (a >= 0x700000) return slice(dll, a - 0x700000, n); throw Error("Unreadable fixture address"); };
        std::vector<Module> modules{{0x400000, 0x4000, "fixture.exe", {}, {}}, {0x700000, 0x4000, "fixture.dll", {}, {}}};
        PE pe(read, 0x400000); ExportIndex exports(read, modules, width); const auto imports = recover_imports(pe, exports);
        expect(imports.size() == 2 && imports[0].name == "Alpha" && !imports[1].name && imports[1].ordinal == 9, "Named and ordinal imports");
        const auto rebuilt = build_imports(imports, 0x4000, width); expect(rebuilt.descriptor_size == 40 && rebuilt.patches.size() == 2, "Import section");
        CaptureTarget target{read, [] {}, [&] { return modules; }, {4242, 0, 0x5000, 0, 0, "fixture.exe"}, nullptr};
        const auto path = temp.path / (std::to_string(width) + (original ? "oft" : "exports") + ".exe");
        dump_pe(target, 0x400000, path, {}); const auto output = read_file(path); PE file([&](std::uint64_t a, std::size_t n) { return slice(output, a, n); }, 0);
        expect(file.sections.size() == 4 && file.sections.back().name == ".imprec", "Rebuilt section layout");
        const auto report_bytes = read_file(path.string() + ".json"); const auto report = Json::parse({reinterpret_cast<const char*>(report_bytes.data()), report_bytes.size()});
        expect(report.at("sha256").string() == sha256(output) && report.at("imports").items().size() == 2, "Report matches output");
        fails([&] { dump_pe(target, 0x400000, path, {}); }, "already exists");
        auto bad = image; put(bad, pe.section_table + 40 + 12, 0x1000, 4); fails([&] { PE malformed([&](std::uint64_t a, std::size_t n) { return slice(bad, a, n); }, 0); }, "Overlapping");
        // A matching on-disk image must use raw offsets rather than RVAs.
        Bytes disk(0x3400); copy_into(disk, 0, slice(image, 0, 0x400)); for (unsigned i = 0; i < 3; ++i) copy_into(disk, 0x400 + i * 0x1000, slice(image, (i + 1) * 0x1000, 0x1000));
        BackingImage backing(disk, pe, "fixture"); expect(backing.read(0x1000,16) == slice(image,0x1000,16), "Backing disk sections");
        auto mismatch = disk; mismatch[0x88] = 1; fails([&] { BackingImage invalid(mismatch, pe, "bad"); }, "exactly match");
        // Missing private bytes never use an original executable as a substitute.
        const auto original_read = target.read; target.read = [&](std::uint64_t a, std::size_t n) { if (a >= 0x403000 && a < 0x404000) throw PageUnavailable(0, "private page"); return original_read(a,n); };
        const auto backing_path = temp.path / ("backing" + std::to_string(width)); if (!std::filesystem::exists(backing_path)) publish(backing_path, disk);
        DumpOptions options; options.backing_file = backing_path; const auto incomplete_path = temp.path / ("missing" + std::to_string(width) + (original ? "oft" : "rev"));
        fails([&] { dump_pe(target,0x400000,incomplete_path,options); }, "Cannot capture"); expect(!std::filesystem::exists(incomplete_path), "No partial failed output");
        options.allow_missing = true; dump_pe(target,0x400000,incomplete_path,options);
    }
    auto image = loaded(); PE pe([&](std::uint64_t a,std::size_t n) { return slice(image,a,n); },0);
    auto disk = Bytes(0x3400); copy_into(disk,0,slice(image,0,0x400)); for (unsigned i=0;i<3;++i) copy_into(disk,0x400+i*0x1000,slice(image,(i+1)*0x1000,0x1000));
    BackingImage relocated(disk,pe,"wrongbase"); fails([&] { relocated.read(0x1000,1); }, "no relocations");
    // A raced report publication must preserve the pre-existing report and remove our binary.
    const auto race = temp.path / "race"; publish(race.string()+".json",Bytes{42}); fails([&] { publish_pair(race,Bytes{1},Json::object({})); });
    expect(!std::filesystem::exists(race) && read_file(race.string()+".json") == Bytes{42}, "Publication rollback");
}
void relocation_tests() {
    for (const unsigned width : {4U, 8U}) for (const int direction : {-1, 1}) {
        auto image = loaded(width);
        const unsigned dir = 0x98 + (width == 8 ? 112 : 96);
        put(image, dir + 40, 0x3000, 4); put(image, dir + 44, 12, 4);
        put(image, 0x3000, 0x1000, 4); put(image, 0x3004, 12, 4); put(image, 0x3008, ((width == 8 ? 10U : 3U) << 12) | 8, 2);
        put(image, 0x1008, 0x401234, width);
        Bytes disk(0x3400); copy_into(disk, 0, slice(image, 0, 0x400));
        for (unsigned i = 0; i < 3; ++i) copy_into(disk, 0x400 + i * 0x1000, slice(image, (i + 1) * 0x1000, 0x1000));
        const std::uint64_t moved = direction > 0 ? 0x500000 : 0x300000;
        PE pe([&](std::uint64_t a, std::size_t n) { return slice(image, a - moved, n); }, moved);
        BackingImage backing(disk, pe, "relocation fixture");
        expect(get(backing.read(0x1008,width),0,width) == moved + 0x1234, "Positive/negative ASLR relocation");
        expect(backing.identity.at("relocations_applied").integer() == 1, "Relocation provenance");
        put(image, 0x98 + (width == 8 ? 24 : 28), moved, width);
        PE normalized([&](std::uint64_t a, std::size_t n) { return slice(image, a - moved, n); }, moved);
        BackingImage adjusted(disk,normalized,"normalized base");
        expect(adjusted.identity.at("header_adjustments").items().size()==1, "Mapped ImageBase normalization");
        expect(get(adjusted.read(0x1008,width),0,width)==moved+0x1234, "Normalization keeps preferred relocation base");
        put(disk,0x2408,0xf008,2);
        BackingImage unsupported(disk,normalized,"bad relocation"); fails([&] { unsupported.read(0x1000,16); }, "Unsupported");
    }
}
void windows_tests() {
    constexpr std::uint64_t high = 0xffff800000000000ULL, base = high + 0x200000, system = high + 0x1800000, target = high + 0x1802000;
    const auto profile = Profile::load("profiles/B661C6FE72991D160FE37C48B8BC5470-1.json");
    Bytes ram(32 * 1024 * 1024);
    auto physical = [](std::uint64_t address) { return address >= high ? address - high : address; };
    auto write = [&](std::uint64_t address, std::uint64_t value, unsigned width = 8) { put(ram, physical(address), value, width); };
    for (const auto root : {0x1000U,0x5000U}) { write(root,0x2003); write(root+256*8,0x2003); }
    write(0x2000,0x3003); for(unsigned i=0;i<16;++i) write(0x3000+i*8,std::uint64_t(i)*0x200000|0x83);
    write(base,0x5a4d,2); write(base+0x3c,0x80,4); write(base+0x80,0x4550,4); write(base+0x84,0x8664,2); write(base+0x94,0xf0,2);
    write(base+0x98,0x20b,2); write(base+0x98+56,0x1600000,4); write(base+0x98+108,16,4); write(base+0x98+160,0x1000,4); write(base+0x98+164,28,4);
    const auto& pdb=profile.data.at("metadata").at("windows").at("pdb"); const auto guid=pdb.at("GUID").string();
    Bytes record(24); put(record,0,0x53445352,4); const std::array<unsigned,16> order{7,6,5,4,9,8,11,10,12,13,14,15,16,17,18,19};
    for(unsigned i=0;i<16;++i) record[order[i]]=static_cast<std::uint8_t>(number("0x"+guid.substr(i*2,2)));
    put(record,20,pdb.at("age").integer(),4); const auto name=pdb.at("database").string(); record.insert(record.end(),name.begin(),name.end());record.push_back(0);
    copy_into(ram,physical(base+0x1100),record);write(base+0x100c,2,4);write(base+0x1010,record.size(),4);write(base+0x1014,0x1100,4);
    const auto link=profile.offset("_EPROCESS","ActiveProcessLinks"),head=base+profile.symbol("PsActiveProcessHead");
    write(head,system+link);write(head+8,target+link);write(system+link,target+link);write(system+link+8,head);write(target+link,head);write(target+link+8,system+link);
    for(const auto a:{system,target}){
        write(a+profile.offset("_EPROCESS","UniqueProcessId"),a==system?4:4242);
        write(a+profile.offset("_EPROCESS","Pcb")+profile.offset("_KPROCESS","DirectoryTableBase"),a==system?0x1000:0x5000);
    }
    write(base+profile.symbol("PsInitialSystemProcess"),system);write(target+profile.offset("_EPROCESS","SectionBaseAddress"),0x400000);
    write(0x9000,0x00000001000600e9);write(0x9070,base+0x12345);write(0x90a0,0x1000);
    Temp temp;publish(temp.path/"ram",ram);Physical file(temp.path/"ram");auto discovered=discover(file,profile);
    expect(discovered->base==base && discovered->processes().size()==2,"Low stub exact-profile discovery");
    Read read=[&](std::uint64_t a,std::size_t n){return slice(ram,a,n);};Windows windows(read,profile,base,0x1000);auto selected=windows.attach(4242);
    expect(selected->main_image_base()==0x400000,"Main image base");expect(selected->modules().empty(),"Absent PEB");
    const auto vad=high+0x1b00000,proto=high+0x1b01000;
    write(target+profile.offset("_EPROCESS","VadRoot"),vad);write(vad+profile.offset("_MMVAD_SHORT","StartingVpn"),0x400,4);write(vad+profile.offset("_MMVAD_SHORT","EndingVpn"),0x401,4);
    write(vad+profile.offset("_MMVAD_SHORT","u"),2<<4,4);write(vad+profile.offset("_MMVAD","FirstPrototypePte"),proto);write(vad+profile.offset("_MMVAD","LastContiguousPte"),proto+8);
    write(0x3000+2*8,0x6003);write(0x6000,0);write(proto,0xa001);text(ram,0xa000,"shared-image");
    expect(selected->read(0x400000,12)==Bytes({'s','h','a','r','e','d','-','i','m','a','g','e'}),"Empty PTE uses resident image VAD");
    expect(selected->shared_pages==std::set<std::uint64_t>{0x400000},"Shared page provenance");
    // One user-visible page exercises the retained ZIP64 process archive API.
    write(0x5000,0x2007);write(0x2000,0x3007);write(0x3000+2*8,0x6007);write(0x6000,0xa007);
    std::vector<Mapping> user;selected->space.user_mappings([&](const Mapping& m){user.push_back(m);});
    expect(user.size()==1&&user.front().address==0x400000&&user.front().physical==0xa000,"Resident user mapping enumeration");
    fails([&]{dump_process(*selected,temp.path/"running.zip",false);},"halted");
    const auto archive_summary=dump_process(*selected,temp.path/"resident.zip",true);const auto archive=read_file(temp.path/"resident.zip");
    expect(archive_summary.at("size").integer()==4096&&get(archive,0,4)==0x04034b50&&get(archive,archive.size()-22,4)==0x06054b50,"ZIP64 process archive");
    expect(slice(archive,30+10+20,12)==Bytes({'s','h','a','r','e','d','-','i','m','a','g','e'}),"Archive contains resident bytes");
    write(0x6000,0);
    write(vad+profile.offset("_MMVAD_SHORT","u"),(2<<4)|(1<<21),4);fails([&]{selected->read(0x400000,12);},"not in a shared image VAD");
    write(vad+profile.offset("_MMVAD_SHORT","u"),2<<4,4);write(proto,0xbc0acc09da580460ULL);
    try { selected->read(0x400000,12);throw std::runtime_error("Expected file-backed failure"); }
    catch(const PageUnavailable& e){expect(e.file_backed&&e.file_backed_va==0x400000&&e.image_vad_start==0x400000,"File recovery authorized only by verified VAD");}
    write(target+profile.offset("_EPROCESS","CreateTime"),1);fails([&]{selected->read(0x400000,1);},"PID was reused");
    ram[physical(base+0x1104)]^=1;fails([&]{Windows mismatch(read,profile,base,0x1000);},"mismatch");
}
void rsp_tests() {
    expect(decode_rsp("a* ")==Bytes({'a','a','a','a'}),"RSP run length");
    expect(decode_rsp("}\x04")==Bytes{'$'},"RSP escaping");
    for(const auto* invalid:{"}","* ","a*","a*\1"})fails([&]{decode_rsp(invalid);});
}
void wof_tests() {
    expect(normalize_guest_path("\\??\\C:\\Windows\\\\System32\\a.exe") == "/Windows/System32/a.exe", "Guest path normalization");
    for (const auto* path : {"relative.exe", "C:/../secret", "//server/share/file", "/"}) fails([&] { normalize_guest_path(path); });
    Bytes reparse(24); put(reparse,0,0x80000017,4); put(reparse,4,16,2); put(reparse,8,1,4); put(reparse,12,2,4); put(reparse,16,1,4);
    expect(compression_format(reparse) == 0, "WOF FILE provider"); reparse[6]=1; fails([&] { compression_format(reparse); });
    Bytes raw(4096,65); expect(decompress_wof(raw,4096,0)==raw,"Raw WOF chunk");
    Bytes invalid(8); fails([&] { decompress_wof(invalid,8192,0); },"offsets");
    Bytes broken(260); fails([&] { decompress_wof(broken,4096,0); });
}
}
int main() {
    try { json_tests(); memory_tests(); pe_tests(); relocation_tests(); windows_tests(); wof_tests(); rsp_tests(); std::cout << checks << " focused checks passed\n"; return 0; }
    catch (const std::exception& e) { std::cerr << "FAILED after " << checks << " checks: " << e.what() << '\n'; return 1; }
}
