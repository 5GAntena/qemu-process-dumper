#include "qpd/dump.hpp"
#include <chrono>
#include <climits>
#include <iomanip>
#include <sstream>
#include <zlib.h>

namespace qpd {
Json dump_range(CaptureTarget target, std::uint64_t address, std::uint64_t size, const std::filesystem::path& filename) {
    require(size && address <= UINT64_MAX - (size - 1) && canonical(address) && canonical(address + size - 1) &&
            (address >> 48) == ((address + size - 1) >> 48), "Dump requires positive size within one canonical range");
    const auto destination = std::filesystem::absolute(filename); Digest digest; target.validate();
    publish_generated(destination, [&](const Sink& sink) {
        for (std::uint64_t offset = 0; offset < size;) {
            const auto count = std::min<std::uint64_t>(1024 * 1024, size - offset);
            const auto data = target.read(address + offset, count); require(data.size() == count, "Short raw range read");
            sink(data); digest.update(data); offset += count;
        }
        target.validate();
    });
    return Json::object({{"file", destination.string()}, {"pid", target.process.pid}, {"address", hex(address)}, {"size", size}, {"sha256", digest.finish()}});
}
namespace {
std::string utc_now() {
    const auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
    const auto day = std::chrono::floor<std::chrono::days>(now);
    const std::chrono::year_month_day date(day);
    const std::chrono::hh_mm_ss time(now - day);
    std::ostringstream out;
    out << std::setfill('0') << std::setw(4) << int(date.year()) << '-'
        << std::setw(2) << unsigned(date.month()) << '-' << std::setw(2) << unsigned(date.day())
        << 'T' << std::setw(2) << time.hours().count() << ':' << std::setw(2) << time.minutes().count()
        << ':' << std::setw(2) << time.seconds().count() << 'Z';
    return out.str();
}
// Stored ZIP64 entries use data descriptors so memory.bin can stream without
// seeking back through guest data. ZIP structures are encoded little-endian.
class Archive {
public:
    explicit Archive(const Sink& sink) : sink_(sink) {}
    void entry(const std::string& name, const std::function<void(const Sink&)>& produce) {
        const auto offset = position_; Bytes header(30); put(header,0,0x04034b50,4); put(header,4,45,2); put(header,6,8,2);
        put(header,18,UINT32_MAX,4);put(header,22,UINT32_MAX,4);put(header,26,name.size(),2);put(header,28,20,2);write(header);write_text(name);
        Bytes extra(20);put(extra,0,1,2);put(extra,2,16,2);write(extra);
        std::uint64_t size=0;uLong crc=crc32(0,nullptr,0);
        produce([&](std::span<const std::uint8_t> data){
            require(data.size()<=UINT_MAX && size<=UINT64_MAX-data.size(),"ZIP entry size overflow");
            crc=crc32(crc,data.data(),static_cast<uInt>(data.size()));size+=data.size();write(data);
        });
        Bytes descriptor(24);put(descriptor,0,0x08074b50,4);put(descriptor,4,crc,4);put(descriptor,8,size,8);put(descriptor,16,size,8);write(descriptor);
        entries_.push_back({name,offset,size,crc});
    }
    void finish() {
        const auto start=position_;
        for(const auto& e:entries_){
            Bytes central(46);put(central,0,0x02014b50,4);put(central,4,45,2);put(central,6,45,2);put(central,8,8,2);put(central,16,e.crc,4);
            put(central,20,UINT32_MAX,4);put(central,24,UINT32_MAX,4);put(central,28,e.name.size(),2);put(central,30,28,2);put(central,42,UINT32_MAX,4);write(central);write_text(e.name);
            Bytes extra(28);put(extra,0,1,2);put(extra,2,24,2);put(extra,4,e.size,8);put(extra,12,e.size,8);put(extra,20,e.offset,8);write(extra);
        }
        const auto central_size=position_-start,zip64_offset=position_;
        Bytes end64(56);put(end64,0,0x06064b50,4);put(end64,4,44,8);put(end64,12,45,2);put(end64,14,45,2);
        put(end64,24,entries_.size(),8);put(end64,32,entries_.size(),8);put(end64,40,central_size,8);put(end64,48,start,8);write(end64);
        Bytes locator(20);put(locator,0,0x07064b50,4);put(locator,8,zip64_offset,8);put(locator,16,1,4);write(locator);
        Bytes end(22);put(end,0,0x06054b50,4);put(end,8,65535,2);put(end,10,65535,2);put(end,12,UINT32_MAX,4);put(end,16,UINT32_MAX,4);write(end);
    }
private:
    struct Entry {std::string name;std::uint64_t offset,size;uLong crc;};
    void write(std::span<const std::uint8_t> data) {check_cancelled();require(position_<=UINT64_MAX-data.size(),"ZIP offset overflow");sink_(data);position_+=data.size();}
    void write_text(const std::string& text){write(std::span(reinterpret_cast<const std::uint8_t*>(text.data()),text.size()));}
    const Sink& sink_;
    std::uint64_t position_=0;
    std::vector<Entry> entries_;
};
}
Json dump_process(Target& target, const std::filesystem::path& filename, bool guest_halted) {
    require(guest_halted,"VM must be halted for a resident process archive");target.validate();
    const auto destination=std::filesystem::absolute(filename);Digest digest;auto regions=Json::array();std::uint64_t total=0;
    const auto timestamp = utc_now();
    std::string memory_hash;
    publish_generated(destination,[&](const Sink& sink){
        Archive archive(sink);
        archive.entry("memory.bin",[&](const Sink& memory){
            target.space.user_mappings([&](const Mapping& m){
                const auto offset=total;
                for(std::uint64_t consumed=0;consumed<m.size;){
                    const auto count=std::min<std::uint64_t>(1024*1024,m.size-consumed);const auto data=target.read(m.address+consumed,count);
                    require(data.size()==count,"Short resident process read");memory(data);digest.update(data);consumed+=count;total+=count;
                }
                auto& items=regions.items();
                if(!items.empty()&&items.back().at("address").integer()+items.back().at("size").integer()==m.address&&
                   items.back().at("writable").boolean()==m.writable&&items.back().at("executable").boolean()==m.executable)
                    items.back()["size"]=items.back().at("size").integer()+m.size;
                else regions.push(Json::object({{"address",m.address},{"size",m.size},{"offset",offset},{"writable",m.writable},{"executable",m.executable}}));
            });
        });
        require(!regions.items().empty(),"Process has no resident user-accessible mappings");target.validate();
        memory_hash = digest.finish();
        const auto manifest=Json::object({{"format","vmidbg-process-dump"},{"version",1},{"process",target.process.json()},{"memory_file","memory.bin"},
                                          {"created_utc", timestamp}, {"scope", "resident user-accessible mappings"},
                                          {"kernel_pdb", target.windows().identity}, {"kernel_base", target.windows().base},
                                          {"memory_size",total},{"memory_sha256",memory_hash},{"regions",regions},{"consistency","caller-established halted guest"},
                                          {"omitted", Json(Json::Array{"nonpresent pages including transition/pagefile/compressed pages", "kernel/supervisor mappings"})}}).dump()+"\n";
        archive.entry("manifest.json",[&](const Sink& output){output(std::span(reinterpret_cast<const std::uint8_t*>(manifest.data()),manifest.size()));});archive.finish();
    });
    return Json::object({{"file",destination.string()},{"pid",target.process.pid},{"size",total},{"regions",regions.items().size()}, {"sha256", memory_hash}});
}
} // namespace qpd
