#include "qpd/pe.hpp"
#include "qpd/dump.hpp"
#include "qpd/rsp.hpp"
#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace qpd {
int attach_domain_main(const std::vector<std::string>& argv) {
    std::string domain = "windows11-hardware", uri = "qemu:///system";
    std::uint64_t port = 12345;
    bool enable = false, disable = false;
    for (std::size_t i = 0; i < argv.size(); ++i) {
        const auto& key = argv[i];
        if (key == "--help") {
            std::cout << "Legacy GDB listener helper: [--domain NAME] [--uri URI] [--port 12345]\n"
                         "  [--enable-gdb | --disable-gdb]\n"
                         "Enabling a listener does not connect; connecting the legacy debugger pauses the VM.\n";
            return 0;
        }
        if (key == "--enable-gdb") enable = true;
        else if (key == "--disable-gdb") disable = true;
        else {
            require((key == "--domain" || key == "--uri" || key == "--port") && i + 1 < argv.size(), "Invalid attach-domain option");
            const auto value = argv[++i];
            if (key == "--domain") domain = value;
            else if (key == "--uri") uri = value;
            else port = number(value);
        }
    }
    require(!(enable && disable) && port >= 1024 && port <= 65535, "Choose one GDB action and port 1024..65535");
    auto virsh = [&](std::vector<std::string> args) { args.insert(args.begin(), {"virsh", "-c", uri}); return command_text(args); };
    const auto state = virsh({"domstate", domain}); require(state == "running" || state == "paused", "Domain must already be started");
    auto channels = [&] {
        const auto response = Json::parse(virsh({"qemu-monitor-command", domain, Json::object({{"execute", "query-chardev"}}).dump()}));
        auto result = Json::array();
        for (const auto& channel : response.at("return").items()) if (channel.at("label").string() == "gdb") result.push(channel);
        return result;
    };
    const auto current = channels(); std::cout << Json::object({{"domain", domain}, {"state", state}, {"gdb_channels", current}}).dump() << '\n';
    if (disable) { std::cout << virsh({"qemu-monitor-command", "--hmp", domain, "gdbserver none"}) << '\n'; return 0; }
    require(current.items().empty(), "A GDB listener already exists; do not replace an active debugger");
    const auto listener = "gdbserver tcp:127.0.0.1:" + std::to_string(port);
    if (enable) { std::cout << virsh({"qemu-monitor-command", "--hmp", domain, listener}) << '\n'; require(!channels().items().empty(), "QEMU did not create GDB listener"); }
    else std::cout << "Use --enable-gdb to enable a loopback listener on port " << port << ".\n";
    return 0;
}
namespace {
std::unique_ptr<Windows> discover_stopped(Qemu& qemu, const Profile& profile, std::optional<std::uint64_t> base, std::optional<std::uint64_t> dtb) {
    Read physical = [&qemu](std::uint64_t a, std::size_t n) { return qemu.read(a,n); }; const auto original = qemu.selected;
    try {
        for (const auto& cpu : qemu.cpus()) {
            qemu.select(cpu); const auto regs = qemu.monitor_registers();
            if (!regs.contains("CR0") || !regs.contains("CR4") || !(regs.at("CR0") & (1ULL << 31)) || !(regs.at("CR4") & (1ULL << 5))) continue;
            require(!(regs.at("CR4") & (1ULL << 12)), "Five-level kernel paging is unsupported");
            const auto root = dtb ? *dtb : regs.at("CR3"); AddressSpace space(physical, root, false);
            if (base) {
                try { auto w = std::make_unique<Windows>(physical,profile,*base,root); qemu.select(original); return w; }
                catch (const Error&) { if (dtb) throw; continue; }
            }
            std::vector<std::uint64_t> hints; const auto rip = qemu.reg("rip"); if (rip >> 63) hints.push_back(rip);
            if (regs.contains("IDT")) try {
                const auto gates = space.read(regs.at("IDT"),16*32);
                for (unsigned i=0;i<32;++i) {
                    const auto offset = i*16; const auto handler = get(gates,offset,2) | (get(gates,offset+6,2)<<16) | (get(gates,offset+8,4)<<32);
                    if ((gates[offset+5]&128) && (handler>>63) && canonical(handler)) hints.push_back(handler);
                }
            } catch (const Error&) { /* IDT may be hidden by KPTI. */ }
            for (std::size_t h=0;h<std::min<std::size_t>(hints.size(),4);++h) for (unsigned i=0;i<512;++i) {
                const auto start = hints[h] & ~65535ULL; if (start < std::uint64_t(i)*65536) break; const auto candidate = start-std::uint64_t(i)*65536;
                try { if (space.read(candidate,2) != Bytes({'M','Z'})) continue; auto w = std::make_unique<Windows>(physical,profile,candidate,root); qemu.select(original); return w; }
                catch (const Error&) { /* Try the next mapped kernel candidate. */ }
            }
        }
    } catch (...) { qemu.select(original); throw; }
    qemu.select(original); throw Error("Kernel discovery failed; supply current --kernel-base and --kernel-cr3");
}
std::vector<std::string> words(const std::string& line) {
    std::istringstream input(line); std::vector<std::string> result; std::string part;
    while (input >> std::quoted(part)) result.push_back(part);
    return result;
}
}
int legacy_main(const std::vector<std::string>& argv) {
    std::map<std::string,std::string> args; std::set<std::string> flags; std::vector<std::string> commands;
    for (std::size_t i=0;i<argv.size();++i) {
        const auto& key=argv[i];
        if (key == "--help") {
            std::cout << "Legacy pausing debugger: --allow-vm-pause --endpoint unix:/path|tcp:host:port\n"
                         "  [--profile FILE] [--kernel-base VA --kernel-cr3 DTB] [--pid PID]\n"
                         "  [--command 'COMMAND']... [--resume-on-exit]\n"
                         "Commands: ps, attach PID, threads, modules, regs, cpu [ID], read VA SIZE,\n"
                         "dump VA SIZE FILE, disasm VA [SIZE], bp VA, bc VA, bl, continue [SECONDS], step, quit, resume\n"; return 0;
        }
        if (key == "--allow-vm-pause" || key == "--resume-on-exit") flags.insert(key);
        else {
            require(key == "--endpoint" || key == "--profile" || key == "--kernel-base" || key == "--kernel-cr3" || key == "--pid" || key == "--command", "Unknown legacy option: "+key);
            require(i+1<argv.size(),"Missing legacy option value"); const auto value=argv[++i]; if(key=="--command") commands.push_back(value); else args[key]=value;
        }
    }
    require(flags.contains("--allow-vm-pause"), "Legacy debugger pauses the VM; explicitly supply --allow-vm-pause, or use the live dumper");
    require(args.contains("--endpoint"),"Legacy debugger requires --endpoint");
    const auto profile=Profile::load(args.contains("--profile")?args.at("--profile"):(executable_path().parent_path().parent_path()/"profiles/B661C6FE72991D160FE37C48B8BC5470-1.json").string());
    auto numeric=[&](const char* key)->std::optional<std::uint64_t>{return args.contains(key)?std::optional(number(args.at(key))):std::nullopt;};
    Qemu qemu(args.at("--endpoint")); bool resume=flags.contains("--resume-on-exit");
    try {
        qemu.initialize(); auto windows=discover_stopped(qemu,profile,numeric("--kernel-base"),numeric("--kernel-cr3")); std::unique_ptr<Target> target;
        if(const auto pid=numeric("--pid")) target=windows->attach(*pid);
        std::optional<std::uint64_t> last_breakpoint; std::string last_cpu;
        auto selected=[&]()->Target&{require(bool(target),"Select a process with attach PID first");return *target;};
        auto matches=[&] { const auto cr3=qemu.reg("cr3")&address_mask; return cr3 && (cr3==selected().process.dtb || cr3==selected().process.user_dtb); };
        auto step_past=[&](std::uint64_t address,unsigned timeout) {
            qemu.breakpoint(address,false);
            try { const auto stop=qemu.run(true,timeout); require(stop.size()>=3 && stop.substr(1,2)=="05","Unexpected breakpoint step stop"); }
            catch(...){qemu.breakpoint(address,true);throw;} qemu.breakpoint(address,true);
        };
        auto execute=[&](const std::string& line) {
            const auto parts=words(line); if(parts.empty())return false; const auto& cmd=parts.front();
            auto arity=[&](std::size_t min,std::size_t max){require(parts.size()>=min+1 && parts.size()<=max+1,"Invalid arguments for "+cmd);};
            auto show=[](const Json& v){std::cout<<v.dump()<<'\n';};
            if(cmd=="quit"||cmd=="resume"){arity(0,0);if(cmd=="resume")resume=true;return true;}
            if(cmd=="ps"){arity(0,0);auto list=Json::array();for(const auto& p:windows->processes())list.push(p.json());show(list);}
            else if(cmd=="attach"){arity(1,1);require(qemu.breakpoints.empty(),"Clear target breakpoints before switching process");target=windows->attach(number(parts[1]));show(target->process.json());}
            else if(cmd=="modules"){arity(0,0);auto list=Json::array();for(const auto& m:selected().modules())list.push(m.json());show(list);}
            else if(cmd=="threads"){
                arity(0,0);auto list=Json::array();const auto& p=windows->profile;
                for(const auto a:windows->list(windows->kernel,selected().process.eprocess+p.offset("_EPROCESS","ThreadListHead"),p.offset("_ETHREAD","ThreadListEntry"))){
                    const auto cid=a+p.offset("_ETHREAD","Cid");list.push(Json::object({{"ethread",a},{"pid",windows->kernel.scalar(cid+p.offset("_CLIENT_ID","UniqueProcess"))},{"tid",windows->kernel.scalar(cid+p.offset("_CLIENT_ID","UniqueThread"))}}));
                }show(list);
            }
            else if(cmd=="cpu"){arity(0,1);const auto cpus=qemu.cpus();if(parts.size()==2){require(std::find(cpus.begin(),cpus.end(),parts[1])!=cpus.end(),"Unknown CPU");qemu.select(parts[1]);}auto list=Json::array();for(const auto& cpu:cpus)list.push(cpu);show(Json::object({{"cpus",list},{"selected",qemu.selected}}));}
            else if(cmd=="regs"){arity(0,0);auto regs=Json::object({});for(const auto* name:{"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","rip","eflags","cr3"})regs[name]=hex(qemu.reg(name));show(Json::object({{"cpu",qemu.selected},{"in_target",target?Json(matches()):Json{}},{"registers",regs}}));}
            else if(cmd=="read"||cmd=="dump"||cmd=="disasm"){
                arity(cmd=="disasm"?1:cmd=="dump"?3:2,cmd=="dump"?3:2);const auto address=number(parts[1]);const auto size=parts.size()>2?number(parts[2]):64;
                if(cmd=="dump"){
                    CaptureTarget capture{[&](std::uint64_t a,std::size_t n){return selected().read(a,n);},[&]{selected().validate();},[&]{return selected().modules();},selected().process,nullptr};
                    show(dump_range(capture,address,size,parts[3]));return false;
                }
                require(size<=16*1024*1024 && (cmd!="disasm"||(size&&size<=65536)),"Invalid read size");const auto data=selected().read(address,size);
                if(cmd=="disasm"){
                    const auto temp=std::filesystem::temp_directory_path()/("qpd-disasm-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
                    require(std::filesystem::create_directory(temp),"Cannot reserve disassembly directory");
                    try{publish(temp/"bytes",data);std::cout<<command_text({"objdump","-D","-b","binary","-m","i386:x86-64","-M","intel","--adjust-vma="+hex(address),(temp/"bytes").string()})<<'\n';std::filesystem::remove_all(temp);}catch(...){std::filesystem::remove_all(temp);throw;}
                }else for(std::size_t i=0;i<data.size();i+=16){std::cout<<hex(address+i)<<"  ";for(std::size_t j=i;j<std::min(i+16,data.size());++j)std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<unsigned(data[j])<<' ';std::cout<<std::dec<<'\n';}
            }
            else if(cmd=="bp"||cmd=="bc"){
                arity(1,1);selected().validate();const auto address=number(parts[1]);require(canonical(address)&&!(address>>63),"Breakpoints require user VA");
                if(cmd=="bp"){Checks checks;selected().space.walk(address,checks);require(qemu.breakpoints.contains(address)||qemu.breakpoints.size()<4,"At most four hardware breakpoint slots");qemu.breakpoint(address,true);}
                else{require(qemu.breakpoints.contains(address),"No such target breakpoint");qemu.breakpoint(address,false);if(last_breakpoint==address)last_breakpoint.reset();}
            }
            else if(cmd=="bl"){arity(0,0);auto list=Json::array();for(const auto address:qemu.breakpoints)list.push(hex(address));show(list);}
            else if(cmd=="step"){arity(0,0);selected().validate();if(last_breakpoint&&last_cpu==qemu.selected){step_past(*last_breakpoint,5);last_breakpoint.reset();}else qemu.run(true,5);show(Json::object({{"stop",qemu.last_stop},{"cpu",qemu.selected},{"in_target",matches()}}));}
            else if(cmd=="continue"){
                arity(0,1);selected().validate();const auto seconds=parts.size()==2?number(parts[1]):30;require(seconds&&seconds<=3600,"Timeout must be 1..3600 seconds");
                const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(seconds);
                if(last_breakpoint){qemu.select(last_cpu);step_past(*last_breakpoint,5);last_breakpoint.reset();}
                for(;;){check_cancelled();const auto remaining=std::chrono::duration_cast<std::chrono::seconds>(deadline-std::chrono::steady_clock::now()).count();require(remaining>=0,"Continue deadline expired");qemu.run(false,static_cast<unsigned>(remaining+1));const auto rip=qemu.reg("rip");
                    if(qemu.last_stop.substr(1,2)!="05"||!qemu.breakpoints.contains(rip)){show(Json::object({{"stop",qemu.last_stop},{"cpu",qemu.selected},{"rip",rip}}));break;}
                    if(matches()){last_breakpoint=rip;last_cpu=qemu.selected;show(Json::object({{"stop",qemu.last_stop},{"cpu",qemu.selected},{"rip",rip},{"in_target",true}}));break;}step_past(rip,5);
                }
            }
            else throw Error("Unknown command: "+cmd);
            return false;
        };
        if(!commands.empty()){for(const auto& line:commands)if(execute(line))break;}
        else{std::cout<<"Whole VM halted. Use resume to detach and run; quit leaves it halted.\n";std::string line;while(std::cout<<"vmi> "<<std::flush,std::getline(std::cin,line)){try{if(execute(line))break;}catch(const Cancelled&){throw;}catch(const Error& e){std::cerr<<"error: "<<e.what()<<'\n';}}}
        qemu.close(resume);std::cerr<<(resume?"Disconnected; VM resumed.\n":"Disconnected; VM left halted.\n");return 0;
    }catch(...){qemu.close(resume);throw;}
}
} // namespace qpd
