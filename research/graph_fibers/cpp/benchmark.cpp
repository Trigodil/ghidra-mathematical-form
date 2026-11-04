#include "synthesis.hpp"
#include <iomanip>
#include <iostream>
#include <sys/resource.h>

using namespace fibers;
namespace fs=std::filesystem;
static double elapsed(std::chrono::steady_clock::time_point start) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();
}
static std::string clean(std::string value) {
    for(auto& c:value)if(c=='\n'||c=='\r'||c=='\t')c=' ';
    return value;
}
int main(int argc,char** argv) {
    try {
        ghidra::AttributeId::initialize();ghidra::ElementId::initialize();
        fs::path binary,sla,output;size_t sample_count=256,probe_count=24;
        for(int i=1;i<argc;++i){require(i+1<argc,"Need option/value pairs");std::string option=argv[i++],value=argv[i];
            if(option=="--binary")binary=value;else if(option=="--sla")sla=value;else if(option=="--output")output=value;
            else if(option=="--samples")sample_count=std::stoul(value);else if(option=="--probes")probe_count=std::stoul(value);
            else throw std::runtime_error("Unknown option: "+option);}
        require(!binary.empty()&&!sla.empty()&&!output.empty()&&sample_count>0,"Need --binary --sla --output");
        fs::create_directories(output);auto begin=std::chrono::steady_clock::now();Elf elf(binary);
        const auto& functions=elf.functions();double index_seconds=elapsed(begin);
        std::vector<NamedFunction> eligible,small;std::unordered_set<uint64_t> addresses;
        for(const auto& function:functions)if(function.size<=65536&&addresses.insert(function.address).second){
            eligible.push_back(function);if(function.size<=64)small.push_back(function);}
        require(!eligible.empty(),"No eligible native function symbols");
        std::ofstream per_function(output/"translation.tsv");
        per_function<<"name\tsize\tbytes_translated\tinstructions\tpcode_ops\tstatus\treason\n";
        size_t sampled=std::min(sample_count,eligible.size()),complete=0,truncated=0,failed=0,
               bytes=0,instructions=0,pcode_ops=0,symbol_bytes=0;
        std::map<std::string,size_t> opcodes,errors;
        for(size_t number=0;number<sampled;++number) {
            const auto& symbol=eligible[number*eligible.size()/sampled];size_t covered=0,count=0,ops=0;
            std::string status="complete",reason;
            try {
                auto function=elf.function(symbol);Engine engine(function,sla);
                while(covered<function.bytes.size()&&covered<4096&&count<256) {
                    ghidra::Address pc(engine.sleigh.getDefaultCodeSpace(),function.address+covered);Assembly assembly;
                    auto length=engine.sleigh.printAssembly(assembly,pc);
                    supported(length>0&&uint64_t(length)<=function.bytes.size()-covered,"Invalid instruction boundary");
                    Emit emit;supported(engine.sleigh.oneInstruction(emit,pc)==length,"Translation size mismatch");
                    for(const auto& op:emit.ops)++opcodes[ghidra::get_opname(op.opcode)];
                    covered+=size_t(length);++count;ops+=emit.ops.size();
                }
                if(covered<function.bytes.size())status="budget_limited";
            }catch(const ghidra::LowlevelError& e){status="failed";reason=e.explain;}
             catch(const std::exception& e){status="failed";reason=e.what();}
            complete+=status=="complete";truncated+=status=="budget_limited";failed+=status=="failed";
            if(!reason.empty())++errors[clean(reason)];
            bytes+=covered;instructions+=count;pcode_ops+=ops;symbol_bytes+=symbol.size;
            per_function<<clean(symbol.name)<<'\t'<<symbol.size<<'\t'<<covered<<'\t'<<count<<'\t'<<ops<<'\t'<<status<<'\t'<<clean(reason)<<'\n';
            if((number+1)%32==0)std::cout<<"translation "<<number+1<<'/'<<sampled<<std::endl;
        }
        const double translation_seconds=elapsed(begin)-index_seconds;
        z3::context c;size_t probes=std::min(probe_count,small.size()),modeled=0,reconstructions=0,exact=0,semantic=0;
        std::ofstream probe_log(output/"symbolic_probes.tsv");probe_log<<"name\tstatus\treason\n";
        for(size_t number=0;number<probes;++number) {
            const auto& symbol=small[number*small.size()/probes];
            try {
                auto model=lift(c,elf,symbol.name,sla);++modeled;
                probe_log<<clean(symbol.name)<<"\tmodeled_under_probe_ABI\t2 u8 inputs, AL return; prototype unverified\n";
                if(reconstructions<3&&query(model.memory_out!=model.memory_in).status=="unsat") {
                    auto directory=output/("candidate_"+std::to_string(reconstructions++));
                    auto result=reconstruct(model,elf,symbol.name,directory);
                    exact+=result.status=="verified_exact";semantic+=result.status=="verified_semantic";
                    probe_log<<clean(symbol.name)<<'\t'<<result.status<<'\t'<<result.family<<'\n';
                }
            }catch(const ghidra::LowlevelError& e){probe_log<<clean(symbol.name)<<"\tunsupported\t"<<clean(e.explain)<<'\n';++errors[clean(e.explain)];}
             catch(const std::exception& e){probe_log<<clean(symbol.name)<<"\tunsupported\t"<<clean(e.what())<<'\n';++errors[clean(e.what())];}
            std::cout<<"symbolic probe "<<number+1<<'/'<<probes<<std::endl;
        }
        struct rusage usage{};getrusage(RUSAGE_SELF,&usage);
        std::ostringstream report;report<<std::fixed<<std::setprecision(3);
        report<<"Target: "<<fs::canonical(binary)<<"\nFile bytes: "<<elf.file_size()<<"\nExecutable segment bytes: "<<elf.executable_bytes()
              <<"\nUnambiguous sized function symbols: "<<functions.size()<<"\nEligible unique-address functions (<=64 KiB): "<<eligible.size()
              <<"\nRead-only mmap; symbols indexed once. Target was not executed or modified.\n\n"
              <<"Stratified-by-address sample: "<<sampled<<" functions; total declared sample bytes: "<<symbol_bytes<<'\n'
              <<"Linear-sweep p-code translation: complete="<<complete<<", budget_limited="<<truncated<<", failed="<<failed<<'\n'
              <<"Translated bytes: "<<bytes<<"; instructions: "<<instructions<<"; p-code operations: "<<pcode_ops<<'\n'
              <<"Budgets: <=4096 bytes and <=256 instructions per sampled function.\n"
              <<"Symbolic small-function probes: "<<probes<<"; accepted under supplied probe ABI: "<<modeled<<'\n'
              <<"Source reconstruction attempts: "<<reconstructions<<"; exact byte matches="<<exact<<"; semantic-only matches="<<semantic<<'\n'
              <<"Probe ABI is two byte inputs and AL output, not a recovered Claude function signature.\n\n"
              <<"Symbol index seconds: "<<index_seconds<<"\nTranslation seconds: "<<translation_seconds
              <<"\nTotal seconds: "<<elapsed(begin)<<"\nPeak process RSS KiB: "<<usage.ru_maxrss<<"\n\n"
              <<"This measures a bounded sample of native code, including bundled runtime/library code.\n"
              <<"Translation success does not establish semantic correctness or whole-program decompilation.\n"
              <<"Embedded assets/JavaScript, arbitrary ABIs, complex calls, indirect control flow and general loops remain outside this reconstruction test.\n\n"
              <<"Operation counts:\n";
        for(const auto& [name,count]:opcodes)report<<"  "<<name<<": "<<count<<'\n';
        report<<"\nObserved failures:\n";for(const auto& [name,count]:errors)report<<"  "<<count<<": "<<name<<'\n';
        write_file(output/"report.txt",report.str());std::cout<<report.str();return 0;
    }catch(const ghidra::LowlevelError& e){std::cerr<<e.explain<<'\n';}
     catch(const std::exception& e){std::cerr<<e.what()<<'\n';}
    return 1;
}
