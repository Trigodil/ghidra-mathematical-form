#include "inverse.hpp"
#include <iostream>
#include <limits>

using namespace fibers;
namespace fs=std::filesystem;
static z3::expr load(const z3::expr& memory,const z3::expr& address,unsigned size) {
    auto value=z3::select(memory,address+int(size)-1);
    for(int i=int(size)-2;i>=0;--i)value=z3::concat(value,z3::select(memory,address+i));
    return value;
}
static z3::expr store_bytes(z3::expr memory,const z3::expr& address,const z3::expr& value) {
    for(unsigned i=0;i<value.get_sort().bv_size()/8;++i)memory=z3::store(memory,address+int(i),value.extract(8*i+7,8*i));
    return memory;
}
int main(int argc,char** argv) {
    try {
        ghidra::AttributeId::initialize();ghidra::ElementId::initialize();fs::path binary,sla,output;
        unsigned timeout_ms=10000;
        for(int i=1;i<argc;++i){require(i+1<argc,"Need option/value pairs");std::string key=argv[i++],value=argv[i];
            if(key=="--binary")binary=value;else if(key=="--sla")sla=value;else if(key=="--output")output=value;
            else if(key=="--timeout-ms") {
                require(!value.empty()&&value.find_first_not_of("0123456789")==std::string::npos,"Timeout must be a nonnegative integer");
                auto parsed=std::stoull(value);require(parsed<=std::numeric_limits<unsigned>::max(),"Timeout is too large");
                timeout_ms=unsigned(parsed);
            }
            else throw std::runtime_error("Unknown option: "+key);}
        require(!binary.empty()&&!sla.empty()&&!output.empty(),"Need --binary --sla --output");fs::create_directories(output);
        Elf elf(binary);z3::context c;std::ostringstream report;unsigned passed=0,unresolved=0;
        for(const std::string name:{"_ZNK2v810CpuProfile10GetEndTimeEv","_ZNK2v812ScriptOrigin7OptionsEv","uv_version_string","napi_get_version"}) {
            auto directory=output/name;fs::create_directories(directory);
            auto model=lift(c,elf,name,sla,{{"p",64,"RDI"},{"q",64,"RSI"},{"stack",64,"RSP"},{"saved_rbp",64,"RBP"}},"RAX",{"RSP","RBP"});
            auto p=model.inputs[0],q=model.inputs[1],sp=model.inputs[2],bp=model.inputs[3];
            auto frame=sp-8;
            auto pushed=store_bytes(model.memory_in,frame,bp);
            auto expected=model.result;auto expected_memory=pushed;
            auto assumptions=c.bool_val(true);
            if(name.find("GetEndTime")!=std::string::npos)expected=load(pushed,p+0x48,8);
            else if(name.find("Options")!=std::string::npos)expected=z3::zext(load(pushed,p+0x10,4),32);
            else if(name=="uv_version_string")expected=c.bv_val(uint64_t(0x99353a),64);
            else {
                auto code=z3::ite(q==0,c.bv_val(1,32),c.bv_val(0,32));
                expected=z3::zext(z3::ite(p==0,c.bv_val(1,32),code),32);
                expected_memory=z3::ite(p==0,pushed,z3::ite(q==0,store_bytes(pushed,p+0x1c,c.bv_val(1,32)),
                    store_bytes(store_bytes(pushed,q,c.bv_val(10,32)),p+0x1c,c.bv_val(0,32))));
                // Half-open nonwrapping write boxes are disjoint from [stack-8,stack).
                assumptions=z3::uge(sp,8)&&
                    ((p==0)||(z3::ule(p,c.bv_val(UINT64_MAX-32,64))&&
                               (z3::ule(p+32,frame)||z3::uge(p+28,sp))))&&
                    ((q==0)||(z3::ule(q,c.bv_val(UINT64_MAX-4,64))&&
                               (z3::ule(q+4,frame)||z3::uge(q,sp))));
            }
            auto mismatch=model.result!=expected||model.memory_out!=expected_memory||
                          model.registers.at("RSP")!=sp||model.registers.at("RBP")!=bp;
            require(query(assumptions,model.inputs,timeout_ms).status=="sat","Summary domain is empty or unresolved");
            Answer proof{"unsat",{}, {}};
            if(name=="napi_get_version") {
                // The three boxes cover all p/q nullness cases. Substitute only
                // Boolean facts explicitly asserted by the corresponding box.
                for(unsigned branch=0;branch<3;++branch) {
                    auto domain=assumptions&&(branch==0?p==0:p!=0);
                    if(branch>0)domain=domain&&(branch==1?q==0:q!=0);
                    z3::expr_vector from(c),to(c);from.push_back(p==0);to.push_back(c.bool_val(branch==0));
                    if(branch>0){from.push_back(q==0);to.push_back(c.bool_val(branch==1));}
                    auto specialized=mismatch;specialized=specialized.substitute(from,to).simplify();
                    std::cout<<"checking "<<name<<" case "<<branch<<"; timeout_ms="<<timeout_ms<<std::endl;
                    auto check=query(domain&&specialized,model.inputs,timeout_ms,directory/("case_"+std::to_string(branch)+".smt2"));
                    if(check.status!="unsat"){proof=check;break;}
                }
            }else proof=query(assumptions&&mismatch,model.inputs,timeout_ms,directory/"summary.smt2");
            std::ostringstream detail;detail<<"Return: "<<model.result<<"\nFinal RAM: "<<model.memory_out
                <<"\nAssumptions: "<<assumptions<<"\nRSP: "<<model.registers.at("RSP")<<"\nRBP: "<<model.registers.at("RBP")<<'\n';
            for(const auto& trace:model.trace)detail<<trace;
            write_file(directory/"model.txt",detail.str());
            if(proof.status=="unsat") {
                ++passed;report<<name<<": return, complete RAM effect, RSP/RBP preservation verified; paths="<<model.paths<<'\n';
                std::cout<<"verified "<<name<<std::endl;
            }else {
                ++unresolved;report<<name<<": NOT VERIFIED; solver status="<<proof.status<<"; "<<proof.reason<<'\n';
                std::cout<<"not verified "<<name<<": "<<proof.status<<std::endl;
            }
        }
        report<<"\nSummary verification timeout_ms: "<<timeout_ms<<" (0 means no configured limit).\n"
              <<"Verified: "<<passed<<" actual executable function summaries; unresolved/rejected: "<<unresolved<<".\n"
              <<"Full pointer/stack inputs replace the earlier byte-argument probe.\n"
              <<"Targets were not executed. These are candidate summaries checked against lifted machine semantics.\n"
              <<"RAM is a total byte array. OS memory validity/faults are outside the model.\n"
              <<"napi_get_version requires its writes not to overlap the saved stack-frame bytes.\n"
              <<"No source-byte round trip or whole-application proof is asserted here.\n";
        write_file(output/"report.txt",report.str());std::cout<<report.str();return unresolved?2:0;
    }catch(const ghidra::LowlevelError& e){std::cerr<<e.explain<<'\n';}
     catch(const std::exception& e){std::cerr<<e.what()<<'\n';}
    return 1;
}
