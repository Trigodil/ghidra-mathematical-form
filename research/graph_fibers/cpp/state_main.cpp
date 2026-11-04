#include "loop_proof.hpp"
#include <dlfcn.h>
#include <iostream>

using namespace fibers;
namespace fs=std::filesystem;
template<class T> static T lookup(void* handle,const std::string& name) {
    auto value=dlsym(handle,name.c_str());require(value!=nullptr,"Missing fixture symbol: "+name);return reinterpret_cast<T>(value);
}
struct Library {
    void* handle;
    explicit Library(const fs::path& path):handle(dlopen(fs::absolute(path).c_str(),RTLD_NOW|RTLD_LOCAL)) {
        require(handle!=nullptr,"Cannot load generated fixture library");
    }
    ~Library(){dlclose(handle);}
};
int main(int argc,char** argv) {
    try {
        ghidra::AttributeId::initialize();ghidra::ElementId::initialize();
        fs::path sla,fixtures,loops,output;
        for(int i=1;i<argc;++i) {
            require(i+1<argc,"Expected option/value pairs");std::string option=argv[i++],value=argv[i];
            if(option=="--sla")sla=value;else if(option=="--fixtures")fixtures=value;
            else if(option=="--loops")loops=value;else if(option=="--output")output=value;
            else throw std::runtime_error("Unknown option: "+option);
        }
        require(!sla.empty()&&!fixtures.empty()&&!loops.empty()&&!output.empty(),"Need --sla --fixtures --loops --output");
        fs::create_directories(output);z3::context c;Elf functions(fixtures),loop_functions(loops);
        Library native(fixtures),native_loops(loops);std::ostringstream report;
        {
            auto code=functions.function("affine");Engine engine(code,sla);State aliases(c);
            auto word=fresh_word(c,"alias_word",64),low=fresh_word(c,"alias_low",8),high=fresh_word(c,"alias_high",8);
            aliases.write(engine.sleigh.getRegister("RAX"),word);aliases.write(engine.sleigh.getRegister("AL"),low);
            auto expected=(word&c.bv_val(UINT64_MAX^uint64_t(0xff),64))|z3::zext(low,56);
            auto bad=aliases.read(engine.sleigh.getRegister("RAX"))!=expected;
            aliases.write(engine.sleigh.getRegister("AH"),high);
            expected=(expected&c.bv_val(UINT64_MAX^uint64_t(0xff00),64))|z3::shl(z3::zext(high,56),8);
            bad=bad||(aliases.read(engine.sleigh.getRegister("RAX"))!=expected)||
                    (aliases.read(engine.sleigh.getRegister("EAX"))!=expected.extract(31,0));
            require(query(bad,{word,low,high},5000,output/"register_alias_cache.smt2").status=="unsat","Register alias cache is inconsistent");
            report<<"Whole-register cache: symbolic AL/AH overwrites preserve RAX/EAX alias semantics.\n";
        }
        size_t formula_count=0,exact_count=0,native_checks=0,refinements=0;
        using Function=uint8_t(*)(uint8_t,uint8_t);
        for(const std::string name:{"affine","bitxor","bitand","product","quadratic","mixed","branchy"}) {
            std::cout<<"reconstructing "<<name<<std::endl;
            auto model=lift(c,functions,name,sla);auto directory=output/name;
            auto result=reconstruct(model,functions,name,directory);
            require(result.status=="verified_exact"||result.status=="verified_semantic","Reconstruction unresolved: "+name+": "+result.status);
            ++formula_count;exact_count+=result.status=="verified_exact";refinements+=result.counterexamples;
            Library rebuilt(directory/result.family/"reconstructed.so");
            auto before=lookup<Function>(native.handle,name),after=lookup<Function>(rebuilt.handle,"reconstructed");
            for(unsigned x=0;x<256;++x)for(unsigned y=0;y<256;++y) {
                require(before(uint8_t(x),uint8_t(y))==after(uint8_t(x),uint8_t(y)),"Native reconstruction mismatch: "+name);
                ++native_checks;
            }
            report<<name<<": "<<result.status<<"; family="<<result.family<<"; counterexamples="<<result.counterexamples<<'\n';
        }
        for(const std::string name:{"loop_add","loop_xor"}) {
            std::cout<<"proving "<<name<<std::endl;
            auto result=prove_loop(c,loop_functions,name,sla,output/name);
            require(result.status=="verified","Loop proof unresolved: "+name+": "+result.status);
            const bool bitwise=result.family=="xor_parity";
            require(result.parameter==(bitwise?0xa5u:3u),"Incorrect synthesized loop parameter");
            auto function=lookup<Function>(native_loops.handle,name);
            for(unsigned x=0;x<256;++x)for(unsigned n=0;n<256;++n) {
                auto expected=bitwise?uint8_t(x^((n&1u)?result.parameter:0)):uint8_t(x+result.parameter*n);
                require(function(uint8_t(x),uint8_t(n))==expected,"Native loop summary mismatch");++native_checks;
            }
            auto wrong_rank=loop_problem(c,loop_functions,name,sla,bitwise,true);
            z3::expr_vector from(c),to(c);from.push_back(wrong_rank.parameters[0]);to.push_back(c.bv_val(result.parameter,8));
            auto failure=wrong_rank.rank_bad.substitute(from,to);
            require(query(failure,{},5000,output/name/"bad_ranking_counterexample.smt2").status=="sat","Invalid ranking function accepted");
            auto wrong_invariant=loop_problem(c,loop_functions,name,sla,bitwise);
            from.resize(0);to.resize(0);from.push_back(wrong_invariant.parameters[0]);to.push_back(c.bv_val(result.parameter^1u,8));
            failure=wrong_invariant.step_bad.substitute(from,to);
            require(query(failure,{},5000,output/name/"bad_invariant_counterexample.smt2").status=="sat","Invalid invariant accepted");
            report<<name<<": invariant synthesized and checked; family="<<result.family<<"; parameter="<<result.parameter
                  <<"; initialization/preservation/exit/termination verified; wrong invariant/ranking rejected\n";
        }
        auto always_bad=synthesize(c.bool_val(true),{},output/"negative_unsatisfiable");
        require(always_bad.status=="grammar_exhausted","Unsolvable synthesis falsely accepted");
        auto capped=synthesize(c.bv_const("cap_state",8)!=c.bv_const("cap_parameter",8),
                              {c.bv_const("cap_parameter",8)},output/"negative_limit",1);
        require(capped.status=="iteration_limit","Incomplete synthesis falsely accepted");
        report<<"\nPASS: "<<formula_count<<" reconstructed formulas; "<<exact_count<<" exact byte round trips; "
              <<refinements<<" expression counterexamples used for refinement.\n"
              <<"2 compiled-loop invariant and termination proofs; "<<native_checks<<" native input checks.\n"
              <<"Loop register bindings are explicit fixture contracts, not automatically inferred for arbitrary code.\n"
              <<"The controller is complete only when its finite search finishes; unknown/iteration limits remain unresolved.\n"
              <<"Semantic verification and exact function-byte inversion are distinct result states.\n";
        write_file(output/"report.txt",report.str());std::cout<<report.str();return 0;
    }catch(const ghidra::LowlevelError& error){std::cerr<<error.explain<<'\n';}
     catch(const std::exception& error){std::cerr<<error.what()<<'\n';}
    return 1;
}
