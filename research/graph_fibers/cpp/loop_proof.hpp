#pragma once
#include "synthesis.hpp"

namespace fibers {
struct Boundary { State state;z3::expr guard;bool returned; };

// A one-lap symbolic interpreter for register-only loop contracts. It uses the
// same SLEIGH translation, register storage, flags and compute() as the lifter.
inline std::vector<Boundary> walk_loop(Engine& engine,const Function& code,uint64_t start,uint64_t header,
                                       State initial,const z3::expr& assumptions) {
    auto& c=assumptions.ctx();
    struct Frame {uint64_t pc;State state;z3::expr guard;std::unordered_set<uint64_t> visited;};
    std::vector<Frame> pending;pending.push_back({start,std::move(initial),c.bool_val(true),{}});
    std::vector<Boundary> result;size_t explored=0;
    while(!pending.empty()) {
        auto f=std::move(pending.back());pending.pop_back();
        auto feasible=query(assumptions&&f.guard);
        if(feasible.status=="unsat") continue;
        supported(feasible.status=="sat","Loop feasibility unknown");
        supported(++explored<=256&&f.visited.size()<128,"Loop contract exploration limit");
        if(f.pc==header&&!f.visited.empty()) {result.push_back({std::move(f.state),f.guard,false});continue;}
        supported(f.visited.insert(f.pc).second,"Nested/unmapped loop in contract");
        supported(f.pc>=code.address&&f.pc-code.address<code.bytes.size(),"Loop leaves function");
        ghidra::Address address(engine.sleigh.getDefaultCodeSpace(),f.pc);Assembly assembly;
        auto length=engine.sleigh.printAssembly(assembly,address);
        supported(length>0&&uint64_t(length)<=code.bytes.size()-(f.pc-code.address),"Invalid loop instruction");
        if(assembly.mnemonic=="RET"&&assembly.body.empty()) {result.push_back({std::move(f.state),f.guard,true});continue;}
        f.state.clear_temporaries();Emit emit;engine.sleigh.oneInstruction(emit,address);
        bool branched=false;auto next=f.pc+uint64_t(length);
        for(size_t index=0;index<emit.ops.size();++index) {
            const auto& op=emit.ops[index];using namespace ghidra;
            if(op.opcode==CPUI_BRANCH||op.opcode==CPUI_CBRANCH) {
                supported(op.inputs.at(0).space->getName()=="ram"&&index+1==emit.ops.size(),"Unsupported loop branch");
                auto test=op.opcode==CPUI_CBRANCH?truth(f.state.read(op.inputs.at(1))):c.bool_val(true);
                pending.push_back({op.inputs[0].offset,f.state,(f.guard&&test).simplify(),f.visited});
                pending.push_back({next,std::move(f.state),(f.guard&&!test).simplify(),std::move(f.visited)});
                branched=true;break;
            }
            supported(op.opcode!=CPUI_LOAD&&op.opcode!=CPUI_STORE,"Memory loop requires a memory invariant contract");
            supported(op.opcode!=CPUI_CALL&&op.opcode!=CPUI_CALLIND&&op.opcode!=CPUI_CALLOTHER&&
                      op.opcode!=CPUI_BRANCHIND&&op.opcode!=CPUI_RETURN,"Unsupported loop control flow");
            std::vector<z3::expr> values;for(const auto& var:op.inputs) values.push_back(f.state.read(var));
            supported(op.output.has_value(),"Unsupported loop operation without output");
            f.state.write(*op.output,compute(op,values).simplify());
        }
        if(!branched) pending.push_back({next,std::move(f.state),f.guard,std::move(f.visited)});
    }
    auto covered=c.bool_val(false);for(const auto& end:result) covered=covered||end.guard;
    supported(query(assumptions&&!covered).status=="unsat","One-lap/entry coverage not proved");
    return result;
}

inline uint64_t single_loop_header(Engine& engine,const Function& code) {
    std::set<uint64_t> headers;
    for(uint64_t offset=0;offset<code.bytes.size();) {
        ghidra::Address address(engine.sleigh.getDefaultCodeSpace(),code.address+offset);Assembly assembly;
        auto size=engine.sleigh.printAssembly(assembly,address);
        supported(size>0&&uint64_t(size)<=code.bytes.size()-offset,"Invalid instruction while finding loop");
        if(assembly.mnemonic!="RET") {
            Emit emit;engine.sleigh.oneInstruction(emit,address);
            for(const auto& op:emit.ops) if((op.opcode==ghidra::CPUI_BRANCH||op.opcode==ghidra::CPUI_CBRANCH)&&
                    op.inputs.at(0).space->getName()=="ram"&&op.inputs[0].offset<=address.getOffset())
                headers.insert(op.inputs[0].offset);
        }
        offset+=uint64_t(size);
    }
    supported(headers.size()==1,"Need exactly one direct loop header");return *headers.begin();
}

struct LoopProblem {
    z3::expr init_bad,step_bad,exit_bad,rank_bad;
    std::vector<z3::expr> parameters;
    std::string family;
    z3::expr violation() const {return (init_bad||step_bad||exit_bad||rank_bad).simplify();}
};

// Explicit fixture contract: EDI=initial byte x, ESI=byte bound n,
// EDX=iteration counter, AL=accumulator. The machine transitions are extracted,
// not replaced by handwritten a'=a+k or a'=a^k assignments.
inline LoopProblem loop_problem(z3::context& c,const Elf& elf,const std::string& symbol,
                                 const std::filesystem::path& sla,bool xor_family,bool bad_ranking=false) {
    auto code=elf.function(symbol);Engine engine(code,sla);auto header=single_loop_header(engine,code);
    auto x=c.bv_const("loop_x",32),n=c.bv_const("loop_n",32),i=c.bv_const("loop_i",32),a=c.bv_const("loop_a",32);
    auto k=fresh_word(c,xor_family?"xor_mask":"add_stride",8);
    auto domain=z3::ult(x,256)&&z3::ult(n,256);
    auto read=[&](State& state,const std::string& reg){return state.read(engine.sleigh.getRegister(reg));};
    auto write=[&](State& state,const std::string& reg,const z3::expr& value){state.write(engine.sleigh.getRegister(reg),value);};
    auto summary=[&](const z3::expr& count) {
        auto low=count.extract(7,0),input=x.extract(7,0);
        return xor_family?input^z3::ite((low&c.bv_val(1,8))!=0,k,c.bv_val(0,8)):input+k*low;
    };
    auto invariant=[&](State& state) {
        return domain&&(read(state,"EDI")==x)&&(read(state,"ESI")==n)&&
               z3::ult(read(state,"EDX"),n)&&(read(state,"AL")==summary(read(state,"EDX")));
    };
    auto post=[&](State& state){return read(state,"AL")==summary(n);};
    auto rank=[&](State& state){return bad_ranking?c.int_val(1):z3::bv2int(n,false)-z3::bv2int(read(state,"EDX"),false);};
    State initial(c);write(initial,"EDI",x);write(initial,"ESI",n);
    auto entry=walk_loop(engine,code,code.address,header,initial,domain);
    auto init_bad=c.bool_val(false),step_bad=c.bool_val(false),exit_bad=c.bool_val(false),rank_bad=c.bool_val(false);
    for(auto& end:entry) {
        if(end.returned) exit_bad=exit_bad||(domain&&end.guard&&!post(end.state));
        else init_bad=init_bad||(domain&&end.guard&&!invariant(end.state));
    }
    State arbitrary(c);write(arbitrary,"EDI",x);write(arbitrary,"ESI",n);write(arbitrary,"EDX",i);write(arbitrary,"EAX",a);
    auto before=invariant(arbitrary),old_rank=rank(arbitrary);
    // Exploration uses the parameter-independent superset of possible header states.
    auto exploration_domain=domain&&z3::ult(i,n);
    auto transitions=walk_loop(engine,code,header,header,arbitrary,exploration_domain);
    for(auto& end:transitions) {
        if(end.returned) exit_bad=exit_bad||(before&&end.guard&&!post(end.state));
        else {
            step_bad=step_bad||(before&&end.guard&&!invariant(end.state));
            rank_bad=rank_bad||(before&&end.guard&&!(old_rank>0&&rank(end.state)>=0&&rank(end.state)<old_rank));
        }
    }
    return {init_bad.simplify(),step_bad.simplify(),exit_bad.simplify(),rank_bad.simplify(),{k},xor_family?"xor_parity":"modular_add"};
}

struct LoopProof {std::string status,family;uint64_t parameter=0;size_t refinements=0;};
inline LoopProof prove_loop(z3::context& c,const Elf& elf,const std::string& symbol,const std::filesystem::path& sla,
                            const std::filesystem::path& output) {
    std::ostringstream report;LoopProof result{"outside_contract","",0,0};
    for(bool xor_family:{false,true}) {
        auto problem=loop_problem(c,elf,symbol,sla,xor_family);auto directory=output/problem.family;
        auto fit=synthesize(problem.violation(),problem.parameters,directory);
        report<<problem.family<<": "<<fit.status<<"; refinements="<<fit.counterexamples<<'\n';
        result.refinements+=fit.counterexamples;
        if(fit.status!="verified") {if(fit.status!="grammar_exhausted") result.status="unresolved";continue;}
        z3::expr_vector from(c),to(c);from.push_back(problem.parameters[0]);to.push_back(c.bv_val(fit.parameters[0],8));
        for(auto [name,violation]:std::vector<std::pair<std::string,z3::expr>>{{"initialization",problem.init_bad},
                {"preservation",problem.step_bad},{"exit",problem.exit_bad},{"termination",problem.rank_bad}}) {
            auto check=violation.substitute(from,to);
            require(query(check,{},5000,directory/(name+".smt2")).status=="unsat","Final loop obligation failed: "+name);
            report<<"  "<<name<<": unsat\n";
        }
        result.status="verified";result.family=problem.family;result.parameter=fit.parameters[0];
        report<<"parameter="<<result.parameter<<"\nContract: full EDI/ESI in [0,255]; EDX counter; AL accumulator.\n";
        break;
    }
    std::filesystem::create_directories(output);write_file(output/"loop_proof.txt",report.str());return result;
}
} // namespace fibers
