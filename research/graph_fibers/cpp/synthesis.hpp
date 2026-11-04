#pragma once
#include "inverse.hpp"

namespace fibers {
inline z3::expr fresh_word(z3::context& c,const std::string& name,unsigned width) {
    return z3::to_expr(c,Z3_mk_fresh_const(c,name.c_str(),c.bv_sort(width)));
}
struct Synthesis {
    std::string status;
    std::vector<uint64_t> parameters;
    size_t rounds=0,counterexamples=0;
};

// Exists parameters, forall states: NOT violation(parameters, states).
// Both parameter and state variables must have finite bit-vector domains.
inline Synthesis synthesize(const z3::expr& violation,const std::vector<z3::expr>& parameters,
                            const std::filesystem::path& output,size_t limit=64) {
    std::filesystem::create_directories(output);
    auto& c=violation.ctx();auto problem=violation.simplify();
    std::unordered_set<unsigned> parameter_ids;
    for(const auto& p:parameters) parameter_ids.insert(p.id());
    std::vector<z3::expr> states;
    for(const auto& variable:variables(problem)) {
        supported(variable.is_bv()&&variable.get_sort().bv_size()<=64,"Synthesis requires finite word variables");
        if(!parameter_ids.count(variable.id())) states.push_back(variable);
    }
    z3::solver proposals(c);proposals.set("timeout",5000u);
    std::ostringstream trace;Synthesis answer;
    for(size_t round=0;round<limit;++round) {
        answer.rounds=round+1;trace<<"round "<<round<<": propose\n";
        auto status=proposals.check();
        if(status==z3::unsat) {answer.status="grammar_exhausted";break;}
        if(status==z3::unknown) {answer.status="unknown";trace<<proposals.reason_unknown()<<'\n';break;}
        auto model=proposals.get_model();z3::expr_vector from(c),to(c);
        answer.parameters.clear();
        for(const auto& p:parameters) {
            auto value=model.eval(p,true);from.push_back(p);to.push_back(value);
            answer.parameters.push_back(value.get_numeral_uint64());
        }
        auto candidate=problem;candidate=candidate.substitute(from,to).simplify();
        auto proof=query(candidate,states,5000,output/("verify_"+std::to_string(round)+".smt2"));
        trace<<"verify: "<<proof.status<<'\n';
        if(proof.status=="unsat") {answer.status="verified";break;}
        if(proof.status=="unknown") {answer.status="unknown";trace<<proof.reason<<'\n';break;}
        ++answer.counterexamples;from.resize(0);to.resize(0);
        for(const auto& state:states) {
            auto value=proof.witness.at(state.decl().name().str());
            from.push_back(state);to.push_back(c.bv_val(value,state.get_sort().bv_size()));
            trace<<"  "<<state.decl().name()<<'='<<value<<'\n';
        }
        auto constraint=problem;constraint=constraint.substitute(from,to);
        proposals.add(!constraint);trace<<"refine\n";
    }
    if(answer.status.empty()) answer.status="iteration_limit";
    trace<<"status: "<<answer.status<<"\nrounds: "<<answer.rounds<<"\ncounterexamples: "<<answer.counterexamples<<'\n';
    write_file(output/"state_loop.txt",trace.str());return answer;
}

struct FormulaFamily {
    std::string name;
    std::vector<z3::expr> parameters;
    z3::expr expression;
    std::function<std::string(const std::vector<uint64_t>&)> source;
};
inline std::vector<FormulaFamily> formula_families(const Model& model) {
    supported(model.inputs.size()==2,"Formula synthesis needs two input words");
    auto& c=model.result.ctx();auto width=model.result.get_sort().bv_size();
    supported((width==8||width==32)&&model.inputs[0].get_sort().bv_size()==width&&
              model.inputs[1].get_sort().bv_size()==width,"Formula synthesis requires equal u8/u32 widths");
    supported(query(model.memory_out!=model.memory_in).status=="unsat","Formula family is pure; memory effects need a different grammar");
    auto x=model.inputs[0],y=model.inputs[1];std::vector<FormulaFamily> families;
    auto polynomial=[&](bool quadratic) {
        std::vector<z3::expr> p;const unsigned count=quadratic?6:3;
        for(unsigned i=0;i<count;++i) {
            auto name=std::string(quadratic?"quadratic_":"affine_")+std::to_string(i);
            p.push_back(fresh_word(c,name,width));
        }
        auto formula=p[0]+p[1]*x+p[2]*y;
        if(quadratic) formula=formula+p[3]*x*y+p[4]*x*x+p[5]*y*y;
        auto emit=[quadratic](const std::vector<uint64_t>& v) {
            auto k=[&](unsigned i){return "std::uint32_t{"+std::to_string(v.at(i))+"u}";};
            auto text=k(0)+" + "+k(1)+"*x + "+k(2)+"*y";
            if(quadratic) text+=" + "+k(3)+"*x*y + "+k(4)+"*x*x + "+k(5)+"*y*y";
            return text;
        };
        families.push_back({quadratic?"quadratic":"affine",p,formula,emit});
    };
    polynomial(false);
    for(const std::string op:{"xor","and","or","product","mixed"}) {
        auto formula=x^y;std::string source="x ^ y";
        if(op=="and"){formula=x&y;source="x & y";}
        if(op=="or"){formula=x|y;source="x | y";}
        if(op=="product"){formula=x*y;source="std::uint32_t{x} * y";}
        if(op=="mixed"){formula=(x*y)^(x+y);source="(std::uint32_t{x} * y) ^ (std::uint32_t{x} + y)";}
        families.push_back({op,{},formula,[source](const auto&){return source;}});
    }
    polynomial(true);
    std::vector<z3::expr> p;
    for(unsigned i=0;i<4;++i) p.push_back(fresh_word(c,"guarded_"+std::to_string(i),width));
    families.push_back({"guarded_affine_xor",p,z3::ite(z3::ult(x,p[0]),p[1]*x+p[2]*y+p[3],x^y),
        [](const std::vector<uint64_t>& v) {
            return "x < "+std::to_string(v[0])+"u ? (std::uint32_t{"+std::to_string(v[1])+"u}*x + "
                   "std::uint32_t{"+std::to_string(v[2])+"u}*y + std::uint32_t{"+std::to_string(v[3])+"u}) : (x ^ y)";
        }});
    return families;
}

struct Reconstruction { std::string status,family;size_t counterexamples=0; };
inline Reconstruction reconstruct(const Model& model,const Elf& input,const std::string& symbol,
                                   const std::filesystem::path& output) {
    std::filesystem::create_directories(output);std::ostringstream trace;
    Reconstruction result{"outside_grammar","",0};
    bool unresolved=false;
    for(const auto& family:formula_families(model)) {
        auto directory=output/family.name;
        auto fit=synthesize(model.result!=family.expression,family.parameters,directory);
        result.counterexamples+=fit.counterexamples;
        trace<<family.name<<": "<<fit.status<<"; rounds="<<fit.rounds<<'\n';
        if(fit.status!="verified") {
            unresolved|=fit.status!="grammar_exhausted";continue;
        }
        const auto width=model.result.get_sort().bv_size();
        std::string type=width==8?"std::uint8_t":"std::uint32_t";
        auto body=family.source(fit.parameters);
        write_file(directory/"reconstructed.cpp","#include <cstdint>\nextern \"C\" "+type+" reconstructed("+type+
                   " x, "+type+" y) { return static_cast<"+type+">("+body+"); }\n");
        auto source=std::filesystem::absolute(directory/"reconstructed.cpp"),
             binary=std::filesystem::absolute(directory/"reconstructed.so");
        run_process({"g++","-std=c++17","-O2","-shared","-fPIC","-fcf-protection=none",
                     "-fno-if-conversion","-fno-if-conversion2",source.string(),"-o",binary.string()},directory/"compiler.log");
        const auto before=input.function(symbol),after=Elf(binary).function("reconstructed");
        const bool exact=before.bytes==after.bytes;
        trace<<"  semantics verified; exact function bytes: "<<(exact?"yes":"no")<<'\n';
        result.status=exact?"verified_exact":"verified_semantic";result.family=family.name;
        if(exact) break;
    }
    if(result.status=="outside_grammar"&&unresolved) result.status="unresolved";
    trace<<"final: "<<result.status<<"; family="<<result.family<<'\n';
    write_file(output/"reconstruction.txt",trace.str());return result;
}
} // namespace fibers
