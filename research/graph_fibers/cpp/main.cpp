#include "native.hpp"
#include "inverse.hpp"
#include "dimensions.hpp"
#include <dlfcn.h>
#include <iostream>

using namespace fibers;
namespace fs=std::filesystem;

static void save(const Model& model,const std::string& name,const fs::path& output) {
    require(name.find('/')==std::string::npos && name!="..","Invalid artifact name");
    std::ofstream text(output/(name+".txt"));
    text<<"return paths: "<<model.paths<<"\nreturn: "<<model.result<<"\nRAM: "<<model.memory_out
        <<"\ninitial register bytes proved irrelevant: "<<model.projected_register_bytes<<"\n\n";
    for(const auto& line:model.trace) text<<line;
    auto graph=semantic_graph(model.result,model.memory_out);
    std::ofstream dot(output/(name+".dot")); dot<<"digraph dataflow {\n";
    auto escape=[](const std::string& value) {
        std::string out;
        for(char ch:value) { if(ch=='"'||ch=='\\') out+='\\'; out+=ch=='\n'?' ':ch; }
        return out;
    };
    for(size_t i=0;i<graph.vertices.size();++i) {
        dot<<"n"<<i<<" [label=\""<<escape(graph.vertices[i].label)<<"\"];\n";
        for(auto [slot,target]:graph.vertices[i].outgoing)
            dot<<"n"<<i<<" -> n"<<target<<" [label=\""<<slot<<"\"];\n";
    }
    dot<<"}\n";
}

template<class T> static T symbol(void* library,const char* name) {
    auto pointer=dlsym(library,name); require(pointer!=nullptr,std::string("Missing native symbol: ")+name);
    return reinterpret_cast<T>(pointer);
}

static void inverse_demo(const fs::path& sla,const fs::path& binary,const fs::path& output) {
    fs::create_directories(output);z3::context c;Elf elf(binary);std::ostringstream report;
    size_t exact_existing=0,canonical_cases=0;
    for(const std::string name:{"affine","affine_shifts","affine_wrong","affine32"}) {
        const bool wide=name=="affine32";
        const unsigned width=wide?32:8;
        std::vector<Argument> args{{"x",width,wide?"EDI":"DIL"},{"y",width,wide?"ESI":"SIL"}};
        auto model=lift(c,elf,name,sla,args,wide?"EAX":"AL");
        auto inverse=invert_affine(elf,name,model,output/name);
        report<<name<<": recovered ("<<inverse.recovered.a<<','<<inverse.recovered.b<<','<<inverse.recovered.c
              <<"); exact function-byte round trip: "<<(inverse.exact?"PASS":"NO MATCH")<<'\n';
        if(inverse.exact) ++exact_existing;
    }
    require(exact_existing>0,"No existing fixture achieved an exact round trip");
    const std::vector<Affine> cases{{8,0,0,0},{8,1,0,0},{8,0,1,0},{8,6,1,4},{8,255,255,255},
                                   {8,17,33,241},{32,6,1,4},{32,0xffffffff,0x80000000,0x12345678}};
    for(size_t i=0;i<cases.size();++i) {
        auto directory=output/("canonical_"+std::to_string(i));
        auto generated=compile_canonical(cases[i],directory/"input");Elf canonical(generated);
        auto width=cases[i].width;
        auto model=lift(c,canonical,"reconstructed",sla,
                        {{"x",width,width==8?"DIL":"EDI"},{"y",width,width==8?"SIL":"ESI"}},width==8?"AL":"EAX");
        auto inverse=invert_affine(canonical,"reconstructed",model,directory/"inverse");
        require(inverse.exact&&inverse.recovered.a==cases[i].a&&inverse.recovered.b==cases[i].b&&
                inverse.recovered.c==cases[i].c,"Canonical inverse failed");++canonical_cases;
    }
    auto xor_model=lift(c,elf,"bitxor",sla);bool rejected=false;
    fs::create_directories(output/"negative_xor");
    try {recover_affine(xor_model,output/"negative_xor");}
    catch(const Unsupported&){rejected=true;}
    require(rejected,"Non-affine XOR was incorrectly accepted");
    dimension_experiment(c,output/"dimensions",report);
    // Lift the actual byte-returning function again, observing full EAX at RET.
    // The declared input state is full EDI/ESI, then constrained to a byte and zero.
    auto eax=lift(c,elf,"affine",sla,{{"trace_x",32,"EDI"},{"trace_y",32,"ESI"}},"EAX");
    save(eax,"eax_observation",output);
    auto tx=eax.inputs[0],ty=eax.inputs[1];
    auto trace_domain=z3::ult(tx,256)&&ty==0;
    auto observed_byte=eax.result.extract(7,0)==c.bv_val(22,8);
    auto quotient=z3::lshr(eax.result,8);
    require(query(trace_domain&&(eax.result!=6*tx+4),eax.inputs,5000,
                  output/"actual_eax_lift.smt2").status=="unsat","Actual EAX lift disagrees with model");
    auto byte_only=enumerate(trace_domain&&observed_byte,{tx});
    std::sort(byte_only.points.begin(),byte_only.points.end());
    auto zero_quotient=enumerate(trace_domain&&observed_byte&&quotient==0,{tx});
    auto three_quotient=enumerate(trace_domain&&observed_byte&&quotient==3,{tx});
    require(byte_only.complete&&byte_only.points==std::vector<std::vector<uint64_t>>{{3},{131}}&&
            zero_quotient.complete&&zero_quotient.points==std::vector<std::vector<uint64_t>>{{3}}&&
            three_quotient.complete&&three_quotient.points==std::vector<std::vector<uint64_t>>{{131}},
            "Actual EAX observation failed to refine the byte-only fiber");
    report<<"Actual affine code, modeled at RET with EDI in [0,255] and ESI=0:\n"
          <<"  AL=22 -> {3,131}; additionally EAX>>8=0 -> {3}; EAX>>8=3 -> {131}.\n"
          <<"  This is a static register-state check; a live debugger trace was not collected.\n";
    report<<"\nPASS: "<<exact_existing<<" existing function byte round trips; "<<canonical_cases
          <<" canonical-source inversions; non-affine negative case; embedding and topology checks.\n"
          <<"C_theta maps canonical source to named-function code bytes with fixed g++ flags.\n"
          <<"I is accepted as an exact partial right inverse only when C_theta(I(b)) == b is byte-verified.\n"
          <<"Parameter uniqueness is within the declared affine family. Whole-ELF/original-text recovery is not claimed.\n";
    write_file(output/"report.txt",report.str());std::cout<<report.str();
}

static void demo(const fs::path& sla,const fs::path& binary,const fs::path& output) {
    fs::create_directories(output);
    z3::context c; Elf elf(binary);
    std::ostringstream report;
    auto begin=std::chrono::steady_clock::now();
    using ByteFunction=uint8_t(*)(uint8_t,uint8_t);
    // This mode is a validation harness and executes only the explicitly supplied fixtures.
    // The analyze mode below never loads or executes its input ELF.
    void* library=dlopen(fs::absolute(binary).c_str(),RTLD_NOW|RTLD_LOCAL);
    require(library!=nullptr,"Cannot load fixture library");
    struct Close { void* pointer; ~Close(){ dlclose(pointer); } } close{library};
    std::map<std::string,Model> models;
    uint64_t native_checks=0; unsigned formula_proofs=0;
    for(const std::string name:{"affine","affine_shifts","affine_wrong","add","bitxor",
                               "subtract","subtract_swapped","branchy","branchy_wrong"}) {
        auto model=lift(c,elf,name,sla); auto x=model.inputs[0],y=model.inputs[1];
        auto candidate=6*x+y+4;
        std::function<uint8_t(unsigned,unsigned)> evaluate=[](unsigned a,unsigned b){return uint8_t(6*a+b+4);};
        if(name=="affine_wrong") { candidate=6*x+y+5; evaluate=[](unsigned a,unsigned b){return uint8_t(6*a+b+5);}; }
        else if(name=="add") { candidate=x+y; evaluate=[](unsigned a,unsigned b){return uint8_t(a+b);}; }
        else if(name=="bitxor") { candidate=x^y; evaluate=[](unsigned a,unsigned b){return uint8_t(a^b);}; }
        else if(name=="subtract") { candidate=x-y; evaluate=[](unsigned a,unsigned b){return uint8_t(a-b);}; }
        else if(name=="subtract_swapped") { candidate=y-x; evaluate=[](unsigned a,unsigned b){return uint8_t(b-a);}; }
        else if(name=="branchy"||name=="branchy_wrong") {
            unsigned threshold=name=="branchy"?128:127;
            candidate=z3::ite(z3::ult(x,int(threshold)),6*x+y+4,x^y);
            evaluate=[threshold](unsigned a,unsigned b){return uint8_t(a<threshold?6*a+b+4:a^b);};
        }
        auto proof=query(model.result!=candidate || model.memory_out!=model.memory_in,model.inputs,5000,
                         output/("prove_"+name+".smt2"));
        require(proof.status=="unsat","p-code/candidate equivalence not proved for "+name+": "+proof.status);
        ++formula_proofs;
        auto native=symbol<ByteFunction>(library,name.c_str());
        for(unsigned a=0;a<256;++a) for(unsigned b=0;b<256;++b) {
            require(native(uint8_t(a),uint8_t(b))==evaluate(a,b),"Native byte fixture mismatch: "+name);
            ++native_checks;
        }
        save(model,name,output); models.emplace(name,std::move(model));
    }
    auto model32=lift(c,elf,"affine32",sla,{{"x",32,"EDI"},{"y",32,"ESI"}},"EAX");
    auto x32=model32.inputs[0],y32=model32.inputs[1];
    require(query(model32.result!=6*x32+y32+4,model32.inputs,5000,output/"prove_affine32.smt2").status=="unsat",
            "32-bit p-code equivalence not proved"); ++formula_proofs;
    auto native32=symbol<uint32_t(*)(uint32_t,uint32_t)>(library,"affine32");
    std::vector<uint32_t> boundary{0,1,127,128,255,0x7fffffff,0x80000000,0xffffffff};
    for(auto a:boundary) for(auto b:boundary) require(native32(a,b)==uint32_t(6u*a+b+4u),"32-bit boundary mismatch");
    save(model32,"affine32",output);

    auto& branch=models.at("branchy"); auto& wrong=models.at("branchy_wrong");
    auto difference=query(branch.result!=wrong.result,branch.inputs,5000,output/"branch_difference.smt2");
    require(difference.status=="sat","Changed branch was not distinguished");
    auto wx=difference.witness.at("x"),wy=difference.witness.at("y");
    require(symbol<ByteFunction>(library,"branchy")(uint8_t(wx),uint8_t(wy))!=
            symbol<ByteFunction>(library,"branchy_wrong")(uint8_t(wx),uint8_t(wy)),"Witness failed native replay");
    report<<"Changed branch counterexample: x="<<wx<<", y="<<wy<<" (replayed natively)\n";

    auto alias=lift(c,elf,"boxed_alias",sla,{{"p",64,"RDI"},{"q",64,"RSI"}});
    auto p=alias.inputs[0],q=alias.inputs[1];
    auto alias_memory=z3::store(z3::store(alias.memory_in,p,c.bv_val(7,8)),q,c.bv_val(9,8));
    auto alias_return=z3::ite(p==q,c.bv_val(9,8),c.bv_val(7,8));
    require(query(alias.result!=alias_return || alias.memory_out!=alias_memory,alias.inputs,5000,
                  output/"prove_alias.smt2").status=="unsat","Alias return/RAM proof failed");
    save(alias,"boxed_alias",output);
    Box B{"allocation",z3::uge(p,0x1000)&&z3::ult(p,0x1002)&&z3::uge(q,0x1000)&&z3::ult(q,0x1002)};
    auto A=B.intersect({"alias",p==q}); auto Z=B.intersect({"return9",alias.result==9});
    require(A.subset_of(B).status=="unsat" && A.subset_of(Z).status=="unsat" && Z.subset_of(A).status=="unsat",
            "Box containment checks failed");
    auto overlap=A.overlaps(Z,alias.inputs);
    require(overlap.status=="sat","Expected nonempty A intersection Z");
    require(B.intersect({"nonalias",p!=q}).overlaps(Z).status=="unsat","Nonalias box incorrectly overlaps return9");
    query(A.states&&!Z.states,alias.inputs,5000,output/"A_subset_Z.smt2");
    query(A.states&&Z.states,alias.inputs,5000,output/"A_intersection_Z.smt2");
    report<<"Boxes: A subset B; A subset Z; Z subset A; A intersection Z is nonempty\n"
          <<"  witness p="<<overlap.witness.at("p")<<", q="<<overlap.witness.at("q")<<'\n';

    auto partial=lift(c,elf,"boxed_overlap",sla,{{"p",64,"RDI"},{"q",64,"RSI"}},"AX");
    auto low=z3::ite(q==p,c.bv_val(0x33,8),c.bv_val(0x11,8));
    auto high=z3::ite(q==p+1,c.bv_val(0x33,8),c.bv_val(0x22,8));
    auto partial_memory=z3::store(z3::store(z3::store(partial.memory_in,p,c.bv_val(0x11,8)),
                                          p+1,c.bv_val(0x22,8)),q,c.bv_val(0x33,8));
    require(query(partial.result!=z3::concat(high,low) || partial.memory_out!=partial_memory,
                  partial.inputs,5000,output/"prove_partial_overlap.smt2").status=="unsat",
            "Partial memory overlap proof failed");
    save(partial,"boxed_overlap",output);

    size_t memory_checks=0;
    auto native_alias=symbol<uint8_t(*)(uint8_t*,uint8_t*)>(library,"boxed_alias");
    auto native_partial=symbol<uint16_t(*)(uint8_t*,uint8_t*)>(library,"boxed_overlap");
    for(bool is_partial:{false,true}) for(unsigned seed:{0u,42u,255u})
        for(unsigned left=0;left<2;++left) for(unsigned right=0;right<(is_partial?3u:2u);++right) {
            uint8_t bytes[]={uint8_t(seed),uint8_t(seed^99u),uint8_t(seed^51u)};
            auto memory=z3::const_array(c.bv_sort(64),c.bv_val(0,8));
            auto address=reinterpret_cast<uintptr_t>(bytes);
            for(unsigned i=0;i<3;++i) memory=z3::store(memory,c.bv_val(uint64_t(address+i),64),c.bv_val(unsigned(bytes[i]),8));
            auto actual=is_partial?unsigned(native_partial(bytes+left,bytes+right)):unsigned(native_alias(bytes+left,bytes+right));
            const auto& model=is_partial?partial:alias;
            z3::expr_vector from(c),to(c); from.push_back(p);from.push_back(q);from.push_back(model.memory_in);
            to.push_back(c.bv_val(uint64_t(address+left),64));to.push_back(c.bv_val(uint64_t(address+right),64));to.push_back(memory);
            auto result=model.result; auto final_memory=model.memory_out;
            result=result.substitute(from,to).simplify(); final_memory=final_memory.substitute(from,to);
            require(result.get_numeral_uint64()==actual,"Symbolic/native memory return mismatch");
            for(unsigned i=0;i<3;++i) require(z3::select(final_memory,c.bv_val(uint64_t(address+i),64)).simplify().get_numeral_uint64()==bytes[i],
                                             "Symbolic/native final byte mismatch");
            ++memory_checks;
        }
    require(query(z3::store(alias.memory_in,p,c.bv_val(7,8))!=z3::store(alias.memory_in,p,c.bv_val(9,8))).status=="sat",
            "Different memory effects were missed");

    auto& affine=models.at("affine"); auto x=affine.inputs[0],y=affine.inputs[1];
    auto fiber=enumerate(affine.result==22 && y==0,{x});
    std::sort(fiber.points.begin(),fiber.points.end());
    require(fiber.complete && fiber.points==std::vector<std::vector<uint64_t>>{{3},{131}},"Incorrect complete fiber");
    auto narrowed=enumerate(affine.result==22 && y==0 && z3::ult(x,128),{x});
    require(narrowed.complete && narrowed.points==std::vector<std::vector<uint64_t>>{{3}},"Incorrect narrowed fiber");
    require(!enumerate(x==x,{x},1).complete,"Capped enumeration mislabeled complete");
    report<<"Execution fiber: {3,131}; intersect x<128: {3}\n";

    // 512-by-512 possible inputs represented by two 9-bit variables, not a dense grid.
    auto gx=c.bv_const("grid_x",9),gy=c.bv_const("grid_y",9);
    Box gridA{"A",z3::ult(gx,200)&&z3::ult(gy,200)};
    Box gridB{"B",z3::ult(gx,256)&&z3::ult(gy,256)};
    auto sum=z3::zext(gx,1)+z3::zext(gy,1); // Preserve ordinary sum; no 9-bit wrap.
    Box gridZ{"Z",sum==255};
    auto grid_begin=std::chrono::steady_clock::now();
    require(gridA.subset_of(gridB).status=="unsat","512-state box containment failed");
    auto grid_overlap=gridA.overlaps(gridZ,{gx,gy});
    require(grid_overlap.status=="sat","512-state box overlap failed");
    require(gridA.overlaps({"impossible sum",sum==511}).status=="unsat","Disjoint grid boxes overlapped");
    auto grid_us=std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now()-grid_begin).count();
    report<<"512x512 domain: symbolic containment and two overlap queries; no Cartesian scan\n"
          <<"  observed query time: "<<grid_us<<" us; witness "<<grid_overlap.witness.at("grid_x")
          <<','<<grid_overlap.witness.at("grid_y")<<" (timing is not an asymptotic bound)\n";

    auto left=semantic_graph(affine.result,affine.memory_out);
    auto& shifts=models.at("affine_shifts");
    auto colors=refine(left,semantic_graph(shifts.result,shifts.memory_out));
    require(colors.indistinguishable,"Expected structural candidate match");
    require(!refine(semantic_graph(models.at("add").result,models.at("add").memory_out),
                    semantic_graph(models.at("bitxor").result,models.at("bitxor").memory_out)).indistinguishable,
            "Typed graph failed to distinguish add and XOR");
    Graph cycle,triangles;
    for(unsigned i=0;i<6;++i){cycle.node("v");triangles.node("v");}
    for(unsigned i=0;i<6;++i){auto j=(i+1)%6;cycle.edge(i,j);cycle.edge(j,i);}
    for(auto [a,b]:std::vector<std::pair<unsigned,unsigned>>{{0,1},{1,2},{2,0},{3,4},{4,5},{5,3}}){triangles.edge(a,b);triangles.edge(b,a);}
    require(refine(cycle,triangles).indistinguishable,"Known 1-WL boundary check failed");
    try { lift(c,elf,"loop_example",sla); throw std::runtime_error("Loop accepted without invariant"); }
    catch(const Unsupported& error){report<<"Loop rejected explicitly: "<<error.what()<<'\n';}

    auto total_ms=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-begin).count();
    report<<"\nPASS: "<<formula_proofs<<" p-code/formula equivalence checks; alias and partial-overlap return/RAM checks\n"
          <<"Native validation: "<<native_checks<<" byte input pairs; "<<boundary.size()*boundary.size()
          <<" 32-bit boundary pairs; "<<memory_checks<<" memory/overlap cases\n"
          <<"Sparse graph match: "<<left.vertices.size()<<" vertices, "<<colors.rounds<<" refinement rounds\n"
          <<"Observed total validation time: "<<total_ms<<" ms\n\n"
          <<"Scope: Linux x86-64, explicit ABI, fixed-width bit-vectors, acyclic control flow, total byte-array RAM.\n"
          <<"Normal RET boundary; no page faults, permissions, MMIO, concurrency, calls, or loop invariants.\n"
          <<"SMT results are solver checks, not independently checked certificates.\n"
          <<"SLEIGH engine compiled from this fork; compiled x86 specification from pypcode 3.3.3.\n"
          <<"No Python runtime. No claim of universal linear complexity.\n";
    std::ofstream(output/"report.txt")<<report.str(); std::cout<<report.str();
}

int main(int argc,char** argv) {
    try {
        ghidra::AttributeId::initialize(); ghidra::ElementId::initialize();
        fs::path sla,binary,output="results"; std::string name,ret="AL"; std::vector<Argument> arguments;
        bool fixtures=false,analysis=false,inverse_validation=false;
        std::string recovery;
        for(int i=1;i<argc;++i) {
            std::string option=argv[i]; require(i+1<argc,"Missing option value"); std::string value=argv[++i];
            if(option=="--sla") sla=value;
            else if(option=="--fixtures") { require(!analysis,"Choose fixtures or analysis mode"); fixtures=true;binary=value; }
            else if(option=="--binary") { require(!fixtures,"Choose fixtures or analysis mode"); analysis=true;binary=value; }
            else if(option=="--inverse-fixtures") {inverse_validation=true;binary=value;}
            else if(option=="--recover") recovery=value;
            else if(option=="--output") output=value;
            else if(option=="--symbol") name=value;
            else if(option=="--return") ret=value;
            else if(option=="--arg") {
                auto first=value.find(':'),last=value.rfind(':');
                require(first!=std::string::npos && first!=last,"Argument format: NAME:WIDTH:REGISTER");
                arguments.push_back({value.substr(0,first),unsigned(std::stoul(value.substr(first+1,last-first-1))),value.substr(last+1)});
            } else throw std::runtime_error("Unknown option: "+option);
        }
        require(!sla.empty()&&!binary.empty(),"Required: --sla FILE and --fixtures ELF, or --binary ELF --symbol NAME --arg x:8:DIL");
        require(unsigned(fixtures)+unsigned(analysis)+unsigned(inverse_validation)==1,"Choose exactly one input mode");
        require(((fixtures||inverse_validation) && name.empty()) || (analysis && !name.empty()),"Use --fixtures/--inverse-fixtures for validation, or --binary with --symbol for analysis");
        require(recovery.empty() || (analysis&&recovery=="affine"),"--recover affine requires --binary and --symbol");
        if(inverse_validation) inverse_demo(sla,binary,output);
        else if(fixtures) demo(sla,binary,output);
        else {
            require(!arguments.empty(),"Declare the input ABI with --arg"); fs::create_directories(output);
            z3::context c; Elf elf(binary); auto model=lift(c,elf,name,sla,arguments,ret); save(model,name,output);
            std::cout<<name<<": "<<model.paths<<" return path(s); "<<model.result<<'\n';
            if(!recovery.empty()) {
                auto inverse=invert_affine(elf,name,model,output/"inverse");
                std::cout<<"Recovered a="<<inverse.recovered.a<<", b="<<inverse.recovered.b<<", c="<<inverse.recovered.c
                         <<"; exact function-byte round trip: "<<(inverse.exact?"PASS":"NO MATCH")<<'\n';
                if(!inverse.exact) return 2;
            }
        }
        return 0;
    } catch(const ghidra::LowlevelError& error){ std::cerr<<error.explain<<'\n'; }
      catch(const std::exception& error){std::cerr<<error.what()<<'\n';}
    return 1;
}
