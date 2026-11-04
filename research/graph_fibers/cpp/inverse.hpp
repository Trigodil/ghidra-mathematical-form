#pragma once
#include "native.hpp"
#include <cerrno>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fibers {
inline void write_file(const std::filesystem::path& path,const std::string& text) {
    std::ofstream output(path); output<<text; require(bool(output),"Cannot write artifact: "+path.string());
}
inline void run_process(std::vector<std::string> command,const std::filesystem::path& log) {
    std::vector<char*> args;
    for(auto& word:command) args.push_back(word.data());
    args.push_back(nullptr);
    int descriptor=open(log.c_str(),O_WRONLY|O_CREAT|O_TRUNC,0600);
    require(descriptor>=0,"Cannot create compiler log");
    pid_t child=fork();
    if(child<0) {close(descriptor);throw std::runtime_error("Cannot start compiler");}
    if(child==0) {
        if(dup2(descriptor,STDOUT_FILENO)<0 || dup2(descriptor,STDERR_FILENO)<0) _exit(126);
        close(descriptor); execvp(args[0],args.data()); _exit(127);
    }
    close(descriptor); int status;
    while(waitpid(child,&status,0)<0) if(errno!=EINTR) throw std::runtime_error("Cannot wait for compiler");
    require(WIFEXITED(status)&&WEXITSTATUS(status)==0,"Compiler failed; see "+log.string());
}

struct Affine { unsigned width; uint64_t a,b,c; };
inline std::string canonical_source(const Affine& value) {
    require(value.width==8 || value.width==32,"Canonical source family supports u8 and u32");
    const std::string type=value.width==8?"std::uint8_t":"std::uint32_t";
    std::ostringstream out;
    out<<"#include <cstdint>\nextern \"C\" "<<type<<" reconstructed("<<type<<" x, "<<type<<" y) {\n"
       <<"    return static_cast<"<<type<<">(std::uint32_t{"<<value.a<<"u} * x + "
       <<"std::uint32_t{"<<value.b<<"u} * y + std::uint32_t{"<<value.c<<"u});\n}\n";
    return out.str();
}
inline std::filesystem::path compile_canonical(const Affine& value,const std::filesystem::path& directory) {
    namespace fs=std::filesystem;
    fs::create_directories(directory);
    auto source=fs::absolute(directory/"reconstructed.cpp"), binary=fs::absolute(directory/"reconstructed.so");
    write_file(source,canonical_source(value));
    run_process({"g++","-std=c++17","-O2","-shared","-fPIC","-fcf-protection=none",
                 "-fno-if-conversion","-fno-if-conversion2",source.string(),"-o",binary.string()},
                directory/"compiler.log");
    run_process({"g++","--version"},directory/"compiler_version.txt");
    return binary;
}

inline Affine recover_affine(const Model& model,const std::filesystem::path& directory) {
    supported(model.inputs.size()==2 && model.result.is_bv(),"Need two inputs and a word result");
    const auto width=model.result.get_sort().bv_size();
    supported((width==8||width==32) && model.inputs[0].get_sort().bv_size()==width &&
              model.inputs[1].get_sort().bv_size()==width,"Affine inverse needs equal u8/u32 input/output widths");
    auto& context=model.result.ctx();
    auto evaluate=[&](unsigned x,unsigned y) {
        z3::expr_vector from(context),to(context);
        for(const auto& input:model.inputs) from.push_back(input);
        to.push_back(context.bv_val(x,width));to.push_back(context.bv_val(y,width));
        auto value=model.result;value=value.substitute(from,to).simplify();
        supported(value.is_numeral(),"Basis value depends on memory or undeclared state");
        return value.get_numeral_uint64();
    };
    const uint64_t mask=(uint64_t(1)<<width)-1;
    const uint64_t c=evaluate(0,0),a=(evaluate(1,0)-c)&mask,b=(evaluate(0,1)-c)&mask;
    auto candidate=context.bv_val(a,width)*model.inputs[0]+context.bv_val(b,width)*model.inputs[1]+context.bv_val(c,width);
    auto validity=query(model.result!=candidate || model.memory_out!=model.memory_in,model.inputs,5000,
                        directory/"affine_membership.smt2");
    supported(validity.status=="unsat","Affine membership was not proved: "+validity.status);
    // Three basis observations uniquely fix the normalized modular coefficients.
    auto aa=context.bv_const("alternative_a",width),bb=context.bv_const("alternative_b",width),
         cc=context.bv_const("alternative_c",width);
    auto ambiguous=(cc==context.bv_val(c,width)) &&
                   (aa+cc==context.bv_val((a+c)&mask,width)) &&
                   (bb+cc==context.bv_val((b+c)&mask,width)) &&
                   ((aa!=context.bv_val(a,width)) || (bb!=context.bv_val(b,width)) ||
                    (cc!=context.bv_val(c,width)));
    supported(query(ambiguous,{aa,bb,cc},5000,directory/"parameter_uniqueness.smt2").status=="unsat",
              "Parameter uniqueness was not proved");
    return {width,a,b,c};
}

struct Inversion { Affine recovered; bool exact; size_t input_size,output_size; };
inline Inversion invert_affine(const Elf& input,const std::string& symbol,const Model& model,
                              const std::filesystem::path& directory) {
    std::filesystem::create_directories(directory);
    auto recovered=recover_affine(model,directory);
    auto binary=compile_canonical(recovered,directory);
    auto before=input.function(symbol),after=Elf(binary).function("reconstructed");
    const bool exact=before.bytes==after.bytes;
    std::ofstream original(directory/"input_function.bin",std::ios::binary),
                  rebuilt(directory/"recompiled_function.bin",std::ios::binary);
    original.write(reinterpret_cast<const char*>(before.bytes.data()),std::streamsize(before.bytes.size()));
    rebuilt.write(reinterpret_cast<const char*>(after.bytes.data()),std::streamsize(after.bytes.size()));
    std::ostringstream report;
    report<<"Family: canonical u"<<recovered.width<<" affine C++ function, modulo 2^"<<recovered.width<<"\n"
          <<"Recovered parameters: a="<<recovered.a<<", b="<<recovered.b<<", c="<<recovered.c<<"\n"
          <<"All-input semantic membership: SMT unsat\nNormalized parameter uniqueness: SMT unsat\n"
          <<"Input function bytes: "<<before.bytes.size()<<"\nRecompiled function bytes: "<<after.bytes.size()<<"\n"
          <<"Exact function-byte round trip C_theta(I(b)) == b: "<<(exact?"PASS":"NO MATCH")<<"\n"
          <<"The compiler flags are in inverse.hpp; compiler identity is in compiler_version.txt.\n"
          <<"Observation is a named function's code bytes, not the entire ELF file.\n"
          <<"Source is the canonical family member; historical source spelling is not asserted.\n";
    write_file(directory/"inverse_report.txt",report.str());
    return {recovered,exact,before.bytes.size(),after.bytes.size()};
}
} // namespace fibers
