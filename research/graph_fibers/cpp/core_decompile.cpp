#include "native.hpp"
#include "libdecomp.hh"
#include "ruleaction.hh"
#include "printlanguage.hh"
#include <fstream>
#include <iostream>

// All ELF segments are data read through mmap(PROT_READ), never dlopen/exec.
class MappedElfImage : public ghidra::LoadImage {
    fibers::ReadOnlyFile data;
    std::vector<Elf64_Phdr> segments;
    ghidra::AddrSpace *space=nullptr;
public:
    explicit MappedElfImage(const std::string& path):LoadImage(path),data(path) {
        fibers::require(data.size()>=sizeof(Elf64_Ehdr),"Truncated ELF");
        Elf64_Ehdr h;std::memcpy(&h,data.data(),sizeof(h));
        fibers::require(!std::memcmp(h.e_ident,ELFMAG,SELFMAG)&&h.e_machine==EM_X86_64&&
            h.e_ident[EI_CLASS]==ELFCLASS64&&h.e_ident[EI_DATA]==ELFDATA2LSB,"Need x86-64 ELF");
        fibers::require(h.e_phentsize==sizeof(Elf64_Phdr)&&h.e_phoff<=data.size()&&
            uint64_t(h.e_phnum)*sizeof(Elf64_Phdr)<=data.size()-h.e_phoff,"Invalid ELF segments");
        for(unsigned i=0;i<h.e_phnum;++i) {
            Elf64_Phdr p;std::memcpy(&p,data.data()+h.e_phoff+i*sizeof(p),sizeof(p));
            if(p.p_type!=PT_LOAD)continue;
            fibers::require(p.p_offset<=data.size()&&p.p_filesz<=data.size()-p.p_offset&&
                p.p_filesz<=p.p_memsz,"Truncated load segment");segments.push_back(p);
        }
    }
    void attach(ghidra::AddrSpace *s){space=s;}
    bool executableAddress(uint64_t address) const {
        for(const auto& p:segments)
            if((p.p_flags&PF_X) && address>=p.p_vaddr && address-p.p_vaddr<p.p_filesz)
                return true;
        return false;
    }
    void loadFill(ghidra::uint1 *out,ghidra::int4 size,const ghidra::Address& address) override {
        for(int i=0;i<size;++i) {
            auto a=address.getOffset()+uint64_t(i);bool found=false;
            for(const auto& p:segments)if(a>=p.p_vaddr&&a-p.p_vaddr<p.p_memsz) {
                auto offset=a-p.p_vaddr;out[i]=offset<p.p_filesz?data.data()[p.p_offset+offset]:0;
                found=true;break;
            }
            if(!found)throw ghidra::DataUnavailError("Address outside ELF load segments");
        }
    }
    void getReadonly(ghidra::RangeList& ranges) const override {
        if(space)for(const auto& p:segments)if(!(p.p_flags&PF_W)&&p.p_filesz)
            ranges.insertRange(space,p.p_vaddr,p.p_vaddr+p.p_filesz-1);
    }
    std::string getArchType() const override{return "x86:LE:64:default:gcc";}
    void adjustVma(long) override{throw ghidra::LowlevelError("VMA adjustment unsupported");}
};
class StaticElfArchitecture : public ghidra::SleighArchitecture {
    void buildLoader(ghidra::DocumentStorage&) override {
        collectSpecFiles(std::cerr);loader=new MappedElfImage(getFilename());
    }
    void postSpecFile() override {
        ghidra::Architecture::postSpecFile();
        static_cast<MappedElfImage*>(loader)->attach(getDefaultCodeSpace());
    }
public:
    explicit StaticElfArchitecture(const std::string& file)
        :SleighArchitecture(file,"x86:LE:64:default:gcc",&std::cerr){}
};
int main(int argc,char **argv) {
    try {
        fibers::require(argc==5,"Usage: core-decompile BINARY SPEC_DIRECTORY SYMBOL OUTPUT");
        ghidra::startDecompilerLibrary(std::vector<std::string>{argv[2]});
        fibers::Elf elf(argv[1]);
        const std::string selector=argv[3];
        uint64_t selectedAddress;
        const bool byAddress=selector.compare(0,3,"@0x")==0;
        if(byAddress) {
            fibers::require(selector.size()>3 && selector.size()<=19 &&
                selector.find_first_not_of("0123456789abcdefABCDEF",3)==std::string::npos,
                "Invalid hexadecimal address selector");
            selectedAddress=std::stoull(selector.substr(3),nullptr,16);
        } else selectedAddress=elf.function(selector).address;
        StaticElfArchitecture arch(argv[1]);ghidra::DocumentStorage store;arch.init(store);
        MappedElfImage* image=static_cast<MappedElfImage*>(arch.loader);
        fibers::require(image->executableAddress(selectedAddress),"Selected address is not file-backed executable code");
        auto scope=arch.symboltab->getGlobalScope();std::unordered_set<uint64_t> added;
        for(const auto& symbol:elf.functions())if(added.insert(symbol.address).second)
            scope->addFunction(ghidra::Address(arch.getDefaultCodeSpace(),symbol.address),symbol.name);
        ghidra::Address selected(arch.getDefaultCodeSpace(),selectedAddress);
        if(added.insert(selectedAddress).second) {
            std::ostringstream name;name<<"__recovered_"<<std::hex<<selectedAddress;
            scope->addFunction(selected,name.str());
        }
        auto fd=scope->queryFunction(selected);
        fibers::require(fd!=nullptr,"Cannot create selected function");
        auto action=arch.allacts.getCurrent();auto peel=action->getSubRule("peel_multi_region");
        fibers::require(peel!=nullptr,"Updated peel_multi_region pass is absent from the action pool");
        action->reset(*fd);int result=action->perform(*fd);
        fibers::require(result>=0,"Decompilation stopped before completion");
        std::filesystem::create_directories(argv[4]);
        std::ofstream out(std::filesystem::path(argv[4])/"decompiled.c");
        arch.print->setOutputStream(&out);arch.print->docFunction(fd);out.flush();
        fibers::require(bool(out),"Cannot save pseudocode");
        std::cout<<"pseudocode_emitted; peel_tests="<<peel->getNumTests()
                 <<"; peel_applications="<<peel->getNumApply()<<'\n';
        // Printing is heuristic decompilation, not a semantic or byte-roundtrip proof.
        return 0;
    }catch(const ghidra::LowlevelError& e){std::cerr<<e.explain<<'\n';}
     catch(const std::exception& e){std::cerr<<e.what()<<'\n';}
    return 1;
}
