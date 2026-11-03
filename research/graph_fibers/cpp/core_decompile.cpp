#include "native.hpp"
#include "libdecomp.hh"
#include "ruleaction.hh"
#include "printlanguage.hh"
#include "jumptable.hh"
#include <fstream>
#include <iostream>

// All ELF segments are data read through mmap(PROT_READ), never dlopen/exec.
class MappedElfImage : public ghidra::LoadImage {
    fibers::ReadOnlyFile data;
    std::vector<Elf64_Phdr> segments;
    ghidra::AddrSpace *space=nullptr;
    struct Relocation { uint64_t address; bool known; uint64_t value; };
    std::vector<Relocation> relocations;
    bool unknownRelocationRead=false;
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
        // The decompiler uses link-time virtual addresses (load base zero).
        // Apply x86-64 RELATIVE relocations; all other relocation reads taint
        // the function so its inferred edges are not consumed by the frontend.
        fibers::require(h.e_shentsize==sizeof(Elf64_Shdr) && h.e_shoff<=data.size() &&
            uint64_t(h.e_shnum)*sizeof(Elf64_Shdr)<=data.size()-h.e_shoff,"Invalid ELF sections");
        for(unsigned i=0;i<h.e_shnum;++i) {
            Elf64_Shdr sh; std::memcpy(&sh,data.data()+h.e_shoff+i*sizeof(sh),sizeof(sh));
            if(sh.sh_type!=SHT_RELA && sh.sh_type!=SHT_REL && sh.sh_type!=SHT_RELR) continue;
            size_t width=sh.sh_type==SHT_RELA ? sizeof(Elf64_Rela) : (sh.sh_type==SHT_REL ? sizeof(Elf64_Rel) : sizeof(uint64_t));
            fibers::require(sh.sh_entsize==width && sh.sh_size%width==0 && sh.sh_offset<=data.size() && sh.sh_size<=data.size()-sh.sh_offset,"Invalid relocations");
            uint64_t cursor=0;
            for(uint64_t off=0;off<sh.sh_size;off+=width) {
                if(sh.sh_type==SHT_RELA) {
                    Elf64_Rela r;std::memcpy(&r,data.data()+sh.sh_offset+off,sizeof(r));
                    if(ELF64_R_TYPE(r.r_info)!=R_X86_64_NONE)
                        relocations.push_back({r.r_offset, ELF64_R_TYPE(r.r_info)==R_X86_64_RELATIVE && ELF64_R_SYM(r.r_info)==0, uint64_t(r.r_addend)});
                } else if(sh.sh_type==SHT_REL) {
                    Elf64_Rel r;std::memcpy(&r,data.data()+sh.sh_offset+off,sizeof(r));
                    if(ELF64_R_TYPE(r.r_info)!=R_X86_64_NONE) relocations.push_back({r.r_offset,false,0});
                } else {
                    uint64_t r;std::memcpy(&r,data.data()+sh.sh_offset+off,sizeof(r));
                    if((r&1)==0) { relocations.push_back({r,false,0}); cursor=r+8; }
                    else {
                        for(unsigned bit=1;bit<64;++bit) if(r&(uint64_t(1)<<bit)) relocations.push_back({cursor+(bit-1)*8,false,0});
                        cursor+=63*8;
                    }
                }
            }
        }
        std::sort(relocations.begin(),relocations.end(),[](const auto& a,const auto& b){return a.address<b.address;});
    }
    void attach(ghidra::AddrSpace *s){space=s;}
    bool hasUnknownRelocationRead() const { return unknownRelocationRead; }
    bool readReadonlyPointer(uint64_t address, uint64_t& value) {
        for(const auto& p:segments) {
            if((p.p_flags&PF_W) || address<p.p_vaddr || address-p.p_vaddr>p.p_filesz ||
               p.p_filesz-(address-p.p_vaddr)<8) continue;
            uint8_t bytes[8];
            bool before=unknownRelocationRead;
            loadFill(bytes,8,ghidra::Address(space,address));
            if(unknownRelocationRead && !before) return false;
            if(unknownRelocationRead) return false;
            value=0; for(unsigned i=0;i<8;++i) value|=uint64_t(bytes[i])<<(8*i);
            return true;
        }
        return false;
    }
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
            auto it=std::upper_bound(relocations.begin(),relocations.end(),a,
                [](uint64_t value,const Relocation& r){return value<r.address;});
            if(it!=relocations.begin()) {
                --it;
                if(a>=it->address && a-it->address<8) {
                    if(it->known) out[i]=uint8_t(it->value >> ((a-it->address)*8));
                    else unknownRelocationRead=true;
                }
            }
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
        // Export only addresses the decompiler actually resolved; the frontend
        // decides whether the image's relocation state permits using them.
        std::ofstream edges(std::filesystem::path(argv[4])/"recovered-edges.tsv");
        edges << "kind\tsite\ttarget\n";
        for(int i=0;i<fd->numCalls();++i) {
            auto call=fd->getCallSpecs(i); auto op=call->getOp();
            auto target=call->getEntryAddress();
            if(op && (target.isInvalid() || target.getSpace()!=arch.getDefaultCodeSpace()) &&
               op->code()==ghidra::CPUI_CALLIND && op->numInput()>0 && op->getIn(0)->isConstant())
                target=ghidra::Address(arch.getDefaultCodeSpace(),op->getIn(0)->getOffset());
            if(op && target.isInvalid() && op->code()==ghidra::CPUI_CALLIND && op->numInput()>0) {
                auto value=op->getIn(0); auto def=value->getDef();
                uint64_t directPointer;
                if(value->getSize()==8 && value->getSpace()==arch.getDefaultDataSpace() &&
                   image->readReadonlyPointer(value->getOffset(),directPointer))
                    target=ghidra::Address(arch.getDefaultCodeSpace(),directPointer);
                if(def && def->code()==ghidra::CPUI_LOAD && def->numInput()>1 &&
                   value->getSize()==8 && def->getIn(1)->isConstant()) {
                    uint64_t pointer;
                    if(image->readReadonlyPointer(def->getIn(1)->getOffset(),pointer))
                        target=ghidra::Address(arch.getDefaultCodeSpace(),pointer);
                }
            }
            if(op && !target.isInvalid() && target.getSpace()==arch.getDefaultCodeSpace() &&
               image->executableAddress(target.getOffset()))
                edges << (op->code()==ghidra::CPUI_CALLIND ? "indirect_call\t" : "call\t") << std::hex << op->getAddr().getOffset() << "\t" << target.getOffset() << "\n";
        }
        for(int i=0;i<fd->numJumpTables();++i) {
            auto table=fd->getJumpTable(i); auto op=table->getIndirectOp();
            if(!op) continue;
            for(int j=0;j<table->numEntries();++j) {
                auto target=table->getAddressByIndex(j);
                if(!target.isInvalid() && target.getSpace()==arch.getDefaultCodeSpace() && image->executableAddress(target.getOffset()))
                    edges << "switch\t" << std::hex << op->getAddr().getOffset() << "\t" << target.getOffset() << "\n";
            }
        }
        edges.close(); fibers::require(bool(edges),"Cannot save recovered edges");
        std::ofstream quality(std::filesystem::path(argv[4])/"quality.tsv");
        quality << "unimplemented\t" << (fd->hasUnimplemented()?1:0) << "\n";
        quality << "bad_data\t" << (fd->hasBadData()?1:0) << "\n";
        quality << "unknown_relocation_read\t" << (image->hasUnknownRelocationRead()?1:0) << "\n";
        quality.close(); fibers::require(bool(quality),"Cannot save quality data");
        std::cout<<"pseudocode_emitted; peel_tests="<<peel->getNumTests()
                 <<"; peel_applications="<<peel->getNumApply()<<'\n';
        // Printing is heuristic decompilation, not a semantic or byte-roundtrip proof.
        return 0;
    }catch(const ghidra::LowlevelError& e){std::cerr<<e.explain<<'\n';}
     catch(const std::exception& e){std::cerr<<e.what()<<'\n';}
    return 1;
}
