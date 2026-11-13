#include "native.hpp"
#include "libdecomp.hh"
#include "ruleaction.hh"
#include "printlanguage.hh"
#include "jumptable.hh"
#include "variable.hh"
#include <fstream>
#include <iostream>
#include <cctype>
#include <iomanip>
#include <memory>
#include <set>

// All ELF segments are data read through mmap(PROT_READ), never dlopen/exec.
class MappedElfImage : public ghidra::LoadImage {
    fibers::ReadOnlyFile data;
    std::vector<Elf64_Phdr> segments;
    ghidra::AddrSpace *space=nullptr;
    struct Relocation { uint64_t address; bool known; uint64_t value; };
    std::vector<Relocation> relocations;
    std::vector<std::pair<uint64_t,uint64_t>> sections;	// allocated section ranges
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
            if((sh.sh_flags&SHF_ALLOC) && sh.sh_size) sections.push_back({sh.sh_addr,sh.sh_size});
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
    // Headers and gaps between sections are not addresses; no section table means no filter.
    bool inSection(uint64_t address) const {
        if(sections.empty()) return true;
        for(const auto& s:sections) if(address>=s.first && address-s.first<s.second) return true;
        return false;
    }
    bool hasUnknownRelocationRead() const { return unknownRelocationRead; }
    bool dataRange(uint64_t address,uint64_t size) const {
        if(size==0 || address>UINT64_MAX-size) return false;
        for(const auto& p:segments)
            if(!(p.p_flags&PF_X) && address>=p.p_vaddr && address-p.p_vaddr<=p.p_memsz &&
               size<=p.p_memsz-(address-p.p_vaddr)) return true;
        return false;
    }
    bool relativePointer(uint64_t address,uint64_t size,uint64_t& target) const {
        if(size!=8 || !dataRange(address,size)) return false;
        auto it=std::lower_bound(relocations.begin(),relocations.end(),address>7?address-7:0,
            [](const Relocation& r,uint64_t value){return r.address<value;});
        unsigned count=0;bool known=false;
        for(;it!=relocations.end() && it->address<address+size;++it) {
            ++count;
            if(it->address==address && it->known) {known=true;target=it->value;}
        }
        return count==1 && known;
    }
    // Export original non-executable data only. Relocated bytes are deliberately
    // withheld until their source-level referents can be reconstructed.
    std::string initialData(uint64_t address,uint64_t size,std::string& status) const {
        if(size>1048576) {status="size_limit";return {};}
        if(!dataRange(address,size)) {status="not_mapped_data";return {};}
        auto it=std::lower_bound(relocations.begin(),relocations.end(),address>7?address-7:0,
            [](const Relocation& r,uint64_t value){return r.address<value;});
        for(;it!=relocations.end() && it->address<address+size;++it) {
            if(it->address<=address && address-it->address>=8) continue;
            status="relocation_requires_resolution";return {};
        }
        std::ostringstream hex;hex<<std::hex<<std::setfill('0');
        for(const auto& p:segments) if(!(p.p_flags&PF_X) && address>=p.p_vaddr &&
                address-p.p_vaddr<=p.p_memsz && size<=p.p_memsz-(address-p.p_vaddr)) {
            for(uint64_t i=0;i<size;++i) {
                uint64_t off=address-p.p_vaddr+i;
                unsigned value=off<p.p_filesz?data.data()[p.p_offset+off]:0;
                hex<<std::setw(2)<<value;
            }
            status="known";return hex.str();
        }
        status="not_mapped_data";return {};
    }
    bool initialPointer(uint64_t address,uint64_t size,bool pointerType,uint64_t& target) const {
        if(relativePointer(address,size,target)) return true;
        if(!pointerType || size!=8) return false;
        std::string status;auto hex=initialData(address,size,status);
        if(status!="known") return false;
        target=0;
        for(unsigned i=0;i<8;++i) target|=uint64_t(std::stoul(hex.substr(2*i,2),nullptr,16))<<(8*i);
        return target!=0;
    }
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
    // Instruction bytes without relocation tainting; shorter at the end of a segment.
    size_t codeBytes(uint64_t address,uint8_t* out,size_t size) const {
        for(const auto& p:segments) {
            if(!(p.p_flags&PF_X) || address<p.p_vaddr || address-p.p_vaddr>=p.p_filesz) continue;
            size_t count=std::min<uint64_t>(size,p.p_filesz-(address-p.p_vaddr));
            std::memcpy(out,data.data()+p.p_offset+(address-p.p_vaddr),count);
            return count;
        }
        return 0;
    }
    // Bytes of a NUL-terminated read-only string at an address, or empty when none.
    std::string stringAt(uint64_t address,size_t limit) const {
        for(const auto& p:segments) {
            if((p.p_flags&(PF_X|PF_W)) || address<p.p_vaddr || address-p.p_vaddr>=p.p_filesz) continue;
            const char* begin=reinterpret_cast<const char*>(data.data()+p.p_offset+(address-p.p_vaddr));
            size_t room=std::min<uint64_t>(limit,p.p_filesz-(address-p.p_vaddr));
            for(size_t i=0;i<room;++i) {
                unsigned char c=begin[i];
                if(c==0) return i?std::string(begin,i+1):std::string();
                if(!(c>=32&&c<127) && c!='\n' && c!='\t') return {};
            }
            return {};
        }
        return {};
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
static std::string jsonString(const std::string& value) {
    std::ostringstream out;out<<'"';
    for(unsigned char c:value) {
        if(c=='"' || c=='\\') out<<'\\'<<c;
        else if(c<32 || c>=127) out<<"\\u00"<<std::hex<<std::setfill('0')<<std::setw(2)<<unsigned(c);
        else out<<c;
    }
    out<<'"';return out.str();
}
static void exportGlobals(ghidra::Architecture& arch,ghidra::Funcdata& function,MappedElfImage& image,
                          const std::string& functionText,const std::filesystem::path& path) {
    std::unordered_set<std::string> pointerUses;
    std::function<void(ghidra::Varnode*,unsigned)> pointerUse=[&](ghidra::Varnode* value,unsigned depth) {
        using namespace ghidra;
        if(depth>32 || value->isConstant() || value->isAnnotation()) return;
        auto* symbol=value->getHigh()->getSymbol();
        if(symbol && symbol->getScope()->isGlobal()) pointerUses.insert(symbol->getName());
        auto* definition=value->getDef();if(!definition || definition->numInput()==0) return;
        auto op=definition->code();
        if(op==CPUI_COPY || op==CPUI_CAST || op==CPUI_PTRADD || op==CPUI_PTRSUB)
            pointerUse(definition->getIn(0),depth+1);
        else if(op==CPUI_INT_ADD && definition->numInput()==2) {
            if(definition->getIn(0)->isConstant()) pointerUse(definition->getIn(1),depth+1);
            else if(definition->getIn(1)->isConstant()) pointerUse(definition->getIn(0),depth+1);
        }
    };
    for(auto it=function.beginOpAlive();it!=function.endOpAlive();++it) {
        auto* op=*it;
        if((op->code()==ghidra::CPUI_LOAD || op->code()==ghidra::CPUI_STORE) && op->numInput()>1)
            pointerUse(op->getIn(1),0);
        else if((op->code()==ghidra::CPUI_CALLIND || op->code()==ghidra::CPUI_BRANCHIND) && op->numInput()>0)
            pointerUse(op->getIn(0),0);
    }
    std::unordered_set<std::string> identifiers;
    for(size_t i=0;i<functionText.size();) {
        if(std::isalpha(static_cast<unsigned char>(functionText[i])) || functionText[i]=='_') {
            size_t start=i++;
            while(i<functionText.size() && (std::isalnum(static_cast<unsigned char>(functionText[i])) || functionText[i]=='_')) ++i;
            identifiers.insert(functionText.substr(start,i-start));
            // Local ELF symbols such as __PRETTY_FUNCTION__.18 carry a dotted clone suffix.
            size_t dotted=i;
            while(dotted+1<functionText.size() && functionText[dotted]=='.' && std::isalnum(static_cast<unsigned char>(functionText[dotted+1]))) {
                ++dotted;
                while(dotted<functionText.size() && (std::isalnum(static_cast<unsigned char>(functionText[dotted])) || functionText[dotted]=='_')) ++dotted;
                identifiers.insert(functionText.substr(start,dotted-start));
            }
        } else ++i;
    }
    std::ofstream metadata(path);metadata<<"{\"version\":2,\"globals\":[";
    auto scope=arch.symboltab->getGlobalScope();bool first=true;uint64_t exportedBytes=0;
    // Include referenced data objects needed by known relative pointer initializers.
    // This recovers initial state only; writable pointer targets may change later.
    bool changed=true;
    while(changed) {
        changed=false;
        for(auto it=scope->begin();it!=scope->end();++it) {
            auto* entry=*it;auto* symbol=entry->getSymbol();uint64_t target=0;
            if(entry->getAddr().getSpace()!=arch.getDefaultDataSpace() || !identifiers.count(symbol->getName()) ||
               !image.initialPointer(entry->getAddr().getOffset(),entry->getSize(),
                                     symbol->getType()->getMetatype()==ghidra::TYPE_PTR || pointerUses.count(symbol->getName()),target)) continue;
            for(auto jt=scope->begin();jt!=scope->end();++jt) {
                auto* other=*jt;auto* candidate=other->getSymbol();
                if(other->getAddr().getSpace()!=arch.getDefaultDataSpace() || dynamic_cast<ghidra::FunctionSymbol*>(candidate)) continue;
                uint64_t begin=other->getAddr().getOffset();
                if(target>=begin && target-begin<uint64_t(other->getSize()) &&
                   identifiers.insert(candidate->getName()).second) changed=true;
            }
        }
    }
    std::unordered_set<const ghidra::Symbol*> seen;
    for(auto it=scope->begin();it!=scope->end();++it) {
        const auto* entry=*it;auto* symbol=entry->getSymbol();
        if(entry->isPiece() || !identifiers.count(symbol->getName()) || !seen.insert(symbol).second ||
           dynamic_cast<ghidra::FunctionSymbol*>(symbol) || dynamic_cast<ghidra::LabSymbol*>(symbol)) continue;
        if(entry->getAddr().getSpace()!=arch.getDefaultDataSpace()) continue;
        auto* type=symbol->getType();uint64_t address=entry->getAddr().getOffset();
        std::string status,bytes;
        if(type->getSize()<=0 || type->getSize()!=entry->getSize() || entry->getOffset()!=0) status="partial_mapping";
        else if(exportedBytes+uint64_t(type->getSize())>16777216) status="export_budget";
        else {bytes=image.initialData(address,type->getSize(),status);exportedBytes+=bytes.size()/2;}
        std::ostringstream declaration;arch.print->setOutputStream(&declaration);arch.print->docSingleGlobal(symbol);
        if(!first)metadata<<',';first=false;
        uint64_t pointerTarget=0;bool pointerKnown=image.initialPointer(address,entry->getSize(),
            type->getMetatype()==ghidra::TYPE_PTR || pointerUses.count(symbol->getName()),pointerTarget);
        metadata<<"{\"name\":"<<jsonString(symbol->getName())<<",\"address\":"<<address
                <<",\"size\":"<<type->getSize()<<",\"declaration\":"<<jsonString(declaration.str())
                <<",\"type_name\":"<<jsonString(type->getName())<<",\"initial_status\":"<<jsonString(status)
                <<",\"initial_hex\":"<<jsonString(bytes)
                <<",\"pointer_target\":"<<(pointerKnown?std::to_string(pointerTarget):"null")
                <<",\"pointer_target_is_code\":"<<(pointerKnown && image.executableAddress(pointerTarget)?"true":"false")<<'}';
    }
    metadata<<"]}\n";metadata.close();fibers::require(bool(metadata),"Cannot save global metadata");
}
// A varnode that moves when an instruction is decoded at a displaced address was computed from
// the instruction pointer, so it is an address reference rather than an integer.
class RipProvenance {
    struct Window : ghidra::LoadImage {
        uint64_t base=0;uint8_t bytes[16]={};
        Window():LoadImage("instruction window"){}
        void loadFill(ghidra::uint1 *out,ghidra::int4 size,const ghidra::Address& a) override {
            for(int i=0;i<size;++i) {uint64_t off=a.getOffset()+i-base;out[i]=off<16?bytes[off]:0;}
        }
        std::string getArchType() const override{return "x86-64";}
        void adjustVma(long) override{throw ghidra::LowlevelError("VMA adjustment unsupported");}
    };
    struct Capture : ghidra::PcodeEmit {
        std::vector<ghidra::VarnodeData> items;
        void dump(const ghidra::Address&,ghidra::OpCode opcode,ghidra::VarnodeData *out,
                  ghidra::VarnodeData *in,ghidra::int4 count) override {
            calls|=opcode==ghidra::CPUI_CALL || opcode==ghidra::CPUI_CALLIND;
            // A branch destination is a control transfer, not an operand.
            const int first=(opcode==ghidra::CPUI_BRANCH || opcode==ghidra::CPUI_CBRANCH)?1:0;
            if(out) items.push_back(*out);
            for(int i=first;i<count;++i) items.push_back(in[i]);
        }
        bool calls=false;
    };
    static constexpr uint64_t displacement=0x10000000;
    MappedElfImage& image;Window window;ghidra::ContextInternal context;
    ghidra::Sleigh sleigh;ghidra::DocumentStorage documents;
    std::unordered_set<uint64_t> scanned;
    bool decode(uint64_t at,uint64_t base,const uint8_t* bytes,Capture& capture) {
        window.base=base;std::memcpy(window.bytes,bytes,16);
        try {sleigh.oneInstruction(capture,ghidra::Address(sleigh.getDefaultCodeSpace(),at));return true;}
        catch(const ghidra::LowlevelError&) {return false;}
    }
public:
    struct Reference { uint64_t site,target;bool constant; };
    std::vector<Reference> references;
    std::unordered_set<uint64_t> constants;
    bool isTarget(uint64_t value) const { return constants.count(value)!=0; }
    RipProvenance(MappedElfImage& img,const std::string& sla):image(img),sleigh(&window,&context) {
        std::string escaped;
        for(char ch:sla) escaped+=ch=='&'?"&amp;":ch=='<'?"&lt;":std::string(1,ch);
        std::istringstream xml("<sleigh>"+escaped+"</sleigh>");
        auto *root=documents.parseDocument(xml)->getRoot();documents.registerTag(root);
        sleigh.initialize(documents);
        context.setVariableDefault("addrsize",2);context.setVariableDefault("opsize",1);
        context.setVariableDefault("rexprefix",0);context.setVariableDefault("longMode",1);
    }
    void scan(uint64_t site) {
        if(!scanned.insert(site).second) return;
        uint8_t bytes[16]={};
        if(image.codeBytes(site,bytes,16)==0) return;
        Capture here,moved;
        if(!decode(site,site,bytes,here) || !decode(site+displacement,site+displacement,bytes,moved)) return;
        // Calls push their own return address; that is not a reference to data or code.
        if(here.calls || here.items.size()!=moved.items.size()) return;
        for(size_t i=0;i<here.items.size();++i) {
            const auto &a=here.items[i],&b=moved.items[i];
            const bool constant=a.space->getType()==ghidra::IPTR_CONSTANT;
            if(a.space!=b.space || a.size!=b.size || a.size<4 || a.size>8 || (!constant && a.space!=sleigh.getDefaultDataSpace())) continue;
            const uint64_t mask=a.size==8?~uint64_t(0):((uint64_t(1)<<(8*a.size))-1);
            if(((b.offset-a.offset)&mask)!=displacement) continue;
            references.push_back({site,a.offset,constant});
            if(constant) constants.insert(a.offset&mask);
        }
    }
};
class StaticElfArchitecture : public ghidra::SleighArchitecture {
    std::string sla;
    std::set<uint64_t> defined;
    void buildLoader(ghidra::DocumentStorage&) override {
        collectSpecFiles(std::cerr);loader=new MappedElfImage(getFilename());
    }
    void postSpecFile() override {
        ghidra::Architecture::postSpecFile();
        auto* image=static_cast<MappedElfImage*>(loader);
        image->attach(getDefaultCodeSpace());
        provenance=std::make_unique<RipProvenance>(*image,sla);
    }
    // Strings become char arrays and other data a byte array up to the next object or target,
    // so the decompiler's own pointer inference resolves constants there to references.
    void defineTargets(const std::set<uint64_t>& targets) {
        auto* image=static_cast<MappedElfImage*>(loader);
        auto* scope=symboltab->getGlobalScope();
        uint64_t covered=0;
        for(auto it=targets.begin();it!=targets.end();++it) {
            const uint64_t target=*it;
            ghidra::Address where(getDefaultDataSpace(),target);
            auto* existing=scope->findContainer(where,1,ghidra::Address());
            if(!image->dataRange(target,1) || !defined.insert(target).second ||
               (existing && existing->getAddr()==where)) continue;
            std::string text=image->stringAt(target,4096);
            uint64_t size;ghidra::Datatype* type;
            if(!text.empty()) {size=text.size();type=types->getTypeArray(size,types->getTypeChar(1));covered=target+size;}
            else {
                auto next=std::upper_bound(objectStarts.begin(),objectStarts.end(),target);
                size=std::min<uint64_t>(next==objectStarts.end()?4096:*next-target,4096);
                auto following=std::next(it);
                if(following!=targets.end()) size=std::min<uint64_t>(size,*following-target);
                while(size>1 && !image->dataRange(target,size)) --size;
                type=size==1?types->getBase(1,ghidra::TYPE_UNKNOWN):
                    types->getTypeArray(size,types->getBase(1,ghidra::TYPE_UNKNOWN));
            }
            std::ostringstream name;name<<(text.empty()?"__recovery_object_":"__recovery_string_")<<std::hex<<target;
            scope->addSymbol(name.str(),type,where,ghidra::Address());
        }
    }
    bool isMappedAddress(ghidra::uintb value) const override {
        return static_cast<MappedElfImage*>(loader)->inSection(value);
    }
    bool isAddressConstant(ghidra::uintb value) const override {
        return provenance->isTarget(value);
    }
    void flowTraced(ghidra::Funcdata& fd) override {
        std::set<uint64_t> sites;
        for(auto it=fd.beginOpAlive();it!=fd.endOpAlive();++it) sites.insert((*it)->getAddr().getOffset());
        const size_t before=provenance->references.size();
        for(auto site:sites) provenance->scan(site);
        std::set<uint64_t> targets;
        for(size_t i=before;i<provenance->references.size();++i)
            if(provenance->references[i].constant) targets.insert(provenance->references[i].target);
        defineTargets(targets);
    }
public:
    std::vector<uint64_t> objectStarts;
    std::unique_ptr<RipProvenance> provenance;
    StaticElfArchitecture(const std::string& file,const std::string& specs)
        :SleighArchitecture(file,"x86:LE:64:default:gcc",&std::cerr),
         sla(std::filesystem::absolute(std::filesystem::path(specs)/"x86-64.sla").string()) {}
};
// Encode only fully described primitive and pointer types. Unknown and
// aggregate types are explicitly unsupported for prototype seeding.
static std::string describePrototypeType(const ghidra::Datatype *type, int depth = 0) {
    if (type == nullptr || depth > 8) return "unsupported";
    const auto meta = type->getMetatype();
    if (meta == ghidra::TYPE_PTR) {
        const auto *pointer = dynamic_cast<const ghidra::TypePointer *>(type);
        if (pointer == nullptr) return "unsupported";
        const auto child = describePrototypeType(pointer->getPtrTo(), depth + 1);
        if (child == "unsupported") return child;
        return "p" + std::to_string(type->getSize()) + "_" + child;
    }
    if (meta != ghidra::TYPE_VOID && meta != ghidra::TYPE_INT &&
        meta != ghidra::TYPE_UINT && meta != ghidra::TYPE_BOOL &&
        meta != ghidra::TYPE_FLOAT && meta != ghidra::TYPE_UNKNOWN) return "unsupported";
    return "b" + std::to_string(static_cast<int>(meta)) + "_" +
        std::to_string(type->getSize());
}

// Join pieces as space:offset:size, most significant first, since join offsets are per-run ids.
static std::string joinPieces(const ghidra::Address &address) {
    const auto *record = address.getSpace()->findJoin(address.getOffset());
    if (record == nullptr) return "";
    std::ostringstream text;
    for (int i = 0; i < record->numPieces(); ++i) {
        const auto &piece = record->getPiece(i);
        text << (i ? "," : "") << piece.space->getName() << ':' << std::hex << piece.offset
             << std::dec << ':' << piece.size;
    }
    return text.str();
}

// Stack words read above the return address form one by-value struct argument.
struct StackArg { uint64_t offset; int size; std::string type; };

// A field keeps pointer-ness: function pointers are p8_c0_0, other opaque pointers void *.
static std::string stackFieldType(const ghidra::Datatype *type) {
    std::string text = describePrototypeType(type);
    if (text != "unsupported") return text;
    if (type->getMetatype() == ghidra::TYPE_PTR && type->getSize() == 8) {
        const auto *to = static_cast<const ghidra::TypePointer *>(type)->getPtrTo();
        return to->getMetatype() == ghidra::TYPE_CODE ? "p8_c0_0" : "p8_b17_0";
    }
    return "b15_" + std::to_string(type->getSize());
}

static bool isStackArgs(const ghidra::Datatype *type) {
    const std::string &name = type->getName();
    return type->getMetatype() == ghidra::TYPE_STRUCT && name.size() > 10 &&
           name.compare(name.size() - 10, 10, "_stackargs") == 0;
}

// Stack offset 8 is the first word above the return address.
static std::vector<StackArg> discoverStackArgs(ghidra::Funcdata &fd) {
    std::vector<StackArg> found;
    // A cold fragment runs in its parent's frame, so its stack words are not arguments.
    const std::string &name = fd.getName();
    if (name.find("cold") != std::string::npos) return found;
    // Words the decompiler already made parameters are not left over.
    const auto &proto = fd.getFuncProto();
    for (int i = 0; i < proto.numParams(); ++i) {
        auto address = proto.getParam(i)->getAddress();
        if (!address.isInvalid() && address.getSpace()->getType() == ghidra::IPTR_SPACEBASE) return found;
    }
    for (auto it = fd.beginDef(ghidra::Varnode::input); it != fd.endDef(ghidra::Varnode::input); ++it) {
        auto *vn = *it;
        if (vn->getSpace()->getType() != ghidra::IPTR_SPACEBASE || vn->getOffset() < 8 ||
            vn->getOffset() >= 8 + 512) continue;
        if (vn->getSize() < 1 || vn->getSize() > 16) return {};
        std::string type = stackFieldType(vn->getType());
        found.push_back({vn->getOffset(), vn->getSize(), type});
    }
    std::sort(found.begin(), found.end(), [](const StackArg &a, const StackArg &b) {
        return a.offset != b.offset ? a.offset < b.offset : a.size > b.size; });
    std::vector<StackArg> fields;
    for (const auto &arg : found) {
        if (!fields.empty() && arg.offset < fields.back().offset + fields.back().size) {
            if (arg.offset + arg.size > fields.back().offset + fields.back().size) return {};
            continue;	// contained in a wider word
        }
        fields.push_back(arg);
    }
    // Callers store whole words, so a narrow field owns the rest of its slot when free.
    for (size_t i = 0; i < fields.size(); ++i) {
        auto &field = fields[i];
        if (field.size >= 8 || field.offset % 8 != 0) continue;
        if (i + 1 == fields.size() || fields[i + 1].offset >= field.offset + 8) {
            field.size = 8;
            field.type = "b15_8";
        }
    }
    return fields;
}

static std::vector<StackArg> structStackArgs(const ghidra::Datatype *type) {
    std::vector<StackArg> fields;
    const auto *record = dynamic_cast<const ghidra::TypeStruct *>(type);
    if (record == nullptr) return fields;
    for (auto it = record->beginField(); it != record->endField(); ++it) {
        std::string text = stackFieldType(it->type);
        fields.push_back({uint64_t(it->offset) + 8, it->type->getSize(), text});
    }
    return fields;
}

// Record the decompiler's inferred machine storage without claiming that it is
// an authoritative source signature. Each decompilation has its own context.
static void exportPrototype(std::ostream &out, const std::string &kind,
                            uint64_t site, uint64_t target,
                            const ghidra::FuncProto &proto,
                            const std::vector<StackArg> *discovered = nullptr,
                            const ghidra::PcodeOp *callOp = nullptr) {
    // The stack struct is reported apart from the register parameters.
    int stackIndex = -1;
    for (int i = 0; i < proto.numParams(); ++i)
        if (proto.getParam(i)->getType() && isStackArgs(proto.getParam(i)->getType())) stackIndex = i;
    out << kind << '\t' << std::hex << site << '\t' << target << std::dec
        << '\t' << (proto.hasModel() ? proto.getModelName() : "unknown")
        << '\t' << proto.isDotdotdot() << '\t' << proto.hasCustomStorage()
        << '\t' << proto.numParams() - (stackIndex >= 0) << "\n";
    auto writeParameter = [&](const char *role, int index, ghidra::ProtoParameter *param) {
        if (param == nullptr || param->getType() == nullptr) return;
        auto address = param->getAddress();
        out << "parameter\t" << role << '\t' << index << '\t'
            << (address.isInvalid() ? "invalid" : address.getSpace()->getName())
            << '\t' << std::hex << (address.isInvalid() ? 0 : address.getOffset())
            << std::dec << '\t' << param->getSize() << '\t'
            << static_cast<int>(param->getType()->getMetatype()) << '\t'
            << param->isTypeLocked() << '\t'
            << describePrototypeType(param->getType());
        if (!address.isInvalid() && address.getSpace()->getType() == ghidra::IPTR_JOIN)
            out << '\t' << joinPieces(address);
        out << "\n";
    };
    auto *result = callOp ? callOp->getOut() : nullptr;
    if (result != nullptr && result->getSpace()->getType() == ghidra::IPTR_PROCESSOR &&
        (proto.getOutput() == nullptr || proto.getOutput()->getAddress().isInvalid())) {
        // An unlocked callee: report the width the caller actually reads.
        out << "parameter\toutput\t-1\t" << result->getSpace()->getName() << '\t' << std::hex
            << result->getOffset() << std::dec << '\t' << result->getSize() << '\t'
            << static_cast<int>(result->getType()->getMetatype()) << "\t0\t"
            << describePrototypeType(result->getType()) << "\n";
    }
    else writeParameter("output", -1, proto.getOutput());
    for (int i = 0; i < proto.numParams(); ++i)
        if (i != stackIndex) writeParameter("input", i, proto.getParam(i));
    std::vector<StackArg> fields;
    std::string name = "-";
    int total = 0;
    if (stackIndex >= 0) {
        auto *type = proto.getParam(stackIndex)->getType();
        fields = structStackArgs(type);
        name = type->getName();
        total = type->getSize();
    } else if (discovered != nullptr && !discovered->empty()) {
        fields = *discovered;
        total = int((fields.back().offset + fields.back().size - 8 + 7) & ~uint64_t(7));
        if (total < 24) total = 24;	// over 16 bytes the struct is passed in memory
    }
    if (fields.empty()) return;
    out << "stackargs\t" << name << '\t' << std::hex << total << std::dec << "\n";
    for (const auto &field : fields)
        out << "stackarg\t" << std::hex << field.offset << '\t' << std::dec << field.size
            << '\t' << field.type << "\n";
}

struct SeedStorage {
    ghidra::Datatype *type;
    std::string space;
    uint64_t offset;
    int size;
    std::string pieces;
};

static ghidra::Datatype *parseSeedType(ghidra::Architecture &arch,
                                      const std::string &text, size_t &pos,
                                      int depth = 0) {
    if (depth > 8 || pos >= text.size()) throw std::runtime_error("type depth");
    char kind = text[pos++];
    size_t start = pos;
    if (kind == 'c') {	// c0_0: code
        if (text.compare(pos, 3, "0_0") != 0) throw std::runtime_error("invalid type descriptor");
        pos += 3;
        return arch.types->getTypeCode();
    }
    while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) ++pos;
    if (pos == start || pos >= text.size() || text[pos++] != '_')
        throw std::runtime_error("invalid type descriptor");
    int number = std::stoi(text.substr(start, pos - start - 1));
    if (kind == 'p') {
        if (number != 8) throw std::runtime_error("unsupported pointer size");
        return arch.types->getTypePointer(number, parseSeedType(arch, text, pos, depth + 1), 1);
    }
    if (kind != 'b') throw std::runtime_error("unknown type descriptor");
    start = pos;
    while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) ++pos;
    if (pos == start) throw std::runtime_error("missing type size");
    int size = std::stoi(text.substr(start, pos - start));
    auto meta = static_cast<ghidra::type_metatype>(number);
    if (meta == ghidra::TYPE_VOID && size == 0) return arch.types->getTypeVoid();
    if ((meta == ghidra::TYPE_BOOL && size != 1) ||
        (meta == ghidra::TYPE_FLOAT && size != 4 && size != 8 && size != 10 && size != 16))
        throw std::runtime_error("unsupported primitive size");
    if (size < 1 || size > 16 ||
        (meta != ghidra::TYPE_UNKNOWN && meta != ghidra::TYPE_INT &&
         meta != ghidra::TYPE_UINT && meta != ghidra::TYPE_BOOL && meta != ghidra::TYPE_FLOAT))
        throw std::runtime_error("unsupported primitive");
    return arch.types->getBase(size, meta);
}

static SeedStorage parseSeedStorage(ghidra::Architecture &arch, std::string field) {
    std::string pieces;
    if (auto slash = field.find('/'); slash != std::string::npos) {
        pieces = field.substr(slash + 1);
        field.resize(slash);
    }
    auto at = field.find('@');
    if (at == std::string::npos) throw std::runtime_error("invalid storage descriptor");
    auto first = field.find(':', at);
    if (first == std::string::npos) throw std::runtime_error("invalid storage descriptor");
    auto second = field.find(':', first + 1);
    if (second == std::string::npos)
        throw std::runtime_error("invalid storage descriptor");
    size_t pos = 0;
    auto *type = parseSeedType(arch, field.substr(0, at), pos);
    if (pos != at) throw std::runtime_error("trailing type descriptor");
    std::string space = field.substr(at + 1, first - at - 1);
    const auto offsetText = field.substr(first + 1, second - first - 1);
    const auto sizeText = field.substr(second + 1);
    size_t consumed = 0;
    auto offset = std::stoull(offsetText, &consumed, 16);
    if (consumed != offsetText.size()) throw std::runtime_error("invalid offset");
    int size = std::stoi(sizeText, &consumed);
    if (consumed != sizeText.size()) throw std::runtime_error("invalid size");
    if (size != type->getSize()) throw std::runtime_error("storage size mismatch");
    if ((space == "join") == pieces.empty()) throw std::runtime_error("join pieces mismatch");
    return {type, space, offset, size, pieces};
}

static void applyPrototypeSeeds(StaticElfArchitecture &arch, ghidra::Scope *scope,
                                uint64_t selected, const std::string &path,
                                const std::filesystem::path &output,
                                const std::unordered_set<uint64_t> &imports) {
    std::ifstream input(path);
    fibers::require(bool(input), "Cannot open prototype seed manifest");
    std::ofstream results(output / "prototype-seeds-result.tsv");
    std::string line;
    size_t rows = 0;
    while (std::getline(input, line)) {
        fibers::require(++rows <= 100000 && line.size() <= 16384, "Prototype manifest too large");
        std::string rowTarget = "-";
        try {
            std::istringstream stream(line);
            std::string field;
            std::vector<std::string> fields;
            while (std::getline(stream, field, '\t')) fields.push_back(field);
            if (fields.size() < 3 || fields.size() > 67) throw std::runtime_error("invalid row");
            rowTarget = fields[0];
            size_t consumed = 0;
            uint64_t target = std::stoull(fields[0], &consumed, 16);
            if (consumed != fields[0].size()) throw std::runtime_error("invalid target");
            auto *image = static_cast<MappedElfImage *>(arch.loader);
            if (!image->executableAddress(target)) throw std::runtime_error("non-executable target");
            if (imports.count(target)) throw std::runtime_error("import prototype is fixed");
            auto *model = arch.getModel(fields[1]);
            if (model == nullptr || model->isUnknown()) throw std::runtime_error("unknown model");
            std::vector<SeedStorage> expected;
            bool noReturn = false;
            std::string stackSeed;
            for (size_t i = 2; i < fields.size(); ++i) {
                if (fields[i] == "noreturn") noReturn = true;
                else if (fields[i].compare(0, 6, "stack=") == 0) stackSeed = fields[i].substr(6);
                else expected.push_back(parseSeedStorage(arch, fields[i]));
            }
            if (expected.empty()) throw std::runtime_error("invalid row");
            ghidra::PrototypePieces pieces;
            pieces.model = model;
            pieces.outtype = expected[0].type;
            pieces.firstVarArgSlot = -1;
            for (size_t i = 1; i < expected.size(); ++i) {
                pieces.intypes.push_back(expected[i].type);
                pieces.innames.push_back("");
            }
            int stackSize = 0;
            if (!stackSeed.empty()) {
                // stack=NAME;SIZE;OFFSET.SIZE.TYPE;...  with offsets from 8
                std::vector<std::string> parts;
                std::istringstream text(stackSeed);
                std::string part;
                while (std::getline(text, part, ';')) parts.push_back(part);
                if (parts.size() < 3 || parts[0].size() < 11) throw std::runtime_error("invalid stack seed");
                stackSize = std::stoi(parts[1], nullptr, 16);
                if (stackSize <= 16 || stackSize > 4096 || stackSize % 8) throw std::runtime_error("invalid stack size");
                std::vector<ghidra::TypeField> members;
                uint64_t end = 0;
                for (size_t i = 2; i < parts.size(); ++i) {
                    auto dot = parts[i].find('.');
                    auto dot2 = parts[i].find('.', dot + 1);
                    if (dot == std::string::npos || dot2 == std::string::npos) throw std::runtime_error("invalid stack field");
                    uint64_t offset = std::stoull(parts[i].substr(0, dot), nullptr, 16);
                    int size = std::stoi(parts[i].substr(dot + 1, dot2 - dot - 1));
                    size_t pos = 0;
                    std::string descriptor = parts[i].substr(dot2 + 1);
                    auto *type = parseSeedType(arch, descriptor, pos);
                    if (pos != descriptor.size() || type->getSize() != size || offset < 8 ||
                        offset - 8 < end || offset - 8 + size > uint64_t(stackSize))
                        throw std::runtime_error("invalid stack field");
                    end = offset - 8 + size;
                    members.emplace_back(int(i), int(offset - 8), "f_" + parts[i].substr(0, dot), type);
                }
                auto *record = arch.types->getTypeStruct(parts[0]);
                arch.types->setStructFields(members, record, stackSize, 8);
                pieces.intypes.push_back(record);
                pieces.innames.push_back("");
            }
            std::vector<ghidra::ParameterPieces> assigned;
            model->assignParameterStorage(pieces, assigned, false);
            if (stackSize) {
                if (assigned.size() != expected.size() + 1) throw std::runtime_error("implicit parameters");
                const auto last = assigned.back().addr;
                if (last.isInvalid() || last.getSpace()->getName() != "stack" || last.getOffset() != 8)
                    throw std::runtime_error("ABI storage mismatch");
                assigned.pop_back();
            }
            if (assigned.size() != expected.size()) throw std::runtime_error("implicit parameters");
            for (size_t i = 0; i < assigned.size(); ++i) {
                const auto address = assigned[i].addr;
                const std::string space = address.isInvalid() ? "invalid" : address.getSpace()->getName();
                const uint64_t offset = address.isInvalid() ? 0 : address.getOffset();
                // Join offsets are per-run ids, so joins compare by their ordered pieces.
                const bool join = space == "join" && expected[i].space == "join";
                if (join ? joinPieces(address) != expected[i].pieces : false)
                    throw std::runtime_error("ABI storage mismatch");
                if (space != expected[i].space || (!join && offset != expected[i].offset) ||
                    assigned[i].type->getSize() != expected[i].size || assigned[i].flags != 0)
                    throw std::runtime_error("ABI storage mismatch");
            }
            ghidra::Address address(arch.getDefaultCodeSpace(), target);
            auto *fd = scope->queryFunction(address);
            if (fd == nullptr) {
                scope->addFunction(address, "__recovered_" + fields[0]);
                fd = scope->queryFunction(address);
            }
            if (fd == nullptr) throw std::runtime_error("cannot create function");
            fd->getFuncProto().setPieces(pieces);
            if (noReturn) fd->getFuncProto().setNoReturn(true);
            results << fields[0] << "\tapplied\n";
        } catch (const std::exception &error) {
            results << rowTarget << "\trejected\t" << error.what() << "\n";
        } catch (const ghidra::LowlevelError &error) {
            results << rowTarget << "\trejected\t" << error.explain << "\n";
        }
    }
    results.flush();
    fibers::require(bool(results), "Cannot save seed results");
}

// Standard C library signatures as return type, parameter types, and "..." for varargs.
// Codes: v void, i int, u unsigned, l long, z size_t, p void *, s char *, d double,
// pN pointer to an N byte output buffer (such as struct stat).
static const std::unordered_map<std::string, std::string> &importSignatures() {
    static const std::unordered_map<std::string, std::string> table = {
        {"printf", "i s ..."}, {"__printf_chk", "i i s ..."}, {"fprintf", "i p s ..."},
        {"__fprintf_chk", "i p i s ..."}, {"sprintf", "i s s ..."}, {"snprintf", "i s z s ..."},
        {"__sprintf_chk", "i s i z s ..."}, {"__snprintf_chk", "i s z i z s ..."},
        {"scanf", "i s ..."}, {"sscanf", "i s s ..."}, {"__isoc99_sscanf", "i s s ..."},
        {"__isoc99_scanf", "i s ..."}, {"open", "i s i ..."}, {"open64", "i s i ..."},
        {"puts", "i s"}, {"putchar", "i i"}, {"fputs", "i s p"}, {"fputc", "i i p"},
        {"fwrite", "z p z z p"}, {"fread", "z p z z p"}, {"fopen", "p s s"}, {"fopen64", "p s s"},
        {"fclose", "i p"}, {"fflush", "i p"}, {"fileno", "i p"}, {"malloc", "p z"},
        {"calloc", "p z z"}, {"realloc", "p p z"}, {"free", "v p"}, {"memcpy", "p p p z"},
        {"__memcpy_chk", "p p p z z"}, {"memmove", "p p p z"}, {"memset", "p p i z"},
        {"memcmp", "i p p z"}, {"strlen", "z s"}, {"strcmp", "i s s"}, {"strncmp", "i s s z"},
        {"strcpy", "s s s"}, {"strncpy", "s s s z"}, {"strchr", "s s i"}, {"strrchr", "s s i"},
        {"strdup", "s s"}, {"strerror", "s i"}, {"atoi", "i s"}, {"strtol", "l s p i"},
        {"strtoul", "z s p i"}, {"getenv", "s s"}, {"close", "i i"}, {"read", "l i p z"},
        {"write", "l i p z"}, {"__errno_location", "p"}, {"exit", "v i"}, {"_exit", "v i"},
        {"abort", "v"}, {"__stack_chk_fail", "v"}, {"__cxa_finalize", "v p"},
        {"qsort", "v p z z p"}, {"time", "l p"}, {"clock_gettime", "i i p"},
        {"stat", "i s p144"}, {"stat64", "i s p144"}, {"lstat", "i s p144"}, {"lstat64", "i s p144"},
        {"fstat", "i i p144"}, {"fstat64", "i i p144"}, {"sqrt", "d d"},
        {"sysconf", "l i"}, {"clock", "l"}, {"isatty", "i i"}, {"raise", "i i"}, {"perror", "v s"},
        {"fgets", "s s i p"}, {"getc", "i p"}, {"ftell", "l p"}, {"fseek", "i p l i"},
        {"feof", "i p"}, {"ferror", "i p"}, {"setvbuf", "i p s i z"}, {"remove", "i s"},
        {"chmod", "i s u"}, {"fchmod", "i i u"}, {"chown", "i s u u"}, {"fchown", "i i u u"},
        {"mkdir", "i s u"}, {"opendir", "p s"}, {"readdir", "p p"}, {"closedir", "i p"},
        {"mmap", "p p z i i i l"}, {"munmap", "i p z"}, {"setpriority", "i i u i"},
        {"backtrace", "i p i"}, {"backtrace_symbols", "p p i"}, {"fdopen", "p i s"},
        {"strstr", "s s s"}, {"__isoc23_strtol", "l s p i"},
        {"pthread_mutex_lock", "i p"}, {"pthread_mutex_unlock", "i p"},
        {"pthread_mutex_destroy", "i p"}, {"pthread_cond_signal", "i p"},
        {"pthread_cond_broadcast", "i p"}, {"pthread_cond_destroy", "i p"},
        {"pthread_mutex_init", "i p p"}, {"pthread_cond_init", "i p p"},
        {"pthread_cond_wait", "i p p"}, {"pthread_create", "i p p p p"}, {"pthread_join", "i z p"}};
    return table;
}

static ghidra::Datatype *importType(ghidra::Architecture &arch, const std::string &token) {
    auto *types = arch.types;
    if (token.size() > 1 && token[0] == 'p') {
        auto *bytes = types->getBase(1, ghidra::TYPE_UNKNOWN);
        return types->getTypePointer(8, types->getTypeArray(std::stoi(token.substr(1)), bytes), 1);
    }
    switch (token[0]) {
    case 'v': return types->getTypeVoid();
    case 'i': return types->getBase(4, ghidra::TYPE_INT);
    case 'u': return types->getBase(4, ghidra::TYPE_UINT);
    case 'l': return types->getBase(8, ghidra::TYPE_INT);
    case 'z': return types->getBase(8, ghidra::TYPE_UINT);
    case 'p': return types->getTypePointer(8, types->getTypeVoid(), 1);
    case 's': return types->getTypePointer(8, types->getTypeChar(1), 1);
    case 'd': return types->getBase(8, ghidra::TYPE_FLOAT);
    }
    throw std::runtime_error("unknown import type code");
}

// Without these, calls to imports such as printf lose their arguments in the pseudocode.
static std::unordered_set<uint64_t> applyImportPrototypes(
    StaticElfArchitecture &arch, ghidra::Scope *scope, const fibers::Elf &elf,
    std::unordered_set<uint64_t> &added, uint64_t selectedAddress) {
    std::unordered_set<uint64_t> applied;
    auto apply = [&](const std::string &name, uint64_t address) {
        const auto found = importSignatures().find(name);
        if (address == selectedAddress || found == importSignatures().end())
            return;
        const ghidra::Address entry(arch.getDefaultCodeSpace(), address);
        if (added.insert(address).second)
            scope->addFunction(entry, name);
        auto *function = scope->queryFunction(entry);
        if (function == nullptr)
            return;
        std::istringstream codes(found->second);
        std::string code;
        ghidra::PrototypePieces pieces;
        pieces.model = arch.defaultfp;
        pieces.firstVarArgSlot = -1;
        codes >> code;
        pieces.outtype = importType(arch, code);
        while (codes >> code) {
            if (code == "...") {
                pieces.firstVarArgSlot = static_cast<int>(pieces.intypes.size());
                break;
            }
            pieces.intypes.push_back(importType(arch, code));
            pieces.innames.push_back("");
        }
        function->getFuncProto().setPieces(pieces);
        applied.insert(address);
    };
    for (const auto &symbol : elf.functions())
        apply(symbol.name, symbol.address);
    for (const auto &stub : elf.pltStubs())
        apply(stub.name, stub.address);
    return applied;
}

// Without noreturn knowledge, flow after a call such as __stack_chk_fail runs into the
// next function in memory and merges unrelated functions into one.
static void markNoReturnCallees(StaticElfArchitecture &arch, ghidra::Scope *scope,
                                const fibers::Elf &elf, std::unordered_set<uint64_t> &added,
                                uint64_t selectedAddress) {
    static const std::unordered_set<std::string> noReturn = {
        "__stack_chk_fail", "__chk_fail", "__fortify_fail", "__assert_fail", "__assert_perror_fail",
        "__assert", "abort", "exit", "_exit", "_Exit", "quick_exit", "pthread_exit", "longjmp",
        "_longjmp", "siglongjmp", "__longjmp_chk", "__cxa_throw", "__cxa_rethrow", "__cxa_bad_cast",
        "__cxa_bad_typeid", "__cxa_throw_bad_array_new_length", "__libc_fatal", "err", "errx",
        "verr", "verrx", "_ZSt9terminatev"};
    auto mark = [&](const std::string &name, uint64_t address) {
        if (address == selectedAddress || !noReturn.count(name))
            return;
        const ghidra::Address entry(arch.getDefaultCodeSpace(), address);
        if (added.insert(address).second)
            scope->addFunction(entry, name);
        if (auto *function = scope->queryFunction(entry))
            function->getFuncProto().setNoReturn(true);
    };
    for (const auto &symbol : elf.functions())
        mark(symbol.name, symbol.address);
    for (const auto &stub : elf.pltStubs())
        mark(stub.name, stub.address);
}

int main(int argc,char **argv) {
    try {
        fibers::require(argc==5 || argc==6,"Usage: core-decompile BINARY SPEC_DIRECTORY SYMBOL OUTPUT [SEEDS]");
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
        StaticElfArchitecture arch(argv[1],argv[2]);ghidra::DocumentStorage store;arch.init(store);
        // ELF symbols give no body bounds, so a jump to another symbol is a tail call.
        arch.branch_entry_tailcall=true;
        MappedElfImage* image=static_cast<MappedElfImage*>(arch.loader);
        fibers::require(image->executableAddress(selectedAddress),"Selected address is not file-backed executable code");
        auto scope=arch.symboltab->getGlobalScope();std::unordered_set<uint64_t> added;
        for(const auto& symbol:elf.functions())if(added.insert(symbol.address).second)
            scope->addFunction(ghidra::Address(arch.getDefaultCodeSpace(),symbol.address),symbol.name);
        const auto imports = applyImportPrototypes(arch, scope, elf, added, selectedAddress);
        markNoReturnCallees(arch, scope, elf, added, selectedAddress);
        std::unordered_set<uint64_t> dataAddresses;
        for(const auto& symbol:elf.objects()) {
            arch.objectStarts.push_back(symbol.address);
            if(symbol.size>1048576 || !image->dataRange(symbol.address,symbol.size) ||
               !dataAddresses.insert(symbol.address).second) continue;
            bool word=symbol.size==1 || symbol.size==2 || symbol.size==4 || symbol.size==8 || symbol.size==16;
            auto* type=word?arch.types->getBase(symbol.size,ghidra::TYPE_UNKNOWN):
                arch.types->getTypeArray(symbol.size,arch.types->getBase(1,ghidra::TYPE_UNKNOWN));
            scope->addSymbol(symbol.name,type,ghidra::Address(arch.getDefaultDataSpace(),symbol.address),ghidra::Address());
        }
        std::sort(arch.objectStarts.begin(),arch.objectStarts.end());
        ghidra::Address selected(arch.getDefaultCodeSpace(),selectedAddress);
        if(added.insert(selectedAddress).second) {
            std::ostringstream name;name<<"__recovered_"<<std::hex<<selectedAddress;
            scope->addFunction(selected,name.str());
        }
        std::filesystem::create_directories(argv[4]);
        if (argc == 6) applyPrototypeSeeds(arch, scope, selectedAddress, argv[5], argv[4], imports);
        auto fd=scope->queryFunction(selected);
        fibers::require(fd!=nullptr,"Cannot create selected function");
        auto action=arch.allacts.getCurrent();auto peel=action->getSubRule("peel_multi_region");
        fibers::require(peel!=nullptr,"Updated peel_multi_region pass is absent from the action pool");
        action->reset(*fd);int result=action->perform(*fd);
        fibers::require(result>=0,"Decompilation stopped before completion");
        std::filesystem::create_directories(argv[4]);
        std::ostringstream functionText;arch.print->setOutputStream(&functionText);arch.print->docFunction(fd);
        std::ofstream out(std::filesystem::path(argv[4])/"decompiled.c");out<<functionText.str();out.flush();
        fibers::require(bool(out),"Cannot save pseudocode");
        exportGlobals(arch,*fd,*image,functionText.str(),std::filesystem::path(argv[4])/"globals.json");
        arch.print->setOutputStream(&out);
        // Export only addresses the decompiler actually resolved; the frontend
        // decides whether the image's relocation state permits using them.
        std::ofstream prototypes(std::filesystem::path(argv[4]) / "prototype-evidence.tsv");
        const auto stackArgs = discoverStackArgs(*fd);
        exportPrototype(prototypes, "function", selectedAddress, selectedAddress,
                        fd->getFuncProto(), &stackArgs);
        for (int i = 0; i < fd->numCalls(); ++i) {
            auto call = fd->getCallSpecs(i);
            auto op = call->getOp();
            auto target = call->getEntryAddress();
            if (op == nullptr) continue;
            const bool resolved = !target.isInvalid() &&
                target.getSpace() == arch.getDefaultCodeSpace();
            exportPrototype(prototypes, resolved ? "call" : "indirect",
                            op->getAddr().getOffset(),
                            resolved ? target.getOffset() : 0, *call, nullptr, op);
        }
        prototypes.flush();
        fibers::require(bool(prototypes), "Cannot save prototype evidence");
        // Operands computed from the instruction pointer, with the decoder's own account of them.
        std::ofstream rip(std::filesystem::path(argv[4])/"rip-references.tsv");
        rip << "site\ttarget\tkind\tregion\n";
        for(const auto& reference:arch.provenance->references)
            rip << std::hex << reference.site << "\t" << reference.target << "\t"
                << (reference.constant?"address":"memory") << "\t"
                << (image->executableAddress(reference.target)?"code":image->dataRange(reference.target,1)?"data":"other") << "\n";
        rip.close(); fibers::require(bool(rip),"Cannot save RIP references");
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
        // Proven only when the finished flow has blocks, no real RETURN (halts are not returns),
        // and no unresolved indirect jump.
        bool noReturn = fd->getBasicBlocks().getSize() > 0 &&
            fd->beginOp(ghidra::CPUI_BRANCHIND) == fd->endOp(ghidra::CPUI_BRANCHIND);
        for (auto it = fd->beginOp(ghidra::CPUI_RETURN); it != fd->endOp(ghidra::CPUI_RETURN); ++it)
            if (((*it)->getHaltType() & (ghidra::PcodeOp::halt | ghidra::PcodeOp::noreturn)) == 0) noReturn = false;
        quality << "noreturn\t" << (noReturn?1:0) << "\n";
        quality.close(); fibers::require(bool(quality),"Cannot save quality data");
        std::cout<<"pseudocode_emitted; peel_tests="<<peel->getNumTests()
                 <<"; peel_applications="<<peel->getNumApply()<<'\n';
        // Printing is heuristic decompilation, not a semantic or byte-roundtrip proof.
        return 0;
    }catch(const ghidra::LowlevelError& e){std::cerr<<e.explain<<'\n';}
     catch(const std::exception& e){std::cerr<<e.what()<<'\n';}
    return 1;
}
