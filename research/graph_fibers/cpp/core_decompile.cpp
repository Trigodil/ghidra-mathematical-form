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

// Record the decompiler's inferred machine storage without claiming that it is
// an authoritative source signature. Each decompilation has its own context.
static void exportPrototype(std::ostream &out, const std::string &kind,
                            uint64_t site, uint64_t target,
                            const ghidra::FuncProto &proto) {
    out << kind << '\t' << std::hex << site << '\t' << target << std::dec
        << '\t' << (proto.hasModel() ? proto.getModelName() : "unknown")
        << '\t' << proto.isDotdotdot() << '\t' << proto.hasCustomStorage()
        << '\t' << proto.numParams() << "\n";
    auto writeParameter = [&](const char *role, int index, ghidra::ProtoParameter *param) {
        if (param == nullptr || param->getType() == nullptr) return;
        auto address = param->getAddress();
        out << "parameter\t" << role << '\t' << index << '\t'
            << (address.isInvalid() ? "invalid" : address.getSpace()->getName())
            << '\t' << std::hex << (address.isInvalid() ? 0 : address.getOffset())
            << std::dec << '\t' << param->getSize() << '\t'
            << static_cast<int>(param->getType()->getMetatype()) << '\t'
            << param->isTypeLocked() << '\t'
            << describePrototypeType(param->getType()) << "\n";
    };
    writeParameter("output", -1, proto.getOutput());
    for (int i = 0; i < proto.numParams(); ++i)
        writeParameter("input", i, proto.getParam(i));
}

struct SeedStorage {
    ghidra::Datatype *type;
    std::string space;
    uint64_t offset;
    int size;
};

static ghidra::Datatype *parseSeedType(ghidra::Architecture &arch,
                                      const std::string &text, size_t &pos,
                                      int depth = 0) {
    if (depth > 8 || pos >= text.size()) throw std::runtime_error("type depth");
    char kind = text[pos++];
    size_t start = pos;
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

static SeedStorage parseSeedStorage(ghidra::Architecture &arch, const std::string &field) {
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
    return {type, space, offset, size};
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
            if (target == selected) throw std::runtime_error("self seed");
            if (imports.count(target)) throw std::runtime_error("import prototype is fixed");
            auto *model = arch.getModel(fields[1]);
            if (model == nullptr || model->isUnknown()) throw std::runtime_error("unknown model");
            std::vector<SeedStorage> expected;
            for (size_t i = 2; i < fields.size(); ++i) expected.push_back(parseSeedStorage(arch, fields[i]));
            ghidra::PrototypePieces pieces;
            pieces.model = model;
            pieces.outtype = expected[0].type;
            pieces.firstVarArgSlot = -1;
            for (size_t i = 1; i < expected.size(); ++i) {
                pieces.intypes.push_back(expected[i].type);
                pieces.innames.push_back("");
            }
            std::vector<ghidra::ParameterPieces> assigned;
            model->assignParameterStorage(pieces, assigned, false);
            if (assigned.size() != expected.size()) throw std::runtime_error("implicit parameters");
            for (size_t i = 0; i < assigned.size(); ++i) {
                const auto address = assigned[i].addr;
                const std::string space = address.isInvalid() ? "invalid" : address.getSpace()->getName();
                const uint64_t offset = address.isInvalid() ? 0 : address.getOffset();
                if (space != expected[i].space || offset != expected[i].offset ||
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
// Codes: v void, i int, u unsigned, l long, z size_t, p void *, s char *, d double.
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
        {"qsort", "v p z z p"}, {"time", "l p"}, {"clock_gettime", "i i p"}, {"sqrt", "d d"}};
    return table;
}

static ghidra::Datatype *importType(ghidra::Architecture &arch, char code) {
    auto *types = arch.types;
    switch (code) {
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
        pieces.outtype = importType(arch, code[0]);
        while (codes >> code) {
            if (code == "...") {
                pieces.firstVarArgSlot = static_cast<int>(pieces.intypes.size());
                break;
            }
            pieces.intypes.push_back(importType(arch, code[0]));
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
        StaticElfArchitecture arch(argv[1]);ghidra::DocumentStorage store;arch.init(store);
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
            if(symbol.size>1048576 || !image->dataRange(symbol.address,symbol.size) ||
               !dataAddresses.insert(symbol.address).second) continue;
            bool word=symbol.size==1 || symbol.size==2 || symbol.size==4 || symbol.size==8 || symbol.size==16;
            auto* type=word?arch.types->getBase(symbol.size,ghidra::TYPE_UNKNOWN):
                arch.types->getTypeArray(symbol.size,arch.types->getBase(1,ghidra::TYPE_UNKNOWN));
            scope->addSymbol(symbol.name,type,ghidra::Address(arch.getDefaultDataSpace(),symbol.address),ghidra::Address());
        }
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
        exportPrototype(prototypes, "function", selectedAddress, selectedAddress,
                        fd->getFuncProto());
        for (int i = 0; i < fd->numCalls(); ++i) {
            auto call = fd->getCallSpecs(i);
            auto op = call->getOp();
            auto target = call->getEntryAddress();
            if (op == nullptr) continue;
            const bool resolved = !target.isInvalid() &&
                target.getSpace() == arch.getDefaultCodeSpace();
            exportPrototype(prototypes, resolved ? "call" : "indirect",
                            op->getAddr().getOffset(),
                            resolved ? target.getOffset() : 0, *call);
        }
        prototypes.flush();
        fibers::require(bool(prototypes), "Cannot save prototype evidence");
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
