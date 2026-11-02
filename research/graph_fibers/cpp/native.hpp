#pragma once
#include "core.hpp"
#include "loadimage.hh"
#include "sleigh.hh"
#include <cstring>
#include <elf.h>
#include <functional>
#include <optional>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fibers {
struct Unsupported : std::runtime_error { using std::runtime_error::runtime_error; };
inline void supported(bool value, const std::string& message) {
    if (!value) throw Unsupported(message);
}

struct Function { uint64_t address; std::vector<uint8_t> bytes; };
struct NamedFunction {std::string name;uint64_t address,size;};
class ReadOnlyFile {
    void* mapping=MAP_FAILED;size_t length=0;
public:
    explicit ReadOnlyFile(const std::filesystem::path& path) {
        int descriptor=open(path.c_str(),O_RDONLY);supported(descriptor>=0,"Cannot open ELF file");
        struct stat info{};
        if(fstat(descriptor,&info)!=0||!S_ISREG(info.st_mode)||info.st_size<=0) {
            close(descriptor);throw Unsupported("Need a nonempty regular ELF file");
        }
        length=size_t(info.st_size);mapping=mmap(nullptr,length,PROT_READ,MAP_PRIVATE,descriptor,0);close(descriptor);
        supported(mapping!=MAP_FAILED,"Cannot map ELF read-only");
    }
    ReadOnlyFile(const ReadOnlyFile&)=delete;
    ReadOnlyFile& operator=(const ReadOnlyFile&)=delete;
    ~ReadOnlyFile(){if(mapping!=MAP_FAILED)munmap(mapping,length);}
    size_t size() const{return length;}
    const uint8_t* data() const{return static_cast<const uint8_t*>(mapping);}
    const uint8_t* begin() const{return data();}
};
class Elf {
    ReadOnlyFile data;
    mutable bool indexed=false;
    mutable std::unordered_map<std::string,std::pair<uint64_t,uint64_t>> names;
    mutable std::unordered_set<std::string> ambiguous;
    mutable std::vector<NamedFunction> list;
    template<class T> T record(uint64_t offset) const {
        supported(offset <= data.size() && sizeof(T) <= data.size()-offset, "Truncated ELF record");
        T value; std::memcpy(&value, data.data()+offset, sizeof(T)); return value;
    }
    static bool range(uint64_t offset, uint64_t size, uint64_t limit) {
        return offset <= limit && size <= limit-offset;
    }
    Elf64_Ehdr header() const {
        auto header = record<Elf64_Ehdr>(0);
        supported(std::memcmp(header.e_ident, ELFMAG, SELFMAG) == 0 &&
                  header.e_ident[EI_CLASS] == ELFCLASS64 && header.e_ident[EI_DATA] == ELFDATA2LSB &&
                  header.e_machine == EM_X86_64 && (header.e_type == ET_DYN || header.e_type == ET_EXEC),
                  "Expected little-endian x86-64 ELF executable/shared object");
        supported(header.e_shentsize == sizeof(Elf64_Shdr) && header.e_phentsize == sizeof(Elf64_Phdr) &&
                  range(header.e_shoff, uint64_t(header.e_shnum)*header.e_shentsize, data.size()) &&
                  range(header.e_phoff, uint64_t(header.e_phnum)*header.e_phentsize, data.size()),
                  "Invalid/extended ELF header tables");
        return header;
    }
    void index() const {
        if(indexed)return;
        auto header=this->header();
        for (unsigned i = 0; i < header.e_shnum; ++i) {
            auto section = record<Elf64_Shdr>(header.e_shoff + uint64_t(i)*sizeof(Elf64_Shdr));
            if (section.sh_type != SHT_SYMTAB && section.sh_type != SHT_DYNSYM) continue;
            supported(section.sh_entsize == sizeof(Elf64_Sym) && section.sh_link < header.e_shnum &&
                      section.sh_size % sizeof(Elf64_Sym) == 0 && range(section.sh_offset, section.sh_size, data.size()),
                      "Invalid ELF symbol table");
            auto strings = record<Elf64_Shdr>(header.e_shoff + uint64_t(section.sh_link)*sizeof(Elf64_Shdr));
            supported(range(strings.sh_offset, strings.sh_size, data.size()), "Invalid symbol string table");
            for (uint64_t j = 0; j < section.sh_size/sizeof(Elf64_Sym); ++j) {
                auto symbol = record<Elf64_Sym>(section.sh_offset + j*sizeof(Elf64_Sym));
                if (ELF64_ST_TYPE(symbol.st_info) != STT_FUNC || symbol.st_shndx == SHN_UNDEF || symbol.st_size==0) continue;
                supported(symbol.st_name < strings.sh_size, "Invalid symbol name offset");
                const char* text = reinterpret_cast<const char*>(data.data()+strings.sh_offset+symbol.st_name);
                auto available = strings.sh_size-symbol.st_name;
                auto end = static_cast<const char*>(std::memchr(text, 0, available));
                supported(end != nullptr, "Unterminated symbol name");
                std::string name(text,end);if(name.empty())continue;
                const auto found = std::make_pair(symbol.st_value, symbol.st_size);
                auto [it,inserted]=names.emplace(name,found);
                if(!inserted&&it->second!=found)ambiguous.insert(name);
            }
        }
        for(const auto& [name,value]:names)if(!ambiguous.count(name))list.push_back({name,value.first,value.second});
        std::sort(list.begin(),list.end(),[](const auto& a,const auto& b){return a.address!=b.address?a.address<b.address:a.name<b.name;});
        indexed=true;
    }
public:
    explicit Elf(const std::filesystem::path& path):data(path){}
    const std::vector<NamedFunction>& functions() const{index();return list;}
    uint64_t file_size() const{return data.size();}
    std::vector<Function> executable_images() const {
        auto h=header(); std::vector<Function> result;
        for(unsigned i=0;i<h.e_phnum;++i) {
            auto p=record<Elf64_Phdr>(h.e_phoff+uint64_t(i)*sizeof(Elf64_Phdr));
            if(p.p_type!=PT_LOAD || !(p.p_flags&PF_X) || !p.p_filesz) continue;
            supported(range(p.p_offset,p.p_filesz,data.size()) && p.p_vaddr<=UINT64_MAX-p.p_filesz,
                      "Invalid executable segment");
            const auto* begin=data.begin()+p.p_offset;
            result.push_back({p.p_vaddr,std::vector<uint8_t>(begin,begin+p.p_filesz)});
        }
        return result;
    }
    uint64_t executable_bytes() const {
        auto h=header();uint64_t bytes=0;
        for(unsigned i=0;i<h.e_phnum;++i){auto p=record<Elf64_Phdr>(h.e_phoff+uint64_t(i)*sizeof(Elf64_Phdr));
            if(p.p_type==PT_LOAD&&(p.p_flags&PF_X)){supported(range(p.p_offset,p.p_filesz,data.size()),"Invalid code segment");bytes+=p.p_filesz;}}
        return bytes;
    }
    Function function(const std::string& name) const {
        index();auto found=names.find(name);
        supported(found!=names.end()&&!ambiguous.count(name),"Need an unambiguous named function: "+name);
        return function(NamedFunction{name,found->second.first,found->second.second});
    }
    Function function(const NamedFunction& symbol) const {
        const auto h=header();const auto match=std::make_pair(symbol.address,symbol.size);
        supported(match.second>0,"Empty function");
        for (unsigned i = 0; i < h.e_phnum; ++i) {
            auto segment = record<Elf64_Phdr>(h.e_phoff + uint64_t(i)*sizeof(Elf64_Phdr));
            if (segment.p_type != PT_LOAD || !(segment.p_flags & PF_X) || match.first < segment.p_vaddr) continue;
            auto relative = match.first-segment.p_vaddr;
            if (!range(relative, match.second, segment.p_filesz)) continue;
            supported(range(segment.p_offset, segment.p_filesz, data.size()), "Truncated executable segment");
            auto begin = data.begin()+segment.p_offset+relative;
            return {match.first, std::vector<uint8_t>(begin, begin+match.second)};
        }
        throw Unsupported("Function is not within a file-backed executable segment");
    }
};

class Image : public ghidra::LoadImage {
    const Function& code;
public:
    explicit Image(const Function& function) : LoadImage("function bytes"), code(function) {}
    void loadFill(ghidra::uint1* target, ghidra::int4 size, const ghidra::Address& address) override {
        for (ghidra::int4 i = 0; i < size; ++i) {
            const uint64_t offset = address.getOffset()+uint64_t(i)-code.address;
            target[i] = offset < code.bytes.size() ? code.bytes[offset] : 0;
        }
    }
    std::string getArchType() const override { return "x86-64"; }
    void adjustVma(long) override { throw Unsupported("VMA adjustment not supported"); }
};
struct RawOp { ghidra::OpCode opcode; std::optional<ghidra::VarnodeData> output; std::vector<ghidra::VarnodeData> inputs; };
struct Emit : ghidra::PcodeEmit {
    std::vector<RawOp> ops;
    void dump(const ghidra::Address&, ghidra::OpCode opcode, ghidra::VarnodeData* output,
              ghidra::VarnodeData* inputs, ghidra::int4 count) override {
        std::vector<ghidra::VarnodeData> copied;
        if (count > 0) copied.assign(inputs, inputs+count);
        ops.push_back({opcode, output ? std::optional<ghidra::VarnodeData>(*output) : std::nullopt,
                       std::move(copied)});
    }
};
struct Assembly : ghidra::AssemblyEmit {
    std::string mnemonic, body;
    void dump(const ghidra::Address&, const std::string& m, const std::string& b) override { mnemonic=m; body=b; }
};
struct Engine {
    Image image;
    ghidra::ContextInternal defaults;
    ghidra::Sleigh sleigh;
    ghidra::DocumentStorage documents;
    Engine(const Function& code, const std::filesystem::path& sla) : image(code), sleigh(&image, &defaults) {
        std::string path = std::filesystem::absolute(sla).string(), escaped;
        for (char ch : path) {
            if (ch == '&') escaped += "&amp;";
            else if (ch == '<') escaped += "&lt;";
            else escaped += ch;
        }
        std::istringstream xml("<sleigh>"+escaped+"</sleigh>");
        auto* root = documents.parseDocument(xml)->getRoot();
        documents.registerTag(root);
        sleigh.initialize(documents);
        defaults.setVariableDefault("addrsize", 2);
        defaults.setVariableDefault("opsize", 1);
        defaults.setVariableDefault("rexprefix", 0);
        defaults.setVariableDefault("longMode", 1);
    }
};

struct ByteKey {
    bool temporary;
    uint64_t offset;
    bool operator==(const ByteKey& other) const { return temporary==other.temporary && offset==other.offset; }
};
struct ByteHash { size_t operator()(const ByteKey& key) const { return std::hash<uint64_t>{}(key.offset) ^ (size_t(key.temporary)<<63); } };
struct WordKey {
    bool temporary;uint64_t offset;unsigned size;
    bool operator==(const WordKey& other)const{return temporary==other.temporary&&offset==other.offset&&size==other.size;}
};
struct WordHash {size_t operator()(const WordKey& key)const{return ByteHash{}({key.temporary,key.offset})^(size_t(key.size)<<24);}};
struct State {
    z3::context* context;
    std::unordered_map<ByteKey, z3::expr, ByteHash> bytes;
    std::unordered_map<WordKey, z3::expr, WordHash> words;
    z3::expr memory;
    explicit State(z3::context& c) : context(&c), memory(c.constant("memory0", c.array_sort(c.bv_sort(64), c.bv_sort(8)))) {}
    z3::expr read(const ghidra::VarnodeData& var) {
        const auto& space = var.space->getName();
        if (space == "const") return context->bv_val(uint64_t(var.offset), unsigned(var.size*8));
        supported(space == "register" || space == "unique", "Unsupported storage space: "+space);
        supported(var.size > 0 && var.size <= 32, "Unsupported varnode width");
        const WordKey requested{space=="unique",var.offset,unsigned(var.size)};
        auto exact=words.find(requested);if(exact!=words.end())return exact->second;
        for(const auto& [key,value]:words)if(key.temporary==requested.temporary&&requested.offset>=key.offset&&
                requested.offset-key.offset+requested.size<=key.size) {
            auto low=unsigned((requested.offset-key.offset)*8);
            return value.extract(low+requested.size*8-1,low).simplify();
        }
        std::vector<z3::expr> parts;
        for (int i = 0; i < var.size; ++i) {
            ByteKey key{space == "unique", var.offset+uint64_t(i)};
            auto it = bytes.find(key);
            if (it == bytes.end()) {
                supported(!key.temporary, "Read of undefined p-code temporary");
                auto name = "initial_register_"+std::to_string(key.offset);
                it = bytes.emplace(key, context->bv_const(name.c_str(), 8)).first;
            }
            parts.push_back(it->second);
        }
        auto result = parts.back();
        for (int i = var.size-2; i >= 0; --i) result=z3::concat(result, parts[size_t(i)]);
        return result.simplify();
    }
    void write(const ghidra::VarnodeData& var, const z3::expr& value) {
        const auto& space = var.space->getName();
        supported((space == "register" || space == "unique") && value.is_bv() &&
                  value.get_sort().bv_size() == unsigned(var.size*8), "p-code write width/space mismatch");
        for(auto it=words.begin();it!=words.end();) {
            const auto& key=it->first;
            if(key.temporary==(space=="unique")&&key.offset<var.offset+uint64_t(var.size)&&
                    var.offset<key.offset+key.size)it=words.erase(it);else ++it;
        }
        for (int i = 0; i < var.size; ++i)
            bytes.insert_or_assign({space == "unique", var.offset+uint64_t(i)}, value.extract(8*i+7, 8*i).simplify());
        words.emplace(WordKey{space=="unique",var.offset,unsigned(var.size)},value.simplify());
    }
    void clear_temporaries() {
        for (auto it = bytes.begin(); it != bytes.end();) {
            if (it->first.temporary) it=bytes.erase(it); else ++it;
        }
        for(auto it=words.begin();it!=words.end();)if(it->first.temporary)it=words.erase(it);else ++it;
    }
};
inline z3::expr truth(const z3::expr& value) { return value != 0; }
inline z3::expr boolean(const z3::expr& value, unsigned width) {
    return z3::ite(value, value.ctx().bv_val(1, width), value.ctx().bv_val(0, width));
}
inline z3::expr compute(const RawOp& op, const std::vector<z3::expr>& args) {
    using namespace ghidra;
    supported(op.output.has_value() && !args.empty(), "Missing p-code expression operands/output");
    auto a=args[0]; auto& c=a.ctx(); const unsigned width=op.output->size*8, aw=a.get_sort().bv_size();
    switch (op.opcode) {
    case CPUI_COPY: return a;
    case CPUI_INT_ZEXT: supported(width>=aw,"Invalid zero extension"); return z3::zext(a,width-aw);
    case CPUI_INT_SEXT: supported(width>=aw,"Invalid sign extension"); return z3::sext(a,width-aw);
    case CPUI_SUBPIECE: {
        auto low=args.at(1).get_numeral_uint64()*8;
        supported(low<=aw && width<=aw-low,"Invalid SUBPIECE"); return a.extract(unsigned(low+width-1),unsigned(low));
    }
    case CPUI_PIECE: return z3::concat(a,args.at(1));
    case CPUI_INT_2COMP: return -a;
    case CPUI_INT_NEGATE: return ~a;
    case CPUI_BOOL_NEGATE: return boolean(!truth(a),width);
    case CPUI_POPCOUNT: {
        auto count=c.bv_val(0,width);
        for (unsigned i=0;i<aw;++i) count=count+z3::zext(a.extract(i,i),width-1);
        return count;
    }
    default: break;
    }
    supported(args.size()==2,std::string("Unsupported unary p-code operation: ")+get_opname(op.opcode));
    auto b=args[1];
    switch(op.opcode) {
    case CPUI_INT_ADD: return a+b;
    case CPUI_INT_SUB: return a-b;
    case CPUI_INT_MULT: return a*b;
    case CPUI_INT_XOR: return a^b;
    case CPUI_INT_AND: return a&b;
    case CPUI_INT_OR: return a|b;
    case CPUI_INT_EQUAL: return boolean(a==b,width);
    case CPUI_INT_NOTEQUAL: return boolean(a!=b,width);
    case CPUI_INT_LESS: return boolean(z3::ult(a,b),width);
    case CPUI_INT_LESSEQUAL: return boolean(z3::ule(a,b),width);
    case CPUI_INT_SLESS: return boolean(a<b,width);
    case CPUI_INT_SLESSEQUAL: return boolean(a<=b,width);
    case CPUI_BOOL_AND: return boolean(truth(a)&&truth(b),width);
    case CPUI_BOOL_OR: return boolean(truth(a)||truth(b),width);
    case CPUI_BOOL_XOR: return boolean(truth(a)!=truth(b),width);
    case CPUI_INT_CARRY: return boolean(z3::ult(a+b,a),width);
    case CPUI_INT_SCARRY: return boolean(((a<0)==(b<0))&&((a<0)!=(a+b<0)),width);
    case CPUI_INT_SBORROW: return boolean(((a<0)!=(b<0))&&((a<0)!=(a-b<0)),width);
    case CPUI_INT_LEFT: case CPUI_INT_RIGHT: case CPUI_INT_SRIGHT: {
        auto bw=b.get_sort().bv_size();
        auto count=bw<aw ? z3::zext(b,aw-bw) : bw>aw ? b.extract(aw-1,0) : b;
        auto value=op.opcode==CPUI_INT_LEFT ? z3::shl(a,count) :
                   op.opcode==CPUI_INT_RIGHT ? z3::lshr(a,count) : z3::ashr(a,count);
        if (bw>=32 || (uint64_t(1)<<bw)>aw) {
            auto fill=op.opcode==CPUI_INT_SRIGHT ? z3::ite(a<0,c.bv_val(-1,aw),c.bv_val(0,aw)) : c.bv_val(0,aw);
            value=z3::ite(z3::uge(b,c.bv_val(aw,bw)),fill,value);
        }
        return value;
    }
    default: throw Unsupported(std::string("Unsupported p-code: ")+get_opname(op.opcode));
    }
}

struct Argument { std::string name; unsigned width; std::string reg; };
struct Model {
    std::vector<z3::expr> inputs;
    z3::expr result, memory_in, memory_out;
    size_t paths;
    std::vector<std::string> trace;
    size_t projected_register_bytes;
    std::map<std::string,z3::expr> registers;
};
inline Model lift(z3::context& c, const Elf& elf, const std::string& symbol, const std::filesystem::path& sla,
                  const std::vector<Argument>& arguments={{"x",8,"DIL"},{"y",8,"SIL"}},
                  const std::string& return_register="AL",const std::vector<std::string>& observed_registers={}) {
    auto code=elf.function(symbol); Engine engine(code,sla); State initial(c);
    auto initial_memory=initial.memory;
    std::vector<z3::expr> inputs;
    std::set<std::string> names; std::unordered_set<uint64_t> occupied;
    for (const auto& arg:arguments) {
        supported(names.insert(arg.name).second,"Duplicate argument name");
        const auto& var=engine.sleigh.getRegister(arg.reg);
        supported(arg.width==unsigned(var.size*8) && arg.width<=64,"Argument width/ABI mismatch");
        for (int i=0;i<var.size;++i) supported(occupied.insert(var.offset+uint64_t(i)).second,"Overlapping ABI arguments");
        inputs.push_back(c.bv_const(arg.name.c_str(),arg.width)); initial.write(var,inputs.back());
    }
    struct Frame { uint64_t pc; State state; z3::expr guard; std::unordered_set<uint64_t> visited; };
    struct Return { z3::expr guard, result, memory; std::map<std::string,z3::expr> registers; };
    std::vector<Frame> pending; pending.push_back({code.address,std::move(initial),c.bool_val(true),{}});
    std::vector<Return> returns; std::vector<std::string> trace; std::unordered_set<uint64_t> traced;
    size_t explored=0;
    while(!pending.empty()) {
        auto frame=std::move(pending.back()); pending.pop_back();
        auto feasible=query(frame.guard);
        if (feasible.status=="unsat") continue;
        supported(feasible.status=="sat","Path feasibility unknown");
        supported(++explored<=128 && frame.visited.size()<256,"Exploration limit; coverage incomplete");
        supported(frame.visited.insert(frame.pc).second,"Reachable loop requires an invariant");
        supported(frame.pc>=code.address && frame.pc-code.address<code.bytes.size(),"Control flow leaves function");
        ghidra::Address address(engine.sleigh.getDefaultCodeSpace(),frame.pc);
        Assembly assembly;
        const auto length=engine.sleigh.printAssembly(assembly,address);
        supported(length>0 && uint64_t(length)<=code.bytes.size()-(frame.pc-code.address),"Incomplete instruction");
        if (assembly.mnemonic=="RET" && assembly.body.empty()) {
            Return finished{frame.guard,frame.state.read(engine.sleigh.getRegister(return_register)),frame.state.memory,{}};
            for(const auto& reg:observed_registers)finished.registers.emplace(reg,frame.state.read(engine.sleigh.getRegister(reg)));
            returns.push_back(std::move(finished));
            continue;
        }
        frame.state.clear_temporaries();
        Emit emit; supported(engine.sleigh.oneInstruction(emit,address)==length,"Translation length mismatch");
        if (traced.insert(frame.pc).second) {
            std::ostringstream line; line<<std::hex<<frame.pc<<": "<<assembly.mnemonic<<' '<<assembly.body<<'\n';
            for (const auto& op:emit.ops) {
                line<<"  "<<ghidra::get_opname(op.opcode);
                auto show=[&](const ghidra::VarnodeData& v) {
                    line<<" ("<<v.space->getName()<<",0x"<<std::hex<<v.offset<<','<<std::dec<<v.size<<')';
                };
                if(op.output) { line<<" ->"; show(*op.output); }
                for(const auto& v:op.inputs) show(v);
                line<<'\n';
            }
            trace.push_back(line.str());
        }
        auto next_pc=frame.pc+uint64_t(length); bool branched=false;
        for(size_t index=0;index<emit.ops.size();++index) {
            const auto& op=emit.ops[index]; using namespace ghidra;
            if(op.opcode==CPUI_BRANCH || op.opcode==CPUI_CBRANCH) {
                supported(op.inputs.at(0).space->getName()=="ram" && index+1==emit.ops.size(),
                          "Only direct machine branches at instruction end are supported");
                auto condition=op.opcode==CPUI_CBRANCH ? truth(frame.state.read(op.inputs.at(1))) : c.bool_val(true);
                pending.push_back({op.inputs[0].offset,frame.state,(frame.guard&&condition).simplify(),frame.visited});
                pending.push_back({next_pc,std::move(frame.state),(frame.guard&&!condition).simplify(),std::move(frame.visited)});
                branched=true; break;
            }
            supported(op.opcode!=CPUI_CALL && op.opcode!=CPUI_CALLIND && op.opcode!=CPUI_CALLOTHER &&
                      op.opcode!=CPUI_BRANCHIND && op.opcode!=CPUI_RETURN,"Unsupported control flow");
            if(op.opcode==CPUI_LOAD || op.opcode==CPUI_STORE) {
                supported(op.inputs.at(0).getSpaceFromConst()->getName()=="ram","Only ordinary RAM supported");
                auto pointer=frame.state.read(op.inputs.at(1));
                supported(pointer.get_sort().bv_size()==64,"Expected 64-bit memory address");
                const int size=int(op.opcode==CPUI_LOAD ? op.output->size : op.inputs.at(2).size);
                supported(size>0 && size<=32,"Unsupported memory access width");
                if(op.opcode==CPUI_LOAD) {
                    auto value=z3::select(frame.state.memory,pointer+size-1);
                    for(int byte=size-2;byte>=0;--byte) value=z3::concat(value,z3::select(frame.state.memory,pointer+byte));
                    frame.state.write(*op.output,value);
                } else {
                    auto value=frame.state.read(op.inputs.at(2));
                    for(int byte=0;byte<size;++byte)
                        frame.state.memory=z3::store(frame.state.memory,pointer+byte,value.extract(8*byte+7,8*byte));
                }
                continue;
            }
            std::vector<z3::expr> values;
            for(const auto& input:op.inputs) values.push_back(frame.state.read(input));
            supported(op.output.has_value(),"p-code instruction has no supported output");
            frame.state.write(*op.output,compute(op,values).simplify());
        }
        if(!branched) pending.push_back({next_pc,std::move(frame.state),frame.guard,std::move(frame.visited)});
    }
    supported(!returns.empty(),"No supported return paths");
    auto coverage=c.bool_val(false); for(const auto& r:returns) coverage=coverage||r.guard;
    supported(query(!coverage).status=="unsat","Return path coverage not proved");
    auto result=returns.back().result, memory=returns.back().memory;
    auto final_registers=returns.back().registers;
    for(size_t i=returns.size()-1;i>0;--i) {
        const auto& r=returns[i-1]; result=z3::ite(r.guard,r.result,result); memory=z3::ite(r.guard,r.memory,memory);
        for(auto& [name,value]:final_registers)value=z3::ite(r.guard,r.registers.at(name),value);
    }
    result=result.simplify(); memory=memory.simplify();
    std::unordered_set<unsigned> allowed{initial_memory.id()}; for(const auto& v:inputs) allowed.insert(v.id());
    std::map<unsigned,z3::expr> hidden;
    std::vector<z3::expr> observations{result,memory};
    for(auto& [name,value]:final_registers){value=value.simplify();observations.push_back(value);}
    for(const auto& term:observations) for(const auto& var:variables(term))
        if(!allowed.count(var.id())) hidden.emplace(var.id(),var);
    if(!hidden.empty()) {
        z3::expr_vector from(c),to(c);
        for(const auto& [id,var]:hidden) { from.push_back(var); to.push_back(c.bv_val(0,var.get_sort().bv_size())); }
        auto clean_result=result.substitute(from,to).simplify(), clean_memory=memory.substitute(from,to).simplify();
        auto difference=result!=clean_result || memory!=clean_memory;
        auto clean_registers=final_registers;
        for(auto& [name,value]:clean_registers){value=value.substitute(from,to).simplify();difference=difference||(final_registers.at(name)!=value);}
        supported(query(difference).status=="unsat",
                  "Independence from undeclared initial registers not proved");
        result=clean_result; memory=clean_memory;
        final_registers=std::move(clean_registers);
    }
    return {std::move(inputs),result,initial_memory,memory,returns.size(),std::move(trace),hidden.size(),std::move(final_registers)};
}
} // namespace fibers
