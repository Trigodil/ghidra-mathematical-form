#include "native.hpp"
#include <iostream>
using namespace fibers;
namespace fs = std::filesystem;

int main(int argc, char **argv) {
    try {
        ghidra::AttributeId::initialize();
        ghidra::ElementId::initialize();
        require(argc >= 5, "Usage: native-audit decode|lift BINARY SLA OUTPUT [SYMBOL]");
        std::string mode = argv[1];
        Elf elf(argv[2]);
        fs::path sla = argv[3], output = argv[4];
        fs::create_directories(output);
        if (mode == "lift") {
            require(argc == 6, "Need symbol");
            z3::context c;
            std::vector<Argument> inputs;
            for (const std::string reg : {"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RSP", "RBP",
                                          "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"})
                inputs.push_back({"in_" + reg, 64, reg});
            auto model = lift(c, elf, argv[5], sla, inputs, "RAX",
                              {"RSP", "RBP", "RBX", "R12", "R13", "R14", "R15"});
            std::ofstream text(output / "model.txt");
            text << "Generic initial GPR state, not an inferred source ABI.\n"
                 << "Return paths: " << model.paths << "\nRAX: " << model.result
                 << "\nRAM: " << model.memory_out << '\n';
            for (const auto &[name, value] : model.registers)
                text << name << ": " << value << '\n';
            for (const auto &trace : model.trace)
                text << trace;
            require(bool(text), "Cannot write model");
            std::cout << "modeled; paths=" << model.paths << "; no source-byte inverse asserted\n";
            return 0;
        }
        require(mode == "decode", "Unknown mode");
        std::ofstream rows(output / "translation.tsv");
        rows << "name\taddress\tsize\tdecoded_bytes\tinstructions\tpcode_ops\tstatus\treason\n";
        std::unordered_set<uint64_t> seen;
        size_t functions = 0, complete = 0, failed = 0, bytes = 0, instructions = 0, ops = 0;
        for (const auto &symbol : elf.functions()) {
            if (!seen.insert(symbol.address).second)
                continue;
            size_t covered = 0, count = 0, operations = 0;
            std::string error;
            try {
                auto code = elf.function(symbol);
                Engine engine(code, sla);
                while (covered < code.bytes.size()) {
                    ghidra::Address address(engine.sleigh.getDefaultCodeSpace(),
                                            code.address + covered);
                    Assembly assembly;
                    auto length = engine.sleigh.printAssembly(assembly, address);
                    supported(length > 0 && uint64_t(length) <= code.bytes.size() - covered,
                              "Invalid instruction boundary");
                    Emit emit;
                    supported(engine.sleigh.oneInstruction(emit, address) == length,
                              "Translation size mismatch");
                    covered += size_t(length);
                    ++count;
                    operations += emit.ops.size();
                }
            } catch (const ghidra::LowlevelError &e) {
                error = e.explain;
            } catch (const std::exception &e) {
                error = e.what();
            }
            for (auto &ch : error)
                if (ch == '\n' || ch == '\r' || ch == '\t')
                    ch = ' ';
            ++functions;
            complete += error.empty();
            failed += !error.empty();
            bytes += covered;
            instructions += count;
            ops += operations;
            rows << symbol.name << '\t' << symbol.address << '\t' << symbol.size << '\t' << covered
                 << '\t' << count << '\t' << operations << '\t'
                 << (error.empty() ? "complete" : "failed") << '\t' << error << '\n';
            rows.flush();
            if (functions % 64 == 0)
                std::cout << "full named-function decode " << functions << std::endl;
        }
        std::ofstream report(output / "report.txt");
        report << "All unique-address sized function symbols, without per-function "
                  "byte/instruction cutoffs.\n"
               << "Functions: " << functions << "; complete: " << complete << "; failed: " << failed
               << '\n'
               << "Decoded bytes: " << bytes << "; instructions: " << instructions
               << "; p-code ops: " << ops << '\n'
               << "Executable segment bytes: " << elf.executable_bytes() << '\n'
               << "Linear-sweep decoding only. This is not source reconstruction, reachable-flow "
                  "coverage, or a whole-executable proof.\n";
        std::cout << "decode complete: " << complete << '/' << functions << "; bytes=" << bytes
                  << '\n';
        return failed ? 2 : 0;
    } catch (const ghidra::LowlevelError &e) {
        std::cerr << e.explain << '\n';
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
    }
    return 1;
}
