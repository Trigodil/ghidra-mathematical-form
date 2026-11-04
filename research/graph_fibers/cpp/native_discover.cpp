#include "native.hpp"
#include <deque>
#include <fstream>
#include <iostream>
using namespace fibers;
namespace fs = std::filesystem;

int main(int argc, char **argv) {
    try {
        require(argc == 6, "Usage: native-discover BINARY SLA SEEDS OUTPUT MAX_INSTRUCTIONS");
        ghidra::AttributeId::initialize();
        ghidra::ElementId::initialize();
        Elf elf(argv[1]);
        auto images = elf.executable_images();
        std::vector<std::unique_ptr<Engine>> engines;
        for (auto &image : images)
            engines.emplace_back(std::make_unique<Engine>(image, argv[2]));
        auto find = [&](uint64_t addr) -> int {
            for (size_t i = 0; i < images.size(); ++i)
                if (addr >= images[i].address && addr - images[i].address < images[i].bytes.size())
                    return int(i);
            return -1;
        };
        const uint64_t max_instructions = std::stoull(argv[5]);
        constexpr size_t max_functions = 100000, max_work = 2000000;
        std::deque<uint64_t> work;
        std::unordered_set<uint64_t> scheduled, visited, functions, calls;
        std::ifstream seeds(argv[3]);
        require(bool(seeds), "Cannot open seeds");
        uint64_t addr;
        bool truncated = false;
        while (seeds >> std::hex >> addr)
            if (find(addr) >= 0 && !functions.count(addr)) {
                if (functions.size() >= max_functions) {
                    truncated = true;
                    continue;
                }
                functions.insert(addr);
                if (scheduled.insert(addr).second)
                    work.push_back(addr);
            }
        require(seeds.eof(), "Invalid seed address");
        std::ofstream out(fs::path(argv[4]) / "recursive.tsv");
        require(bool(out), "Cannot create discovery output");
        out << "address\tcaller\n";
        uint64_t instructions = 0, errors = 0, indirect_calls = 0, indirect_branches = 0,
                 ambiguous_jumps = 0, outside = 0;
        std::ofstream sites(fs::path(argv[4]) / "sites.tsv");
        sites << "address\treason\n";
        std::vector<std::pair<uint64_t, uint64_t>> covered;
        auto schedule = [&](uint64_t target) {
            if (find(target) < 0) {
                ++outside;
                return;
            }
            if (scheduled.count(target))
                return;
            if (scheduled.size() >= max_work) {
                truncated = true;
                return;
            }
            scheduled.insert(target);
            work.push_back(target);
        };
        while (!work.empty()) {
            if (instructions >= max_instructions) {
                truncated = true;
                break;
            }
            uint64_t pc = work.front();
            work.pop_front();
            if (!visited.insert(pc).second)
                continue;
            int idx = find(pc);
            if (idx < 0)
                continue;
            auto &engine = *engines[idx];
            auto &image = images[idx];
            try {
                ghidra::Address at(engine.sleigh.getDefaultCodeSpace(), pc);
                Emit emit;
                auto length = engine.sleigh.oneInstruction(emit, at);
                supported(length > 0 &&
                              uint64_t(length) <= image.bytes.size() - (pc - image.address),
                          "Invalid instruction boundary");
                ++instructions;
                covered.emplace_back(pc, pc + uint64_t(length));
                bool fallthrough = true;
                for (const auto &op : emit.ops) {
                    using namespace ghidra;
                    if (op.opcode == CPUI_CALL || op.opcode == CPUI_BRANCH ||
                        op.opcode == CPUI_CBRANCH) {
                        if (op.inputs.empty()) {
                            ++errors;
                            fallthrough = false;
                            break;
                        }
                        const auto &dest = op.inputs[0];
                        if (dest.space->getName() == "const")
                            continue; // p-code internal branch
                        uint64_t target = dest.offset;
                        if (op.opcode == CPUI_CALL) {
                            if (find(target) >= 0) {
                                if (!functions.count(target) && functions.size() >= max_functions) {
                                    truncated = true;
                                    continue;
                                }
                                if (calls.insert(target).second)
                                    out << std::hex << target << '\t' << pc << '\n';
                                if (functions.insert(target).second)
                                    schedule(target);
                            } else
                                ++outside;
                        } else {
                            schedule(target);
                            if (op.opcode == CPUI_BRANCH) {
                                ++ambiguous_jumps;
                                fallthrough = false;
                            }
                        }
                    } else if (op.opcode == CPUI_CALLIND) {
                        ++indirect_calls;
                        sites << std::hex << pc << "\tunresolved_indirect_call\n";
                    } else if (op.opcode == CPUI_BRANCHIND) {
                        ++indirect_branches;
                        sites << std::hex << pc << "\tunresolved_indirect_branch\n";
                        fallthrough = false;
                    } else if (op.opcode == CPUI_RETURN)
                        fallthrough = false;
                }
                if (fallthrough && pc <= UINT64_MAX - uint64_t(length))
                    schedule(pc + uint64_t(length));
            } catch (const ghidra::LowlevelError &) {
                ++errors;
                sites << std::hex << pc << "\tdecode_error\n";
            } catch (const std::exception &) {
                ++errors;
                sites << std::hex << pc << "\tdecode_error\n";
            }
        }
        for (auto pending : work)
            sites << std::hex << pending << "\tbudget_pending\n";
        sites.close();
        require(bool(sites), "Cannot write site details");
        std::sort(covered.begin(), covered.end());
        std::vector<std::pair<uint64_t, uint64_t>> merged;
        for (auto range : covered) {
            if (merged.empty() || range.first > merged.back().second)
                merged.push_back(range);
            else
                merged.back().second = std::max(merged.back().second, range.second);
        }
        std::ofstream ranges(fs::path(argv[4]) / "coverage.tsv");
        ranges << "start\tend_exclusive\tstatus\n";
        uint64_t covered_bytes = 0;
        for (auto &image : images) {
            uint64_t cursor = image.address, end = image.address + image.bytes.size();
            for (auto range : merged) {
                if (range.second <= cursor || range.first >= end)
                    continue;
                auto start = std::max(cursor, range.first), stop = std::min(end, range.second);
                if (start > cursor)
                    ranges << std::hex << cursor << "\t" << start << "\tunexamined\n";
                ranges << std::hex << start << "\t" << stop << "\tdecoded\n";
                covered_bytes += stop - start;
                cursor = stop;
            }
            if (cursor < end)
                ranges << std::hex << cursor << "\t" << end << "\tunexamined\n";
        }
        ranges.close();
        require(bool(ranges), "Cannot write coverage");
        out.close();
        require(bool(out), "Cannot write discovery output");
        std::ofstream stats(fs::path(argv[4]) / "recursive-stats.json");
        stats << "{\"instructions\":" << std::dec << instructions
              << ",\"decoded_bytes\":" << covered_bytes
              << ",\"instruction_budget\":" << max_instructions
              << ",\"function_budget\":" << max_functions << ",\"work_budget\":" << max_work
              << ",\"truncated\":" << (truncated ? "true" : "false")
              << ",\"decode_errors\":" << errors
              << ",\"unresolved_indirect_calls\":" << indirect_calls
              << ",\"unresolved_indirect_branches\":" << indirect_branches
              << ",\"ambiguous_direct_jumps\":" << ambiguous_jumps
              << ",\"outside_executable_edges\":" << outside << "}\n";
        require(bool(stats), "Cannot write statistics");
        return 0;
    } catch (const ghidra::LowlevelError &e) {
        std::cerr << e.explain << '\n';
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
    }
    return 1;
}
