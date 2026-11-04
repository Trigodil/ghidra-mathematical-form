#pragma once
#include <z3++.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace fibers {
inline void require(bool condition, const std::string &message) {
    if (!condition)
        throw std::runtime_error(message);
}

struct Answer {
    std::string status;
    std::map<std::string, uint64_t> witness;
    std::string reason;
};

inline Answer query(const z3::expr &predicate, const std::vector<z3::expr> &variables = {},
                    unsigned timeout_ms = 5000, const std::filesystem::path &artifact = {}) {
    z3::solver solver(predicate.ctx());
    if (timeout_ms != 0)
        solver.set("timeout", timeout_ms);
    solver.add(predicate);
    if (!artifact.empty())
        std::ofstream(artifact) << solver.to_smt2();
    auto result = solver.check();
    if (result == z3::unsat)
        return {"unsat", {}, {}};
    if (result == z3::unknown)
        return {"unknown", {}, solver.reason_unknown()};
    Answer answer{"sat", {}, {}};
    auto model = solver.get_model();
    for (const auto &variable : variables)
        answer.witness[variable.decl().name().str()] =
            model.eval(variable, true).get_numeral_uint64();
    return answer;
}

struct Box {
    std::string name;
    z3::expr states;
    Box intersect(const Box &other) const {
        return {name + " & " + other.name, states && other.states};
    }
    Answer subset_of(const Box &other, const std::vector<z3::expr> &vars = {}) const {
        return query(states && !other.states, vars);
    }
    Answer overlaps(const Box &other, const std::vector<z3::expr> &vars = {}) const {
        return query(states && other.states, vars);
    }
};

struct Fiber {
    std::vector<std::vector<uint64_t>> points;
    bool complete = false;
    std::string reason;
};
inline Fiber enumerate(const z3::expr &predicate, const std::vector<z3::expr> &variables,
                       size_t limit = 16) {
    require(!variables.empty() && limit > 0, "Need variables and a positive enumeration limit");
    z3::solver solver(predicate.ctx());
    solver.set("timeout", 5000u);
    solver.add(predicate);
    Fiber result;
    for (;;) {
        auto status = solver.check();
        if (status == z3::unsat) {
            result.complete = true;
            return result;
        }
        if (status == z3::unknown) {
            result.reason = solver.reason_unknown();
            return result;
        }
        if (result.points.size() == limit) {
            result.reason = "enumeration limit";
            return result;
        }
        auto model = solver.get_model();
        std::vector<uint64_t> point;
        auto different = predicate.ctx().bool_val(false);
        for (const auto &var : variables) {
            auto value = model.eval(var, true);
            point.push_back(value.get_numeral_uint64());
            different = different || var != value;
        }
        result.points.push_back(std::move(point));
        solver.add(different);
    }
}

// Sparse adjacency lists; no V-by-V matrix or pairwise node scan.
struct Vertex {
    std::string label;
    std::vector<std::pair<int, unsigned>> incoming, outgoing;
};
struct Graph {
    std::vector<Vertex> vertices;
    unsigned node(std::string label) {
        unsigned id = static_cast<unsigned>(vertices.size());
        vertices.push_back({std::move(label), {}, {}});
        return id;
    }
    void edge(unsigned source, unsigned target, int slot = -1) {
        vertices.at(source).outgoing.emplace_back(slot, target);
        vertices.at(target).incoming.emplace_back(slot, source);
    }
};
struct VectorHash {
    size_t operator()(const std::vector<unsigned> &key) const noexcept {
        size_t hash = 0;
        for (auto value : key)
            hash ^= value + size_t(0x9e3779b9) + (hash << 6) + (hash >> 2);
        return hash;
    }
};
struct Coloring {
    bool indistinguishable;
    unsigned rounds;
};
inline Coloring refine(const Graph &left, const Graph &right) {
    const Graph *graphs[] = {&left, &right};
    std::unordered_map<std::string, unsigned> labels;
    std::vector<unsigned> colors[2];
    for (int g = 0; g < 2; ++g)
        for (const auto &node : graphs[g]->vertices) {
            auto [it, inserted] = labels.emplace(node.label, static_cast<unsigned>(labels.size()));
            colors[g].push_back(it->second);
        }
    unsigned classes = static_cast<unsigned>(labels.size()), rounds = 0;
    for (;;) {
        // Hash collisions cannot merge colors: vector equality verifies every palette key.
        std::unordered_map<std::vector<unsigned>, unsigned, VectorHash> palette;
        std::vector<unsigned> next[2];
        for (int g = 0; g < 2; ++g)
            for (unsigned id = 0; id < graphs[g]->vertices.size(); ++id) {
                std::vector<unsigned> key{colors[g][id]};
                for (const auto *edges :
                     {&graphs[g]->vertices[id].incoming, &graphs[g]->vertices[id].outgoing}) {
                    std::vector<std::pair<int, unsigned>> neighbors;
                    neighbors.reserve(edges->size());
                    for (auto [slot, other] : *edges)
                        neighbors.emplace_back(slot, colors[g][other]);
                    std::sort(neighbors.begin(), neighbors.end());
                    key.push_back(static_cast<unsigned>(neighbors.size()));
                    for (auto [slot, color] : neighbors) {
                        key.push_back(unsigned(slot + 1));
                        key.push_back(color);
                    }
                }
                auto [it, inserted] =
                    palette.emplace(std::move(key), static_cast<unsigned>(palette.size()));
                next[g].push_back(it->second);
            }
        ++rounds;
        const unsigned new_classes = static_cast<unsigned>(palette.size());
        colors[0] = std::move(next[0]);
        colors[1] = std::move(next[1]);
        if (new_classes == classes)
            break;
        classes = new_classes;
    }
    std::vector<size_t> counts[2];
    for (int g = 0; g < 2; ++g) {
        counts[g].assign(classes, 0);
        for (auto color : colors[g])
            ++counts[g][color];
    }
    return {counts[0] == counts[1], rounds};
}

inline bool commutative(Z3_decl_kind kind) {
    return kind == Z3_OP_BADD || kind == Z3_OP_BMUL || kind == Z3_OP_BAND || kind == Z3_OP_BOR ||
           kind == Z3_OP_BXOR || kind == Z3_OP_AND || kind == Z3_OP_OR || kind == Z3_OP_EQ;
}
inline Graph semantic_graph(const z3::expr &result, const z3::expr &memory) {
    Graph graph;
    std::unordered_map<unsigned, unsigned> seen;
    std::function<unsigned(const z3::expr &)> visit = [&](const z3::expr &term) {
        auto found = seen.find(term.id());
        if (found != seen.end())
            return found->second;
        std::ostringstream label;
        label << term.decl().name() << ':' << term.get_sort();
        if (term.is_numeral())
            label << ':' << term;
        const auto decl = term.decl();
        for (unsigned i = 0; !term.is_numeral() && i < Z3_get_decl_num_parameters(term.ctx(), decl);
             ++i) {
            require(Z3_get_decl_parameter_kind(term.ctx(), decl, i) == Z3_PARAMETER_INT,
                    "Unsupported graph declaration parameter");
            label << ':' << Z3_get_decl_int_parameter(term.ctx(), decl, i);
        }
        auto node = graph.node(label.str());
        seen.emplace(term.id(), node);
        for (unsigned i = 0; i < term.num_args(); ++i) {
            auto child = visit(term.arg(i));
            graph.edge(child, node, commutative(term.decl().decl_kind()) ? -1 : int(i));
        }
        return node;
    };
    auto ret = visit(result);
    auto ret_root = graph.node("observed return");
    graph.edge(ret, ret_root, 0);
    auto ram = visit(memory);
    auto ram_root = graph.node("observed RAM");
    graph.edge(ram, ram_root, 0);
    return graph;
}
inline std::vector<z3::expr> variables(const z3::expr &root) {
    std::vector<z3::expr> result, pending{root};
    std::unordered_set<unsigned> seen;
    while (!pending.empty()) {
        auto term = pending.back();
        pending.pop_back();
        if (!seen.insert(term.id()).second)
            continue;
        if (term.num_args() == 0 && term.decl().decl_kind() == Z3_OP_UNINTERPRETED)
            result.push_back(term);
        for (unsigned i = 0; i < term.num_args(); ++i)
            pending.push_back(term.arg(i));
    }
    return result;
}
} // namespace fibers
