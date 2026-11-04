#pragma once
#include "core.hpp"

namespace fibers {
struct Topology { size_t components,cycles; };
inline Topology topology(const Graph& graph) {
    // Underlying simple undirected graph, viewed as a 1-dimensional complex.
    std::vector<unsigned> parent(graph.vertices.size()),size(graph.vertices.size(),1);
    for(unsigned i=0;i<parent.size();++i) parent[i]=i;
    auto root=[&](unsigned node) {
        while(parent[node]!=node) {parent[node]=parent[parent[node]];node=parent[node];}
        return node;
    };
    size_t components=graph.vertices.size();std::unordered_set<uint64_t> edges;
    for(unsigned i=0;i<graph.vertices.size();++i) for(auto [slot,j]:graph.vertices[i].outgoing) {
        auto a=std::min(i,j),b=std::max(i,j);
        if(!edges.insert((uint64_t(a)<<32)|b).second) continue;
        a=root(a);b=root(b);if(a==b) continue;
        if(size[a]<size[b]) std::swap(a,b);
        parent[b]=a;size[a]+=size[b];--components;
    }
    return {components,edges.size()+components-graph.vertices.size()};
}
inline std::vector<z3::expr> add_bits(const std::vector<z3::expr>& a,const std::vector<z3::expr>& b) {
    require(a.size()==b.size()&&!a.empty(),"Bit-vector dimensions must agree");
    auto carry=a[0].ctx().bool_val(false);
    std::vector<z3::expr> sum;
    for(size_t i=0;i<a.size();++i) {
        sum.push_back((a[i]!=b[i])!=carry);
        // In F_2, addition is XOR and multiplication is AND.
        carry=((a[i]&&b[i])!=(a[i]&&carry))!=(b[i]&&carry);
    }
    return sum;
}
inline void dimension_experiment(z3::context& c,const std::filesystem::path& directory,std::ostream& report) {
    std::filesystem::create_directories(directory);
    auto x=c.bv_const("lift_x",8);
    std::vector<z3::expr> xbits,twice,four_times,constant;
    for(unsigned i=0;i<11;++i) {
        xbits.push_back(i<8 ? x.extract(i,i)==c.bv_val(1,1) : c.bool_val(false));
        twice.push_back(i>=1 && i-1<8 ? x.extract(i-1,i-1)==c.bv_val(1,1) : c.bool_val(false));
        four_times.push_back(i>=2 && i-2<8 ? x.extract(i-2,i-2)==c.bv_val(1,1) : c.bool_val(false));
        constant.push_back(c.bool_val(i==2));
    }
    const auto full=add_bits(add_bits(twice,four_times),constant);
    auto field_constraint=c.bool_val(true);
    for(unsigned i=0;i<8;++i) field_constraint=field_constraint && (full[i]==c.bool_val((22u>>i)&1u));
    auto modular_constraint=6*x+4==22;
    require(query(field_constraint!=modular_constraint,{x},5000,directory/"field_ring_equivalence.smt2").status=="unsat",
            "F2 circuit and modular model disagree");
    // A real-coordinate embedding at hypercube vertices; this retains bit constraints.
    auto real_x=c.real_val(0),real_k=c.real_val(0);
    for(unsigned i=0;i<8;++i) real_x=real_x+z3::ite(xbits[i],c.real_val(uint64_t(1)<<i),c.real_val(0));
    for(unsigned i=8;i<11;++i) real_k=real_k+z3::ite(full[i],c.real_val(uint64_t(1)<<(i-8)),c.real_val(0));
    auto real_constraint=6*real_x+4==22+256*real_k;
    require(query(real_constraint!=modular_constraint,{x},5000,directory/"real_ring_equivalence.smt2").status=="unsat",
            "Constrained real embedding and modular model disagree");
    auto ring_fiber=enumerate(modular_constraint,{x}),field_fiber=enumerate(field_constraint,{x}),
         real_fiber=enumerate(real_constraint,{x});
    for(auto* fiber:{&ring_fiber,&field_fiber,&real_fiber}) {
        std::sort(fiber->points.begin(),fiber->points.end());
        require(fiber->complete&&fiber->points==std::vector<std::vector<uint64_t>>{{3},{131}},"Embedding changed the fiber");
    }
    auto full_word=6*z3::zext(x,3)+4;
    auto k=full_word.extract(10,8);
    auto low_k=enumerate(modular_constraint&&k==0,{x});
    auto high_k=enumerate(modular_constraint&&k==3,{x});
    require(low_k.complete&&low_k.points==std::vector<std::vector<uint64_t>>{{3}} &&
            high_k.complete&&high_k.points==std::vector<std::vector<uint64_t>>{{131}},"Overflow observation failed to separate inputs");
    auto other=c.bv_const("lift_other",8);
    require(query((6*z3::zext(x,3)+4==6*z3::zext(other,3)+4)&&(x!=other),{x,other},5000,
                  directory/"augmented_injectivity.smt2").status=="unsat","Augmented map injectivity failed");
    // Relaxing discrete coordinates admits extra solutions. Record a concrete one.
    auto relaxed_k=c.real_const("relaxed_k");
    auto spurious=query((6*c.real_val(4)+4==22+256*relaxed_k)&&relaxed_k>=0&&relaxed_k<=5);
    require(spurious.status=="sat"&&query(modular_constraint&&x==4).status=="unsat","Expected relaxation boundary case");
    Graph cycle,triangles;
    for(unsigned i=0;i<6;++i){cycle.node("v");triangles.node("v");}
    for(unsigned i=0;i<6;++i) cycle.edge(i,(i+1)%6);
    for(auto [a,b]:std::vector<std::pair<unsigned,unsigned>>{{0,1},{1,2},{2,0},{3,4},{4,5},{5,3}}) triangles.edge(a,b);
    // Use both edge directions so that the directed WL test sees regular undirected graphs.
    Graph symmetric_cycle=cycle,symmetric_triangles=triangles;
    for(unsigned i=0;i<cycle.vertices.size();++i) for(auto [slot,j]:cycle.vertices[i].outgoing) symmetric_cycle.edge(j,i);
    for(unsigned i=0;i<triangles.vertices.size();++i) for(auto [slot,j]:triangles.vertices[i].outgoing) symmetric_triangles.edge(j,i);
    require(refine(symmetric_cycle,symmetric_triangles).indistinguishable,"Expected WL ambiguity");
    auto first=topology(cycle),second=topology(triangles);
    require(first.components==1&&first.cycles==1&&second.components==2&&second.cycles==2,"Topological invariants disagree");
    report<<"Dimension experiment: ring, F2 carry circuit and constrained real embedding all give {3,131}.\n"
          <<"Augmented observation (return byte, overflow quotient) is injective on x in [0,255].\n"
          <<"  (22,0) -> 3; (22,3) -> 131; x=(y+256*k-4)/6 on this image.\n"
          <<"  The quotient is an additional observation, not inferred from the return byte.\n"
          <<"Continuous relaxation alone admits x=4, k=3/128; discrete validation rejects it.\n"
          <<"Topology: 1-WL cannot distinguish C6 and two triangles with these labels;\n"
          <<"  graph-complex (beta0,beta1) distinguishes (1,1) from (2,2). Triangles are not filled faces.\n";
}
} // namespace fibers
