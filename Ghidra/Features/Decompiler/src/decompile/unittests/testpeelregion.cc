#include "architecture.hh"
#include "grammar.hh"
#include "ruleaction.hh"
#include "test.hh"

namespace ghidra {
class PeelEnvironment {
  Architecture *arch;
public:
  PeelEnvironment() : arch((Architecture *)0) {}
  ~PeelEnvironment() { delete arch; }
  Architecture *get() {
    if (arch != (Architecture *)0) return arch;
    ArchitectureCapability *cap=ArchitectureCapability::getCapability("xml");
    istringstream xml("<binaryimage arch=\"x86:LE:64:default:gcc\"></binaryimage>");
    DocumentStorage store;
    Document *doc=store.parseDocument(xml);
    store.registerTag(doc->getRoot());
    arch=cap->buildArchitecture("", "", &cout);
    arch->init(store);
    return arch;
  }
};
static PeelEnvironment peelEnvironment;

struct PeelFixture {
  Funcdata *data;
  BlockGraph graph;
  BlockBasic *root,*arms[3],*join;
  PcodeOp *phi,*defs[3];
  Varnode *x,*output;
  PeelFixture(int variant) {
    Architecture *g=peelEnvironment.get();
    static uintb addrOffset=0x2000;
    Address addr(g->getDefaultCodeSpace(),addrOffset);
    addrOffset+=0x100;
    ostringstream name; name << "peel_fixture_" << addrOffset;
    data=g->symboltab->getGlobalScope()->addFunction(addr,name.str())->getFunction();
    const VarnodeData &reg=g->translate->getRegister("EAX");
    x=data->setInputVarnode(data->newVarnode(reg.size,reg.space,reg.offset));
    root=graph.newBlockBasic(data);
    for(int i=0;i<3;++i) arms[i]=graph.newBlockBasic(data);
    join=graph.newBlockBasic(data);
    for(int i=0;i<3;++i) { graph.addEdge(root,arms[i]); graph.addEdge(arms[i],join); }
    vector<FlowBlock *> roots(1,root);
    graph.calcForwardDominator(roots);
    for(int i=0;i<3;++i) {
      defs[i]=data->newOp(2,addr);
      data->opSetOpcode(defs[i],variant==1 && i==1 ? CPUI_INT_XOR : CPUI_INT_ADD);
      data->opSetInput(defs[i],x,0);
      data->opSetInput(defs[i],data->newConstant(4,variant==2 && i==1 ? 2 : 1),1);
      data->newUniqueOut(4,defs[i]);
      data->opInsertEnd(defs[i],arms[i]);
    }
    phi=data->newOp(3,addr);
    data->opSetOpcode(phi,CPUI_MULTIEQUAL);
    for(int i=0;i<3;++i) data->opSetInput(phi,defs[i]->getOut(),i);
    output=data->newUniqueOut(4,phi);
    data->opInsertBegin(phi,join);
    if (variant==3) {
      PcodeOp *extra=data->newOp(1,addr);
      data->opSetOpcode(extra,CPUI_COPY);
      data->opSetInput(extra,defs[1]->getOut(),0);
      data->newUniqueOut(4,extra);
      data->opInsertEnd(extra,arms[1]);
    }
    if (variant==4) {
      PcodeOp *effect=data->newOp(1,addr);
      data->opSetOpcode(effect,CPUI_CALL);
      data->opSetInput(effect,data->newConstant(8,0),0);
      data->opInsertEnd(effect,arms[1]);
    }
    if (variant==5) graph.addEdge(arms[0],arms[0]);
    if (variant==6) graph.addEdge(join,root);
  }
};

TEST(peel_multi_region_factors) {
  PeelFixture fixture(0);
  RulePeelMultiRegion rule("nodejoin");
  ASSERT_EQUALS(rule.applyOp(fixture.phi,*fixture.data),1);
  ASSERT(fixture.output->getDef()==fixture.defs[0]);
  ASSERT(fixture.defs[0]->getParent()==fixture.join);
  ASSERT(fixture.defs[0]->code()==CPUI_INT_ADD);
  ASSERT(fixture.defs[0]->getIn(0)==fixture.x);
  ASSERT_EQUALS(fixture.defs[0]->getIn(1)->getOffset(),1);
  ASSERT_EQUALS(fixture.root->sizeOut(),3);
  ASSERT_EQUALS(fixture.join->sizeIn(),3);
}
TEST(peel_multi_region_action_pool) {
  PeelFixture fixture(0);
  Architecture *g=peelEnvironment.get();
  ASSERT(g->allacts.getCurrent() != (Action *)0);
  ASSERT(g->allacts.getCurrent()->getSubRule("peel_multi_region") != (Rule *)0);
  ActionPool baseline(Action::rule_repeatapply,"baseline-test");
  baseline.reset(*fixture.data);
  baseline.perform(*fixture.data);
  ASSERT(fixture.output->getDef()==fixture.phi);
  ActionPool pool(Action::rule_repeatapply,"peel-test");
  pool.addRule(new RulePeelMultiRegion("nodejoin"));
  pool.reset(*fixture.data);
  pool.perform(*fixture.data);
  ASSERT(fixture.output->getDef()==fixture.defs[0]);
  ASSERT(fixture.defs[0]->getParent()==fixture.join);
}
TEST(peel_multi_region_rejects) {
  RulePeelMultiRegion rule("nodejoin");
  for(int variant=1;variant<=6;++variant) {
    PeelFixture fixture(variant);
    ASSERT_EQUALS(rule.applyOp(fixture.phi,*fixture.data),0);
    ASSERT(fixture.output->getDef()==fixture.phi);
    ASSERT(fixture.phi->code()==CPUI_MULTIEQUAL);
  }
}
}
