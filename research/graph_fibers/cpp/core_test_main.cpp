#include "libdecomp.hh"
#include "test.hh"
#include <iostream>
int main(int argc,char **argv) {
    if(argc!=2)return 2;
    ghidra::startDecompilerLibrary(std::vector<std::string>{argv[1]});
    unsigned passed=0,total=0;
    for(auto test:ghidra::UnitTest::tests()) {
        ++total;
        try {test->func();++passed;std::cout<<"PASS "<<test->name<<std::endl;}
        catch(const ghidra::LowlevelError& e){std::cerr<<"FAIL "<<test->name<<": "<<e.explain<<std::endl;}
        catch(...){std::cerr<<"FAIL "<<test->name<<std::endl;}
    }
    std::cout<<passed<<'/'<<total<<" tests passed\n";
    return total&&passed==total?0:1;
}
