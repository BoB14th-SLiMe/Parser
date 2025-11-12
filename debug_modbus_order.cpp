#include <iostream>
#include <string>

int main() {
    // Simulating the loop
    int num_registers = 3;
    uint16_t start_addr = 12;
    
    std::cout << "Register processing order:" << std::endl;
    for (int i = 0; i < num_registers; ++i) {
        uint16_t reg_addr = start_addr + i;
        std::cout << "i=" << i << " -> reg_addr=" << reg_addr << std::endl;
    }
    
    return 0;
}
