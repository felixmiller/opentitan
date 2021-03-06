// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include <fstream>
#include <iomanip>
#include <iostream>
#include <svdpi.h>

#include "verilated_toplevel.h"
#include "verilator_memutil.h"
#include "verilator_sim_ctrl.h"

extern "C" {
extern unsigned int otbn_base_reg_get(int index);
extern unsigned int otbn_bignum_reg_get(int index, int quarter);
}

int main(int argc, char **argv) {
  otbn_top_sim top;
  VerilatorMemUtil memutil;
  VerilatorSimCtrl &simctrl = VerilatorSimCtrl::GetInstance();
  simctrl.SetTop(&top, &top.IO_CLK, &top.IO_RST_N,
                 VerilatorSimCtrlFlags::ResetPolarityNegative);

  MemAreaLoc imem_loc = {.base = 0x100000, .size = 4096};
  MemAreaLoc dmem_loc = {.base = 0x200000, .size = 4096};

  memutil.RegisterMemoryArea(
      "dmem", "TOP.otbn_top_sim.u_dmem.u_mem.gen_generic.u_impl_generic", 256,
      &dmem_loc);
  memutil.RegisterMemoryArea(
      "imem", "TOP.otbn_top_sim.u_imem.u_mem.gen_generic.u_impl_generic", 32,
      &imem_loc);
  simctrl.RegisterExtension(&memutil);

  bool exit_app = false;
  int ret_code = simctrl.ParseCommandArgs(argc, argv, exit_app);
  if (exit_app) {
    return ret_code;
  }

  std::cout << "Simulation of OTBN" << std::endl
            << "==================" << std::endl
            << std::endl;

  simctrl.RunSimulation();

  if (!simctrl.WasSimulationSuccessful()) {
    return 1;
  }

  svSetScope(svGetScopeFromName("TOP.otbn_top_sim"));

  svBit model_err = otbn_err_get();
  if (model_err) {
    return 1;
  }

  std::cout << "Final Base Register Values:" << std::endl;
  std::cout << "Reg | Value" << std::endl;
  std::cout << "----------------" << std::endl;
  for (int i = 1; i < 32; ++i) {
    std::cout << "x" << std::left << std::dec << std::setw(2)
              << std::setfill(' ') << i << " | 0x" << std::hex << std::setw(8)
              << std::setfill('0') << std::right << otbn_base_reg_get(i)
              << std::endl;
  }

  std::cout << std::endl;

  std::cout << "Final Bignum Register Values:" << std::endl;
  std::cout << "Reg | Value" << std::endl;
  std::cout << "---------------------------------------------------------------"
               "----------------"
            << std::endl;

  for (int i = 0; i < 32; ++i) {
    std::cout << "w" << std::left << std::dec << std::setw(2)
              << std::setfill(' ') << i << " | 0x" << std::hex;

    std::cout << std::setw(8) << std::setfill('0') << std::right
              << otbn_bignum_reg_get(i, 7) << "_";

    std::cout << std::setw(8) << std::setfill('0') << otbn_bignum_reg_get(i, 6)
              << "_";

    std::cout << std::setw(8) << std::setfill('0') << otbn_bignum_reg_get(i, 5)
              << "_";

    std::cout << std::setw(8) << std::setfill('0') << otbn_bignum_reg_get(i, 4)
              << "_";

    std::cout << std::setw(8) << std::setfill('0') << otbn_bignum_reg_get(i, 3)
              << "_";

    std::cout << std::setw(8) << std::setfill('0') << otbn_bignum_reg_get(i, 2)
              << "_";

    std::cout << std::setw(8) << std::setfill('0') << otbn_bignum_reg_get(i, 1)
              << "_";

    std::cout << std::setw(8) << std::setfill('0') << otbn_bignum_reg_get(i, 0)
              << std::endl;
  }

  return 0;
}
