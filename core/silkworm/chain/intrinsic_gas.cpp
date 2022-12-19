/*
   Copyright 2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "intrinsic_gas.hpp"

#include <algorithm>

#include <silkworm/common/as_range.hpp>
#include <silkworm/common/tracing.hpp>
#include <silkworm/common/util.hpp>

#include "protocol_param.hpp"

namespace silkworm {


intx::uint128 intrinsic_gas(const Transaction& txn, bool homestead, bool istanbul) noexcept {
    intx::uint128 gas{fee::kGTransaction};
    tracer_on_value("EVM::intrinsic_gas 0", "gas", "0x" + hex(gas));


    if (!txn.to && homestead) {
        gas += fee::kGTxCreate;
        tracer_on_value("EVM::intrinsic_gas 1", "gas", "0x" + hex(gas));
    }

    // https://eips.ethereum.org/EIPS/eip-2930
    gas += intx::uint128{txn.access_list.size()} * fee::kAccessListAddressCost;
    tracer_on_value("EVM::intrinsic_gas 2", "gas", "0x" + hex(gas));
    for (const AccessListEntry& e : txn.access_list) {
        gas += intx::uint128{e.storage_keys.size()} * fee::kAccessListStorageKeyCost;
        tracer_on_value("EVM::intrinsic_gas 3", "gas", "0x" + hex(gas));
    }

    if (txn.data.empty()) {
        tracer_on_value("EVM::intrinsic_gas 4", "gas", "0x" + hex(gas));
        return gas;
    }

    intx::uint128 non_zero_bytes{as_range::count_if(txn.data, [](char c) { return c != 0; })};
    tracer_on_value("EVM::intrinsic_gas 5", "non_zero_bytes", "0x" + hex(non_zero_bytes));

    uint64_t nonZeroGas{istanbul ? fee::kGTxDataNonZeroIstanbul : fee::kGTxDataNonZeroFrontier};
    tracer_on_value("EVM::intrinsic_gas 6", "nonZeroGas", hexu64(nonZeroGas));

    gas += non_zero_bytes * nonZeroGas;
    tracer_on_value("EVM::intrinsic_gas 7", "gas", "0x" + hex(gas));

    intx::uint128 zero_bytes{txn.data.length() - non_zero_bytes};
    tracer_on_value("EVM::intrinsic_gas 8", "zero_bytes", "0x" + hex(zero_bytes));
    gas += zero_bytes * fee::kGTxDataZero;
    tracer_on_value("EVM::intrinsic_gas 9", "gas", "0x" + hex(gas));

    return gas;
}

}  // namespace silkworm
