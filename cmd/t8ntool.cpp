#include <iostream>

#include <CLI/CLI.hpp>
#include <magic_enum.hpp>

#include <silkworm/common/directories.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/execution/processor.hpp>
#include <silkworm/state/in_memory_state.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/common/tracing.hpp>

#include "evmone/tracing.hpp"
#include "evmone/instructions_traits.hpp"

using namespace silkworm;
using namespace nlohmann;


class T8nTracer : public EvmTracer {
    struct Context
    {
        const uint8_t* const code;  ///< Reference to the code being executed.
        const int64_t start_gas;

        Context(const uint8_t* c, int64_t g) noexcept : code{c}, start_gas{g} {}
    };

    const char* const* m_opcode_names = nullptr;
    std::stack<Context> m_contexts;


  public:
    T8nTracer(std::ofstream& _file, std::optional<evmc::address> contract_address = std::nullopt,
               std::optional<evmc::bytes32> key = std::nullopt)
        : file(_file), contract_address_(contract_address), key_(key) {}

    std::string get_name(const char* const* names, uint8_t opcode)
    {
        const auto name = names[opcode];
        return (name != nullptr) ? name : "0x" + evmc::hex(opcode);
    }

    void on_value(const std::string& phaseName, const std::string& valueName, const std::string& value) noexcept override {
        json r;
        r["type"] = "SwValue";
        r["phase"] = phaseName;
        r["name"] = valueName;
        r["value"] = value;
        file << r << std::endl;
        std::cout <<" \033[33m"  <<  r << " \033[39m" << std::endl;
    }

    void on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept override {

        if (m_contexts.empty())
            m_opcode_names = evmc_get_instruction_names_table(rev);
        m_contexts.emplace(code.data(), msg.gas);

        json r;
        r["type"] = "SwExecutionStart";
        r["code"] = to_hex(code, true);
        r["recipient"] = to_hex(msg.recipient.bytes, true);
        r["gas"] = hexu64(static_cast<uint64_t>(msg.gas));
        file << r << std::endl;
        std::cout <<" \033[33m"  <<  r << " \033[39m" << std::endl;
    }

    void on_instruction_start(uint32_t pc, const intx::uint256* stack_top, int stack_height,
                              const evmone::ExecutionState& state,
                              const IntraBlockState& intra_block_state) noexcept override {

        intra_block_state.number_of_self_destructs();
        const auto& ctx = m_contexts.top();
        const auto opcode = ctx.code[pc];

        json r;
        r["type"] = "SwInstructionStart";
        r["pc"] = pc;
        r["opcode"] = get_name(m_opcode_names, opcode);
        r["gas_left"] = hexu64(static_cast<uint64_t>(state.gas_left));
        if (stack_height > 0) {
            r["stack_top"] = "0x" + hex(*stack_top);
        }
        r["stack_height"] = static_cast<uint64_t>(stack_height);

        file << r << std::endl;
        std::cout <<" \033[33m"  <<  r << " \033[39m" << std::endl;
    }

    void on_execution_end(const evmc_result& res, const IntraBlockState& intra_block_state) noexcept override {
        //const auto& ctx = m_contexts.top();
        intra_block_state.number_of_self_destructs();

        json r;
        r["type"] = "SwExecutionEnd";
        r["status_code"] = hexu64(static_cast<uint64_t>(res.status_code));
        file << r << std::endl;
        std::cout <<" \033[33m"  <<  r << " \033[39m" << std::endl;

        m_contexts.pop();
        if (m_contexts.empty())
            m_opcode_names = nullptr;
    }

    void on_precompiled_run(const evmc_result& /*result*/, int64_t /*gas*/,
                            const IntraBlockState& /*intra_block_state*/) noexcept override {}

    void on_reward_granted(const CallResult& /*result*/,
                           const IntraBlockState& /*intra_block_state*/) noexcept override {}

    bool execution_start_called() const { return execution_start_called_; }
    bool execution_end_called() const { return execution_end_called_; }
    const Bytes& bytecode() const { return bytecode_; }
    const evmc_revision& rev() const { return rev_; }
    const evmc_message& msg() const { return msg_; }
    const std::vector<uint32_t>& pc_stack() const { return pc_stack_; }
    const std::map<uint32_t, std::size_t>& memory_size_stack() const { return memory_size_stack_; }
    const std::map<uint32_t, evmc::bytes32>& storage_stack() const { return storage_stack_; }
    const CallResult& result() const { return result_; }

  private:

    std::ofstream& file;
    bool execution_start_called_{false};
    bool execution_end_called_{false};
    std::optional<evmc::address> contract_address_;
    std::optional<evmc::bytes32> key_;
    evmc_revision rev_;
    evmc_message msg_;
    Bytes bytecode_;
    std::vector<uint32_t> pc_stack_;
    std::map<uint32_t, std::size_t> memory_size_stack_;
    std::map<uint32_t, evmc::bytes32> storage_stack_;
    CallResult result_;
};

std::string strip_leading_zeros(std::string s) {
    size_t new_start = 0;
    while (new_start < s.length() - 1 && s[new_start] == '0') {
        new_start++;
    }
    return s.substr(new_start, s.length() - new_start);
}

std::string validation_error_str(silkworm::ValidationResult err) {
    using namespace silkworm;

    switch (err) {
        case ValidationResult::kIntrinsicGas:
            return "TR_IntrinsicGas";
        case ValidationResult::kInvalidSignature:
            return "InvalidSignature";
        case ValidationResult::kMaxPriorityFeeGreaterThanMax:
            return "TR_TipGtFeeCap";
        case ValidationResult::kMaxFeeLessThanBase:
            return "TR_FeeCapLessThanBlocks";
        case ValidationResult::kUnsupportedTransactionType:
            return "TR_TypeNotSupported";
        case ValidationResult::kWrongChainId:
            return "WrongChainId";
        case ValidationResult::kWrongOmmersHash:
            return "kWrongOmmersHash";
        case ValidationResult::kWrongTransactionsRoot:
            return "kWrongTransactionsRoot";
        case ValidationResult::kTooManyOmmers:
            return "kTooManyOmmers";
        case ValidationResult::kInvalidOmmerHeader:
            return "kInvalidOmmerHeader";
        case ValidationResult::kNotAnOmmer:
            return "kNotAnOmmer";
        case ValidationResult::kDuplicateOmmer:
            return "kDuplicateOmmer";
        case ValidationResult::kGasAboveLimit:
            return "kGasAboveLimit";
        case ValidationResult::kInvalidGasLimit:
            return "kInvalidGasLimit";
        case ValidationResult::kExtraDataTooLong:
            return "kExtraDataTooLong";
        case ValidationResult::kUnknownParent:
            return "kUnknownParent";
        case ValidationResult::kInvalidTimestamp:
            return "kInvalidTimestamp";
        case ValidationResult::kWrongDifficulty:
            return "kWrongDifficulty";
        case ValidationResult::kWrongDaoExtraData:
            return "kWrongDaoExtraData";
        case ValidationResult::kWrongBaseFee:
            return "kWrongBaseFee";
        case ValidationResult::kInvalidSeal:
            return "kInvalidSeal";
        case ValidationResult::kInsufficientFunds:
            return "TR_NoFunds";
        case ValidationResult::kBlockGasLimitExceeded:
            return "TR_GasLimitReached";
        case ValidationResult::kSenderNoEOA:
            return "kSenderNoEOA";
        default:
            printf("couldn't get string for: %d\n", static_cast<int>(err));
            exit(static_cast<int>(err));
    }
}

nlohmann::json to_constant_bytes(std::string s, uint64_t length) {
    using namespace nlohmann;

    json bytes0;
    bytes0["index"] = 0;
    bytes0["constant"] = s;
    bytes0["length"] = length;

    json bytesArray = json::array();
    bytesArray.push_back(bytes0);

    json res;
    res["bytes"] = bytesArray;

    return res;
}

std::string from_constant_bytes(nlohmann::json o) {
    using namespace nlohmann;
    auto bytesValue = o.at("bytes");
    assert(bytesValue.size() == 1);
    auto bytes = bytesValue.at(0);
    auto length =  bytes.at("length");
    auto constant = bytes.at("constant").get<std::string>();
    return constant;
}

void execute_block_no_post_validation(ExecutionProcessor& processor, EVM& evm, std::vector<json>& receipts) {
    uint64_t txi = 0;
    for (const Transaction& txn : evm.block().transactions) {
        json r;
        r["transactionIndex"] = hexu64(txi);

        ValidationResult err = consensus::pre_validate_transaction(txn, evm.block().header.number, evm.config(), evm.block().header.base_fee_per_gas);
        if (err != ValidationResult::kOk) {
            std::cout << "prevalidation failed" << std::endl;
            r["exception"] = validation_error_str(err);
            r["status"] = hexu64(0);
            r["cumulativeGasUsed"] = to_constant_bytes(hexu64(0), 8);
            receipts.push_back(r);
            continue;
        }

        err = processor.validate_transaction(txn);
        if (err != ValidationResult::kOk) {
            std::cout << "validation failed" << std::endl;
            r["exception"] = validation_error_str(err);
            r["status"] = hexu64(0);
            r["cumulativeGasUsed"] = to_constant_bytes(hexu64(0), 8);
            receipts.push_back(r);
            continue;
        }

        Receipt receipt = {};
        processor.execute_transaction(txn, receipt);
        r["status"] = hexu64(receipt.success);
        //r["cumulativeGasUsed"] = hex(receipt.cumulative_gas_used);
        r["cumulativeGasUsed"] = to_constant_bytes(hexu64(receipt.cumulative_gas_used), 8);
        if (!receipt.outputData.empty()) {
            r["outputData"] = to_constant_bytes("0x" + to_hex(receipt.outputData), receipt.outputData.size());
        }

        int logIndex = 0;
        json jlogs;
        for (const Log& log : receipt.logs) {
            json jl;
            jl["index"] = logIndex;
            jl["address"] = "0x" + to_hex(log.address);
            jl["data"] = to_constant_bytes("0x" + to_hex(log.data), log.data.size());

            int topicIndex = 0;
            json jtopics;
            for (const evmc::bytes32& topic : log.topics) {
                json jt;
                jt["index"] = topicIndex;
                jt["value"] = to_constant_bytes("0x" + to_hex(topic.bytes), 32);
                jtopics.push_back(jt);
                topicIndex++;
            }
            jl["topics"] = jtopics;
            jlogs.push_back(jl);
            logIndex++;
        }
        r["logs"] = jlogs;
        receipts.push_back(r);
        txi++;
    }
}

int main(int argc, char* argv[]) {
    using namespace silkworm;
    using namespace nlohmann;

    CLI::App cli{"Execute a t8n transition."};

    std::string pre_path{}, output_dir_path{}, output_post_path{};
    bool crosscheck = false;

    cli.add_option("--pre", pre_path, "Path to pre file")->check(CLI::ExistingFile);
    cli.add_option("--output-dir", output_dir_path, "Path to output directory")->check(CLI::ExistingDirectory);
    cli.add_option("--zevm-silkworm-crosscheck", crosscheck);

    CLI11_PARSE(cli, argc, argv);

    if (pre_path.empty()) {
        std::cerr << "ERROR: please specify a pre_path\n";
        exit(1);
    }

    log::Debug() << "Starting t8n execution: " << argc << " " << argv << "\n";
    std::cout << "pre path: " << pre_path << std::endl;
    std::cout << "output dir path: " << output_dir_path << std::endl;
    output_post_path = output_dir_path + "/post_test.json";
    std::cout << "output_post_path: " << output_post_path << std::endl;

    std::ifstream pre_stream(pre_path);
    json pre;
    pre_stream >> pre;

    json pre_env = pre.value("env", json{});

    Block block{};
    block.header.beneficiary = to_evmc_address(from_hex(pre_env.value("currentCoinbase", "0x")).value());
    block.header.difficulty = intx::from_string<intx::uint256>(pre_env.value("currentDifficulty", "0x00"));
    block.header.gas_limit = intx::from_string<uint64_t>(pre_env.value("currentGasLimit", "0x00"));
    block.header.number = intx::from_string<uint64_t>(pre_env.value("currentNumber", "0x00"));
    block.header.timestamp = intx::from_string<uint64_t>(pre_env.value("currentTimestamp", "0x00"));
    block.header.base_fee_per_gas = intx::from_string<intx::uint256>(pre_env.value("currentBaseFee", "0x00"));

    std::string state_fork = pre_env.value("currentRevision", "invalid");
    auto chain_id = intx::from_string<uint64_t>(pre_env.value("currentChainId", "-1"));

    ChainConfig kTestConfig{
        chain_id,  // chain_id
        SealEngineType::kNoProof,
    };
    evmc_revision rev = EVMC_MAX_REVISION;
    for (size_t i = EVMC_FRONTIER; i <= EVMC_MAX_REVISION; i++) {
        auto r = static_cast<evmc_revision>(i);
        if (evmc_revision_to_string(r) == state_fork) {
            rev = r;
            break;
        }
    }
    for (size_t i{EVMC_MAX_REVISION}; i > 0; --i) {
        auto r = static_cast<evmc_revision>(i);
        kTestConfig.evmc_fork_blocks[i - 1] = r <= rev ? 0 : UINT64_MAX;
    }

    InMemoryState db{};
    {
        auto engine{consensus::engine_factory(kTestConfig)};

        ExecutionProcessor processor{block, *engine, db, kTestConfig};
        IntraBlockState& state = processor.evm().state();

        json pre_alloc = pre.value("alloc", json{});
        for (json::iterator it = pre_alloc.begin(); it != pre_alloc.end(); ++it) {
            json account = it.value();
            std::string balance = from_constant_bytes(account.value("balance", json{}));

            evmc::address address = to_evmc_address(from_hex(account.value("address", "0x00")).value());
            state.add_to_balance(address, intx::from_string<intx::uint256>(balance));
            state.set_nonce(address, intx::from_string<uint64_t>(account.value("nonce", "0x00")));
            state.set_code(address, from_hex(account.value("code", "0x")).value());
            json storage = account.value("storage", json{});

            for (json::iterator sit = storage.begin(); sit != storage.end(); ++sit) {
                json kv = sit.value();
                std::string key = from_constant_bytes(kv.value("key", json{}));
                std::string value = from_constant_bytes(kv.value("value", json{}));

                evmc::bytes32 location = to_bytes32(from_hex(key).value());
                evmc::bytes32 value32 = to_bytes32(from_hex(value).value());
                state.set_storage(address, location, value32);
            }
        }

        json pre_txs = pre.value("txs", json{});
        for (auto& input_tx : pre_txs) {
            Transaction tx{};
            tx.type = static_cast<Transaction::Type>(intx::from_string<uint64_t>(input_tx.value("type", "0x00")));
            tx.nonce = intx::from_string<uint64_t>(input_tx.value("nonce", "0x00"));
            tx.gas_limit = intx::from_string<uint64_t>(input_tx.value("gas", "0x00"));
            if (input_tx.contains("to") && !input_tx.at("to").is_null()) {
                tx.to = to_evmc_address(from_hex(input_tx.value("to", "0x")).value());
            }
            // tx.from = to_evmc_address(from_hex(input_tx.value("from", "0x")).value());
            tx.from = to_evmc_address(from_hex(from_constant_bytes(input_tx.value("from", json{}))).value());
            tx.value = intx::from_string<intx::uint256>(from_constant_bytes(input_tx.value("value", json{})));
            tx.data = from_hex(from_constant_bytes(input_tx.value("input", json{}))).value();
            tx.odd_y_parity = false;
            tx.chain_id = std::nullopt;
            tx.r = 1;
            tx.s = 1;

            if (tx.type == silkworm::Transaction::Type::kEip1559) {
                tx.max_priority_fee_per_gas = intx::from_string<intx::uint256>(input_tx.value("maxPriorityFeePerGas", "0x00"));
                tx.max_fee_per_gas = intx::from_string<intx::uint256>(input_tx.value("maxFeePerGas", "0x00"));
            } else {
                auto gas_price = intx::from_string<uint64_t>(input_tx.value("gasPrice", "0x00"));
                tx.max_priority_fee_per_gas = gas_price;
                tx.max_fee_per_gas = gas_price;
            }

            json access_list = input_tx.value("accessList", json{});
            for (auto& jae : access_list) {
                AccessListEntry ae = AccessListEntry{};
                ae.account = to_evmc_address(from_hex(jae.value("address", "0x")).value());
                for (auto& as : jae.at("storageKeys")) {
                    evmc::bytes32 b = to_bytes32(from_hex(as.get<std::string>()).value());
                    ae.storage_keys.push_back(b);
                }
                tx.access_list.push_back(ae);
            }

            block.transactions.push_back(tx);
        }
        EVM& evm = processor.evm();

        if (evm.revision() < EVMC_LONDON) {
            block.header.base_fee_per_gas = {};
        }

        state.finalize_transaction();
        state.write_to_db(evm.block().header.number - 1);
        state.clear_journal_and_substate();
    }

    auto engine{consensus::engine_factory(kTestConfig)};

    ExecutionProcessor processor{block, *engine, db, kTestConfig};
    IntraBlockState& state = processor.evm().state();
    EVM& evm = processor.evm();
    std::vector<json> receipts;


    std::ofstream* file = nullptr;
    if (crosscheck) {
        file = new std::ofstream();
        file->open(output_dir_path + "/log.json");
        auto tracer = new T8nTracer(*file);
        evm.add_tracer(*tracer);
        tracer_add(tracer);
    }

    execute_block_no_post_validation(processor, evm, receipts);
    state.finalize_transaction();
    state.write_to_db(processor.evm().block().header.number);

    if (file) {
        tracer_clear();
        file->close();
    }

    json alloc(json::value_t::array);
    for (auto& kv : db.accounts()) {
        const evmc::address address = kv.first;
        const Account account = kv.second;

        std::vector<evmc::bytes32> locations;
        db.read_locations(address, account.incarnation, locations);

        if (account.balance == 0 && account.nonce == 0 && account.code_hash == kEmptyHash) {
            bool hasNonZeroStorage = false;
            for (evmc::bytes32 location : locations) {
                if (!is_zero(db.read_storage(address, account.incarnation, location))) {
                    hasNonZeroStorage = true;
                    break;
                }
            }

            if (!hasNonZeroStorage) {
                continue;
            }
        }

        json a;
        a["address"] = to_hex(address, true);
        a["balance"] = to_constant_bytes("0x" + intx::to_string(account.balance, 16), 32);
        a["nonce"] = hexu64(account.nonce);
        a["code"] = "0x" + to_hex(db.read_code(account.code_hash));

        json s(json::value_t::array);
        for (evmc::bytes32 location : locations) {
            json skv(json::value_t::object);
            skv["index"] = "0x" + strip_leading_zeros(to_hex(location));
            skv["key"] = to_constant_bytes("0x" + strip_leading_zeros(to_hex(location)), 32);
            skv["value"] =  to_constant_bytes("0x" + strip_leading_zeros(to_hex(db.read_storage(address, account.incarnation, location))), 32);
            s.push_back(skv);
        }
        a["storage"] = s;

        alloc.push_back(a);
    }

    json post;
    post["alloc"] = alloc;
    post["receipts"] = json(receipts);
    post["stateRoot"] = "0x" + to_hex(db.state_root_hash());

    std::ofstream posto(output_post_path);
    posto << std::setw(4) << post << std::endl;

    return 0;
}