//
// Created by Suhabe Bugrara on 12/19/22.
//
#include "tracing.hpp"
#include <vector>

namespace silkworm {
std::vector<ValueTracer*> value_tracers_;

void tracer_add(ValueTracer* tracer) {
    value_tracers_.push_back(tracer);
}

void tracer_on_value(const std::string& phaseName, const std::string& valueName, const std::string& value) {
    if (!value_tracers_.empty()) {
        for (auto tracer : value_tracers_) {
            tracer->on_value(phaseName, valueName, value);
        }
    }
}

void tracer_clear() {
    value_tracers_.clear();
}

}