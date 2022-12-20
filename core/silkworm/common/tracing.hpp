#pragma once

#include <string>

namespace silkworm {

class ValueTracer {
  public:
    virtual ~ValueTracer() = default;

    virtual void on_value(const std::string& phaseName, const std::string& valueName, const std::string& value) noexcept = 0;
};

void tracer_add(ValueTracer* tracer);

void tracer_on_value(const std::string& phaseName, const std::string& valueName, const std::string& value);

void tracer_clear();

}
