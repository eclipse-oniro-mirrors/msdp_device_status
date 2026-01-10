/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MSDP_TIMER_INFO_H
#define MSDP_TIMER_INFO_H

#include <functional>
#include <sys/time.h>
#include "itimer_info.h"
#include "time_service_client.h"

namespace OHOS {
namespace Msdp {
class MsdpTimerInfo : public MiscServices::ITimerInfo {
public:
    MsdpTimerInfo() = default;
    virtual ~MsdpTimerInfo() override = default;

    static std::string Ts2Str(uint64_t timestamp);

    virtual void SetType(const int &type) override
    {
        this->type = type;
    }

    virtual void SetRepeat(bool repeat) override
    {
        this->repeat = repeat;
    }

    virtual void SetInterval(const uint64_t &interval) override
    {
        this->interval = interval;
    }

    virtual void SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent) override
    {
        this->wantAgent = wantAgent;
    }

    virtual void OnTrigger() override;

    virtual void SetCallback(std::function<void()> cb)
    {
        this->callback_ = cb;
    }

private:
    std::function<void()> callback_ = nullptr;
};
}  // namespace Msdp
}  // namespace OHOS
#endif  // MSDP_TIMER_INFO_H
