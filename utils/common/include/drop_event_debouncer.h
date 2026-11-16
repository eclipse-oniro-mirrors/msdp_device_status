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

#ifndef DEVICE_STATUS_DROP_EVENT_DEBOUNCER_H
#define DEVICE_STATUS_DROP_EVENT_DEBOUNCER_H

#include <chrono>

namespace OHOS {
namespace Msdp {
// Each callback registration owns one instance, accessed only on its event thread.
class DropEventDebouncer {
public:
    bool ShouldDispatch(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) const
    {
        return !hasDropped_ || now - lastDropTime_ >= DEBOUNCE_INTERVAL;
    }

    // Record only after the callback has been dispatched successfully.
    void MarkDispatched(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now())
    {
        hasDropped_ = true;
        lastDropTime_ = now;
    }

private:
    static constexpr std::chrono::seconds DEBOUNCE_INTERVAL {2};
    bool hasDropped_ {false};
    std::chrono::steady_clock::time_point lastDropTime_ {};
};
} // namespace Msdp
} // namespace OHOS
#endif // DEVICE_STATUS_DROP_EVENT_DEBOUNCER_H
