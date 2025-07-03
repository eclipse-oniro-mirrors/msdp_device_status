/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef UNDERAGE_MODEL_NAPI_EVENT_H
#define UNDERAGE_MODEL_NAPI_EVENT_H

#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>

#include "napi/native_api.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
struct UnderageModelEventListener {
    std::set<napi_ref> onRefSets;
};

class UnderageModelNapiEvent {
public:
    UnderageModelNapiEvent(napi_env env, napi_value thisVar);
    virtual ~UnderageModelNapiEvent();
    bool AddCallback(uint32_t eventType, napi_value handler);
    bool CheckEvents(uint32_t eventType);
    bool RemoveAllCallback(uint32_t eventType);
    bool RemoveCallback(uint32_t eventType, napi_value handler);
    virtual void OnEventChanged(uint32_t eventType, int32_t result, float confidence);
    void ConvertUserAgeGroup(napi_value handler, int32_t result, float confidence);

private:
    bool InsertRef(std::shared_ptr<UnderageModelEventListener> listener, const napi_value &handler);
    bool IsSameValue(const napi_env &env, const napi_value &lhs, const napi_value &rhs);

private:
    napi_env env_ { nullptr };
    napi_ref thisVarRef_ { nullptr };
    std::map<uint32_t, std::shared_ptr<UnderageModelEventListener>> events_;
    std::mutex eventsMutex_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // UNDERAGE_MODEL_NAPI_EVENT_H
