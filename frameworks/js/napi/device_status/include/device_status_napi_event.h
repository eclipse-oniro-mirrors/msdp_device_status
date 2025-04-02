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

#ifndef DEVICE_STATUS_NAPI_EVENT_H
#define DEVICE_STATUS_NAPI_EVENT_H

#include <map>
#include <set>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "stationary_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatusV1 {
struct DeviceStatusEventListener {
    std::vector<std::pair<napi_ref, DeviceStatus::OnChangedValue>> onRefSets;
};
class DeviceStatusNapiEvent {
public:
    DeviceStatusNapiEvent(napi_env env, napi_value thisVar);
    DeviceStatusNapiEvent() = default;
    virtual ~DeviceStatusNapiEvent();
    bool AddCallback(DeviceStatus::Type eventType, napi_value handler);
    bool CheckEvents(DeviceStatus::Type eventType);
    bool RemoveCallback(DeviceStatus::Type eventType);
    bool RemoveCallback(DeviceStatus::Type eventType, napi_value handler);
    virtual void OnEvent(DeviceStatus::Type eventType, size_t argc, const DeviceStatus::Data event);
    void CreateIntData(napi_env env, napi_value status, napi_value result, std::string name, int32_t value);

protected:
    bool IsSameValue(const napi_env &env, const napi_value &lhs, const napi_value &rhs);
    bool InsertRef(std::shared_ptr<DeviceStatusEventListener> listener, const napi_value &handler);
    void ConvertEventData(napi_value handler, size_t argc, const DeviceStatus::Data event);

protected:
    napi_env env_;
    napi_ref thisVarRef_;
    std::map<DeviceStatus::Type, std::shared_ptr<DeviceStatusEventListener>> events_;
};
} // namespace DeviceStatusV1
} // namespace Msdp
} // namespace OHOS
#endif // DEVICE_STATUS_NAPI_EVENT_H
