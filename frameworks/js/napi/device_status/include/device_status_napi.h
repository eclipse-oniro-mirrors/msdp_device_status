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

#ifndef DEVICE_STATUS_NAPI_H
#define DEVICE_STATUS_NAPI_H

#include <map>
#include <uv.h>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "devicestatus_callback_stub.h"
#include "device_status_napi_event.h"
#include "iremote_dev_sta_callback.h"
#include "stationary_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatusV1 {
class DeviceStatusCallback : public DeviceStatus::DeviceStatusCallbackStub {
public:
    explicit DeviceStatusCallback(napi_env env) : env_(env) {}
    virtual ~DeviceStatusCallback() {}
    void OnDeviceStatusChanged(const DeviceStatus::Data &devicestatusData) override;
    static void EmitOnEvent(DeviceStatus::Data data);
private:
    napi_env env_;
};

class DeviceStatusNapi : public DeviceStatusNapiEvent {
public:
    explicit DeviceStatusNapi(napi_env env, napi_value thisVar);
    ~DeviceStatusNapi() override;

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value SubscribeDeviceStatus(napi_env env, napi_callback_info info);
    static napi_value UnsubscribeDeviceStatus(napi_env env, napi_callback_info info);

    std::map<DeviceStatus::Type, sptr<DeviceStatus::IRemoteDevStaCallback>> callbacks_;

private:
    static bool SubscribeCallback(napi_env env, DeviceStatus::Type type);
    static bool UnsubscribeCallback(napi_env env, DeviceStatus::Type type);
    static DeviceStatus::Type GetDeviceStatusType(const std::string &type);
    static bool ConstructDeviceStatus(napi_env env, napi_value jsThis);
    static bool ValidateArgsType(napi_env env, napi_value *args, size_t argc,
        const std::vector<std::string> &expectedTypes);
    static bool TransJsToStr(napi_env env, napi_value value, std::string &str);
    static void SetInt32Property(napi_env env, napi_value targetObj, int32_t value, const char *propName);
    static void SetPropertyName(napi_env env, napi_value targetObj, const char *propName, napi_value propValue);

    napi_env env_;
};
} // namespace DeviceStatusV1
} // namespace Msdp
} // namespace OHOS
#endif // DEVICE_STATUS_NAPI_H
