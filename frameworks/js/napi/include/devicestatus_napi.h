/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef DEVICESTATUS_NAPI_H
#define DEVICESTATUS_NAPI_H

#include <map>
#include <tuple>

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include <uv.h>

#include "devicestatus_callback_stub.h"
#include "devicestatus_event.h"
#include "stationary_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DeviceStatusCallback : public DeviceStatusCallbackStub {
public:
    explicit DeviceStatusCallback(napi_env env) : env_(env) {}
    virtual ~DeviceStatusCallback() {};
    void OnDeviceStatusChanged(const Data &devicestatusData) override;
    static void EmitOnEvent(Data* data);
private:
    napi_env env_ { nullptr };
    std::mutex mutex_;
    Data data_;
};

class DeviceStatusNapi : public DeviceStatusEvent {
public:
    explicit DeviceStatusNapi(napi_env env);
    virtual ~DeviceStatusNapi();

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value SubscribeDeviceStatus(napi_env env, napi_callback_info info);
    static napi_value SubscribeDeviceStatusCallback(napi_env env, napi_callback_info info, napi_value handler,
        int32_t type, int32_t event, int32_t latency);
    static napi_value UnsubscribeDeviceStatus(napi_env env, napi_callback_info info);
    static napi_value GetDeviceStatus(napi_env env, napi_callback_info info);
    static napi_value EnumActivityEventConstructor(napi_env env, napi_callback_info info);
    static napi_value DeclareEventTypeInterface(napi_env env, napi_value exports);
    static int32_t ConvertTypeToInt(const std::string &type);
    void OnDeviceStatusChangedDone(int32_t type, int32_t value, bool isOnce);
    static DeviceStatusNapi* GetDeviceStatusNapi();

    static std::map<int32_t, sptr<IRemoteDevStaCallback>> callbacks_;

private:
    static bool CheckArguments(napi_env env, napi_callback_info info);
    static bool IsMatchType(napi_env env, napi_value value, napi_valuetype type);
    static napi_value UnsubscribeCallback(napi_env env, int32_t type, int32_t event);
    static bool CheckGetArguments(napi_env env, napi_callback_info info);
    static std::tuple<bool, napi_value, std::string, int32_t, int32_t> CheckSubscribeParam(napi_env env,
        napi_callback_info info);
    static std::tuple<bool, napi_value, int32_t> CheckGetParam(napi_env env, napi_callback_info info);
    static napi_value GetParameters(napi_env env, size_t argc, const napi_value* args);

    static napi_ref devicestatusValueRef_;
    napi_env env_ { nullptr };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DEVICESTATUS_NAPI_H
