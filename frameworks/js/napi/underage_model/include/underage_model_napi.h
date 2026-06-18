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

#ifndef UNDERAGE_MODEL_NAPI_H
#define UNDERAGE_MODEL_NAPI_H

#include "underage_model_napi_event.h"

#include <array>

#include "device_info.h"
#include "iunderage_model_listener.h"
#include "user_status_data.h"
#include "user_status_napi_util.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using DeviceInfo = UserStatusAwareness::DeviceInfo;
using UserStatusData = UserStatusAwareness::UserStatusData;
using UserStatusNapiUtil = UserStatusAwareness::UserStatusNapiUtil;

typedef int32_t (*RegisterListenerFunc)(uint32_t feature,
    std::shared_ptr<UserStatusAwareness::IUnderageModelListener> listener);
typedef int32_t (*SubscribeCallbackFunc)(uint32_t feature,
    UserStatusAwareness::UserStatusDataCallbackFunc& callback);
typedef int32_t (*SubscribeFunc)(uint32_t feature);
typedef int32_t (*SubscribeWithdeviceInfoFunc)(uint32_t feature, const std::vector<DeviceInfo> &deviceInfo);
typedef int32_t (*UnsubscribeFunc)(uint32_t feature);
typedef int32_t (*ConfigParamsFunc)(uint32_t feature, const std::map<std::string, std::vector<int32_t>>& detail);
typedef int32_t (*QueryCapabilitiesFunc)(std::vector<std::int32_t>& capabilities);

class UnderageModelListener : public UserStatusAwareness::IUnderageModelListener {
public:
    explicit UnderageModelListener(napi_env env) : env_(env) {}
    ~UnderageModelListener() {};
    void OnUnderageModelListener(uint32_t eventType, int32_t result, float confidence) const override;

private:
    napi_env env_;
};

class UserStatusDataCallback {
public:
    explicit UserStatusDataCallback(napi_env env) : env_(env) {}
    ~UserStatusDataCallback() {};
    void OnReceiveData(int32_t callbackId, std::shared_ptr<UserStatusData> userStatusData);

private:
    napi_env env_;
};

class UnderageModelNapi : public UnderageModelNapiEvent {
public:
    UnderageModelNapi(napi_env env, napi_value thisVar);
    ~UnderageModelNapi() override;

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value SubscribeUnderageModel(napi_env env, napi_callback_info info);
    static napi_value UnsubscribeUnderageModel(napi_env env, napi_callback_info info);
    static napi_value SubscribeUserStatus(napi_env env, napi_callback_info info);
    static napi_value UnsubscribeUserStatus(napi_env env, napi_callback_info info);
    static napi_value ConfigParams(napi_env env, napi_callback_info info);
    static napi_value QueryCapabilities(napi_env env, napi_callback_info info);

protected:
    std::map<uint32_t, std::shared_ptr<UserStatusAwareness::IUnderageModelListener>> callbacks_;

private:
    static bool ValidateAndGetDeviceInfo(napi_env env, napi_value arg, std::vector<DeviceInfo>& deviceInfoList);
    static bool InitializeCallback(napi_env env, uint32_t featureId);
    static bool SubscribeWithDeviceInfo(napi_env env, uint32_t featureId,
        const std::vector<DeviceInfo>& deviceInfoList);
    static bool ValidateAndParseParams(napi_env env, napi_value args[], uint32_t& featureId,
        std::map<std::string, std::vector<int32_t>>& details);
    static bool ValidateAndParseArgs(napi_env env, napi_value args[], std::vector<int32_t>& caps);
    static int32_t HandleQueryCapabilities(napi_env env, std::vector<int32_t>& caps);
    static bool LoadLibrary();
    static uint32_t GetUnderageModelType(const std::string &type);
    static bool SubscribeCallback(napi_env env, uint32_t type);
    static bool UnsubscribeCallback(napi_env env, uint32_t type);
    static bool Subscribe(napi_env env, uint32_t type);
    static bool RemoveCallbackArgs(uint32_t type, size_t argc, napi_value args[]);
    static bool ConstructUnderageModel(napi_env env, napi_value jsThis);
    static napi_value CreateAgeGroupObject(napi_env env, napi_handle_scope scope);
    static napi_value CreateDeviceTypeObject(napi_env env, napi_handle_scope scope);
    static napi_value CreateUserStatusFeatureObject(napi_env env, napi_handle_scope scope);
    static napi_value CreateUserStatusAtomicCapObject(napi_env env, napi_handle_scope scope);
    static napi_value CreateReminderLevelObject(napi_env env, napi_handle_scope scope);
    static bool CreateUserAgeGroup(napi_env env, napi_value exports);
    template <std::size_t N>
    static bool ValidateArgsType(napi_env env, napi_value *args, size_t argc,
        const std::array<napi_valuetype, N> &expectedTypes);
    static bool TransJsToStr(napi_env env, napi_value value, std::string &str);
    static bool ParseConfigParams(const std::string& params, std::map<std::string, std::vector<int32_t>> &configMap);
    static bool GetDeviceList(napi_env env, napi_value deviceNapiValue, std::vector<DeviceInfo>& deviceInfoList);
    static bool GetDeviceInfoItem(napi_env env, napi_value value, const char *tag, std::string& result);

private:
    napi_env env_ { nullptr };
    void* g_userStatusHandle { nullptr };
    int32_t g_callbackId { 0 };
    UserStatusAwareness::UserStatusDataCallbackFunc g_callback { nullptr };
    RegisterListenerFunc g_registerListenerFunc { nullptr };
    SubscribeCallbackFunc g_subscribeCallbackFunc { nullptr };
    SubscribeFunc g_subscribeFunc { nullptr };
    SubscribeWithdeviceInfoFunc g_subscribeWithdeviceInfoFunc { nullptr };
    UnsubscribeFunc g_unsubscribeFunc { nullptr };
    ConfigParamsFunc g_configParamsFunc { nullptr };
    QueryCapabilitiesFunc g_queryCapabilitiesFunc { nullptr };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // UNDERAGE_MODEL_NAPI_H