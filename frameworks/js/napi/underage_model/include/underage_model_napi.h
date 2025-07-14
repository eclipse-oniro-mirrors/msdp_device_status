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

#include "iunderage_model_listener.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
typedef int32_t (*RegisterListenerFunc)(uint32_t feature,
    std::shared_ptr<UserStatusAwareness::IUnderageModelListener> listener);
typedef int32_t (*SubscribeFunc)(uint32_t feature);
typedef int32_t (*UnsubscribeFunc)(uint32_t feature);

class UnderageModelListener : public UserStatusAwareness::IUnderageModelListener {
public:
    explicit UnderageModelListener(napi_env env) : env_(env) {}
    ~UnderageModelListener() {};
    void OnUnderageModelListener(uint32_t eventType, int32_t result, float confidence) const override;

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

protected:
    std::map<uint32_t, std::shared_ptr<UserStatusAwareness::IUnderageModelListener>> callbacks_;

private:
    static bool LoadLibrary();
    static uint32_t GetUnderageModelType(const std::string &type);
    static bool SubscribeCallback(napi_env env, uint32_t type);
    static bool UnsubscribeCallback(napi_env env, uint32_t type);
    static bool Subscribe(napi_env env, uint32_t type);
    static bool RemoveCallbackArgs(uint32_t type, size_t argc, napi_value args[]);
    static bool ConstructUnderageModel(napi_env env, napi_value jsThis);
    static bool CreateUserAgeGroup(napi_env env, napi_value exports);
    template <std::size_t N>
    static bool ValidateArgsType(napi_env env, napi_value *args, size_t argc,
        const std::array<napi_valuetype, N> &expectedTypes);
    static bool TransJsToStr(napi_env env, napi_value value, std::string &str);

private:
    napi_env env_ { nullptr };
    void* g_userStatusHandle { nullptr };
    RegisterListenerFunc g_registerListenerFunc { nullptr };
    SubscribeFunc g_subscribeFunc { nullptr };
    UnsubscribeFunc g_unsubscribeFunc { nullptr };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // UNDERAGE_MODEL_NAPI_H