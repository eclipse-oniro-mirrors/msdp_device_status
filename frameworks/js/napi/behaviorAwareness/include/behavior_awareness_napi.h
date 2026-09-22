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

#ifndef BEHAVIOR_AWARENESS_NAPI_H
#define BEHAVIOR_AWARENESS_NAPI_H

#include <mutex>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "behavior_awareness_callback_stub.h"
#include "behavior_awareness_data.h"
#include "behavior_awareness_manager.h"
#include "behavior_awareness_napi_error.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {

class BehaviorAwarenessNapiCallback : public BehaviorAwarenessCallbackStub {
public:
    explicit BehaviorAwarenessNapiCallback(napi_env env) : env_(env) {}
    ~BehaviorAwarenessNapiCallback();
    void OnBehaviorAwareness(const PerceptionEventData &event) override;

    napi_ref callbackRef_ { nullptr };
    napi_env env_ { nullptr };
};

class BehaviorAwarenessNapi {
public:
    BehaviorAwarenessNapi() = default;
    ~BehaviorAwarenessNapi() = default;

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value OnPerception(napi_env env, napi_callback_info info);
    static napi_value OffPerception(napi_env env, napi_callback_info info);
    static napi_value SubmitFeedback(napi_env env, napi_callback_info info);

    static napi_value ConstructPerceptionEvent(napi_env env, const PerceptionEventData &event);

private:
    static bool IsMatchType(napi_env env, napi_value value, napi_valuetype type);
    static bool GetSubscribeOptions(napi_env env, napi_value jsOptions, SubscribeOptions &options);
    static bool GetFeedbackData(napi_env env, napi_value jsFeedback, FeedbackData &feedback);
    static bool SetStringProperty(napi_env env, napi_value targetObj, const std::string &value,
        const char *propName);
    static bool SetInt32Property(napi_env env, napi_value targetObj, int32_t value, const char *propName);
    static bool SetInt64Property(napi_env env, napi_value targetObj, int64_t value, const char *propName);
    static bool SetPropertyName(napi_env env, napi_value targetObj, const char *propName, napi_value propValue);
};
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // BEHAVIOR_AWARENESS_NAPI_H
