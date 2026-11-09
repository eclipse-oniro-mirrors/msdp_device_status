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

#ifndef DEVICE_STATUS_TEST_MOTION_CLIENT_H
#define DEVICE_STATUS_TEST_MOTION_CLIENT_H

#include <functional>
#include "motion_callback_stub.h"

namespace OHOS {
namespace Msdp {
// Test-only replacement selected by include-path order, following BehaviorAwarenessManagerTest.
class MotionClient {
public:
    static MotionClient &GetInstance()
    {
        static MotionClient instance;
        return instance;
    }

    int32_t SubscribeCallback(int32_t type, const sptr<IMotionCallback> &callback)
    {
        ++subscribeCalls;
        lastSubscribeType = type;
        lastCallback = callback;
        if (subscribeHook) {
            subscribeHook(callback);
        }
        return subscribeResult;
    }

    int32_t UnsubscribeCallback(int32_t type, const sptr<IMotionCallback> &callback)
    {
        ++unsubscribeCalls;
        lastUnsubscribeType = type;
        lastUnsubscribeCallback = callback;
        return unsubscribeResult;
    }

    void Reset()
    {
        subscribeResult = 0;
        unsubscribeResult = 0;
        subscribeCalls = 0;
        unsubscribeCalls = 0;
        lastSubscribeType = 0;
        lastUnsubscribeType = 0;
        lastCallback = nullptr;
        lastUnsubscribeCallback = nullptr;
        subscribeHook = nullptr;
    }

    int32_t subscribeResult {0};
    int32_t unsubscribeResult {0};
    int32_t subscribeCalls {0};
    int32_t unsubscribeCalls {0};
    int32_t lastSubscribeType {0};
    int32_t lastUnsubscribeType {0};
    sptr<IMotionCallback> lastCallback;
    sptr<IMotionCallback> lastUnsubscribeCallback;
    std::function<void(const sptr<IMotionCallback> &)> subscribeHook;
};
} // namespace Msdp
} // namespace OHOS
#endif // DEVICE_STATUS_TEST_MOTION_CLIENT_H
