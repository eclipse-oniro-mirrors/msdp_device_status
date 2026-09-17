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

#ifndef CAR_AWARENESS_SERVER_NEW_TEST_H
#define CAR_AWARENESS_SERVER_NEW_TEST_H

#include <gtest/gtest.h>

#include "devicestatus_define.h"
#include "car_awareness_type.h"
#include "car_awareness_server.h"
#include "car_awareness_callback_stub.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

class MockHapToken {
public:
    explicit MockHapToken(
        const std::string& bundle, const std::vector<std::string>& reqPerm, bool isSystemApp = true);
    ~MockHapToken();
    uint32_t mockToken_;
private:
    uint64_t selfToken_;
};

class MockNativeToken {
public:
    explicit MockNativeToken(const std::string& process);
    ~MockNativeToken();
private:
    uint64_t selfToken_;
};

class MockCarAwarenessMgr : public CarAwareness::ICarAwarenessMgr {
public:
    MockCarAwarenessMgr() : callCount_(0), lastCapability_("") {}

    int32_t Initialize() override { return RET_OK; }
    void Deinitialize() override {}
    void GetAllCapability(std::vector<std::string> &capabilities) override {}
    bool IsCapabilitySupport(const std::string &capability) override { return true; }

    int32_t OnCarAwareness(const std::string &capability, CarAwareness::CarAwarenessCallback callback,
                           const CarAwareness::CarAwarenessOptions &options = CarAwareness::CarAwarenessOptions())
                           override
    {
        callCount_++;
        lastCapability_ = capability;
        lastCallback_ = callback;
        lastOptions_ = options;
        return RET_OK;
    }

    void OffCarAwareness(const std::string &capability, CarAwareness::CarAwarenessCallback callback = nullptr,
                         const CarAwareness::CarAwarenessOptions &options = CarAwareness::CarAwarenessOptions())
                         override
    {
        callCount_++;
        lastCapability_ = capability;
        lastOptions_ = options;
    }

    int32_t UpdateSpatialActionStatus(bool isEnable) override { return RET_OK; }
    int32_t UpdateSpatialActionZone(int32_t zoneId) override { return RET_OK; }
    int32_t GetCarAwareness(const std::string &capability, const CarAwareness::CarAwarenessOptions &options,
                            std::vector<std::string> &results) override
    {
        callCount_++;
        lastCapability_ = capability;
        lastOptions_ = options;
        results.push_back(R"([{"device":"TestDevice","function":[{"function_name":"TestFunc"}]}])");
        return 0;
    }

    int32_t GetCallCount() const { return callCount_; }
    std::string GetLastCapability() const { return lastCapability_; }
    CarAwareness::CarAwarenessOptions GetLastOptions() const { return lastOptions_; }
    CarAwareness::CarAwarenessCallback GetLastCallback() const { return lastCallback_; }

private:
    int32_t callCount_;
    std::string lastCapability_;
    CarAwareness::CarAwarenessCallback lastCallback_;
    CarAwareness::CarAwarenessOptions lastOptions_;
};

class CarAwarenessServerNewTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static Security::AccessToken::AccessTokenID hapTokenId_;
    class CarAwarenessServerNewTestCallback : public CarAwarenessCallbackStub {
    public:
        void OnAwarenessEvent(const CarAwarenessEvent &event) override;
    };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif //CAR_AWARENESS_SERVER_NEW_TEST_H