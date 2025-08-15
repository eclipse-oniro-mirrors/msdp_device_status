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

#ifndef DEVICESTATUS_MANAGER_TEST_H
#define DEVICESTATUS_MANAGER_TEST_H

#include <gtest/gtest.h>

#include "boomerang_callback_stub.h"
#include "devicestatus_callback_stub.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DeviceStatusManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    class BoomerangModuleTestCallback : public BoomerangCallbackStub {
    public:
        BoomerangModuleTestCallback() {};
        virtual ~BoomerangModuleTestCallback() {};
        void OnScreenshotResult(const BoomerangData& screentshotData) override;
        void OnNotifyMetadata(const std::string& metadata) override;
        void OnEncodeImageResult(std::shared_ptr<Media::PixelMap> pixelMap) override;
    };

    class StationaryModuleTestCallback : public DeviceStatusCallbackStub {
    public:
        StationaryModuleTestCallback() {};
        virtual ~StationaryModuleTestCallback() {};
        void OnDeviceStatusChanged(const Data &value) override;
    };
    static inline sptr<IRemoteBoomerangCallback> boomerangCallback_ = nullptr;
    static inline sptr<IRemoteDevStaCallback> stationaryCallback_ = nullptr;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DEVICESTATUS_MANAGER_TEST_H
