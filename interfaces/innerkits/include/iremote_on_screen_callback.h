/**
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

#ifndef IREMOTE_ON_SCREEN_CALLBACK_H
#define IREMOTE_ON_SCREEN_CALLBACK_H

#include <iremote_broker.h>
#include <iremote_object.h>

#include "on_screen_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
class IRemoteOnScreenCallback : public IRemoteBroker {
public:
    enum {
        ON_SCREEN_CHANGE = 0,
        ON_SCREEN_AWAREENSS = 1,
    };

    virtual void OnScreenChange(const std::string& changeInfo) = 0;
#ifndef DEVICE_STATUS_PHONE_STANDARD_LITE
    virtual void OnScreenAwareness(const OnscreenAwarenessInfo& info) = 0;
#endif

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.msdp.IRemoteOnScreenCallback");
};
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // IREMOTE_ON_SCREEN_CALLBACK_H