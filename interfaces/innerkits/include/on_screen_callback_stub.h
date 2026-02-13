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

#ifndef ON_SCREEN_CALLBACK_STUB_H
#define ON_SCREEN_CALLBACK_STUB_H

#include <iremote_stub.h>
#include <nocopyable.h>
#include <string>

#include "iremote_on_screen_callback.h"
#include "message_option.h"
#include "message_parcel.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
class OnScreenCallbackStub : public IRemoteStub<IRemoteOnScreenCallback> {
public:
    OnScreenCallbackStub() = default;
    DISALLOW_COPY_AND_MOVE(OnScreenCallbackStub);
    virtual ~OnScreenCallbackStub() = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    virtual void OnScreenChange(const std::string& changeInfo) override {}
#ifndef DEVICE_STATUS_PHONE_STANDARD_LITE
    virtual void OnScreenAwareness(const OnscreenAwarenessInfo& info) override {}
#endif

private:
    int32_t OnScreenChangeStub(MessageParcel &data);
#ifndef DEVICE_STATUS_PHONE_STANDARD_LITE
    int32_t OnScreenAwarenessStub(MessageParcel &data);
#endif
};
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // ON_SCREEN_CALLBACK_STUB_H