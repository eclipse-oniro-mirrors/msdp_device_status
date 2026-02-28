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

#ifndef DEVICESTATUS_CALLBACK_STUB_H
#define DEVICESTATUS_CALLBACK_STUB_H

#include <iremote_stub.h>
#include <nocopyable.h>

#include "message_option.h"
#include "message_parcel.h"

#include "iremote_dev_sta_callback.h"
#include "stationary_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DeviceStatusCallbackStub : public IRemoteStub<IRemoteDevStaCallback> {
public:
    DeviceStatusCallbackStub() = default;
    DISALLOW_COPY_AND_MOVE(DeviceStatusCallbackStub);
    virtual ~DeviceStatusCallbackStub() = default;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    void OnDeviceStatusChanged(const Data &value) override {}

private:
    int32_t OnDeviceStatusChangedStub(MessageParcel &data);
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DEVICESTATUS_CALLBACK_STUB_H
