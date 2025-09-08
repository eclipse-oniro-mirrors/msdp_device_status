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

#ifndef DEVICESTATUS_SRV_STUB_H
#define DEVICESTATUS_SRV_STUB_H

#include <functional>
#include <map>

#include <iremote_stub.h>
#include <nocopyable.h>

#include "i_devicestatus.h"
#include "message_option.h"
#include "message_parcel.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DeviceStatusSrvStub : public IRemoteStub<Idevicestatus> {
public:
    DeviceStatusSrvStub();
    DISALLOW_COPY_AND_MOVE(DeviceStatusSrvStub);
    virtual ~DeviceStatusSrvStub() = default;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DEVICESTATUS_SRV_STUB_H
