/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

// IPC service abstraction.

#ifndef I_INTENTION_H
#define I_INTENTION_H

#include <iremote_broker.h>
#include <message_parcel.h>

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
// Abstration of services.
//
// By design, for ease of extention, all service implementations are required to
// map its functions to this collection of interface, with services identified
// by Intentions.
class IIntention : public IRemoteBroker {
public:
    // Enable the service identified by [`intention`].
    int32_t Enable(uint32_t intention, MessageParcel &data, MessageParcel &reply) = 0;
    // Disable the service identified by [`intention`].
    int32_t Disable(uint32_t intention, MessageParcel &data, MessageParcel &reply) = 0;
    // Start the service identified by [`intention`].
    int32_t Start(uint32_t intention, MessageParcel &data, MessageParcel &reply) = 0;
    // Stop the service identified by [`intention`].
    int32_t Stop(uint32_t intention, MessageParcel &data, MessageParcel &reply) = 0;
    // Add a watch of state of service, with the service identified by [`intention`],
    // the state to watch identified by [`id`], parameters packed in [`data`] parcel.
    int32_t AddWatch(uint32_t intention, uint32_t id, MessageParcel &data, MessageParcel &reply) = 0;
    // Remove a watch of state of service.
    int32_t RemoveWatch(uint32_t intention, uint32_t id, MessageParcel &data, MessageParcel &reply) = 0;
    // Set a parameter of service, with the service identified by [`intention`],
    // the parameter identified by [`id`], and values packed in [`data`] parcel.
    int32_t SetParam(uint32_t intention, uint32_t id, MessageParcel &data, MessageParcel &reply) = 0;
    // Get a parameter of service, with the service identified by [`intention`],
    // the parameter identified by [`id`].
    int32_t GetParam(uint32_t intention, uint32_t id, MessageParcel &data, MessageParcel &reply) = 0;
    // Interact with service identified by [`intention`] for general purpose. This interface
    // supplements functions of previous intefaces. Functionalities of this interface is
    // service spicific.
    int32_t Control(uint32_t intention, uint32_t id, MessageParcel &data, MessageParcel &reply) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.msdp.Idevicestatus");
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // I_INTENTION_H