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

#ifndef ICAR_AWARENESS_CALLBACK_IPC_H
#define ICAR_AWARENESS_CALLBACK_IPC_H

#include <iremote_broker.h>
#include <iremote_object.h>

#include "car_awareness_type.h"

namespace OHOS {
namespace Msdp {
class ICarAwarenessCallback : public IRemoteBroker {
public:
    enum {
        EVENT_CHANGE = 0,
        EVENT_CHANGE_SYSTEM
    };
    virtual void OnAwarenessEvent(const CarAwarenessEvent& event) = 0;
    // 预留System: virtual void OnAwarenessEventEx(const std::vector<CarAwarenessEvent>& events) = 0;
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.msdp.ICarAwarenessCallback");
};
} // namespace Msdp
} // namespace OHOS
#endif // ICAR_AWARENESS_CALLBACK_IPC_H