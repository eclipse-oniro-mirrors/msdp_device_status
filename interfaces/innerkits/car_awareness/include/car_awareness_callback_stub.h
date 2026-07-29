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

 /*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef CAR_AWARENESS_CALLBACK_STUB_H
#define CAR_AWARENESS_CALLBACK_STUB_H

#include "icar_awareness_callback.h"

#include <iremote_stub.h>
#include <nocopyable.h>

#include "message_option.h"
#include "message_parcel.h"

namespace OHOS {
namespace Msdp {
class CarAwarenessCallbackStub : public IRemoteStub<ICarAwarenessCallback> {
public:
    CarAwarenessCallbackStub() = default;
    virtual ~CarAwarenessCallbackStub() = default;
    DISALLOW_COPY_AND_MOVE(CarAwarenessCallbackStub);
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    virtual void OnAwarenessEvent(const CarAwarenessEvent& event) override {};

private:
    int32_t OnEventChangeStub(MessageParcel &data);
    bool IsValidEventType(const int32_t type);
};
} // namespace Msdp
} // namespace OHOS

#endif // CAR_AWARENESS_CALLBACK_STUB_H