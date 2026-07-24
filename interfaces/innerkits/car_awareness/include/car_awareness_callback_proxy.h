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

#ifndef CAR_AWARENESS_CALLBACK_PROXY_H
#define CAR_AWARENESS_CALLBACK_PROXY_H

#include "icar_awareness_callback.h"

#include <iremote_proxy.h>
#include <nocopyable.h>

namespace OHOS {
namespace Msdp {
class CarAwarenessCallbackProxy : public IRemoteProxy<ICarAwarenessCallback> {
public:
    explicit CarAwarenessCallbackProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<ICarAwarenessCallback>(impl) {}
    ~OnScreenCallbackProxy() = default;
    DISALLOW_COPY_AND_MOVE(CarAwarenessCallbackProxy);
    virtual void OnAwarenessEvent(const CarAwarenessEvent& event) override;

private:
    static inline BrokerDelegator<CarAwarenessCallbackProxy> delegator_;
};
} // namespace Msdp
} // namespace OHOS

#endif