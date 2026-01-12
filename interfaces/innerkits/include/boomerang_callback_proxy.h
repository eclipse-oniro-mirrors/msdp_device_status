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

#ifndef BOOMERANG_CALLBACK_PROXY_H
#define BOOMERANG_CALLBACK_PROXY_H

#include <iremote_proxy.h>
#include <nocopyable.h>

#include "iremote_boomerang_callback.h"
#include "stationary_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class BoomerangCallbackProxy : public IRemoteProxy<IRemoteBoomerangCallback> {
public:
    explicit BoomerangCallbackProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<IRemoteBoomerangCallback>(impl) {}
    DISALLOW_COPY_AND_MOVE(BoomerangCallbackProxy);
    ~BoomerangCallbackProxy() = default;

    virtual void OnScreenshotResult(const BoomerangData& data) override;
    virtual void OnNotifyMetadata(const std::string& metadata) override;
    virtual void OnEncodeImageResult(std::shared_ptr<Media::PixelMap> pixelMap) override;

private:
    template <typename WriteCallbackDataFunc>
    void SendRequestCommon(int32_t requestCode, WriteCallbackDataFunc writeCallbackDataFunc);
    static inline BrokerDelegator<BoomerangCallbackProxy> delegator_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // BOOMERANG_CALLBACK_PROXY_H