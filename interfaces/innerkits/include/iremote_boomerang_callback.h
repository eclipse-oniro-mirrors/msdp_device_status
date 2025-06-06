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

#ifndef BOOMERANG_CALLBACK_H
#define BOOMERANG_CALLBACK_H

#include <iremote_broker.h>
#include <iremote_object.h>

#include "boomerang_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class IRemoteBoomerangCallback : public IRemoteBroker {
public:
    enum {
        SCREENSHOT = 0,
        NOTIFY_METADATA = 1,
        ENCODE_IMAGE = 2,
    };

    virtual void OnScreenshotResult(const BoomerangData& screentshotData) = 0;
    virtual void OnNotifyMetadata(const std::string& metadata) = 0;
    virtual void OnEncodeImageResult(std::shared_ptr<Media::PixelMap> pixelMap) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.msdp.IRemoteBoomerangCallback");
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // BOOMERANG_CALLBACK_H