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

#ifndef BOOMERANG_CALLBACK_STUB_H
#define BOOMERANG_CALLBACK_STUB_H

#include <iremote_stub.h>
#include <nocopyable.h>

#include "message_option.h"
#include "message_parcel.h"

#include "boomerang_callback.h"
#include "stationary_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class BoomerangCallbackStub : public IRemoteStub<IRemoteBoomerangCallback> {
public:
    BoomerangCallbackStub() = default;
    DISALLOW_COPY_AND_MOVE(BoomerangCallbackStub);
    virtual ~BoomerangCallbackStub() = default;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    void OnScreenshotResult(const BoomerangData& screentshotData) override {}
    void OnNotifyMetadata(const std::string& metadata) override {}
    void OnEncodeImageResult(std::shared_ptr<Media::PixelMap> pixelMap) override {}

private:
    int32_t OnScreenshotStub(MessageParcel &data);
    int32_t OnNotifyMetadataStub(MessageParcel &data);
    int32_t OnEncodeImageStub(MessageParcel &data);
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // BOOMERANG_CALLBACK_STUB_H