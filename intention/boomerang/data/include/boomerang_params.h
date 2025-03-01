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

#ifndef BOOMERANG_PARAMS_H
#define BOOMERANG_PARAMS_H

#include "intention_identity.h"
#include "boomerang_callback.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
enum BoomerangRequestID : uint32_t {
    ADD_BOOMERAMG_LISTENER,
    REMOVE_BOOMERAMG_LISTENER,
    NOTIFY_METADATA,
    SUBMIT_METADATA,
    ENCODE_IMAGE,
    DECODE_IMAGE,
};

struct SubscribeBoomerangParam final : public ParamBase {
    SubscribeBoomerangParam() = default;
    SubscribeBoomerangParam(BoomerangType type, std::string bundleName, sptr<IRemoteBoomerangCallback> callback);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    BoomerangType type_;
    std::string bundleName_;
    sptr<IRemoteBoomerangCallback> callback_;
};

struct NotifyMetadataParam final : public ParamBase {
    NotifyMetadataParam() = default;
    NotifyMetadataParam(std::string bundleName, sptr<IRemoteBoomerangCallback> callback);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    std::string bundleName_;
    sptr<IRemoteBoomerangCallback> callback_;
};

struct MetadataParam final : public ParamBase {
    MetadataParam() = default;
    MetadataParam(std::string metadata);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    std::string metadata_;
};

struct EncodeImageParam final : public ParamBase {
    EncodeImageParam() = default;
    EncodeImageParam(std::shared_ptr<Media::PixelMap> pixelMap, std::string matedata,
        sptr<IRemoteBoomerangCallback> callback);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    std::shared_ptr<Media::PixelMap> pixelMap_;
    std::string metadata_;
    sptr<IRemoteBoomerangCallback> callback_;
};

struct DecodeImageParam final : public ParamBase {
    DecodeImageParam() = default;
    DecodeImageParam(std::shared_ptr<Media::PixelMap> pixelMap, sptr<IRemoteBoomerangCallback> callback);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    std::shared_ptr<Media::PixelMap> pixelMap_;
    sptr<IRemoteBoomerangCallback> callback_;
};

using UnsubscribeBoomerangParam = SubscribeBoomerangParam;
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // BOOMERANG_PARAMS_H