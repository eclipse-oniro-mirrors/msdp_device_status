/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "boomerang_params.h"

#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "BoomerangParams"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

SubscribeBoomerangParam::SubscribeBoomerangParam(BoomerangType type, std::string bundleName,
    sptr<IRemoteBoomerangCallback> callback) : type_(type), bundleName_(bundleName), callback_(callback)
{}

bool SubscribeBoomerangParam::Marshalling(MessageParcel &parcel) const
{
    return (
        parcel.WriteInt32(type_) &&
        parcel.WriteString(bundleName_) &&
        (callback_ != nullptr) &&
        parcel.WriteRemoteObject(callback_->AsObject())
    );
}

bool SubscribeBoomerangParam::Unmarshalling(MessageParcel &parcel)
{
    int32_t type {};
    bool result =  parcel.ReadInt32(type) && parcel.ReadString(bundleName_);
    if (!result) {
        return false;
    }
    sptr<IRemoteObject> obj = parcel.ReadRemoteObject();
    if (obj == nullptr) {
        return false;
    }
    callback_ = iface_cast<IRemoteBoomerangCallback>(obj);
    return (callback_ != nullptr);
}

NotifyMetadataParam::NotifyMetadataParam(std::string bundleName, sptr<IRemoteBoomerangCallback> callback)
    : bundleName_(bundleName), callback_(callback)
{}

bool NotifyMetadataParam::Marshalling(MessageParcel &parcel) const
{
    return (
        parcel.WriteString(bundleName_) &&
        (callback_ != nullptr) &&
        parcel.WriteRemoteObject(callback_->AsObject())
    );
}

bool NotifyMetadataParam::Unmarshalling(MessageParcel &parcel)
{
    bool result = parcel.ReadString(bundleName_);
    if (!result) {
        return false;
    }
    sptr<IRemoteObject> obj = parcel.ReadRemoteObject();
    if (obj == nullptr) {
        return false;
    }
    callback_ = iface_cast<IRemoteBoomerangCallback>(obj);
    return (callback_ != nullptr);
}

MetadataParam::MetadataParam(std::string metadata) : metadata_(metadata)
{}

bool MetadataParam::Marshalling(MessageParcel &parcel) const
{
    return parcel.WriteString(metadata_);
}

bool MetadataParam::Unmarshalling(MessageParcel &parcel)
{
    return parcel.ReadString(metadata_);
}

EncodeImageParam::EncodeImageParam(std::shared_ptr<Media::PixelMap> pixelMap, std::string metadata,
    sptr<IRemoteBoomerangCallback> callback) : pixelMap_(pixelMap), metadata_(metadata),
    callback_(callback)
{}

bool EncodeImageParam::Marshalling(MessageParcel &parcel) const
{
    return (
        (pixelMap_ != nullptr) && pixelMap_->Marshalling(parcel) &&
        parcel.WriteString(metadata_) &&
        (callback_ != nullptr) &&
        parcel.WriteRemoteObject(callback_->AsObject())
    );
}

bool EncodeImageParam::Unmarshalling(MessageParcel &parcel)
{
    Media::PixelMap *rawPixelMap = OHOS::Media::PixelMap::Unmarshalling(parcel);
    if (rawPixelMap == nullptr) {
        return false;
    }
    pixelMap_ = std::shared_ptr<Media::PixelMap>(rawPixelMap);
    bool result = parcel.ReadString(metadata_);
    if (!result) {
        return false;
    }
    sptr<IRemoteObject> obj = parcel.ReadRemoteObject();
    if (obj == nullptr) {
        return false;
    }
    callback_ = iface_cast<IRemoteBoomerangCallback>(obj);
    return (callback_ != nullptr);
}

DecodeImageParam::DecodeImageParam(std::shared_ptr<Media::PixelMap> pixelMap,
    sptr<IRemoteBoomerangCallback> callback) : pixelMap_(pixelMap),
    callback_(callback)
{}

bool DecodeImageParam::Marshalling(MessageParcel &parcel) const
{
    return (
        (pixelMap_ != nullptr) && pixelMap_->Marshalling(parcel) &&
        (callback_ != nullptr) &&
        parcel.WriteRemoteObject(callback_->AsObject())
    );
}

bool DecodeImageParam::Unmarshalling(MessageParcel &parcel)
{
    Media::PixelMap *rawPixelMap = OHOS::Media::PixelMap::Unmarshalling(parcel);
    if (rawPixelMap == nullptr) {
        return false;
    }
    pixelMap_ = std::shared_ptr<Media::PixelMap>(rawPixelMap);
    sptr<IRemoteObject> obj = parcel.ReadRemoteObject();
    if (obj == nullptr) {
        return false;
    }
    callback_ = iface_cast<IRemoteBoomerangCallback>(obj);
    return (callback_ != nullptr);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS