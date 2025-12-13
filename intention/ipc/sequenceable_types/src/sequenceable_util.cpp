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

#include "sequenceable_util.h"

#include "devicestatus_define.h"
#include "devicestatus_common.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

bool SequenceableUtil::WriteImageId(Parcel &parcel, std::vector<OnScreen::AwarenessInfoImageId> imageIdArr)
{
    WRITEINT32(parcel, static_cast<int32_t>(imageIdArr.size()), false);
    for (auto imageId : imageIdArr) {
        WRITESTRING(parcel, imageId.compId, false);
        WRITESTRING(parcel, imageId.arkDataId, false);
    }
    return true;
}

bool SequenceableUtil::Marshalling(Parcel &parcel, const std::map<std::string, OnScreen::ValueObj>& entityInfo)
{
    WRITEINT32(parcel, static_cast<int32_t>(entityInfo.size()), false);
    for (auto const &[k, v] : entityInfo) {
        WRITESTRING(parcel, k, false);
        int32_t typeIndex = v.index();
        WRITEINT32(parcel, typeIndex, false);
        std::visit([&parcel](auto&& arg){
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, bool>) {
                WRITEBOOL(parcel, arg, false);
                return true;
            } else if constexpr (std::is_same_v<T, int32_t>) {
                WRITEINT32(parcel, arg, false);
                return true;
            } else if constexpr (std::is_same_v<T, int64_t>) {
                WRITEINT64(parcel, arg, false);
                return true;
            } else if constexpr (std::is_same_v<T, std::string>) {
                WRITESTRING(parcel, arg, false);
                return true;
            } else if constexpr (std::is_same_v<T, OnScreen::AwarenessInfoPageLink>) {
                WRITESTRING(parcel, arg.httpLink, false);
                WRITESTRING(parcel, arg.deepLink, false);
                return true;
            } else if constexpr (std::is_same_v<T, std::shared_ptr<Media::PixelMap>>) {
                arg->Marshalling(parcel);
                return true;
            } else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
                WRITESTRINGVECTOR(parcel, arg, false);
                return true;
            } else if constexpr (std::is_same_v<T, std::vector<OnScreen::AwarenessInfoImageId>>) {
                WriteImageId(parcel, arg);
                return true;
            }
        }, v);
    }
    return true;
}

std::vector<OnScreen::AwarenessInfoImageId> SequenceableUtil::ReadImageId(Parcel &parcel)
{
    int32_t size;
    std::vector<OnScreen::AwarenessInfoImageId> imageIdArr;
    READINT32(parcel, size, imageIdArr);
    for (int32_t i = 0; i < size; i++) {
        std::string compId;
        std::string arkDataId;
        READSTRING(parcel, compId, imageIdArr);
        READSTRING(parcel, arkDataId, imageIdArr);
        OnScreen::AwarenessInfoImageId imageId = { compId, arkDataId };
        imageIdArr.push_back(imageId);
    }
    return imageIdArr;
}

bool SequenceableUtil::Unmarshalling(Parcel &parcel, std::map<std::string, OnScreen::ValueObj>& entityInfo)
{
    int32_t size;
    READINT32(parcel, size, false);
    for (int32_t i = 0; i < size; i++) {
        std::string key;
        READSTRING(parcel, key, false);
        int32_t typeIndex;
        READINT32(parcel, typeIndex, false);
        OnScreen::ValueObj obj;
        switch(typeIndex) {
            case OnScreen::BOOL_INDEX: {
                bool result;
                READBOOL(parcel, result, false);
                obj = result;
                break;
            }
            case OnScreen::INT32_INDEX: {
                int32_t result;
                READINT32(parcel, result, false);
                obj = result;
                break;
            }
            case OnScreen::INT64_INDEX: {
                int64_t result;
                READINT64(parcel, result, false);
                obj = result;
                break;
            }
            case OnScreen::STRING_INDEX: {
                std::string result;
                READSTRING(parcel, result, false);
                obj = result;
                break;
            }
            case OnScreen::PAGE_LINK_INDEX: {
                OnScreen::AwarenessInfoPageLink pageLink;
                READSTRING(parcel, pageLink.httpLink, false);
                READSTRING(parcel, pageLink.deepLink, false);
                obj = pageLink;
                break;
            }
            case OnScreen::PIXEL_MAP_INDEX: {
                Media::PixelMap *rawPixelMap = OHOS::Media::PixelMap::Unmarshalling(parcel);
                CHKPF(rawPixelMap);
                obj = std::shared_ptr<Media::PixelMap>(rawPixelMap);
                break;
            }
            case OnScreen::STRING_ARRAY_INDEX: {
                std::vector<std::string> strArr;
                READSTRINGVECTOR(parcel, strArr, false);
                obj = strArr;
                break;
            }
            case OnScreen::IMAGEID_ARRAY_INDEX: {
                obj = ReadImageId(parcel);
                break;
            }
        }
        entityInfo[key] = obj;
    }
    return true;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS