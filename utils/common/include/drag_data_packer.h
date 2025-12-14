/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef DRAG_DATA_PACKER_H
#define DRAG_DATA_PACKER_H

#include <map>
#include <string>
#include <vector>

#include "parcel.h"

#include "drag_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

using SummaryMap = std::map<std::string, int64_t>;
class DragDataPacker {
public:
    static int32_t Marshalling(const DragData &dragData, Parcel &data, bool isCross = false);
    static int32_t UnMarshalling(Parcel &data, DragData &dragData, bool isCross = false);
    static int32_t CheckDragData(const DragData &dragData);
    static int32_t MarshallingDetailedSummarys(const DragData &dragData, Parcel &data);
    static int32_t UnMarshallingDetailedSummarys(Parcel &data, DragData &dragData);
    static int32_t MarshallingSummaryExpanding(const DragData &dragData, Parcel &data);
    static int32_t UnMarshallingSummaryExpanding(Parcel &data, DragData &dragData);
    static int32_t MarshallingMaterialId(const DragData &dragData, Parcel &data);
    static int32_t UnMarshallingMaterialId(Parcel &data, DragData &dragData);
    static int32_t MarshallingMaterialFilter(const DragData &dragData, Parcel &data);
    static int32_t UnMarshallingMaterialFilter(Parcel &data, DragData &dragData);
};

class ShadowPacker {
public:
    static int32_t Marshalling(const std::vector<ShadowInfo> &shadowInfos, Parcel &data, bool isCross = false);
    static int32_t UnMarshalling(Parcel &data, std::vector<ShadowInfo> &shadowInfos, bool isCross = false);
    static int32_t PackUpShadowInfo(const ShadowInfo &shadowInfo, Parcel &data, bool isCross = false);
    static int32_t UnPackShadowInfo(Parcel &data, ShadowInfo &shadowInfo, bool isCross = false);
    static int32_t CheckShadowInfo(const ShadowInfo &shadowInfo);
};

class SummaryPacker {
public:
    static int32_t Marshalling(const SummaryMap &val, Parcel &parcel);
    static int32_t UnMarshalling(Parcel &parcel, SummaryMap &val);
};

class ShadowOffsetPacker {
public:
    static int32_t Marshalling(const ShadowOffset &shadowOffset, Parcel &parcel);
    static int32_t UnMarshalling(Parcel &parcel, ShadowOffset &shadowOffset);
};

class SummaryFormat {
public:
    static int32_t Marshalling(const std::map<std::string, std::vector<int32_t>> &val, Parcel &parcel);
    static int32_t UnMarshalling(Parcel &parcel, std::map<std::string, std::vector<int32_t>> &val);
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DRAG_DATA_PACKER_H
