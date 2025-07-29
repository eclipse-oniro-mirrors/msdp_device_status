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

#include "drag_data_packer.h"

#include "devicestatus_common.h"
#include "devicestatus_define.h"
#include "devicestatus_errors.h"

#undef LOG_TAG
#define LOG_TAG "DragDataPacker"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
int32_t DragDataPacker::MarshallingDetailedSummarys(const DragData &dragData, Parcel &data)
{
    if (SummaryPacker::Marshalling(dragData.detailedSummarys, data) != RET_OK) {
        FI_HILOGE("Marshalling detailedSummarys failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t DragDataPacker::UnMarshallingDetailedSummarys(Parcel &data, DragData &dragData)
{
    if (SummaryPacker::UnMarshalling(data, dragData.detailedSummarys) != RET_OK) {
        FI_HILOGE("UnMarshalling detailedSummarys failed");
    }
    return RET_OK;
}

int32_t DragDataPacker::MarshallingSummaryExpanding(const DragData &dragData, Parcel &data)
{
    if (SummaryFormat::Marshalling(dragData.summaryFormat, data) != RET_OK) {
        FI_HILOGE("Marshalling summaryFormat failed");
        return RET_ERR;
    }
    WRITEINT32(data, dragData.summaryVersion, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    WRITEINT64(data, dragData.summaryTotalSize, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    return RET_OK;
}

int32_t DragDataPacker::UnMarshallingSummaryExpanding(Parcel &data, DragData &dragData)
{
    do {
        if (SummaryFormat::UnMarshalling(data, dragData.summaryFormat) != RET_OK) {
            FI_HILOGE("UnMarshalling summaryFormat failed");
            break;
        }
        if (!(data).ReadInt32(dragData.summaryVersion)) {
            FI_HILOGE("ReadInt32 summaryVersion failed");
            break;
        }
        if (!(data).ReadInt64(dragData.summaryTotalSize)) {
            FI_HILOGE("ReadInt64 summaryTotalSize failed");
            break;
        }
    } while (false);
    return RET_OK;
}

int32_t DragDataPacker::Marshalling(const DragData &dragData, Parcel &data, bool isCross)
{
    CALL_DEBUG_ENTER;
    if (ShadowPacker::Marshalling(dragData.shadowInfos, data, isCross) != RET_OK) {
        FI_HILOGE("Marshalling shadowInfos failed");
        return RET_ERR;
    }
    WRITEUINT8VECTOR(data, dragData.buffer, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    WRITESTRING(data, dragData.udKey, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    WRITESTRING(data, dragData.extraInfo, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    WRITESTRING(data, dragData.filterInfo, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    WRITEINT32(data, dragData.sourceType, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    WRITEINT32(data, dragData.dragNum, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    WRITEINT32(data, dragData.pointerId, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    WRITEINT32(data, dragData.displayX, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    WRITEINT32(data, dragData.displayY, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    WRITEINT32(data, dragData.displayId, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    WRITEINT32(data, dragData.mainWindow, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    WRITEBOOL(data, dragData.hasCanceledAnimation, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    WRITEBOOL(data, dragData.hasCoordinateCorrected, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    if (SummaryPacker::Marshalling(dragData.summarys, data) != RET_OK) {
        FI_HILOGE("Marshalling summary failed");
        return RET_ERR;
    }

    if (!isCross && !data.WriteBool(dragData.isDragDelay)) {
        FI_HILOGE("Marshalling isDragDelay failed");
    }
    return RET_OK;
}

int32_t DragDataPacker::UnMarshalling(Parcel &data, DragData &dragData, bool isCross)
{
    CALL_DEBUG_ENTER;
    if (ShadowPacker::UnMarshalling(data, dragData.shadowInfos, isCross) != RET_OK) {
        FI_HILOGE("UnMarshalling shadowInfos failed");
        return RET_ERR;
    }
    READUINT8VECTOR(data, dragData.buffer, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READSTRING(data, dragData.udKey, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READSTRING(data, dragData.extraInfo, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READSTRING(data, dragData.filterInfo, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READINT32(data, dragData.sourceType, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READINT32(data, dragData.dragNum, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READINT32(data, dragData.pointerId, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READINT32(data, dragData.displayX, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READINT32(data, dragData.displayY, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READINT32(data, dragData.displayId, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READINT32(data, dragData.mainWindow, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READBOOL(data, dragData.hasCanceledAnimation, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READBOOL(data, dragData.hasCoordinateCorrected, E_DEVICESTATUS_READ_PARCEL_ERROR);
    if (SummaryPacker::UnMarshalling(data, dragData.summarys) != RET_OK) {
        FI_HILOGE("Unmarshalling summary failed");
        return RET_ERR;
    }

    if (!isCross && !data.ReadBool(dragData.isDragDelay)) {
        FI_HILOGE("Unmarshalling isDragDelay failed");
    }
    return RET_OK;
}

int32_t DragDataPacker::CheckDragData(const DragData &dragData)
{
    for (const auto& shadowInfo : dragData.shadowInfos) {
        if (ShadowPacker::CheckShadowInfo(shadowInfo) != RET_OK) {
            FI_HILOGE("CheckShadowInfo failed");
            return RET_ERR;
        }
    }
    if ((dragData.dragNum <= 0) || (dragData.buffer.size() > MAX_BUFFER_SIZE) ||
        (dragData.displayX < 0) || (dragData.displayY < 0)) {
        FI_HILOGE("Start drag invalid parameter, dragNum:%{public}d, bufferSize:%{public}zu, "
            "displayX:%{private}d, displayY:%{private}d",
            dragData.dragNum, dragData.buffer.size(), dragData.displayX, dragData.displayY);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t ShadowPacker::Marshalling(const std::vector<ShadowInfo> &shadowInfos, Parcel &data, bool isCross)
{
    CALL_DEBUG_ENTER;
    if (shadowInfos.empty()) {
        FI_HILOGE("Invalid parameter shadowInfos");
        return ERR_INVALID_VALUE;
    }
    int32_t shadowNum = static_cast<int32_t>(shadowInfos.size());
    if (shadowNum > SHADOW_NUM_LIMIT) {
        FI_HILOGW("Only %{public}d shadowInfos allowed at most, now %{public}d", SHADOW_NUM_LIMIT, shadowNum);
        shadowNum = SHADOW_NUM_LIMIT;
    }
    WRITEINT32(data, shadowNum, ERR_INVALID_VALUE);
    for (int32_t i = 0; i < shadowNum; i++) {
        if (PackUpShadowInfo(shadowInfos[i], data, isCross) != RET_OK) {
            FI_HILOGE("PackUpShadowInfo No.%{public}d failed", i);
            return RET_ERR;
        }
    }
    return RET_OK;
}

int32_t ShadowPacker::UnMarshalling(Parcel &data, std::vector<ShadowInfo> &shadowInfos, bool isCross)
{
    CALL_DEBUG_ENTER;
    int32_t shadowNum { 0 };
    READINT32(data, shadowNum, E_DEVICESTATUS_READ_PARCEL_ERROR);
    if (shadowNum <= 0 || shadowNum > SHADOW_NUM_LIMIT) {
        FI_HILOGE("Invalid shadowNum:%{public}d", shadowNum);
        return RET_ERR;
    }
    for (int32_t i = 0; i < shadowNum; i++) {
        ShadowInfo shadowInfo;
        if (UnPackShadowInfo(data, shadowInfo, isCross) != RET_OK) {
            FI_HILOGE("UnPackShadowInfo No.%{public}d failed", i);
            return RET_ERR;
        }
        CHKPR(shadowInfo.pixelMap, RET_ERR);
        shadowInfos.push_back(shadowInfo);
    }
    return RET_OK;
}

int32_t ShadowPacker::PackUpShadowInfo(const ShadowInfo &shadowInfo, Parcel &data, bool isCross)
{
    CALL_DEBUG_ENTER;
    CHKPR(shadowInfo.pixelMap, RET_ERR);
    if (isCross) {
        FI_HILOGD("By EncodeTlv");
        std::vector<uint8_t> pixelBuffer;
        if (!shadowInfo.pixelMap->EncodeTlv(pixelBuffer)) {
            FI_HILOGE("EncodeTlv pixelMap failed");
            return ERR_INVALID_VALUE;
        }
        WRITEUINT8VECTOR(data, pixelBuffer, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    } else {
        FI_HILOGD("By Marshalling");
        if (!shadowInfo.pixelMap->Marshalling(data)) {
            FI_HILOGE("Marshalling pixelMap failed");
            return ERR_INVALID_VALUE;
        }
    }
    WRITEINT32(data, shadowInfo.x, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    WRITEINT32(data, shadowInfo.y, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    return RET_OK;
}

int32_t ShadowPacker::UnPackShadowInfo(Parcel &data, ShadowInfo &shadowInfo, bool isCross)
{
    CALL_DEBUG_ENTER;
    Media::PixelMap *rawPixelMap = nullptr;
    if (isCross) {
        FI_HILOGD("By DecodeTlv");
        std::vector<uint8_t> pixelBuffer;
        READUINT8VECTOR(data, pixelBuffer, ERR_INVALID_VALUE);
        rawPixelMap = Media::PixelMap::DecodeTlv(pixelBuffer);
    } else {
        FI_HILOGD("By UnMarshalling");
        rawPixelMap = OHOS::Media::PixelMap::Unmarshalling(data);
    }
    CHKPR(rawPixelMap, RET_ERR);
    shadowInfo.pixelMap = std::shared_ptr<Media::PixelMap>(rawPixelMap);
    CHKPR(shadowInfo.pixelMap, RET_ERR);
    READINT32(data, shadowInfo.x, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READINT32(data, shadowInfo.y, E_DEVICESTATUS_READ_PARCEL_ERROR);
    return RET_OK;
}

int32_t ShadowPacker::CheckShadowInfo(const ShadowInfo &shadowInfo)
{
    CHKPR(shadowInfo.pixelMap, RET_ERR);
    if ((shadowInfo.x > 0) || (shadowInfo.y > 0) ||
        (shadowInfo.x < -shadowInfo.pixelMap->GetWidth()) || (shadowInfo.y < -shadowInfo.pixelMap->GetHeight())) {
        FI_HILOGE("Invalid parameter, shadowInfoX:%{private}d, shadowInfoY:%{private}d", shadowInfo.x, shadowInfo.y);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t SummaryPacker::Marshalling(const SummaryMap &val, Parcel &parcel)
{
    WRITEINT32(parcel, static_cast<int32_t>(val.size()), ERR_INVALID_VALUE);
    for (auto const &[k, v] : val) {
        WRITESTRING(parcel, k, ERR_INVALID_VALUE);
        WRITEINT64(parcel, v, ERR_INVALID_VALUE);
    }
    return RET_OK;
}

int32_t SummaryPacker::UnMarshalling(Parcel &parcel, SummaryMap &val)
{
    size_t readAbleSize = parcel.GetReadableBytes();
    int32_t size = 0;
    READINT32(parcel, size, E_DEVICESTATUS_READ_PARCEL_ERROR);
    if (size < 0 || (static_cast<size_t>(size) > readAbleSize) || static_cast<size_t>(size) > val.max_size()) {
        FI_HILOGE("Invalid size:%{public}d", size);
        return RET_ERR;
    }
    for (int32_t i = 0; i < size; ++i) {
        std::string key;
        READSTRING(parcel, key, E_DEVICESTATUS_READ_PARCEL_ERROR);
        READINT64(parcel, val[key], E_DEVICESTATUS_READ_PARCEL_ERROR);
    }
    return RET_OK;
}

int32_t ShadowOffsetPacker::Marshalling(const ShadowOffset&shadowOffset, Parcel &parcel)
{
    WRITEINT32(parcel, shadowOffset.offsetX, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    WRITEINT32(parcel, shadowOffset.offsetY, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    WRITEINT32(parcel, shadowOffset.width, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    WRITEINT32(parcel, shadowOffset.height, E_DEVICESTATUS_WRITE_PARCEL_ERROR);
    return RET_OK;
}

int32_t ShadowOffsetPacker::UnMarshalling(Parcel &parcel, ShadowOffset&shadowOffset)
{
    READINT32(parcel, shadowOffset.offsetX, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READINT32(parcel, shadowOffset.offsetY, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READINT32(parcel, shadowOffset.width, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READINT32(parcel, shadowOffset.height, E_DEVICESTATUS_READ_PARCEL_ERROR);
    return RET_OK;
}

int32_t SummaryFormat::Marshalling(const std::map<std::string, std::vector<int32_t>> &val, Parcel &parcel)
{
    WRITEINT32(parcel, static_cast<int32_t>(val.size()), ERR_INVALID_VALUE);
    for (auto const &[k, v] : val) {
        WRITESTRING(parcel, k, ERR_INVALID_VALUE);
        WRITEINT32VECTOR(parcel, v, ERR_INVALID_VALUE);
    }
    return RET_OK;
}

int32_t SummaryFormat::UnMarshalling(Parcel &parcel, std::map<std::string, std::vector<int32_t>> &val)
{
    size_t readAbleSize = parcel.GetReadableBytes();
    int32_t size = 0;
    READINT32(parcel, size, E_DEVICESTATUS_READ_PARCEL_ERROR);
    if (size < 0 || (static_cast<size_t>(size) > readAbleSize) || static_cast<size_t>(size) > val.max_size()) {
        FI_HILOGE("Invalid size:%{public}d", size);
        return RET_ERR;
    }
    for (int32_t i = 0; i < size; ++i) {
        std::string key;
        READSTRING(parcel, key, E_DEVICESTATUS_READ_PARCEL_ERROR);
        READINT32VECTOR(parcel, val[key], E_DEVICESTATUS_READ_PARCEL_ERROR);
    }
    return RET_OK;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
