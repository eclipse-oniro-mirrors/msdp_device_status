/*
 * Copyright 2024 (c) Huawei Device Co., Ltd.
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

#include "user_status_data.h"

#include "message_parcel.h"

#include "fi_log.h"

namespace OHOS {
namespace Msdp {
namespace UserStatusAwareness {
namespace {
constexpr int32_t MAX_APP_SIZE = 50;
} // namespace
UserStatusData::UserStatusData() {}

UserStatusData::~UserStatusData() {}

uint32_t UserStatusData::GetFeature() const
{
    return feature_;
}

void UserStatusData::SetFeature(uint32_t feature)
{
    feature_ = feature;
}

std::string UserStatusData::GetStatus() const
{
    return status_;
}

void UserStatusData::SetStatus(const std::string &status)
{
    status_ = status;
}

int32_t UserStatusData::GetResult() const
{
    return result_;
}

void UserStatusData::SetResult(int32_t result)
{
    result_ = result;
}

int32_t UserStatusData::GetErrorCode() const
{
    return errorCode_;
}

void UserStatusData::SetErrorCode(int32_t errorCode)
{
    errorCode_ = errorCode;
}

std::vector<std::string> UserStatusData::GetResultApps() const
{
    return resultApps_;
}

void UserStatusData::SetResultApps(const std::vector<std::string> resultApps)
{
    resultApps_ = resultApps;
}

std::string UserStatusData::GetHpeDeviceId() const
{
    return hpeDeviceId_;
}

void UserStatusData::SetHpeDeviceId(const std::string &hpeDeviceId)
{
    hpeDeviceId_ = hpeDeviceId;
}

int32_t UserStatusData::GetCoordinateX() const
{
    return coordinateX_;
}

void UserStatusData::SetCoordinateX(int32_t coordinateX)
{
    coordinateX_ = coordinateX;
}

int32_t UserStatusData::GetCoordinateY() const
{
    return coordinateY_;
}

void UserStatusData::SetCoordinateY(int32_t coordinateY)
{
    coordinateY_ = coordinateY;
}

int32_t UserStatusData::GetPointerAction() const
{
    return pointerAction_;
}

void UserStatusData::SetPointerAction(int32_t pointerAction)
{
    pointerAction_ = pointerAction;
}

int32_t UserStatusData::GetOrientation() const
{
    return orientation_;
}

void UserStatusData::SetOrientation(int32_t orientation)
{
    orientation_ = orientation;
}

int32_t UserStatusData::GetDisplayId() const
{
    return displayId_;
}

void UserStatusData::SetDisplayId(int32_t displayId)
{
    displayId_ = displayId;
}

int32_t UserStatusData::GetTpStatus() const
{
    return tpStatus_;
}
 
void UserStatusData::SetTpStatus(int32_t tpStatus)
{
    tpStatus_ = tpStatus;
}

std::string UserStatusData::Dump()
{
    std::string dumpInfo = DumpBaseData();

    if (feature_ == 10) {
        dumpInfo.append(", resultApps_=");
        dumpInfo.append(std::to_string(resultApps_.size()));
        for (const auto& app : resultApps_) {
            dumpInfo.append(", ");
            dumpInfo.append(app.c_str());
        }
    }
    return dumpInfo;
}

std::string UserStatusData::DumpBaseData()
{
    std::ostringstream dumpInfo;
    dumpInfo << "feature=" << static_cast<uint32_t>(feature_)
             << ", status=" << status_
             << ", result=" << result_
             << ", errorCode_=" << errorCode_;
    if (feature_ == 14) {
        dumpInfo << ", pointerAction=" << pointerAction_
                 << ", orientation=" << orientation_
                 << ", displayId=" << displayId_
                 << ", tpStatus=" << tpStatus_;
    }
    return dumpInfo.str();
}

std::shared_ptr<UserStatusData> UserStatusData::Unmarshalling(Parcel &parcel)
{
    auto statusData = std::make_shared<UserStatusData>();
    if (!statusData->ReadFromParcel(parcel)) {
        FI_HILOGE("read from parcel failed");
        return nullptr;
    }
    return statusData;
}

int32_t UserStatusData::UnMarshallingFeature(Parcel &parcel)
{
    return parcel.ReadUint32();
}

bool UserStatusData::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteUint32(feature_)) {
        FI_HILOGE("write features_ is failed");
        return false;
    }
    if (!parcel.WriteInt32(result_)) {
        FI_HILOGE("write result_ is failed");
        return false;
    }
    if (!parcel.WriteInt32(errorCode_)) {
        FI_HILOGE("write errorCode_ is failed");
        return false;
    }
    if (!parcel.WriteString(status_)) {
        FI_HILOGE("write status_ is failed");
        return false;
    }

    if (feature_ == 10) {
        int32_t appSize = static_cast<int32_t>(resultApps_.size());
        if (appSize > MAX_APP_SIZE) {
            appSize = MAX_APP_SIZE;
        }
        if (!parcel.WriteInt32(appSize)) {
            FI_HILOGE("write resultApps_ size is failed");
            return false;
        }
        for (int32_t i = 0; i < appSize; ++i) {
            if (!parcel.WriteString(resultApps_[i])) {
                FI_HILOGE("write resultApps_ item is failed");
                return false;
            }
        }
    }
    if (feature_ == 11) {
        if (!parcel.WriteString(hpeDeviceId_)) {
            FI_HILOGE("write hpeDeviceId_ is failed");
            return false;
        }
    }
    if (feature_ == 14) {
        if (!WriteTimeTunnelData(parcel)) {
            return false;
        }
    }
    return true;
}

bool UserStatusData::WriteTimeTunnelData(Parcel &parcel) const
{
    if (!parcel.WriteInt32(coordinateX_)) {
        FI_HILOGE("write coordinateX_ is failed");
        return false;
    }
    if (!parcel.WriteInt32(coordinateY_)) {
        FI_HILOGE("write coordinateY_ is failed");
        return false;
    }
    if (!parcel.WriteInt32(pointerAction_)) {
        FI_HILOGE("write pointerAction_ is failed");
        return false;
    }
    if (!parcel.WriteInt32(orientation_)) {
        FI_HILOGE("write orientation_ is failed");
        return false;
    }
    if (!parcel.WriteInt32(displayId_)) {
        FI_HILOGE("write displayId_ is failed");
        return false;
    }
    if (!parcel.WriteInt32(tpStatus_)) {
        FI_HILOGE("write tpStatus_ is failed");
        return false;
    }

    return true;
}

bool UserStatusData::ReadFromParcel(Parcel &parcel)
{
    result_ = parcel.ReadInt32();
    errorCode_ = parcel.ReadInt32();
    status_ = parcel.ReadString();
    if (status_.empty()) {
        FI_HILOGE("Read status_ failed");
        return false;
    }

    if (status_ == "userStatusPreferenceApp") {
        int32_t size = parcel.ReadInt32();
        if (size > MAX_APP_SIZE || size < 0) {
            FI_HILOGE("Invalid app size: %{public}d", size);
            return false;
        }
        std::string bundleName;
        for (int32_t i = 0; i < size; ++i) {
            bundleName = parcel.ReadString();
            if (bundleName.empty()) {
                FI_HILOGE("Read bundle name failed, feature: %{public}d, result: %{public}d, errorCode: %{public}d",
                    feature_, result_, errorCode_);
                return false;
            }
            resultApps_.push_back(bundleName);
        }
    }
    if (status_ == "userFaceAngleStatus") {
        hpeDeviceId_ = parcel.ReadString();
    }
    if (status_ == "timeTunnelStatus") {
        coordinateX_ = parcel.ReadInt32();
        coordinateY_ = parcel.ReadInt32();
        pointerAction_ = parcel.ReadInt32();
        orientation_ = parcel.ReadInt32();
        displayId_ = parcel.ReadInt32();
        tpStatus_ = parcel.ReadInt32();
    }
    return true;
}
} // namespace UserStatusAwareness
} // namespace Msdp
} // namespace OHOS
