/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "play_ability_status_data.h"

#include "message_parcel.h"

#include "fi_log.h"

namespace OHOS {
namespace Msdp {
namespace UserStatusAwareness {
namespace {
constexpr int32_t INDEX_ZERO = 0;
constexpr int32_t INDEX_ONE = 1;
constexpr int32_t INDEX_TWO = 2;
constexpr int32_t INDEX_THREE = 3;
} // namespace

PlayAbilityStatusData::PlayAbilityStatusData() {}

PlayAbilityStatusData::~PlayAbilityStatusData() {}

std::vector<float> PlayAbilityStatusData::GetVisualAngle() const
{
    return visualAngle_;
}

void PlayAbilityStatusData::SetVisualAngle(const std::vector<float> &visualAngle)
{
    visualAngle_ = visualAngle;
}

std::vector<float> PlayAbilityStatusData::GetAngularVelocity() const
{
    return angularVelocity_;
}

void PlayAbilityStatusData::SetAngularVelocity(const std::vector<float> &angularVelocity)
{
    angularVelocity_ = angularVelocity;
}

std::vector<float> PlayAbilityStatusData::GetGravityAcc() const
{
    return gravityAcc_;
}

void PlayAbilityStatusData::SetGravityAcc(const std::vector<float> &gravityAcc)
{
    gravityAcc_ = gravityAcc;
}

std::vector<std::vector<float>> PlayAbilityStatusData::GetLinearAcc() const
{
    return linearAcc_;
}

void PlayAbilityStatusData::SetLinearAcc(const std::vector<std::vector<float>> &linearAcc)
{
    linearAcc_ = linearAcc;
}

std::vector<float> PlayAbilityStatusData::GetGameRotationData() const
{
    return gameRotationData_;
}

void PlayAbilityStatusData::SetGameRotationData(const std::vector<float> &gameRotationData)
{
    gameRotationData_ = gameRotationData;
}

bool PlayAbilityStatusData::GetHandExistFlag()
{
    return isHandExist_;
}

void PlayAbilityStatusData::SetHandExistFlag(bool isHandExist)
{
    isHandExist_ = isHandExist;
}

int32_t PlayAbilityStatusData::GetMotionGesture()
{
    return motionGesture_;
}

void PlayAbilityStatusData::SetMotionGesture(int32_t motionGesture)
{
    motionGesture_ = motionGesture;
}

int32_t PlayAbilityStatusData::GetHandType()
{
    return handType_;
}

void PlayAbilityStatusData::SetHandType(int32_t handType)
{
    handType_ = handType;
}

std::vector<float> PlayAbilityStatusData::GetHandPosition()
{
    return handPosition_;
}

void PlayAbilityStatusData::SetHandPosition(const std::vector<float> &handPosition)
{
    handPosition_ = handPosition;
}

std::vector<float> PlayAbilityStatusData::GetDirectionAngle()
{
    return directionAngle_;
}

void PlayAbilityStatusData::SetDirectionAngle(const std::vector<float> &directionAngle)
{
    directionAngle_ = directionAngle;
}

std::vector<float> PlayAbilityStatusData::GetGestureSpeed()
{
    return gestureSpeed_;
}

void PlayAbilityStatusData::SetGestureSpeed(const std::vector<float> &gestureSpeed)
{
    gestureSpeed_ = gestureSpeed;
}

int32_t PlayAbilityStatusData::GetFaceNum() const
{
    return faceNum_;
}

void PlayAbilityStatusData::SetFaceNum(int32_t faceNum)
{
    faceNum_ = faceNum;
}

void PlayAbilityStatusData::DumpVisualAngleData(std::string &dumpInfo)
{
    dumpInfo.append(", visualAngle_[0]=");
    dumpInfo.append(std::to_string(visualAngle_[INDEX_ZERO]));
    dumpInfo.append(", visualAngle_[1]=");
    dumpInfo.append(std::to_string(visualAngle_[INDEX_ONE]));
    dumpInfo.append(", visualAngle_[2]=");
    dumpInfo.append(std::to_string(visualAngle_[INDEX_TWO]));
    dumpInfo.append(", visualAngle_[3]=");
    dumpInfo.append(std::to_string(visualAngle_[INDEX_THREE]));
}

void PlayAbilityStatusData::DumpAngularVelocityData(std::string &dumpInfo)
{
    dumpInfo.append(", angularVelocity_[0]=");
    dumpInfo.append(std::to_string(angularVelocity_[INDEX_ZERO]));
    dumpInfo.append(", angularVelocity_[1]=");
    dumpInfo.append(std::to_string(angularVelocity_[INDEX_ONE]));
    dumpInfo.append(", angularVelocity_[2]=");
    dumpInfo.append(std::to_string(angularVelocity_[INDEX_TWO]));
}

void PlayAbilityStatusData::DumpGravityAccData(std::string &dumpInfo)
{
    dumpInfo.append(", gravityAcc_[0]=");
    dumpInfo.append(std::to_string(gravityAcc_[INDEX_ZERO]));
    dumpInfo.append(", gravityAcc_[1]=");
    dumpInfo.append(std::to_string(gravityAcc_[INDEX_ONE]));
    dumpInfo.append(", gravityAcc_[2]=");
    dumpInfo.append(std::to_string(gravityAcc_[INDEX_TWO]));
}

void PlayAbilityStatusData::DumpLinearAccData(std::string &dumpInfo)
{
    dumpInfo.append(", linearAcc_[0][0]=");
    dumpInfo.append(std::to_string(linearAcc_[INDEX_ZERO][INDEX_ZERO]));
    dumpInfo.append(", linearAcc_[0][1]=");
    dumpInfo.append(std::to_string(linearAcc_[INDEX_ZERO][INDEX_ONE]));
    dumpInfo.append(", linearAcc_[0][2]=");
    dumpInfo.append(std::to_string(linearAcc_[INDEX_ZERO][INDEX_TWO]));
    dumpInfo.append(", linearAcc_[1][0]=");
    dumpInfo.append(std::to_string(linearAcc_[INDEX_ONE][INDEX_ZERO]));
    dumpInfo.append(", linearAcc_[1][1]=");
    dumpInfo.append(std::to_string(linearAcc_[INDEX_ONE][INDEX_ONE]));
    dumpInfo.append(", linearAcc_[1][2]=");
    dumpInfo.append(std::to_string(linearAcc_[INDEX_ONE][INDEX_TWO]));
    dumpInfo.append(", linearAcc_[2][0]=");
    dumpInfo.append(std::to_string(linearAcc_[INDEX_TWO][INDEX_ZERO]));
    dumpInfo.append(", linearAcc_[2][1]=");
    dumpInfo.append(std::to_string(linearAcc_[INDEX_TWO][INDEX_ONE]));
    dumpInfo.append(", linearAcc_[2][2]=");
    dumpInfo.append(std::to_string(linearAcc_[INDEX_TWO][INDEX_TWO]));
    dumpInfo.append(", linearAcc_[3][0]=");
    dumpInfo.append(std::to_string(linearAcc_[INDEX_THREE][INDEX_ZERO]));
    dumpInfo.append(", linearAcc_[3][1]=");
    dumpInfo.append(std::to_string(linearAcc_[INDEX_THREE][INDEX_ONE]));
    dumpInfo.append(", linearAcc_[3][2]=");
    dumpInfo.append(std::to_string(linearAcc_[INDEX_THREE][INDEX_TWO]));
}

void PlayAbilityStatusData::DumpGameRotationData(std::string &dumpInfo)
{
    dumpInfo.append(", gameRotationData_[0]=");
    dumpInfo.append(std::to_string(visualAngle_[INDEX_ZERO]));
    dumpInfo.append(", gameRotationData_[1]=");
    dumpInfo.append(std::to_string(gameRotationData_[INDEX_ONE]));
    dumpInfo.append(", gameRotationData_[2]=");
    dumpInfo.append(std::to_string(gameRotationData_[INDEX_TWO]));
    dumpInfo.append(", gameRotationData_[3]=");
    dumpInfo.append(std::to_string(gameRotationData_[INDEX_THREE]));
}

void PlayAbilityStatusData::DumpIsHandExist(std::string &dumpInfo)
{
    dumpInfo.append(", isHandExist_=");
    dumpInfo.append(std::to_string(isHandExist_));
}

void PlayAbilityStatusData::DumpMotionGesture(std::string &dumpInfo)
{
    dumpInfo.append(", motionGesture_=");
    dumpInfo.append(std::to_string(motionGesture_));
}

void PlayAbilityStatusData::DumpHandPosition(std::string &dumpInfo)
{
    dumpInfo.append(", handPosition_[0]=");
    dumpInfo.append(std::to_string(handPosition_[INDEX_ZERO]));
    dumpInfo.append(", handPosition_[1]=");
    dumpInfo.append(std::to_string(handPosition_[INDEX_ONE]));
    dumpInfo.append(", handPosition_[2]=");
    dumpInfo.append(std::to_string(handPosition_[INDEX_TWO]));
}

void PlayAbilityStatusData::DumpDirectionAngle(std::string &dumpInfo)
{
    dumpInfo.append(", directionAngle_[0]=");
    dumpInfo.append(std::to_string(directionAngle_[INDEX_ZERO]));
    dumpInfo.append(", directionAngle_[1]=");
    dumpInfo.append(std::to_string(directionAngle_[INDEX_ONE]));
    dumpInfo.append(", directionAngle_[2]=");
    dumpInfo.append(std::to_string(directionAngle_[INDEX_TWO]));
}

void PlayAbilityStatusData::DumpGestureSpeed(std::string &dumpInfo)
{
    dumpInfo.append(", gestureSpeed_[0]=");
    dumpInfo.append(std::to_string(gestureSpeed_[INDEX_ZERO]));
    dumpInfo.append(", gestureSpeed_[1]=");
    dumpInfo.append(std::to_string(gestureSpeed_[INDEX_ONE]));
    dumpInfo.append(", gestureSpeed_[2]=");
    dumpInfo.append(std::to_string(gestureSpeed_[INDEX_TWO]));
}

std::string PlayAbilityStatusData::Dump()
{
    std::string dumpInfo = DumpBaseData();
    dumpInfo.append(", faceNum=");
    dumpInfo.append(std::to_string(faceNum_));
    DumpVisualAngleData(dumpInfo);
    DumpAngularVelocityData(dumpInfo);
    DumpGravityAccData(dumpInfo);
    DumpLinearAccData(dumpInfo);
    DumpGameRotationData(dumpInfo);
    DumpIsHandExist(dumpInfo);
    DumpMotionGesture(dumpInfo);
    dumpInfo.append(", handType_=");
    dumpInfo.append(std::to_string(handType_));
    DumpHandPosition(dumpInfo);
    DumpDirectionAngle(dumpInfo);
    DumpGestureSpeed(dumpInfo);
    return dumpInfo;
}

std::shared_ptr<UserStatusData> PlayAbilityStatusData::Unmarshalling(Parcel &parcel)
{
    auto statusData = std::make_shared<PlayAbilityStatusData>();
    if (!statusData->ReadFromParcel(parcel)) {
        FI_HILOGE("read from parcel failed");
        return nullptr;
    }
    return statusData;
}

bool PlayAbilityStatusData::MarshallPlayAbilityData(Parcel &parcel) const
{
    CHKBRF(parcel.WriteInt32(faceNum_));
    CHKBRF(parcel.WriteFloatVector(visualAngle_));
    CHKBRF(parcel.WriteFloatVector(angularVelocity_));
    CHKBRF(parcel.WriteFloatVector(gravityAcc_));

    for (const auto &acc : linearAcc_) {
        CHKBRF(parcel.WriteFloatVector(acc));
    }
    CHKBRF(parcel.WriteFloatVector(gameRotationData_));
    CHKBRF(parcel.WriteBool(isHandExist_));
    CHKBRF(parcel.WriteInt32(motionGesture_));
    CHKBRF(parcel.WriteInt32(handType_));
    CHKBRF(parcel.WriteFloatVector(handPosition_));
    CHKBRF(parcel.WriteFloatVector(directionAngle_));
    CHKBRF(parcel.WriteFloatVector(gestureSpeed_));

    return true;
}

bool PlayAbilityStatusData::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteUint32(feature_)) {
        FI_HILOGE("write features_ failed");
        return false;
    }
    if (!parcel.WriteInt32(result_)) {
        FI_HILOGE("write result_ failed");
        return false;
    }
    if (!parcel.WriteInt32(errorCode_)) {
        FI_HILOGE("write errorCode_ failed");
        return false;
    }
    if (!parcel.WriteString(status_)) {
        FI_HILOGE("write status_ failed");
        return false;
    }
    if (!MarshallPlayAbilityData(parcel)) {
        FI_HILOGE("write PlayAbilityData failed");
        return false;
    }

    return true;
}

bool PlayAbilityStatusData::ReadFromParcel(Parcel &parcel)
{
    result_ = parcel.ReadInt32();
    errorCode_ = parcel.ReadInt32();
    status_ = parcel.ReadString();
    if (status_.empty()) {
        FI_HILOGE("Read status_ failed");
        return false;
    }
    faceNum_ = parcel.ReadInt32();
    parcel.ReadFloatVector(&visualAngle_);
    parcel.ReadFloatVector(&angularVelocity_);
    parcel.ReadFloatVector(&gravityAcc_);
    for (auto &acc : linearAcc_) {
        parcel.ReadFloatVector(&acc);
    }
    parcel.ReadFloatVector(&gameRotationData_);
    isHandExist_ = parcel.ReadBool();
    motionGesture_ = parcel.ReadInt32();
    handType_ = parcel.ReadInt32();
    parcel.ReadFloatVector(&handPosition_);
    parcel.ReadFloatVector(&directionAngle_);
    parcel.ReadFloatVector(&gestureSpeed_);
    return true;
}
} // namespace UserStatusAwareness
} // namespace Msdp
} // namespace OHOS
