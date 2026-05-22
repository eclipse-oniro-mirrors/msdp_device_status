/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "user_blow_data.h"

#include "message_parcel.h"

#include "devicestatus_define.h"
#include "fi_log.h"

namespace OHOS {
namespace Msdp {
namespace UserStatusAwareness {
namespace {
constexpr int32_t INDEX_ZERO = 0;
constexpr int32_t INDEX_ONE = 1;
constexpr int32_t INDEX_TWO = 2;
constexpr int32_t INDEX_THREE = 3;
constexpr size_t SIZE_THREE = 3;
} // namespace
UserBlowData::UserBlowData() {}

UserBlowData::~UserBlowData() {}

std::vector<float> UserBlowData::GetFacePosition() const
{
    return facePosition_;
}

void UserBlowData::SetFacePosition(const std::vector<float> &facePosition)
{
    facePosition_ = facePosition;
}

int32_t UserBlowData::GetStrengthLevel() const
{
    return strengthLevel_;
}

void UserBlowData::SetStrengthLevel(int32_t strengthLevel)
{
    strengthLevel_ = strengthLevel;
}

int32_t UserBlowData::GetDirection() const
{
    return direction_;
}

void UserBlowData::SetDirection(int32_t direction)
{
    direction_ = direction;
}

int32_t UserBlowData::GetEmotion() const
{
    return emotion_;
}

void UserBlowData::SetEmotion(int32_t emotion)
{
    emotion_ = emotion;
}

bool UserBlowData::GetEyesOn() const
{
    return eyesOn_;
}

void UserBlowData::SetEyesOn(bool eyesOn)
{
    eyesOn_ = eyesOn;
}

std::vector<float> UserBlowData::GetGravityAcc() const
{
    return gravityAcc_;
}

void UserBlowData::SetGravityAcc(const std::vector<float> &gravityAcc)
{
    if (gravityAcc.size() != SIZE_THREE) {
        FI_HILOGE("gravityAcc size error");
        return;
    }
    gravityAcc_ = gravityAcc;
}

std::vector<float> UserBlowData::GetLinearAcc() const
{
    return linearAcc_;
}

void UserBlowData::SetLinearAcc(const std::vector<float> &linearAcc)
{
    if (linearAcc.size() != SIZE_THREE) {
        FI_HILOGE("linearAcc size error");
        return;
    }
    linearAcc_ = linearAcc;
}

std::string UserBlowData::Dump()
{
    std::ostringstream dumpInfo;
    dumpInfo << DumpBaseData() << ", strengthLevel_=" << strengthLevel_ << ", direction_=" << direction_
        << ", emotion_=" << emotion_ << ", eyesOn_=" << eyesOn_ << ", facePosition_[0]=" << facePosition_[INDEX_ZERO]
        << ", facePosition_[1]=" << facePosition_[INDEX_ONE] << ", facePosition_[2]=" << facePosition_[INDEX_TWO]
        << ", facePosition_[3]=" << facePosition_[INDEX_THREE];
    dumpInfo << ", gravityAcc_[0]=" << gravityAcc_[0]
             << ", gravityAcc_[1]=" << gravityAcc_[INDEX_ONE]
             << ", gravityAcc_[2]=" << gravityAcc_[INDEX_TWO];
    dumpInfo << ", linearAcc_[0]=" << linearAcc_[0]
             << ", linearAcc_[1]=" << linearAcc_[INDEX_ONE]
             << ", linearAcc_[2]=" << linearAcc_[INDEX_TWO];
    return dumpInfo.str();
}

std::shared_ptr<UserStatusData> UserBlowData::Unmarshalling(Parcel &parcel)
{
    auto data = std::make_shared<UserBlowData>();
    if (!data->ReadFromParcel(parcel)) {
        FI_HILOGE("read from parcel failed");
        return nullptr;
    }
    return data;
}

bool UserBlowData::MarshallBlowData(Parcel &parcel) const
{
    CHKBRF(parcel.WriteInt32(strengthLevel_));
    CHKBRF(parcel.WriteInt32(direction_));
    CHKBRF(parcel.WriteInt32(emotion_));
    CHKBRF(parcel.WriteBool(eyesOn_));
    CHKBRF(parcel.WriteFloatVector(facePosition_));
    CHKBRF(parcel.WriteFloatVector(gravityAcc_));
    CHKBRF(parcel.WriteFloatVector(linearAcc_));
    return true;
}

bool UserBlowData::Marshalling(Parcel &parcel) const
{
    MessageParcel& msgParcel = static_cast<MessageParcel&>(parcel);
    CHKBRF(msgParcel.WriteUint32(feature_));
    CHKBRF(msgParcel.WriteInt32(result_));
    CHKBRF(msgParcel.WriteInt32(errorCode_));
    CHKBRF(msgParcel.WriteString(status_));
    if (!MarshallBlowData(msgParcel)) {
        FI_HILOGE("write PlayAbilityData failed");
        return false;
    }

    return true;
}

bool UserBlowData::ReadFromParcel(Parcel &parcel)
{
    MessageParcel& msgParcel = static_cast<MessageParcel&>(parcel);
    result_ = msgParcel.ReadInt32();
    errorCode_ = msgParcel.ReadInt32();
    status_ = msgParcel.ReadString();
    if (status_.empty()) {
        FI_HILOGE("Read status_ failed");
        return false;
    }
    strengthLevel_ = msgParcel.ReadInt32();
    direction_ = msgParcel.ReadInt32();
    emotion_ = msgParcel.ReadInt32();
    eyesOn_ = parcel.ReadBool();
    CHKBRF(msgParcel.ReadFloatVector(&facePosition_));
    CHKBRF(parcel.ReadFloatVector(&gravityAcc_));
    CHKBRF(parcel.ReadFloatVector(&linearAcc_));
    return true;
}
} // namespace UserStatusAwareness
} // namespace Msdp
} // namespace OHOS
