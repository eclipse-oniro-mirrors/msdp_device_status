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

#include "user_mood_data.h"

#include "message_parcel.h"

#include "fi_log.h"
#include "user_status_napi_util.h"

namespace OHOS {
namespace Msdp {
namespace UserStatusAwareness {
namespace {
constexpr size_t SIZE_THREE = 3;
} // namespace
UserMoodData::UserMoodData() {}

UserMoodData::~UserMoodData() {}

int32_t UserMoodData::GetRealTimeEmotion() const
{
    return emotionRealTime_;
}

void UserMoodData::SetRealTimeEmotion(int32_t emotionRealTime)
{
    emotionRealTime_ = emotionRealTime;
}

std::vector<int32_t> UserMoodData::GetNonRealTimeEmotion() const
{
    return emotionNonRealTime_;
}

void UserMoodData::SetNonRealTimeEmotion(const std::vector<int32_t> &emotionNonRealTime)
{
    emotionNonRealTime_ = emotionNonRealTime;
}

int32_t UserMoodData::GetConfidence() const
{
    return confidence_;
}

void UserMoodData::SetConfidence(int32_t confidence)
{
    confidence_ = confidence;
}

bool UserMoodData::GetIsRealTimeTag() const
{
    return isRealTime_;
}

void UserMoodData::SetIsRealTimeTag(bool isRealTime)
{
    isRealTime_ = isRealTime;
}

bool UserMoodData::GetIsValidMoodTag() const
{
    return isValidMood_;
}

void UserMoodData::SetIsValidMoodTag(bool isValidMood)
{
    isValidMood_ = isValidMood;
}

std::vector<float> UserMoodData::GetGravityAcc() const
{
    return gravityAcc_;
}

void UserMoodData::SetGravityAcc(const std::vector<float> &gravityAcc)
{
    if (gravityAcc.size() != SIZE_THREE) {
        FI_HILOGE("gravityAcc size error");
        return;
    }
    gravityAcc_ = gravityAcc;
}

std::vector<float> UserMoodData::GetLinearAcc() const
{
    return linearAcc_;
}

void UserMoodData::SetLinearAcc(const std::vector<float> &linearAcc)
{
    if (linearAcc.size() != SIZE_THREE) {
        FI_HILOGE("linearAcc size error");
        return;
    }
    linearAcc_ = linearAcc;
}

std::string UserMoodData::Dump()
{
    if (gravityAcc_.size() != SIZE_THREE || linearAcc_.size() != SIZE_THREE) {
        FI_HILOGE("gravityAcc or linearAcc_ size error");
        return "";
    }
    std::ostringstream dumpInfo;
    dumpInfo << DumpBaseData() << ", emotionRealTime_=" << emotionRealTime_
        << ", confidence_=" << confidence_ << ", isRealTime_=" << isRealTime_
        << ", isValidMood_=" << isValidMood_ << ", emotionNonRealTime_={ ";
    for (size_t i = 0; i < emotionNonRealTime_.size(); ++i) {
        dumpInfo << emotionNonRealTime_[i] << " " ;
    }
    dumpInfo << "}";
    dumpInfo << ", gravityAcc_[0]=" << gravityAcc_[0]
             << ", gravityAcc_[1]=" << gravityAcc_[1]
             << ", gravityAcc_[2]=" << gravityAcc_[2];
    dumpInfo << ", linearAcc_[0]=" << linearAcc_[0]
             << ", linearAcc_[1]=" << linearAcc_[1]
             << ", linearAcc_[2]=" << linearAcc_[2];
    return dumpInfo.str();
}

std::shared_ptr<UserStatusData> UserMoodData::Unmarshalling(Parcel &parcel)
{
    auto data = std::make_shared<UserMoodData>();
    if (!data->ReadFromParcel(parcel)) {
        FI_HILOGE("read from parcel failed");
        return nullptr;
    }
    return data;
}

bool UserMoodData::Marshalling(Parcel &parcel) const
{
    CHKBRF(parcel.WriteUint32(feature_));
    CHKBRF(parcel.WriteInt32(result_));
    CHKBRF(parcel.WriteInt32(errorCode_));
    CHKBRF(parcel.WriteString(status_));
    CHKBRF(parcel.WriteInt32(emotionRealTime_));
    CHKBRF(parcel.WriteInt32(confidence_));
    CHKBRF(parcel.WriteBool(isRealTime_));
    CHKBRF(parcel.WriteBool(isValidMood_));
    CHKBRF(parcel.WriteInt32Vector(emotionNonRealTime_));
    CHKBRF(parcel.WriteFloatVector(gravityAcc_));
    CHKBRF(parcel.WriteFloatVector(linearAcc_));
    return true;
}

bool UserMoodData::ReadFromParcel(Parcel &parcel)
{
    result_ = parcel.ReadInt32();
    errorCode_ = parcel.ReadInt32();
    status_ = parcel.ReadString();
    if (status_.empty()) {
        FI_HILOGE("Read status_ failed");
        return false;
    }
    emotionRealTime_ = parcel.ReadInt32();
    confidence_ = parcel.ReadInt32();
    isRealTime_ = parcel.ReadBool();
    isValidMood_ = parcel.ReadBool();
    CHKBRF(parcel.ReadInt32Vector(&emotionNonRealTime_));
    CHKBRF(parcel.ReadFloatVector(&gravityAcc_));
    CHKBRF(parcel.ReadFloatVector(&linearAcc_));
    return true;
}
} // namespace UserStatusAwareness
} // namespace Msdp
} // namespace OHOS
