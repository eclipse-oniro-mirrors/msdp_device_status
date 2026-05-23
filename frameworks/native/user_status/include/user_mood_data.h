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

#ifndef USER_MOOD_DATA_H
#define USER_MOOD_DATA_H

#include <functional>
#include <map>
#include <vector>

#include "user_status_data.h"

namespace OHOS {
namespace Msdp {
namespace UserStatusAwareness {
class UserMoodData : public UserStatusData {
public:
    UserMoodData();
    ~UserMoodData();

    int32_t GetRealTimeEmotion() const;
    void SetRealTimeEmotion(int32_t emotionRealTime);

    std::vector<int32_t> GetNonRealTimeEmotion() const;
    void SetNonRealTimeEmotion(const std::vector<int32_t> &emotionNonRealTime);

    int32_t GetConfidence() const;
    void SetConfidence(int32_t confidence);

    bool GetIsRealTimeTag() const;
    void SetIsRealTimeTag(bool isRealTime);

    bool GetIsValidMoodTag() const;
    void SetIsValidMoodTag(bool isValidMood);

    std::vector<float> GetGravityAcc() const;
    void SetGravityAcc(const std::vector<float> &gravityAcc);

    std::vector<float> GetLinearAcc() const;
    void SetLinearAcc(const std::vector<float> &linearAcc);

    std::string Dump() override;
    std::shared_ptr<UserStatusData> Unmarshalling(Parcel &parcel) override;

    bool Marshalling(Parcel &parcel) const override;

protected:
    bool ReadFromParcel(Parcel &parcel) override;

private:
    int32_t emotionRealTime_ { -1 };
    std::vector<int32_t> emotionNonRealTime_;
    int32_t confidence_ { -1 };
    bool isRealTime_ { false };
    bool isValidMood_ { false };
    std::vector<float> gravityAcc_ { std::vector<float>(3, 0.0f) };
    std::vector<float> linearAcc_ { std::vector<float>(3, 0.0f) };
};
} // namespace UserStatusAwareness
} // namespace Msdp
} // namespace OHOS
#endif // USER_MOOD_DATA_H