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

#ifndef BLOW_DATA_H
#define BLOW_DATA_H

#include <functional>
#include <map>
#include <vector>

#include "user_status_data.h"

namespace OHOS {
namespace Msdp {
namespace UserStatusAwareness {
class UserBlowData : public UserStatusData {
public:
    UserBlowData();
    ~UserBlowData();

    std::vector<float> GetFacePosition() const;
    void SetFacePosition(const std::vector<float> &facePosition);

    int32_t GetStrengthLevel() const;
    void SetStrengthLevel(int32_t strengthLevel);

    int32_t GetDirection() const;
    void SetDirection(int32_t direction);

    int32_t GetEmotion() const;
    void SetEmotion(int32_t emotion);

    bool GetEyesOn() const;
    void SetEyesOn(bool eyesOn);

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
    bool MarshallBlowData(Parcel &parcel) const;

    std::vector<float> facePosition_ { std::vector<float>(4, 0.0f) };
    std::vector<float> gravityAcc_ { std::vector<float>(3, 0.0f) };
    std::vector<float> linearAcc_ { std::vector<float>(3, 0.0f) };
    int32_t strengthLevel_ { -1 };
    int32_t direction_ { -1 };
    int32_t emotion_ { -1 };
    bool eyesOn_ { false };
};
} // namespace UserStatusAwareness
} // namespace Msdp
} // namespace OHOS
#endif // BLOW_DATA_H