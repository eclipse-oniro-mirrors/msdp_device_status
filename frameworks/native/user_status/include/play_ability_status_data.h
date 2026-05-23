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

#ifndef PLAY_ABILITY_STATUS_DATA_H
#define PLAY_ABILITY_STATUS_DATA_H

#include <functional>
#include <map>
#include <vector>

#include "user_status_data.h"

namespace OHOS {
namespace Msdp {
namespace UserStatusAwareness {
class PlayAbilityStatusData : public UserStatusData {
public:
    PlayAbilityStatusData();
    ~PlayAbilityStatusData();

    std::vector<float> GetVisualAngle() const;
    void SetVisualAngle(const std::vector<float> &visualAngle);

    std::vector<float> GetAngularVelocity() const;
    void SetAngularVelocity(const std::vector<float> &angularVelocity);

    std::vector<float> GetGravityAcc() const;
    void SetGravityAcc(const std::vector<float> &gravityAcc);

    std::vector<std::vector<float>> GetLinearAcc() const;
    void SetLinearAcc(const std::vector<std::vector<float>> &linearAcc);

    std::vector<float> GetGameRotationData() const;
    void SetGameRotationData(const std::vector<float> &gameRotationData);

    bool GetHandExistFlag();
    void SetHandExistFlag(bool isHandExist);

    int32_t GetMotionGesture();
    void SetMotionGesture(int32_t motionGesture);

    int32_t GetHandType();
    void SetHandType(int32_t handType);

    std::vector<float> GetHandPosition();
    void SetHandPosition(const std::vector<float> &handPosition);

    std::vector<float> GetDirectionAngle();
    void SetDirectionAngle(const std::vector<float> &directionAngle);

    std::vector<float> GetGestureSpeed();
    void SetGestureSpeed(const std::vector<float> &gestureSpeed);

    int32_t GetFaceNum() const;
    void SetFaceNum(int32_t faceNum);

    std::string Dump() override;
    std::shared_ptr<UserStatusData> Unmarshalling(Parcel &parcel) override;

    bool Marshalling(Parcel &parcel) const override;

protected:
    bool ReadFromParcel(Parcel &parcel) override;

private:
    void DumpVisualAngleData(std::string &dumpInfo);
    void DumpAngularVelocityData(std::string &dumpInfo);
    void DumpGravityAccData(std::string &dumpInfo);
    void DumpLinearAccData(std::string &dumpInfo);
    void DumpGameRotationData(std::string &dumpInfo);
    void DumpIsHandExist(std::string &dumpInfo);
    void DumpMotionGesture(std::string &dumpInfo);
    void DumpHandPosition(std::string &dumpInfo);
    void DumpDirectionAngle(std::string &dumpInfo);
    void DumpGestureSpeed(std::string &dumpInfo);
    bool MarshallPlayAbilityData(Parcel &parcel) const;

    std::vector<float> visualAngle_ { std::vector<float>(4, 0.0f) };
    std::vector<float> angularVelocity_ { std::vector<float>(3, 0.0f) };
    std::vector<float> gravityAcc_ { std::vector<float>(3, 0.0f) };
    std::vector<std::vector<float>> linearAcc_ { std::vector<std::vector<float>>(4, std::vector<float>(3, 0.0f)) };
    std::vector<float> gameRotationData_ { std::vector<float>(4, 0.0f) };
    int32_t faceNum_ { 0 };
    bool isHandExist_ { false };
    int32_t motionGesture_ { -1 };
    int32_t handType_ { -1 };
    std::vector<float> handPosition_ { std::vector<float>(3, 0.0f) };
    std::vector<float> directionAngle_ { std::vector<float>(3, 0.0f) };
    std::vector<float> gestureSpeed_ { std::vector<float>(3, 0.0f) };
};
} // namespace UserStatusAwareness
} // namespace Msdp
} // namespace OHOS
#endif // PLAY_ABILITY_STATUS_DATA_H