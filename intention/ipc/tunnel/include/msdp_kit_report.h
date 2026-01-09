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

#ifndef MSDP_KIT_REPORT
#define MSDP_KIT_REPORT

#include <mutex>
namespace OHOS {
namespace Msdp {
struct MsdpInterfaceEventInfo {
    std::string apiName;
    std::string sdkName;
    int64_t beginTime = 0;
    int32_t callTimes = 0;
    int32_t successTimes = 0;
    int64_t maxCostTime = 0;
    int64_t minCostTime = 0;
    int64_t totalCostTime = 0;
    std::vector<std::string> errorCodeType;
    std::vector<int32_t> errorCodeNum;
};

class MsdpKitReport {
public:
    static MsdpKitReport &GetInstance()
    {
        static MsdpKitReport instance;
        return instance;
    }

    bool UpdateMsdpInterfaceEvent(const MsdpInterfaceEventInfo &msdpInterfaceEventInfo);

private:
    MsdpKitReport();
    ~MsdpKitReport();
    MsdpKitReport(const MsdpKitReport &) = delete;
    MsdpKitReport &operator=(const MsdpKitReport &) = delete;

    void SchedulerUpload();
    void AddEventProcessor();
    void MsdpInterfaceEventReport();

    bool isWatching_{false};
    std::mutex mutex_;
    uint64_t startTimerFd_ = 0;
    int64_t processorId_ = -1;
    std::unordered_map<std::string /* api name */, MsdpInterfaceEventInfo> msdpInterfaceEventInfos_;
};
}  // namespace Msdp
}  // namespace OHOS
#endif  // MSDP_KIT_REPORT