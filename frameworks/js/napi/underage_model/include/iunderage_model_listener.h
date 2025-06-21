/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef IUNDERAGE_MODEL_LISTENER_H
#define IUNDERAGE_MODEL_LISTENER_H

namespace OHOS {
namespace Msdp {
namespace UserStatusAwareness {
class IUnderageModelListener {
public:
    IUnderageModelListener() = default;
    virtual ~IUnderageModelListener() = default;
    virtual void OnUnderageModelListener(uint32_t eventType, int32_t result, float confidence) const;
};
} // namespace UserStatusAwareness
} // namespace Msdp
} // namespace OHOS
#endif // IUNDERAGE_MODEL_LISTENER_H