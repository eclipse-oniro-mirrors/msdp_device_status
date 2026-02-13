/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#ifndef DELEGATE_TASKS_H
#define DELEGATE_TASKS_H

#include <cinttypes>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>

#include "id_factory.h"
#include "i_delegate_tasks.h"
#include "include/util.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DelegateTasks final : public IDelegateTasks,
                            public IdFactory<int32_t> {
public:
    struct TaskData {
        int32_t taskId { 0 };
        uint64_t tid { 0 };
    };
    class Task : public std::enable_shared_from_this<Task> {
    public:
        using Promise = std::promise<int32_t>;
        using Future = std::future<int32_t>;
        using TaskPtr = std::shared_ptr<DelegateTasks::Task>;
        Task(int32_t taskid, DTaskCallback fun, Promise *promise = nullptr)
            : id_(taskid), fun_(fun), promise_(promise) {}
        ~Task() = default;
        void ProcessTask();

        void SetWaited()
        {
            hasWaited_ = true;
        }
        int32_t GetId() const
        {
            return id_;
        }
        TaskPtr GetSharedPtr()
        {
            return shared_from_this();
        }

    private:
        std::atomic_bool hasWaited_ { false };
        int32_t id_ { 0 };
        DTaskCallback fun_ { nullptr };
        Promise* promise_ { nullptr };
    };
    using TaskPtr = Task::TaskPtr;
    using Promise = Task::Promise;
    using Future = Task::Future;

public:
    DelegateTasks() = default;
    ~DelegateTasks();

    bool Init();
    int32_t PostSyncTask(DTaskCallback callback) override;
    int32_t PostAsyncTask(DTaskCallback callback) override;
    void ProcessTasks();

    void SetWorkerThreadId(uint64_t tid)
    {
        workerTid_ = tid;
    }

    int32_t GetReadFd() const
    {
        return fds_[0];
    }

    bool IsCallFromWorkerThread() const
    {
        return (GetThisThreadId() == workerTid_);
    }

private:
    void PopPendingTaskList(std::vector<TaskPtr> &tasks);
    TaskPtr PostTask(DTaskCallback callback, Promise *promise = nullptr);

private:
    std::queue<TaskPtr> tasks_;
    std::mutex mux_;
    int32_t fds_[2] {};
    uint64_t workerTid_ { 0 };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DELEGATE_TASKS_H
