/*
 * Copyright (C) 2022-2025 Huawei Device Co., Ltd.
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
#ifndef NFC_NAPI_ADAPTER_H_
#define NFC_NAPI_ADAPTER_H_

#include "nfc_napi_utils.h"

namespace OHOS {
namespace NFC {
napi_value Init(napi_env env, napi_callback_info info);
napi_value Uninit(napi_env env, napi_callback_info info);
napi_value Initialize(napi_env env, napi_callback_info info);
napi_value UnInitialize(napi_env env, napi_callback_info info);
napi_value ReadNdefTag(napi_env env, napi_callback_info info);
napi_value WriteNdefTag(napi_env env, napi_callback_info info);
napi_value ReadNdefData(napi_env env, napi_callback_info info);
napi_value WriteNdefData(napi_env env, napi_callback_info info);

class ReadAsyncContext : public AsyncContext {
public:
    std::string respNdefData_;
    explicit ReadAsyncContext(napi_env env, napi_async_work work = nullptr, napi_deferred deferred = nullptr)
        : AsyncContext(env, work, deferred) {}

    ReadAsyncContext() = delete;

    ~ReadAsyncContext() override {}
};

class WriteAsyncContext : public AsyncContext {
public:
    std::string writtenNdefData_;
    explicit WriteAsyncContext(napi_env env, napi_async_work work = nullptr, napi_deferred deferred = nullptr)
        : AsyncContext(env, work, deferred)
    {
        writtenNdefData_ = "";
    }

    WriteAsyncContext() = delete;

    ~WriteAsyncContext() override {}
};

class ReadDataAsyncContext : public AsyncContext {
public:
    std::vector<uint8_t> respNdefData_;
    explicit ReadDataAsyncContext(napi_env env, napi_async_work work = nullptr, napi_deferred deferred = nullptr)
        : AsyncContext(env, work, deferred) {}

    ReadDataAsyncContext() = delete;

    ~ReadDataAsyncContext() override {}
};

class WriteDataAsyncContext : public AsyncContext {
public:
    std::vector<uint8_t> writtenNdefData_;
    explicit WriteDataAsyncContext(napi_env env, napi_async_work work = nullptr, napi_deferred deferred = nullptr)
        : AsyncContext(env, work, deferred)
    {
    }

    WriteDataAsyncContext() = delete;

    ~WriteDataAsyncContext() override {}
};

}  // namespace NFC
}  // namespace OHOS

#endif
